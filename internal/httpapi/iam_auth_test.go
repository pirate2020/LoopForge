package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"agentflow/internal/auth"
	"agentflow/internal/repo"

	"github.com/gin-gonic/gin"
)

const iamTestSecret = "iam-http-test-secret"

func clearIAMTestEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"AGENTFLOW_IAM_AUTHORIZE_URL",
		"AGENTFLOW_IAM_TOKEN_URL",
		"AGENTFLOW_IAM_USERINFO_URL",
		"AGENTFLOW_IAM_CLIENT_ID",
		"AGENTFLOW_IAM_CLIENT_SECRET",
		"AGENTFLOW_IAM_REDIRECT_URL",
		"AGENTFLOW_IAM_SCOPES",
		"AGENTFLOW_IAM_PROVIDER_NAME",
		"AGENTFLOW_IAM_SUBJECT_CLAIM",
		"AGENTFLOW_IAM_LOGIN_CLAIM",
		"AGENTFLOW_IAM_NAME_CLAIM",
		"AGENTFLOW_IAM_TOKEN_AUTH_METHOD",
		"AGENTFLOW_IAM_AUTO_PROVISION",
		"AGENTFLOW_IAM_LINK_EXISTING",
	} {
		t.Setenv(key, "")
	}
}

func configureIAMTest(t *testing.T, srv *httptest.Server) {
	t.Helper()
	clearIAMTestEnv(t)
	t.Setenv("AGENTFLOW_IAM_AUTHORIZE_URL", srv.URL+"/authorize")
	t.Setenv("AGENTFLOW_IAM_TOKEN_URL", srv.URL+"/token")
	t.Setenv("AGENTFLOW_IAM_USERINFO_URL", srv.URL+"/userinfo")
	t.Setenv("AGENTFLOW_IAM_CLIENT_ID", "client")
	t.Setenv("AGENTFLOW_IAM_CLIENT_SECRET", "secret")
	t.Setenv("AGENTFLOW_IAM_SCOPES", "openid profile email")
	t.Setenv("AGENTFLOW_IAM_TOKEN_AUTH_METHOD", "client_secret_basic")
	t.Setenv("AGENTFLOW_IAM_LINK_EXISTING", "true")
	t.Setenv("AGENTFLOW_ALLOW_SIGNUP", "true")
	t.Setenv("AGENTFLOW_SECURE_COOKIES", "false")
	t.Setenv("AGENTFLOW_PLATFORM_ADMINS", "")
}

func newIAMTestHandler(t *testing.T) (*authHandlers, *repo.Store) {
	t.Helper()
	st, err := repo.OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	client := auth.NewClient(auth.Config{SessionSecret: iamTestSecret})
	return &authHandlers{deps: &deps{repo: st, authClient: client}}, st
}

func newIAMMockIdP(t *testing.T, claims string) *httptest.Server {
	t.Helper()
	return newIAMMockIdPWith(t, claims, 0, 0)
}

func newIAMMockIdPWith(t *testing.T, claims string, tokenStatus, userInfoStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if tokenStatus != 0 && tokenStatus != http.StatusOK {
				w.WriteHeader(tokenStatus)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"rejected"}`))
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if got := r.PostForm.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.PostForm.Get("code"); got != "code-1" {
				t.Errorf("code = %q", got)
			}
			if got := r.PostForm.Get("redirect_uri"); got != "http://platform.test/api/auth/iam/callback" {
				t.Errorf("redirect_uri = %q", got)
			}
			if user, pass, ok := r.BasicAuth(); !ok || user != "client" || pass != "secret" {
				t.Errorf("basic auth = %q/%q ok=%v", user, pass, ok)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"access-1","token_type":"Bearer"}`))
		case "/userinfo":
			if userInfoStatus != 0 && userInfoStatus != http.StatusOK {
				w.WriteHeader(userInfoStatus)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer access-1" {
				t.Errorf("authorization = %q", got)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(claims))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

type iamStartResult struct {
	rec      *httptest.ResponseRecorder
	rawState string
	state    iamOAuthState
	cookie   *http.Cookie
	bound    iamOAuthCookie
}

func startIAMTest(t *testing.T, h *authHandlers, path string) iamStartResult {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://platform.test"+path, nil)
	h.iamStart(c)
	if rec.Code != http.StatusFound {
		t.Fatalf("start status = %d body=%s", rec.Code, rec.Body.String())
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	rawState := location.Query().Get("state")
	if rawState == "" {
		t.Fatal("start did not include state")
	}
	var state iamOAuthState
	if err := parseSSOPayload(rawState, iamTestSecret, &state); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	var cookie *http.Cookie
	for _, item := range rec.Result().Cookies() {
		if item.Name == iamStateCookieName {
			cookie = item
		}
	}
	if cookie == nil {
		t.Fatal("start did not set the state cookie")
	}
	var bound iamOAuthCookie
	if err := parseSSOPayload(cookie.Value, iamTestSecret, &bound); err != nil {
		t.Fatalf("parse state cookie: %v", err)
	}
	return iamStartResult{rec: rec, rawState: rawState, state: state, cookie: cookie, bound: bound}
}

func callbackIAMTest(h *authHandlers, rawState string, cookie *http.Cookie) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "http://platform.test/api/auth/iam/callback?code=code-1&state="+url.QueryEscape(rawState), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	c.Request = req
	h.iamCallback(c)
	return rec
}

func callbackIAMQueryTest(h *authHandlers, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://platform.test/api/auth/iam/callback?"+query, nil)
	h.iamCallback(c)
	return rec
}

func iamResponseCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func iamErrorFromResponse(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return location.Query().Get("iam_error")
}

func TestIAMStatusDisabledAndEnabled(t *testing.T) {
	clearIAMTestEnv(t)
	h := &authHandlers{deps: &deps{}}
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/auth/iam", nil)
	h.iamStatus(c)
	var body struct {
		Enabled     bool   `json:"enabled"`
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Enabled || body.DisplayName != "IAM" {
		t.Fatalf("disabled status = %+v", body)
	}

	srv := newIAMMockIdP(t, `{"sub":"u-1"}`)
	configureIAMTest(t, srv)
	rec = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/auth/iam", nil)
	h.iamStatus(c)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled {
		t.Fatalf("enabled status = %+v", body)
	}
}

func TestIAMLoginProvisionsAndReusesAccount(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-1","preferred_username":"alice","name":"Alice Chen"}`)
	configureIAMTest(t, srv)
	h, st := newIAMTestHandler(t)
	before := st.UserCount()

	first := startIAMTest(t, h, "/api/auth/iam/start?return_url=%2Fwelcome")
	if first.state.Return != "http://platform.test/welcome" {
		t.Fatalf("return = %q", first.state.Return)
	}
	if first.state.Redirect != "http://platform.test/api/auth/iam/callback" {
		t.Fatalf("redirect = %q", first.state.Redirect)
	}
	if first.state.Nonce != first.bound.Nonce {
		t.Fatalf("state/cookie are not bound: %+v %+v", first.state, first.bound)
	}

	rec := callbackIAMTest(h, first.rawState, first.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "http://platform.test/welcome" {
		t.Fatalf("callback location = %q", got)
	}
	authCookie := iamResponseCookie(rec, authCookieName)
	if authCookie == nil {
		t.Fatal("callback did not set the platform session cookie")
	}
	user, err := h.getAuthClient().ParseSignedUser(authCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if user.LoginName != "alice" || user.ID <= 0 {
		t.Fatalf("session user = %+v", user)
	}
	if got := st.UserCount(); got != before+1 {
		t.Fatalf("user count = %d want %d", got, before+1)
	}
	if mapped, ok := st.ExternalIdentityUser("iam", "u-1"); !ok || mapped != user.ID {
		t.Fatalf("mapping = %d ok=%v want %d", mapped, ok, user.ID)
	}
	if stored, ok := st.UserByLoginName("alice"); !ok || stored.ID != user.ID || stored.ChineseName != "Alice Chen" {
		t.Fatalf("stored user = %+v ok=%v", stored, ok)
	}
	if st.IsPlatformAdmin("alice") {
		t.Fatal("a non-first IAM account must not become an administrator")
	}

	// A repeated login must reuse the mapping, not create another account.
	second := startIAMTest(t, h, "/api/auth/iam/start")
	rec = callbackIAMTest(h, second.rawState, second.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("second callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	authCookie = iamResponseCookie(rec, authCookieName)
	if authCookie == nil {
		t.Fatal("second callback did not set the session cookie")
	}
	again, err := h.getAuthClient().ParseSignedUser(authCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != user.ID {
		t.Fatalf("second login user = %d want %d", again.ID, user.ID)
	}
	if got := st.UserCount(); got != before+1 {
		t.Fatalf("second login created an account: %d want %d", got, before+1)
	}
}

func TestIAMFirstUserBecomesAdmin(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-first","preferred_username":"owner","name":"Owner"}`)
	configureIAMTest(t, srv)
	h, st := newIAMTestHandler(t)
	if err := st.DB.Exec("DELETE FROM users").Error; err != nil {
		t.Fatal(err)
	}
	if st.UserCount() != 0 {
		t.Fatalf("user count = %d", st.UserCount())
	}
	start := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, start.rawState, start.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !st.IsPlatformAdmin("owner") {
		t.Fatal("the first platform user must become an administrator")
	}
	rec = httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/auth/setup", nil)
	h.authSetup(c)
	var setup struct {
		NeedsSetup bool `json:"needsSetup"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if setup.NeedsSetup {
		t.Fatal("setup must be complete after the first IAM account exists")
	}
}

func TestIAMLoginLinksExistingAccount(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-2","preferred_username":"alice","name":"IAM Alice"}`)
	configureIAMTest(t, srv)
	h, st := newIAMTestHandler(t)
	local, err := st.CreateLocalAccount("alice", "password-1", true)
	if err != nil {
		t.Fatal(err)
	}
	stored, ok := st.UserByLoginName("alice")
	if !ok || stored.ID != local.ID {
		t.Fatalf("local account = %+v ok=%v", stored, ok)
	}
	stored.ChineseName = "Local Alice"
	if err := st.PutUser(stored); err != nil {
		t.Fatal(err)
	}
	before := st.UserCount()

	start := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, start.rawState, start.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	authCookie := iamResponseCookie(rec, authCookieName)
	if authCookie == nil {
		t.Fatal("linked login did not set the session cookie")
	}
	user, err := h.getAuthClient().ParseSignedUser(authCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if user.ID != local.ID || user.LoginName != "alice" || user.ChineseName != "Local Alice" {
		t.Fatalf("session user = %+v want platform account %d", user, local.ID)
	}
	if !st.IsPlatformAdmin("alice") {
		t.Fatal("linking must preserve the platform administrator role")
	}
	if !st.CheckLocalPassword(local.ID, "password-1") {
		t.Fatal("linking must preserve the local password")
	}
	if mapped, ok := st.ExternalIdentityUser("iam", "u-2"); !ok || mapped != local.ID {
		t.Fatalf("mapping = %d ok=%v want %d", mapped, ok, local.ID)
	}
	if got := st.UserCount(); got != before {
		t.Fatalf("linking created a user: %d want %d", got, before)
	}
}

func TestIAMDoesNotTakeOverAccountLinkedToAnotherIdentity(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-new","preferred_username":"alice","name":"New Alice"}`)
	configureIAMTest(t, srv)
	h, st := newIAMTestHandler(t)
	local, err := st.CreateLocalAccount("alice", "password-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.LinkExternalIdentity("iam", "u-old", local.ID); err != nil {
		t.Fatal(err)
	}
	before := st.UserCount()

	start := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, start.rawState, start.cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := iamErrorFromResponse(t, rec); got != "account_linked" {
		t.Fatalf("error = %q", got)
	}
	if iamResponseCookie(rec, authCookieName) != nil {
		t.Fatal("a second IAM identity must not receive a session")
	}
	if mapped, ok := st.ExternalIdentityUser("iam", "u-old"); !ok || mapped != local.ID {
		t.Fatalf("existing mapping = %d ok=%v want %d", mapped, ok, local.ID)
	}
	if _, ok := st.ExternalIdentityUser("iam", "u-new"); ok {
		t.Fatal("a second identity was linked to the account")
	}
	if got := st.UserCount(); got != before {
		t.Fatalf("rejected takeover created a user: %d want %d", got, before)
	}
}

func TestIAMLinkExistingCanBeDisabled(t *testing.T) {
	t.Run("configuration switch", func(t *testing.T) {
		srv := newIAMMockIdP(t, `{"sub":"u-1","preferred_username":"alice"}`)
		configureIAMTest(t, srv)
		t.Setenv("AGENTFLOW_IAM_LINK_EXISTING", "false")
		h, st := newIAMTestHandler(t)
		if _, err := st.CreateLocalAccount("alice", "password-1", false); err != nil {
			t.Fatal(err)
		}
		start := startIAMTest(t, h, "/api/auth/iam/start")
		rec := callbackIAMTest(h, start.rawState, start.cookie)
		if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "link_disabled" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if _, ok := st.ExternalIdentityUser("iam", "u-1"); ok {
			t.Fatal("linking was disabled but the identity was stored")
		}
	})

	t.Run("never mode", func(t *testing.T) {
		srv := newIAMMockIdP(t, `{"sub":"u-2","preferred_username":"bob"}`)
		configureIAMTest(t, srv)
		t.Setenv("AGENTFLOW_IAM_AUTO_PROVISION", "never")
		h, st := newIAMTestHandler(t)
		if _, err := st.CreateLocalAccount("bob", "password-2", false); err != nil {
			t.Fatal(err)
		}
		start := startIAMTest(t, h, "/api/auth/iam/start")
		rec := callbackIAMTest(h, start.rawState, start.cookie)
		if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "link_disabled" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		if _, ok := st.ExternalIdentityUser("iam", "u-2"); ok {
			t.Fatal("never mode linked the identity")
		}
	})
}

func TestIAMSignupDisabledRejectsUnknownIdentity(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-3","preferred_username":"newbie","name":"Newbie"}`)
	configureIAMTest(t, srv)
	t.Setenv("AGENTFLOW_ALLOW_SIGNUP", "false")
	h, st := newIAMTestHandler(t)
	before := st.UserCount()
	start := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, start.rawState, start.cookie)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := iamErrorFromResponse(t, rec); got != "signup_disabled" {
		t.Fatalf("error = %q", got)
	}
	if got := st.UserCount(); got != before {
		t.Fatalf("user count = %d want %d", got, before)
	}
}

func TestIAMAutoProvisionAlwaysOverridesSignupSwitch(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-4","preferred_username":"member","name":"Member"}`)
	configureIAMTest(t, srv)
	t.Setenv("AGENTFLOW_ALLOW_SIGNUP", "false")
	t.Setenv("AGENTFLOW_IAM_AUTO_PROVISION", "always")
	h, st := newIAMTestHandler(t)
	before := st.UserCount()
	start := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, start.rawState, start.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	if got := st.UserCount(); got != before+1 {
		t.Fatalf("user count = %d want %d", got, before+1)
	}
}

func TestIAMAutoProvisionNeverAllowsLinkedIdentityOnly(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-5","preferred_username":"linked","name":"Linked"}`)
	configureIAMTest(t, srv)
	t.Setenv("AGENTFLOW_IAM_AUTO_PROVISION", "always")
	h, st := newIAMTestHandler(t)
	first := startIAMTest(t, h, "/api/auth/iam/start")
	rec := callbackIAMTest(h, first.rawState, first.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("provision callback status = %d body=%s", rec.Code, rec.Body.String())
	}
	before := st.UserCount()

	t.Setenv("AGENTFLOW_IAM_AUTO_PROVISION", "never")
	second := startIAMTest(t, h, "/api/auth/iam/start")
	rec = callbackIAMTest(h, second.rawState, second.cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("linked callback status = %d body=%s", rec.Code, rec.Body.String())
	}

	srv2 := newIAMMockIdP(t, `{"sub":"u-6","preferred_username":"unknown","name":"Unknown"}`)
	configureIAMTest(t, srv2)
	t.Setenv("AGENTFLOW_IAM_AUTO_PROVISION", "never")
	third := startIAMTest(t, h, "/api/auth/iam/start")
	rec = callbackIAMTest(h, third.rawState, third.cookie)
	if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "signup_disabled" {
		t.Fatalf("unknown identity status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := st.UserCount(); got != before {
		t.Fatalf("unknown identity created a user: %d want %d", got, before)
	}
}

func TestIAMCallbackStateBinding(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-7","preferred_username":"state"}`)
	configureIAMTest(t, srv)
	h, _ := newIAMTestHandler(t)
	first := startIAMTest(t, h, "/api/auth/iam/start")
	second := startIAMTest(t, h, "/api/auth/iam/start")

	if rec := callbackIAMTest(h, first.rawState, nil); iamErrorFromResponse(t, rec) != "state" {
		t.Fatalf("missing cookie error = %q", iamErrorFromResponse(t, rec))
	}
	if rec := callbackIAMTest(h, first.rawState, second.cookie); iamErrorFromResponse(t, rec) != "state" {
		t.Fatalf("mismatched cookie error = %q", iamErrorFromResponse(t, rec))
	}
	if rec := callbackIAMTest(h, first.rawState+"x", first.cookie); iamErrorFromResponse(t, rec) != "state" {
		t.Fatalf("tampered state error = %q", iamErrorFromResponse(t, rec))
	}

	expired := time.Now().Add(-time.Minute).Unix()
	rawState, err := signSSOPayload(iamOAuthState{
		Nonce: "nonce", Exp: expired, Return: "/", Redirect: "http://platform.test/api/auth/iam/callback",
	}, iamTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	rawCookie, err := signSSOPayload(iamOAuthCookie{Nonce: "nonce", Exp: expired}, iamTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	if rec := callbackIAMTest(h, rawState, &http.Cookie{Name: iamStateCookieName, Value: rawCookie}); iamErrorFromResponse(t, rec) != "state" {
		t.Fatalf("expired state error = %q", iamErrorFromResponse(t, rec))
	}

	rec := callbackIAMQueryTest(h, "error=access_denied")
	if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "access_denied" {
		t.Fatalf("access denied status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIAMReturnURLStaysOnPlatform(t *testing.T) {
	srv := newIAMMockIdP(t, `{"sub":"u-8"}`)
	configureIAMTest(t, srv)
	h, _ := newIAMTestHandler(t)
	cases := map[string]string{
		"/api/auth/iam/start?return_url=https%3A%2F%2Fevil.example%2F": "http://platform.test/",
		"/api/auth/iam/start?return_url=%2Flogin.html":                 "http://platform.test/",
		"/api/auth/iam/start?return_url=%2Fwelcome":                    "http://platform.test/welcome",
		"/api/auth/iam/start":                                          "http://platform.test/",
	}
	for path, want := range cases {
		result := startIAMTest(t, h, path)
		if result.state.Return != want {
			t.Fatalf("%s return = %q want %q", path, result.state.Return, want)
		}
	}
}

func TestIAMProviderFailures(t *testing.T) {
	t.Run("token exchange", func(t *testing.T) {
		srv := newIAMMockIdPWith(t, `{"sub":"u-9"}`, http.StatusBadRequest, 0)
		configureIAMTest(t, srv)
		h, _ := newIAMTestHandler(t)
		start := startIAMTest(t, h, "/api/auth/iam/start")
		rec := callbackIAMTest(h, start.rawState, start.cookie)
		if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "provider" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("userinfo", func(t *testing.T) {
		srv := newIAMMockIdPWith(t, `{"sub":"u-10"}`, 0, http.StatusUnauthorized)
		configureIAMTest(t, srv)
		h, _ := newIAMTestHandler(t)
		start := startIAMTest(t, h, "/api/auth/iam/start")
		rec := callbackIAMTest(h, start.rawState, start.cookie)
		if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "profile" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
	t.Run("missing subject", func(t *testing.T) {
		srv := newIAMMockIdP(t, `{"preferred_username":"nosub"}`)
		configureIAMTest(t, srv)
		h, _ := newIAMTestHandler(t)
		start := startIAMTest(t, h, "/api/auth/iam/start")
		rec := callbackIAMTest(h, start.rawState, start.cookie)
		if rec.Code != http.StatusSeeOther || iamErrorFromResponse(t, rec) != "profile" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestIAMAuthPathsArePublic(t *testing.T) {
	for _, path := range []string{"/api/auth/iam", "/api/auth/iam/start", "/api/auth/iam/callback"} {
		if protectedAccessPath(path) {
			t.Fatalf("%s must stay public for a signed-out browser", path)
		}
	}
	if !protectedAccessPath("/api/runs") {
		t.Fatal("ordinary API paths must stay protected")
	}
}

func TestIAMLoginNameSanitization(t *testing.T) {
	if got := sanitizeSSOLogin("alice", "u-1"); got != "alice" {
		t.Fatalf("login = %q", got)
	}
	if got := sanitizeSSOLogin("alice@example.com", "u-1"); got != "alice-example.com" {
		t.Fatalf("email login = %q", got)
	}
	if got := sanitizeSSOLogin("-alice-", "u-1"); got != "alice" {
		t.Fatalf("trimmed login = %q", got)
	}
	if got := sanitizeSSOLogin("用户", "u-2"); !strings.HasPrefix(got, "sso-") || !validSSOLogin(got) {
		t.Fatalf("fallback login = %q", got)
	}
	if got := sanitizeSSOLogin("a", "u-3"); got == "a" || !validSSOLogin(got) {
		t.Fatalf("short login = %q", got)
	}
	if got := sanitizeSSOLogin(strings.Repeat("a", 70), "u-4"); len(got) != 64 || !validSSOLogin(got) {
		t.Fatalf("long login length = %d", len(got))
	}
	if got := ssoDisplayName("", "alice"); got != "alice" {
		t.Fatalf("display name fallback = %q", got)
	}
	if got := ssoDisplayName(strings.Repeat("名", 200), "alice"); len([]rune(got)) != 128 {
		t.Fatalf("display name length = %d", len([]rune(got)))
	}
}
