package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func clearIAMEnv(t *testing.T) {
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
	} {
		t.Setenv(key, "")
	}
}

func testConfig() Config {
	return Config{
		AuthorizeURL:    "https://iam.example.test/oauth/authorize?tenant=demo",
		TokenURL:        "https://iam.example.test/oauth/token",
		UserInfoURL:     "https://iam.example.test/oauth/userinfo",
		ClientID:        "loopforge",
		ClientSecret:    "secret",
		Scopes:          []string{"openid", "profile"},
		ProviderName:    "Corp IAM",
		SubjectClaim:    "sub",
		LoginClaim:      "preferred_username",
		NameClaim:       "name",
		TokenAuthMethod: "client_secret_basic",
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	clearIAMEnv(t)
	cfg := ConfigFromEnv()
	if cfg.ProviderName != DefaultProviderName || cfg.SubjectClaim != DefaultSubjectClaim ||
		cfg.LoginClaim != DefaultLoginClaim || cfg.NameClaim != DefaultNameClaim {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.TokenAuthMethod != "client_secret_basic" {
		t.Fatalf("unexpected auth defaults: %+v", cfg)
	}
	if cfg.Enabled() {
		t.Fatal("an unconfigured deployment must not enable IAM")
	}
}

func TestConfigFromEnvOverrides(t *testing.T) {
	clearIAMEnv(t)
	t.Setenv("AGENTFLOW_IAM_AUTHORIZE_URL", "https://iam.example.test/authorize")
	t.Setenv("AGENTFLOW_IAM_TOKEN_URL", "https://iam.example.test/token")
	t.Setenv("AGENTFLOW_IAM_USERINFO_URL", "https://iam.example.test/userinfo")
	t.Setenv("AGENTFLOW_IAM_CLIENT_ID", "client")
	t.Setenv("AGENTFLOW_IAM_CLIENT_SECRET", "secret")
	t.Setenv("AGENTFLOW_IAM_REDIRECT_URL", "https://loopforge.example.test/api/auth/iam/callback")
	t.Setenv("AGENTFLOW_IAM_SCOPES", "openid, profile email")
	t.Setenv("AGENTFLOW_IAM_PROVIDER_NAME", " 企业 IAM ")
	t.Setenv("AGENTFLOW_IAM_SUBJECT_CLAIM", "user.id")
	t.Setenv("AGENTFLOW_IAM_LOGIN_CLAIM", "user.login")
	t.Setenv("AGENTFLOW_IAM_NAME_CLAIM", "user.name")
	t.Setenv("AGENTFLOW_IAM_TOKEN_AUTH_METHOD", "post")

	cfg := ConfigFromEnv()
	if !cfg.Enabled() {
		t.Fatalf("expected enabled config: %+v", cfg)
	}
	if cfg.ProviderName != "企业 IAM" {
		t.Fatalf("provider name = %q", cfg.ProviderName)
	}
	if got := strings.Join(cfg.Scopes, " "); got != "openid profile email" {
		t.Fatalf("scopes = %q", got)
	}
	if cfg.TokenAuthMethod != "client_secret_post" {
		t.Fatalf("auth method = %q", cfg.TokenAuthMethod)
	}
	if cfg.SubjectClaim != "user.id" || cfg.LoginClaim != "user.login" || cfg.NameClaim != "user.name" {
		t.Fatalf("claims = %+v", cfg)
	}
}

func TestValidateRequiresClientSecret(t *testing.T) {
	cfg := testConfig()
	cfg.ClientSecret = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
	cfg.ClientSecret = "secret"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("confidential client should be valid: %v", err)
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	cfg := testConfig()
	got, err := cfg.BuildAuthorizeURL("state-1", "https://loopforge.example.test/api/auth/iam/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("tenant") != "demo" {
		t.Fatalf("existing query lost: %s", got)
	}
	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "loopforge",
		"redirect_uri":          "https://loopforge.example.test/api/auth/iam/callback",
		"state":                 "state-1",
		"scope":                 "openid profile",
	} {
		if q.Get(key) != want {
			t.Fatalf("%s = %q want %q (%s)", key, q.Get(key), want, got)
		}
	}
	if strings.Contains(got, "secret") {
		t.Fatal("client secret must never appear in the authorize URL")
	}
}

func TestExchangeJSONWithBasicAuth(t *testing.T) {
	var gotForm url.Values
	var gotAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if user, pass, ok := r.BasicAuth(); ok {
			gotAuth = user == "loopforge" && pass == "secret"
		}
		_ = r.ParseForm()
		gotForm = r.PostForm
		_, _ = w.Write([]byte(`{"access_token":"token-1","token_type":"Bearer"}`))
	}))
	t.Cleanup(srv.Close)
	withIAMClient(t, srv)
	cfg := testConfig()
	cfg.TokenURL = srv.URL + "/token"
	token, err := cfg.Exchange(context.Background(), "code-1", "https://loopforge.example.test/callback")
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-1" {
		t.Fatalf("token = %q", token)
	}
	if !gotAuth {
		t.Fatal("client_secret_basic must send basic authentication")
	}
	if gotForm.Get("grant_type") != "authorization_code" || gotForm.Get("code") != "code-1" ||
		gotForm.Get("redirect_uri") != "https://loopforge.example.test/callback" {
		t.Fatalf("form = %v", gotForm)
	}
	if gotForm.Get("client_secret") != "" {
		t.Fatal("secret must not be sent in the form for client_secret_basic")
	}
}

func TestExchangeFormResponseAndPostAuth(t *testing.T) {
	var gotForm url.Values
	var gotAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, gotAuth = r.BasicAuth()
		_ = r.ParseForm()
		gotForm = r.PostForm
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		_, _ = w.Write([]byte("access_token=token-2&token_type=Bearer"))
	}))
	t.Cleanup(srv.Close)
	withIAMClient(t, srv)
	cfg := testConfig()
	cfg.TokenURL = srv.URL + "/token"
	cfg.TokenAuthMethod = "client_secret_post"
	token, err := cfg.Exchange(context.Background(), "code-2", "https://loopforge.example.test/callback")
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-2" {
		t.Fatalf("token = %q", token)
	}
	if gotAuth {
		t.Fatal("client_secret_post must not use basic authentication")
	}
	if gotForm.Get("client_secret") != "secret" {
		t.Fatalf("form = %v", gotForm)
	}
}

func TestExchangeSurfacesProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
	}))
	t.Cleanup(srv.Close)
	withIAMClient(t, srv)
	cfg := testConfig()
	cfg.TokenURL = srv.URL + "/token"
	_, err := cfg.Exchange(context.Background(), "code", "https://loopforge.example.test/callback")
	if err == nil || !strings.Contains(err.Error(), "code expired") {
		t.Fatalf("error = %v", err)
	}
}

func TestUserInfoAndIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-3" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"sub":12345,"preferred_username":"alice","name":"Alice Chen","profile":{"team":"platform"}}`))
	}))
	t.Cleanup(srv.Close)
	withIAMClient(t, srv)
	cfg := testConfig()
	cfg.UserInfoURL = srv.URL + "/userinfo"
	info, err := cfg.UserInfo(context.Background(), "token-3")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := cfg.Identity(info)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Subject != "12345" || identity.Login != "alice" || identity.Name != "Alice Chen" {
		t.Fatalf("identity = %+v", identity)
	}

	cfg.LoginClaim = "profile.team"
	cfg.NameClaim = "missing"
	identity, err = cfg.Identity(info)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Login != "platform" || identity.Name != "Alice Chen" {
		t.Fatalf("fallback identity = %+v", identity)
	}
}

func TestIdentityRequiresSubject(t *testing.T) {
	cfg := testConfig()
	if _, err := cfg.Identity(map[string]any{"preferred_username": "alice"}); err == nil {
		t.Fatal("expected a missing subject error")
	}
}

func TestParseTokenResponseRejectsEmptyBody(t *testing.T) {
	if _, err := parseTokenResponse(nil); err == nil {
		t.Fatal("expected an error for an empty body")
	}
	if _, err := parseTokenResponse([]byte("{}")); err != nil {
		t.Fatalf("empty JSON object should parse: %v", err)
	}
}

func TestClaimStringScalarTypes(t *testing.T) {
	info := map[string]any{
		"string": " value ",
		"number": json.Number("42"),
		"float":  float64(7),
		"object": map[string]any{"nested": "yes"},
	}
	if got := claimString(info, "string"); got != "value" {
		t.Fatalf("string = %q", got)
	}
	if got := claimString(info, "number"); got != "42" {
		t.Fatalf("number = %q", got)
	}
	if got := claimString(info, "float"); got != "7" {
		t.Fatalf("float = %q", got)
	}
	if got := claimString(info, "object"); got != "" {
		t.Fatalf("object = %q", got)
	}
	if got := claimString(info, "object.nested"); got != "yes" {
		t.Fatalf("object to scalar path = %q", got)
	}
}

func TestBasicAuthMatchesRFCEncoding(t *testing.T) {
	cfg := testConfig()
	cfg.ClientID = "client id"
	cfg.ClientSecret = "secret/value"
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(cfg.ClientID)+":"+url.QueryEscape(cfg.ClientSecret)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != expected {
			t.Errorf("authorization = %q want %q", r.Header.Get("Authorization"), expected)
		}
		_, _ = io.WriteString(w, `{"access_token":"ok"}`)
	}))
	t.Cleanup(srv.Close)
	withIAMClient(t, srv)
	cfg.TokenURL = srv.URL
	if _, err := cfg.Exchange(context.Background(), "code", "https://loopforge.example.test/callback"); err != nil {
		t.Fatal(err)
	}
}

func withIAMClient(t *testing.T, srv *httptest.Server) {
	t.Helper()
	previous := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = previous })
}
