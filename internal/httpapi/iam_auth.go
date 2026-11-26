package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"agentflow/internal/auth"
	"agentflow/internal/iam"

	"github.com/gin-gonic/gin"
)

const (
	iamProvider        = "iam"
	iamOAuthStateTTL   = 10 * time.Minute
	iamStateCookieName = "agentflow_iam_state"
	iamStateCookiePath = "/api/auth/iam"
)

type iamOAuthState struct {
	Nonce    string `json:"n"`
	Exp      int64  `json:"exp"`
	Return   string `json:"ret,omitempty"`
	Redirect string `json:"ru"`
}

type iamOAuthCookie struct {
	Nonce string `json:"n"`
	Exp   int64  `json:"exp"`
}

// iamStatus tells the login page whether to offer the IAM button. It is public
// and exposes only the display label.
func (h *authHandlers) iamStatus(c *gin.Context) {
	cfg := iam.ConfigFromEnv()
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"enabled":     cfg.Enabled(),
		"displayName": cfg.ProviderName,
	})
}

// iamStart begins the authorization-code flow. The state is signed with the
// platform session secret and bound to a short-lived HttpOnly cookie so a
// callback from another browser cannot complete it.
func (h *authHandlers) iamStart(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	cfg := iam.ConfigFromEnv()
	if !cfg.Enabled() {
		h.iamError(c, "config")
		return
	}
	redirectURI := h.iamRedirectURI(c.Request, cfg)
	returnURL := h.ssoReturnURL(c.Request)
	nonce, err := randomHex(32)
	if err != nil {
		h.iamError(c, "config")
		return
	}
	secret := h.getAuthClient().Config().SessionSecret
	exp := time.Now().Add(iamOAuthStateTTL).Unix()
	state, err := signSSOPayload(iamOAuthState{Nonce: nonce, Exp: exp, Return: returnURL, Redirect: redirectURI}, secret)
	if err != nil {
		h.iamError(c, "config")
		return
	}
	cookie, err := signSSOPayload(iamOAuthCookie{Nonce: nonce, Exp: exp}, secret)
	if err != nil {
		h.iamError(c, "config")
		return
	}
	location, err := cfg.BuildAuthorizeURL(state, redirectURI)
	if err != nil {
		h.iamError(c, "config")
		return
	}
	h.setIAMStateCookie(c.Writer, c.Request, cookie)
	c.Redirect(http.StatusFound, location)
}

// iamCallback validates the browser-bound state, exchanges the code, reads the
// userinfo claims, and issues the same signed session cookie as password login.
func (h *authHandlers) iamCallback(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	cfg := iam.ConfigFromEnv()
	if !cfg.Enabled() {
		h.iamError(c, "config")
		return
	}
	if reason := strings.TrimSpace(c.Query("error")); reason != "" {
		if reason == "access_denied" {
			h.iamError(c, "access_denied")
		} else {
			h.iamError(c, "provider")
		}
		return
	}
	secret := h.getAuthClient().Config().SessionSecret
	now := time.Now().Unix()
	var state iamOAuthState
	if err := parseSSOPayload(c.Query("state"), secret, &state); err != nil ||
		state.Exp < now || strings.TrimSpace(state.Nonce) == "" || strings.TrimSpace(state.Redirect) == "" {
		h.iamError(c, "state")
		return
	}
	cookie, err := c.Cookie(iamStateCookieName)
	if err != nil || strings.TrimSpace(cookie) == "" {
		h.iamError(c, "state")
		return
	}
	var bound iamOAuthCookie
	if err := parseSSOPayload(cookie, secret, &bound); err != nil ||
		bound.Exp < now || subtle.ConstantTimeCompare([]byte(state.Nonce), []byte(bound.Nonce)) != 1 {
		h.iamError(c, "state")
		return
	}
	// The state is single-use: clear it before any outbound call so a replayed
	// callback cannot complete twice. Invalid callbacks leave the cookie alone
	// so a cross-site request cannot cancel a legitimate login in progress.
	h.clearIAMStateCookie(c.Writer, c.Request)
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		h.iamError(c, "provider")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	accessToken, err := cfg.Exchange(ctx, code, state.Redirect)
	if err != nil {
		log.Printf("[auth] iam token exchange failed: %v", err)
		h.iamError(c, "provider")
		return
	}
	info, err := cfg.UserInfo(ctx, accessToken)
	if err != nil {
		log.Printf("[auth] iam userinfo failed: %v", err)
		h.iamError(c, "profile")
		return
	}
	identity, err := cfg.Identity(info)
	if err != nil {
		log.Printf("[auth] iam identity failed: %v", err)
		h.iamError(c, "profile")
		return
	}
	user, err := h.resolveIAMUser(identity)
	if err != nil {
		h.iamError(c, ssoErrorCode(err))
		return
	}
	token, err := h.getAuthClient().SignUser(user)
	if err != nil {
		h.iamError(c, "provision_failed")
		return
	}
	h.setAuthCookie(c.Writer, c.Request, token)
	target := strings.TrimSpace(state.Return)
	if target == "" {
		target = "/"
	}
	c.Redirect(http.StatusFound, target)
}

// resolveIAMUser adapts the OAuth2 IAM identity to the shared external-user
// resolver. The provider string keeps external-identity mappings independent.
func (h *authHandlers) resolveIAMUser(identity iam.Identity) (*auth.User, error) {
	return h.resolveExternalUser(iamProvider, ssoIdentity{
		Subject: identity.Subject,
		Login:   identity.Login,
		Name:    identity.Name,
	}, ssoPolicy{
		AutoProvision: iamAutoProvisionMode(),
		LinkExisting:  iamLinkExisting(),
	})
}

func iamAutoProvisionMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AGENTFLOW_IAM_AUTO_PROVISION"))) {
	case "always":
		return "always"
	case "never":
		return "never"
	default:
		return "signup"
	}
}

// iamLinkExisting controls whether an IAM identity may bind to an existing
// platform account with the same normalized login name. It defaults to true
// because deployments that configure IAM usually want pre-created accounts to
// be usable; set AGENTFLOW_IAM_LINK_EXISTING=false to reject collisions.
func iamLinkExisting() bool {
	value := strings.TrimSpace(os.Getenv("AGENTFLOW_IAM_LINK_EXISTING"))
	if value == "" {
		return true
	}
	enabled, err := strconv.ParseBool(value)
	return err == nil && enabled
}

// iamRedirectURI is the exact callback registered on the IAM application.
// Deployments behind a proxy should set AGENTFLOW_IAM_REDIRECT_URL so the
// authorization and token requests agree on the public URL.
func (h *authHandlers) iamRedirectURI(r *http.Request, cfg iam.Config) string {
	if redirect := strings.TrimSpace(cfg.RedirectURL); redirect != "" {
		return redirect
	}
	proto := "http"
	if secureRequest(r) {
		proto = "https"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = h.getAuthClient().Config().AppDomain
	}
	return proto + "://" + host + "/api/auth/iam/callback"
}

// ssoReturnURL keeps a successful login off the login page itself. The
// explicit return_url is still validated by getReturnURL/safeReturnURL.
func (h *authHandlers) ssoReturnURL(r *http.Request) string {
	target := h.getReturnURL(r)
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "/"
	}
	path := strings.TrimSuffix(u.Path, "/")
	if path == "/login.html" {
		return u.Scheme + "://" + u.Host + "/"
	}
	return target
}

func (h *authHandlers) iamError(c *gin.Context, code string) {
	c.Redirect(http.StatusSeeOther, "/login.html?iam_error="+url.QueryEscape(code))
}

func (h *authHandlers) setIAMStateCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     iamStateCookieName,
		Value:    value,
		Path:     iamStateCookiePath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureRequest(r),
		MaxAge:   int(iamOAuthStateTTL.Seconds()),
	})
}

func (h *authHandlers) clearIAMStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     iamStateCookieName,
		Value:    "",
		Path:     iamStateCookiePath,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureRequest(r),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// signSSOPayload uses the same HMAC construction as the other OAuth state
// helpers. There is no built-in fallback key: a key published in the source
// would let anyone mint a state or a browser-bound state cookie.
func signSSOPayload(v any, secret string) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", errNoOAuthStateSecret
	}
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	return encoded + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

func parseSSOPayload(raw, secret string, out any) error {
	if strings.TrimSpace(secret) == "" {
		return errNoOAuthStateSecret
	}
	encoded, sig, ok := strings.Cut(strings.TrimSpace(raw), ".")
	if !ok || encoded == "" || sig == "" {
		return os.ErrInvalid
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return os.ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

