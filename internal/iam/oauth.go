// Package iam implements the generic OAuth 2.0 authorization-code flow used
// by IAM single sign-on. It is deliberately provider-neutral: deployments
// configure the authorization, token and userinfo endpoints, and the platform
// only relies on the standard OAuth 2.0 wire protocol.
package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultProviderName = "IAM"
	DefaultSubjectClaim = "sub"
	DefaultLoginClaim   = "preferred_username"
	DefaultNameClaim    = "name"

	// maxResponseBytes caps how much of any IAM response body is read.
	maxResponseBytes = 1 << 20
)

// httpClient bounds every call to the IAM endpoints. Redirects are refused so
// a misconfigured or compromised endpoint cannot forward the client secret or
// access token to another host.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Config describes the OAuth 2.0 application registered on the IAM host.
type Config struct {
	AuthorizeURL    string
	TokenURL        string
	UserInfoURL     string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	Scopes          []string
	ProviderName    string
	SubjectClaim    string
	LoginClaim      string
	NameClaim       string
	TokenAuthMethod string
}

// ConfigFromEnv reads the deployment's IAM application configuration.
// Optional values get stable defaults so an unconfigured deployment stays on
// password login.
func ConfigFromEnv() Config {
	return Config{
		AuthorizeURL:    envTrim("AGENTFLOW_IAM_AUTHORIZE_URL"),
		TokenURL:        envTrim("AGENTFLOW_IAM_TOKEN_URL"),
		UserInfoURL:     envTrim("AGENTFLOW_IAM_USERINFO_URL"),
		ClientID:        envTrim("AGENTFLOW_IAM_CLIENT_ID"),
		ClientSecret:    envTrim("AGENTFLOW_IAM_CLIENT_SECRET"),
		RedirectURL:     envTrim("AGENTFLOW_IAM_REDIRECT_URL"),
		Scopes:          splitScopes(envTrim("AGENTFLOW_IAM_SCOPES")),
		ProviderName:    providerName(envTrim("AGENTFLOW_IAM_PROVIDER_NAME")),
		SubjectClaim:    envOrDefault("AGENTFLOW_IAM_SUBJECT_CLAIM", DefaultSubjectClaim),
		LoginClaim:      envOrDefault("AGENTFLOW_IAM_LOGIN_CLAIM", DefaultLoginClaim),
		NameClaim:       envOrDefault("AGENTFLOW_IAM_NAME_CLAIM", DefaultNameClaim),
		TokenAuthMethod: tokenAuthMethod(envTrim("AGENTFLOW_IAM_TOKEN_AUTH_METHOD")),
	}
}

// Enabled reports whether the deployment has a complete, usable configuration.
func (c Config) Enabled() bool {
	return c.Validate() == nil
}

// PartiallyConfigured reports whether any IAM setting is present. A partially
// configured application is disabled, and the API logs it once at startup so
// the missing setting is visible instead of silently hiding the login button.
func (c Config) PartiallyConfigured() bool {
	return c.AuthorizeURL != "" || c.TokenURL != "" || c.UserInfoURL != "" ||
		c.ClientID != "" || c.ClientSecret != ""
}

// Validate rejects configurations that cannot complete a login.
func (c Config) Validate() error {
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("IAM client ID is not configured")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("IAM client secret is not configured")
	}
	for name, raw := range map[string]string{
		"authorize": c.AuthorizeURL,
		"token":     c.TokenURL,
		"userinfo":  c.UserInfoURL,
	} {
		if err := validateHTTPURL(raw); err != nil {
			return fmt.Errorf("IAM %s URL is invalid: %w", name, err)
		}
	}
	if c.RedirectURL != "" {
		if err := validateHTTPURL(c.RedirectURL); err != nil {
			return fmt.Errorf("IAM redirect URL is invalid: %w", err)
		}
	}
	if strings.TrimSpace(c.SubjectClaim) == "" {
		return errors.New("IAM subject claim is empty")
	}
	if c.TokenAuthMethod != "" && c.TokenAuthMethod != "client_secret_basic" && c.TokenAuthMethod != "client_secret_post" {
		return fmt.Errorf("IAM token auth method %q is not supported", c.TokenAuthMethod)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("host is empty")
	}
	if u.User != nil {
		return errors.New("URL must not contain credentials")
	}
	if u.Fragment != "" {
		return errors.New("URL must not contain a fragment")
	}
	return nil
}

// BuildAuthorizeURL is the browser location that asks the user to approve the
// application. Existing query parameters on the configured URL are preserved.
func (c Config) BuildAuthorizeURL(state, redirectURI string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(state) == "" || strings.TrimSpace(redirectURI) == "" {
		return "", errors.New("IAM state and redirect URI are required")
	}
	if err := validateHTTPURL(redirectURI); err != nil {
		return "", fmt.Errorf("IAM redirect URI is invalid: %w", err)
	}
	u, err := url.Parse(c.AuthorizeURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	if len(c.Scopes) > 0 {
		q.Set("scope", strings.Join(c.Scopes, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Exchange trades an authorization code for an access token. The returned
// access token is used only to read the userinfo endpoint.
func (c Config) Exchange(ctx context.Context, code, redirectURI string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", errors.New("IAM authorization code is empty")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", errors.New("IAM redirect URI is empty")
	}
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {c.ClientID},
	}
	method := c.TokenAuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if method == "client_secret_post" && c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "LoopForge")
	if method == "client_secret_basic" && c.ClientSecret != "" {
		// RFC 6749 section 2.3.1 requires form-encoding the credentials
		// before Basic authentication.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	status, body, err := do(req)
	if err != nil {
		return "", err
	}
	raw, parseErr := parseTokenResponse(body)
	if parseErr != nil {
		return "", fmt.Errorf("IAM token response is invalid: %s", redact(c, truncate(string(body), 180)))
	}
	if raw.Error != "" || raw.ErrorDescription != "" {
		msg := raw.ErrorDescription
		if msg == "" {
			msg = raw.Error
		}
		return "", fmt.Errorf("IAM token exchange failed: %s", redact(c, truncate(msg, 180)))
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return "", fmt.Errorf("IAM token endpoint returned HTTP %d: %s", status, redact(c, truncate(string(body), 180)))
	}
	if strings.TrimSpace(raw.AccessToken) == "" {
		return "", errors.New("IAM token response has no access_token")
	}
	return raw.AccessToken, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// parseTokenResponse accepts both the usual JSON response and the
// application/x-www-form-urlencoded form some providers still return.
func parseTokenResponse(body []byte) (tokenResponse, error) {
	var raw tokenResponse
	if err := json.Unmarshal(body, &raw); err == nil {
		return raw, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return tokenResponse{}, err
	}
	if values.Get("access_token") == "" && values.Get("error") == "" && values.Get("error_description") == "" {
		return tokenResponse{}, errors.New("empty token response")
	}
	return tokenResponse{
		AccessToken:      values.Get("access_token"),
		TokenType:        values.Get("token_type"),
		Error:            values.Get("error"),
		ErrorDescription: values.Get("error_description"),
	}, nil
}

// UserInfo returns the JSON object behind an access token.
func (c Config) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, errors.New("IAM access token is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "LoopForge")
	status, body, err := do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("IAM userinfo returned HTTP %d", status)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var info map[string]any
	if err := decoder.Decode(&info); err != nil {
		return nil, errors.New("IAM userinfo returned invalid JSON")
	}
	if info == nil {
		return nil, errors.New("IAM userinfo returned an empty object")
	}
	return info, nil
}

// Identity is the platform-relevant part of an IAM userinfo response.
type Identity struct {
	Subject string
	Login   string
	Name    string
}

// Identity extracts the stable subject and display claims from userinfo.
// Login and name fall back to common claim names so a deployment only needs to
// configure SubjectClaim when its provider follows the usual conventions.
func (c Config) Identity(info map[string]any) (Identity, error) {
	subject := claimString(info, c.SubjectClaim)
	if subject == "" {
		return Identity{}, fmt.Errorf("IAM userinfo has no %q claim", c.SubjectClaim)
	}
	login := firstClaim(info, c.LoginClaim, "preferred_username", "login", "username", "email")
	if login == "" {
		login = subject
	}
	name := firstClaim(info, c.NameClaim, "name", "display_name", "nickname")
	if name == "" {
		name = login
	}
	return Identity{Subject: subject, Login: login, Name: name}, nil
}

func firstClaim(info map[string]any, claims ...string) string {
	seen := map[string]bool{}
	for _, claim := range claims {
		claim = strings.TrimSpace(claim)
		if claim == "" || seen[claim] {
			continue
		}
		seen[claim] = true
		if value := claimString(info, claim); value != "" {
			return value
		}
	}
	return ""
}

// claimString resolves a top-level or dot-separated claim and renders scalar
// values as text. Objects and arrays are ignored.
func claimString(info map[string]any, claim string) string {
	claim = strings.TrimSpace(claim)
	if claim == "" {
		return ""
	}
	var value any = info
	for _, part := range strings.Split(claim, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value, ok = object[part]
		if !ok {
			return ""
		}
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return ""
	}
}

func do(req *http.Request) (int, []byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cannot reach IAM endpoint: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func redact(c Config, msg string) string {
	if c.ClientSecret != "" {
		msg = strings.ReplaceAll(msg, c.ClientSecret, "***")
	}
	return msg
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func envTrim(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func envOrDefault(key, fallback string) string {
	if value := envTrim(key); value != "" {
		return value
	}
	return fallback
}

func splitScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field = strings.TrimSpace(field); field != "" {
			out = append(out, field)
		}
	}
	return out
}

func providerName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultProviderName
	}
	raw = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultProviderName
	}
	if runes := []rune(raw); len(runes) > 40 {
		raw = string(runes[:40])
	}
	return raw
}

func tokenAuthMethod(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "client_secret_basic", "basic":
		return "client_secret_basic"
	case "client_secret_post", "post":
		return "client_secret_post"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}
