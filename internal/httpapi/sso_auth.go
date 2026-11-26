package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"unicode/utf8"

	"agentflow/internal/auth"
	"agentflow/internal/domain"
	"agentflow/internal/repo"
)

// ssoIdentity is the provider-neutral identity produced by OAuth2 IAM.
type ssoIdentity struct {
	Subject string
	Login   string
	Name    string
}

// ssoPolicy controls whether an unknown identity may create an account and
// whether a login-name collision may bind to an existing platform account.
type ssoPolicy struct {
	AutoProvision string
	LinkExisting  bool
}

var (
	errSSOSignupDisabled  = errors.New("sso auto-provision is disabled")
	errSSOLoginConflict   = errors.New("sso login name is already taken")
	errSSOAccountLinked   = errors.New("sso account is already linked to another identity")
	errSSOLinkDisabled    = errors.New("sso linking existing accounts is disabled")
	errSSOAccountMissing  = errors.New("sso account is missing")
	errSSOProvision       = errors.New("sso account provisioning failed")
)

// resolveExternalUser maps a stable provider subject to a platform user. An
// existing login name is linked to that platform account and keeps all of its
// roles and credentials, but an account already bound to another subject for
// the same provider is never taken over.
func (h *authHandlers) resolveExternalUser(provider string, identity ssoIdentity, policy ssoPolicy) (*auth.User, error) {
	if h.repo == nil {
		return nil, errSSOProvision
	}
	if userID, ok := h.repo.ExternalIdentityUser(provider, identity.Subject); ok {
		return h.ssoStoredUser(userID)
	}
	registerMu.Lock()
	defer registerMu.Unlock()
	if userID, ok := h.repo.ExternalIdentityUser(provider, identity.Subject); ok {
		return h.ssoStoredUser(userID)
	}
	login := sanitizeSSOLogin(identity.Login, identity.Subject)
	if existing, ok := h.repo.UserByLoginName(login); ok {
		return h.ssoLinkExistingUser(provider, existing, identity, policy)
	}
	if !h.ssoProvisionAllowed(policy) {
		return nil, errSSOSignupDisabled
	}
	first := h.repo.UserCount() == 0
	candidate := domain.User{
		LoginName:   login,
		ChineseName: ssoDisplayName(identity.Name, login),
	}
	if first {
		candidate.PlatformRole = domain.PlatformRoleAdmin
	}
	stored, err := h.repo.CreateUser(candidate)
	if errors.Is(err, repo.ErrLoginTaken) {
		return nil, errSSOLoginConflict
	}
	if err != nil {
		log.Printf("[auth] %s create user %s failed: %v", provider, login, err)
		return nil, errSSOProvision
	}
	if err := h.repo.LinkExternalIdentity(provider, identity.Subject, stored.ID); err != nil {
		if errors.Is(err, repo.ErrExternalIdentityTaken) {
			// Another API instance provisioned the same subject while this
			// request waited. Prefer the existing mapping over a duplicate.
			if userID, ok := h.repo.ExternalIdentityUser(provider, identity.Subject); ok {
				return h.ssoStoredUser(userID)
			}
		}
		log.Printf("[auth] %s link identity failed: %v", provider, err)
		return nil, errSSOProvision
	}
	if !first {
		h.joinWelcomeProject(stored.ID)
	}
	user := domainUserToAuth(stored)
	user.AvatarURL = auth.AvatarURL(stored.LoginName, 100)
	return user, nil
}

// ssoLinkExistingUser binds an external subject to a platform account that
// already uses the same login name. The platform account keeps its role,
// display name, password and credentials; only the identity mapping is added.
func (h *authHandlers) ssoLinkExistingUser(provider string, existing domain.User, identity ssoIdentity, policy ssoPolicy) (*auth.User, error) {
	if policy.AutoProvision == "never" || !policy.LinkExisting {
		return nil, errSSOLinkDisabled
	}
	if subject, ok := h.repo.ExternalIdentityForUser(provider, existing.ID); ok {
		if subject != identity.Subject {
			return nil, errSSOAccountLinked
		}
		return h.ssoStoredUser(existing.ID)
	}
	if err := h.repo.LinkExternalIdentity(provider, identity.Subject, existing.ID); err != nil {
		switch {
		case errors.Is(err, repo.ErrExternalIdentityTaken):
			// Another API instance resolved the same subject first. The
			// subject's existing mapping is authoritative.
			if userID, ok := h.repo.ExternalIdentityUser(provider, identity.Subject); ok {
				return h.ssoStoredUser(userID)
			}
			return nil, errSSOLoginConflict
		case errors.Is(err, repo.ErrExternalIdentityUserLinked):
			return nil, errSSOAccountLinked
		default:
			log.Printf("[auth] %s link existing account %s failed: %v", provider, existing.LoginName, err)
			return nil, errSSOProvision
		}
	}
	log.Printf("[auth] %s linked existing platform account %s (user %d)", provider, existing.LoginName, existing.ID)
	return h.ssoStoredUser(existing.ID)
}

func (h *authHandlers) ssoStoredUser(userID int64) (*auth.User, error) {
	stored, ok := h.repo.User(userID)
	if !ok {
		return nil, errSSOAccountMissing
	}
	user := domainUserToAuth(stored)
	user.AvatarURL = auth.AvatarURL(stored.LoginName, 100)
	return user, nil
}

func (h *authHandlers) ssoProvisionAllowed(policy ssoPolicy) bool {
	switch policy.AutoProvision {
	case "always":
		return true
	case "never":
		return false
	default:
		return signupEnabled() || h.repo.UserCount() == 0
	}
}

func ssoErrorCode(err error) string {
	switch {
	case errors.Is(err, errSSOSignupDisabled):
		return "signup_disabled"
	case errors.Is(err, errSSOLoginConflict):
		return "login_conflict"
	case errors.Is(err, errSSOAccountLinked):
		return "account_linked"
	case errors.Is(err, errSSOLinkDisabled):
		return "link_disabled"
	case errors.Is(err, errSSOAccountMissing):
		return "account_missing"
	default:
		return "provision_failed"
	}
}

// sanitizeSSOLogin turns an external login claim into a platform login name.
// Values that cannot produce a legal name fall back to a subject-derived one,
// so the platform never stores an unusable row.
func sanitizeSSOLogin(raw, subject string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if isSSOLoginRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	login := strings.Trim(b.String(), "-._")
	if len(login) > 64 {
		login = strings.TrimRight(login[:64], "-._")
	}
	if !validSSOLogin(login) {
		sum := sha256.Sum256([]byte(subject))
		login = "sso-" + hex.EncodeToString(sum[:])[:12]
	}
	return login
}

func isSSOLoginRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '_' || r == '.' || r == '-':
		return true
	default:
		return false
	}
}

func validSSOLogin(login string) bool {
	if len(login) < 2 || len(login) > 64 {
		return false
	}
	first := login[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, r := range login {
		if !isSSOLoginRune(r) {
			return false
		}
	}
	return true
}

func ssoDisplayName(raw, fallback string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = fallback
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if name == "" {
		name = fallback
	}
	if utf8.RuneCountInString(name) > 128 {
		name = string([]rune(name)[:128])
	}
	return name
}
