package repo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ErrExternalIdentityTaken means the provider subject is already linked to a
// different platform user. Callers must never silently re-link it.
var ErrExternalIdentityTaken = errors.New("external identity is already linked to another user")

// ErrExternalIdentityUserLinked means the platform user already has a
// different subject for this provider. One platform account may keep only one
// IAM identity, so a login-name collision cannot replace an existing binding.
var ErrExternalIdentityUserLinked = errors.New("user already has an external identity for this provider")

// externalIdentityRow maps a stable external subject (for example an IAM
// "sub") to one platform user. The subject hash is the primary lookup key so
// the mapping stays case-sensitive even on MySQL's case-insensitive default
// collation; the plain subject is retained for operator inspection. The
// (provider, user_id) unique index allows at most one identity per provider
// for a platform account.
type externalIdentityRow struct {
	Provider    string     `gorm:"column:provider;primaryKey;size:32;uniqueIndex:uq_user_external_identities_user"`
	SubjectHash string     `gorm:"column:subject_hash;primaryKey;size:64"`
	Subject     string     `gorm:"column:subject;size:255;not null"`
	UserID      int64      `gorm:"column:user_id;uniqueIndex:uq_user_external_identities_user;not null"`
	Created     *time.Time `gorm:"column:created_at"`
	Updated     *time.Time `gorm:"column:updated_at"`
}

func (externalIdentityRow) TableName() string { return "user_external_identities" }

func externalSubjectHash(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

// ExternalIdentityUser resolves an external subject to a platform user id.
func (r *UsersRepo) ExternalIdentityUser(provider, subject string) (int64, bool) {
	provider = strings.TrimSpace(provider)
	subject = strings.TrimSpace(subject)
	if provider == "" || subject == "" {
		return 0, false
	}
	var row externalIdentityRow
	err := r.DB.Where("provider = ? AND subject_hash = ?", provider, externalSubjectHash(subject)).Take(&row).Error
	if err != nil || row.UserID <= 0 {
		return 0, false
	}
	return row.UserID, true
}

// ExternalIdentityForUser returns the provider subject already bound to a
// platform user. A user has at most one subject per provider.
func (r *UsersRepo) ExternalIdentityForUser(provider string, userID int64) (string, bool) {
	provider = strings.TrimSpace(provider)
	if provider == "" || userID <= 0 {
		return "", false
	}
	var row externalIdentityRow
	err := r.DB.Where("provider = ? AND user_id = ?", provider, userID).Take(&row).Error
	if err != nil || row.Subject == "" {
		return "", false
	}
	return row.Subject, true
}

// LinkExternalIdentity binds an external subject to a platform user. The
// operation is idempotent for the same subject/user pair. It refuses to link a
// subject already owned by someone else, and refuses to replace a different
// subject already bound to the same user.
func (r *UsersRepo) LinkExternalIdentity(provider, subject string, userID int64) error {
	provider = strings.TrimSpace(provider)
	subject = strings.TrimSpace(subject)
	if provider == "" || subject == "" || userID <= 0 {
		return errors.New("external identity provider, subject, and user are required")
	}
	if len(provider) > 32 || len(subject) > 255 {
		return errors.New("external identity provider or subject is too long")
	}
	if _, ok := r.User(userID); !ok {
		return errors.New("user not found")
	}
	now := time.Now().UTC()
	hash := externalSubjectHash(subject)
	inserted, err := insertIgnore(r.DB, "user_external_identities", map[string]any{
		"provider":     provider,
		"subject_hash": hash,
		"subject":      subject,
		"user_id":      userID,
		"created_at":   timePtr(now),
		"updated_at":   timePtr(now),
	})
	if err != nil {
		return err
	}
	if inserted {
		return nil
	}
	// The insert was ignored because either the subject or the user already
	// has a row. Distinguish the two so callers can report the right error.
	if existingUserID, ok := r.ExternalIdentityUser(provider, subject); ok {
		if existingUserID == userID {
			return nil
		}
		return ErrExternalIdentityTaken
	}
	if _, ok := r.ExternalIdentityForUser(provider, userID); ok {
		return ErrExternalIdentityUserLinked
	}
	return errors.New("external identity was not inserted")
}
