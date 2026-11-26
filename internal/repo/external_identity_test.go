package repo

import (
	"errors"
	"testing"

	"agentflow/internal/domain"
)

func TestExternalIdentityMapping(t *testing.T) {
	st, err := OpenTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	before := st.UserCount()
	alice, err := st.CreateLocalAccount("iam-alice", "password-1", false)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := st.CreateLocalAccount("iam-bob", "password-2", false)
	if err != nil {
		t.Fatal(err)
	}
	if after := st.UserCount(); after != before+2 {
		t.Fatalf("user count = %d want %d", after, before+2)
	}
	if _, err := st.CreateUser(domain.User{LoginName: "iam-alice"}); !errors.Is(err, ErrLoginTaken) {
		t.Fatalf("CreateUser must not adopt an existing login: %v", err)
	}

	if err := st.LinkExternalIdentity("iam", "subject-1", alice.ID); err != nil {
		t.Fatal(err)
	}
	if got, ok := st.ExternalIdentityUser("iam", "subject-1"); !ok || got != alice.ID {
		t.Fatalf("mapping = %d ok=%v want %d", got, ok, alice.ID)
	}
	// Re-linking the same subject to the same user is idempotent.
	if err := st.LinkExternalIdentity("iam", "subject-1", alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.LinkExternalIdentity("iam", "subject-1", bob.ID); !errors.Is(err, ErrExternalIdentityTaken) {
		t.Fatalf("conflicting link error = %v", err)
	}
	if got, _ := st.ExternalIdentityUser("iam", "subject-1"); got != alice.ID {
		t.Fatalf("conflict changed mapping to %d", got)
	}

	// MySQL's default collation is case-insensitive, so different-case
	// subjects must remain distinct identities.
	if err := st.LinkExternalIdentity("iam", "SUBJECT-1", bob.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ExternalIdentityUser("iam", "SUBJECT-1"); got != bob.ID {
		t.Fatalf("uppercase mapping = %d want %d", got, bob.ID)
	}
	if got, _ := st.ExternalIdentityUser("iam", "subject-1"); got != alice.ID {
		t.Fatalf("lowercase mapping = %d want %d", got, alice.ID)
	}
	if subject, ok := st.ExternalIdentityForUser("iam", alice.ID); !ok || subject != "subject-1" {
		t.Fatalf("user identity = %q ok=%v", subject, ok)
	}
	// One platform account keeps at most one IAM identity.
	if err := st.LinkExternalIdentity("iam", "subject-2", alice.ID); !errors.Is(err, ErrExternalIdentityUserLinked) {
		t.Fatalf("second identity for a user = %v", err)
	}

	// Providers are isolated from each other.
	if _, ok := st.ExternalIdentityUser("other", "subject-1"); ok {
		t.Fatal("unknown provider must not resolve")
	}
	if _, ok := st.ExternalIdentityUser("iam", " "); ok {
		t.Fatal("empty subject must not resolve")
	}
	if err := st.LinkExternalIdentity("iam", "subject-2", 0); err == nil {
		t.Fatal("missing user id must be rejected")
	}
	if err := st.LinkExternalIdentity("iam", "subject-2", 999999); err == nil {
		t.Fatal("unknown user must be rejected")
	}
}
