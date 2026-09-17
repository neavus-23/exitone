package credential

import (
	"path/filepath"
	"testing"
	"time"

	"exitone/internal/store"
)

func TestMask(t *testing.T) {
	if got := Mask("Password123"); got == "Password123" || got != "P**********" {
		t.Fatalf("Mask inesperado: %q", got)
	}
	if got := Mask("🔐secreto"); got != "🔐*******" {
		t.Fatalf("Mask debe conservar UTF-8 válido: %q", got)
	}
}

func TestRevealReturnsOnlyExactCredentialInSession(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "credential.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO session(id, target_label, started_at) VALUES ('s1', 'one', ?), ('s2', 'two', ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`
		INSERT INTO credential(id, session_id, secret_value, secret_fingerprint, source_ref, status, created_at)
		VALUES ('cred-1', 's1', 'correct horse', 'fp-1', 'test', 'discovered', ?),
		       ('cred-2', 's2', 'other secret', 'fp-2', 'test', 'discovered', ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	value, err := Reveal(s, "s1", "cred-1")
	if err != nil || value != "correct horse" {
		t.Fatalf("Reveal() value=%q err=%v", value, err)
	}
	if _, err := Reveal(s, "s1", "cred-2"); err == nil {
		t.Fatal("Reveal() crossed session boundary")
	}
}
