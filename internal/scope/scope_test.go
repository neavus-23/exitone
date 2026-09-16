package scope

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"exitone/internal/store"
)

func newTestSession(t *testing.T) (s *store.Store, sessionID string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	sessionID = uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO session(id, target_label, started_at) VALUES (?, ?, ?)`, sessionID, "test-target", now); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return s, sessionID
}

func TestCheck_NoRulesIsUnknown(t *testing.T) {
	s, sessionID := newTestSession(t)
	status, _, err := Check(s, sessionID, "192.168.1.1")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != Unknown {
		t.Errorf("status = %q, want unknown", status)
	}
}

func TestCheck_InScopeMatch(t *testing.T) {
	s, sessionID := newTestSession(t)
	if _, err := Add(s, sessionID, "example.com", true, "programa HackerOne"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	status, pattern, err := Check(s, sessionID, "api.example.com")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != In {
		t.Errorf("status = %q, want in", status)
	}
	if pattern != "example.com" {
		t.Errorf("pattern = %q, want example.com", pattern)
	}
}

func TestCheck_ExclusionWinsOverInScope(t *testing.T) {
	s, sessionID := newTestSession(t)
	if _, err := Add(s, sessionID, "example.com", true, "scope general"); err != nil {
		t.Fatalf("Add in-scope: %v", err)
	}
	if _, err := Add(s, sessionID, "internal.example.com", false, "excluido explícitamente"); err != nil {
		t.Fatalf("Add exclusion: %v", err)
	}
	status, pattern, err := Check(s, sessionID, "internal.example.com")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != Out {
		t.Errorf("status = %q, want out (la exclusión debe ganar)", status)
	}
	if pattern != "internal.example.com" {
		t.Errorf("pattern = %q, want internal.example.com", pattern)
	}
}

func TestCheck_UnrelatedValueIsUnknown(t *testing.T) {
	s, sessionID := newTestSession(t)
	if _, err := Add(s, sessionID, "example.com", true, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	status, _, err := Check(s, sessionID, "totally-unrelated.org")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != Unknown {
		t.Errorf("status = %q, want unknown", status)
	}
}

func TestRemove_ByIDPrefix(t *testing.T) {
	s, sessionID := newTestSession(t)
	id, err := Add(s, sessionID, "example.com", true, "")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := Remove(s, sessionID, id[:8]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rules, err := List(s, sessionID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("List() after Remove = %d rules, want 0", len(rules))
	}
}

func TestRemove_ByExactPattern(t *testing.T) {
	s, sessionID := newTestSession(t)
	if _, err := Add(s, sessionID, "example.com", true, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := Remove(s, sessionID, "example.com"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	rules, _ := List(s, sessionID)
	if len(rules) != 0 {
		t.Errorf("List() after Remove = %d rules, want 0", len(rules))
	}
}

func TestRemove_NoMatchIsError(t *testing.T) {
	s, sessionID := newTestSession(t)
	if err := Remove(s, sessionID, "nope"); err == nil {
		t.Error("Remove sin coincidencias = nil error, want error")
	}
}

func TestRemove_AmbiguousIDPrefixIsError(t *testing.T) {
	s, sessionID := newTestSession(t)
	// Insertamos dos reglas y forzamos un prefijo de ID compartido buscando
	// con un prefijo vacío-ish improbable de colisionar naturalmente no
	// aplica aquí; en su lugar probamos que dos patterns con substring
	// mutuo (uno contenido en el otro) generan match ambiguo por pattern.
	if _, err := Add(s, sessionID, "example.com", true, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := Add(s, sessionID, "example.com", false, "duplicado deliberado"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := Remove(s, sessionID, "example.com"); err == nil {
		t.Error("Remove con 2 reglas del mismo pattern = nil error, want listado de ambigüedad")
	}
}

func TestList_OrderedNewestFirst(t *testing.T) {
	s, sessionID := newTestSession(t)
	if _, err := Add(s, sessionID, "first.com", true, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := Add(s, sessionID, "second.com", true, ""); err != nil {
		t.Fatalf("Add: %v", err)
	}
	rules, err := List(s, sessionID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 2 || rules[0].Pattern != "second.com" {
		t.Errorf("List() = %+v, want second.com primero", rules)
	}
}
