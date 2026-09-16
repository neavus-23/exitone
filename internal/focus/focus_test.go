package focus

import (
	"testing"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

func newTestSession(t *testing.T) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	sessionID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO session(id, target_label, started_at) VALUES (?, ?, ?)`,
		sessionID, "test-target", now,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return s, sessionID
}

func TestSetGetClear(t *testing.T) {
	s, sessionID := newTestSession(t)

	if f, err := Get(s, sessionID); err != nil || f != nil {
		t.Fatalf("Get antes de Set = %+v, %v — want nil, nil", f, err)
	}

	hypID := uuid.NewString()
	if err := Set(s, sessionID, "hypothesis", hypID); err != nil {
		t.Fatalf("Set: %v", err)
	}
	f, err := Get(s, sessionID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if f == nil || f.RefType != "hypothesis" || f.RefID != hypID {
		t.Fatalf("Get = %+v, want hypothesis/%s", f, hypID)
	}

	// Set de nuevo reemplaza (un solo focus activo por sesión).
	objID := uuid.NewString()
	if err := Set(s, sessionID, "objective", objID); err != nil {
		t.Fatalf("Set (reemplazo): %v", err)
	}
	f, err = Get(s, sessionID)
	if err != nil || f == nil || f.RefType != "objective" || f.RefID != objID {
		t.Fatalf("Get tras reemplazo = %+v, %v — want objective/%s", f, err, objID)
	}

	if err := Clear(s, sessionID); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if f, err := Get(s, sessionID); err != nil || f != nil {
		t.Fatalf("Get tras Clear = %+v, %v — want nil, nil", f, err)
	}
	// Clear sin focus activo no debe fallar.
	if err := Clear(s, sessionID); err != nil {
		t.Fatalf("Clear (sin focus activo): %v", err)
	}
}

func TestResolve(t *testing.T) {
	s, sessionID := newTestSession(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	entityID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES (?, ?, 'host', '10.0.0.1', ?, ?)`,
		entityID, sessionID, now, now,
	); err != nil {
		t.Fatalf("insert entity: %v", err)
	}

	hypID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO hypothesis(id, session_id, statement, subject_entity_id, status, confidence, opened_at) VALUES (?, ?, ?, ?, 'open', 0, ?)`,
		hypID, sessionID, "test hypothesis", entityID, now,
	); err != nil {
		t.Fatalf("insert hypothesis: %v", err)
	}
	objID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO methodology_objective(id, session_id, intent_key, trigger_entity_id, status, created_at) VALUES (?, ?, 'test_intent', ?, 'open', ?)`,
		objID, sessionID, entityID, now,
	); err != nil {
		t.Fatalf("insert objective: %v", err)
	}

	refType, refID, err := Resolve(s, sessionID, hypID[:8])
	if err != nil || refType != "hypothesis" || refID != hypID {
		t.Errorf("Resolve(hypothesis prefix) = %s/%s, %v — want hypothesis/%s", refType, refID, err, hypID)
	}

	refType, refID, err = Resolve(s, sessionID, objID[:8])
	if err != nil || refType != "objective" || refID != objID {
		t.Errorf("Resolve(objective prefix) = %s/%s, %v — want objective/%s", refType, refID, err, objID)
	}

	if _, _, err := Resolve(s, sessionID, "nonexistent"); err == nil {
		t.Error("Resolve(prefijo inexistente) = nil error, want error")
	}
}
