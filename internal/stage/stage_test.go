package stage

import (
	"path/filepath"
	"testing"
	"time"

	"exitone/internal/store"
)

func newTestSession(t *testing.T) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "stage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sessionID := "sess-1"
	if _, err := s.DB.Exec(`INSERT INTO session(id, target_label, started_at) VALUES (?, 'target', ?)`, sessionID, now); err != nil {
		t.Fatal(err)
	}
	return s, sessionID
}

func stageByName(t *testing.T, stages []Stage, name string) Stage {
	t.Helper()
	for _, st := range stages {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no se encontró la etapa %q entre %d etapas devueltas", name, len(stages))
	return Stage{}
}

func TestEstimateDiscoveryNotStartedWithoutServices(t *testing.T) {
	s, sessionID := newTestSession(t)
	stages, err := Estimate(s, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stageByName(t, stages, "discovery"); got.Status != NotStarted {
		t.Fatalf("discovery = %s, want NOT_STARTED (razón: %s)", got.Status, got.Reason)
	}
}

func TestEstimateDiscoverySufficientWhenObjectiveAnswered(t *testing.T) {
	s, sessionID := newTestSession(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES ('svc-1', ?, 'service', '10.0.0.1:80/tcp', ?, ?)`, sessionID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`
		INSERT INTO methodology_objective(id, session_id, phase_key, intent_key, trigger_entity_id, status, created_at)
		VALUES ('obj-1', ?, 'discovery', 'initial_discovery', 'svc-1', 'answered', ?)`, sessionID, now); err != nil {
		t.Fatal(err)
	}

	stages, err := Estimate(s, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stageByName(t, stages, "discovery"); got.Status != Sufficient {
		t.Fatalf("discovery = %s, want SUFFICIENT (razón: %s)", got.Status, got.Reason)
	}
}

// TestEstimateValidationCreditsConfirmedHypotheses cubre el bug real
// encontrado validando ExitOne contra HTB Nexus: la validación real se hizo
// confirmando/refutando hipótesis directamente (`hypothesis confirm`), sin
// pasar nunca por el loop next→accept→resolve — la etapa no debe quedar
// ciega a ese trabajo solo porque no hay ninguna `action` con
// phase_key='validation'.
func TestEstimateValidationCreditsConfirmedHypotheses(t *testing.T) {
	s, sessionID := newTestSession(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES ('host-1', ?, 'host', '10.0.0.1', ?, ?)`, sessionID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`
		INSERT INTO hypothesis(id, session_id, statement, subject_entity_id, status, opened_at, closed_at)
		VALUES ('hyp-1', ?, 'RCE confirmado', 'host-1', 'confirmed', ?, ?)`, sessionID, now, now); err != nil {
		t.Fatal(err)
	}

	stages, err := Estimate(s, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stageByName(t, stages, "validation"); got.Status == NotStarted {
		t.Fatalf("validation = %s, want distinto de NOT_STARTED con una hipótesis confirmada (razón: %s)", got.Status, got.Reason)
	}
}
