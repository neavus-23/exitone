package hypothesis

import (
	"testing"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

func newTestFixture(t *testing.T) (s *store.Store, sessionID, entityID, evidenceID string) {
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
	entityID = uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES (?, ?, 'service', '10.0.0.1:445/tcp', ?, ?)`,
		entityID, sessionID, now, now,
	); err != nil {
		t.Fatalf("insert entity: %v", err)
	}
	evidenceID = uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO evidence(id, raw_output_ref, tool_name, parse_level, created_at) VALUES (?, '/tmp/x', 'smbclient', 1, ?)`,
		evidenceID, now,
	); err != nil {
		t.Fatalf("insert evidence: %v", err)
	}
	return s, sessionID, entityID, evidenceID
}

func newObservation(t *testing.T, s *store.Store, evidenceID, kind string) string {
	t.Helper()
	obsID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status) VALUES (?, ?, ?, '{}', 1.0, 'active')`,
		obsID, evidenceID, kind,
	); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	return obsID
}

func TestOpen_StartsUntested(t *testing.T) {
	s, sessionID, entityID, _ := newTestFixture(t)
	hypID, err := Open(s, sessionID, entityID, "test hypothesis")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	exp, err := Explain(s, hypID[:8])
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if exp.Status != Untested || exp.SupportingObservations != 0 || exp.ContradictingObservations != 0 {
		t.Errorf("Explain = %+v, want untested/0/0", exp)
	}
}

func TestSupportAndContradict_RecomputeStatusByPresenceNotCount(t *testing.T) {
	s, sessionID, entityID, evidenceID := newTestFixture(t)
	hypID, _ := Open(s, sessionID, entityID, "test hypothesis")

	obs1 := newObservation(t, s, evidenceID, "fact")
	if err := Support(s, hypID, obs1); err != nil {
		t.Fatalf("Support: %v", err)
	}
	exp, _ := Explain(s, hypID[:8])
	if exp.Status != Supported {
		t.Errorf("status tras 1 support = %s, want supported", exp.Status)
	}

	// Un SEGUNDO support NO debe convertirse en una fuerza mayor — sigue
	// siendo categórico "supported", nunca "strong"/"muy soportado".
	obs2 := newObservation(t, s, evidenceID, "fact")
	if err := Support(s, hypID, obs2); err != nil {
		t.Fatalf("Support (2do): %v", err)
	}
	exp, _ = Explain(s, hypID[:8])
	if exp.Status != Supported || exp.SupportingObservations != 2 {
		t.Errorf("tras 2 supports = %+v, want status=supported con conteo=2 (nunca una fuerza derivada)", exp)
	}

	obs3 := newObservation(t, s, evidenceID, "fact")
	if err := Contradict(s, hypID, obs3); err != nil {
		t.Fatalf("Contradict: %v", err)
	}
	exp, _ = Explain(s, hypID[:8])
	if exp.Status != Disputed {
		t.Errorf("status tras support+contradict = %s, want disputed", exp.Status)
	}
}

func TestContradictOnly_MeansRefuted(t *testing.T) {
	s, sessionID, entityID, evidenceID := newTestFixture(t)
	hypID, _ := Open(s, sessionID, entityID, "test hypothesis")
	obs := newObservation(t, s, evidenceID, "fact")
	if err := Contradict(s, hypID, obs); err != nil {
		t.Fatalf("Contradict: %v", err)
	}
	exp, _ := Explain(s, hypID[:8])
	if exp.Status != Refuted {
		t.Errorf("status = %s, want refuted", exp.Status)
	}
}

// TestGenuineReopening reproduce el ejemplo H01 del plan de arquitectura: una
// hipótesis se soporta y se cierra explícitamente (CONFIRMED), y solo se
// reabre cuando una observation 'contradicts' llega DESPUÉS de ese cierre —
// no por aparecer una entidad nueva de cierto tipo en general.
func TestGenuineReopening(t *testing.T) {
	s, sessionID, entityID, evidenceID := newTestFixture(t)
	hypID, err := Open(s, sessionID, entityID, "El acceso anónimo a SMB no está disponible")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	obsA := newObservation(t, s, evidenceID, "smb_auth_denied")
	if err := Support(s, hypID, obsA); err != nil {
		t.Fatalf("Support: %v", err)
	}
	if err := Confirm(s, hypID); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	exp, _ := Explain(s, hypID[:8])
	if exp.Status != Confirmed {
		t.Fatalf("status tras Confirm = %s, want confirmed", exp.Status)
	}

	// Más soporte tras el cierre NO debe reabrir nada (Support nunca reabre).
	obsExtra := newObservation(t, s, evidenceID, "smb_auth_denied")
	if err := Support(s, hypID, obsExtra); err != nil {
		t.Fatalf("Support (post-cierre): %v", err)
	}
	exp, _ = Explain(s, hypID[:8])
	if exp.Status != Confirmed {
		t.Errorf("un Support post-cierre cambió el status a %s, want que siga confirmed", exp.Status)
	}

	// Observation B: listado anónimo exitoso desde otro endpoint/config —
	// esto SÍ contradice específicamente el cierre anterior.
	obsB := newObservation(t, s, evidenceID, "smb_anonymous_listing_succeeded")
	if err := Contradict(s, hypID, obsB); err != nil {
		t.Fatalf("Contradict: %v", err)
	}
	exp, _ = Explain(s, hypID[:8])
	if exp.Status != Reopened {
		t.Errorf("status tras contradicción post-cierre = %s, want reopened (reapertura genuina)", exp.Status)
	}
}

func TestExplain_UnknownPrefix(t *testing.T) {
	s, sessionID, _, _ := newTestFixture(t)
	_ = sessionID
	if _, err := Explain(s, "doesnotexist"); err == nil {
		t.Error("Explain(prefijo inexistente) = nil error, want error")
	}
}
