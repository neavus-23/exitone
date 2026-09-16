package strategy

import (
	"testing"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

func newTestSessionForRabbitHole(t *testing.T) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	sessionID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO session(id, target_label, started_at) VALUES (?, ?, ?)`, sessionID, "t", now); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return s, sessionID
}

// makeStagnantBranch inserta N acciones resueltas sobre el mismo
// objective_path con el mismo intent_key, cada una con outcome sin
// entidades/relaciones nuevas — la rama "estancada" que DetectRabbitHole
// debe reconocer.
func makeStagnantBranch(t *testing.T, s *store.Store, sessionID string, attempts int) (pathID string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	entityID := uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES (?, ?, 'service', 'svc', ?, ?)`, entityID, sessionID, now, now); err != nil {
		t.Fatalf("insert entity: %v", err)
	}
	objID := uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO methodology_objective(id, session_id, intent_key, trigger_entity_id, status, created_at) VALUES (?, ?, 'x', ?, 'open', ?)`, objID, sessionID, entityID, now); err != nil {
		t.Fatalf("insert objective: %v", err)
	}
	pathID = uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO objective_path(id, objective_id, path_key, description, status, created_at) VALUES (?, ?, 'stagnant_path', 'stagnant path', 'open', ?)`, pathID, objID, now); err != nil {
		t.Fatalf("insert objective_path: %v", err)
	}

	for i := 0; i < attempts; i++ {
		candID := uuid.NewString()
		if _, err := s.DB.Exec(`
			INSERT INTO candidate(id, session_id, source, objective_path_id, intent_key, parameters, tool, command_template_rendered, score, score_terms, explanation, created_at, status)
			VALUES (?, ?, 'methodology', ?, 'test_intent', '{}', 'x', 'x', 0, '{}', 'x', ?, 'accepted')`,
			candID, sessionID, pathID, now,
		); err != nil {
			t.Fatalf("insert candidate: %v", err)
		}
		actID := uuid.NewString()
		if _, err := s.DB.Exec(`INSERT INTO action(id, candidate_id, objective_path_id, executed_at, status) VALUES (?, ?, ?, ?, 'resolved')`, actID, candID, pathID, now); err != nil {
			t.Fatalf("insert action: %v", err)
		}
		outID := uuid.NewString()
		if _, err := s.DB.Exec(`
			INSERT INTO outcome(id, action_id, new_entities, new_relationships, hypotheses_confirmed, hypotheses_refuted, contradictions_resolved, computed_information_gain, recorded_at)
			VALUES (?, ?, 0, 0, 0, 0, 0, 0.1, ?)`,
			outID, actID, now,
		); err != nil {
			t.Fatalf("insert outcome: %v", err)
		}
	}
	return pathID
}

// makeUntriedAlternative inserta un segundo objective_path abierto con un
// candidato 'proposed' que nunca se intentó — la "rama alternativa con
// evidencia sin probar" que DetectRabbitHole debe encontrar.
func makeUntriedAlternative(t *testing.T, s *store.Store, sessionID string) (pathID, description string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	entityID := uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES (?, ?, 'service', 'svc2', ?, ?)`, entityID, sessionID, now, now); err != nil {
		t.Fatalf("insert entity: %v", err)
	}
	objID := uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO methodology_objective(id, session_id, intent_key, trigger_entity_id, status, created_at) VALUES (?, ?, 'y', ?, 'open', ?)`, objID, sessionID, entityID, now); err != nil {
		t.Fatalf("insert objective: %v", err)
	}
	description = "alternative path untried"
	pathID = uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO objective_path(id, objective_id, path_key, description, status, created_at) VALUES (?, ?, 'alt_path', ?, 'open', ?)`, pathID, objID, description, now); err != nil {
		t.Fatalf("insert objective_path: %v", err)
	}
	candID := uuid.NewString()
	if _, err := s.DB.Exec(`
		INSERT INTO candidate(id, session_id, source, objective_path_id, intent_key, parameters, tool, command_template_rendered, score, score_terms, explanation, created_at, status)
		VALUES (?, ?, 'methodology', ?, 'alt_intent', '{}', 'y', 'y', 0, '{}', 'y', ?, 'proposed')`,
		candID, sessionID, pathID, now,
	); err != nil {
		t.Fatalf("insert alt candidate: %v", err)
	}
	return pathID, description
}

func TestDetectRabbitHole_NoWarningBelowThreshold(t *testing.T) {
	s, sessionID := newTestSessionForRabbitHole(t)
	makeStagnantBranch(t, s, sessionID, stagnantAttemptThreshold-1)
	makeUntriedAlternative(t, s, sessionID)

	w, err := DetectRabbitHole(s, sessionID)
	if err != nil {
		t.Fatalf("DetectRabbitHole: %v", err)
	}
	if w != nil {
		t.Errorf("warning = %+v, want nil (menos intentos que el umbral)", w)
	}
}

func TestDetectRabbitHole_NoWarningWithoutAlternative(t *testing.T) {
	s, sessionID := newTestSessionForRabbitHole(t)
	makeStagnantBranch(t, s, sessionID, stagnantAttemptThreshold)
	// sin makeUntriedAlternative — no hay a dónde más ir

	w, err := DetectRabbitHole(s, sessionID)
	if err != nil {
		t.Fatalf("DetectRabbitHole: %v", err)
	}
	if w != nil {
		t.Errorf("warning = %+v, want nil (sin rama alternativa no vale la pena advertir)", w)
	}
}

func TestDetectRabbitHole_WarnsWhenStagnantAndAlternativeExists(t *testing.T) {
	s, sessionID := newTestSessionForRabbitHole(t)
	pathID := makeStagnantBranch(t, s, sessionID, stagnantAttemptThreshold)
	altPathID, altDesc := makeUntriedAlternative(t, s, sessionID)

	w, err := DetectRabbitHole(s, sessionID)
	if err != nil {
		t.Fatalf("DetectRabbitHole: %v", err)
	}
	if w == nil {
		t.Fatal("warning = nil, want una advertencia (rama estancada + alternativa sin probar)")
	}
	if w.StagnantObjectivePathID != pathID {
		t.Errorf("StagnantObjectivePathID = %s, want %s", w.StagnantObjectivePathID, pathID)
	}
	if w.AttemptCount != stagnantAttemptThreshold {
		t.Errorf("AttemptCount = %d, want %d", w.AttemptCount, stagnantAttemptThreshold)
	}
	if w.AlternativePathID != altPathID || w.AlternativeDescription != altDesc {
		t.Errorf("alternative = %s/%s, want %s/%s", w.AlternativePathID, w.AlternativeDescription, altPathID, altDesc)
	}
}

func TestDetectRabbitHole_NoWarningIfNewEvidenceProduced(t *testing.T) {
	s, sessionID := newTestSessionForRabbitHole(t)
	pathID := makeStagnantBranch(t, s, sessionID, stagnantAttemptThreshold)
	makeUntriedAlternative(t, s, sessionID)

	// Una de las acciones SÍ produjo evidencia nueva — la rama no está
	// realmente estancada, no debe advertirse.
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`
		UPDATE outcome SET new_entities = 1
		WHERE action_id = (SELECT id FROM action WHERE objective_path_id = ? LIMIT 1)`,
		pathID,
	); err != nil {
		t.Fatalf("update outcome: %v", err)
	}
	_ = now

	w, err := DetectRabbitHole(s, sessionID)
	if err != nil {
		t.Fatalf("DetectRabbitHole: %v", err)
	}
	if w != nil {
		t.Errorf("warning = %+v, want nil (sí produjo evidencia nueva)", w)
	}
}
