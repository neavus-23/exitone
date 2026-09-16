package investigation

import (
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/llm"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// IngestGeneric registra evidencia de Nivel 2 (LLM-assisted, sección 6/8/J
// del plan): cada Observation queda marcada con status='candidate' — NUNCA
// 'active' como las de Nivel 1 — y con la confianza ya acotada por
// internal/llm.ExtractObservations. Las entidades sí se crean (para que
// aparezcan en el Investigation Model y el operador las vea), pero quedan
// etiquetadas attrs.extracted_by="llm" para que cualquier consumidor futuro
// pueda tratarlas con más cautela que una entidad de Nivel 1.
func IngestGeneric(s *store.Store, sessionID, rawOutputRef, toolName string, obs []llm.CandidateObservation) (*IngestResult, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res := &IngestResult{}

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	evidenceID := uuid.NewString()
	if _, err := tx.Exec(
		`INSERT INTO evidence(id, event_id, raw_output_ref, tool_name, parse_level, created_at)
		 VALUES (?, NULL, ?, ?, 2, ?)`,
		evidenceID, rawOutputRef, toolName, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	entityTypeByKind := map[string]string{
		"endpoint":   "endpoint",
		"identity":   "identity",
		"technology": "technology",
		"domain":     "domain",
	}

	for _, o := range obs {
		entType, ok := entityTypeByKind[o.Kind]
		if !ok {
			entType = "candidate_fact" // kind="other" u otro valor no reconocido
		}

		payload, _ := json.Marshal(map[string]any{"kind": o.Kind, "value": o.Value, "tool": toolName})
		obsID := uuid.NewString()
		if _, err := tx.Exec(
			`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status) VALUES (?, ?, ?, ?, ?, 'candidate')`,
			obsID, evidenceID, o.Kind, string(payload), o.Confidence,
		); err != nil {
			return nil, fmt.Errorf("insert observation: %w", err)
		}

		attrs := map[string]any{"extracted_by": "llm", "source_tool": toolName, "confidence": o.Confidence}
		entID, created, _, err := upsertEntity(tx, sessionID, entType, o.Value, attrs, now)
		if err != nil {
			return nil, err
		}
		if created {
			res.NewEntities = append(res.NewEntities, entID)
		}
		if _, err := tx.Exec(`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?)`, obsID, entID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}
