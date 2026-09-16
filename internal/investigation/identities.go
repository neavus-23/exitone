package investigation

import (
	"fmt"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

// IngestIdentities crea una entidad type=identity por cada nombre nuevo. Esta
// es la evidencia que, más tarde, el Temporal Reasoner compara contra los
// ACTION_ASSUMPTION de acciones ya cerradas para decidir reaperturas (D1).
func IngestIdentities(s *store.Store, sessionID, rawOutputRef, toolName string, names []string) (*IngestResult, error) {
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
		 VALUES (?, NULL, ?, ?, 1, ?)`,
		evidenceID, rawOutputRef, toolName, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	for _, name := range names {
		id, created, _, err := upsertEntity(tx, sessionID, "identity", name, map[string]any{"source": toolName}, now)
		if err != nil {
			return nil, err
		}
		if created {
			res.NewEntities = append(res.NewEntities, id)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}
