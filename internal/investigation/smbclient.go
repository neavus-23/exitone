package investigation

import (
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/parsers"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// IngestSmbclient registra la evidencia de `smbclient -L` y actualiza el
// Investigation Model: entidad domain (si se reportó) con relación
// MEMBER_OF desde el host, y una entidad share por cada share con relación
// HAS_SHARE. Esto es lo que habilita la correlación cross-tool de Slice 2
// (sección L): SMB -> domain -> nuevo methodology objective.
func IngestSmbclient(s *store.Store, sessionID, rawOutputRef, host string, listing parsers.SmbclientListing) (*IngestResult, error) {
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
		 VALUES (?, NULL, ?, 'smbclient', 1, ?)`,
		evidenceID, rawOutputRef, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	hostEntityID, hostCreated, _, err := upsertEntity(tx, sessionID, "host", host, map[string]any{}, now)
	if err != nil {
		return nil, err
	}
	if hostCreated {
		res.NewEntities = append(res.NewEntities, hostEntityID)
	}

	if listing.Domain != "" {
		domAttrs := map[string]any{"os": listing.OS, "server": listing.Server}
		domID, domCreated, _, err := upsertEntity(tx, sessionID, "domain", listing.Domain, domAttrs, now)
		if err != nil {
			return nil, err
		}
		if domCreated {
			res.NewEntities = append(res.NewEntities, domID)
		}

		payload, _ := json.Marshal(map[string]any{"domain": listing.Domain, "os": listing.OS, "server": listing.Server})
		obsID := uuid.NewString()
		if _, err := tx.Exec(
			`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status) VALUES (?, ?, 'domain', ?, 1.0, 'active')`,
			obsID, evidenceID, string(payload),
		); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?), (?, ?)`,
			obsID, hostEntityID, obsID, domID); err != nil {
			return nil, err
		}

		if domCreated || hostCreated {
			relID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO relationship(id, source_entity_id, target_entity_id, kind, confidence, supporting_observation_id, valid_from, valid_to)
				 VALUES (?, ?, ?, 'MEMBER_OF', 1.0, ?, ?, NULL)`,
				relID, hostEntityID, domID, obsID, now,
			); err != nil {
				return nil, err
			}
			res.NewRelations = append(res.NewRelations, relID)
		}
	}

	for _, sh := range listing.Shares {
		shareValue := fmt.Sprintf("%s/%s", host, sh.Name)
		attrs := map[string]any{"type": sh.Type, "comment": sh.Comment}
		shareID, shCreated, _, err := upsertEntity(tx, sessionID, "share", shareValue, attrs, now)
		if err != nil {
			return nil, err
		}
		if shCreated {
			res.NewEntities = append(res.NewEntities, shareID)
		}

		payload, _ := json.Marshal(map[string]any{"host": host, "share": sh.Name, "type": sh.Type, "comment": sh.Comment})
		obsID := uuid.NewString()
		if _, err := tx.Exec(
			`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status) VALUES (?, ?, 'share', ?, 1.0, 'active')`,
			obsID, evidenceID, string(payload),
		); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?), (?, ?)`,
			obsID, hostEntityID, obsID, shareID); err != nil {
			return nil, err
		}

		if shCreated {
			relID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO relationship(id, source_entity_id, target_entity_id, kind, confidence, supporting_observation_id, valid_from, valid_to)
				 VALUES (?, ?, ?, 'HAS_SHARE', 1.0, ?, ?, NULL)`,
				relID, hostEntityID, shareID, obsID, now,
			); err != nil {
				return nil, err
			}
			res.NewRelations = append(res.NewRelations, relID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}
