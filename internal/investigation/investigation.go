// Package investigation implementa el núcleo del Investigation Model
// (sección C1/D del plan): ingesta observaciones deterministas y las
// convierte en entidades y relaciones persistentes, sin interpretar texto.
package investigation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/parsers"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// IngestResult resume qué se creó, usado luego para medir Outcome (sección G2).
type IngestResult struct {
	EvidenceID   string
	NewEntities  []string // entity IDs creados en esta ingesta
	NewRelations []string
	OpenPorts    []parsers.OpenPort
}

// IngestNmap registra la evidencia cruda, crea una Observation por puerto
// abierto (Nivel 1, confidence 1.0 — parser determinista) y actualiza el
// Investigation Model (entidades host/service + relación HAS_SERVICE).
func IngestNmap(s *store.Store, sessionID, rawOutputRef, eventID string, ports []parsers.OpenPort) (*IngestResult, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res := &IngestResult{OpenPorts: ports}

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	evidenceID := uuid.NewString()
	if _, err := tx.Exec(
		`INSERT INTO evidence(id, event_id, raw_output_ref, tool_name, parse_level, created_at)
		 VALUES (?, ?, ?, 'nmap', 1, ?)`,
		evidenceID, nullableString(eventID), rawOutputRef, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	for _, p := range ports {
		hostEntityID, hostCreated, _, err := upsertEntity(tx, sessionID, "host", p.Host, map[string]any{}, now)
		if err != nil {
			return nil, err
		}
		if hostCreated {
			res.NewEntities = append(res.NewEntities, hostEntityID)
		}

		serviceValue := fmt.Sprintf("%s:%d/%s", p.Host, p.Port, p.Proto)
		attrs := map[string]any{
			"protocol": p.Service,
			"port":     p.Port,
			"proto":    p.Proto,
		}
		if p.Product != "" {
			attrs["product"] = p.Product
		}
		serviceEntityID, svcCreated, _, err := upsertEntity(tx, sessionID, "service", serviceValue, attrs, now)
		if err != nil {
			return nil, err
		}
		if svcCreated {
			res.NewEntities = append(res.NewEntities, serviceEntityID)
		}

		payload, _ := json.Marshal(map[string]any{
			"host": p.Host, "port": p.Port, "proto": p.Proto,
			"service": p.Service, "product": p.Product,
		})
		obsID := uuid.NewString()
		if _, err := tx.Exec(
			`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status)
			 VALUES (?, ?, 'open_port', ?, 1.0, 'active')`,
			obsID, evidenceID, string(payload),
		); err != nil {
			return nil, fmt.Errorf("insert observation: %w", err)
		}
		if _, err := tx.Exec(
			`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?), (?, ?)`,
			obsID, hostEntityID, obsID, serviceEntityID,
		); err != nil {
			return nil, err
		}

		if svcCreated || hostCreated {
			relID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO relationship(id, source_entity_id, target_entity_id, kind, confidence, supporting_observation_id, valid_from, valid_to)
				 VALUES (?, ?, ?, 'HAS_SERVICE', 1.0, ?, ?, NULL)`,
				relID, hostEntityID, serviceEntityID, obsID, now,
			); err != nil {
				return nil, fmt.Errorf("insert relationship: %w", err)
			}
			res.NewRelations = append(res.NewRelations, relID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// upsertEntity crea la entidad si no existe (unique por session+type+valor),
// o la actualiza si ya existía, aplicando el patrón confirmado en
// report_host/report_service de Metasploit: se hace merge campo por campo,
// solo se escribe lo que cambió, nunca se sobrescribe con un valor vacío, y
// los atributos desconocidos no se descartan (a diferencia de Metasploit,
// aquí no hay columnas fijas — todo vive en `attrs` JSON). `changed` indica
// si algún atributo fue nuevo o distinto (o si la entidad se acaba de crear),
// para que el llamador decida si vale la pena registrar una Observation.
func upsertEntity(tx *sql.Tx, sessionID, entType, canonicalValue string, attrs map[string]any, now string) (id string, created bool, changed bool, err error) {
	var existingID, existingAttrsJSON string
	err = tx.QueryRow(
		`SELECT id, attrs FROM entity WHERE session_id = ? AND type = ? AND canonical_value = ?`,
		sessionID, entType, canonicalValue,
	).Scan(&existingID, &existingAttrsJSON)
	if err == nil {
		existingAttrs := map[string]any{}
		if existingAttrsJSON != "" {
			_ = json.Unmarshal([]byte(existingAttrsJSON), &existingAttrs)
		}
		mergedAny := false
		for k, v := range attrs {
			sv := fmt.Sprintf("%v", v)
			if sv == "" {
				continue // nunca sobrescribir con vacío
			}
			if cur, ok := existingAttrs[k]; !ok || fmt.Sprintf("%v", cur) != sv {
				existingAttrs[k] = v
				mergedAny = true
			}
		}
		if mergedAny {
			newJSON, _ := json.Marshal(existingAttrs)
			if _, err2 := tx.Exec(`UPDATE entity SET attrs = ?, last_seen = ? WHERE id = ?`, string(newJSON), now, existingID); err2 != nil {
				return "", false, false, err2
			}
		} else {
			if _, err2 := tx.Exec(`UPDATE entity SET last_seen = ? WHERE id = ?`, now, existingID); err2 != nil {
				return "", false, false, err2
			}
		}
		return existingID, false, mergedAny, nil
	}
	if err != sql.ErrNoRows {
		return "", false, false, err
	}

	newID := uuid.NewString()
	attrsJSON, _ := json.Marshal(attrs)
	if _, err := tx.Exec(
		`INSERT INTO entity(id, session_id, type, canonical_value, attrs, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		newID, sessionID, entType, canonicalValue, string(attrsJSON), now, now,
	); err != nil {
		return "", false, false, err
	}
	return newID, true, true, nil
}
