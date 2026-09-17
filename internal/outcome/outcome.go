// Package outcome cierra el ciclo de una ACTION: mide qué produjo (sección
// G2/D del plan) y actualiza el estado del objective_path correspondiente.
// Esto es lo que alimenta el futuro Strategy Learning (sección H) — cada
// OUTCOME queda anclado a la ACTION y su DECISION_CONTEXT ya grabados.
package outcome

import (
	"database/sql"
	"fmt"
	"time"

	"exitone/internal/investigation"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// Record calcula y persiste el OUTCOME de una ACTION identificada por prefijo
// explícito (`--for-action`) — usar cuando la evidencia no llega por el
// camino de auto-ingesta (ej. se ingiere un archivo capturado fuera de tmux).
func Record(s *store.Store, actionIDPrefix string, res *investigation.IngestResult, pathResolved bool) (string, error) {
	var actionID string
	var objectivePathID sql.NullString
	err := s.DB.QueryRow(
		`SELECT id, objective_path_id FROM action WHERE id LIKE ? || '%' ORDER BY COALESCE(executed_at, decided_at) DESC LIMIT 1`,
		actionIDPrefix,
	).Scan(&actionID, &objectivePathID)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no se encontró una acción con prefijo %q", actionIDPrefix)
	}
	if err != nil {
		return "", err
	}
	return recordFor(s, actionID, objectivePathID, res, pathResolved)
}

// AutoRecordPending busca la acción 'awaiting_evidence' más reciente de esta
// sesión para la MISMA herramienta que se acaba de ingerir, y cierra su
// OUTCOME automáticamente — sin necesitar que el operador pase --for-action
// a mano. Esto es lo que corrige el bug encontrado en la prueba de lab: la
// auto-ingesta (disparada por el propio comando tecleado en tmux) ahora sabe
// qué acción cerrar, en vez de dejar el objective_path abierto y hacer que
// ExitOne vuelva a sugerir un comando ya ejecutado.
//
// Si hay más de una acción de la misma herramienta no elige arbitrariamente:
// devuelve matched=false y conserva `--for-action` como vía explícita.
func AutoRecordPending(s *store.Store, sessionID, tool string, res *investigation.IngestResult, pathResolved bool) (matched bool, outcomeID string, err error) {
	rows, err := s.DB.Query(`
		SELECT a.id, a.objective_path_id
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		WHERE c.session_id = ? AND c.tool = ? AND a.status = 'awaiting_evidence'
		ORDER BY COALESCE(a.executed_at, a.decided_at) DESC LIMIT 2`,
		sessionID, tool,
	)
	if err != nil {
		return false, "", err
	}
	defer rows.Close()
	type pending struct {
		id     string
		pathID sql.NullString
	}
	var found []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.pathID); err != nil {
			return false, "", err
		}
		found = append(found, p)
	}
	if err := rows.Err(); err != nil {
		return false, "", err
	}
	if len(found) != 1 {
		return false, "", nil
	}
	id, err := recordFor(s, found[0].id, found[0].pathID, res, pathResolved)
	if err != nil {
		return false, "", err
	}
	return true, id, nil
}

// AutoRecordForEvent es el camino preciso para la auto-ingesta: el hook ya
// entregó el mismo evento que se vinculó a la acción al observar el comando.
// Si no hay vínculo (comando manual/no modelado) devuelve matched=false y el
// llamador puede usar el fallback por herramienta.
func AutoRecordForEvent(s *store.Store, eventID string, res *investigation.IngestResult, pathResolved bool) (matched bool, outcomeID string, err error) {
	if eventID == "" {
		return false, "", nil
	}
	var actionID string
	var objectivePathID sql.NullString
	err = s.DB.QueryRow(`
		SELECT a.id, a.objective_path_id
		FROM action_event ae JOIN action a ON a.id = ae.action_id
		WHERE ae.event_id = ? AND a.status IN ('executed','awaiting_evidence')
		LIMIT 1`, eventID).Scan(&actionID, &objectivePathID)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	id, err := recordFor(s, actionID, objectivePathID, res, pathResolved)
	if err != nil {
		return false, "", err
	}
	return true, id, nil
}

func recordFor(s *store.Store, actionID string, objectivePathID sql.NullString, res *investigation.IngestResult, pathResolved bool) (string, error) {
	newEntities := len(res.NewEntities)
	newRelations := len(res.NewRelations)

	gain := 0.25*clamp01(float64(newEntities)/3.0) +
		0.25*clamp01(float64(newRelations)/3.0)
	if pathResolved {
		gain += 0.5
	}
	gain = clamp01(gain)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	outcomeID := uuid.NewString()
	if _, err := s.DB.Exec(`
		INSERT INTO outcome(id, action_id, new_entities, new_relationships, hypotheses_confirmed,
			hypotheses_refuted, contradictions_resolved, computed_information_gain, recorded_at)
		VALUES (?, ?, ?, ?, 0, 0, 0, ?, ?)`,
		outcomeID, actionID, newEntities, newRelations, gain, now,
	); err != nil {
		return "", fmt.Errorf("insert outcome: %w", err)
	}
	if _, err := s.DB.Exec(`UPDATE action SET status = 'resolved', executed_at = COALESCE(executed_at, ?) WHERE id = ?`, now, actionID); err != nil {
		return "", fmt.Errorf("mark action resolved: %w", err)
	}

	if pathResolved && objectivePathID.Valid {
		if _, err := s.DB.Exec(`UPDATE objective_path SET status = 'answered' WHERE id = ?`, objectivePathID.String); err != nil {
			return "", fmt.Errorf("mark path answered: %w", err)
		}
		// Sección F: el objective se marca 'answered' cuando CUALQUIER path lo resuelve.
		var objectiveID string
		if err := s.DB.QueryRow(`SELECT objective_id FROM objective_path WHERE id = ?`, objectivePathID.String).Scan(&objectiveID); err == nil {
			if _, err := s.DB.Exec(`UPDATE methodology_objective SET status = 'answered' WHERE id = ?`, objectiveID); err != nil {
				return "", fmt.Errorf("mark objective answered: %w", err)
			}
		}
	}

	return outcomeID, nil
}

// RecordManualResult registra el resultado de una acción resuelta a mano por
// el operador (`exitone resolve <action> --result fail|success`), sin
// archivo de evidencia de por medio (así que no hay IngestResult que medir).
// Fase 3 del plan de arquitectura: esto reemplaza lo que antes hacía
// hypothesis.RecordResult, que forzaba crear una HYPOTHESIS nueva en cada
// intento SSH solo para poder registrar el resultado. La cobertura real
// (qué identidades ya se probaron contra qué servicio) ya la refleja
// directamente la tabla `candidate` (ver internal/strategy/ssh.go:
// candidateExists) — no hace falta el ciclo hypothesis→close→reopen para
// saber "qué falta probar", que es justo la confusión que producía la
// anomalía real encontrada (una hipótesis vieja podía quedar 'reopened' sin
// relación con la identidad que en realidad causaba el gap).
func RecordManualResult(s *store.Store, actionIDPrefix, result string) (actionID string, err error) {
	if result != "fail" && result != "success" {
		return "", fmt.Errorf("result debe ser 'fail' o 'success', recibido %q", result)
	}

	var objectivePathID sql.NullString
	err = s.DB.QueryRow(
		`SELECT id, objective_path_id FROM action WHERE id LIKE ? || '%' ORDER BY COALESCE(executed_at, decided_at) DESC LIMIT 1`,
		actionIDPrefix,
	).Scan(&actionID, &objectivePathID)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no se encontró una acción con prefijo %q", actionIDPrefix)
	}
	if err != nil {
		return "", err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	gain := 0.1
	pathResolved := false
	if result == "success" {
		gain = 0.9
		pathResolved = true // éxito resuelve directamente el path que motivó el intento
	}

	outcomeID := uuid.NewString()
	if _, err := s.DB.Exec(`
		INSERT INTO outcome(id, action_id, new_entities, new_relationships, hypotheses_confirmed,
			hypotheses_refuted, contradictions_resolved, computed_information_gain, recorded_at)
		VALUES (?, ?, 0, 0, 0, 0, 0, ?, ?)`,
		outcomeID, actionID, gain, now,
	); err != nil {
		return "", fmt.Errorf("insert outcome: %w", err)
	}
	if _, err := s.DB.Exec(`UPDATE action SET status = 'resolved', executed_at = COALESCE(executed_at, ?) WHERE id = ?`, now, actionID); err != nil {
		return "", fmt.Errorf("mark action resolved: %w", err)
	}
	if pathResolved && objectivePathID.Valid {
		if _, err := s.DB.Exec(`UPDATE objective_path SET status = 'answered' WHERE id = ?`, objectivePathID.String); err != nil {
			return "", fmt.Errorf("mark path answered: %w", err)
		}
		var objectiveID string
		if err := s.DB.QueryRow(`SELECT objective_id FROM objective_path WHERE id = ?`, objectivePathID.String).Scan(&objectiveID); err == nil {
			if _, err := s.DB.Exec(`UPDATE methodology_objective SET status = 'answered' WHERE id = ?`, objectiveID); err != nil {
				return "", fmt.Errorf("mark objective answered: %w", err)
			}
		}
	}
	return actionID, nil
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
