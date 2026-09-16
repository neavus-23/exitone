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
		`SELECT id, objective_path_id FROM action WHERE id LIKE ? || '%' ORDER BY executed_at DESC LIMIT 1`,
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
// Limitación conocida y documentada: si hubiera dos acciones de la MISMA
// herramienta esperando evidencia simultáneamente en la misma sesión, esto
// resuelve la más reciente — puede no ser la correcta. Para ese caso, sigue
// existiendo `--for-action` explícito como vía de desambiguación.
func AutoRecordPending(s *store.Store, sessionID, tool string, res *investigation.IngestResult, pathResolved bool) (matched bool, outcomeID string, err error) {
	var actionID string
	var objectivePathID sql.NullString
	err = s.DB.QueryRow(`
		SELECT a.id, a.objective_path_id
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		WHERE c.session_id = ? AND c.tool = ? AND a.status = 'awaiting_evidence'
		ORDER BY a.executed_at DESC LIMIT 1`,
		sessionID, tool,
	).Scan(&actionID, &objectivePathID)
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
	if _, err := s.DB.Exec(`UPDATE action SET status = 'resolved' WHERE id = ?`, actionID); err != nil {
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

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
