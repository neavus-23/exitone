// Package hypothesis registra el resultado de una ACTION de tipo
// test_ssh_auth: crea (o reutiliza) una HYPOTHESIS y la cierra/confirma,
// dejando un OUTCOME. Es el punto donde una conclusión entra al dominio y
// queda disponible para que internal/temporal decida más adelante si debe
// reabrirse.
package hypothesis

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

// RecordResult cierra la acción identificada por actionIDPrefix con el
// resultado de la prueba SSH: crea la HYPOTHESIS, la vincula vía
// action_hypothesis (relation_kind=TESTED), y persiste el OUTCOME.
func RecordResult(s *store.Store, sessionID, actionIDPrefix, result string) (hypothesisID string, err error) {
	if result != "fail" && result != "success" {
		return "", fmt.Errorf("result debe ser 'fail' o 'success', recibido %q", result)
	}

	var actionID, candidateID string
	err = s.DB.QueryRow(
		`SELECT id, candidate_id FROM action WHERE id LIKE ? || '%' ORDER BY executed_at DESC LIMIT 1`,
		actionIDPrefix,
	).Scan(&actionID, &candidateID)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("no se encontró una acción con prefijo %q", actionIDPrefix)
	}
	if err != nil {
		return "", err
	}

	var paramsJSON string
	if err := s.DB.QueryRow(`SELECT parameters FROM candidate WHERE id = ?`, candidateID).Scan(&paramsJSON); err != nil {
		return "", err
	}
	var params struct {
		ServiceEntityID string `json:"service_entity_id"`
		Identity        struct {
			Value string `json:"value"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return "", fmt.Errorf("parsear parámetros del candidato: %w", err)
	}
	if params.ServiceEntityID == "" {
		return "", fmt.Errorf("el candidato de esta acción no es de tipo test_ssh_auth (sin service_entity_id)")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	status := "closed"
	hypConfirmed, hypRefuted := 0, 0
	if result == "success" {
		status = "confirmed"
		hypConfirmed = 1
	} else {
		hypRefuted = 1
	}

	hypID := uuid.NewString()
	statement := fmt.Sprintf("Autenticación SSH investigada para el servicio (identidad probada: %s)", params.Identity.Value)
	if _, err := s.DB.Exec(
		`INSERT INTO hypothesis(id, session_id, statement, subject_entity_id, status, confidence, opened_at, closed_at)
		 VALUES (?, ?, ?, ?, ?, 1.0, ?, ?)`,
		hypID, sessionID, statement, params.ServiceEntityID, status, now, now,
	); err != nil {
		return "", fmt.Errorf("insert hypothesis: %w", err)
	}

	if _, err := s.DB.Exec(
		`INSERT INTO action_hypothesis(action_id, hypothesis_id, relation_kind) VALUES (?, ?, 'TESTED')`,
		actionID, hypID,
	); err != nil {
		return "", fmt.Errorf("insert action_hypothesis: %w", err)
	}

	outID := uuid.NewString()
	gain := 0.1
	if result == "success" {
		gain = 0.9
	}
	if _, err := s.DB.Exec(`
		INSERT INTO outcome(id, action_id, new_entities, new_relationships, hypotheses_confirmed,
			hypotheses_refuted, contradictions_resolved, computed_information_gain, recorded_at)
		VALUES (?, ?, 0, 0, ?, ?, 0, ?, ?)`,
		outID, actionID, hypConfirmed, hypRefuted, gain, now,
	); err != nil {
		return "", fmt.Errorf("insert outcome: %w", err)
	}

	// Bug real encontrado revisando el contexto de `exitone ask`: sin esto, la
	// acción quedaba 'awaiting_evidence' para siempre después de resolverse
	// con `exitone resolve`, arriesgando que outcome.AutoRecordPending la
	// volviera a emparejar incorrectamente con una ingesta posterior de la
	// misma herramienta (ssh) que en realidad correspondía a otra acción.
	if _, err := s.DB.Exec(`UPDATE action SET status = 'resolved' WHERE id = ?`, actionID); err != nil {
		return "", fmt.Errorf("mark action resolved: %w", err)
	}

	return hypID, nil
}
