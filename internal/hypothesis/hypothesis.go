// Package hypothesis implementa el motor de hipótesis rediseñado (Fase 3 del
// plan de arquitectura): `hypothesis` significa exactamente una proposición
// falsable, con evidencia a favor/en contra al nivel correcto (una
// Observation concreta, no un Evidence completo) y un estado categórico —
// nunca una fuerza inventada por conteo. La reapertura queda reservada para
// el caso genuino: una observation 'contradicts' que llega DESPUÉS de un
// cierre CONFIRMED/REFUTED — no "apareció una entidad nueva de cierto tipo",
// que es lo que el diseño anterior (generalizar el diff de conjuntos de
// internal/temporal) confundía.
package hypothesis

import (
	"database/sql"
	"fmt"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

type Status string

const (
	Untested  Status = "untested"
	Supported Status = "supported"
	Disputed  Status = "disputed"
	Refuted   Status = "refuted"
	Confirmed Status = "confirmed"
	Reopened  Status = "reopened"
)

// Explanation es la respuesta a `why <hypothesis-id>`: conteos crudos y un
// status categórico, nunca una fuerza derivada ("alta/media/baja") — dos
// observaciones del mismo escaneo no son dos fuentes independientes, así que
// no se inflan a una confianza que el sistema no puede respaldar todavía.
type Explanation struct {
	Statement                 string
	Status                    Status
	SupportingObservations    int
	ContradictingObservations int
}

// Open crea una hipótesis nueva en estado UNTESTED — el único punto de
// entrada al ciclo de vida. subjectEntityID ancla la hipótesis a la entidad
// sobre la que trata (ej. el service SMB al que aplica).
func Open(s *store.Store, sessionID, subjectEntityID, statement string) (string, error) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO hypothesis(id, session_id, statement, subject_entity_id, status, opened_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, sessionID, statement, subjectEntityID, string(Untested), now,
	); err != nil {
		return "", fmt.Errorf("insert hypothesis: %w", err)
	}
	return id, nil
}

// Support vincula una Observation como evidencia A FAVOR. Si la hipótesis ya
// estaba cerrada (CONFIRMED/REFUTED), un soporte adicional NO la reabre —
// solo una contradicción reabre un cierre (ver Contradict). En cualquier
// otro estado, el status se recalcula por presencia/ausencia de evidencia en
// cada sentido, nunca por cantidad.
func Support(s *store.Store, hypothesisID, observationID string) error {
	return link(s, hypothesisID, observationID, "supports")
}

// Contradict vincula una Observation como evidencia EN CONTRA. Si la
// hipótesis estaba CONFIRMED o REFUTED, esta es la reapertura genuina: nueva
// evidencia contradice específicamente un cierre anterior → REOPENED.
func Contradict(s *store.Store, hypothesisID, observationID string) error {
	return link(s, hypothesisID, observationID, "contradicts")
}

func link(s *store.Store, hypothesisID, observationID, relation string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO hypothesis_observation(hypothesis_id, observation_id, relation, created_at) VALUES (?, ?, ?, ?)`,
		hypothesisID, observationID, relation, now,
	); err != nil {
		return fmt.Errorf("insert hypothesis_observation: %w", err)
	}
	return recomputeStatus(s, hypothesisID, relation)
}

func recomputeStatus(s *store.Store, hypothesisID, newRelation string) error {
	var current string
	if err := s.DB.QueryRow(`SELECT status FROM hypothesis WHERE id = ?`, hypothesisID).Scan(&current); err != nil {
		return err
	}

	// Reapertura genuina (sección J3): una contradicción que llega DESPUÉS
	// de un cierre explícito — no se recalcula por conteo, se marca REOPENED
	// directamente y se sale, preservando que fue un cierre el que se reabrió.
	if newRelation == "contradicts" && (Status(current) == Confirmed || Status(current) == Refuted) {
		_, err := s.DB.Exec(`UPDATE hypothesis SET status = ? WHERE id = ?`, string(Reopened), hypothesisID)
		return err
	}
	// CONFIRMED es un cierre explícito (ver Confirm) — un soporte adicional
	// no lo cambia ni lo recalcula.
	if Status(current) == Confirmed {
		return nil
	}

	var supports, contradicts int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM hypothesis_observation WHERE hypothesis_id = ? AND relation = 'supports'`, hypothesisID).Scan(&supports); err != nil {
		return err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM hypothesis_observation WHERE hypothesis_id = ? AND relation = 'contradicts'`, hypothesisID).Scan(&contradicts); err != nil {
		return err
	}

	var next Status
	switch {
	case supports > 0 && contradicts > 0:
		next = Disputed
	case contradicts > 0:
		next = Refuted
	case supports > 0:
		next = Supported
	default:
		next = Untested
	}
	_, err := s.DB.Exec(`UPDATE hypothesis SET status = ? WHERE id = ?`, string(next), hypothesisID)
	return err
}

// FindingDetails son los campos explícitos de un hallazgo, fijados por el
// operador al cerrar una hipótesis — nunca inferidos por conteo ni
// redactados libremente por el LLM (`exitone report` los usa tal cual).
// Todos son opcionales: una hipótesis cerrada sin detalle sigue siendo
// válida, solo que el reporte final la mostrará sin severidad/remediación.
type FindingDetails struct {
	Severity     string // '' | low | medium | high | critical
	Remediation  string
	EvidenceNote string // prueba de impacto puntual, ej. un flag o un output concreto
}

// Confirm es un cierre EXPLÍCITO (nunca automático por conteo) — el llamador
// decide que la evidencia acumulada es concluyente. Solo esto (o Refute)
// deja una hipótesis en un estado del que una contradicción futura la
// reabre genuinamente.
func Confirm(s *store.Store, hypothesisID string, details FindingDetails) error {
	return closeWithDetails(s, hypothesisID, Confirmed, details)
}

// Refute es el cierre explícito equivalente a Confirm, para cuando la
// evidencia concluyente va en contra de la proposición.
func Refute(s *store.Store, hypothesisID string, details FindingDetails) error {
	return closeWithDetails(s, hypothesisID, Refuted, details)
}

func closeWithDetails(s *store.Store, hypothesisID string, status Status, details FindingDetails) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(
		`UPDATE hypothesis SET status = ?, closed_at = ?,
		 severity = CASE WHEN ? != '' THEN ? ELSE severity END,
		 remediation = CASE WHEN ? != '' THEN ? ELSE remediation END,
		 evidence_note = CASE WHEN ? != '' THEN ? ELSE evidence_note END
		 WHERE id = ?`,
		string(status), now,
		details.Severity, details.Severity,
		details.Remediation, details.Remediation,
		details.EvidenceNote, details.EvidenceNote,
		hypothesisID,
	)
	return err
}

// Explain responde `why <hypothesis-id>`: statement + conteos crudos +
// status categórico — nunca una fuerza inventada.
func Explain(s *store.Store, hypothesisIDPrefix string) (*Explanation, error) {
	var id, statement, status string
	err := s.DB.QueryRow(
		`SELECT id, statement, status FROM hypothesis WHERE id LIKE ? || '%' ORDER BY opened_at DESC LIMIT 1`,
		hypothesisIDPrefix,
	).Scan(&id, &statement, &status)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no se encontró una hipótesis con prefijo %q", hypothesisIDPrefix)
	}
	if err != nil {
		return nil, err
	}

	var supports, contradicts int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM hypothesis_observation WHERE hypothesis_id = ? AND relation = 'supports'`, id).Scan(&supports); err != nil {
		return nil, err
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM hypothesis_observation WHERE hypothesis_id = ? AND relation = 'contradicts'`, id).Scan(&contradicts); err != nil {
		return nil, err
	}

	return &Explanation{
		Statement:                 statement,
		Status:                    Status(status),
		SupportingObservations:    supports,
		ContradictingObservations: contradicts,
	}, nil
}
