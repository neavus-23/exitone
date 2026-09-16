// Package stage implementa el Stage Estimator descrito en la sección E/9 del
// plan, en su forma de MVP: reglas explícitas sobre conteos reales de la
// base de datos, NUNCA porcentajes sin evidencia que los respalde. Estados
// discretos (NOT_STARTED/ACTIVE/PARTIAL/SUFFICIENT/BLOCKED/REOPENED), no
// probabilidades — tal como pide explícitamente el protocolo de validación.
package stage

import (
	"fmt"

	"exitone/internal/store"
)

type Status string

const (
	NotStarted Status = "NOT_STARTED"
	Active     Status = "ACTIVE"
	Partial    Status = "PARTIAL"
	Sufficient Status = "SUFFICIENT"
	Blocked    Status = "BLOCKED"
	Reopened   Status = "REOPENED"
)

type Stage struct {
	Name   string
	Status Status
	Reason string // por qué se asignó este estado — siempre trazable a una cuenta real
}

func Estimate(s *store.Store, sessionID string) ([]Stage, error) {
	var stages []Stage

	serviceCount, err := count(s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service'`, sessionID)
	if err != nil {
		return nil, err
	}
	initialDiscoveryAnswered, err := objectiveAnswered(s, sessionID, "initial_discovery")
	if err != nil {
		return nil, err
	}
	switch {
	case serviceCount == 0:
		stages = append(stages, Stage{"surface_discovery", NotStarted, "0 entidades type=service en la sesión"})
	case initialDiscoveryAnswered:
		stages = append(stages, Stage{"surface_discovery", Sufficient, "objective 'initial_discovery' respondido y hay entidades de servicio"})
	default:
		stages = append(stages, Stage{"surface_discovery", Active, "hay entidades de servicio pero el objective de descubrimiento sigue abierto"})
	}

	fingerprintedCount, err := count(s, `
		SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service' AND json_extract(attrs, '$.product') IS NOT NULL`,
		sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case serviceCount == 0:
		stages = append(stages, Stage{"service_fingerprinting", NotStarted, "no hay servicios que fingerprintear todavía"})
	case fingerprintedCount == 0:
		stages = append(stages, Stage{"service_fingerprinting", NotStarted, "servicios conocidos pero sin versión/producto identificado (0 con attrs.product)"})
	case fingerprintedCount < serviceCount:
		stages = append(stages, Stage{"service_fingerprinting", Partial, fmtCount("%d de %d servicios tienen producto/versión identificado", fingerprintedCount, serviceCount)})
	default:
		stages = append(stages, Stage{"service_fingerprinting", Sufficient, "todos los servicios conocidos tienen producto/versión identificado"})
	}

	httpObjectiveExists, err := objectiveExists(s, sessionID, "http_enumeration")
	if err != nil {
		return nil, err
	}
	httpActionCount, err := count(s, `
		SELECT COUNT(*) FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		WHERE c.session_id = ? AND (c.intent_key LIKE 'http_%' OR c.tool IN ('curl','whatweb','ffuf','gobuster'))`,
		sessionID)
	if err != nil {
		return nil, err
	}
	// endpointCount: el extractor genérico de dirb/gobuster/ffuf (ver
	// internal/parsers, internal/methodology.EvaluateEndpointTriggers) crea
	// entity(type='endpoint') sin pasar por el flujo action/candidate — antes
	// de esto, http_mapping se quedaba en NOT_STARTED aunque el operador ya
	// hubiera enumerado endpoints reales, porque solo miraba `action`.
	endpointCount, err := count(s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'endpoint'`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case !httpObjectiveExists:
		stages = append(stages, Stage{"http_mapping", NotStarted, "no se ha descubierto ningún servicio HTTP/HTTPS"})
	case httpActionCount == 0 && endpointCount == 0:
		stages = append(stages, Stage{"http_mapping", NotStarted, "objective http_enumeration abierto pero sin ninguna acción ni endpoint descubierto todavía"})
	case httpActionCount == 0:
		stages = append(stages, Stage{"http_mapping", Active, fmtCount("%d endpoint(s) descubierto(s) (dirb/ffuf/gobuster), sin acción de seguimiento registrada aún", endpointCount, 0)})
	default:
		stages = append(stages, Stage{"http_mapping", Active, fmtCount("%d acción(es) HTTP registradas", httpActionCount, 0)})
	}

	identityCount, err := count(s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'identity'`, sessionID)
	if err != nil {
		return nil, err
	}
	if identityCount == 0 {
		stages = append(stages, Stage{"identity_discovery", NotStarted, "0 entidades type=identity"})
	} else {
		stages = append(stages, Stage{"identity_discovery", Active, fmtCount("%d identidad(es) conocida(s)", identityCount, 0)})
	}

	authActionCount, err := count(s, `
		SELECT COUNT(*) FROM action a JOIN candidate c ON c.id = a.candidate_id
		WHERE c.session_id = ? AND c.intent_key = 'test_ssh_auth'`, sessionID)
	if err != nil {
		return nil, err
	}
	reopenedHypCount, err := count(s, `SELECT COUNT(*) FROM hypothesis WHERE session_id = ? AND status = 'reopened'`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case reopenedHypCount > 0:
		stages = append(stages, Stage{"authentication", Reopened, fmtCount("%d hipótesis de autenticación reabierta(s) por evidencia estructural nueva", reopenedHypCount, 0)})
	case authActionCount == 0:
		stages = append(stages, Stage{"authentication", NotStarted, "0 acciones test_ssh_auth ejecutadas"})
	default:
		stages = append(stages, Stage{"authentication", Active, fmtCount("%d intento(s) de autenticación registrados", authActionCount, 0)})
	}

	// initial_access: ExitOne no modela todavía obtención de shell/acceso —
	// esto queda fuera del alcance actual del Methodology Model (honesto,
	// no se infiere de ninguna evidencia porque no hay evidencia que ExitOne
	// sepa interpretar como "acceso obtenido").
	stages = append(stages, Stage{"initial_access", NotStarted, "ExitOne no tiene todavía una metodología para acceso inicial/explotación (fuera del alcance actual)"})

	return stages, nil
}

func count(s *store.Store, query, sessionID string) (int, error) {
	var n int
	err := s.DB.QueryRow(query, sessionID).Scan(&n)
	return n, err
}

func objectiveExists(s *store.Store, sessionID, intentKey string) (bool, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM methodology_objective WHERE session_id = ? AND intent_key = ?`, sessionID, intentKey).Scan(&n)
	return n > 0, err
}

func objectiveAnswered(s *store.Store, sessionID, intentKey string) (bool, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM methodology_objective WHERE session_id = ? AND intent_key = ? AND status = 'answered'`, sessionID, intentKey).Scan(&n)
	return n > 0, err
}

func fmtCount(format string, a, b int) string {
	if b == 0 {
		return fmt.Sprintf(format, a)
	}
	return fmt.Sprintf(format, a, b)
}
