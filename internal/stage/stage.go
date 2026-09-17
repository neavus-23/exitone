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

// Status es uno de los seis estados discretos que puede tener una etapa de
// la investigación — nunca un porcentaje ni una probabilidad.
type Status string

const (
	NotStarted Status = "NOT_STARTED"
	Active     Status = "ACTIVE"
	Partial    Status = "PARTIAL"
	Sufficient Status = "SUFFICIENT"
	Blocked    Status = "BLOCKED"
	Reopened   Status = "REOPENED"
)

// Stage es el estado calculado de una etapa de la investigación (discovery,
// enumeration, validation, etc.) junto con la razón trazable a una consulta
// real que llevó a asignarle ese Status.
type Stage struct {
	Name   string
	Status Status
	Reason string // por qué se asignó este estado — siempre trazable a una cuenta real
}

// Estimate calcula el estado de todas las etapas conocidas para una sesión,
// en el orden fijo discovery → enumeration → analysis → hypotheses →
// validation → exploitation_guidance → post_access → privilege_access →
// objectives. Cada Stage.Reason cita el conteo real que la produjo.
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
		stages = append(stages, Stage{"discovery", NotStarted, "0 entidades type=service en la sesión"})
	case initialDiscoveryAnswered:
		stages = append(stages, Stage{"discovery", Sufficient, "objective 'initial_discovery' respondido y hay entidades de servicio"})
	default:
		stages = append(stages, Stage{"discovery", Active, "hay servicios observados y preguntas de descubrimiento todavía abiertas"})
	}

	openEnumeration, err := count(s, `SELECT COUNT(*) FROM methodology_objective WHERE session_id = ? AND phase_key = 'enumeration' AND status = 'open'`, sessionID)
	if err != nil {
		return nil, err
	}
	answeredEnumeration, err := count(s, `SELECT COUNT(*) FROM methodology_objective WHERE session_id = ? AND phase_key = 'enumeration' AND status = 'answered'`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case openEnumeration == 0 && answeredEnumeration == 0:
		stages = append(stages, Stage{"enumeration", NotStarted, "ningún servicio o dominio abrió preguntas de enumeración"})
	case openEnumeration == 0:
		stages = append(stages, Stage{"enumeration", Sufficient, fmtCount("%d objective(s) de enumeración respondidos", answeredEnumeration, 0)})
	case answeredEnumeration > 0:
		stages = append(stages, Stage{"enumeration", Partial, fmt.Sprintf("%d objective(s) respondidos y %d abiertos", answeredEnumeration, openEnumeration)})
	default:
		stages = append(stages, Stage{"enumeration", Active, fmtCount("%d objective(s) de enumeración abiertos", openEnumeration, 0)})
	}

	fingerprintedCount, err := count(s, `
		SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service' AND json_extract(attrs, '$.product') IS NOT NULL`,
		sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case serviceCount == 0:
		stages = append(stages, Stage{"analysis", NotStarted, "no hay servicios ni relaciones que analizar todavía"})
	case fingerprintedCount == 0:
		stages = append(stages, Stage{"analysis", Active, "hay servicios conocidos pero ninguna versión/producto confirmado"})
	case fingerprintedCount < serviceCount:
		stages = append(stages, Stage{"analysis", Partial, fmtCount("%d de %d servicios tienen producto/versión identificado", fingerprintedCount, serviceCount)})
	default:
		stages = append(stages, Stage{"analysis", Sufficient, "todos los servicios conocidos tienen producto/versión identificado; los gaps adicionales siguen en objectives"})
	}

	hypothesisCount, err := count(s, `SELECT COUNT(*) FROM hypothesis WHERE session_id = ?`, sessionID)
	if err != nil {
		return nil, err
	}
	reopenedHypCount, err := count(s, `SELECT COUNT(*) FROM hypothesis WHERE session_id = ? AND status = 'reopened'`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case reopenedHypCount > 0:
		stages = append(stages, Stage{"hypotheses", Reopened, fmtCount("%d hipótesis reabierta(s) por contradicción nueva", reopenedHypCount, 0)})
	case hypothesisCount == 0:
		stages = append(stages, Stage{"hypotheses", NotStarted, "no hay hipótesis falsables registradas"})
	default:
		stages = append(stages, Stage{"hypotheses", Active, fmtCount("%d hipótesis registradas", hypothesisCount, 0)})
	}

	validationActions, err := count(s, `SELECT COUNT(*) FROM action a JOIN candidate c ON c.id = a.candidate_id WHERE c.session_id = ? AND c.phase_key = 'validation'`, sessionID)
	if err != nil {
		return nil, err
	}
	// Confirmar o refutar una hipótesis ES el acto de validación (probar algo
	// falsable y cerrarlo con evidencia) — no solo un candidate aceptado con
	// phase_key='validation'. Bug real encontrado validando ExitOne contra
	// HTB Nexus: toda la fase de validación real (probar login SSH con la
	// password filtrada en git, confirmar el login al CRM, etc.) se hizo
	// operando directamente contra el target y cerrando la hipótesis con
	// `hypothesis confirm`/`refute` — nunca se pasó por el loop
	// next→accept→resolve, así que 0 acciones con ese phase_key no significa
	// "no se validó nada", solo que no se validó POR ESE camino en particular.
	closedHypotheses, err := count(s, `SELECT COUNT(*) FROM hypothesis WHERE session_id = ? AND status IN ('confirmed','refuted')`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case validationActions == 0 && closedHypotheses == 0:
		stages = append(stages, Stage{"validation", NotStarted, "0 acciones de validación y 0 hipótesis confirmadas/refutadas"})
	default:
		stages = append(stages, Stage{"validation", Active, fmt.Sprintf("%d acción(es) de validación observadas, %d hipótesis confirmada(s)/refutada(s)", validationActions, closedHypotheses)})
	}

	exploitationCandidates, err := count(s, `SELECT COUNT(*) FROM candidate WHERE session_id = ? AND phase_key = 'exploitation_guidance'`, sessionID)
	if err != nil {
		return nil, err
	}
	// Mismo principio: un hallazgo ya CONFIRMADO de severidad alta/crítica es
	// evidencia directa de que se llegó a explotar algo, independientemente
	// de si ExitOne llegó a proponer un candidate de esa fase primero. La
	// severidad es un campo explícito fijado por el operador al confirmar
	// (`hypothesis confirm --severity`), nunca inferido de texto libre.
	confirmedExploits, err := count(s, `SELECT COUNT(*) FROM hypothesis WHERE session_id = ? AND status = 'confirmed' AND severity IN ('critical','high')`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case exploitationCandidates == 0 && confirmedExploits == 0:
		stages = append(stages, Stage{"exploitation_guidance", NotStarted, "ninguna dirección de explotación respaldada por el estado actual"})
	default:
		stages = append(stages, Stage{"exploitation_guidance", Active, fmt.Sprintf("%d candidato(s) de guía de explotación; %d hallazgo(s) crítico(s)/alto(s) ya confirmados; ejecución siempre humana", exploitationCandidates, confirmedExploits)})
	}

	accessCount, err := count(s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type IN ('access_context','principal')`, sessionID)
	if err != nil {
		return nil, err
	}
	if accessCount == 0 {
		stages = append(stages, Stage{"post_access", NotStarted, "no existe evidencia confirmada de un contexto de acceso"})
	} else {
		stages = append(stages, Stage{"post_access", Active, fmtCount("%d contexto(s) de acceso/principal observados", accessCount, 0)})
	}

	privilegeCount, err := count(s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'privilege'`, sessionID)
	if err != nil {
		return nil, err
	}
	if privilegeCount == 0 {
		stages = append(stages, Stage{"privilege_access", NotStarted, "no hay capacidades o privilegios confirmados que analizar"})
	} else {
		stages = append(stages, Stage{"privilege_access", Active, fmtCount("%d capacidad(es)/privilegio(s) observados", privilegeCount, 0)})
	}

	openObjectives, err := count(s, `SELECT COUNT(*) FROM operator_objective WHERE session_id = ? AND status = 'open'`, sessionID)
	if err != nil {
		return nil, err
	}
	completedObjectives, err := count(s, `SELECT COUNT(*) FROM operator_objective WHERE session_id = ? AND status = 'completed'`, sessionID)
	if err != nil {
		return nil, err
	}
	switch {
	case openObjectives == 0 && completedObjectives == 0:
		stages = append(stages, Stage{"objectives", NotStarted, "el operador todavía no definió un objetivo final"})
	case openObjectives == 0:
		stages = append(stages, Stage{"objectives", Sufficient, fmtCount("%d objetivo(s) completados con cierre explícito", completedObjectives, 0)})
	default:
		stages = append(stages, Stage{"objectives", Active, fmt.Sprintf("%d objetivo(s) abiertos; %d completados", openObjectives, completedObjectives)})
	}

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
