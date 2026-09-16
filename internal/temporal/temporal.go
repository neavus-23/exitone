// Package temporal implementa el Temporal Reasoner (sección C1/D1 del plan):
// detecta cuándo una HYPOTHESIS cerrada debe reabrirse, por comparación
// ESTRUCTURAL de conjuntos de entidades — nunca interpretando el texto de la
// hipótesis. Esta es la pieza que Slice 3 debía validar como diferenciador
// central de ExitOne frente a un wrapper de LLM (ver sección P, kill
// criterion "Nuevo").
package temporal

import (
	"exitone/internal/store"
)

type GapEntity struct {
	ID    string
	Value string
}

// gapForHypothesis calcula, para una hipótesis dada, qué entidades del tipo
// relevante (identity) existen AHORA en la sesión pero NO estaban en
// ACTION_ASSUMPTION (role='known_identity') de la acción que la cerró.
// known_at_test_time = { entidades en ACTION_ASSUMPTION de esa ACTION }
// known_now          = { entidades type=identity en la sesión, ahora }
// gap                = known_now - known_at_test_time
func gapForHypothesis(s *store.Store, hypothesisID string) ([]GapEntity, error) {
	var sessionID string
	if err := s.DB.QueryRow(`SELECT session_id FROM hypothesis WHERE id = ?`, hypothesisID).Scan(&sessionID); err != nil {
		return nil, err
	}

	rows, err := s.DB.Query(`
		SELECT e.id, e.canonical_value
		FROM entity e
		WHERE e.session_id = ? AND e.type = 'identity'
		AND e.id NOT IN (
			SELECT aa.entity_id
			FROM action_hypothesis ah
			JOIN action_assumption aa ON aa.action_id = ah.action_id AND aa.role = 'known_identity'
			WHERE ah.hypothesis_id = ?
		)`, sessionID, hypothesisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var gap []GapEntity
	for rows.Next() {
		var g GapEntity
		if err := rows.Scan(&g.ID, &g.Value); err != nil {
			return nil, err
		}
		gap = append(gap, g)
	}
	return gap, rows.Err()
}

// DetectReopenings revisa todas las hipótesis 'closed' de la sesión y marca
// como 'reopened' las que tengan un gap no vacío. Devuelve los IDs reabiertos.
// Es una consulta SQL determinista (comparación de conjuntos vía joins), tal
// como exige la sección D1 — no hay LLM ni matching de texto involucrado.
func DetectReopenings(s *store.Store, sessionID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT id FROM hypothesis WHERE session_id = ? AND status = 'closed'`, sessionID)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()

	var reopened []string
	for _, id := range ids {
		gap, err := gapForHypothesis(s, id)
		if err != nil {
			return nil, err
		}
		if len(gap) > 0 {
			if _, err := s.DB.Exec(`UPDATE hypothesis SET status = 'reopened' WHERE id = ?`, id); err != nil {
				return nil, err
			}
			reopened = append(reopened, id)
		}
	}
	return reopened, nil
}

// GapEntitiesFor expone el mismo cálculo para que el Candidate Generator
// pueda generar un candidato de reapertura por cada entidad del gap.
func GapEntitiesFor(s *store.Store, hypothesisID string) ([]GapEntity, error) {
	return gapForHypothesis(s, hypothesisID)
}
