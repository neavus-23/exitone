package strategy

import (
	"database/sql"

	"exitone/internal/store"
)

// stagnantAttemptThreshold — Fase 4 del plan de arquitectura: constante fija
// para MVP (decisión ya tomada, ver N.4 del plan — señal compuesta, no un
// umbral configurable), no expuesta como configuración de usuario todavía.
const stagnantAttemptThreshold = 3

type RabbitHoleWarning struct {
	StagnantObjectiveID     string
	StagnantObjectivePathID string
	StagnantIntentKey       string
	AttemptCount            int
	AlternativePathID       string
	AlternativeDescription  string
}

// DetectRabbitHole implementa la señal compuesta de la sección K del plan de
// arquitectura — nunca un solo umbral de intentos. Todas las condiciones son
// verificables mecánicamente contra tablas existentes
// (action/candidate/objective_path/outcome), sin ML:
//
//	misma rama (mismo objective_path_id)
//	+ intento semánticamente repetido (mismo intent_key)
//	+ sin observaciones/entidades/relaciones nuevas en esos intentos
//	+ sin cambio de estado del path (sigue 'open', no progresó)
//	+ existe una rama alternativa abierta con un candidato 'proposed' sin
//	  ninguna acción todavía (evidencia sin probar)
//
// Devuelve nil, nil si no hay ninguna rama que cumpla las 7 condiciones —
// no es un error, es el caso normal.
func DetectRabbitHole(s *store.Store, sessionID string) (*RabbitHoleWarning, error) {
	rows, err := s.DB.Query(`
		SELECT op.id, op.objective_id, c.intent_key, op.status,
		       COALESCE(SUM(o.new_entities), 0), COALESCE(SUM(o.new_relationships), 0),
		       COUNT(*)
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		JOIN objective_path op ON op.id = a.objective_path_id
		LEFT JOIN outcome o ON o.action_id = a.id
		WHERE c.session_id = ? AND a.status = 'resolved' AND a.objective_path_id IS NOT NULL
		GROUP BY op.id, c.intent_key
		HAVING COUNT(*) >= ?
	`, sessionID, stagnantAttemptThreshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type stagnant struct {
		pathID, objectiveID, intentKey, pathStatus string
		newEntities, newRelations, attempts        int
	}
	var candidates []stagnant
	for rows.Next() {
		var st stagnant
		if err := rows.Scan(&st.pathID, &st.objectiveID, &st.intentKey, &st.pathStatus, &st.newEntities, &st.newRelations, &st.attempts); err != nil {
			return nil, err
		}
		candidates = append(candidates, st)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, st := range candidates {
		if st.pathStatus != "open" {
			continue // ya progresó — es una rama resuelta, no un rabbit hole
		}
		if st.newEntities > 0 || st.newRelations > 0 {
			continue // sí produjo evidencia nueva, no está estancada
		}

		var altPathID, altDescription string
		err := s.DB.QueryRow(`
			SELECT op2.id, op2.description
			FROM objective_path op2
			JOIN methodology_objective mo2 ON mo2.id = op2.objective_id
			JOIN candidate c2 ON c2.objective_path_id = op2.id AND c2.status = 'proposed'
			WHERE mo2.session_id = ? AND op2.status = 'open' AND op2.id != ?
			  AND NOT EXISTS (SELECT 1 FROM action a2 WHERE a2.objective_path_id = op2.id)
			LIMIT 1
		`, sessionID, st.pathID).Scan(&altPathID, &altDescription)
		if err == sql.ErrNoRows {
			continue // no hay a dónde más ir todavía, no vale la pena advertir
		}
		if err != nil {
			return nil, err
		}

		return &RabbitHoleWarning{
			StagnantObjectiveID:     st.objectiveID,
			StagnantObjectivePathID: st.pathID,
			StagnantIntentKey:       st.intentKey,
			AttemptCount:            st.attempts,
			AlternativePathID:       altPathID,
			AlternativeDescription:  altDescription,
		}, nil
	}
	return nil, nil
}
