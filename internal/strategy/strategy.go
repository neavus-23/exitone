// Package strategy implementa el Candidate Generator (multi-fuente, sección
// G1) y el Strategy Ranker con EIG cualitativo (sección G2, punto 8 del
// changelog v2 — factores multiplicativos, no solo volumen).
package strategy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/commandengine"
	"exitone/internal/debuglog"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// ScoreTerms — cada factor en [0,1] salvo la penalización (sección G2).
//
// Corrección de nomenclatura (Fase 4 del plan de arquitectura): esto NO es
// Expected Information Gain en sentido estadístico (no hay un modelo
// probabilístico detrás) — es una heurística multiplicativa de utilidad.
// UtilityScore() es el nombre honesto; las columnas de DB (`candidate.score`,
// `outcome.computed_information_gain`) se mantienen tal cual para no migrar
// nada, pero ningún nombre Go nuevo debe sugerir más precisión de la que hay.
type ScoreTerms struct {
	Novelty              float64 `json:"novelty"`
	Relevance            float64 `json:"relevance"`
	SourceConfidence     float64 `json:"confidence_source"`
	HypothesisImpact     float64 `json:"hypothesis_impact"`
	ObjectiveImpact      float64 `json:"objective_impact"`
	UncertaintyReduction float64 `json:"uncertainty_reduction"`
	RedundancyPenalty    float64 `json:"redundancy_penalty"`
}

// UtilityScore calcula el puntaje heurístico de un candidato — ver el
// comentario de ScoreTerms sobre por qué no se llama "InformationGain".
func (t ScoreTerms) UtilityScore() float64 {
	base := t.Novelty * t.Relevance * t.SourceConfidence *
		max(t.HypothesisImpact, 0.05) * // nunca 0 total: un candidato sin hipótesis afectadas
		max(t.ObjectiveImpact, 0.05) * // aún puede tener algo de valor exploratorio
		t.UncertaintyReduction
	return base - t.RedundancyPenalty
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// GenerateAndRankMethodologyCandidates es el Candidate Generator restringido a
// la fuente "methodology" (única fuente activa en Slice 1 — sección L).
// Para cada objective_path abierto sin candidato 'proposed' ya pendiente,
// genera un candidato, lo puntúa y lo persiste.
func GenerateAndRankMethodologyCandidates(s *store.Store, sessionID string) ([]string, error) {
	rows, err := s.DB.Query(`
		SELECT op.id, op.path_key, op.description, mo.intent_key, mo.trigger_entity_id
		FROM objective_path op
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE op.status = 'open' AND mo.session_id = ?
		  AND NOT EXISTS (
		      SELECT 1 FROM candidate c
		      WHERE c.objective_path_id = op.id AND c.status = 'proposed'
		  )
		  AND NOT EXISTS (
		      -- Sin esto, aceptar un candidato y no resolverlo todavía deja el
		      -- path 'open' y una regeneración posterior vuelve a sugerirlo
		      -- (mismo bug de fondo encontrado con nmap/smbclient en el lab).
		      SELECT 1 FROM action a
		      WHERE a.objective_path_id = op.id AND a.status = 'awaiting_evidence'
		  )
	`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query open paths: %w", err)
	}
	defer rows.Close()

	type pathRow struct {
		pathID, pathKey, description, intentKey, triggerEntityID string
	}
	var paths []pathRow
	for rows.Next() {
		var p pathRow
		if err := rows.Scan(&p.pathID, &p.pathKey, &p.description, &p.intentKey, &p.triggerEntityID); err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}

	var created []string
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for _, p := range paths {
		// Solo el camino "anonymous_access" tiene template determinista en Slice 1
		// (los otros requieren credenciales/otra fuente que aún no existen — quedan
		// abiertos como candidatos futuros, no se fuerza un comando sin sentido).
		if p.pathKey != "anonymous_access" || p.intentKey != "smb_enumeration" {
			continue
		}

		var hostValue string
		err := s.DB.QueryRow(`
			SELECT e2.canonical_value FROM entity e1
			JOIN relationship r ON r.target_entity_id = e1.id AND r.kind = 'HAS_SERVICE'
			JOIN entity e2 ON e2.id = r.source_entity_id
			WHERE e1.id = ?`, p.triggerEntityID).Scan(&hostValue)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve host for service: %w", err)
		}

		rendered, err := commandengine.Render("enumerate_smb_shares_anonymous",
			commandengine.Slot{Value: hostValue, Provenance: "confirmed"})
		if err != nil {
			return nil, err
		}

		terms := ScoreTerms{
			Novelty:              1.0, // nada se sabe aún de shares/dominio
			Relevance:            1.0, // directamente conectado al objective disparado
			SourceConfidence:     1.0, // metodología determinista, trigger confirmado por nmap
			HypothesisImpact:     0.05,
			ObjectiveImpact:      1.0, // resuelve directamente este path
			UncertaintyReduction: 0.8,
			RedundancyPenalty:    0,
		}
		score := terms.UtilityScore()

		explanation := fmt.Sprintf(
			"SMB expuesto en %s (observación determinista de nmap).\n"+
				"Enumeración SMB no se ha intentado todavía (0 intentos previos).\n"+
				"Resuelve directamente el objective_path %q → dominio/shares desconocidos.",
			hostValue, p.pathKey,
		)

		termsJSON, _ := json.Marshal(terms)
		params, _ := json.Marshal(map[string]any{
			"target": map[string]string{"value": hostValue, "provenance": "confirmed"},
		})

		candID := uuid.NewString()
		if _, err := s.DB.Exec(`
			INSERT INTO candidate(
				id, session_id, source, objective_path_id, intent_key, parameters,
				tool, command_template_rendered, score, score_terms, explanation, created_at, status
			) VALUES (?, ?, 'methodology', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed')`,
			candID, sessionID, p.pathID, p.intentKey, string(params),
			rendered.Tool, rendered.FormatForShell(), score, string(termsJSON), explanation, now,
		); err != nil {
			return nil, fmt.Errorf("insert candidate: %w", err)
		}
		debuglog.Log("candidate_created", map[string]any{
			"candidate": candID, "source": "methodology", "intent_key": p.intentKey,
			"tool": rendered.Tool, "command": rendered.FormatForShell(),
			"score": score, "score_terms": terms, "explanation": explanation,
		})
		created = append(created, candID)
	}

	return created, nil
}
