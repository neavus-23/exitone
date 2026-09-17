package strategy

import (
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/commandengine"
	"exitone/internal/debuglog"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// GenerateInitialDiscoveryCandidates cubre el primer Action Intent posible
// desde Investigation State VACÍO (sección Prueba 1 del protocolo de
// validación): sin esto, ExitOne no tiene nada que recomendar hasta que el
// operador ya haya corrido algo por su cuenta, lo cual contradice el
// principio de "ExitOne acompaña desde el inicio".
func GenerateInitialDiscoveryCandidates(s *store.Store, sessionID string) ([]string, error) {
	rows, err := s.DB.Query(`
		SELECT op.id, mo.trigger_entity_id
		FROM objective_path op
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE mo.intent_key = 'initial_discovery' AND op.path_key = 'port_scan'
		  AND op.status = 'open' AND mo.session_id = ?
		  AND NOT EXISTS (SELECT 1 FROM candidate c WHERE c.objective_path_id = op.id AND c.status = 'proposed')
		  AND NOT EXISTS (SELECT 1 FROM action a WHERE a.objective_path_id = op.id AND a.status = 'awaiting_evidence')`,
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("query initial_discovery paths: %w", err)
	}
	type pr struct{ pathID, hostEntityID string }
	var paths []pr
	for rows.Next() {
		var p pr
		if err := rows.Scan(&p.pathID, &p.hostEntityID); err != nil {
			rows.Close()
			return nil, err
		}
		paths = append(paths, p)
	}
	rows.Close()

	var created []string
	for _, p := range paths {
		var hostValue string
		if err := s.DB.QueryRow(`SELECT canonical_value FROM entity WHERE id = ?`, p.hostEntityID).Scan(&hostValue); err != nil {
			return nil, err
		}

		rendered := commandengine.RenderPortScan(commandengine.Slot{Value: hostValue, Provenance: "user-provided"})

		terms := ScoreTerms{
			Novelty:              1.0,
			Relevance:            1.0,
			SourceConfidence:     1.0,
			HypothesisImpact:     0.05,
			ObjectiveImpact:      1.0,
			UncertaintyReduction: 0.9, // no se sabe absolutamente nada del target todavía
			RedundancyPenalty:    0,
		}
		if err := ApplyHistoricalOutcome(s, sessionID, "discover_exposed_services", &terms); err != nil {
			return nil, err
		}
		score := terms.UtilityScore()
		explanation := fmt.Sprintf(
			"No existe información de servicios para %s (Investigation State vacío).\n"+
				"Ningún reconocimiento se ha intentado todavía (0 intentos previos).\n"+
				"Resuelve directamente el objective_path \"port_scan\" → descubre superficie expuesta.",
			hostValue,
		)
		termsJSON, _ := json.Marshal(terms)
		params, _ := json.Marshal(map[string]any{
			"target": map[string]string{"value": hostValue, "provenance": "user-provided"},
		})

		candID := uuid.NewString()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`
			INSERT INTO candidate(
				id, session_id, source, objective_path_id, intent_key, parameters,
				tool, command_template_rendered, score, score_terms, explanation, created_at, status,
				phase_key, expected_evidence
			) VALUES (?, ?, 'methodology', ?, 'discover_exposed_services', ?, ?, ?, ?, ?, ?, ?, 'proposed',
				'discovery', 'Puertos, servicios y versiones observables del target')`,
			candID, sessionID, p.pathID, string(params),
			rendered.Tool, rendered.FormatForShell(), score, string(termsJSON), explanation, now,
		); err != nil {
			return nil, fmt.Errorf("insert bootstrap candidate: %w", err)
		}
		debuglog.Log("candidate_created", map[string]any{
			"candidate": candID, "source": "methodology", "intent_key": "discover_exposed_services",
			"tool": rendered.Tool, "command": rendered.FormatForShell(),
			"score": score, "score_terms": terms, "explanation": explanation,
		})
		created = append(created, candID)
	}
	return created, nil
}
