package strategy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"exitone/internal/commandengine"
	"exitone/internal/debuglog"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// interestingEndpointKeywords — regla explícita y pequeña (mismo estilo que
// el resto del paquete), no un motor genérico de clasificación de riesgo:
// si la URL de un endpoint descubierto contiene alguna de estas palabras,
// vale la pena mirarlo antes que otros endpoints genéricos.
var interestingEndpointKeywords = []string{
	"phpmyadmin", "admin", "wp-admin", "backup", "config", ".git", ".env", "login", "upload", "manager",
}

// GenerateEndpointFollowupCandidates es el Candidate Generator para la fuente
// "methodology" aplicada a entity(type='endpoint') recién descubiertas por el
// extractor genérico de dirb/gobuster/ffuf (ver internal/parsers,
// internal/investigation.ApplyScanResult). No sugiere nada por cada endpoint
// (produciría ruido) — solo cuando el endpoint contiene una palabra clave de
// interés, y solo una vez por endpoint (dedup por parameters.target.value).
func GenerateEndpointFollowupCandidates(s *store.Store, sessionID string, newEntityIDs []string) ([]string, error) {
	if len(newEntityIDs) == 0 {
		return nil, nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var created []string

	for _, entID := range newEntityIDs {
		var entType, canonicalValue string
		err := s.DB.QueryRow(`SELECT type, canonical_value FROM entity WHERE id = ? AND session_id = ?`, entID, sessionID).Scan(&entType, &canonicalValue)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint entity: %w", err)
		}
		if entType != "endpoint" {
			continue
		}

		lower := strings.ToLower(canonicalValue)
		matched := ""
		for _, kw := range interestingEndpointKeywords {
			if strings.Contains(lower, kw) {
				matched = kw
				break
			}
		}
		if matched == "" {
			continue
		}

		var exists int
		if err := s.DB.QueryRow(
			`SELECT COUNT(*) FROM candidate WHERE session_id = ? AND intent_key = 'inspect_endpoint' AND parameters LIKE ?`,
			sessionID, "%"+canonicalValue+"%",
		).Scan(&exists); err != nil {
			return nil, err
		}
		if exists > 0 {
			continue // ya se sugirió inspeccionar este mismo endpoint
		}

		rendered := commandengine.RenderEndpointFollowup(commandengine.Slot{Value: canonicalValue, Provenance: "confirmed"})

		terms := ScoreTerms{
			Novelty:              1.0, // endpoint recién descubierto, nunca inspeccionado
			Relevance:            0.8, // palabra clave de interés, no una confirmación de vulnerabilidad
			SourceConfidence:     1.0, // extractor determinista (dirb/ffuf/gobuster), no LLM
			HypothesisImpact:     0.05,
			ObjectiveImpact:      0.6, // progresa el path "endpoints" de http_enumeration, no lo resuelve del todo
			UncertaintyReduction: 0.6,
			RedundancyPenalty:    0,
		}
		score := terms.Score()

		explanation := fmt.Sprintf(
			"Endpoint %q contiene la palabra clave %q (posible panel de administración/backup/config expuesto).\n"+
				"Descubierto por enumeración web determinista, sin inspeccionar todavía.",
			canonicalValue, matched,
		)

		termsJSON, _ := json.Marshal(terms)
		params, _ := json.Marshal(map[string]any{
			"target": map[string]string{"value": canonicalValue, "provenance": "confirmed"},
		})

		candID := uuid.NewString()
		if _, err := s.DB.Exec(`
			INSERT INTO candidate(
				id, session_id, source, objective_path_id, intent_key, parameters,
				tool, command_template_rendered, score, score_terms, explanation, created_at, status
			) VALUES (?, ?, 'methodology', NULL, 'inspect_endpoint', ?, ?, ?, ?, ?, ?, ?, 'proposed')`,
			candID, sessionID, string(params),
			rendered.Tool, rendered.FormatForShell(), score, string(termsJSON), explanation, now,
		); err != nil {
			return nil, fmt.Errorf("insert candidate: %w", err)
		}
		debuglog.Log("candidate_created", map[string]any{
			"candidate": candID, "source": "methodology", "intent_key": "inspect_endpoint",
			"tool": rendered.Tool, "command": rendered.FormatForShell(),
			"score": score, "score_terms": terms, "explanation": explanation,
		})
		created = append(created, candID)
	}

	return created, nil
}
