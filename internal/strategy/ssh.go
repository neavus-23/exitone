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

// resolveHostForService replica la resolución usada en el flujo SMB: dado un
// entity_id de tipo 'service', encuentra el host del que cuelga vía HAS_SERVICE.
func resolveHostForService(s *store.Store, serviceEntityID string) (string, error) {
	var hostValue string
	err := s.DB.QueryRow(`
		SELECT e2.canonical_value FROM entity e1
		JOIN relationship r ON r.target_entity_id = e1.id AND r.kind = 'HAS_SERVICE'
		JOIN entity e2 ON e2.id = r.source_entity_id
		WHERE e1.id = ?`, serviceEntityID).Scan(&hostValue)
	return hostValue, err
}

// candidateExists evita generar el mismo candidato test_ssh_auth dos veces
// para el mismo (servicio, identidad) — comprobación simple por parámetros
// serializados, suficiente para el alcance de Slice 3.
func candidateExists(s *store.Store, sessionID, serviceEntityID, identityEntityID string) (bool, error) {
	var count int
	err := s.DB.QueryRow(`
		SELECT COUNT(*) FROM candidate
		WHERE session_id = ? AND intent_key = 'test_ssh_auth'
		AND parameters LIKE '%"service_entity_id":"` + serviceEntityID + `"%'
		AND parameters LIKE '%"identity_entity_id":"` + identityEntityID + `"%'`,
		sessionID,
	).Scan(&count)
	return count > 0, err
}

// GenerateSSHAuthCandidates cubre la fuente "methodology" del Candidate
// Generator (G1): un candidato por cada identidad conocida aún no probada
// contra un servicio SSH con el objective_path 'credential_test' abierto.
//
// Fase 3 del plan de arquitectura: antes existía una segunda fuente
// ("reopening") que generaba un candidato equivalente cuando una hipótesis
// SSH pasaba a 'reopened' vía diff de conjuntos de identidades — se retiró
// porque era exactamente el mismo candidato que este generador ya produce
// para cualquier identidad nueva sin necesitar ninguna hipótesis de por
// medio: candidateExists() deduplica por (servicio, identidad) directamente
// contra la tabla `candidate`, que ya ES la cobertura real. La reapertura de
// hipótesis (internal/hypothesis.Contradict) queda reservada para cuando
// evidencia nueva contradiga específicamente un cierre previo — un concepto
// distinto de "hay una identidad más por probar".
func GenerateSSHAuthCandidates(s *store.Store, sessionID string) ([]string, error) {
	return generateSSHMethodologyCandidates(s, sessionID)
}

func generateSSHMethodologyCandidates(s *store.Store, sessionID string) ([]string, error) {
	rows, err := s.DB.Query(`
		SELECT op.id, mo.trigger_entity_id
		FROM objective_path op
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE mo.intent_key = 'ssh_auth_investigation' AND op.path_key = 'credential_test'
		  AND op.status = 'open' AND mo.session_id = ?`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query ssh paths: %w", err)
	}
	type pr struct{ pathID, serviceEntityID string }
	var paths []pr
	for rows.Next() {
		var p pr
		if err := rows.Scan(&p.pathID, &p.serviceEntityID); err != nil {
			rows.Close()
			return nil, err
		}
		paths = append(paths, p)
	}
	rows.Close()

	identRows, err := s.DB.Query(`SELECT id, canonical_value FROM entity WHERE session_id = ? AND type = 'identity'`, sessionID)
	if err != nil {
		return nil, err
	}
	type idn struct{ id, value string }
	var idents []idn
	for identRows.Next() {
		var i idn
		if err := identRows.Scan(&i.id, &i.value); err != nil {
			identRows.Close()
			return nil, err
		}
		idents = append(idents, i)
	}
	identRows.Close()

	var created []string
	for _, p := range paths {
		host, err := resolveHostForService(s, p.serviceEntityID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, ident := range idents {
			exists, err := candidateExists(s, sessionID, p.serviceEntityID, ident.id)
			if err != nil {
				return nil, err
			}
			if exists {
				continue
			}
			id, err := insertSSHCandidate(s, sessionID, "methodology", &p.pathID, nil, p.serviceEntityID, ident.id, ident.value, host)
			if err != nil {
				return nil, err
			}
			created = append(created, id)
		}
	}
	return created, nil
}

func insertSSHCandidate(s *store.Store, sessionID, source string, objectivePathID, hypothesisID *string, serviceEntityID, identityEntityID, identityValue, host string) (string, error) {
	rendered := commandengine.RenderSSHAuthTest(
		commandengine.Slot{Value: identityValue, Provenance: "confirmed"},
		commandengine.Slot{Value: host, Provenance: "confirmed"},
	)

	var terms ScoreTerms
	var explanation string
	if source == "reopening" {
		terms = ScoreTerms{
			Novelty:              1.0,
			Relevance:            1.0,
			SourceConfidence:     0.95, // reapertura estructural determinista, no LLM
			HypothesisImpact:     1.0,  // reabre directamente una hipótesis cerrada
			ObjectiveImpact:      0.3,
			UncertaintyReduction: 0.7,
			RedundancyPenalty:    0,
		}
		explanation = fmt.Sprintf(
			"REAPERTURA ESTRUCTURAL (sección D1): la identidad %q no formaba parte del "+
				"conjunto de identidades conocidas cuando se cerró una hipótesis previa sobre "+
				"este servicio SSH. gap = known_now - known_at_test_time ≠ ∅ (comparación de "+
				"conjuntos vía ACTION_ASSUMPTION, no interpretación de texto).",
			identityValue,
		)
	} else {
		terms = ScoreTerms{
			Novelty:              1.0,
			Relevance:            1.0,
			SourceConfidence:     1.0,
			HypothesisImpact:     0.05,
			ObjectiveImpact:      0.6,
			UncertaintyReduction: 0.5,
			RedundancyPenalty:    0,
		}
		explanation = fmt.Sprintf(
			"Identidad %q conocida y servicio SSH expuesto en %s; autenticación no probada todavía para este par.",
			identityValue, host,
		)
	}
	score := terms.UtilityScore()
	termsJSON, _ := json.Marshal(terms)
	params, _ := json.Marshal(map[string]any{
		"service_entity_id":  serviceEntityID,
		"identity_entity_id": identityEntityID,
		"identity":           map[string]string{"value": identityValue, "provenance": "confirmed"},
		"target":             map[string]string{"value": host, "provenance": "confirmed"},
	})

	candID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`
		INSERT INTO candidate(
			id, session_id, source, objective_path_id, intent_key, parameters,
			tool, command_template_rendered, score, score_terms, explanation, created_at, status, hypothesis_id
		) VALUES (?, ?, ?, ?, 'test_ssh_auth', ?, ?, ?, ?, ?, ?, ?, 'proposed', ?)`,
		candID, sessionID, source, nullableStr(objectivePathID), string(params),
		rendered.Tool, rendered.FormatForShell(), score, string(termsJSON), explanation, now, nullableStr(hypothesisID),
	)
	if err != nil {
		return "", fmt.Errorf("insert ssh candidate: %w", err)
	}
	debuglog.Log("candidate_created", map[string]any{
		"candidate": candID, "source": source, "intent_key": "test_ssh_auth",
		"tool": rendered.Tool, "command": rendered.FormatForShell(),
		"score": score, "score_terms": terms, "explanation": explanation,
		"hypothesis_id": nullableStr(hypothesisID),
	})
	return candID, nil
}

func nullableStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
