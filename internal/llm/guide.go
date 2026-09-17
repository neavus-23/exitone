package llm

import (
	"context"
	"fmt"
	"strings"

	"exitone/internal/scope"
	"exitone/internal/stage"
	"exitone/internal/store"
)

// guideSystemPrompt produce contexto operativo breve para un pentester que
// ya conoce las herramientas. Go elige el candidato; el LLM solo comprime el
// porqué, el riesgo y el gap siguiente.
const guideSystemPrompt = `Eres un copiloto de pentesting para un operador experimentado.
Recibes: (1) las ETAPAS de la investigación con su estado real (NOT_STARTED/ACTIVE/PARTIAL/SUFFICIENT/BLOCKED/REOPENED
y la razón de cada una, ya calculadas de forma determinista), y (2) el CANDIDATO de mayor score YA calculado por ExitOne.
También puede venir (3) una nota de SCOPE ya calculada — si dice que el candidato apunta a un asset
EXCLUIDO del programa/reglas de compromiso, esa es la prioridad de tu respuesta: adviértelo primero,
antes que cualquier otra cosa, y no lo presentes como "buen próximo paso" sin esa advertencia.
Devuelve contexto operativo, no una guía didáctica: máximo 45 palabras y 3 líneas.
- Si hay advertencia de scope, la primera línea debe empezar con "SCOPE:".
- Resume por qué el candidato desbloquea evidencia útil en una línea que empiece con "WHY:".
- Solo si existe un gap inmediatamente relevante, añade "AFTER:" con el área a cubrir después.
Reglas estrictas:
- NUNCA inventes un comando o técnica que no esté en el candidato dado — para el detalle exacto existe 'exitone next'/'why'.
- NUNCA afirmes una vulnerabilidad específica no confirmada.
- No expliques qué hace la herramienta, no repitas el comando y no incluyas introducciones.
- Usa lenguaje técnico y directo. Responde en español.`

// BuildGuideContext arma el contexto de "guide" — deliberadamente más
// angosto que BuildContextSummary (ask.go): solo etapas + el candidato top,
// nunca el volcado completo de entidades/hipótesis, para que la narración
// se quede enfocada en "qué hacer ahora" y no derive en un resumen general.
func BuildGuideContext(s *store.Store, sessionID string) (string, error) {
	var candidateID, cmd, source, explanation string
	var score float64
	candErr := s.DB.QueryRow(`
		SELECT id, command_template_rendered, source, explanation, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 1`, sessionID,
	).Scan(&candidateID, &cmd, &source, &explanation, &score)

	var b strings.Builder

	// La nota de scope va PRIMERO, en su propio bloque con encabezado en
	// mayúsculas — un modelo de 3B con un prompt largo tiende a ignorar una
	// instrucción de "menciona esto primero" si el dato en sí está al final
	// del contexto (bug real observado: la regla se cargaba correctamente
	// pero el modelo igual no la mencionaba). Ponerla primero, literalmente,
	// es más confiable que pedírselo por instrucción.
	if candErr == nil {
		if note := scopeWarningFor(s, sessionID, candidateID); note != "" {
			b.WriteString("⚠️ ADVERTENCIA DE SCOPE (léela y menciónala primero, antes que cualquier otra cosa):\n")
			b.WriteString(note)
			b.WriteString("\n")
		}
	}

	stages, err := stage.Estimate(s, sessionID)
	if err != nil {
		return "", err
	}
	b.WriteString("ETAPAS:\n")
	for _, st := range stages {
		fmt.Fprintf(&b, "- %s [%s]: %s\n", st.Name, st.Status, st.Reason)
	}

	b.WriteString("\nCANDIDATO DE MAYOR SCORE (ya calculado por ExitOne — no propongas otro):\n")
	if candErr == nil {
		fmt.Fprintf(&b, "- %q (source=%s, score=%.2f). Motivo: %s\n", cmd, source, score, strings.ReplaceAll(explanation, "\n", " "))
	} else {
		b.WriteString("- (ninguno pendiente — todo lo generado ya fue aceptado o descartado; sugiere revisar 'stages'/'ingest' para generar más.)\n")
	}

	return b.String(), nil
}

// scopeWarningFor resuelve el host detrás del candidato (vía el objective
// que lo disparó o la hypothesis a la que responde) y devuelve la nota de
// scope si está EXCLUIDO — "" si no hay regla o si está in-scope/unknown
// (nunca genera ruido para el caso común sin scope configurado).
func scopeWarningFor(s *store.Store, sessionID, candidateID string) string {
	var entityID string
	err := s.DB.QueryRow(`
		SELECT mo.trigger_entity_id FROM candidate c
		JOIN objective_path op ON op.id = c.objective_path_id
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE c.id = ?`, candidateID).Scan(&entityID)
	if err != nil {
		err = s.DB.QueryRow(`
			SELECT h.subject_entity_id FROM candidate c
			JOIN hypothesis h ON h.id = c.hypothesis_id
			WHERE c.id = ?`, candidateID).Scan(&entityID)
	}
	if err != nil {
		err = s.DB.QueryRow(`
			SELECT cb.ref_id FROM candidate_basis cb
			JOIN entity e ON e.id = cb.ref_id
			WHERE cb.candidate_id = ? AND cb.ref_type = 'entity'
			ORDER BY CASE e.type WHEN 'host' THEN 0 WHEN 'service' THEN 1 ELSE 2 END
			LIMIT 1`, candidateID).Scan(&entityID)
	}
	if err != nil || entityID == "" {
		return ""
	}

	var etype, hostAddr string
	if err := s.DB.QueryRow(`SELECT type, canonical_value FROM entity WHERE id = ?`, entityID).Scan(&etype, &hostAddr); err != nil {
		return ""
	}
	if etype != "host" {
		entityValue := hostAddr
		var parentHost string
		err = s.DB.QueryRow(`
			SELECT h.canonical_value FROM relationship r
			JOIN entity h ON h.id = r.source_entity_id
			WHERE r.target_entity_id = ? AND r.kind = 'HAS_SERVICE'`, entityID).Scan(&parentHost)
		if err == nil {
			hostAddr = parentHost
		} else {
			hostAddr = ""
		}
		if err != nil && (etype == "domain" || etype == "hostname") {
			hostAddr = entityValue
		}
	}
	if hostAddr == "" {
		return ""
	}

	status, pattern, err := scope.Check(s, sessionID, hostAddr)
	if err != nil || status != scope.Out {
		return ""
	}
	return fmt.Sprintf("%s está marcado como EXCLUIDO del scope (regla: %q).\n", hostAddr, pattern)
}

// Guide responde con la narración de "por dónde seguir" a partir del
// contexto angosto de arriba.
func Guide(ctx context.Context, c *Client, guideContext string) (string, error) {
	return c.Chat(ctx, guideSystemPrompt, guideContext)
}
