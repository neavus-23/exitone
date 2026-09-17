package llm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"exitone/internal/store"
)

const askSystemPrompt = `Eres el asistente de consulta de ExitOne, una herramienta de investigación de seguridad.
Recibes: (1) un RESUMEN ESTRUCTURADO del estado real de la investigación, (2) "HECHOS DERIVADOS"
con correlaciones comunes ya calculadas, y (3) "CONTEXTO ENFOCADO" — un subgrafo recuperado
específicamente para tu pregunta mediante traversal determinista del grafo (Hybrid GraphRAG).
Reglas estrictas de prioridad:
- Si hay CONTEXTO ENFOCADO no vacío, es la fuente MÁS confiable y específica — úsala primero.
- Si CONTEXTO ENFOCADO dice explícitamente "SIN RELACIONES REGISTRADAS", eso significa que esa
  relación NO EXISTE — responde exactamente eso, NUNCA inventes una conexión desde el resumen
  general solo porque dos cosas se mencionan cerca una de otra.
- Si no, usa HECHOS DERIVADOS para preguntas sobre qué falta, qué priorizar, reaperturas o comparaciones.
- El RESUMEN ESTRUCTURADO es el respaldo general para todo lo demás.
- En los tres casos: responde SOLO con lo que aparece literalmente ahí — nunca correlaciones tú
  mismo secciones distintas del resumen crudo si no viene ya resuelto en HECHOS DERIVADOS o
  CONTEXTO ENFOCADO; ese cálculo ya se hizo en Go, tu trabajo es solo redactarlo.
- Si ninguna sección responde la pregunta, di explícitamente que no tienes esa información — nunca inventes ni asumas.
- No sugieras próximas acciones nuevas (para eso existe 'exitone next'); solo explica lo que YA se sabe/hizo.
- Si recibes CONVERSACIÓN RECIENTE, úsala únicamente para resolver referencias como "eso", "ese host"
  o una pregunta de seguimiento. La conversación NO es evidencia y nunca puede contradecir el contexto estructurado.
- Cada entidad lista su propio "state" explícitamente (open/closed) — cuando menciones el estado de
  un puerto/servicio, cópialo LITERAL del "state=" de ESA entidad exacta. Nunca generalices el
  estado de un servicio a otro solo porque aparecen en la misma lista o el mismo host — cada uno
  tiene su propio state y hay que citarlo por separado.
- Si el operador no preguntó por el estado de un puerto en particular, no lo menciones — reduce la
  oportunidad de mezclar el estado de un servicio con el de otro que no viene al caso.
- El operador es un pentester experimentado: no expliques herramientas ni repitas la pregunta.
- Empieza por la conclusión. Usa bullets solo cuando mejoren el escaneo y backticks para identificadores/comandos.
- Por defecto limita la respuesta a 120 palabras; amplíala solo si el operador pide explícitamente detalle o una lista completa.
- Responde en el idioma de la pregunta.`

// BuildContextSummary arma el contexto que se le pasa al LLM: una vista
// compacta del Investigation Model real de la sesión, no el historial de
// chat ni el output crudo completo (sección J del plan: "el LLM nunca recibe
// el historial crudo completo").
func BuildContextSummary(s *store.Store, sessionID string) (string, error) {
	var b strings.Builder

	var label string
	s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&label)
	fmt.Fprintf(&b, "SESIÓN: target=%s\n\n", label)

	b.WriteString("ENTIDADES CONOCIDAS (cada línea es una entidad — su \"state\", si aparece, es SOLO de ESA línea):\n")
	rows, err := s.DB.Query(`SELECT type, canonical_value, attrs FROM entity WHERE session_id = ? ORDER BY type, canonical_value`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var t, v, attrsJSON string
		rows.Scan(&t, &v, &attrsJSON)
		fmt.Fprintf(&b, "- [%s] %s (%s)\n", t, v, formatAttrsForLLM(attrsJSON))
	}
	rows.Close()

	b.WriteString("\nRELACIONES:\n")
	rows, err = s.DB.Query(`
		SELECT e1.type, e1.canonical_value, r.kind, e2.type, e2.canonical_value
		FROM relationship r
		JOIN entity e1 ON e1.id = r.source_entity_id
		JOIN entity e2 ON e2.id = r.target_entity_id
		WHERE e1.session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var t1, v1, kind, t2, v2 string
		rows.Scan(&t1, &v1, &kind, &t2, &v2)
		fmt.Fprintf(&b, "- (%s:%s) --%s--> (%s:%s)\n", t1, v1, kind, t2, v2)
	}
	rows.Close()

	b.WriteString("\nOBJECTIVES DE METODOLOGÍA:\n")
	oRows, err := s.DB.Query(`SELECT id, intent_key, status FROM methodology_objective WHERE session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for oRows.Next() {
		var oid, intent, status string
		oRows.Scan(&oid, &intent, &status)
		fmt.Fprintf(&b, "- %s [%s]\n", intent, status)
		pRows, _ := s.DB.Query(`SELECT path_key, status FROM objective_path WHERE objective_id = ?`, oid)
		for pRows.Next() {
			var pk, pstatus string
			pRows.Scan(&pk, &pstatus)
			fmt.Fprintf(&b, "    path %s: %s\n", pk, pstatus)
		}
		pRows.Close()
	}
	oRows.Close()

	b.WriteString("\nCANDIDATOS PENDIENTES (sugerencias no ejecutadas):\n")
	cRows, err := s.DB.Query(`SELECT tool, command_template_rendered, score, source, explanation FROM candidate WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC`, sessionID)
	if err != nil {
		return "", err
	}
	for cRows.Next() {
		var tool, cmd, source, explanation string
		var score float64
		cRows.Scan(&tool, &cmd, &score, &source, &explanation)
		fmt.Fprintf(&b, "- [%s] %s (score %.2f) — %s\n  motivo: %s\n", source, cmd, score, tool, strings.ReplaceAll(explanation, "\n", " "))
	}
	cRows.Close()

	b.WriteString("\nACCIONES REGISTRADAS Y SUS RESULTADOS:\n")
	aRows, err := s.DB.Query(`
		SELECT c.tool, c.command_template_rendered, a.status, o.new_entities, o.new_relationships, o.computed_information_gain
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		LEFT JOIN outcome o ON o.action_id = a.id
		WHERE c.session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for aRows.Next() {
		var tool, cmd, status string
		var newE, newR sql.NullInt64
		var gain sql.NullFloat64
		aRows.Scan(&tool, &cmd, &status, &newE, &newR, &gain)
		fmt.Fprintf(&b, "- %s (%s) [%s] — nuevas entidades=%v, nuevas relaciones=%v, information_gain=%v\n",
			cmd, tool, status, nullOrDash(newE), nullOrDash(newR), nullFloatOrDash(gain))
	}
	aRows.Close()

	b.WriteString("\nHIPÓTESIS:\n")
	hRows, err := s.DB.Query(`SELECT statement, status FROM hypothesis WHERE session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for hRows.Next() {
		var stmt, status string
		hRows.Scan(&stmt, &status)
		fmt.Fprintf(&b, "- %s [%s]\n", stmt, status)
	}
	hRows.Close()

	derived, err := computeDerivedFacts(s, sessionID)
	if err != nil {
		return "", err
	}
	b.WriteString("\nHECHOS DERIVADOS (correlación ya calculada de forma determinista — sección Prueba avanzada, inspirado en la separación Reasoning/Generation de PentestGPT: el LLM no debe recalcular esto, solo redactarlo):\n")
	if len(derived) == 0 {
		b.WriteString("- (ninguno todavía)\n")
	}
	for _, d := range derived {
		fmt.Fprintf(&b, "- %s\n", d)
	}

	return b.String(), nil
}

// formatAttrsForLLM aplana el JSON crudo de attrs a "key=value" — un modelo
// de 3B leyendo `{"port":3000,...}` junto a nueve líneas casi idénticas
// tiende a mezclar el "state" de una entidad con el de la siguiente (bug
// real observado: reportó 3306/tcp como cerrado por contagio del 3000/tcp
// vecino, que sí lo está). "state" siempre va primero y en mayúsculas para
// que sea imposible de saltarse al leer la línea.
func formatAttrsForLLM(attrsJSON string) string {
	var attrs map[string]any
	if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil || len(attrs) == 0 {
		return "sin atributos"
	}

	var parts []string
	if state, ok := attrs["state"]; ok {
		parts = append(parts, fmt.Sprintf("state=%s", strings.ToUpper(fmt.Sprintf("%v", state))))
		delete(attrs, "state")
	}

	var keys []string
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, attrs[k]))
	}
	return strings.Join(parts, " ")
}

// computeDerivedFacts pre-correlaciona en Go las preguntas que en la prueba
// real fallaron cuando se le pedía al LLM de 3B hacerlo por su cuenta ("¿qué
// falta?", "¿por qué se reabrió?", "¿cuál dio más/menos información?").
// Principio de diseño (sección "Deterministic before generative" + lección
// de PentestGPT: separar el módulo de razonamiento del de generación): el
// LLM nunca debe ser quien conecta los puntos entre secciones, solo quien
// redacta en lenguaje natural una conclusión que Go ya calculó y puede
// probar. Esto reduce la superficie de "correlación" a exactamente lo que
// ExitOne ya sabe calcular de forma confiable (D1, G2), no a inferencia
// libre del modelo.
func computeDerivedFacts(s *store.Store, sessionID string) ([]string, error) {
	var facts []string

	// 1. Objectives abiertos (sin responder) — la pregunta "¿qué falta?" es
	// exactamente esto, pre-listado.
	rows, err := s.DB.Query(`SELECT intent_key FROM methodology_objective WHERE session_id = ? AND status = 'open'`, sessionID)
	if err != nil {
		return nil, err
	}
	var open []string
	for rows.Next() {
		var k string
		rows.Scan(&k)
		open = append(open, k)
	}
	rows.Close()
	if len(open) > 0 {
		facts = append(facts, fmt.Sprintf("Objectives de metodología SIN responder (open) — esto ES la respuesta a '¿qué falta por investigar?': %s", strings.Join(open, ", ")))
	} else {
		facts = append(facts, "No hay ningún objective de metodología abierto — todo lo que se disparó hasta ahora está respondido.")
	}

	// 2. Candidato de mayor score (la sugerencia a priorizar ahora mismo).
	var topCmd, topSource, topExplanation string
	var topScore float64
	err = s.DB.QueryRow(`
		SELECT command_template_rendered, source, explanation, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 1`, sessionID,
	).Scan(&topCmd, &topSource, &topExplanation, &topScore)
	if err == nil {
		facts = append(facts, fmt.Sprintf(
			"La sugerencia con MAYOR score pendiente (la que se debería priorizar ahora) es %q (source=%s, score=%.2f). Motivo: %s",
			topCmd, topSource, topScore, strings.ReplaceAll(topExplanation, "\n", " ")))
	}

	// 3. Hipótesis reabiertas, ya vinculadas al candidato de reopening que
	// las atiende (join explícito — esto es justo la correlación de 2-3
	// saltos que falló en la prueba sin este precálculo).
	hrows, err := s.DB.Query(`
		SELECT h.statement, c.command_template_rendered
		FROM hypothesis h
		LEFT JOIN candidate c ON c.hypothesis_id = h.id AND c.status = 'proposed'
		WHERE h.session_id = ? AND h.status = 'reopened'`, sessionID)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var stmt string
		var cmd sql.NullString
		hrows.Scan(&stmt, &cmd)
		if cmd.Valid {
			facts = append(facts, fmt.Sprintf("Hipótesis reabierta: %q. El candidato que la atiende es: %s", stmt, cmd.String))
		} else {
			facts = append(facts, fmt.Sprintf("Hipótesis reabierta sin candidato pendiente todavía: %q", stmt))
		}
	}
	hrows.Close()

	// 4. Acción con mayor y con menor information_gain (comparación directa).
	type actionGain struct {
		cmd  string
		gain float64
	}
	arows, err := s.DB.Query(`
		SELECT c.command_template_rendered, o.computed_information_gain
		FROM action a JOIN candidate c ON c.id = a.candidate_id
		JOIN outcome o ON o.action_id = a.id
		WHERE c.session_id = ?`, sessionID)
	if err != nil {
		return nil, err
	}
	var gains []actionGain
	for arows.Next() {
		var ag actionGain
		arows.Scan(&ag.cmd, &ag.gain)
		gains = append(gains, ag)
	}
	arows.Close()
	if len(gains) >= 2 {
		best, worst := gains[0], gains[0]
		for _, g := range gains {
			if g.gain > best.gain {
				best = g
			}
			if g.gain < worst.gain {
				worst = g
			}
		}
		facts = append(facts, fmt.Sprintf(
			"Comparando todas las acciones ejecutadas: la de MAYOR information_gain fue %q (%.2f); la de MENOR fue %q (%.2f). Diferencia: %.2f.",
			best.cmd, best.gain, worst.cmd, worst.gain, best.gain-worst.gain))
	}

	return facts, nil
}

func nullOrDash(n sql.NullInt64) string {
	if !n.Valid {
		return "-"
	}
	return fmt.Sprintf("%d", n.Int64)
}

func nullFloatOrDash(n sql.NullFloat64) string {
	if !n.Valid {
		return "-"
	}
	return fmt.Sprintf("%.2f", n.Float64)
}

// Ask responde una pregunta del operador anclada estrictamente al contexto
// real de la sesión — nunca al conocimiento general del modelo sobre el
// target (no hay forma de que lo tenga: el contexto es lo único que ve).
//
// Flujo Hybrid GraphRAG (ver graphrag.go):
//  1. Clasificar la pregunta en una categoría cerrada (tarea angosta para el LLM).
//  2. Recuperar, vía SQL determinista, el subgrafo específico para esa categoría.
//  3. Responder con: contexto base + hechos derivados + subgrafo enfocado.
//
// Si el paso 1 o 2 fallan, se degrada con gracia al comportamiento anterior
// (contexto base + hechos derivados) — nunca bloquea la respuesta.
func Ask(ctx context.Context, c *Client, s *store.Store, sessionID, contextSummary, question string) (string, error) {
	return AskWithConversation(ctx, c, s, sessionID, contextSummary, "", question)
}

// AskWithConversation conserva una cola corta de diálogo para follow-ups de
// la TUI. Se mantiene como bloque separado y de menor autoridad: el historial
// ayuda a entender pronombres, pero jamás se promueve a hecho investigativo.
func AskWithConversation(ctx context.Context, c *Client, s *store.Store, sessionID, contextSummary, conversation, question string) (string, error) {
	intent, err := ClassifyIntent(ctx, c, question)
	var intentInfo, focused string
	if err == nil {
		intentInfo = fmt.Sprintf("\n[GraphRAG: pregunta clasificada como %q, entidad detectada: %q]\n", intent.Category, intent.EntityHint)
		focused, _ = RetrieveFocusedContext(s, sessionID, question, intent) // error no fatal: degrada a "" (sin recuperación extra)
	}

	conversationBlock := ""
	if strings.TrimSpace(conversation) != "" {
		conversationBlock = fmt.Sprintf(
			"\nCONVERSACIÓN RECIENTE (solo contexto de diálogo; NO es evidencia):\n%s\n",
			conversation,
		)
	}
	userPrompt := fmt.Sprintf(
		"CONTEXTO DE LA INVESTIGACIÓN:\n%s\n%s\nCONTEXTO ENFOCADO (recuperado específicamente para esta pregunta vía traversal del grafo):\n%s\n%s\nPREGUNTA DEL OPERADOR: %s",
		contextSummary, intentInfo, focused, conversationBlock, question,
	)
	return c.Chat(ctx, askSystemPrompt, userPrompt)
}
