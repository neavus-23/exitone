// Package llm — Hybrid GraphRAG para `exitone ask` (generaliza el fix puntual
// de computeDerivedFacts, sección "corrige el problema" de la sesión de
// pruebas contra el lab).
//
// Por qué GraphRAG y no vector RAG: el dominio de ExitOne YA es un grafo
// relacional (entity/relationship/hypothesis/candidate/action conectados por
// FKs en SQLite), y el volumen por sesión es pequeño (decenas de filas, no
// miles de documentos). Trocear texto y embeder para similitud coseno no
// resolvería nada que un JOIN no resuelva ya mejor y de forma determinista —
// añadir pgvector aquí sería sobreingeniería (sección K/O del plan: "simple
// antes que distribuido"). Lo que sí generaliza el problema real (el LLM de
// 3B no correlaciona bien preguntas abiertas) es separar:
//
//	pregunta en lenguaje natural
//	        ↓ (LLM: tarea ANGOSTA de clasificación — no de síntesis)
//	intent + entidad mencionada
//	        ↓ (Go: traversal determinista del grafo vía SQL — sin LLM)
//	subgrafo enfocado y ya correlacionado
//	        ↓ (LLM: solo redacta en lenguaje natural)
//	respuesta
//
// Esto es la misma separación Reasoning/Generation que usa PentestGPT, pero
// el "Reasoning" aquí es SQL, no otro LLM — más barato, más confiable, y
// consistente con "deterministic before generative".
package llm

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"exitone/internal/debuglog"
	"exitone/internal/store"
)

type Intent struct {
	Category   string `json:"category"`    // pending_work | reopening_chain | tool_comparison | entity_detail | general
	EntityHint string `json:"entity_hint"` // valor literal mencionado en la pregunta (ej. "admin", "ssh", "192.168.72.130"), o ""
}

const classifySystemPrompt = `Clasificas preguntas sobre una investigación de seguridad en UNA de estas categorías exactas:
- "pending_work": qué falta, qué priorizar, qué sigue, qué está sin responder
- "reopening_chain": por qué se reabrió algo, qué causó un cambio de hipótesis, relación entre una identidad nueva y una conclusión anterior
- "tool_comparison": comparar resultados/ganancia de información entre acciones o herramientas
- "entity_detail": preguntas sobre una entidad específica (un host, servicio, share, identidad) y sus relaciones directas
- "general": cualquier otra cosa

También extrae, si aparece literalmente en la pregunta, el nombre/valor de la entidad o herramienta mencionada (ej. "admin", "smbclient", "192.168.72.130") en "entity_hint". Si no hay ninguna, deja "entity_hint" vacío.

Responde EXCLUSIVAMENTE con un objeto JSON: {"category": "...", "entity_hint": "..."}
Sin texto adicional, sin markdown.`

// ClassifyIntent es la única llamada al LLM que hace una tarea de
// clasificación cerrada (5 categorías) en vez de síntesis abierta — mucho
// más confiable para un modelo pequeño que "responde la pregunta".
func ClassifyIntent(ctx context.Context, c *Client, question string) (Intent, error) {
	raw, err := c.Chat(ctx, classifySystemPrompt, question)
	if err != nil {
		debuglog.LogError("graphrag_classify", err, map[string]any{"question": question})
		return Intent{Category: "general"}, err
	}
	jsonStr := extractJSONObject(raw)
	if jsonStr == "" {
		debuglog.Log("graphrag_classify", map[string]any{"question": question, "raw": raw, "warning": "no json object found, fallback general"})
		return Intent{Category: "general"}, nil // fallback seguro, no falla la consulta completa
	}
	var intent Intent
	if err := json.Unmarshal([]byte(jsonStr), &intent); err != nil {
		debuglog.LogError("graphrag_classify_parse", err, map[string]any{"question": question, "raw": raw})
		return Intent{Category: "general"}, nil
	}
	if intent.Category == "" {
		intent.Category = "general"
	}
	intent.EntityHint = stripTypeWords(intent.EntityHint)
	debuglog.Log("graphrag_classify", map[string]any{"question": question, "intent": intent})
	return intent, nil
}

// stripTypeWords limpia palabras de tipo que el clasificador a veces incluye
// junto al valor (ej. devolvió "identidad public" en vez de solo "public"),
// rompiendo el LIKE de retrieveEntityDetail. Defensivo: no confiar en que el
// LLM devuelva el JSON perfectamente limpio incluso cuando se le pide.
func stripTypeWords(hint string) string {
	words := strings.Fields(hint)
	var kept []string
	for _, w := range words {
		if _, isType := entityTypeHints[strings.ToLower(w)]; isType {
			continue
		}
		kept = append(kept, w)
	}
	return strings.TrimSpace(strings.Join(kept, " "))
}

func extractJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start == -1 {
		return ""
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// RetrieveFocusedContext hace el traversal determinista del grafo según el
// intent clasificado. Nunca reemplaza el contexto base (sigue yendo también
// el resumen completo + hechos derivados) — esto es la parte "híbrida": una
// base siempre presente + una recuperación dirigida encima.
func RetrieveFocusedContext(s *store.Store, sessionID, question string, intent Intent) (string, error) {
	switch intent.Category {
	case "reopening_chain":
		return retrieveReopeningChain(s, sessionID, intent.EntityHint)
	case "tool_comparison":
		return retrieveToolComparison(s, sessionID, intent.EntityHint)
	case "entity_detail":
		return retrieveEntityDetail(s, sessionID, intent.EntityHint, question)
	case "pending_work":
		return retrievePendingWork(s, sessionID)
	default:
		return "", nil // "general": sin recuperación adicional, solo contexto base + hechos derivados
	}
}

// retrieveReopeningChain hace el traversal completo hipótesis -> acción que
// la cerró -> identidades conocidas en ese momento -> gap -> candidato de
// reapertura. Es EXACTAMENTE la cadena de 3 saltos que falló cuando se le
// pidió al LLM que la reconstruyera él solo (sección D1).
func retrieveReopeningChain(s *store.Store, sessionID, entityHint string) (string, error) {
	var b strings.Builder
	rows, err := s.DB.Query(`
		SELECT h.id, h.statement, h.status, a.id
		FROM hypothesis h
		JOIN action_hypothesis ah ON ah.hypothesis_id = h.id AND ah.relation_kind = 'TESTED'
		JOIN action a ON a.id = ah.action_id
		WHERE h.session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	type hyp struct{ id, statement, status, actionID string }
	var hyps []hyp
	for rows.Next() {
		var h hyp
		rows.Scan(&h.id, &h.statement, &h.status, &h.actionID)
		hyps = append(hyps, h)
	}
	rows.Close()

	if len(hyps) == 0 {
		return "", nil
	}
	b.WriteString("CADENA DE REAPERTURA (traversal directo del grafo, ya resuelto):\n")
	for _, h := range hyps {
		fmt.Fprintf(&b, "- Hipótesis: %q [%s]\n", h.statement, h.status)

		var known []string
		kr, _ := s.DB.Query(`
			SELECT e.canonical_value FROM action_assumption aa
			JOIN entity e ON e.id = aa.entity_id
			WHERE aa.action_id = ? AND aa.role = 'known_identity'`, h.actionID)
		for kr.Next() {
			var v string
			kr.Scan(&v)
			known = append(known, v)
		}
		kr.Close()
		fmt.Fprintf(&b, "  Identidades conocidas cuando se cerró: %s\n", strings.Join(known, ", "))

		if h.status == "reopened" {
			cr, _ := s.DB.Query(`
				SELECT command_template_rendered, explanation FROM candidate
				WHERE hypothesis_id = ? AND status = 'proposed'`, h.id)
			for cr.Next() {
				var cmd, expl string
				cr.Scan(&cmd, &expl)
				fmt.Fprintf(&b, "  → Candidato de reapertura generado: %s\n    Motivo exacto: %s\n", cmd, strings.ReplaceAll(expl, "\n", " "))
			}
			cr.Close()
		}
	}
	return b.String(), nil
}

// retrieveToolComparison agrupa outcomes por tool con agregados — el LLM no
// tiene que sumar/comparar, ya viene ordenado.
func retrieveToolComparison(s *store.Store, sessionID, entityHint string) (string, error) {
	rows, err := s.DB.Query(`
		SELECT c.tool, COUNT(*), AVG(o.computed_information_gain), MAX(o.computed_information_gain), MIN(o.computed_information_gain)
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		JOIN outcome o ON o.action_id = a.id
		WHERE c.session_id = ?
		GROUP BY c.tool
		ORDER BY AVG(o.computed_information_gain) DESC`, sessionID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var b strings.Builder
	b.WriteString("COMPARACIÓN POR HERRAMIENTA (agregado ya calculado, ordenado de mayor a menor ganancia promedio):\n")
	any := false
	for rows.Next() {
		any = true
		var tool string
		var n int
		var avg, max, min float64
		rows.Scan(&tool, &n, &avg, &max, &min)
		fmt.Fprintf(&b, "- %s: %d acción(es), gain promedio=%.2f, máximo=%.2f, mínimo=%.2f\n", tool, n, avg, max, min)
	}
	if !any {
		return "", nil
	}
	return b.String(), nil
}

// entityTypeHints mapea palabras de la pregunta a un type de entidad — esto
// resuelve la ambigüedad real encontrada probando: la pregunta "¿con qué se
// relaciona el SHARE public?" hacía LIKE '%public%' sin filtrar por tipo, y
// SQLite devolvía la entidad type=identity "public" en vez del type=share
// "192.168.72.130/public" — una coincidencia de nombre distinta a la que
// preguntaba el operador. Determinista, no requiere al LLM adivinar el tipo.
var entityTypeHints = map[string]string{
	"share": "share", "shares": "share", "recurso": "share",
	"servicio": "service", "puerto": "service", "service": "service",
	"host": "host", "target": "host", "objetivo": "host",
	"identidad": "identity", "identity": "identity", "usuario": "identity", "user": "identity",
	"dominio": "domain", "domain": "domain",
}

func detectEntityTypeHint(question string) string {
	lower := strings.ToLower(question)
	for word, t := range entityTypeHints {
		if strings.Contains(lower, word) {
			return t
		}
	}
	return ""
}

// retrieveEntityDetail trae TODO lo conectado a una entidad concreta
// (relaciones en ambas direcciones + observaciones que la mencionan), dado
// un valor literal mencionado en la pregunta. Filtra por tipo cuando la
// pregunta lo deja claro (ver entityTypeHints) para evitar resolver a la
// entidad equivocada cuando dos tipos comparten el mismo valor textual.
func retrieveEntityDetail(s *store.Store, sessionID, entityHint, question string) (string, error) {
	if entityHint == "" {
		return "", nil
	}
	typeHint := detectEntityTypeHint(question)

	var entID, entType, entValue string
	var err error
	if typeHint != "" {
		err = s.DB.QueryRow(`
			SELECT id, type, canonical_value FROM entity
			WHERE session_id = ? AND type = ? AND canonical_value LIKE ? LIMIT 1`,
			sessionID, typeHint, "%"+entityHint+"%",
		).Scan(&entID, &entType, &entValue)
		if err == sql.ErrNoRows {
			// el tipo detectado no matcheó nada — reintentar sin filtro de tipo
			// en vez de reportar "no encontrado" prematuramente.
			err = s.DB.QueryRow(`
				SELECT id, type, canonical_value FROM entity
				WHERE session_id = ? AND canonical_value LIKE ? LIMIT 1`,
				sessionID, "%"+entityHint+"%",
			).Scan(&entID, &entType, &entValue)
		}
	} else {
		err = s.DB.QueryRow(`
			SELECT id, type, canonical_value FROM entity
			WHERE session_id = ? AND canonical_value LIKE ? LIMIT 1`,
			sessionID, "%"+entityHint+"%",
		).Scan(&entID, &entType, &entValue)
	}
	if err == sql.ErrNoRows {
		return fmt.Sprintf("DETALLE DE ENTIDAD: no se encontró ninguna entidad que coincida con %q.\n", entityHint), nil
	}
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "DETALLE DE ENTIDAD (traversal directo para %q, tipo resuelto=%s):\n- [%s] %s\n", entityHint, entType, entType, entValue)

	rows, _ := s.DB.Query(`
		SELECT r.kind, e2.type, e2.canonical_value, 'source' FROM relationship r
		JOIN entity e2 ON e2.id = r.target_entity_id WHERE r.source_entity_id = ?
		UNION ALL
		SELECT r.kind, e1.type, e1.canonical_value, 'target' FROM relationship r
		JOIN entity e1 ON e1.id = r.source_entity_id WHERE r.target_entity_id = ?`, entID, entID)
	relCount := 0
	for rows.Next() {
		relCount++
		var kind, t2, v2, dir string
		rows.Scan(&kind, &t2, &v2, &dir)
		if dir == "source" {
			fmt.Fprintf(&b, "  --%s--> [%s] %s\n", kind, t2, v2)
		} else {
			fmt.Fprintf(&b, "  <--%s-- [%s] %s\n", kind, t2, v2)
		}
	}
	rows.Close()
	if relCount == 0 {
		// Explícito y sin ambigüedad: sin esto, un LLM débil tiende a rellenar
		// el vacío con una asociación inventada desde el contexto general en
		// vez de reportar la ausencia (bug real encontrado en esta prueba).
		b.WriteString("  SIN RELACIONES REGISTRADAS para esta entidad. Si la pregunta asume una relación con otra entidad, esa relación NO existe en el grafo.\n")
	}
	return b.String(), nil
}

func retrievePendingWork(s *store.Store, sessionID string) (string, error) {
	// Ya cubierto por computeDerivedFacts en el contexto base — no duplicar.
	return "", nil
}
