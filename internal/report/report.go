// Package report genera el informe final de una investigación: scope,
// resumen ejecutivo, hallazgos con severidad/remediación, credenciales,
// cronología completa y preguntas de metodología sin responder. Cada dato
// sale de una fila real (session/scope_rule/hypothesis/credential/evidence/
// methodology_objective) — nunca inventado. La severidad y la remediación de
// cada hallazgo son las que el operador fijó explícitamente al confirmarlo
// (`hypothesis confirm --severity ... --remediation ...`).
//
// La prosa (resumen ejecutivo, narrativa de cada hallazgo, narrativa de la
// cronología) puede redactarla el LLM vía GenerateNarrative — pero SIEMPRE en
// llamadas pequeñas y acotadas por sección, nunca pidiéndole que reproduzca
// el reporte completo de una sola vez. Bug real encontrado validando esto:
// con un modelo local de 3B, pedirle reescribir el documento entero (~100
// líneas, tablas incluidas) se corta a mitad de camino por el límite de
// tokens Y corrompe el contenido de una celda de tabla mezclando texto de
// otra sección. Separarlo en llamadas angostas (un resumen, una narrativa
// por hallazgo, una narrativa de cronología) es más lento en total pero
// nunca trunca ni cruza datos entre secciones — y las tablas/listas
// factuales (scope, cobertura, credenciales, preguntas abiertas) nunca pasan
// por el LLM en absoluto, se renderizan tal cual desde la base.
package report

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"exitone/internal/credential"
	"exitone/internal/scope"
	"exitone/internal/stage"
	"exitone/internal/store"
)

type Finding struct {
	Statement    string
	Subject      string
	Severity     string
	Remediation  string
	EvidenceNote string
	ClosedAt     string
}

type TimelineStep struct {
	Timestamp string
	Label     string
	Detail    string
}

// Narrator es lo único que este paquete necesita del LLM — tres funciones
// angostas, una por sección narrable. Mantenerlo como una interfaz mínima
// (en vez de importar internal/llm directamente) deja `report` puro y
// testeable sin un modelo real; `cmd/exitone` provee la implementación real
// con los system prompts de internal/llm.
type Narrator struct {
	Summary  func(findingsText string) (string, error)
	Finding  func(findingText string) (string, error)
	Timeline func(timelineText string) (string, error)
}

var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

// Generate arma el reporte 100% determinista (usado por `--raw`, o como
// fallback si el LLM local no está disponible). reveal controla si los
// valores de credenciales aparecen en texto plano.
func Generate(s *store.Store, sessionID string, reveal bool) (string, error) {
	var b strings.Builder
	if err := writeHeader(&b, s, sessionID); err != nil {
		return "", err
	}

	findings, err := LoadFindings(s, sessionID)
	if err != nil {
		return "", err
	}
	steps, err := LoadTimeline(s, sessionID)
	if err != nil {
		return "", err
	}

	if err := writeScope(&b, s, sessionID); err != nil {
		return "", err
	}
	writeExecutiveSummaryDeterministic(&b, findings)
	if err := writeCoverage(&b, s, sessionID); err != nil {
		return "", err
	}
	writeFindingsDeterministic(&b, findings)
	if err := writeCredentials(&b, s, sessionID, reveal); err != nil {
		return "", err
	}
	writeTimelineDeterministic(&b, steps)
	if err := writeOpenQuestions(&b, s, sessionID); err != nil {
		return "", err
	}
	return b.String(), nil
}

// GenerateNarrative es el mismo reporte, pero con prosa redactada por el LLM
// en llamadas pequeñas y acotadas (nunca una sola llamada por el documento
// completo — ver comentario del paquete). Si `narrate` falla para una
// sección puntual, esa sección cae con gracia a su versión determinista en
// vez de fallar el reporte completo.
func GenerateNarrative(s *store.Store, sessionID string, reveal bool, n Narrator) (string, error) {
	var b strings.Builder
	if err := writeHeader(&b, s, sessionID); err != nil {
		return "", err
	}

	findings, err := LoadFindings(s, sessionID)
	if err != nil {
		return "", err
	}
	steps, err := LoadTimeline(s, sessionID)
	if err != nil {
		return "", err
	}

	if err := writeScope(&b, s, sessionID); err != nil {
		return "", err
	}

	b.WriteString("## Resumen ejecutivo\n\n")
	if summary, err := n.Summary(summarizeFindingsForLLM(findings)); err == nil && strings.TrimSpace(summary) != "" {
		b.WriteString(strings.TrimSpace(summary))
		b.WriteString("\n\n")
	} else {
		writeExecutiveSummaryBody(&b, findings)
	}

	if err := writeCoverage(&b, s, sessionID); err != nil {
		return "", err
	}

	b.WriteString("## Hallazgos confirmados\n\n")
	if len(findings) == 0 {
		b.WriteString("_Ninguna hipótesis fue confirmada explícitamente en esta investigación._\n\n")
	}
	for i, f := range findings {
		writeFindingBody(&b, i, f)
		if narrative, err := n.Finding(describeFindingForLLM(f)); err == nil && strings.TrimSpace(narrative) != "" {
			b.WriteString(strings.TrimSpace(narrative))
			b.WriteString("\n\n")
		}
	}

	if err := writeCredentials(&b, s, sessionID, reveal); err != nil {
		return "", err
	}

	b.WriteString("## Cronología\n\n")
	if narrative, err := n.Timeline(describeTimelineForLLM(steps)); err == nil && strings.TrimSpace(narrative) != "" {
		b.WriteString(strings.TrimSpace(narrative))
		b.WriteString("\n\n")
	}
	writeTimelineDetailBody(&b, steps)

	if err := writeOpenQuestions(&b, s, sessionID); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeHeader(b *strings.Builder, s *store.Store, sessionID string) error {
	var label, startedAt string
	var closedAt sql.NullString
	if err := s.DB.QueryRow(`SELECT target_label, started_at, closed_at FROM session WHERE id = ?`, sessionID).
		Scan(&label, &startedAt, &closedAt); err != nil {
		return fmt.Errorf("leer workspace: %w", err)
	}
	fmt.Fprintf(b, "# Reporte de investigación — %s\n\n", label)
	fmt.Fprintf(b, "- Iniciado: %s\n", startedAt)
	if closedAt.Valid {
		fmt.Fprintf(b, "- Cerrado: %s\n", closedAt.String)
	}
	fmt.Fprintf(b, "- Generado: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	return nil
}

// writeScope restablece qué estaba autorizado a tocarse — un reporte sin
// esto no se puede leer de forma independiente del contexto del engagement.
func writeScope(b *strings.Builder, s *store.Store, sessionID string) error {
	rules, err := scope.List(s, sessionID)
	if err != nil {
		return fmt.Errorf("leer scope: %w", err)
	}
	b.WriteString("## Alcance autorizado\n\n")
	if len(rules) == 0 {
		b.WriteString("_No se registraron reglas de scope explícitas para este workspace — se asume que el propio target de la sesión fue el alcance completo._\n\n")
		return nil
	}
	b.WriteString("| Patrón | Estado | Nota |\n|---|---|---|\n")
	for _, r := range rules {
		state := "in-scope"
		if !r.InScope {
			state = "EXCLUIDO"
		}
		fmt.Fprintf(b, "| %s | %s | %s |\n", r.Pattern, state, escapePipe(r.Note))
	}
	b.WriteString("\n")
	return nil
}

func writeExecutiveSummaryDeterministic(b *strings.Builder, findings []Finding) {
	b.WriteString("## Resumen ejecutivo\n\n")
	writeExecutiveSummaryBody(b, findings)
}

// writeExecutiveSummaryBody es la versión determinista (conteos reales, sin
// prosa libre) — usada tal cual en el reporte --raw, y como fallback si la
// redacción del LLM falla para esta sección puntual.
func writeExecutiveSummaryBody(b *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		b.WriteString("No se confirmó ningún hallazgo en esta investigación.\n\n")
		return
	}
	counts := map[string]int{}
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "sin clasificar"
		}
		counts[sev]++
	}
	fmt.Fprintf(b, "Se confirmaron **%d hallazgo(s)** durante esta investigación", len(findings))
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "sin clasificar"} {
		if n, ok := counts[sev]; ok {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(b, " (%s)", strings.Join(parts, ", "))
	}
	b.WriteString(".\n\n")
	if counts["critical"] > 0 {
		b.WriteString("**Al menos un hallazgo crítico requiere atención inmediata antes de cualquier otra priorización.**\n\n")
	}
}

func summarizeFindingsForLLM(findings []Finding) string {
	if len(findings) == 0 {
		return "No hay hallazgos confirmados."
	}
	var b strings.Builder
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "sin clasificar"
		}
		fmt.Fprintf(&b, "- [%s] %s (afectado: %s)\n", sev, f.Statement, f.Subject)
	}
	return b.String()
}

func writeCoverage(b *strings.Builder, s *store.Store, sessionID string) error {
	stages, err := stage.Estimate(s, sessionID)
	if err != nil {
		return fmt.Errorf("estimar cobertura: %w", err)
	}
	b.WriteString("## Cobertura de la investigación\n\n")
	b.WriteString("| Etapa | Estado | Razón |\n|---|---|---|\n")
	for _, st := range stages {
		fmt.Fprintf(b, "| %s | %s | %s |\n", st.Name, st.Status, escapePipe(st.Reason))
	}
	b.WriteString("\n")
	return nil
}

// LoadFindings devuelve los hallazgos confirmados, más severo primero — el
// lector no debería tener que buscar el crítico en medio de la lista.
func LoadFindings(s *store.Store, sessionID string) ([]Finding, error) {
	rows, err := s.DB.Query(`
		SELECT h.statement, e.canonical_value, h.severity, h.remediation, h.evidence_note, h.closed_at
		FROM hypothesis h
		JOIN entity e ON e.id = h.subject_entity_id
		WHERE h.session_id = ? AND h.status = 'confirmed'
		ORDER BY h.closed_at`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("leer hallazgos: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var closedAt sql.NullString
		if err := rows.Scan(&f.Statement, &f.Subject, &f.Severity, &f.Remediation, &f.EvidenceNote, &closedAt); err != nil {
			return nil, err
		}
		f.ClosedAt = closedAt.String
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && severityOrder[findings[j].Severity] < severityOrder[findings[j-1].Severity]; j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
	return findings, nil
}

func writeFindingsDeterministic(b *strings.Builder, findings []Finding) {
	b.WriteString("## Hallazgos confirmados\n\n")
	if len(findings) == 0 {
		b.WriteString("_Ninguna hipótesis fue confirmada explícitamente en esta investigación._\n\n")
		return
	}
	for i, f := range findings {
		writeFindingBody(b, i, f)
	}
}

// writeFindingBody redacta la parte SIEMPRE determinista de un hallazgo
// (afectado/severidad/evidencia/remediación) — nunca pasa por el LLM, para
// que estos datos nunca puedan corromperse en la redacción.
func writeFindingBody(b *strings.Builder, index int, f Finding) {
	fmt.Fprintf(b, "### %d. %s\n\n", index+1, f.Statement)
	fmt.Fprintf(b, "- **Afectado:** %s\n", f.Subject)
	sev := f.Severity
	if sev == "" {
		sev = "_sin clasificar — fijar con `hypothesis confirm --severity`_"
	}
	fmt.Fprintf(b, "- **Severidad:** %s\n", sev)
	if f.ClosedAt != "" {
		fmt.Fprintf(b, "- **Confirmado:** %s\n", f.ClosedAt)
	}
	if f.EvidenceNote != "" {
		fmt.Fprintf(b, "- **Prueba de impacto:** %s\n", f.EvidenceNote)
	}
	if f.Remediation != "" {
		fmt.Fprintf(b, "- **Remediación recomendada:** %s\n", f.Remediation)
	} else {
		b.WriteString("- **Remediación recomendada:** _no fijada — completar con `hypothesis confirm --remediation` antes de entregar._\n")
	}
	b.WriteString("\n")
}

func describeFindingForLLM(f Finding) string {
	sev := f.Severity
	if sev == "" {
		sev = "sin clasificar"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Hallazgo: %s\n", f.Statement)
	fmt.Fprintf(&b, "Afectado: %s\n", f.Subject)
	fmt.Fprintf(&b, "Severidad: %s\n", sev)
	if f.EvidenceNote != "" {
		fmt.Fprintf(&b, "Prueba de impacto: %s\n", f.EvidenceNote)
	}
	if f.Remediation != "" {
		fmt.Fprintf(&b, "Remediación ya fijada por el operador: %s\n", f.Remediation)
	}
	return b.String()
}

func writeCredentials(b *strings.Builder, s *store.Store, sessionID string, reveal bool) error {
	creds, err := credential.List(s, sessionID, reveal)
	if err != nil {
		return fmt.Errorf("leer credenciales: %w", err)
	}
	b.WriteString("## Credenciales encontradas\n\n")
	if len(creds) == 0 {
		b.WriteString("_Ninguna credencial registrada._\n\n")
		return nil
	}
	b.WriteString("| ID | Identidad | Servicio | Valor | Estado | Fuente |\n|---|---|---|---|---|---|\n")
	for _, c := range creds {
		fmt.Fprintf(b, "| %s | %s | %s | `%s` | %s | %s |\n",
			c.ID[:8], emptyDash(c.Identity), emptyDash(c.Service), c.Value, c.Status, escapePipe(c.Source))
	}
	b.WriteString("\n")

	rows, err := s.DB.Query(`
		SELECT c.id, ca.result, ca.attempted_at
		FROM credential_attempt ca
		JOIN credential c ON c.id = ca.credential_id
		WHERE c.session_id = ?
		ORDER BY ca.attempted_at`, sessionID)
	if err != nil {
		return fmt.Errorf("leer intentos de credencial: %w", err)
	}
	defer rows.Close()
	var attempts [][3]string
	for rows.Next() {
		var credID, result, attemptedAt string
		if err := rows.Scan(&credID, &result, &attemptedAt); err != nil {
			return err
		}
		attempts = append(attempts, [3]string{credID[:8], result, attemptedAt})
	}
	if len(attempts) > 0 {
		b.WriteString("Intentos de uso:\n\n")
		b.WriteString("| Credencial | Resultado | Cuándo |\n|---|---|---|\n")
		for _, a := range attempts {
			fmt.Fprintf(b, "| %s | %s | %s |\n", a[0], a[1], a[2])
		}
		b.WriteString("\n")
	}
	return rows.Err()
}

// LoadTimeline reconstruye la cronología real fusionando dos fuentes:
// ACTIONs (candidatos aceptados vía el flujo normal de ExitOne) y EVIDENCE
// (cada archivo ingerido, sin importar si pasó por accept/resolve). Sin la
// segunda fuente, cualquier paso ejecutado fuera del ciclo accept→ingest
// desaparece de la cronología aunque haya sido decisivo — el gap real
// encontrado validando el reporte contra un engagement real de principio a
// fin.
func LoadTimeline(s *store.Store, sessionID string) ([]TimelineStep, error) {
	var steps []TimelineStep

	actionRows, err := s.DB.Query(`
		SELECT c.tool, c.command_template_rendered, a.status,
		       COALESCE(a.decided_at, a.executed_at) AS ts,
		       o.new_entities, o.new_relationships, o.computed_information_gain
		FROM action a
		JOIN candidate c ON c.id = a.candidate_id
		LEFT JOIN outcome o ON o.action_id = a.id
		WHERE c.session_id = ?`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("leer acciones: %w", err)
	}
	for actionRows.Next() {
		var tool, cmd, status, ts string
		var newE, newR sql.NullInt64
		var gain sql.NullFloat64
		if err := actionRows.Scan(&tool, &cmd, &status, &ts, &newE, &newR, &gain); err != nil {
			actionRows.Close()
			return nil, err
		}
		detail := fmt.Sprintf("**%s** (%s) — %s", tool, status, escapePipe(truncate(cmd, 120)))
		if newE.Valid || newR.Valid || gain.Valid {
			detail += fmt.Sprintf(" _(nuevas entidades=%s, relaciones=%s, information_gain=%s)_",
				intOrDash(newE), intOrDash(newR), floatOrDash(gain))
		}
		steps = append(steps, TimelineStep{Timestamp: ts, Label: "acción aceptada", Detail: detail})
	}
	if err := actionRows.Err(); err != nil {
		actionRows.Close()
		return nil, err
	}
	actionRows.Close()

	evRows, err := s.DB.Query(`
		SELECT ev.tool_name, ev.created_at, ev.parse_level
		FROM evidence ev
		JOIN observation o ON o.evidence_id = ev.id
		JOIN observation_entity oe ON oe.observation_id = o.id
		JOIN entity ent ON ent.id = oe.entity_id
		WHERE ent.session_id = ?
		GROUP BY ev.id
		ORDER BY ev.created_at`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("leer evidencia: %w", err)
	}
	for evRows.Next() {
		var tool, ts string
		var parseLevel int
		if err := evRows.Scan(&tool, &ts, &parseLevel); err != nil {
			evRows.Close()
			return nil, err
		}
		level := "determinista"
		if parseLevel == 2 {
			level = "LLM, Nivel 2"
		} else if parseLevel == 0 {
			level = "sin parsear"
		}
		steps = append(steps, TimelineStep{Timestamp: ts, Label: "evidencia ingerida", Detail: fmt.Sprintf("**%s** (%s)", tool, level)})
	}
	if err := evRows.Err(); err != nil {
		evRows.Close()
		return nil, err
	}
	evRows.Close()

	for i := 1; i < len(steps); i++ {
		for j := i; j > 0 && steps[j].Timestamp < steps[j-1].Timestamp; j-- {
			steps[j], steps[j-1] = steps[j-1], steps[j]
		}
	}
	return steps, nil
}

func writeTimelineDeterministic(b *strings.Builder, steps []TimelineStep) {
	b.WriteString("## Cronología completa\n\n")
	writeTimelineDetailBody(b, steps)
}

func writeTimelineDetailBody(b *strings.Builder, steps []TimelineStep) {
	if len(steps) == 0 {
		b.WriteString("_Ninguna acción ni evidencia fue registrada todavía en esta investigación._\n\n")
		return
	}
	for _, st := range steps {
		fmt.Fprintf(b, "- `%s` — %s: %s\n", st.Timestamp, st.Label, st.Detail)
	}
	b.WriteString("\n")
}

func describeTimelineForLLM(steps []TimelineStep) string {
	if len(steps) == 0 {
		return "No hay pasos registrados."
	}
	var b strings.Builder
	for _, st := range steps {
		fmt.Fprintf(&b, "- %s (%s): %s\n", st.Timestamp, st.Label, st.Detail)
	}
	return b.String()
}

func writeOpenQuestions(b *strings.Builder, s *store.Store, sessionID string) error {
	rows, err := s.DB.Query(`
		SELECT mo.intent_key, op.path_key, op.description
		FROM methodology_objective mo
		JOIN objective_path op ON op.objective_id = mo.id
		WHERE mo.session_id = ? AND op.status = 'open'
		ORDER BY mo.intent_key, op.path_key`, sessionID)
	if err != nil {
		return fmt.Errorf("leer preguntas abiertas: %w", err)
	}
	defer rows.Close()

	b.WriteString("## Preguntas de metodología sin responder\n\n")
	found := false
	for rows.Next() {
		var intent, pathKey, desc string
		if err := rows.Scan(&intent, &pathKey, &desc); err != nil {
			return err
		}
		found = true
		fmt.Fprintf(b, "- **%s** / %s — %s\n", intent, pathKey, desc)
	}
	if !found {
		b.WriteString("_Ninguna — todo lo disparado hasta ahora fue respondido._\n")
	}
	b.WriteString("\n")
	return rows.Err()
}

func escapePipe(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func intOrDash(n sql.NullInt64) string {
	if !n.Valid {
		return "-"
	}
	return fmt.Sprintf("%d", n.Int64)
}

func floatOrDash(n sql.NullFloat64) string {
	if !n.Valid {
		return "-"
	}
	return fmt.Sprintf("%.2f", n.Float64)
}
