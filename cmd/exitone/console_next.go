package main

import (
	"fmt"

	"exitone/internal/console"
)

// handleNext — sección I del plan: fuera de un contexto de navegación,
// delega tal cual en el `next` legacy (scoring/focus real). Dentro de un
// contexto, printCandidatesForViewContext agrupa la MISMA lista por
// relevancia visual, sin recalcular nada ni tocar `focus`.
func handleNext(cs *ConsoleSession, args []string) error {
	ctx := cs.Stack.Current()
	if ctx.Type == console.Workspace {
		return legacyAdapter("next")(cs, args)
	}
	return printCandidatesForViewContext(cs, ctx)
}

// printCandidatesForViewContext nunca lee ni escribe la tabla `focus` — es
// pura vista de datos, deliberadamente separada de cmdNext (ver O.2 del
// plan: "use nunca reordena next").
func printCandidatesForViewContext(cs *ConsoleSession, ctx console.ConsoleContext) error {
	related, err := relatedCandidateIDs(cs.Store, cs.SessionID, ctx)
	if err != nil {
		return err
	}

	rows, err := cs.Store.DB.Query(`
		SELECT id, score, command_template_rendered, explanation, kind, phase_key, risk_level, status FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC`, cs.SessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var relatedRows, otherRows [][]string
	var results console.ResultSet
	i := 0
	for rows.Next() {
		var id, command, explanation, kind, phase, risk, status string
		var score float64
		if err := rows.Scan(&id, &score, &command, &explanation, &kind, &phase, &risk, &status); err != nil {
			return err
		}
		display := command
		if display == "" {
			display = explanation
		}
		hostAddr := candidateTargetHost(cs.Store, id)
		row := []string{fmt.Sprintf("%d", i), id[:8], fmt.Sprintf("%.2f", score), kind, phase, risk, truncateText(display, 45), status, scopeLabel(cs, hostAddr)}
		results = append(results, console.ResultRef{Type: console.Candidate, ID: id, Label: id[:8]})
		if related[id] {
			relatedRows = append(relatedRows, row)
		} else {
			otherRows = append(otherRows, row)
		}
		i++
	}

	headers := []string{"#", "ID", "Score", "Kind", "Phase", "Risk", "Suggestion", "Status", "Scope"}
	fmt.Print(console.RenderTable("Related to "+describeContext(ctx), headers, relatedRows))
	fmt.Println()
	fmt.Print(console.RenderTable("Other suggestions", headers, otherRows))
	cs.Results = results
	return rows.Err()
}
