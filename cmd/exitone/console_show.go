package main

import (
	"encoding/json"
	"fmt"

	"exitone/internal/console"
	"exitone/internal/focus"
	"exitone/internal/stage"
)

// handleShow — sección G del plan: qué subcomando actualiza cs.Results está
// documentado ahí; coverage/focus/evidence NUNCA lo hacen porque no son
// listas de objetos navegables por índice.
func handleShow(cs *ConsoleSession, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: show <hosts|services|objectives|hypotheses|candidates|coverage|focus|evidence> [--all]")
	}
	sub := args[0]
	rest := args[1:]
	all := false
	var filtered []string
	for _, a := range rest {
		if a == "--all" {
			all = true
			continue
		}
		filtered = append(filtered, a)
	}
	ctx := cs.Stack.Current()
	if all {
		ctx = console.ConsoleContext{Type: console.Workspace, ID: cs.SessionID}
	}

	switch sub {
	case "hosts":
		return showHosts(cs)
	case "services":
		return showServices(cs, ctx)
	case "objectives":
		return showObjectives(cs, ctx)
	case "hypotheses":
		return showHypotheses(cs, ctx)
	case "candidates":
		return showCandidates(cs, ctx)
	case "coverage":
		return showCoverage(cs)
	case "focus":
		return showFocus(cs)
	case "evidence":
		return showEvidence(cs, ctx)
	default:
		return fmt.Errorf("subcomando de show desconocido: %q", sub)
	}
}

func showHosts(cs *ConsoleSession) error {
	rows, err := cs.Store.DB.Query(`SELECT id, canonical_value FROM entity WHERE session_id = ? AND type = 'host' ORDER BY canonical_value`, cs.SessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var results console.ResultSet
	var table [][]string
	i := 0
	for rows.Next() {
		var id, addr string
		if err := rows.Scan(&id, &addr); err != nil {
			return err
		}
		var svcCount int
		cs.Store.DB.QueryRow(`
			SELECT COUNT(*) FROM relationship r JOIN entity e ON e.id = r.target_entity_id
			WHERE r.source_entity_id = ? AND r.kind = 'HAS_SERVICE' AND e.type = 'service'`, id).Scan(&svcCount)
		table = append(table, []string{fmt.Sprintf("%d", i), addr, fmt.Sprintf("%d", svcCount), scopeLabel(cs, addr)})
		results = append(results, console.ResultRef{Type: console.Host, ID: id, Label: addr})
		i++
	}
	fmt.Print(console.RenderTable("Hosts", []string{"#", "Address", "Services", "Scope"}, table))
	cs.Results = results
	return rows.Err()
}

func showServices(cs *ConsoleSession, ctx console.ConsoleContext) error {
	query := `
		SELECT e.id, e.canonical_value, e.attrs, h.canonical_value FROM entity e
		JOIN relationship r ON r.target_entity_id = e.id AND r.kind = 'HAS_SERVICE'
		JOIN entity h ON h.id = r.source_entity_id
		WHERE e.session_id = ? AND e.type = 'service'`
	args := []any{cs.SessionID}
	if ctx.Type == console.Host {
		query += ` AND h.id = ?`
		args = append(args, ctx.ID)
	}
	query += ` ORDER BY h.canonical_value, e.canonical_value`

	rows, err := cs.Store.DB.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var results console.ResultSet
	var table [][]string
	i := 0
	for rows.Next() {
		var id, canonical, attrsJSON, hostAddr string
		if err := rows.Scan(&id, &canonical, &attrsJSON, &hostAddr); err != nil {
			return err
		}
		var attrs map[string]any
		json.Unmarshal([]byte(attrsJSON), &attrs)
		port := fmt.Sprintf("%v", attrs["port"])
		proto, _ := attrs["proto"].(string)
		service, _ := attrs["protocol"].(string)
		product, _ := attrs["product"].(string)
		state, _ := attrs["state"].(string)
		if state == "" {
			state = "?"
		}
		label := serviceLabel(attrsJSON)
		table = append(table, []string{fmt.Sprintf("%d", i), hostAddr, port, proto, service, state, scopeLabel(cs, hostAddr), product})
		results = append(results, console.ResultRef{Type: console.Service, ID: id, Label: label})
		i++
	}
	fmt.Print(console.RenderTable("Services", []string{"#", "Host", "Port", "Proto", "Service", "State", "Scope", "Product"}, table))
	cs.Results = results
	return rows.Err()
}

func showObjectives(cs *ConsoleSession, ctx console.ConsoleContext) error {
	query := `SELECT id, intent_key, status FROM methodology_objective WHERE session_id = ?`
	args := []any{cs.SessionID}
	switch ctx.Type {
	case console.Host, console.Service:
		query += ` AND trigger_entity_id = ?`
		args = append(args, ctx.ID)
	case console.Objective:
		query += ` AND id = ?`
		args = append(args, ctx.ID)
	}
	query += ` ORDER BY intent_key`

	rows, err := cs.Store.DB.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var results console.ResultSet
	var table [][]string
	i := 0
	for rows.Next() {
		var id, intent, status string
		if err := rows.Scan(&id, &intent, &status); err != nil {
			return err
		}
		short := id[:8]
		table = append(table, []string{fmt.Sprintf("%d", i), short, intent, status})
		results = append(results, console.ResultRef{Type: console.Objective, ID: id, Label: short})
		i++
	}
	fmt.Print(console.RenderTable("Objectives", []string{"#", "ID", "Intent", "Status"}, table))
	cs.Results = results
	return rows.Err()
}

func showHypotheses(cs *ConsoleSession, ctx console.ConsoleContext) error {
	query := `SELECT id, statement, status, subject_entity_id FROM hypothesis WHERE session_id = ?`
	args := []any{cs.SessionID}
	switch ctx.Type {
	case console.Service:
		query += ` AND subject_entity_id = ?`
		args = append(args, ctx.ID)
	case console.Host:
		descendants, err := descendantEntityIDs(cs.Store, ctx.ID)
		if err != nil {
			return err
		}
		placeholders, dArgs := inClause(descendants)
		query += ` AND subject_entity_id IN (` + placeholders + `)`
		args = append(args, dArgs...)
	case console.Hypothesis:
		query += ` AND id = ?`
		args = append(args, ctx.ID)
	}

	rows, err := cs.Store.DB.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var results console.ResultSet
	var table [][]string
	i := 0
	for rows.Next() {
		var id, statement, status, subjectID string
		if err := rows.Scan(&id, &statement, &status, &subjectID); err != nil {
			return err
		}
		short := id[:8]
		table = append(table, []string{fmt.Sprintf("%d", i), short, truncateText(statement, 50), status})
		results = append(results, console.ResultRef{Type: console.Hypothesis, ID: id, Label: short})
		i++
	}
	fmt.Print(console.RenderTable("Hypotheses", []string{"#", "ID", "Statement", "Status"}, table))
	cs.Results = results
	return rows.Err()
}

func showCandidates(cs *ConsoleSession, ctx console.ConsoleContext) error {
	rows, err := cs.Store.DB.Query(`
		SELECT id, score, command_template_rendered, status FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC`, cs.SessionID)
	if err != nil {
		return err
	}
	defer rows.Close()

	var related map[string]bool
	if ctx.Type != console.Workspace {
		related, err = relatedCandidateIDs(cs.Store, cs.SessionID, ctx)
		if err != nil {
			return err
		}
	}

	var results console.ResultSet
	var table [][]string
	i := 0
	for rows.Next() {
		var id, command, status string
		var score float64
		if err := rows.Scan(&id, &score, &command, &status); err != nil {
			return err
		}
		if related != nil && !related[id] {
			continue
		}
		short := id[:8]
		hostAddr := candidateTargetHost(cs.Store, id)
		table = append(table, []string{fmt.Sprintf("%d", i), short, fmt.Sprintf("%.2f", score), truncateText(command, 50), status, scopeLabel(cs, hostAddr)})
		results = append(results, console.ResultRef{Type: console.Candidate, ID: id, Label: short})
		i++
	}
	fmt.Print(console.RenderTable("Candidates", []string{"#", "ID", "Score", "Command", "Status", "Scope"}, table))
	cs.Results = results
	return rows.Err()
}

func showCoverage(cs *ConsoleSession) error {
	stages, err := stage.Estimate(cs.Store, cs.SessionID)
	if err != nil {
		return err
	}
	var table [][]string
	for _, st := range stages {
		table = append(table, []string{st.Name, string(st.Status), st.Reason})
	}
	fmt.Print(console.RenderTable("Coverage", []string{"Stage", "Status", "Reason"}, table))
	return nil
}

func showFocus(cs *ConsoleSession) error {
	f, err := focus.Get(cs.Store, cs.SessionID)
	if err != nil {
		return err
	}
	if f == nil {
		fmt.Println(statusLine("*", ansiCyan, "No hay focus activo."))
		return nil
	}
	fmt.Printf("Focus: %s %s (desde %s)\n", f.RefType, f.RefID[:8], f.SetAt)
	return nil
}

func showEvidence(cs *ConsoleSession, ctx console.ConsoleContext) error {
	query := `
		SELECT DISTINCT o.id, o.kind, o.payload, ev.tool_name, ev.created_at
		FROM observation o
		JOIN evidence ev ON ev.id = o.evidence_id
		JOIN observation_entity oe ON oe.observation_id = o.id
		JOIN entity ent ON ent.id = oe.entity_id
		WHERE ent.session_id = ?`
	args := []any{cs.SessionID}
	if ctx.Type == console.Host || ctx.Type == console.Service {
		query += ` AND oe.entity_id = ?`
		args = append(args, ctx.ID)
	}
	query += ` ORDER BY ev.created_at DESC LIMIT 50`

	rows, err := cs.Store.DB.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var table [][]string
	for rows.Next() {
		var id, kind, payloadJSON, toolName, createdAt string
		if err := rows.Scan(&id, &kind, &payloadJSON, &toolName, &createdAt); err != nil {
			return err
		}
		table = append(table, []string{id[:8], kind, toolName, truncateText(payloadJSON, 60), createdAt})
	}
	fmt.Print(console.RenderTable("Evidence", []string{"ID", "Kind", "Tool", "Payload", "Created"}, table))
	return rows.Err()
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
