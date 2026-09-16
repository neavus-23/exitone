package main

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"exitone/internal/console"
	"exitone/internal/hypothesis"
)

// handleInfo — "info" siempre significa "detalle sobre el objeto
// actualmente cargado en contexto" (sección 11 del pedido original); el
// formato exacto varía por tipo, ver tabla G del plan.
func handleInfo(cs *ConsoleSession, args []string) error {
	ctx := cs.Stack.Current()
	switch ctx.Type {
	case console.Host:
		return infoHost(cs, ctx)
	case console.Service:
		return infoService(cs, ctx)
	case console.Hypothesis:
		return infoHypothesis(cs, ctx)
	case console.Objective:
		return infoObjective(cs, ctx)
	case console.Candidate:
		return infoCandidate(cs, ctx)
	default:
		return infoWorkspace(cs)
	}
}

func infoWorkspace(cs *ConsoleSession) error {
	var hosts, services, objectives, hypotheses int
	cs.Store.DB.QueryRow(`SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'host'`, cs.SessionID).Scan(&hosts)
	cs.Store.DB.QueryRow(`SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service'`, cs.SessionID).Scan(&services)
	cs.Store.DB.QueryRow(`SELECT COUNT(*) FROM methodology_objective WHERE session_id = ?`, cs.SessionID).Scan(&objectives)
	cs.Store.DB.QueryRow(`SELECT COUNT(*) FROM hypothesis WHERE session_id = ?`, cs.SessionID).Scan(&hypotheses)

	fmt.Printf("Workspace %s\n\n", cs.Stack.Current().Label)
	fmt.Printf("  Hosts:       %d\n", hosts)
	fmt.Printf("  Services:    %d\n", services)
	fmt.Printf("  Objectives:  %d\n", objectives)
	fmt.Printf("  Hypotheses:  %d\n", hypotheses)
	return nil
}

func infoHost(cs *ConsoleSession, ctx console.ConsoleContext) error {
	var attrsJSON string
	cs.Store.DB.QueryRow(`SELECT attrs FROM entity WHERE id = ?`, ctx.ID).Scan(&attrsJSON)
	fmt.Printf("Host %s\n\n", ctx.Label)
	printAttrs(attrsJSON)

	fmt.Println("\nServices:")
	rows, err := cs.Store.DB.Query(`
		SELECT e.attrs FROM entity e
		JOIN relationship r ON r.target_entity_id = e.id AND r.kind = 'HAS_SERVICE'
		WHERE r.source_entity_id = ? AND e.type = 'service'`, ctx.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var svcAttrs string
		if err := rows.Scan(&svcAttrs); err != nil {
			return err
		}
		fmt.Println("  " + serviceLabel(svcAttrs))
	}

	fmt.Println("\nObjectives:")
	oRows, err := cs.Store.DB.Query(`SELECT id, intent_key, status FROM methodology_objective WHERE trigger_entity_id = ?`, ctx.ID)
	if err != nil {
		return err
	}
	defer oRows.Close()
	for oRows.Next() {
		var id, intent, status string
		if err := oRows.Scan(&id, &intent, &status); err != nil {
			return err
		}
		fmt.Printf("  %s [%s] (%s)\n", intent, status, id[:8])
	}
	return nil
}

func infoService(cs *ConsoleSession, ctx console.ConsoleContext) error {
	var attrsJSON, hostAddr string
	cs.Store.DB.QueryRow(`
		SELECT e.attrs, h.canonical_value FROM entity e
		JOIN relationship r ON r.target_entity_id = e.id AND r.kind = 'HAS_SERVICE'
		JOIN entity h ON h.id = r.source_entity_id
		WHERE e.id = ?`, ctx.ID).Scan(&attrsJSON, &hostAddr)

	fmt.Printf("Service %s (host %s)\n\n", ctx.Label, hostAddr)
	printAttrs(attrsJSON)

	fmt.Println("\nObjectives:")
	oRows, err := cs.Store.DB.Query(`SELECT id, intent_key, status FROM methodology_objective WHERE trigger_entity_id = ?`, ctx.ID)
	if err != nil {
		return err
	}
	defer oRows.Close()
	for oRows.Next() {
		var id, intent, status string
		if err := oRows.Scan(&id, &intent, &status); err != nil {
			return err
		}
		fmt.Printf("  %s [%s] (%s)\n", intent, status, id[:8])
	}

	fmt.Println("\nHypotheses:")
	hRows, err := cs.Store.DB.Query(`SELECT id, statement, status FROM hypothesis WHERE subject_entity_id = ?`, ctx.ID)
	if err != nil {
		return err
	}
	defer hRows.Close()
	for hRows.Next() {
		var id, statement, status string
		if err := hRows.Scan(&id, &statement, &status); err != nil {
			return err
		}
		fmt.Printf("  %s [%s] (%s)\n", truncateText(statement, 60), status, id[:8])
	}
	return nil
}

func infoHypothesis(cs *ConsoleSession, ctx console.ConsoleContext) error {
	exp, err := hypothesis.Explain(cs.Store, ctx.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Hypothesis %s\n\nStatus: %s\n\n%s\n\n", ctx.Label, exp.Status, exp.Statement)
	fmt.Printf("Supporting observations: %d\n", exp.SupportingObservations)
	fmt.Printf("Contradicting observations: %d\n", exp.ContradictingObservations)

	fmt.Println("\nCandidates:")
	rows, err := cs.Store.DB.Query(`SELECT id, score, status FROM candidate WHERE hypothesis_id = ? ORDER BY score DESC`, ctx.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status string
		var score float64
		if err := rows.Scan(&id, &score, &status); err != nil {
			return err
		}
		fmt.Printf("  %s — score %.2f [%s]\n", id[:8], score, status)
	}
	return nil
}

func infoObjective(cs *ConsoleSession, ctx console.ConsoleContext) error {
	var intent, status string
	cs.Store.DB.QueryRow(`SELECT intent_key, status FROM methodology_objective WHERE id = ?`, ctx.ID).Scan(&intent, &status)
	fmt.Printf("Objective %s — %s [%s]\n\n", ctx.Label, intent, status)

	fmt.Println("Paths:")
	pRows, err := cs.Store.DB.Query(`SELECT path_key, status, description FROM objective_path WHERE objective_id = ?`, ctx.ID)
	if err != nil {
		return err
	}
	defer pRows.Close()
	for pRows.Next() {
		var pk, pstatus, desc string
		if err := pRows.Scan(&pk, &pstatus, &desc); err != nil {
			return err
		}
		fmt.Printf("  %s [%s]: %s\n", pk, pstatus, desc)
	}

	fmt.Println("\nCandidates:")
	related, err := relatedCandidateIDs(cs.Store, cs.SessionID, ctx)
	if err != nil {
		return err
	}
	cRows, err := cs.Store.DB.Query(`SELECT id, score, status FROM candidate WHERE session_id = ? ORDER BY score DESC`, cs.SessionID)
	if err != nil {
		return err
	}
	defer cRows.Close()
	for cRows.Next() {
		var id, status string
		var score float64
		if err := cRows.Scan(&id, &score, &status); err != nil {
			return err
		}
		if !related[id] {
			continue
		}
		fmt.Printf("  %s — score %.2f [%s]\n", id[:8], score, status)
	}
	return nil
}

func infoCandidate(cs *ConsoleSession, ctx console.ConsoleContext) error {
	var tool, command, explanation, scoreTermsJSON, status string
	var score float64
	var objectivePathID, hypothesisID sql.NullString
	err := cs.Store.DB.QueryRow(`
		SELECT tool, command_template_rendered, explanation, score, score_terms, status, objective_path_id, hypothesis_id
		FROM candidate WHERE id = ?`, ctx.ID,
	).Scan(&tool, &command, &explanation, &score, &scoreTermsJSON, &status, &objectivePathID, &hypothesisID)
	if err != nil {
		return err
	}

	fmt.Printf("Candidate %s — score %.2f [%s]\n\n", ctx.Label, score, status)
	fmt.Printf("Tool: %s\n", tool)
	fmt.Printf("Command: %s\n\n", command)
	fmt.Printf("%s\n\n", explanation)

	var terms map[string]float64
	json.Unmarshal([]byte(scoreTermsJSON), &terms)
	fmt.Println("Score terms:")
	for k, v := range terms {
		fmt.Printf("  %-22s %.2f\n", k, v)
	}

	if objectivePathID.Valid {
		var objID string
		cs.Store.DB.QueryRow(`SELECT objective_id FROM objective_path WHERE id = ?`, objectivePathID.String).Scan(&objID)
		if objID != "" {
			fmt.Printf("\nObjective: %s\n", objID[:8])
		}
	}
	if hypothesisID.Valid {
		fmt.Printf("Hypothesis: %s\n", hypothesisID.String[:8])
	}
	return nil
}

func printAttrs(attrsJSON string) {
	var attrs map[string]any
	json.Unmarshal([]byte(attrsJSON), &attrs)
	for k, v := range attrs {
		fmt.Printf("  %-14s %v\n", k, v)
	}
}
