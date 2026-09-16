package main

import (
	"fmt"

	"exitone/internal/console"
)

// handleSearch — sección 13 del pedido original: desde el día 1 cubre los 5
// tipos (host, service, objective, hypothesis, candidate), nunca solo un
// subconjunto restringido.
func handleSearch(cs *ConsoleSession, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: search [type:host|service|objective|hypothesis|candidate] [status:<s>] [host:<ip>] <texto libre>")
	}
	q := console.ParseQuery(args)
	typeFilter := q.Filters["type"]
	statusFilter := q.Filters["status"]
	hostFilter := q.Filters["host"]

	var hostEntityID string
	if hostFilter != "" {
		var matched bool
		var err error
		var ctx console.ConsoleContext
		if ctx, matched, err = matchHost(cs.Store, cs.SessionID, hostFilter); err != nil {
			return err
		} else if matched {
			hostEntityID = ctx.ID
		} else {
			return fmt.Errorf("host:%s no coincide con ningún host de este workspace", hostFilter)
		}
	}

	var results console.ResultSet
	var table [][]string
	i := 0
	add := func(kind string, ref console.ResultRef, detail string) {
		table = append(table, []string{fmt.Sprintf("%d", i), kind, ref.Label, detail})
		results = append(results, ref)
		i++
	}

	if typeFilter == "" || typeFilter == "host" {
		rows, err := cs.Store.DB.Query(`SELECT id, canonical_value FROM entity WHERE session_id = ? AND type = 'host' AND canonical_value LIKE '%' || ? || '%'`, cs.SessionID, q.Text)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, addr string
			if err := rows.Scan(&id, &addr); err != nil {
				rows.Close()
				return err
			}
			add("host", console.ResultRef{Type: console.Host, ID: id, Label: addr}, "")
		}
		rows.Close()
	}

	if typeFilter == "" || typeFilter == "service" {
		query := `
			SELECT e.id, e.attrs, h.canonical_value FROM entity e
			JOIN relationship r ON r.target_entity_id = e.id AND r.kind = 'HAS_SERVICE'
			JOIN entity h ON h.id = r.source_entity_id
			WHERE e.session_id = ? AND e.type = 'service' AND (e.canonical_value LIKE '%' || ? || '%' OR e.attrs LIKE '%' || ? || '%')`
		sqlArgs := []any{cs.SessionID, q.Text, q.Text}
		if hostEntityID != "" {
			query += ` AND h.id = ?`
			sqlArgs = append(sqlArgs, hostEntityID)
		}
		rows, err := cs.Store.DB.Query(query, sqlArgs...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, attrsJSON, hostAddr string
			if err := rows.Scan(&id, &attrsJSON, &hostAddr); err != nil {
				rows.Close()
				return err
			}
			add("service", console.ResultRef{Type: console.Service, ID: id, Label: serviceLabel(attrsJSON)}, hostAddr)
		}
		rows.Close()
	}

	if typeFilter == "" || typeFilter == "objective" {
		query := `SELECT id, intent_key, status FROM methodology_objective WHERE session_id = ? AND intent_key LIKE '%' || ? || '%'`
		sqlArgs := []any{cs.SessionID, q.Text}
		if statusFilter != "" {
			query += ` AND status = ?`
			sqlArgs = append(sqlArgs, statusFilter)
		}
		if hostEntityID != "" {
			query += ` AND trigger_entity_id = ?`
			sqlArgs = append(sqlArgs, hostEntityID)
		}
		rows, err := cs.Store.DB.Query(query, sqlArgs...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, intent, status string
			if err := rows.Scan(&id, &intent, &status); err != nil {
				rows.Close()
				return err
			}
			add("objective", console.ResultRef{Type: console.Objective, ID: id, Label: id[:8]}, intent+" ["+status+"]")
		}
		rows.Close()
	}

	if typeFilter == "" || typeFilter == "hypothesis" {
		query := `SELECT id, statement, status FROM hypothesis WHERE session_id = ? AND statement LIKE '%' || ? || '%'`
		sqlArgs := []any{cs.SessionID, q.Text}
		if statusFilter != "" {
			query += ` AND status = ?`
			sqlArgs = append(sqlArgs, statusFilter)
		}
		if hostEntityID != "" {
			descendants, err := descendantEntityIDs(cs.Store, hostEntityID)
			if err != nil {
				return err
			}
			placeholders, dArgs := inClause(descendants)
			query += ` AND subject_entity_id IN (` + placeholders + `)`
			sqlArgs = append(sqlArgs, dArgs...)
		}
		rows, err := cs.Store.DB.Query(query, sqlArgs...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, statement, status string
			if err := rows.Scan(&id, &statement, &status); err != nil {
				rows.Close()
				return err
			}
			add("hypothesis", console.ResultRef{Type: console.Hypothesis, ID: id, Label: id[:8]}, truncateText(statement, 40)+" ["+status+"]")
		}
		rows.Close()
	}

	if typeFilter == "" || typeFilter == "candidate" {
		query := `SELECT id, command_template_rendered, status, score FROM candidate WHERE session_id = ? AND command_template_rendered LIKE '%' || ? || '%'`
		sqlArgs := []any{cs.SessionID, q.Text}
		if statusFilter != "" {
			query += ` AND status = ?`
			sqlArgs = append(sqlArgs, statusFilter)
		}
		rows, err := cs.Store.DB.Query(query, sqlArgs...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, command, status string
			var score float64
			if err := rows.Scan(&id, &command, &status, &score); err != nil {
				rows.Close()
				return err
			}
			if hostEntityID != "" {
				related, err := relatedCandidateIDs(cs.Store, cs.SessionID, console.ConsoleContext{Type: console.Host, ID: hostEntityID})
				if err != nil {
					rows.Close()
					return err
				}
				if !related[id] {
					continue
				}
			}
			add("candidate", console.ResultRef{Type: console.Candidate, ID: id, Label: id[:8]}, fmt.Sprintf("score %.2f [%s]", score, status))
		}
		rows.Close()
	}

	fmt.Print(console.RenderTable("Search results", []string{"#", "Type", "Label", "Detail"}, table))
	cs.Results = results
	return nil
}
