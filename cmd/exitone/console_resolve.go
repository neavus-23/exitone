package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"exitone/internal/console"
	"exitone/internal/store"
)

// ResolveByIdentity implementa el paso 2 de `use` (el 1 es
// ResultSet.ResolveIndex, ver console_use.go): resolución por identidad
// real, en el orden fijo de la sección F del plan. Corta en el primer paso
// que produzca >=1 coincidencia — nunca sigue probando los siguientes, y
// nunca elige arbitrariamente entre varias (sección 26 del pedido
// original: listar todas, no adivinar).
func ResolveByIdentity(s *store.Store, sessionID string, current console.ConsoleContext, token string) (console.ConsoleContext, error) {
	// a) prefijo contra hypothesis.id
	if ctx, matched, err := matchHypothesis(s, sessionID, token); err != nil {
		return console.ConsoleContext{}, err
	} else if matched {
		return ctx, nil
	}

	// b) prefijo contra methodology_objective.id
	if ctx, matched, err := matchObjective(s, sessionID, token); err != nil {
		return console.ConsoleContext{}, err
	} else if matched {
		return ctx, nil
	}

	// c) entity tipo host, exacta o por prefijo de canonical_value
	if ctx, matched, err := matchHost(s, sessionID, token); err != nil {
		return console.ConsoleContext{}, err
	} else if matched {
		return ctx, nil
	}

	// d) SOLO dentro de un contexto Host: puerto exacto contra un servicio
	// de ese host — resuelve `use 445` sin ambigüedad, nada más que aquí.
	if current.Type == console.Host {
		if port, err := strconv.Atoi(token); err == nil {
			if ctx, matched, err := matchServiceByPort(s, current.ID, port); err != nil {
				return console.ConsoleContext{}, err
			} else if matched {
				return ctx, nil
			}
		}
	}

	// e) prefijo contra candidate.id
	if ctx, matched, err := matchCandidate(s, sessionID, token); err != nil {
		return console.ConsoleContext{}, err
	} else if matched {
		return ctx, nil
	}

	return console.ConsoleContext{}, fmt.Errorf("no se encontró nada con %q en este workspace", token)
}

func matchHypothesis(s *store.Store, sessionID, token string) (console.ConsoleContext, bool, error) {
	rows, err := s.DB.Query(`SELECT id, statement FROM hypothesis WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, token)
	if err != nil {
		return console.ConsoleContext{}, false, err
	}
	defer rows.Close()
	type row struct{ id, statement string }
	var matches []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.statement); err != nil {
			return console.ConsoleContext{}, false, err
		}
		matches = append(matches, r)
	}
	switch len(matches) {
	case 0:
		return console.ConsoleContext{}, false, nil
	case 1:
		return console.ConsoleContext{Type: console.Hypothesis, ID: matches[0].id, Label: matches[0].id[:8]}, true, nil
	default:
		var ids []string
		for _, m := range matches {
			ids = append(ids, m.id[:8])
		}
		return console.ConsoleContext{}, false, fmt.Errorf("%q matches %d hypotheses:\n\n    %s", token, len(matches), strings.Join(ids, "\n    "))
	}
}

func matchObjective(s *store.Store, sessionID, token string) (console.ConsoleContext, bool, error) {
	rows, err := s.DB.Query(`SELECT id, intent_key FROM methodology_objective WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, token)
	if err != nil {
		return console.ConsoleContext{}, false, err
	}
	defer rows.Close()
	type row struct{ id, intentKey string }
	var matches []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.intentKey); err != nil {
			return console.ConsoleContext{}, false, err
		}
		matches = append(matches, r)
	}
	switch len(matches) {
	case 0:
		return console.ConsoleContext{}, false, nil
	case 1:
		return console.ConsoleContext{Type: console.Objective, ID: matches[0].id, Label: matches[0].id[:8]}, true, nil
	default:
		var ids []string
		for _, m := range matches {
			ids = append(ids, m.id[:8])
		}
		return console.ConsoleContext{}, false, fmt.Errorf("%q matches %d objectives:\n\n    %s", token, len(matches), strings.Join(ids, "\n    "))
	}
}

func matchHost(s *store.Store, sessionID, token string) (console.ConsoleContext, bool, error) {
	rows, err := s.DB.Query(`
		SELECT id, canonical_value FROM entity
		WHERE session_id = ? AND type = 'host' AND (canonical_value = ? OR canonical_value LIKE ? || '%')`,
		sessionID, token, token)
	if err != nil {
		return console.ConsoleContext{}, false, err
	}
	defer rows.Close()
	type row struct{ id, value string }
	var matches []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.value); err != nil {
			return console.ConsoleContext{}, false, err
		}
		matches = append(matches, r)
	}
	switch len(matches) {
	case 0:
		return console.ConsoleContext{}, false, nil
	case 1:
		return console.ConsoleContext{Type: console.Host, ID: matches[0].id, Label: matches[0].value}, true, nil
	default:
		var vals []string
		for _, m := range matches {
			vals = append(vals, m.value)
		}
		return console.ConsoleContext{}, false, fmt.Errorf("%q matches %d hosts:\n\n    %s", token, len(matches), strings.Join(vals, "\n    "))
	}
}

func matchServiceByPort(s *store.Store, hostEntityID string, port int) (console.ConsoleContext, bool, error) {
	rows, err := s.DB.Query(`
		SELECT e.id, e.attrs FROM entity e
		JOIN relationship r ON r.target_entity_id = e.id AND r.kind = 'HAS_SERVICE'
		WHERE r.source_entity_id = ? AND e.type = 'service' AND json_extract(e.attrs, '$.port') = ?`,
		hostEntityID, port)
	if err != nil {
		return console.ConsoleContext{}, false, err
	}
	defer rows.Close()
	type row struct {
		id, attrsJSON string
	}
	var matches []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.attrsJSON); err != nil {
			return console.ConsoleContext{}, false, err
		}
		matches = append(matches, r)
	}
	if len(matches) == 0 {
		return console.ConsoleContext{}, false, nil
	}
	if len(matches) > 1 {
		return console.ConsoleContext{}, false, fmt.Errorf("port %d matches %d services in this host", port, len(matches))
	}
	return console.ConsoleContext{Type: console.Service, ID: matches[0].id, Label: serviceLabel(matches[0].attrsJSON)}, true, nil
}

func matchCandidate(s *store.Store, sessionID, token string) (console.ConsoleContext, bool, error) {
	rows, err := s.DB.Query(`SELECT id FROM candidate WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, token)
	if err != nil {
		return console.ConsoleContext{}, false, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return console.ConsoleContext{}, false, err
		}
		ids = append(ids, id)
	}
	switch len(ids) {
	case 0:
		return console.ConsoleContext{}, false, nil
	case 1:
		return console.ConsoleContext{Type: console.Candidate, ID: ids[0], Label: ids[0][:8]}, true, nil
	default:
		var short []string
		for _, id := range ids {
			short = append(short, id[:8])
		}
		return console.ConsoleContext{}, false, fmt.Errorf("%q matches %d candidates:\n\n    %s", token, len(ids), strings.Join(short, "\n    "))
	}
}

// serviceLabel arma "445/smb" a partir de attrs.port/attrs.protocol — mismo
// formato ya usado en mensajes existentes del proyecto.
func serviceLabel(attrsJSON string) string {
	var attrs map[string]any
	_ = json.Unmarshal([]byte(attrsJSON), &attrs)
	port := ""
	if p, ok := attrs["port"]; ok {
		port = fmt.Sprintf("%v", p)
	}
	proto := ""
	if p, ok := attrs["protocol"]; ok {
		proto, _ = p.(string)
	}
	if proto == "" {
		return port
	}
	return port + "/" + proto
}
