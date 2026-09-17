// Package activity registra comandos observados por el shell y los asocia
// con candidatos sin ejecutar nada. Es la frontera explícita entre una
// sugerencia de ExitOne y una ejecución que ocurrió porque el operador
// pulsó Enter en su propia terminal.
package activity

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

type EventInput struct {
	SessionID string
	Pane      string
	Command   string
	Cwd       string
	StartedAt string
	EndedAt   string
	ExitCode  int
	Source    string
}

type ObserveResult struct {
	EventID       string
	Fingerprint   string
	LinkStatus    string
	ActionID      string
	CandidateID   string
	CandidateHits int
	Created       bool
}

var whitespace = regexp.MustCompile(`\s+`)

// NormalizeCommand es deliberadamente conservador: normaliza whitespace y
// elimina el comentario visual que ExitOne añade a slots inferidos, pero no
// reinterpreta quoting, variables ni redirecciones como lo haría una shell.
func NormalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if i := strings.Index(command, "  # "); i >= 0 {
		command = command[:i]
	}
	return whitespace.ReplaceAllString(command, " ")
}

func Fingerprint(in EventInput) string {
	material := strings.Join([]string{in.SessionID, in.Pane, in.StartedAt, NormalizeCommand(in.Command)}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

// Observe persiste el evento idempotentemente y enlaza una acción solamente
// si existe exactamente un candidato con el mismo comando normalizado.
func Observe(s *store.Store, in EventInput) (*ObserveResult, error) {
	if in.SessionID == "" || strings.TrimSpace(in.Command) == "" {
		return nil, fmt.Errorf("session y command son obligatorios")
	}
	if in.Source == "" {
		in.Source = "shell_hook"
	}
	fingerprint := Fingerprint(in)

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	result := &ObserveResult{Fingerprint: fingerprint, LinkStatus: "unmatched"}
	err = tx.QueryRow(`SELECT id, link_status FROM event WHERE session_id = ? AND fingerprint = ?`, in.SessionID, fingerprint).
		Scan(&result.EventID, &result.LinkStatus)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}
	if err == sql.ErrNoRows {
		result.EventID = uuid.NewString()
		_, err = tx.Exec(`INSERT INTO event(
			id, session_id, tmux_pane_id, command_raw, cwd, started_at, ended_at,
			exit_code, source, fingerprint, link_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unmatched')`,
			result.EventID, in.SessionID, nullable(in.Pane), in.Command, nullable(in.Cwd),
			nullable(in.StartedAt), nullable(in.EndedAt), in.ExitCode, in.Source, fingerprint,
		)
		if err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
		result.Created = true
	}

	// Si ya fue asociado en una invocación anterior (observe-event seguido
	// por ingest --event), se devuelve el vínculo existente sin duplicarlo.
	if result.LinkStatus == "matched" {
		_ = tx.QueryRow(`SELECT ae.action_id, a.candidate_id FROM action_event ae JOIN action a ON a.id = ae.action_id WHERE ae.event_id = ? LIMIT 1`, result.EventID).
			Scan(&result.ActionID, &result.CandidateID)
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return result, nil
	}

	normalized := NormalizeCommand(in.Command)
	rows, err := tx.Query(`SELECT id, command_template_rendered FROM candidate
		WHERE session_id = ? AND status IN ('proposed','accepted') AND kind = 'command'`, in.SessionID)
	if err != nil {
		return nil, err
	}
	var matches []string
	for rows.Next() {
		var id, command string
		if err := rows.Scan(&id, &command); err != nil {
			rows.Close()
			return nil, err
		}
		if normalized != "" && NormalizeCommand(command) == normalized {
			matches = append(matches, id)
		}
	}
	rows.Close()
	result.CandidateHits = len(matches)

	switch len(matches) {
	case 0:
		result.LinkStatus = "unmatched"
	case 1:
		result.LinkStatus = "matched"
		result.CandidateID = matches[0]
		var actionID string
		err := tx.QueryRow(`SELECT id FROM action WHERE candidate_id = ? ORDER BY COALESCE(decided_at, executed_at) DESC LIMIT 1`, matches[0]).Scan(&actionID)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		if err == sql.ErrNoRows {
			actionID = uuid.NewString()
			var pathID sql.NullString
			if err := tx.QueryRow(`SELECT objective_path_id FROM candidate WHERE id = ?`, matches[0]).Scan(&pathID); err != nil {
				return nil, err
			}
			decided := in.StartedAt
			if decided == "" {
				decided = time.Now().UTC().Format(time.RFC3339Nano)
			}
			status := "awaiting_evidence"
			if in.ExitCode != 0 {
				status = "executed"
			}
			if _, err := tx.Exec(`INSERT INTO action(id, candidate_id, objective_path_id, decided_at, executed_at, status)
				VALUES (?, ?, ?, ?, ?, ?)`, actionID, matches[0], nullString(pathID), decided, nullable(in.EndedAt), status); err != nil {
				return nil, err
			}
		} else {
			status := "awaiting_evidence"
			if in.ExitCode != 0 {
				status = "executed"
			}
			if _, err := tx.Exec(`UPDATE action SET executed_at = COALESCE(?, executed_at), status = ? WHERE id = ?`, nullable(in.EndedAt), status, actionID); err != nil {
				return nil, err
			}
		}
		result.ActionID = actionID
		if _, err := tx.Exec(`INSERT OR IGNORE INTO action_event(action_id, event_id) VALUES (?, ?)`, actionID, result.EventID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE candidate SET status = 'accepted' WHERE id = ?`, matches[0]); err != nil {
			return nil, err
		}
	case 2:
		fallthrough
	default:
		result.LinkStatus = "ambiguous"
	}

	if _, err := tx.Exec(`UPDATE event SET link_status = ? WHERE id = ?`, result.LinkStatus, result.EventID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func nullable(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
