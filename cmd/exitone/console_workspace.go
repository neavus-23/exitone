package main

import (
	"fmt"
	"strings"

	"exitone/internal/console"
	"exitone/internal/store"
)

// handleWorkspace atiende tanto `workspace ...` como `session ...` (mismo
// handler, dos CommandSpec — sección E del plan). `session new` sigue
// funcionando exactamente igual que siempre porque delega en cmdSession vía
// legacyAdapter; lo único nuevo es sincronizar ConsoleSession después.
func handleWorkspace(cs *ConsoleSession, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: workspace <new|use|list|info> ...")
	}
	switch args[0] {
	case "new":
		if err := legacyAdapter("session")(cs, args); err != nil {
			return err
		}
		return syncWorkspaceFromAppState(cs)

	case "use":
		if len(args) < 2 {
			return fmt.Errorf("uso: workspace use <label|id>")
		}
		id, label, err := resolveWorkspaceToken(cs.Store, args[1])
		if err != nil {
			return err
		}
		if err := cs.Store.SetAppState("current_session", id); err != nil {
			return err
		}
		cs.SwitchWorkspace(id, label)
		fmt.Println(statusLine("*", ansiCyan, "Using workspace "+label))
		return nil

	case "list":
		return listWorkspaces(cs)

	case "info":
		return infoWorkspace(cs)

	default:
		return fmt.Errorf("subcomando de workspace desconocido: %q", args[0])
	}
}

// syncWorkspaceFromAppState relee app_state.current_session tras un
// `workspace new`/`session new` legacy (que ya lo dejó escrito) y lo refleja
// en ConsoleSession — el único punto que hace esa transición (E).
func syncWorkspaceFromAppState(cs *ConsoleSession) error {
	id, ok, err := cs.Store.GetAppState("current_session")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no se pudo determinar el workspace activo tras crearlo")
	}
	var label string
	cs.Store.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, id).Scan(&label)
	cs.SwitchWorkspace(id, label)
	return nil
}

type workspaceRow struct {
	id, label, startedAt, status string
}

func listWorkspaces(cs *ConsoleSession) error {
	rows, err := cs.Store.DB.Query(`SELECT id, target_label, started_at, closed_at FROM session ORDER BY started_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var table [][]string
	for rows.Next() {
		var id, label, startedAt string
		var closedAt *string
		if err := rows.Scan(&id, &label, &startedAt, &closedAt); err != nil {
			return err
		}
		status := "open"
		if closedAt != nil {
			status = "closed"
		}
		table = append(table, []string{id[:8], label, status, startedAt})
	}
	fmt.Print(console.RenderTable("Workspaces", []string{"ID", "Label", "Status", "Started"}, table))
	return rows.Err()
}

// resolveWorkspaceToken — sección H del plan: nunca elige silenciosamente
// entre labels duplicados, siempre lista y pide el ID completo/prefijo.
func resolveWorkspaceToken(s *store.Store, token string) (id, label string, err error) {
	rows, err := s.DB.Query(`SELECT id, target_label, started_at FROM session WHERE target_label = ? ORDER BY started_at DESC`, token)
	if err != nil {
		return "", "", err
	}
	var byLabel []workspaceRow
	for rows.Next() {
		var r workspaceRow
		if err := rows.Scan(&r.id, &r.label, &r.startedAt); err != nil {
			rows.Close()
			return "", "", err
		}
		byLabel = append(byLabel, r)
	}
	rows.Close()

	switch len(byLabel) {
	case 1:
		return byLabel[0].id, byLabel[0].label, nil
	case 0:
		// no hubo match exacto de label — reintentar como prefijo de ID.
		idRows, err := s.DB.Query(`SELECT id, target_label FROM session WHERE id LIKE ? || '%'`, token)
		if err != nil {
			return "", "", err
		}
		defer idRows.Close()
		var byID []workspaceRow
		for idRows.Next() {
			var r workspaceRow
			if err := idRows.Scan(&r.id, &r.label); err != nil {
				return "", "", err
			}
			byID = append(byID, r)
		}
		switch len(byID) {
		case 1:
			return byID[0].id, byID[0].label, nil
		case 0:
			return "", "", fmt.Errorf("no se encontró un workspace %q", token)
		default:
			return "", "", ambiguousWorkspaceError(byID)
		}
	default:
		// NUNCA elegir la más reciente entre labels duplicados.
		return "", "", ambiguousWorkspaceError(byLabel)
	}
}

func ambiguousWorkspaceError(rows []workspaceRow) error {
	var lines []string
	for _, r := range rows {
		lines = append(lines, fmt.Sprintf("%s  %s", r.id[:8], r.label))
	}
	return fmt.Errorf("varios workspaces coinciden — usa el ID completo:\n\n    %s", strings.Join(lines, "\n    "))
}
