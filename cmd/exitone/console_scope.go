package main

import (
	"fmt"

	"exitone/internal/console"
	"exitone/internal/scope"
)

// handleScope — flujo bug-bounty/reglas de compromiso (pedido explícito):
// qué assets están autorizados a tocarse. Nunca bloquea nada por sí solo —
// `show`/`use`/`next` MARCAN lo que está fuera de scope, nunca lo ocultan
// (mismo principio de "nunca ocultar, solo señalar" que el resto de la
// consola, sección 25 del pedido original de la Control Console).
func handleScope(cs *ConsoleSession, args []string) error {
	if cs.SessionID == "" {
		return fmt.Errorf("no hay workspace activo — empieza con: workspace new <target>")
	}
	if len(args) < 1 {
		return fmt.Errorf("uso: scope <add|list|remove> ...")
	}
	switch args[0] {
	case "add":
		return scopeAdd(cs, args[1:])
	case "list":
		return scopeList(cs)
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("uso: scope remove <id|pattern>")
		}
		if err := scope.Remove(cs.Store, cs.SessionID, args[1]); err != nil {
			return err
		}
		fmt.Println(statusLine("+", ansiGreen, "Regla de scope eliminada."))
		return nil
	default:
		return fmt.Errorf("subcomando de scope desconocido: %q", args[0])
	}
}

func scopeAdd(cs *ConsoleSession, args []string) error {
	var pattern, note string
	out := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			out = true
		case "--note":
			if i+1 >= len(args) {
				return fmt.Errorf("--note requiere un valor")
			}
			i++
			note = args[i]
		default:
			if pattern == "" {
				pattern = args[i]
			}
		}
	}
	if pattern == "" {
		return fmt.Errorf(`uso: scope add <pattern> [--out] [--note "..."]`)
	}

	id, err := scope.Add(cs.Store, cs.SessionID, pattern, !out, note)
	if err != nil {
		return err
	}
	label := "in-scope"
	if out {
		label = "EXCLUIDO"
	}
	fmt.Println(statusLine("+", ansiGreen, fmt.Sprintf("Regla agregada (%s): %s (%s)", label, pattern, id[:8])))
	return nil
}

func scopeList(cs *ConsoleSession) error {
	rules, err := scope.List(cs.Store, cs.SessionID)
	if err != nil {
		return err
	}
	var table [][]string
	for _, r := range rules {
		label := "in-scope"
		if !r.InScope {
			label = "EXCLUIDO"
		}
		table = append(table, []string{r.ID[:8], r.Pattern, label, r.Note})
	}
	fmt.Print(console.RenderTable("Scope", []string{"ID", "Pattern", "Estado", "Nota"}, table))
	return nil
}

// scopeLabel es el string corto reutilizado por show/use/next para marcar
// una fila/contexto — nunca bloquea, solo informa.
func scopeLabel(cs *ConsoleSession, value string) string {
	if cs.SessionID == "" || value == "" {
		return "?"
	}
	status, _, err := scope.Check(cs.Store, cs.SessionID, value)
	if err != nil {
		return "?"
	}
	switch status {
	case scope.In:
		return "in"
	case scope.Out:
		return "OUT"
	default:
		return "?"
	}
}
