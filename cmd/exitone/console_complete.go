package main

import (
	"strings"

	"github.com/reeflective/readline"

	"exitone/internal/console"
)

// consoleComplete — sección 21 del pedido original: completado contextual
// que prioriza según el contexto activo SIN nunca ocultar los comandos
// globales (help/back/show/search/exit siguen apareciendo siempre).
func consoleComplete(cs *ConsoleSession, line []rune, cursor int) readline.Completions {
	text := string(line[:cursor])
	fields := strings.Fields(text)
	startingNewWord := strings.HasSuffix(text, " ") || len(fields) == 0

	if len(fields) == 0 || (len(fields) == 1 && !startingNewWord) {
		prefix := ""
		if len(fields) == 1 {
			prefix = fields[0]
		}
		return completeRootCommands(cs, prefix)
	}

	cmdName := fields[0]
	wordPrefix := ""
	if !startingNewWord {
		wordPrefix = fields[len(fields)-1]
	}
	return completeSubcommand(cs, cmdName, wordPrefix)
}

func completeRootCommands(cs *ConsoleSession, prefix string) readline.Completions {
	ctx := cs.Stack.Current()
	seen := map[string]bool{}
	var pairs []string

	addSpec := func(spec *console.CommandSpec) {
		if seen[spec.Name] || !strings.HasPrefix(spec.Name, prefix) {
			return
		}
		seen[spec.Name] = true
		pairs = append(pairs, spec.Name, spec.Description)
	}

	// Comandos relevantes al contexto actual primero — nunca en exclusiva.
	for _, spec := range consoleRegistry.ValidIn(ctx.Type) {
		addSpec(spec)
	}
	for _, spec := range consoleRegistry.All() {
		addSpec(spec)
	}

	if len(pairs) == 0 {
		return readline.CompleteValues()
	}
	return readline.CompleteValuesDescribed(pairs...)
}

func completeSubcommand(cs *ConsoleSession, cmdName, prefix string) readline.Completions {
	spec, ok := consoleRegistry.Resolve(cmdName)
	if !ok {
		return readline.CompleteValues()
	}

	var options []string
	switch spec.Name {
	case "show":
		options = []string{"hosts", "services", "objectives", "hypotheses", "candidates", "coverage", "focus", "evidence"}
	case "workspace", "session":
		options = []string{"new", "use", "list", "info"}
	default:
		return readline.CompleteValues()
	}

	var filtered []string
	for _, o := range options {
		if strings.HasPrefix(o, prefix) {
			filtered = append(filtered, o)
		}
	}
	return readline.CompleteValues(filtered...)
}
