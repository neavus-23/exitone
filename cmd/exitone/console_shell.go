package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/reeflective/readline"

	"exitone/internal/console"
	"exitone/internal/focus"
	"exitone/internal/store"
)

// consoleRegistry/consoleHandlers son estado de proceso, no de sesión —
// construidos una vez en runConsole() desde el único slice de
// console_commands.go (nunca pueden desincronizarse entre sí).
var (
	consoleRegistry *console.Registry
	consoleHandlers map[string]consoleHandler
)

// runConsole reemplaza el viejo runRepl() self-exec-por-línea (sección M,
// paso 11 — Polish): ahora dispatch() corre en el mismo proceso durante
// toda la sesión, necesario para que ContextStack/ResultSet sobrevivan
// entre comandos. fatal()/os.Exit(1) legacy se contiene vía legacyAdapter
// (console_bridge.go) — el único panic/recover de toda la consola nueva.
func runConsole() {
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}

	s, err := store.Open(dbPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: no se pudo abrir la base de datos: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	consoleRegistry, consoleHandlers = buildConsole()

	cs := &ConsoleSession{Store: s, SelfPath: selfPath}
	if id, ok, _ := s.GetAppState("current_session"); ok {
		var label string
		s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, id).Scan(&label)
		cs.SwitchWorkspace(id, label)
	} else {
		cs.Stack = console.NewContextStack(console.ConsoleContext{Type: console.Workspace})
	}

	printBanner()
	if cs.SessionID != "" {
		fmt.Println(statusLine("+", ansiGreen, "workspace activo: "+cs.Stack.Current().Label))
	} else {
		fmt.Println(statusLine("*", ansiCyan, "sin workspace activo — empieza con: workspace new <target>"))
	}
	fmt.Println(colorize(ansiGray, "escribe 'help' para ver comandos, 'exit' para salir\n"))

	rl := readline.NewShell()
	rl.Prompt.Primary(func() string { return consolePromptString(cs) })
	rl.Completer = func(line []rune, cursor int) readline.Completions { return consoleComplete(cs, line, cursor) }

	// NewHistoryFromFile hace os.Open (nunca os.Create) — en el primer
	// arranque el archivo todavía no existe, así que sin este touch previo
	// NUNCA se registraba ninguna fuente de historial (bug real encontrado
	// en el smoke test manual: el archivo no se creaba ni siquiera tras
	// varios comandos y una salida limpia).
	historyPath := historyFilePath()
	if f, err := os.OpenFile(historyPath, os.O_CREATE|os.O_APPEND, 0o600); err == nil {
		f.Close()
	}
	if hist, err := readline.NewHistoryFromFile(historyPath); err == nil {
		rl.History.Add("exitone", &filteredHistory{inner: hist})
	}

	for {
		line, err := rl.Readline()
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println()
				return
			}
			if errors.Is(err, readline.ErrInterrupt) {
				continue
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		tokens := tokenizeConsoleLine(line)
		if len(tokens) == 0 {
			continue
		}
		name, rest := tokens[0], tokens[1:]

		spec, ok := consoleRegistry.Resolve(name)
		if !ok {
			printUnknownCommand(name)
			continue
		}

		switch spec.Name {
		case "exit":
			fmt.Println(statusLine("*", ansiCyan, "cerrando ExitOne."))
			return
		case "clear":
			fmt.Print("\033[H\033[2J")
			continue
		}

		handler := consoleHandlers[spec.Name]
		if handler == nil {
			fmt.Println(statusLine("-", ansiRed, fmt.Sprintf("comando %q sin handler registrado (bug)", spec.Name)))
			continue
		}
		if err := handler(cs, rest); err != nil {
			fmt.Println(statusLine("-", ansiRed, err.Error()))
		}
	}
}

func printUnknownCommand(name string) {
	suggestions := consoleRegistry.Suggest(name)
	if len(suggestions) > 0 {
		fmt.Println(statusLine("-", ansiRed, fmt.Sprintf("comando desconocido: %q — ¿quisiste decir %v?", name, suggestions)))
		return
	}
	fmt.Println(statusLine("-", ansiRed, fmt.Sprintf("comando desconocido: %q", name)))
}

func historyFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".exitone_history"
	}
	dir := filepath.Join(home, ".exitone")
	os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	return filepath.Join(dir, "history")
}

// consolePromptString — sección J del plan: refleja profundidad de
// navegación, nunca una fase/etapa inferida (eso vive en `show coverage`).
// El tag de focus se omite cuando coincide con el contexto de navegación
// actual, para no mostrar información redundante.
func consolePromptString(cs *ConsoleSession) string {
	ctx := cs.Stack.Current()
	base := colorize(ansiBold+ansiCyan, "exitone")

	if ctx.Type == console.Workspace && ctx.Label == "" {
		return base + colorize(ansiGray, " > ")
	}

	prompt := base
	if ctx.Type == console.Workspace {
		prompt += colorize(ansiGray, "(") + colorize(ansiBold+ansiGreen, ctx.Label) + colorize(ansiGray, ")")
	} else {
		prompt += " " + colorize(ansiBold+ansiGreen, string(ctx.Type)+"("+ctx.Label+")")
	}

	if cs.SessionID != "" {
		if f, err := focus.Get(cs.Store, cs.SessionID); err == nil && f != nil && len(f.RefID) >= 8 {
			focusID := f.RefID[:8]
			sameAsCurrent := (ctx.Type == console.Hypothesis || ctx.Type == console.Objective) && len(ctx.ID) >= 8 && ctx.ID[:8] == focusID
			if !sameAsCurrent {
				prompt += colorize(ansiGray, "[") + colorize(ansiYellow, "focus:"+focusID) + colorize(ansiGray, "]")
			}
		}
	}

	return prompt + colorize(ansiGray, " > ")
}
