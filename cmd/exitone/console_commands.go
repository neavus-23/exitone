package main

import (
	"fmt"

	"exitone/internal/console"
)

// commandDefinition — sección E del plan: UNA fuente de verdad que alimenta
// tanto el Registry (help/autocompletado) como el dispatcher real
// (consoleHandlers). Estructuralmente imposible que diverjan.
type commandDefinition struct {
	Spec    console.CommandSpec
	Handler consoleHandler
}

// handleAccept — legacyAdapter("accept") + la línea fija de la sección 27
// del pedido original, reforzando el límite humano-ejecuta sin tener que
// repetirlo en cada punto de interacción.
func handleAccept(cs *ConsoleSession, args []string) error {
	if err := legacyAdapter("accept")(cs, args); err != nil {
		return err
	}
	fmt.Println(statusLine("*", ansiCyan, "ExitOne no la ejecuta automáticamente."))
	return nil
}

var commandDefinitions = []commandDefinition{
	{Spec: console.CommandSpec{
		Name: "help", Aliases: []string{"?"}, Category: "Core",
		Usage: "help [comando] [--all]", Description: "ayuda contextual, agrupada por categoría",
	}, Handler: handleHelp},
	{Spec: console.CommandSpec{
		Name: "exit", Aliases: []string{"quit", "q"}, Category: "Core",
		Usage: "exit", Description: "salir de la consola",
	}, Handler: nil}, // manejado directamente en el loop de console_shell.go
	{Spec: console.CommandSpec{
		Name: "clear", Aliases: []string{"cls"}, Category: "Core",
		Usage: "clear", Description: "limpiar la pantalla",
	}, Handler: nil}, // idem

	{Spec: console.CommandSpec{
		Name: "show", Category: "Navigation",
		Usage:       "show <hosts|services|objectives|hypotheses|candidates|coverage|focus|evidence> [--all]",
		Description: "listar objetos del workspace, filtrados por contexto salvo --all",
	}, Handler: handleShow},
	{Spec: console.CommandSpec{
		Name: "use", Category: "Navigation",
		ValidContexts: []console.ContextType{console.Workspace, console.Host, console.Service, console.Objective, console.Hypothesis, console.Candidate},
		Usage:         "use <índice|ID|token>", Description: "navegar a un objeto — nunca ejecuta ni cambia estrategia",
	}, Handler: handleUse},
	{Spec: console.CommandSpec{
		Name: "back", Category: "Navigation",
		ValidContexts: []console.ContextType{console.Host, console.Service, console.Objective, console.Hypothesis, console.Candidate},
		Usage:         "back", Description: "volver al contexto anterior — nunca falla, ni en la raíz",
	}, Handler: handleBack},
	{Spec: console.CommandSpec{
		Name: "info", Category: "Navigation",
		ValidContexts: []console.ContextType{console.Workspace, console.Host, console.Service, console.Objective, console.Hypothesis, console.Candidate},
		Usage:         "info", Description: "detalle del objeto actualmente cargado en contexto",
	}, Handler: handleInfo},
	{Spec: console.CommandSpec{
		Name: "search", Category: "Navigation",
		Usage:       "search [type:<t>] [status:<s>] [host:<ip>] <texto>",
		Description: "buscar hosts/services/objectives/hypotheses/candidates",
	}, Handler: handleSearch},

	{Spec: console.CommandSpec{
		Name: "scope", Category: "Scope",
		Usage:       `scope <add|list|remove> <pattern> [--out] [--note "..."]`,
		Description: "qué assets están autorizados a tocarse (bug bounty / reglas de compromiso) — nunca bloquea, solo marca",
	}, Handler: handleScope},

	{Spec: console.CommandSpec{
		Name: "workspace", Category: "Workspace",
		Usage: "workspace <new|use|list|info> ...", Description: "crear/cambiar/listar workspaces (sesiones de investigación)",
	}, Handler: handleWorkspace},
	{Spec: console.CommandSpec{
		Name: "session", Category: "Legacy",
		Usage: "session <new|use|list|info> ...", Description: "alias legacy de workspace",
	}, Handler: handleWorkspace},

	{Spec: console.CommandSpec{
		Name: "next", Category: "Strategy",
		ValidContexts: []console.ContextType{console.Host, console.Service, console.Objective, console.Hypothesis, console.Candidate},
		Usage:         "next [--raw]", Description: "sugerencias rankeadas — agrupadas por contexto si hay uno activo",
	}, Handler: handleNext},
	{Spec: console.CommandSpec{
		Name: "why", Category: "Strategy",
		Usage: "why <candidate-id-prefix>", Description: "explicar por qué se sugirió un candidato",
	}, Handler: legacyAdapter("why")},
	{Spec: console.CommandSpec{
		Name: "accept", Category: "Strategy",
		Usage: "accept <candidate-id-prefix>", Description: "aceptar un candidato — registra la acción, NO la ejecuta",
	}, Handler: handleAccept},
	{Spec: console.CommandSpec{
		Name: "resolve", Category: "Strategy",
		Usage: "resolve <action-id-prefix> --result fail|success", Description: "cerrar/confirmar una hipótesis tras probar algo",
	}, Handler: legacyAdapter("resolve")},
	{Spec: console.CommandSpec{
		Name: "dismiss", Category: "Strategy",
		Usage: "dismiss <candidate-id-prefix>", Description: "descartar una sugerencia obsoleta",
	}, Handler: legacyAdapter("dismiss")},
	{Spec: console.CommandSpec{
		Name: "focus", Category: "Strategy",
		Usage: "focus [<hypothesis-or-objective-id-prefix>|clear]", Description: "dónde invertir esfuerzo ahora — siempre explícito, nunca inferido",
	}, Handler: legacyAdapter("focus")},

	{Spec: console.CommandSpec{
		Name: "guide", Category: "Mentor",
		Usage:       "guide",
		Description: "modo mentor: sugiere por dónde seguir según las etapas reales y el candidato de mayor score (nunca inventa una técnica nueva)",
	}, Handler: handleGuide},

	{Spec: console.CommandSpec{
		Name: "explain", Category: "Mentor",
		ValidContexts: []console.ContextType{console.Service, console.Objective, console.Hypothesis},
		Usage:         "explain [tecnología|servicio]",
		Description:   "modo mentor: explica una tecnología detectada en términos genéricos de metodología (nunca afirma nada de este target específico)",
	}, Handler: handleExplain},

	{Spec: console.CommandSpec{
		Name: "ingest", Category: "Evidence",
		Usage: "ingest <archivo> [--tool <hint>] [--host <ip>]", Description: "ingerir evidencia manualmente",
	}, Handler: legacyAdapter("ingest")},
	{Spec: console.CommandSpec{
		Name: "ask", Category: "Evidence",
		Usage: "ask \"<pregunta>\"", Description: "consulta en lenguaje natural anclada al estado real",
	}, Handler: legacyAdapter("ask")},
	{Spec: console.CommandSpec{
		Name: "status", Category: "Evidence",
		Usage: "status", Description: "estado completo: entidades, relaciones, objectives",
	}, Handler: legacyAdapter("status")},
	{Spec: console.CommandSpec{
		Name: "stages", Category: "Evidence",
		Usage: "stages", Description: "etapas de la investigación (NOT_STARTED/ACTIVE/...)",
	}, Handler: legacyAdapter("stages")},

	{Spec: console.CommandSpec{
		Name: "watch", Category: "Terminal",
		Usage: "watch [--interval <segundos>]", Description: "dashboard en vivo, solo lectura (subproceso)",
	}, Handler: subprocessAdapter("watch")},
	{Spec: console.CommandSpec{
		Name: "start", Category: "Terminal",
		Usage: "start <target> [--tmux]", Description: "terminal embebida + dashboard en vivo (subproceso)",
	}, Handler: subprocessAdapter("start")},
	{Spec: console.CommandSpec{
		Name: "tui", Category: "Terminal",
		Usage: "tui", Description: "la app completa directamente (subproceso)",
	}, Handler: subprocessAdapter("tui")},
}

// aliasCommandDefinitions cubre la sección L del plan: hosts/services/
// hypotheses/coverage como atajos directos de `show ...`.
var aliasCommandDefinitions = []commandDefinition{
	{Spec: console.CommandSpec{Name: "hosts", Category: "Navigation", Usage: "hosts", Description: "alias de: show hosts"},
		Handler: func(cs *ConsoleSession, args []string) error { return handleShow(cs, append([]string{"hosts"}, args...)) }},
	{Spec: console.CommandSpec{Name: "services", Category: "Navigation", Usage: "services", Description: "alias de: show services"},
		Handler: func(cs *ConsoleSession, args []string) error { return handleShow(cs, append([]string{"services"}, args...)) }},
	{Spec: console.CommandSpec{Name: "hypotheses", Category: "Navigation", Usage: "hypotheses", Description: "alias de: show hypotheses"},
		Handler: func(cs *ConsoleSession, args []string) error { return handleShow(cs, append([]string{"hypotheses"}, args...)) }},
	{Spec: console.CommandSpec{Name: "coverage", Category: "Navigation", Usage: "coverage", Description: "alias de: show coverage"},
		Handler: func(cs *ConsoleSession, args []string) error { return handleShow(cs, append([]string{"coverage"}, args...)) }},
}

// buildConsole arma Registry+handlers desde el ÚNICO slice de arriba —
// diverger entre ambos es estructuralmente imposible.
func buildConsole() (*console.Registry, map[string]consoleHandler) {
	reg := console.NewRegistry()
	handlers := map[string]consoleHandler{}

	register := func(def commandDefinition) {
		if err := reg.Register(def.Spec); err != nil {
			panic(err) // error de programación (nombre/alias duplicado) — falla al arrancar
		}
		if def.Handler != nil {
			handlers[def.Spec.Name] = def.Handler
			for _, a := range def.Spec.Aliases {
				handlers[a] = def.Handler
			}
		}
	}

	for _, def := range commandDefinitions {
		register(def)
	}
	for _, def := range aliasCommandDefinitions {
		register(def)
	}

	return reg, handlers
}
