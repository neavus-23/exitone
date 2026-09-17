package main

import (
	"fmt"
	"sort"
	"strings"

	"exitone/internal/console"
)

// handleHelp cubre tanto `help` como `?` — sección 15 del pedido original:
// deliberadamente el MISMO comportamiento exacto, nunca dos vistas
// distintas. `help --all` ignora la priorización por contexto; `help <cmd>`
// muestra el detalle de un comando puntual.
func handleHelp(cs *ConsoleSession, args []string) error {
	if len(args) == 1 && args[0] != "--all" {
		return printCommandHelp(cs, args[0])
	}

	ctx := cs.Stack.Current()
	showAll := len(args) == 1 && args[0] == "--all"

	if !showAll && ctx.Type != console.Workspace {
		relevant := consoleRegistry.ValidIn(ctx.Type)
		if len(relevant) > 0 {
			fmt.Printf("Comandos relevantes en contexto %s:\n\n", describeContext(ctx))
			for _, spec := range relevant {
				printSpecLine(spec)
			}
			fmt.Println()
		}
	}

	fmt.Println("Todos los comandos:")
	categories := consoleRegistry.ByCategory()
	var names []string
	for cat := range categories {
		names = append(names, cat)
	}
	sort.Strings(names)
	for _, cat := range names {
		// Encabezado de sección en MAYÚSCULA — mismo formato de industria
		// que `nmap` usa en su OPTIONS SUMMARY (TARGET SPECIFICATION, HOST
		// DISCOVERY, etc.), agrupando por tarea en vez de alfabético.
		fmt.Printf("\n%s\n", strings.ToUpper(cat))
		for _, spec := range categories[cat] {
			printSpecLine(spec)
		}
	}
	return nil
}

func printSpecLine(spec *console.CommandSpec) {
	usage := spec.Usage
	if usage == "" {
		usage = spec.Name
	}
	fmt.Printf("  %-32s %s\n", usage, spec.Description)
}

func printCommandHelp(cs *ConsoleSession, name string) error {
	spec, ok := consoleRegistry.Resolve(name)
	if !ok {
		suggestions := consoleRegistry.Suggest(name)
		if len(suggestions) > 0 {
			return fmt.Errorf("comando desconocido: %q — ¿quisiste decir %v?", name, suggestions)
		}
		return fmt.Errorf("comando desconocido: %q", name)
	}
	fmt.Printf("%s\n\n%s\n", spec.Usage, spec.Description)
	if len(spec.Aliases) > 0 {
		fmt.Printf("\nAliases: %v\n", spec.Aliases)
	}
	return nil
}
