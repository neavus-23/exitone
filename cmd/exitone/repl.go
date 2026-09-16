// Modo interactivo: `exitone` sin argumentos deja al operador "dentro" del
// programa, escribiendo comandos sin repetir `exitone` cada vez (ej. `next`,
// `accept <id>`, `ask "..."`) hasta que sale con `exit`/`quit`/Ctrl+D.
//
// Estética inspirada en msfconsole (banner + prompt de sesión + prefijos de
// color [+]/[-]/[!]/[*]) en vez de replicar la UI de Claude Code (basada en
// Ink/React, un reconciler de terminal que no tiene equivalente ligero en Go
// sin adoptar un framework TUI completo como Bubble Tea — ver sección O del
// plan, "TUI/CLI framework", pendiente para cuando se justifique la
// inversión). msfconsole es además la referencia visual con la que el
// público objetivo de ExitOne (pentesters/CTF) ya está familiarizado.
//
// Cada línea se ejecuta re-invocando este mismo binario como subproceso
// (self-exec) en vez de llamar a dispatch() directamente en el mismo
// proceso. Razón: fatal() en el resto del CLI llama a os.Exit(1) — si el
// REPL llamara a dispatch() in-process, un solo error mataría toda la
// sesión interactiva. Con self-exec, solo muere el subproceso del comando
// que falló; el REPL sigue vivo. Además, capturamos su stdout/stderr por
// pipe (en vez de heredarlo directo) para poder colorear por heurística sin
// tocar los ~20 puntos de fmt.Println repartidos por el resto del CLI.
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"exitone/internal/store"
)

// Paleta ANSI — msfconsole usa rojo para el banner/prompt y verde/rojo para
// resultados; aquí cian para la identidad de ExitOne (evita el cliché
// hacker verde-sobre-negro que la sección 28 del plan pide evitar) y el
// mismo verde/rojo/amarillo semántico de msfconsole para resultados.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

func colorize(color, s string) string { return color + s + ansiReset }

const bannerWidth = 62

func printBanner() {
	top := "┌" + strings.Repeat("─", bannerWidth-2) + "┐"
	bot := "└" + strings.Repeat("─", bannerWidth-2) + "┘"
	fmt.Println(colorize(ansiCyan, top))
	fmt.Println(colorize(ansiCyan, "│") + centerText("E X I T O N E", bannerWidth-2, ansiBold+ansiCyan) + colorize(ansiCyan, "│"))
	fmt.Println(colorize(ansiCyan, "│") + centerText("exit code 1 — algo requiere investigación", bannerWidth-2, ansiDim) + colorize(ansiCyan, "│"))
	fmt.Println(colorize(ansiCyan, bot))
	fmt.Println(colorize(ansiDim, "  observa · correlaciona · sugiere — el humano decide y ejecuta"))
	fmt.Println()
}

func centerText(s string, width int, color string) string {
	pad := width - len([]rune(s))
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + colorize(color, s) + strings.Repeat(" ", right)
}

// commandHelp — misma idea que la tabla "Core Commands" de msfconsole.
var commandHelp = [][2]string{
	{"session new <target>", "crear/activar una sesión de investigación"},
	{"next", "sugerencias rankeadas (Action Intents)"},
	{"why <id>", "explicar por qué se sugirió un candidato"},
	{"accept <id>", "aceptar un candidato — registra la acción, NO ejecuta nada"},
	{"resolve <action-id> --result fail|success", "cerrar/confirmar una hipótesis tras probar algo"},
	{"dismiss <id>", "descartar una sugerencia obsoleta"},
	{"ingest <archivo> [--tool <hint>] [--host <ip>]", "ingerir evidencia manualmente (agnóstico a la herramienta)"},
	{"ingest identities <archivo> --source <origen>", "registrar identidades descubiertas"},
	{"status", "estado completo: entidades, relaciones, objectives"},
	{"stages", "etapas de la investigación (NOT_STARTED/ACTIVE/...)"},
	{"ask \"<pregunta>\"", "consulta en lenguaje natural, anclada al estado real"},
	{"watch", "dashboard en vivo (mejor en un pane aparte — ver 'exitone start')"},
	{"clear", "limpiar pantalla"},
	{"exit / quit", "salir"},
}

func printHelpTable() {
	fmt.Println(colorize(ansiBold, "\nComandos disponibles\n") + colorize(ansiGray, strings.Repeat("=", 60)))
	width := 0
	for _, row := range commandHelp {
		if len(row[0]) > width {
			width = len(row[0])
		}
	}
	for _, row := range commandHelp {
		fmt.Printf("  %s%-*s%s  %s\n", ansiGreen, width, row[0], ansiReset, row[1])
	}
	fmt.Println()
}

func runRepl() {
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}

	printBanner()
	label := currentSessionLabelOrEmpty()
	if label != "" {
		fmt.Println(statusLine("+", ansiGreen, "sesión activa: "+label))
	} else {
		fmt.Println(statusLine("*", ansiCyan, "sin sesión activa — empieza con: session new <target>"))
	}
	fmt.Println(colorize(ansiGray, "escribe 'help' para ver comandos, 'exit' para salir\n"))

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(replPromptString())
		if !scanner.Scan() {
			fmt.Println()
			break // EOF (Ctrl+D)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch line {
		case "exit", "quit", "q":
			fmt.Println(statusLine("*", ansiCyan, "cerrando ExitOne."))
			return
		case "help", "?":
			printHelpTable()
			continue
		case "clear", "cls":
			fmt.Print("\033[H\033[2J")
			continue
		}

		args := splitReplLine(line)
		if len(args) == 0 {
			continue
		}
		runChildCommand(selfPath, args)
	}
}

func statusLine(symbol, color, text string) string {
	return fmt.Sprintf("%s[%s]%s %s", color, symbol, ansiReset, text)
}

// runChildCommand ejecuta `exitone <args...>` como subproceso, capturando su
// salida por pipe para poder colorear por heurística (estilo msfconsole:
// verde=éxito, rojo=error, amarillo=advertencia) sin modificar el resto del
// CLI existente.
func runChildCommand(selfPath string, args []string) {
	cmd := exec.Command(selfPath, args...)
	cmd.Stdin = os.Stdin

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(statusLine("-", ansiRed, err.Error()))
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Println(statusLine("-", ansiRed, err.Error()))
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println(statusLine("-", ansiRed, err.Error()))
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go streamColorized(stdout, false, &wg)
	go streamColorized(stderr, true, &wg)
	wg.Wait()
	_ = cmd.Wait() // el exit code ya se comunicó vía el texto de error coloreado
}

var (
	reHeaderLine    = regexp.MustCompile(`^[A-ZÁÉÍÓÚÑa-záéíóúñ ]+:$`)
	reCandidateLine = regexp.MustCompile(`^\d+\.\s+\[`)
)

func streamColorized(r io.Reader, isStderr bool, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(colorizeChildLine(line, isStderr))
	}
}

// colorizeChildLine aplica la misma semántica de color que msfconsole:
// rojo=error, amarillo=advertencia, verde=confirmación de éxito,
// cian en negrita=encabezados de sección, gris=líneas de detalle.
func colorizeChildLine(line string, isStderr bool) string {
	trimmed := strings.TrimSpace(line)
	switch {
	case isStderr || strings.HasPrefix(trimmed, "error:"):
		return statusLine("-", ansiRed, line)
	case strings.Contains(line, "⚠"):
		return colorize(ansiYellow, line)
	case strings.HasPrefix(trimmed, "Sesión creada") ||
		strings.HasPrefix(trimmed, "Acción registrada") ||
		strings.HasPrefix(trimmed, "Outcome") ||
		strings.HasPrefix(trimmed, "Hipótesis registrada") ||
		strings.HasPrefix(trimmed, "Candidato descartado") ||
		strings.HasPrefix(trimmed, "Ingesta OK"):
		return statusLine("+", ansiGreen, line)
	case strings.HasPrefix(trimmed, "Candidatos generados") ||
		strings.HasPrefix(trimmed, "Nuevos methodology"):
		return statusLine("*", ansiCyan, line)
	case reCandidateLine.MatchString(trimmed):
		return colorize(ansiBold, line)
	case reHeaderLine.MatchString(trimmed):
		return colorize(ansiBold+ansiCyan, line)
	default:
		return line
	}
}

// splitReplLine tokeniza respetando comillas dobles — necesario para
// `ask "pregunta con espacios"`.
func splitReplLine(line string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuotes = !inQuotes
		case c == ' ' && !inQuotes:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}

// replPromptString imita `msf6 exploit(...) >` — muestra la sesión activa
// para que el operador siempre sepa contra qué target está trabajando.
func replPromptString() string {
	label := currentSessionLabelOrEmpty()
	if label == "" {
		return colorize(ansiBold+ansiCyan, "exitone") + colorize(ansiGray, " > ")
	}
	return colorize(ansiBold+ansiCyan, "exitone") + colorize(ansiGray, "(") +
		colorize(ansiBold+ansiGreen, label) + colorize(ansiGray, ") > ")
}

func currentSessionLabelOrEmpty() string {
	s, err := store.Open(dbPath())
	if err != nil {
		return ""
	}
	defer s.Close()
	id, ok, err := s.GetAppState("current_session")
	if err != nil || !ok {
		return ""
	}
	var label string
	s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, id).Scan(&label)
	return label
}
