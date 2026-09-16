// exitone watch / exitone start — el flujo normal que un pentester debería
// tener por defecto: una ventana de trabajo normal (su shell de siempre,
// con los hooks corriendo silenciosos) + un panel en vivo mostrando en qué
// va la investigación, sin tener que teclear `next`/`status` cada rato.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"exitone/internal/stage"
	"exitone/internal/store"
)

// cmdWatch es un dashboard que se redibuja solo — pensado para dejarlo
// corriendo en un pane de tmux al lado de la terminal donde el operador
// trabaja de verdad. Nunca ejecuta nada, solo lee el estado real de la DB.
func cmdWatch(s *store.Store, args []string) {
	_, flags := parseFlags(args)
	interval := 3 * time.Second
	if v := flags["interval"]; v != "" {
		if secs, err := time.ParseDuration(v + "s"); err == nil {
			interval = secs
		}
	}

	for {
		sessionID, hasSession := tryCurrentSession(s)
		fmt.Print("\033[H\033[2J")
		printWatchHeader(s, sessionID, hasSession, interval)
		if hasSession {
			printWatchStages(s, sessionID)
			printWatchCandidates(s, sessionID)
			printWatchObjectives(s, sessionID)
		}
		fmt.Println(colorize(ansiGray, "\n  Ctrl+C para salir — este panel nunca ejecuta nada, solo observa."))
		time.Sleep(interval)
	}
}

func tryCurrentSession(s *store.Store) (string, bool) {
	id, ok, err := s.GetAppState("current_session")
	if err != nil || !ok {
		return "", false
	}
	return id, true
}

func printWatchHeader(s *store.Store, sessionID string, hasSession bool, interval time.Duration) {
	top := "┌" + strings.Repeat("─", bannerWidth-2) + "┐"
	bot := "└" + strings.Repeat("─", bannerWidth-2) + "┘"
	fmt.Println(colorize(ansiCyan, top))
	fmt.Println(colorize(ansiCyan, "│") + centerText("E X I T O N E — watch", bannerWidth-2, ansiBold+ansiCyan) + colorize(ansiCyan, "│"))
	if hasSession {
		var label string
		s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&label)
		fmt.Println(colorize(ansiCyan, "│") + centerText("target: "+label, bannerWidth-2, ansiDim) + colorize(ansiCyan, "│"))
	} else {
		fmt.Println(colorize(ansiCyan, "│") + centerText("sin sesión activa", bannerWidth-2, ansiDim) + colorize(ansiCyan, "│"))
	}
	fmt.Println(colorize(ansiCyan, bot))
	fmt.Printf("  %s   refresco cada %s\n\n", time.Now().Format("15:04:05"), interval)
}

func printWatchStages(s *store.Store, sessionID string) {
	stages, err := stage.Estimate(s, sessionID)
	if err != nil {
		return
	}
	fmt.Println(colorize(ansiBold+ansiCyan, "ETAPAS"))
	for _, st := range stages {
		color := ansiGray
		switch st.Status {
		case stage.Active, stage.Partial:
			color = ansiYellow
		case stage.Sufficient:
			color = ansiGreen
		case stage.Reopened:
			color = ansiRed
		}
		fmt.Printf("  %-24s %s\n", st.Name, colorize(color, string(st.Status)))
	}
	fmt.Println()
}

func printWatchCandidates(s *store.Store, sessionID string) {
	fmt.Println(colorize(ansiBold+ansiCyan, "PRÓXIMAS SUGERENCIAS (top 5, exitone next)"))
	rows, err := s.DB.Query(`
		SELECT source, tool, command_template_rendered, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 5`, sessionID)
	if err != nil {
		return
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		any = true
		var source, tool, cmd string
		var score float64
		rows.Scan(&source, &tool, &cmd, &score)
		fmt.Printf("  %s [%s] %s\n", colorize(ansiBold, fmt.Sprintf("%.2f", score)), source, cmd)
	}
	if !any {
		fmt.Println(colorize(ansiGray, "  (ninguna pendiente)"))
	}
	fmt.Println()
}

func printWatchObjectives(s *store.Store, sessionID string) {
	fmt.Println(colorize(ansiBold+ansiCyan, "OBJECTIVES ABIERTOS"))
	rows, err := s.DB.Query(`SELECT id, intent_key FROM methodology_objective WHERE session_id = ? AND status = 'open'`, sessionID)
	if err != nil {
		return
	}
	type obj struct{ id, intent string }
	var objs []obj
	for rows.Next() {
		var o obj
		rows.Scan(&o.id, &o.intent)
		objs = append(objs, o)
	}
	rows.Close()
	if len(objs) == 0 {
		fmt.Println(colorize(ansiGray, "  (ninguno)"))
		return
	}
	for _, o := range objs {
		fmt.Printf("  %s\n", o.intent)
		pRows, _ := s.DB.Query(`SELECT path_key, status FROM objective_path WHERE objective_id = ? AND status = 'open'`, o.id)
		for pRows.Next() {
			var pk, ps string
			pRows.Scan(&pk, &ps)
			fmt.Printf("    ? %s\n", pk)
		}
		pRows.Close()
	}
}

// cmdStart es el punto de entrada normal: crea/activa la sesión y arranca
// directo la TUI (terminal embebida + dashboard en vivo, sección "hagamoslo")
// — SIN tmux. Esto reemplaza el layout basado en tmux que usábamos antes de
// tener la TUI real; `exitone watch`/`exitone start --tmux` se mantienen
// como alternativa explícita para quien prefiera seguir usando panes de
// tmux en vez de la terminal embebida.
func cmdStart(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone start <target-label> [--tmux]")
	}
	target := args[0]
	_, flags := parseFlags(args[1:])

	cmdSession(s, []string{"new", target})

	if _, useTmux := flags["tmux"]; useTmux {
		startWithTmuxLayout(target)
		return
	}
	cmdTUI(s)
}

// startWithTmuxLayout es el layout anterior (dos panes de tmux) — se
// mantiene disponible con `--tmux` para quien no quiera la terminal
// embebida de la TUI (ej. limitaciones del emulador VT con alguna
// herramienta específica — ver limitaciones conocidas).
func startWithTmuxLayout(target string) {
	if _, err := exec.LookPath("tmux"); err != nil {
		fatal("tmux no está instalado o no está en el PATH")
	}
	sessionName := "exitone-" + sanitizeTmuxName(target)
	exists := exec.Command("tmux", "has-session", "-t", sessionName).Run() == nil

	if !exists {
		runQuiet("tmux", "new-session", "-d", "-s", sessionName, "-n", "work")
		runQuiet("tmux", "send-keys", "-t", sessionName+":work", "clear", "Enter")
		runQuiet("tmux", "split-window", "-h", "-t", sessionName+":work")
		runQuiet("tmux", "send-keys", "-t", sessionName+":work.1", "exitone watch", "Enter")
		runQuiet("tmux", "select-pane", "-t", sessionName+":work.0")
		fmt.Println(statusLine("+", ansiGreen, "layout creado: pane izquierdo = tu shell, pane derecho = exitone watch"))
	} else {
		fmt.Println(statusLine("*", ansiCyan, "la sesión tmux "+sessionName+" ya existía, reutilizándola"))
	}

	if os.Getenv("TMUX") != "" {
		runQuiet("tmux", "switch-client", "-t", sessionName)
		return
	}
	tmuxPath, _ := exec.LookPath("tmux")
	_ = syscall.Exec(tmuxPath, []string{"tmux", "attach-session", "-t", sessionName}, os.Environ())
}

func sanitizeTmuxName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
}

func runQuiet(name string, args ...string) {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		fmt.Println(statusLine("-", ansiRed, fmt.Sprintf("%s %s: %v", name, strings.Join(args, " "), err)))
	}
}
