// exitone tui — la app real (sección "hagamoslo"): una sola ventana con una
// terminal embebida de verdad (PTY + emulador VT) a la izquierda, donde el
// operador trabaja normal, y un panel en vivo a la derecha con el estado de
// ExitOne — sin necesitar tmux. Inspirado directamente en cómo PentestGPT
// resuelve esto con una TUI de Textual (investigado explícitamente para
// esta decisión): un solo programa, no procesos/paneles coordinados por
// fuera.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"

	"exitone/internal/stage"
	"exitone/internal/store"
)

const sidebarWidth = 42

type ptyOutputMsg []byte
type ptyClosedMsg struct{}
type dashboardTickMsg time.Time

// sidebarMode — el panel lateral es angosto (sidebarWidth), así que en vez
// de amontonar todo, se cicla entre vistas enfocadas con Tab (idea tomada
// de RedAmon: un grafo del attack surface en vez de solo listas planas; y
// de Pentest Copilot: una vista dedicada de identidades/credenciales en
// vez de mezclarlas con el resto de entidades).
type sidebarMode int

const (
	sidebarOverview sidebarMode = iota
	sidebarGraph
	sidebarVault
	sidebarModeCount
)

func (m sidebarMode) label() string {
	switch m {
	case sidebarGraph:
		return "GRAPH"
	case sidebarVault:
		return "VAULT"
	default:
		return "OVERVIEW"
	}
}

type tuiModel struct {
	s          *store.Store
	emu        *vt.Emulator
	ptmx       *os.File
	cmd        *exec.Cmd
	width      int
	height     int
	termWidth  int
	termHeight int
	sidebar    string
	quitting   bool
	paused     bool        // Ctrl+P (tomado de PentestGPT): congela el refresco del panel
	showHelp   bool        // F1 (tomado de PentestGPT): overlay de ayuda contextual
	mode       sidebarMode // Tab: cicla Overview/Graph/Vault
}

func newTUIModel(s *store.Store) *tuiModel {
	return &tuiModel{s: s}
}

func (m *tuiModel) Init() tea.Cmd {
	// Deliberadamente NO arrancamos la pty aquí todavía. Bug real encontrado
	// probando en vivo: si el shell empieza a dibujar su prompt en un
	// emulador de 80x24 (tamaño por defecto) y LUEGO llega el primer
	// WindowSizeMsg forzando un Resize() al tamaño real del pane, el
	// contenido ya escrito se pierde (Resize no lo conserva/redibuja solo).
	// Por eso esperamos a conocer el tamaño real antes de crear el
	// emulador y lanzar la pty — así arrancan ya con las dimensiones
	// correctas y nunca hace falta un resize "destructivo" de por medio.
	//
	// Nota sobre el cursor: probamos primero mostrar y posicionar el cursor
	// NATIVO del terminal (tea.ShowCursor + secuencia CUP), pero el renderer
	// de Bubble Tea en alt-screen lo fuerza siempre a la última línea del
	// frame después de cada redibujado (confirmado en su código fuente,
	// standard_renderer.go) — no hay forma de posicionarlo nosotros en esta
	// versión. Por eso el cursor se dibuja a mano en View() (ver
	// overlayCursor) y el nativo se deja OCULTO (default) para no mostrar
	// un segundo cursor parpadeando sin sentido en la última línea.
	return tickDashboard()
}

func (m *tuiModel) startShell() tea.Cmd {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/zsh"
	}
	c := exec.Command(shell, "-i")
	c.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.StartWithSize(c, &pty.Winsize{Rows: uint16(m.termHeight), Cols: uint16(m.termWidth)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "no se pudo abrir la pty:", err)
		os.Exit(1)
	}
	m.ptmx = ptmx
	m.cmd = c
	m.emu = vt.NewEmulator(m.termWidth, m.termHeight)

	// CAUSA RAÍZ del freeze real encontrado probando en vivo (confirmado con
	// volcado de goroutines vía SIGUSR1, no adivinado): cuando algo dentro
	// del shell embebido pregunta por el color de fondo del terminal
	// (secuencia OSC 10/11 — lipgloss/termenv lo hacen SIEMPRE al arrancar,
	// así que CUALQUIER binario de Go con esas dependencias lo dispara,
	// incluido nuestro propio `exitone status`), el emulador genera la
	// "respuesta" que un terminal real enviaría y la deja disponible vía
	// Emulator.Read() — pero si nadie llama a Read(), el pipe interno se
	// llena y el siguiente Write() (parseo de escape sequences) se queda
	// bloqueado para siempre. Como Update() llama a emu.Write()
	// sincrónicamente y Bubble Tea tiene un event loop single-threaded, esto
	// congelaba TODA la TUI, no solo el panel de la terminal. La corrección:
	// drenar Read() continuamente y reenviar esos bytes al PTY real — así
	// el emulador se comporta exactamente como una terminal de verdad que
	// responde a las preguntas de las aplicaciones que corren dentro.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := m.emu.Read(buf)
			if n > 0 {
				m.ptmx.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	return waitForPtyOutput(m.ptmx)
}

func waitForPtyOutput(f *os.File) tea.Cmd {
	return func() tea.Msg {
		buf := make([]byte, 8192)
		n, err := f.Read(buf)
		if err != nil {
			return ptyClosedMsg{}
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return ptyOutputMsg(out)
	}
}

func tickDashboard() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return dashboardTickMsg(t) })
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.termWidth = m.width - sidebarWidth - 1
		if m.termWidth < 20 {
			m.termWidth = 20
		}
		m.termHeight = m.height - 1
		if m.termHeight < 5 {
			m.termHeight = 5
		}
		m.sidebar = renderSidebar(m.s, m.termHeight, m.mode)

		if m.ptmx == nil {
			// Primer tamaño conocido: arrancar la pty ya con las
			// dimensiones correctas (ver comentario en Init/startShell).
			return m, m.startShell()
		}
		// Resize real (el operador cambió el tamaño de la ventana de
		// verdad): aquí sí hace falta Resize+Setsize, con el riesgo
		// conocido y documentado de que el contenido visible se pierda
		// hasta que el shell redibuje (ej. al pulsar Enter).
		m.emu.Resize(m.termWidth, m.termHeight)
		pty.Setsize(m.ptmx, &pty.Winsize{Rows: uint16(m.termHeight), Cols: uint16(m.termWidth)})
		return m, nil

	case ptyOutputMsg:
		m.emu.Write(msg)
		return m, waitForPtyOutput(m.ptmx)

	case ptyClosedMsg:
		// El shell embebido terminó (exit/Ctrl+D) — cerramos la TUI con él,
		// igual que pasaría si cerraras la única terminal que tenías abierta.
		m.quitting = true
		return m, tea.Quit

	case dashboardTickMsg:
		// Ctrl+P (tomado de PentestGPT): congela el refresco para poder leer
		// tranquilo un dato que está a punto de cambiar — el tick sigue
		// programado, solo se ignora el redibujado mientras esté pausado.
		if !m.paused {
			m.sidebar = renderSidebar(m.s, m.termHeight, m.mode)
		}
		return m, tickDashboard()

	case tea.KeyMsg:
		if m.showHelp {
			// Con la ayuda abierta, cualquier tecla la cierra sin mandarla
			// al shell — evita que se cuele texto en el prompt sin querer.
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "f1":
			// F1 (tomado de PentestGPT): ayuda contextual, sin salir de la TUI.
			m.showHelp = true
			return m, nil
		case "ctrl+p":
			// Ctrl+P (tomado de PentestGPT, ahí pausa/reanuda al agente
			// autónomo — aquí no hay agente que pausar, así que se reutiliza
			// para congelar/reanudar el refresco del panel lateral).
			m.paused = !m.paused
			return m, nil
		case "f2":
			// Cicla Overview/Graph/Vault. Deliberadamente NO es Tab: Tab lo
			// necesita el shell embebido para autocompletar rutas/comandos —
			// robárselo habría roto el uso normal de la terminal.
			m.mode = (m.mode + 1) % sidebarModeCount
			m.sidebar = renderSidebar(m.s, m.termHeight, m.mode)
			return m, nil
		case "ctrl+q":
			// Salida explícita de la TUI SIN matar el shell embebido de forma
			// abrupta — le mandamos exit para que cierre limpio.
			if m.ptmx != nil {
				m.ptmx.Write([]byte("\r"))
			}
			m.quitting = true
			return m, tea.Quit
		case "ctrl+@", "ctrl+space":
			// Autocomplete (sección I del plan): inserta el comando top-1 en
			// el buffer de línea del shell embebido — nunca lo ejecuta. Es
			// exactamente lo mismo que hacía el widget de zsh, pero ahora
			// escribiendo directo al PTY en vez de manipular BUFFER de zle.
			if suggestion := topSuggestion(m.s); suggestion != "" && m.ptmx != nil {
				m.ptmx.Write([]byte(suggestion))
			}
			return m, nil
		default:
			if m.ptmx != nil {
				m.ptmx.Write(keyMsgToBytes(msg))
			}
			return m, nil
		}
	}
	return m, nil
}

func (m *tuiModel) View() string {
	if m.quitting {
		return "Cerrando ExitOne...\n"
	}
	if m.width == 0 {
		return "iniciando..."
	}

	// emu.Render() NO rellena cada línea hasta el ancho completo (recorta
	// espacios finales) — sin envolverlo en un lipgloss.Style con
	// Width/Height, lipgloss.JoinHorizontal mide el bloque por su línea más
	// larga real (ej. 13 caracteres de "kali@kali:~%") en vez del ancho
	// real de la pty (157), dejando el panel visualmente angosto/vacío al
	// unirlo con el sidebar. Bug real encontrado probando en vivo — el
	// causante NO era el resize (ese era un bug real aparte, ya corregido
	// por separado), sino este padding faltante.
	// Bug de UX real reportado probando ("no se ve dónde se está escribiendo,
	// no parece una terminal real"): investigando la causa en el código
	// fuente de Bubble Tea (standard_renderer.go) encontramos que su
	// renderer, en modo alt-screen, SIEMPRE fuerza el cursor real del
	// terminal a la última línea del frame después de cada redibujado —
	// cualquier código de posicionamiento (CUP) que pongamos en View() se
	// sobreescribe de inmediato, sin excepción, en esta versión de la
	// librería (no hay v2 publicada todavía para resolverlo de raíz). En
	// vez de pelear con el renderer, dibujamos el cursor NOSOTROS: invertir
	// el carácter exacto bajo la posición real del cursor del emulador,
	// usando ansi.Cut (respeta los códigos de color ya presentes en esa
	// línea en vez de romperlos).
	cursorPos := m.emu.CursorPosition()
	rawRender := overlayCursor(m.emu.Render(), cursorPos.X, cursorPos.Y)
	termPane := lipgloss.NewStyle().
		Width(m.termWidth).
		Height(m.termHeight).
		MaxHeight(m.termHeight).
		Render(rawRender)
	// Bug real encontrado probando en vivo: strings.Repeat("│\n", N) deja un
	// '\n' final que añade una línea vacía de MÁS respecto a termPane/
	// sidebarPane (que tienen exactamente termHeight líneas) — ese desajuste
	// de conteo de líneas entre los tres bloques hacía que
	// lipgloss.JoinHorizontal los desalineara y el panel de la terminal
	// terminara pareciendo vacío. strings.Repeat + TrimSuffix asegura
	// exactamente termHeight líneas, ni una más.
	divider := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		Height(m.termHeight).
		Render(strings.TrimSuffix(strings.Repeat("│\n", m.termHeight), "\n"))

	sidebarPane := lipgloss.NewStyle().
		Width(sidebarWidth).
		Height(m.termHeight).
		Padding(0, 1).
		Render(m.sidebar)

	pauseTag := ""
	if m.paused {
		pauseTag = colorize(ansiYellow, " [PAUSADO]")
	}
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("8")).
		Render("Ctrl+Space: sugerencia · F2: "+m.mode.label()+" · Ctrl+P: pausar · F1: ayuda · Ctrl+Q: salir") + pauseTag

	view := lipgloss.JoinHorizontal(lipgloss.Top, termPane, divider, sidebarPane) + "\n" + footer

	if m.showHelp {
		return renderHelpOverlay(m.width, m.height)
	}
	return view
}

// overlayCursor invierte visualmente (fondo/texto intercambiados) el
// carácter en la posición (x,y) del texto multilínea renderizado por el
// emulador — así se ve claramente dónde está el cursor incluso sin poder
// usar el cursor nativo del terminal (ver comentario en View()). Usa
// ansi.Cut para cortar por columna VISUAL sin romper los códigos de color
// que ya trae la línea.
func overlayCursor(rendered string, x, y int) string {
	lines := strings.Split(rendered, "\n")
	if y < 0 || y >= len(lines) {
		return rendered
	}
	line := lines[y]
	before := ansi.Cut(line, 0, x)
	at := ansi.Cut(line, x, x+1)
	if at == "" {
		at = " " // el cursor puede estar una columna más allá del último carácter escrito
	}
	after := ansi.Cut(line, x+1, 100000)
	lines[y] = before + "\x1b[7m" + at + "\x1b[27m" + after
	return strings.Join(lines, "\n")
}

func renderHelpOverlay(width, height int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("6")).
		Padding(1, 3).
		Render(strings.Join([]string{
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render("ExitOne — ayuda"),
			"",
			"Ctrl+Space   insertar la sugerencia de mayor score en el prompt (nunca la ejecuta)",
			"F2           cambiar de vista en el panel: Overview → Graph → Vault",
			"Ctrl+P       pausar/reanudar el refresco del panel (para leer tranquilo)",
			"F1           esta ayuda — cualquier tecla la cierra",
			"Ctrl+Q       salir de ExitOne (el shell embebido se cierra con él)",
			"",
			"Todo lo demás se manda tal cual al shell embebido — es una terminal real.",
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("(pulsa cualquier tecla para volver)"),
		}, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// topSuggestion consulta directo el candidato de mayor score — equivalente a
// `exitone next --raw` pero sin lanzar un subproceso (ya tenemos *store.Store
// abierto en el proceso de la TUI).
func topSuggestion(s *store.Store) string {
	sessionID, ok, err := s.GetAppState("current_session")
	if err != nil || !ok {
		return ""
	}
	var cmd string
	err = s.DB.QueryRow(`
		SELECT command_template_rendered FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 1`, sessionID).Scan(&cmd)
	if err != nil {
		return ""
	}
	return cmd
}

func renderSidebar(s *store.Store, height int, mode sidebarMode) string {
	var b strings.Builder
	sessionID, ok, _ := s.GetAppState("current_session")
	if !ok {
		b.WriteString(lipgloss.NewStyle().Bold(true).Render("ExitOne"))
		b.WriteString("\n\nsin sesión activa\n(session new <target>)\n")
		return b.String()
	}

	var label string
	s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&label)
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render("ExitOne — " + label))
	b.WriteString(fmt.Sprintf("\n%s   [%s]\n\n", time.Now().Format("15:04:05"), mode.label()))

	switch mode {
	case sidebarGraph:
		renderAttackSurfaceGraph(&b, s, sessionID)
	case sidebarVault:
		renderVault(&b, s, sessionID)
	default:
		renderOverview(&b, s, sessionID)
	}

	return b.String()
}

func renderOverview(b *strings.Builder, s *store.Store, sessionID string) {
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("ETAPAS") + "\n")
	if stages, err := stage.Estimate(s, sessionID); err == nil {
		for _, st := range stages {
			fmt.Fprintf(b, "%-22s %s\n", st.Name, st.Status)
		}
	}

	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("SUGERENCIAS") + "\n")
	rows, err := s.DB.Query(`
		SELECT source, tool, command_template_rendered, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 4`, sessionID)
	if err == nil {
		any := false
		for rows.Next() {
			any = true
			var source, tool, cmd string
			var score float64
			rows.Scan(&source, &tool, &cmd, &score)
			fmt.Fprintf(b, "%.2f [%s] %s\n", score, source, truncate(cmd, sidebarWidth-14))
		}
		rows.Close()
		if !any {
			b.WriteString("(ninguna pendiente)\n")
		}
	}

	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("OBJECTIVES ABIERTOS") + "\n")
	orows, err := s.DB.Query(`SELECT intent_key FROM methodology_objective WHERE session_id = ? AND status = 'open'`, sessionID)
	if err == nil {
		any := false
		for orows.Next() {
			any = true
			var k string
			orows.Scan(&k)
			b.WriteString("? " + k + "\n")
		}
		orows.Close()
		if !any {
			b.WriteString("(ninguno)\n")
		}
	}
}

// renderAttackSurfaceGraph — tomado de RedAmon (grafo del attack surface),
// adaptado a un árbol ASCII porque un layout de grafo real (force-directed)
// no cabe en un panel de texto de 42 columnas. host → servicios/shares →
// dominio, por indentación — es la misma información que RELACIONES en
// `exitone status`, pero como estructura navegable en vez de lista plana.
func renderAttackSurfaceGraph(b *strings.Builder, s *store.Store, sessionID string) {
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("ATTACK SURFACE") + "\n")
	hosts, err := s.DB.Query(`SELECT id, canonical_value FROM entity WHERE session_id = ? AND type = 'host'`, sessionID)
	if err != nil {
		return
	}
	type hostRow struct{ id, value string }
	var hs []hostRow
	for hosts.Next() {
		var h hostRow
		hosts.Scan(&h.id, &h.value)
		hs = append(hs, h)
	}
	hosts.Close()

	if len(hs) == 0 {
		b.WriteString("(sin entidades todavía)\n")
		return
	}

	for _, h := range hs {
		fmt.Fprintf(b, "%s\n", h.value)
		rows, _ := s.DB.Query(`
			SELECT r.kind, e2.type, e2.canonical_value
			FROM relationship r JOIN entity e2 ON e2.id = r.target_entity_id
			WHERE r.source_entity_id = ?`, h.id)
		type rel struct{ kind, etype, value string }
		var rels []rel
		for rows.Next() {
			var rr rel
			rows.Scan(&rr.kind, &rr.etype, &rr.value)
			rels = append(rels, rr)
		}
		rows.Close()
		for i, rr := range rels {
			branch := "├─"
			if i == len(rels)-1 {
				branch = "└─"
			}
			fmt.Fprintf(b, "%s %s: %s\n", branch, strings.ToLower(rr.etype), truncate(rr.value, sidebarWidth-16))
		}
	}
}

// renderVault — tomado de Pentest Copilot (vault de credenciales
// deduplicado, siempre visible). Aquí: todas las identidades descubiertas
// en la sesión, con su provenance (confirmed/user-provided/inferred-llm) —
// exactamente la distinción que la Prueba 6 del protocolo de validación
// exigía que nunca se perdiera de vista.
func renderVault(b *strings.Builder, s *store.Store, sessionID string) {
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("IDENTITY VAULT") + "\n")
	rows, err := s.DB.Query(`SELECT canonical_value, attrs FROM entity WHERE session_id = ? AND type = 'identity' ORDER BY canonical_value`, sessionID)
	if err != nil {
		return
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		any = true
		var value, attrsJSON string
		rows.Scan(&value, &attrsJSON)
		fmt.Fprintf(b, "• %-16s %s\n", truncate(value, 16), provenanceLabel(attrsJSON))
	}
	if !any {
		b.WriteString("(ninguna identidad descubierta todavía)\n")
	}
}

func provenanceLabel(attrsJSON string) string {
	var attrs map[string]any
	if json.Unmarshal([]byte(attrsJSON), &attrs) != nil {
		return "confirmed"
	}
	if attrs["extracted_by"] == "llm" {
		conf, _ := attrs["confidence"].(float64)
		return fmt.Sprintf("llm(%.2f)", conf)
	}
	if src, ok := attrs["source"].(string); ok && src != "" {
		return "via:" + src
	}
	return "confirmed"
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func truncate(s string, n int) string {
	if n < 1 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// keyMsgToBytes traduce el evento de tecla de bubbletea a los bytes que
// esperaría recibir un terminal real — necesario porque el PTY embebido no
// entiende "KeyMsg", entiende bytes crudos (secuencias VT100 para flechas,
// códigos de control para Ctrl+letra, etc.).
func keyMsgToBytes(msg tea.KeyMsg) []byte {
	switch msg.String() {
	case "enter":
		return []byte("\r")
	case "backspace":
		return []byte("\x7f")
	case "tab":
		return []byte("\t")
	case "esc":
		return []byte("\x1b")
	case "up":
		return []byte("\x1b[A")
	case "down":
		return []byte("\x1b[B")
	case "right":
		return []byte("\x1b[C")
	case "left":
		return []byte("\x1b[D")
	case "space":
		return []byte(" ")
	case "ctrl+c":
		return []byte("\x03")
	case "ctrl+d":
		return []byte("\x04")
	case "ctrl+z":
		return []byte("\x1a")
	case "ctrl+l":
		return []byte("\x0c")
	}
	// ctrl+<letra> genérico: código de control = letra - 'a' + 1
	if strings.HasPrefix(msg.String(), "ctrl+") {
		rest := strings.TrimPrefix(msg.String(), "ctrl+")
		if len(rest) == 1 && rest[0] >= 'a' && rest[0] <= 'z' {
			return []byte{rest[0] - 'a' + 1}
		}
	}
	if len(msg.Runes) > 0 {
		return []byte(string(msg.Runes))
	}
	return nil
}

func cmdTUI(s *store.Store) {
	installGoroutineDumpHandler()
	m := newTUIModel(s)
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error en la TUI:", err)
		os.Exit(1)
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
	}
}

// installGoroutineDumpHandler: SIGUSR1 vuelca el stack de TODAS las
// goroutines a ~/.exitone/tui_goroutines.log — la única forma honesta de
// diagnosticar un freeze real (dónde está bloqueado, no adivinar).
func installGoroutineDumpHandler() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)
	go func() {
		for range sigCh {
			home, _ := os.UserHomeDir()
			f, err := os.Create(filepath.Join(home, ".exitone", "tui_goroutines.log"))
			if err != nil {
				continue
			}
			pprof.Lookup("goroutine").WriteTo(f, 2)
			f.Close()
		}
	}()
}
