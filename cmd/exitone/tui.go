// exitone tui — la app real (sección "hagamoslo"): una sola ventana con una
// terminal embebida de verdad (PTY + emulador VT) a la izquierda, donde el
// operador trabaja normal, y un panel en vivo a la derecha con el estado de
// ExitOne — sin necesitar tmux. Inspirado directamente en cómo PentestGPT
// resuelve esto con una TUI de Textual (investigado explícitamente para
// esta decisión): un solo programa, no procesos/paneles coordinados por
// fuera.
//
// El panel lateral fue rediseñado para dejar de ser un dashboard puramente
// estático (pedido real del operador probando en vivo): la sugerencia top
// ahora se narra con el LLM local (mismo `llm.Guide` que usa `exitone
// guide`), hay una sección de actividad en vivo (última evidencia/candidato,
// estado del worker de estrategia), y un modo de chat embebido (mismo
// `llm.Ask` que usa `exitone ask`) para consultar sin salir de la TUI. El
// aspecto visual se inspira en tmux/zellij: cada pane tiene su propio borde
// con título embebido, el sidebar tiene una barra de pestañas real, y el
// footer es una status-line de dos segmentos en vez de una línea de texto
// suelta.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"

	credentialstore "exitone/internal/credential"
	"exitone/internal/llm"
	"exitone/internal/stage"
	"exitone/internal/store"
)

const sidebarWidth = 42

type ptyOutputMsg []byte
type ptyClosedMsg struct{}
type dashboardTickMsg time.Time

// narrationMsg es la respuesta asíncrona de narrateCmd — candidateID identifica
// PARA QUÉ candidato se pidió, así Update() puede descartarla si para cuando
// llega el operador ya avanzó y el top real cambió (nunca mostrar una
// narración desincronizada del estado actual).
type narrationMsg struct {
	candidateID string
	text        string
	err         error
}

// chatAnswerMsg es la respuesta asíncrona de askCmd — se busca por texto de
// la pregunta en chatHistory porque solo puede haber una pregunta pendiente
// a la vez (chatAsking bloquea el envío de una segunda mientras la primera
// no respondió).
type chatAnswerMsg struct {
	question string
	answer   string
	err      error
}

type chatTurn struct {
	question string
	answer   string
	err      error
}

// sidebarMode — el panel lateral es angosto (sidebarWidth), así que en vez
// de amontonar todo, se cicla entre vistas enfocadas con F2 (idea tomada
// de RedAmon: un grafo del attack surface en vez de solo listas planas; de
// Pentest Copilot: una vista dedicada de identidades/credenciales en vez de
// mezclarlas con el resto de entidades; y un modo de chat embebido, mismo
// `llm.Ask` que ya usa `exitone ask` en otra terminal).
type sidebarMode int

const (
	sidebarOverview sidebarMode = iota
	sidebarGraph
	sidebarVault
	sidebarChat
	sidebarModeCount
)

func (m sidebarMode) label() string {
	switch m {
	case sidebarGraph:
		return "GRAPH"
	case sidebarVault:
		return "VAULT"
	case sidebarChat:
		return "CHAT"
	default:
		return "OVERVIEW"
	}
}

// appPhase separa "todavía no hay workspace elegido" de "la TUI normal ya
// está corriendo" — mientras phaseOnboarding, la pty NO se lanza (no hay
// target contra el cual abrir una terminal todavía).
type appPhase int

const (
	phaseOnboarding appPhase = iota
	phaseRunning
)

type workspaceOption struct {
	id, label, startedAt string
	hostCount            int
}

// onboardingModel — pantalla previa a la TUI normal cuando no hay una única
// sesión abierta obvia (ver newTUIModel): listar/crear workspace sin salir
// del programa ni tener que teclear `exitone session new <target>` a mano.
type onboardingModel struct {
	workspaces  []workspaceOption
	cursor      int
	creatingNew bool
	newLabel    string
	preparing   bool // esperando la narración de bienvenida antes de pasar a phaseRunning
	err         string
}

type tuiModel struct {
	s          *store.Store
	phase      appPhase
	onboarding onboardingModel
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
	mode       sidebarMode // F2: cicla Overview/Graph/Vault/Chat
	streamFile *os.File    // Fase 0: espejo de los bytes crudos del PTY, mismo formato/ruta
	// que tmux pipe-pane escribía antes — hooks.zsh lo consume igual

	// Narración de la sugerencia top (LLM, ver narrateCmd) — se dispara sola
	// cuando el candidato de mayor score CAMBIA, nunca en cada tick de 2s
	// (spamear al llama-server local en cada refresco del dashboard sería
	// tanto lento como inútil: la mayoría de los ticks no cambian nada). La
	// misma narración se reusa como "bienvenida" al salir del onboarding
	// (ver enterPreparing) — nunca una segunda llamada LLM redundante.
	narration           string
	narrationLoading    bool
	narratedCandidateID string

	// Chat embebido (LLM, ver askCmd) — mientras mode == sidebarChat, el
	// teclado deja de ir a la pty y va acá (ver handleChatKey).
	chatHistory []chatTurn
	chatInput   string
	chatAsking  bool
}

// newTUIModel decide, ANTES de dibujar nada, si hace falta onboarding:
// fricción mínima real (parte del pedido de "máxima automatización") — 0
// workspaces abiertos va directo al formulario de "nuevo target" (no hay
// nada que listar), exactamente 1 se resume solo sin mostrar ninguna
// pantalla, y solo con 2+ aparece el selector.
func newTUIModel(s *store.Store) *tuiModel {
	m := &tuiModel{s: s, phase: phaseRunning}
	if _, ok := currentSessionID(s); ok {
		return m
	}

	om := loadOnboarding(s)
	switch len(om.workspaces) {
	case 0:
		om.creatingNew = true
		m.phase = phaseOnboarding
		m.onboarding = om
	case 1:
		if err := s.SetAppState("current_session", om.workspaces[0].id); err == nil {
			return m // phaseRunning, sin pantalla de onboarding
		}
		m.phase = phaseOnboarding
		m.onboarding = om
	default:
		m.phase = phaseOnboarding
		m.onboarding = om
	}
	return m
}

// loadOnboarding lista los workspaces ABIERTOS (mismo criterio que
// `listWorkspaces`, console_workspace.go) con un conteo rápido de hosts por
// uno, para que el selector diga algo más útil que solo la fecha.
func loadOnboarding(s *store.Store) onboardingModel {
	var om onboardingModel
	rows, err := s.DB.Query(`SELECT id, target_label, started_at FROM session WHERE closed_at IS NULL ORDER BY started_at DESC`)
	if err != nil {
		return om
	}
	defer rows.Close()
	for rows.Next() {
		var w workspaceOption
		if err := rows.Scan(&w.id, &w.label, &w.startedAt); err != nil {
			continue
		}
		s.DB.QueryRow(`SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'host'`, w.id).Scan(&w.hostCount)
		om.workspaces = append(om.workspaces, w)
	}
	return om
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

	// Fase 0 del plan de arquitectura de captura: la TUI embebida es la
	// fuente PRIMARIA (ya posee el PTY y recibe todos sus bytes), tmux
	// pipe-pane pasa a ser fallback. Se le da al shell embebido su propio
	// EXITONE_STREAM_FILE (uno por proceso de TUI, vía PID) y hooks.zsh lo
	// respeta tal cual en vez de derivarlo de TMUX_PANE — mismo formato de
	// archivo que pipe-pane escribía, así que el recorte por offset de
	// bytes que hooks.zsh ya hace (__exitone_maybe_capture_full_output)
	// funciona sin ningún cambio de lógica ahí, solo de origen del archivo.
	streamDir := filepath.Join(os.Getenv("HOME"), ".exitone", "streams")
	if err := os.MkdirAll(streamDir, 0700); err == nil {
		_ = os.Chmod(streamDir, 0700)
		streamPath := filepath.Join(streamDir, fmt.Sprintf("tui%d.log", os.Getpid()))
		if f, err := os.OpenFile(streamPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600); err == nil {
			m.streamFile = f
			c.Env = append(c.Env, "EXITONE_STREAM_FILE="+streamPath)
		}
	}

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

// currentSessionID es el mismo lookup que ya hacían topSuggestion/
// renderSidebar por separado — centralizado para que narrateCmd/askCmd/
// handleChatKey lo compartan sin repetir la consulta a app_state.
func currentSessionID(s *store.Store) (string, bool) {
	id, ok, err := s.GetAppState("current_session")
	if err != nil {
		return "", false
	}
	return id, ok
}

// topCandidateID devuelve el ID del candidato de mayor score — separado de
// topSuggestion (que devuelve el comando, usado por Ctrl+Space) porque la
// narración necesita el ID para detectar cuándo el top CAMBIÓ, no el texto.
func topCandidateID(s *store.Store, sessionID string) string {
	var id string
	err := s.DB.QueryRow(`
		SELECT id FROM candidate
		WHERE session_id = ? AND status = 'proposed' AND kind = 'command' AND command_template_rendered <> ''
		ORDER BY score DESC LIMIT 1`, sessionID).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}

// narrateCmd corre `llm.Guide` (mismo que usa `exitone guide`) en su propia
// goroutine — NUNCA sincrónico en Update(), porque una llamada de 10-60s
// congelaría también la terminal embebida (Bubble Tea es de un solo hilo de
// eventos). El candidateID viaja en el mensaje de vuelta para que Update()
// pueda descartar la respuesta si el operador ya avanzó y el top cambió
// mientras el LLM pensaba.
func narrateCmd(s *store.Store, sessionID, candidateID string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		guideContext, err := llm.BuildGuideContext(s, sessionID)
		if err != nil {
			return narrationMsg{candidateID: candidateID, err: err}
		}
		client := llm.New()
		text, err := llm.Guide(ctx, client, guideContext)
		return narrationMsg{candidateID: candidateID, text: text, err: err}
	}
}

// askCmd es el equivalente para el chat embebido: mismo `llm.Ask` que usa
// `exitone ask`, mismo patrón de goroutine-propia-vía-tea.Cmd que narrateCmd.
func askCmd(s *store.Store, sessionID, question string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		summary, err := llm.BuildContextSummary(s, sessionID)
		if err != nil {
			return chatAnswerMsg{question: question, err: err}
		}
		client := llm.New()
		answer, err := llm.Ask(ctx, client, s, sessionID, summary, question)
		return chatAnswerMsg{question: question, answer: answer, err: err}
	}
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// Cada pane ahora tiene su propio borde (ver renderTitledBox en
		// View()): 2 columnas (izq+der) y 2 filas (arriba+abajo) de borde
		// por pane, más 1 columna de separación entre ambos y 1 fila para
		// la status-line inferior. Sin restar exactamente esto, el
		// contenido reportado a la pty no coincide con el espacio real
		// donde se renderiza — mismo bug de fondo ya documentado más abajo
		// en View() (desalineación de tamaños entre bloques).
		m.termWidth = m.width - sidebarWidth - 5
		if m.termWidth < 20 {
			m.termWidth = 20
		}
		m.termHeight = m.height - 3
		if m.termHeight < 5 {
			m.termHeight = 5
		}
		if m.phase == phaseOnboarding {
			// Todavía no hay workspace elegido — nada de pty hasta que se
			// resuelva (ver enterPreparing/finishOnboarding).
			return m, nil
		}
		m.sidebar = renderSidebar(m)

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
		if m.streamFile != nil {
			m.streamFile.Write(msg)
		}
		m.emu.Write(msg)
		return m, waitForPtyOutput(m.ptmx)

	case ptyClosedMsg:
		// El shell embebido terminó (exit/Ctrl+D) — cerramos la TUI con él,
		// igual que pasaría si cerraras la única terminal que tenías abierta.
		if m.streamFile != nil {
			m.streamFile.Close()
		}
		m.quitting = true
		return m, tea.Quit

	case dashboardTickMsg:
		// Ctrl+P (tomado de PentestGPT): congela el refresco para poder leer
		// tranquilo un dato que está a punto de cambiar — el tick sigue
		// programado, solo se ignora el redibujado mientras esté pausado.
		var cmds []tea.Cmd
		cmds = append(cmds, tickDashboard())
		if !m.paused && m.phase == phaseRunning {
			m.sidebar = renderSidebar(m)

			// La narración se dispara SOLO cuando el candidato top cambió
			// de verdad — nunca en cada tick de 2s (eso sería spamear al
			// llama-server local con una llamada de ~10-60s cada vez, la
			// gran mayoría inútiles porque nada cambió).
			if sessionID, ok := currentSessionID(m.s); ok {
				if candID := topCandidateID(m.s, sessionID); candID != "" &&
					candID != m.narratedCandidateID && !m.narrationLoading {
					m.narrationLoading = true
					m.narratedCandidateID = candID
					cmds = append(cmds, narrateCmd(m.s, sessionID, candID))
				}
			}
		}
		return m, tea.Batch(cmds...)

	case narrationMsg:
		// Se descarta con gracia si ya no es el candidato que nos interesa
		// (el operador avanzó mientras el LLM pensaba) — nunca se muestra
		// una guía desincronizada del estado actual.
		if msg.candidateID == m.narratedCandidateID {
			m.narrationLoading = false
			if msg.err == nil && strings.TrimSpace(msg.text) != "" {
				m.narration = strings.TrimSpace(msg.text)
			} else {
				// Degradación con gracia (LLM no disponible/timeout): la
				// lista cruda de candidatos se sigue mostrando igual, solo
				// no hay narración encima.
				m.narration = ""
			}
			// Esta es la MISMA narración que sirve de "bienvenida" al salir
			// del onboarding — nunca una segunda llamada LLM redundante.
			if m.phase == phaseOnboarding {
				return m.finishOnboarding()
			}
			m.sidebar = renderSidebar(m)
		}
		return m, nil

	case chatAnswerMsg:
		for i := range m.chatHistory {
			if m.chatHistory[i].question == msg.question && m.chatHistory[i].answer == "" && m.chatHistory[i].err == nil {
				if msg.err != nil {
					m.chatHistory[i].err = msg.err
				} else {
					m.chatHistory[i].answer = msg.answer
				}
				break
			}
		}
		m.chatAsking = false
		m.sidebar = renderSidebar(m)
		return m, nil

	case tea.KeyMsg:
		if m.phase == phaseOnboarding {
			return m.handleOnboardingKey(msg)
		}
		if m.showHelp {
			// Con la ayuda abierta, cualquier tecla la cierra sin mandarla
			// al shell — evita que se cuele texto en el prompt sin querer.
			m.showHelp = false
			return m, nil
		}
		// Estas cuatro se mantienen SIEMPRE disponibles, sin importar el
		// modo del sidebar — en particular, F2/Ctrl+Q deben poder sacar al
		// operador del modo Chat en cualquier momento.
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
			// Cicla Overview/Graph/Vault/Chat. Deliberadamente NO es Tab:
			// Tab lo necesita el shell embebido para autocompletar rutas/
			// comandos — robárselo habría roto el uso normal de la terminal.
			m.mode = (m.mode + 1) % sidebarModeCount
			m.sidebar = renderSidebar(m)
			return m, nil
		case "ctrl+q":
			// Salida explícita de la TUI SIN matar el shell embebido de forma
			// abrupta — le mandamos exit para que cierre limpio.
			if m.ptmx != nil {
				m.ptmx.Write([]byte("\r"))
			}
			if m.streamFile != nil {
				m.streamFile.Close()
			}
			m.quitting = true
			return m, tea.Quit
		}

		// Foco en el chat: el teclado deja de ir a la pty y va al cuadro de
		// texto del asistente — único cambio real de enrutamiento de
		// teclado de todo este panel (ver handleChatKey).
		if m.mode == sidebarChat {
			return m.handleChatKey(msg)
		}

		switch msg.String() {
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

// handleChatKey enruta el teclado al cuadro de texto del asistente en vez de
// a la pty — solo se llama cuando m.mode == sidebarChat (ver Update).
func (m *tuiModel) handleChatKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Vuelve el foco a la terminal sin salir de la TUI.
		m.mode = sidebarOverview
		m.sidebar = renderSidebar(m)
		return m, nil
	case "enter":
		question := strings.TrimSpace(m.chatInput)
		if question == "" || m.chatAsking {
			return m, nil
		}
		sessionID, ok := currentSessionID(m.s)
		if !ok {
			m.chatHistory = append(m.chatHistory, chatTurn{question: question, err: fmt.Errorf("sin sesión activa")})
			m.chatInput = ""
			m.sidebar = renderSidebar(m)
			return m, nil
		}
		m.chatHistory = append(m.chatHistory, chatTurn{question: question})
		m.chatInput = ""
		m.chatAsking = true
		m.sidebar = renderSidebar(m)
		return m, askCmd(m.s, sessionID, question)
	case "backspace":
		if r := []rune(m.chatInput); len(r) > 0 {
			m.chatInput = string(r[:len(r)-1])
		}
		m.sidebar = renderSidebar(m)
		return m, nil
	default:
		if len(msg.Runes) > 0 {
			m.chatInput += string(msg.Runes)
			m.sidebar = renderSidebar(m)
		}
		return m, nil
	}
}

// handleOnboardingKey enruta el teclado mientras m.phase == phaseOnboarding
// — la pty todavía no existe, así que nada se manda a un shell.
func (m *tuiModel) handleOnboardingKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+q" || msg.String() == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}
	if m.onboarding.preparing {
		// Esperando la narración de bienvenida (o el paso directo si no
		// hubo candidato que narrar) — no hay nada más que hacer acá.
		return m, nil
	}

	if !m.onboarding.creatingNew {
		switch msg.String() {
		case "up":
			if m.onboarding.cursor > 0 {
				m.onboarding.cursor--
			}
		case "down":
			if m.onboarding.cursor < len(m.onboarding.workspaces)-1 {
				m.onboarding.cursor++
			}
		case "n":
			m.onboarding.creatingNew = true
			m.onboarding.newLabel = ""
			m.onboarding.err = ""
		case "enter":
			return m.submitOnboarding()
		}
		return m, nil
	}

	// Modo "nuevo target": todo lo que se escribe va al input de texto.
	switch msg.String() {
	case "esc":
		if len(m.onboarding.workspaces) > 0 {
			m.onboarding.creatingNew = false
			m.onboarding.err = ""
		}
	case "enter":
		return m.submitOnboarding()
	case "backspace":
		if r := []rune(m.onboarding.newLabel); len(r) > 0 {
			m.onboarding.newLabel = string(r[:len(r)-1])
		}
	default:
		if len(msg.Runes) > 0 {
			m.onboarding.newLabel += string(msg.Runes)
		}
	}
	return m, nil
}

// submitOnboarding resuelve el workspace elegido/creado — crear pasa por el
// mismo puente no-fatal que usa legacyAdapter para envolver cmdSession
// (ver createOrResumeSession), así que un error real (ej. fallo de disco)
// se muestra en pantalla en vez de matar la TUI entera.
func (m *tuiModel) submitOnboarding() (tea.Model, tea.Cmd) {
	if m.onboarding.creatingNew {
		label := strings.TrimSpace(m.onboarding.newLabel)
		if label == "" {
			return m, nil
		}
		if err := createOrResumeSession(m.s, label); err != nil {
			m.onboarding.err = err.Error()
			return m, nil
		}
		return m.enterPreparing()
	}
	if len(m.onboarding.workspaces) == 0 {
		return m, nil
	}
	chosen := m.onboarding.workspaces[m.onboarding.cursor]
	if err := m.s.SetAppState("current_session", chosen.id); err != nil {
		m.onboarding.err = err.Error()
		return m, nil
	}
	return m.enterPreparing()
}

// enterPreparing dispara la MISMA narración que después se ve en GUÍA (ver
// narrateCmd) para usarla como bienvenida — nunca una segunda llamada LLM
// redundante. Si no hay ningún candidato que narrar todavía (workspace
// recién creado sin bootstrap, o el LLM local no está disponible), pasa
// directo sin bloquear al operador.
func (m *tuiModel) enterPreparing() (tea.Model, tea.Cmd) {
	m.onboarding.preparing = true
	sessionID, ok := currentSessionID(m.s)
	if !ok {
		return m.finishOnboarding()
	}
	if candID := topCandidateID(m.s, sessionID); candID != "" {
		m.narrationLoading = true
		m.narratedCandidateID = candID
		return m, narrateCmd(m.s, sessionID, candID)
	}
	return m.finishOnboarding()
}

func (m *tuiModel) finishOnboarding() (tea.Model, tea.Cmd) {
	m.phase = phaseRunning
	m.sidebar = renderSidebar(m)
	return m, m.startShell()
}

// createOrResumeSession llama cmdSession(s, {"new", label}) protegido por el
// mismo puente que ya usa legacyAdapter (console_bridge.go) para convertir
// fatal()/os.Exit en un error normal — necesario porque cmdSession, con
// interactiveMode=false (el default fuera de la consola), mataría el
// proceso entero de la TUI ante cualquier error real. cmdSession ya trae
// toda la lógica de resumir-si-existe/crear/bootstrap — no se duplica nada.
//
// cmdSession también imprime su propio "Sesión creada: ..."/"Candidatos
// generados: ..." por os.Stdout — bug real encontrado probando en vivo: esos
// `fmt.Printf` sueltos se cuelan por encima de la pantalla alterna de Bubble
// Tea (que no los controla), corrompiendo visualmente el onboarding. Se
// redirige os.Stdout a /dev/null solo durante esta llamada — el propio
// onboarding ya muestra "Preparando workspace..." como equivalente visible.
func createOrResumeSession(s *store.Store, label string) (err error) {
	devNull, openErr := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if openErr == nil {
		prevStdout := os.Stdout
		os.Stdout = devNull
		defer func() {
			os.Stdout = prevStdout
			devNull.Close()
		}()
	}

	defer func() {
		if r := recover(); r != nil {
			if msg, ok := r.(consoleAbort); ok {
				err = fmt.Errorf("%s", string(msg))
				return
			}
			panic(r) // pánico real (bug) — nunca se enmascara como un error de usuario
		}
	}()
	prev := interactiveMode
	interactiveMode = true
	defer func() { interactiveMode = prev }()
	cmdSession(s, []string{"new", label})
	return nil
}

// renderOnboarding — pantalla centrada, mismo lenguaje visual que
// renderHelpOverlay/renderTitledBox (borde redondeado, lipgloss.Place
// centrado) en vez de un prompt de texto suelto en la terminal.
func renderOnboarding(m *tuiModel) string {
	if m.width == 0 {
		return "iniciando..."
	}
	var body strings.Builder
	body.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render("Bienvenido a ExitOne") + "\n\n")

	switch {
	case m.onboarding.preparing:
		body.WriteString("Preparando workspace... " + renderChip(" razonando… ", lipgloss.Color("5")) + "\n")
	case m.onboarding.creatingNew:
		title := "Nuevo workspace"
		if len(m.onboarding.workspaces) > 0 {
			title += "  (Esc para volver a la lista)"
		}
		body.WriteString(lipgloss.NewStyle().Bold(true).Render(title) + "\n\n")
		body.WriteString("Target/IP: " + m.onboarding.newLabel + "_\n")
	default:
		body.WriteString(lipgloss.NewStyle().Bold(true).Render("Elegí un workspace (↑/↓, Enter) o 'n' para uno nuevo") + "\n\n")
		for i, w := range m.onboarding.workspaces {
			line := fmt.Sprintf("%-24s %-10s %d host(s)", truncate(w.label, 24), relTime(w.startedAt), w.hostCount)
			if i == m.onboarding.cursor {
				body.WriteString(lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("6")).Foreground(lipgloss.Color("0")).Render("> "+line) + "\n")
			} else {
				body.WriteString("  " + line + "\n")
			}
		}
		body.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("n: nuevo workspace · Ctrl+Q: salir") + "\n")
	}
	if m.onboarding.err != "" {
		body.WriteString("\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(m.onboarding.err) + "\n")
	}

	const contentWidth = 56
	lines := strings.Split(strings.TrimRight(body.String(), "\n"), "\n")
	content := lipgloss.NewStyle().Width(contentWidth).Height(len(lines)).Render(body.String())
	box := renderTitledBox("EXITONE", contentWidth, len(lines), content, lipgloss.Color("6"))
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
}

func (m *tuiModel) View() string {
	if m.quitting {
		return "Cerrando ExitOne...\n"
	}
	if m.phase == phaseOnboarding {
		return renderOnboarding(m)
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
	termContent := lipgloss.NewStyle().
		Width(m.termWidth).
		Height(m.termHeight).
		MaxHeight(m.termHeight).
		Render(rawRender)
	termBox := renderTitledBox("OPERATOR", m.termWidth, m.termHeight, termContent, lipgloss.Color("8"))

	var target string
	sessionID, hasSession := currentSessionID(m.s)
	if hasSession {
		m.s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&target)
	}
	sidebarTitle := "EXITONE"
	if target != "" {
		sidebarTitle = "EXITONE — " + target
	}
	// El pane con foco de teclado (chat) se resalta con un borde de acento —
	// mismo lenguaje visual que zellij usa para marcar el pane activo.
	sidebarAccent := lipgloss.Color("8")
	if m.mode == sidebarChat {
		sidebarAccent = lipgloss.Color("6")
	}
	sidebarContent := lipgloss.NewStyle().
		Width(sidebarWidth).
		Height(m.termHeight).
		MaxHeight(m.termHeight).
		Padding(0, 1).
		Render(renderModeTabs(m.mode) + "\n\n" + m.sidebar)
	sidebarBox := renderTitledBox(sidebarTitle, sidebarWidth, m.termHeight, sidebarContent, sidebarAccent)

	// Bug real encontrado probando en vivo (ya documentado más arriba en
	// este archivo): unir bloques de alturas distintas con
	// lipgloss.JoinHorizontal los desalinea. termBox/sidebarBox ya salen con
	// exactamente la misma altura (m.termHeight + 2 líneas de borde cada
	// uno) porque ambos se construyen desde el mismo m.termHeight — un
	// simple espacio en blanco como separador alcanza, ya no hace falta un
	// divisor "│" dibujado a mano (cada pane ya trae el suyo propio).
	panes := lipgloss.JoinHorizontal(lipgloss.Top, termBox, " ", sidebarBox)

	right := "Ctrl+Space sugerencia · F2 modo · Ctrl+P pausar · Esc salir del chat · F1 ayuda · Ctrl+Q salir"
	if m.paused {
		right = renderChip(" PAUSADO ", lipgloss.Color("3")) + " " + right
	}
	left := fmt.Sprintf(" %s · %s · %s ", orDash(target), m.mode.label(), time.Now().Format("15:04:05"))
	statusBar := renderStatusBar(m.width, left, right)

	view := panes + "\n" + statusBar

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

// renderTitledBox dibuja un borde redondeado con el título embebido en el
// propio borde superior — igual que `tmux set-option pane-border-status
// top` (ya usado literalmente en el layout `--tmux` de dashboard.go) y el
// borde por-pane de zellij. `content` debe venir YA renderizado a exactamente
// `width` columnas y `height` filas (vía lipgloss Width/Height) — esta
// función solo agrega el marco alrededor, nunca reajusta el contenido.
func renderTitledBox(title string, width, height int, content string, accentColor lipgloss.Color) string {
	style := lipgloss.NewStyle().Foreground(accentColor)
	label := " " + title + " "
	if len(label) > width {
		label = truncate(label, width)
	}
	dashes := width - 1 - len(label)
	if dashes < 0 {
		dashes = 0
	}
	top := style.Render("╭─" + label + strings.Repeat("─", dashes) + "╮")
	bottom := style.Render("╰" + strings.Repeat("─", width) + "╯")

	lines := strings.Split(content, "\n")
	var b strings.Builder
	b.WriteString(top + "\n")
	for i := 0; i < height; i++ {
		line := ""
		if i < len(lines) {
			line = lines[i]
		}
		b.WriteString(style.Render("│") + line + style.Render("│") + "\n")
	}
	b.WriteString(bottom)
	return b.String()
}

// renderModeTabs — barra de pestañas estilo zellij (pestañas con fondo
// sólido, no un label de texto suelto): reemplaza el `[OVERVIEW]` de antes,
// y de paso hace visible que existen 4 modos sin tener que abrir F1.
func renderModeTabs(active sidebarMode) string {
	labels := []string{"Overview", "Graph", "Vault", "Chat"}
	var parts []string
	for i, l := range labels {
		if sidebarMode(i) == active {
			parts = append(parts, lipgloss.NewStyle().Bold(true).
				Background(lipgloss.Color("6")).Foreground(lipgloss.Color("0")).
				Padding(0, 1).Render(l))
		} else {
			parts = append(parts, lipgloss.NewStyle().
				Foreground(lipgloss.Color("8")).Padding(0, 1).Render(l))
		}
	}
	return strings.Join(parts, "")
}

// renderStatusBar — status-line de dos segmentos con fondo sólido, estilo
// tmux, en vez del footer de una sola línea de texto gris que había antes.
func renderStatusBar(width int, left, right string) string {
	bar := lipgloss.NewStyle().Background(lipgloss.Color("8")).Foreground(lipgloss.Color("15"))
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	content := left + strings.Repeat(" ", gap) + right
	if lipgloss.Width(content) > width {
		content = truncate(content, width)
	}
	return bar.Width(width).Render(content)
}

// renderChip — una etiqueta con fondo sólido para estados puntuales
// ("razonando…", "pensando…", "PAUSADO") en vez de texto plano suelto.
func renderChip(text string, bg lipgloss.Color) string {
	return lipgloss.NewStyle().Background(bg).Foreground(lipgloss.Color("0")).Render(text)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
			"F2           cambiar de vista en el panel: Overview → Graph → Vault → Chat",
			"Esc          (solo en Chat) volver el foco a la terminal embebida",
			"Ctrl+P       pausar/reanudar el refresco del panel (para leer tranquilo)",
			"F1           esta ayuda — cualquier tecla la cierra",
			"Ctrl+Q       salir de ExitOne (el shell embebido se cierra con él)",
			"",
			"En Chat, lo que escribas va al asistente (Enter para preguntar), no al shell.",
			"En cualquier otro modo, todo lo demás se manda tal cual al shell embebido.",
			"",
			lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("(pulsa cualquier tecla para volver)"),
		}, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// topSuggestion consulta directo el candidato de mayor score — equivalente a
// `exitone next --raw` pero sin lanzar un subproceso (ya tenemos *store.Store
// abierto en el proceso de la TUI).
func topSuggestion(s *store.Store) string {
	sessionID, ok := currentSessionID(s)
	if !ok {
		return ""
	}
	var cmd string
	err := s.DB.QueryRow(`
		SELECT command_template_rendered FROM candidate
		WHERE session_id = ? AND status = 'proposed' AND kind = 'command' AND command_template_rendered <> ''
		ORDER BY score DESC LIMIT 1`, sessionID).Scan(&cmd)
	if err != nil {
		return ""
	}
	return cmd
}

// renderSidebar arma SOLO el cuerpo del panel según el modo activo — el
// título (target de la sesión) y las pestañas de modo ahora viven en el
// marco del pane (ver View()/renderTitledBox/renderModeTabs), no acá, para
// no duplicarlos.
func renderSidebar(m *tuiModel) string {
	var b strings.Builder
	sessionID, ok := currentSessionID(m.s)
	if !ok {
		b.WriteString("sin sesión activa\n(session new <target>)\n")
		return b.String()
	}

	switch m.mode {
	case sidebarGraph:
		renderAttackSurfaceGraph(&b, m.s, sessionID)
	case sidebarVault:
		renderVault(&b, m.s, sessionID)
	case sidebarChat:
		renderChat(&b, m)
	default:
		renderOverview(&b, m, sessionID)
	}

	return b.String()
}

func renderOverview(b *strings.Builder, m *tuiModel, sessionID string) {
	s := m.s

	b.WriteString(lipgloss.NewStyle().Bold(true).Render("ACTIVIDAD") + "\n")
	var evTool, evAt string
	if err := s.DB.QueryRow(`SELECT tool_name, created_at FROM evidence ORDER BY created_at DESC LIMIT 1`).Scan(&evTool, &evAt); err == nil {
		fmt.Fprintf(b, "última evidencia: %s (%s)\n", evTool, relTime(evAt))
	} else {
		b.WriteString("última evidencia: (ninguna)\n")
	}
	var candTool, candAt string
	if err := s.DB.QueryRow(`SELECT tool, created_at FROM candidate WHERE session_id = ? ORDER BY created_at DESC LIMIT 1`, sessionID).Scan(&candTool, &candAt); err == nil {
		fmt.Fprintf(b, "último candidato: %s (%s)\n", candTool, relTime(candAt))
	} else {
		b.WriteString("último candidato: (ninguno)\n")
	}
	var jobStatus, jobQueuedAt string
	if err := s.DB.QueryRow(`SELECT status, queued_at FROM strategy_job WHERE session_id = ?`, sessionID).Scan(&jobStatus, &jobQueuedAt); err == nil {
		switch jobStatus {
		case "pending", "running":
			b.WriteString("razonamiento exploratorio: " + renderChip(" en curso ", lipgloss.Color("5")) + "\n")
		case "failed":
			b.WriteString("razonamiento exploratorio: falló\n")
		default:
			fmt.Fprintf(b, "razonamiento exploratorio: al día (%s)\n", relTime(jobQueuedAt))
		}
	}

	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("GUÍA") + "\n")
	switch {
	case m.narrationLoading:
		b.WriteString(renderChip(" razonando… ", lipgloss.Color("5")) + "\n")
	case m.narration != "":
		b.WriteString(wrapText(m.narration, sidebarWidth) + "\n")
	default:
		b.WriteString("(se narra sola cuando cambia la sugerencia top)\n")
	}

	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("ETAPAS") + "\n")
	if stages, err := stage.Estimate(s, sessionID); err == nil {
		for _, st := range stages {
			fmt.Fprintf(b, "%-22s %s\n", st.Name, stageStatusStyled(st.Status))
		}
	}

	b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("SUGERENCIAS") + "\n")
	rows, err := s.DB.Query(`
		SELECT source, kind, phase_key, risk_level, command_template_rendered, explanation, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 4`, sessionID)
	if err == nil {
		any := false
		for rows.Next() {
			any = true
			var source, kind, phase, risk, cmd, explanation string
			var score float64
			rows.Scan(&source, &kind, &phase, &risk, &cmd, &explanation, &score)
			if cmd == "" {
				cmd = explanation
			}
			prefix := fmt.Sprintf("%s %.2f [%s/%s %s %s] ", renderScoreBar(score), score, source, kind, phase, risk)
			fmt.Fprintf(b, "%s%s\n", prefix, truncate(cmd, max(4, sidebarWidth-lipgloss.Width(prefix))))
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

// renderChat — modo de chat embebido: mismo `llm.Ask`/`llm.BuildContextSummary`
// que usa `exitone ask` en otra terminal, solo que acá el historial vive en
// memoria de la sesión de TUI (no se persiste — igual que `ask` hoy solo
// deja rastro en el debug log, no en una tabla dedicada).
func renderChat(b *strings.Builder, m *tuiModel) {
	b.WriteString(lipgloss.NewStyle().Bold(true).Render("ASISTENTE") + "\n\n")
	if len(m.chatHistory) == 0 {
		b.WriteString("(sin preguntas todavía — escribí y Enter)\n\n")
	}
	for _, turn := range m.chatHistory {
		fmt.Fprintf(b, "%s\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6")).Render("> "+turn.question))
		switch {
		case turn.err != nil:
			fmt.Fprintf(b, "%s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(turn.err.Error()))
		case turn.answer != "":
			b.WriteString(wrapText(turn.answer, sidebarWidth) + "\n")
		default:
			b.WriteString(renderChip(" pensando… ", lipgloss.Color("5")) + "\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(strings.Repeat("─", sidebarWidth)) + "\n")
	cursor := "_"
	if m.chatAsking {
		cursor = ""
	}
	fmt.Fprintf(b, "> %s%s\n", m.chatInput, cursor)
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
	if credentials, err := credentialstore.List(s, sessionID, false); err == nil {
		b.WriteString("\n" + lipgloss.NewStyle().Bold(true).Render("CREDENTIALS") + "\n")
		if len(credentials) == 0 {
			b.WriteString("(ninguna credencial registrada)\n")
		}
		for _, c := range credentials {
			fmt.Fprintf(b, "• %s %-12s %s\n", c.ID[:8], truncate(c.Identity, 12), c.Value)
		}
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

// stageStatusStyled colorea el estado de una etapa — verde lo suficiente,
// amarillo en progreso, gris sin empezar, rojo bloqueado, magenta reabierto.
func stageStatusStyled(status stage.Status) string {
	color := lipgloss.Color("8")
	switch status {
	case stage.Sufficient:
		color = lipgloss.Color("2")
	case stage.Active, stage.Partial:
		color = lipgloss.Color("3")
	case stage.Blocked:
		color = lipgloss.Color("1")
	case stage.Reopened:
		color = lipgloss.Color("5")
	}
	return lipgloss.NewStyle().Foreground(color).Render(string(status))
}

// renderScoreBar reemplaza el "%.2f" suelto de antes por una barra chica
// coloreada por umbral — mismo dato (score ya calculado por
// internal/strategy), solo más fácil de escanear de un vistazo.
func renderScoreBar(score float64) string {
	const width = 8
	filled := int(score * width)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("·", width-filled)
	color := lipgloss.Color("8")
	switch {
	case score >= 0.7:
		color = lipgloss.Color("2")
	case score >= 0.4:
		color = lipgloss.Color("3")
	}
	return lipgloss.NewStyle().Foreground(color).Render(bar)
}

// wrapText es un ajuste de línea simple por palabras — suficiente para
// prosa corta del LLM (guía/chat) dentro del ancho fijo del sidebar; no
// necesita manejar párrafos ni markdown.
func wrapText(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	var cur strings.Builder
	for _, w := range words {
		if cur.Len() > 0 && cur.Len()+1+len(w) > width {
			lines = append(lines, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(w)
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return strings.Join(lines, "\n")
}

// relTime formatea un timestamp RFC3339Nano como "hace Xs/Xm/Xh" — para la
// sección ACTIVIDAD, donde lo que importa es qué tan reciente es cada cosa,
// no el timestamp exacto (para eso está `exitone events`/`status`).
func relTime(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ts
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("hace %ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("hace %dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("hace %dh", int(d.Hours()))
	}
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
