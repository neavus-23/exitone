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
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"github.com/creack/pty"

	credentialstore "exitone/internal/credential"
	"exitone/internal/debuglog"
	"exitone/internal/llm"
	"exitone/internal/stage"
	"exitone/internal/store"
)

const (
	defaultSplitRatio   = 0.50
	minPaneContentWidth = 28
	scrollStep          = 3
	sidebarHeaderRows   = 2
	maxChatInputRunes   = 2000
	graphHeaderRows     = 3
	maxGraphFilterRunes = 128
	vaultHeaderRows     = 3
	maxVaultFilterRunes = 128
	vaultRevealDuration = 10 * time.Second
	vaultArmDuration    = 5 * time.Second
)

type ptyOutputMsg []byte
type ptyClosedMsg struct{}
type dashboardTickMsg time.Time
type vaultRevealExpiredMsg struct {
	credentialID string
	until        time.Time
}

// narrationMsg es la respuesta asíncrona de narrateCmd — candidateID identifica
// PARA QUÉ candidato se pidió, así Update() puede descartarla si para cuando
// llega el operador ya avanzó y el top real cambió (nunca mostrar una
// narración desincronizada del estado actual).
type narrationMsg struct {
	candidateID string
	text        string
	err         error
}

// chatAnswerMsg vuelve con un ID monotónico. El texto no sirve como clave:
// un operador puede repetir exactamente la misma pregunta o reintentarla.
type chatAnswerMsg struct {
	requestID uint64
	answer    string
	err       error
}

type chatTurn struct {
	id        uint64
	question  string
	answer    string
	err       error
	startedAt time.Time
	elapsed   time.Duration
}

type graphRow struct {
	entityID   string
	parentID   string
	entityType string
	value      string
	attrs      string
	relation   string
	confidence float64
	depth      int
	children   int
	incoming   int
	outgoing   int
	expanded   bool
	crossLink  bool
}

type vaultRowKind int

const (
	vaultIdentityRow vaultRowKind = iota
	vaultCredentialRow
)

type vaultRow struct {
	kind         vaultRowKind
	key          string
	parentKey    string
	identityID   string
	credentialID string
	identity     string
	service      string
	maskedValue  string
	status       string
	source       string
	provenance   string
	createdAt    string
	lastResult   string
	lastAttempt  string
	attempts     int
	successes    int
	failures     int
	children     int
	expanded     bool
}

type paneFocus int

const (
	focusTerminal paneFocus = iota
	focusSidebar
)

type dragTarget int

const (
	dragNone dragTarget = iota
	dragDivider
	dragTerminalScrollbar
	dragSidebarScrollbar
)

// sidebarMode — para no amontonar señales distintas, se cicla entre vistas
// enfocadas con F2 (idea tomada
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
	sideWidth  int
	sidebar    string
	splitRatio float64
	termScroll int // líneas desde el fondo; 0 sigue la salida en vivo
	sideScroll [sidebarModeCount]int
	focus      paneFocus
	dragging   dragTarget
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
	chatCursor  int // índice de runa, no byte
	chatAsking  bool
	chatNextID  uint64
	chatActive  uint64
	chatCancel  context.CancelFunc
	chatRecall  int
	chatDraft   string

	// Graph explorer: la selección se conserva por fila visible y el mapa de
	// colapso por entity ID. El filtro es local al pane y nunca modifica el
	// Investigation Model persistido.
	graphRows         []graphRow
	graphCursor       int
	graphCollapsed    map[string]bool
	graphFilter       string
	graphFilterCursor int
	graphFiltering    bool

	vaultRows         []vaultRow
	vaultCursor       int
	vaultCollapsed    map[string]bool
	vaultFilter       string
	vaultFilterCursor int
	vaultFiltering    bool
	vaultRevealID     string
	vaultRevealValue  string
	vaultRevealUntil  time.Time
	vaultRevealArmed  string
	vaultArmUntil     time.Time
	vaultError        string
}

// newTUIModel decide, ANTES de dibujar nada, si hace falta onboarding:
// fricción mínima real (parte del pedido de "máxima automatización") — 0
// workspaces abiertos va directo al formulario de "nuevo target" (no hay
// nada que listar), exactamente 1 se resume solo sin mostrar ninguna
// pantalla, y solo con 2+ aparece el selector.
func newTUIModel(s *store.Store) *tuiModel {
	m := &tuiModel{
		s: s, phase: phaseRunning, splitRatio: defaultSplitRatio, focus: focusTerminal,
		chatRecall: -1, graphCollapsed: make(map[string]bool), vaultCollapsed: make(map[string]bool),
	}
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
				if _, werr := m.ptmx.Write(buf[:n]); werr != nil {
					debuglog.LogError("tui_pty_echo_write", werr, nil)
				}
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

// askCmd es el equivalente para el chat embebido. Recibe el contexto ya
// cancelable y una cola corta de conversación para resolver follow-ups sin
// convertir el historial del chat en evidencia de la investigación.
func askCmd(ctx context.Context, s *store.Store, sessionID string, requestID uint64, conversation, question string) tea.Cmd {
	return func() tea.Msg {
		summary, err := llm.BuildContextSummary(s, sessionID)
		if err != nil {
			return chatAnswerMsg{requestID: requestID, err: err}
		}
		client := llm.New()
		answer, err := llm.AskWithConversation(ctx, client, s, sessionID, summary, conversation, question)
		return chatAnswerMsg{requestID: requestID, answer: answer, err: err}
	}
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// Siete columnas no pertenecen al contenido: dos bordes por pane,
		// una scrollbar por pane y el divisor arrastrable central.
		m.applySplit()
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
			if _, err := m.streamFile.Write(msg); err != nil {
				debuglog.LogError("tui_stream_file_write", err, nil)
			}
		}
		oldScrollback := m.terminalScrollbackLen()
		if _, err := m.emu.Write(msg); err != nil {
			debuglog.LogError("tui_emulator_write", err, nil)
		}
		// Si el operador está leyendo historia, mantener anclada la misma
		// región aunque entren líneas nuevas. En 0 se sigue el fondo.
		if m.termScroll > 0 {
			m.termScroll += m.terminalScrollbackLen() - oldScrollback
		}
		m.clampScrolls()
		return m, waitForPtyOutput(m.ptmx)

	case ptyClosedMsg:
		// El shell embebido terminó (exit/Ctrl+D) — cerramos la TUI con él,
		// igual que pasaría si cerraras la única terminal que tenías abierta.
		if m.streamFile != nil {
			m.streamFile.Close()
		}
		if m.chatCancel != nil {
			m.chatCancel()
		}
		m.clearVaultReveal()
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
			m.clampScrolls()

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
			m.clampScrolls()
		}
		return m, nil

	case chatAnswerMsg:
		// Una respuesta cancelada puede llegar después de que ya arrancó otro
		// request. El ID evita que cierre o sobrescriba el turno nuevo.
		if msg.requestID != m.chatActive {
			return m, nil
		}
		if m.chatCancel != nil {
			m.chatCancel()
			m.chatCancel = nil
		}
		for i := range m.chatHistory {
			if m.chatHistory[i].id == msg.requestID {
				m.chatHistory[i].elapsed = time.Since(m.chatHistory[i].startedAt)
				if msg.err != nil {
					m.chatHistory[i].err = msg.err
				} else {
					m.chatHistory[i].answer = strings.TrimSpace(msg.answer)
				}
				break
			}
		}
		m.chatAsking = false
		m.chatActive = 0
		m.sidebar = renderSidebar(m)
		m.scrollSidebarToEnd()
		return m, nil

	case vaultRevealExpiredMsg:
		if m.vaultRevealID == msg.credentialID && m.vaultRevealUntil.Equal(msg.until) {
			m.clearVaultReveal()
			m.sidebar = renderSidebar(m)
		}
		return m, nil

	case tea.MouseMsg:
		if m.phase == phaseRunning {
			m.handleMouse(tea.MouseEvent(msg))
		}
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
			if m.mode == sidebarVault {
				m.clearVaultReveal()
			}
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
			if m.mode == sidebarVault {
				m.clearVaultReveal()
			}
			m.mode = (m.mode + 1) % sidebarModeCount
			if m.mode == sidebarGraph || m.mode == sidebarVault || m.mode == sidebarChat {
				m.focus = focusSidebar
			} else {
				m.focus = focusTerminal
			}
			m.sidebar = renderSidebar(m)
			m.clampScrolls()
			return m, nil
		case "f3":
			if m.focus == focusTerminal {
				m.focus = focusSidebar
			} else {
				if m.mode == sidebarVault {
					m.clearVaultReveal()
				}
				m.focus = focusTerminal
			}
			return m, nil
		case "alt+left":
			m.setSideWidth(m.sideWidth + 2)
			return m, nil
		case "alt+right":
			m.setSideWidth(m.sideWidth - 2)
			return m, nil
		case "pgup", "shift+up":
			m.scrollFocused(max(1, m.sidebarViewportHeight()/2))
			return m, nil
		case "pgdown", "shift+down":
			m.scrollFocused(-max(1, m.sidebarViewportHeight()/2))
			return m, nil
		case "ctrl+home":
			m.scrollFocusedToStart()
			return m, nil
		case "ctrl+end":
			m.scrollFocusedToEnd()
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
			if m.chatCancel != nil {
				m.chatCancel()
			}
			m.clearVaultReveal()
			m.quitting = true
			return m, tea.Quit
		}

		// Foco en el chat: el teclado deja de ir a la pty y va al cuadro de
		// texto del asistente — único cambio real de enrutamiento de
		// teclado de todo este panel (ver handleChatKey).
		if m.mode == sidebarChat && m.focus == focusSidebar {
			return m.handleChatKey(msg)
		}
		if m.mode == sidebarGraph && m.focus == focusSidebar {
			return m.handleGraphKey(msg)
		}
		if m.mode == sidebarVault && m.focus == focusSidebar {
			return m.handleVaultKey(msg)
		}

		switch msg.String() {
		case "ctrl+@", "ctrl+space":
			// Autocomplete (sección I del plan): inserta el comando top-1 en
			// el buffer de línea del shell embebido — nunca lo ejecuta. Es
			// exactamente lo mismo que hacía el widget de zsh, pero ahora
			// escribiendo directo al PTY en vez de manipular BUFFER de zle.
			if suggestion := topSuggestion(m.s); suggestion != "" && m.ptmx != nil {
				if _, err := m.ptmx.Write([]byte(suggestion)); err != nil {
					debuglog.LogError("tui_pty_write_suggestion", err, nil)
				}
			}
			return m, nil
		default:
			if m.ptmx != nil {
				if _, err := m.ptmx.Write(keyMsgToBytes(msg)); err != nil {
					debuglog.LogError("tui_pty_write_key", err, nil)
				}
			}
			return m, nil
		}
	}
	return m, nil
}

// handleChatKey ofrece edición de línea familiar para un operador de
// terminal. El historial y los requests viven solo en memoria; ninguna
// tecla de chat llega accidentalmente al PTY.
func (m *tuiModel) handleChatKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Mantiene el chat visible: Esc solo devuelve el teclado a la terminal.
		m.focus = focusTerminal
		return m, nil
	case "enter", "ctrl+enter":
		return m.submitChatQuestion(strings.TrimSpace(m.chatInput))
	case "ctrl+c":
		if m.chatAsking {
			m.cancelChatRequest()
		} else {
			m.setChatInput("")
		}
		m.sidebar = renderSidebar(m)
		return m, nil
	case "ctrl+r":
		if m.chatAsking {
			return m, nil
		}
		for i := len(m.chatHistory) - 1; i >= 0; i-- {
			if m.chatHistory[i].err != nil {
				return m.submitChatQuestion(m.chatHistory[i].question)
			}
		}
		return m, nil
	case "ctrl+l":
		if !m.chatAsking {
			m.chatHistory = nil
			m.sideScroll[sidebarChat] = 0
			m.sidebar = renderSidebar(m)
		}
		return m, nil
	case "ctrl+u":
		m.setChatInput("")
		m.sidebar = renderSidebar(m)
		return m, nil
	case "ctrl+w":
		m.deleteChatWord()
		m.sidebar = renderSidebar(m)
		return m, nil
	case "left":
		m.chatCursor = max(0, m.chatCursor-1)
		return m, nil
	case "right":
		m.chatCursor = min(len([]rune(m.chatInput)), m.chatCursor+1)
		return m, nil
	case "home", "ctrl+a":
		m.chatCursor = 0
		return m, nil
	case "end", "ctrl+e":
		m.chatCursor = len([]rune(m.chatInput))
		return m, nil
	case "up":
		m.recallChatQuestion(-1)
		m.sidebar = renderSidebar(m)
		return m, nil
	case "down":
		m.recallChatQuestion(1)
		m.sidebar = renderSidebar(m)
		return m, nil
	case "backspace":
		runes := []rune(m.chatInput)
		if m.chatCursor > 0 && m.chatCursor <= len(runes) {
			runes = append(runes[:m.chatCursor-1], runes[m.chatCursor:]...)
			m.chatCursor--
			m.chatInput = string(runes)
		}
		m.resetChatRecall()
		m.sidebar = renderSidebar(m)
		return m, nil
	case "delete":
		runes := []rune(m.chatInput)
		if m.chatCursor >= 0 && m.chatCursor < len(runes) {
			runes = append(runes[:m.chatCursor], runes[m.chatCursor+1:]...)
			m.chatInput = string(runes)
		}
		m.resetChatRecall()
		m.sidebar = renderSidebar(m)
		return m, nil
	default:
		if len(msg.Runes) > 0 {
			runes := []rune(m.chatInput)
			cursor := clamp(m.chatCursor, 0, len(runes))
			room := max(0, maxChatInputRunes-len(runes))
			insert := msg.Runes[:min(len(msg.Runes), room)]
			updated := make([]rune, 0, len(runes)+len(insert))
			updated = append(updated, runes[:cursor]...)
			updated = append(updated, insert...)
			updated = append(updated, runes[cursor:]...)
			m.chatInput = string(updated)
			m.chatCursor = cursor + len(insert)
			m.resetChatRecall()
			m.sidebar = renderSidebar(m)
		}
		return m, nil
	}
}

func (m *tuiModel) submitChatQuestion(question string) (tea.Model, tea.Cmd) {
	if question == "" || m.chatAsking {
		return m, nil
	}
	m.chatNextID++
	id := m.chatNextID
	started := time.Now()
	sessionID, ok := currentSessionID(m.s)
	if !ok {
		m.chatHistory = append(m.chatHistory, chatTurn{
			id: id, question: question, err: fmt.Errorf("sin sesión activa"), startedAt: started,
		})
		m.setChatInput("")
		m.sidebar = renderSidebar(m)
		m.scrollSidebarToEnd()
		return m, nil
	}

	conversation := recentChatContext(m.chatHistory, 3, 2400)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	m.chatCancel = cancel
	m.chatActive = id
	m.chatAsking = true
	m.chatHistory = append(m.chatHistory, chatTurn{id: id, question: question, startedAt: started})
	m.setChatInput("")
	m.sidebar = renderSidebar(m)
	m.scrollSidebarToEnd()
	return m, askCmd(ctx, m.s, sessionID, id, conversation, question)
}

func (m *tuiModel) cancelChatRequest() {
	if !m.chatAsking {
		return
	}
	if m.chatCancel != nil {
		m.chatCancel()
	}
	for i := range m.chatHistory {
		if m.chatHistory[i].id == m.chatActive {
			m.chatHistory[i].err = fmt.Errorf("consulta cancelada")
			m.chatHistory[i].elapsed = time.Since(m.chatHistory[i].startedAt)
			break
		}
	}
	m.chatCancel = nil
	m.chatActive = 0
	m.chatAsking = false
}

func (m *tuiModel) setChatInput(value string) {
	runes := []rune(value)
	if len(runes) > maxChatInputRunes {
		runes = runes[:maxChatInputRunes]
	}
	m.chatInput = string(runes)
	m.chatCursor = len(runes)
	m.resetChatRecall()
}

func (m *tuiModel) resetChatRecall() {
	m.chatRecall = -1
	m.chatDraft = ""
}

func (m *tuiModel) recallChatQuestion(direction int) {
	if len(m.chatHistory) == 0 {
		return
	}
	if m.chatRecall < 0 {
		if direction > 0 {
			return
		}
		m.chatDraft = m.chatInput
		m.chatRecall = len(m.chatHistory) - 1
	} else {
		m.chatRecall += direction
	}
	if m.chatRecall < 0 {
		m.chatRecall = 0
	}
	if m.chatRecall >= len(m.chatHistory) {
		m.chatRecall = -1
		m.chatInput = m.chatDraft
		m.chatDraft = ""
		m.chatCursor = len([]rune(m.chatInput))
		return
	}
	m.chatInput = m.chatHistory[m.chatRecall].question
	m.chatCursor = len([]rune(m.chatInput))
}

func (m *tuiModel) deleteChatWord() {
	runes := []rune(m.chatInput)
	cursor := clamp(m.chatCursor, 0, len(runes))
	start := cursor
	for start > 0 && runes[start-1] == ' ' {
		start--
	}
	for start > 0 && runes[start-1] != ' ' {
		start--
	}
	m.chatInput = string(append(runes[:start], runes[cursor:]...))
	m.chatCursor = start
	m.resetChatRecall()
}

func recentChatContext(history []chatTurn, maxTurns, maxChars int) string {
	if maxTurns < 1 || maxChars < 1 {
		return ""
	}
	var turns []string
	for i := len(history) - 1; i >= 0 && len(turns) < maxTurns; i-- {
		if history[i].answer == "" || history[i].err != nil {
			continue
		}
		turns = append([]string{fmt.Sprintf("OPERADOR: %s\nEXITONE: %s", history[i].question, history[i].answer)}, turns...)
	}
	context := strings.Join(turns, "\n\n")
	runes := []rune(context)
	if len(runes) > maxChars {
		context = "…" + string(runes[len(runes)-maxChars+1:])
	}
	return context
}

func (m *tuiModel) handleGraphKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.graphFiltering {
		switch msg.String() {
		case "esc":
			m.graphFiltering = false
		case "enter":
			m.graphFiltering = false
		case "ctrl+u":
			m.graphFilter = ""
			m.graphFilterCursor = 0
		case "left":
			m.graphFilterCursor = max(0, m.graphFilterCursor-1)
		case "right":
			m.graphFilterCursor = min(len([]rune(m.graphFilter)), m.graphFilterCursor+1)
		case "home", "ctrl+a":
			m.graphFilterCursor = 0
		case "end", "ctrl+e":
			m.graphFilterCursor = len([]rune(m.graphFilter))
		case "backspace":
			runes := []rune(m.graphFilter)
			if m.graphFilterCursor > 0 && m.graphFilterCursor <= len(runes) {
				runes = append(runes[:m.graphFilterCursor-1], runes[m.graphFilterCursor:]...)
				m.graphFilterCursor--
				m.graphFilter = string(runes)
			}
		case "delete":
			runes := []rune(m.graphFilter)
			if m.graphFilterCursor >= 0 && m.graphFilterCursor < len(runes) {
				runes = append(runes[:m.graphFilterCursor], runes[m.graphFilterCursor+1:]...)
				m.graphFilter = string(runes)
			}
		default:
			if len(msg.Runes) > 0 {
				runes := []rune(m.graphFilter)
				room := max(0, maxGraphFilterRunes-len(runes))
				insert := msg.Runes[:min(room, len(msg.Runes))]
				cursor := clamp(m.graphFilterCursor, 0, len(runes))
				updated := make([]rune, 0, len(runes)+len(insert))
				updated = append(updated, runes[:cursor]...)
				updated = append(updated, insert...)
				updated = append(updated, runes[cursor:]...)
				m.graphFilter = string(updated)
				m.graphFilterCursor = cursor + len(insert)
			}
		}
		m.refreshGraph(true)
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.focus = focusTerminal
		return m, nil
	case "/":
		m.graphFiltering = true
		m.graphFilterCursor = len([]rune(m.graphFilter))
		return m, nil
	case "c":
		m.graphFilter = ""
		m.graphFilterCursor = 0
		m.refreshGraph(true)
	case "r":
		m.graphFilter = ""
		m.graphFilterCursor = 0
		m.graphCollapsed = make(map[string]bool)
		m.refreshGraph(true)
	case "up", "k":
		m.graphCursor = max(0, m.graphCursor-1)
		m.ensureGraphCursorVisible()
		m.sidebar = renderSidebar(m)
	case "down", "j":
		m.graphCursor = min(max(0, len(m.graphRows)-1), m.graphCursor+1)
		m.ensureGraphCursorVisible()
		m.sidebar = renderSidebar(m)
	case "home", "g":
		m.graphCursor = 0
		m.ensureGraphCursorVisible()
		m.sidebar = renderSidebar(m)
	case "end", "G":
		m.graphCursor = max(0, len(m.graphRows)-1)
		m.ensureGraphCursorVisible()
		m.sidebar = renderSidebar(m)
	case "left", "h":
		if row, ok := m.selectedGraphRow(); ok {
			if row.children > 0 && row.expanded {
				m.graphCollapsed[row.entityID] = true
				m.refreshGraph(true)
			} else if row.parentID != "" {
				m.selectGraphEntity(row.parentID)
			}
		}
	case "right", "l":
		if row, ok := m.selectedGraphRow(); ok && row.children > 0 && !row.expanded {
			delete(m.graphCollapsed, row.entityID)
			m.refreshGraph(true)
		}
	case "enter", "space":
		if row, ok := m.selectedGraphRow(); ok && row.children > 0 {
			if row.expanded {
				m.graphCollapsed[row.entityID] = true
			} else {
				delete(m.graphCollapsed, row.entityID)
			}
			m.refreshGraph(true)
		}
	}
	return m, nil
}

func (m *tuiModel) selectedGraphRow() (graphRow, bool) {
	if m.graphCursor < 0 || m.graphCursor >= len(m.graphRows) {
		return graphRow{}, false
	}
	return m.graphRows[m.graphCursor], true
}

func (m *tuiModel) selectGraphEntity(entityID string) {
	for i := range m.graphRows {
		if m.graphRows[i].entityID == entityID && !m.graphRows[i].crossLink {
			m.graphCursor = i
			m.ensureGraphCursorVisible()
			m.sidebar = renderSidebar(m)
			return
		}
	}
}

func (m *tuiModel) refreshGraph(reveal bool) {
	m.sidebar = renderSidebar(m)
	if reveal {
		m.ensureGraphCursorVisible()
	}
}

func (m *tuiModel) ensureGraphCursorVisible() {
	if len(m.graphRows) == 0 {
		m.sideScroll[sidebarGraph] = 0
		return
	}
	m.graphCursor = clamp(m.graphCursor, 0, len(m.graphRows)-1)
	docLine := graphHeaderRows + m.graphCursor
	height := m.sidebarViewportHeight()
	top := m.sideScroll[sidebarGraph]
	if docLine < top {
		top = docLine
	} else if height > 0 && docLine >= top+height {
		top = docLine - height + 1
	}
	m.sideScroll[sidebarGraph] = max(0, top)
}

func (m *tuiModel) handleVaultKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.expireVaultReveal()
	if m.vaultFiltering {
		switch msg.String() {
		case "esc", "enter":
			m.vaultFiltering = false
		case "ctrl+u":
			m.vaultFilter = ""
			m.vaultFilterCursor = 0
		case "left":
			m.vaultFilterCursor = max(0, m.vaultFilterCursor-1)
		case "right":
			m.vaultFilterCursor = min(len([]rune(m.vaultFilter)), m.vaultFilterCursor+1)
		case "home", "ctrl+a":
			m.vaultFilterCursor = 0
		case "end", "ctrl+e":
			m.vaultFilterCursor = len([]rune(m.vaultFilter))
		case "backspace":
			runes := []rune(m.vaultFilter)
			if m.vaultFilterCursor > 0 && m.vaultFilterCursor <= len(runes) {
				runes = append(runes[:m.vaultFilterCursor-1], runes[m.vaultFilterCursor:]...)
				m.vaultFilterCursor--
				m.vaultFilter = string(runes)
			}
		case "delete":
			runes := []rune(m.vaultFilter)
			if m.vaultFilterCursor >= 0 && m.vaultFilterCursor < len(runes) {
				runes = append(runes[:m.vaultFilterCursor], runes[m.vaultFilterCursor+1:]...)
				m.vaultFilter = string(runes)
			}
		default:
			if len(msg.Runes) > 0 {
				runes := []rune(m.vaultFilter)
				room := max(0, maxVaultFilterRunes-len(runes))
				insert := msg.Runes[:min(room, len(msg.Runes))]
				cursor := clamp(m.vaultFilterCursor, 0, len(runes))
				updated := make([]rune, 0, len(runes)+len(insert))
				updated = append(updated, runes[:cursor]...)
				updated = append(updated, insert...)
				updated = append(updated, runes[cursor:]...)
				m.vaultFilter = string(updated)
				m.vaultFilterCursor = cursor + len(insert)
			}
		}
		m.clearVaultReveal()
		m.refreshVault(true)
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.clearVaultReveal()
		m.focus = focusTerminal
	case "/":
		m.clearVaultReveal()
		m.vaultFiltering = true
		m.vaultFilterCursor = len([]rune(m.vaultFilter))
	case "c":
		m.clearVaultReveal()
		m.vaultFilter = ""
		m.vaultFilterCursor = 0
		m.refreshVault(true)
	case "r":
		m.clearVaultReveal()
		m.vaultFilter = ""
		m.vaultFilterCursor = 0
		m.vaultCollapsed = make(map[string]bool)
		m.vaultError = ""
		m.refreshVault(true)
	case "up", "k":
		m.moveVaultCursor(-1)
	case "down", "j":
		m.moveVaultCursor(1)
	case "home", "g":
		m.clearVaultReveal()
		m.vaultCursor = 0
		m.ensureVaultCursorVisible()
		m.sidebar = renderSidebar(m)
	case "end", "G":
		m.clearVaultReveal()
		m.vaultCursor = max(0, len(m.vaultRows)-1)
		m.ensureVaultCursorVisible()
		m.sidebar = renderSidebar(m)
	case "left", "h":
		if row, ok := m.selectedVaultRow(); ok {
			m.clearVaultReveal()
			if row.kind == vaultIdentityRow && row.children > 0 && row.expanded {
				m.vaultCollapsed[row.key] = true
				m.refreshVault(true)
			} else if row.parentKey != "" {
				m.selectVaultKey(row.parentKey)
			}
		}
	case "right", "l":
		if row, ok := m.selectedVaultRow(); ok && row.kind == vaultIdentityRow && row.children > 0 && !row.expanded {
			m.clearVaultReveal()
			delete(m.vaultCollapsed, row.key)
			m.refreshVault(true)
		}
	case "enter", "space":
		if row, ok := m.selectedVaultRow(); ok && row.kind == vaultIdentityRow && row.children > 0 {
			m.clearVaultReveal()
			if row.expanded {
				m.vaultCollapsed[row.key] = true
			} else {
				delete(m.vaultCollapsed, row.key)
			}
			m.refreshVault(true)
		}
	case "v":
		cmd := m.toggleVaultReveal()
		m.sidebar = renderSidebar(m)
		return m, cmd
	}
	return m, nil
}

func (m *tuiModel) moveVaultCursor(delta int) {
	if len(m.vaultRows) == 0 {
		return
	}
	m.clearVaultReveal()
	m.vaultCursor = clamp(m.vaultCursor+delta, 0, len(m.vaultRows)-1)
	m.ensureVaultCursorVisible()
	m.sidebar = renderSidebar(m)
}

func (m *tuiModel) selectedVaultRow() (vaultRow, bool) {
	if m.vaultCursor < 0 || m.vaultCursor >= len(m.vaultRows) {
		return vaultRow{}, false
	}
	return m.vaultRows[m.vaultCursor], true
}

func (m *tuiModel) selectVaultKey(key string) {
	for i := range m.vaultRows {
		if m.vaultRows[i].key == key {
			m.vaultCursor = i
			m.ensureVaultCursorVisible()
			m.sidebar = renderSidebar(m)
			return
		}
	}
}

func (m *tuiModel) refreshVault(reveal bool) {
	m.sidebar = renderSidebar(m)
	if reveal {
		m.ensureVaultCursorVisible()
	}
}

func (m *tuiModel) ensureVaultCursorVisible() {
	if len(m.vaultRows) == 0 {
		m.sideScroll[sidebarVault] = 0
		return
	}
	m.vaultCursor = clamp(m.vaultCursor, 0, len(m.vaultRows)-1)
	docLine := vaultHeaderRows + m.vaultCursor
	height := m.sidebarViewportHeight()
	top := m.sideScroll[sidebarVault]
	if docLine < top {
		top = docLine
	} else if height > 0 && docLine >= top+height {
		top = docLine - height + 1
	}
	m.sideScroll[sidebarVault] = max(0, top)
}

func (m *tuiModel) toggleVaultReveal() tea.Cmd {
	row, ok := m.selectedVaultRow()
	if !ok || row.kind != vaultCredentialRow {
		return nil
	}
	now := time.Now()
	if m.vaultRevealID == row.credentialID && now.Before(m.vaultRevealUntil) {
		m.clearVaultReveal()
		return nil
	}
	if m.vaultRevealArmed != row.credentialID || now.After(m.vaultArmUntil) {
		m.clearVaultReveal()
		m.vaultRevealArmed = row.credentialID
		m.vaultArmUntil = now.Add(vaultArmDuration)
		return nil
	}
	sessionID, ok := currentSessionID(m.s)
	if !ok {
		m.clearVaultReveal()
		m.vaultError = "no active session"
		return nil
	}
	value, err := credentialstore.Reveal(m.s, sessionID, row.credentialID)
	if err != nil {
		m.clearVaultReveal()
		m.vaultError = err.Error()
		return nil
	}
	m.vaultRevealArmed = ""
	m.vaultArmUntil = time.Time{}
	m.vaultRevealID = row.credentialID
	m.vaultRevealValue = value
	m.vaultRevealUntil = now.Add(vaultRevealDuration)
	m.vaultError = ""
	credentialID := row.credentialID
	until := m.vaultRevealUntil
	return tea.Tick(vaultRevealDuration, func(time.Time) tea.Msg {
		return vaultRevealExpiredMsg{credentialID: credentialID, until: until}
	})
}

func (m *tuiModel) expireVaultReveal() {
	now := time.Now()
	if m.vaultRevealID != "" && !m.vaultRevealUntil.IsZero() && !now.Before(m.vaultRevealUntil) {
		m.clearVaultReveal()
	}
	if m.vaultRevealArmed != "" && !m.vaultArmUntil.IsZero() && !now.Before(m.vaultArmUntil) {
		m.vaultRevealArmed = ""
		m.vaultArmUntil = time.Time{}
	}
}

func (m *tuiModel) clearVaultReveal() {
	m.vaultRevealID = ""
	m.vaultRevealValue = ""
	m.vaultRevealUntil = time.Time{}
	m.vaultRevealArmed = ""
	m.vaultArmUntil = time.Time{}
	m.vaultError = ""
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

// enterPreparing dispara la MISMA narración que después se ve en WHY / RISK (ver
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

	termLines, termTop, termTotal := m.terminalViewport()
	termContent := renderViewportLines(termLines, m.termWidth, m.termHeight)
	termBar := renderScrollbar(termTotal, m.termHeight, termTop, m.focus == focusTerminal)
	termInner := lipgloss.JoinHorizontal(lipgloss.Top, termContent, termBar)
	termTitle := "OPERATOR"
	termAccent := lipgloss.Color("8")
	if m.focus == focusTerminal {
		termTitle = "▶ OPERATOR"
		termAccent = lipgloss.Color("6")
	}
	termBox := renderTitledBox(termTitle, m.termWidth+1, m.termHeight, termInner, termAccent)

	var target string
	sessionID, hasSession := currentSessionID(m.s)
	if hasSession {
		m.s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&target)
	}
	sidebarTitle := "EXITONE"
	if target != "" {
		sidebarTitle = "EXITONE — " + target
	}
	// El foco nunca depende solo del color: además del borde de acento, el
	// pane activo lleva un marcador ▶ en el título.
	sidebarAccent := lipgloss.Color("8")
	if m.focus == focusSidebar {
		sidebarAccent = lipgloss.Color("6")
		sidebarTitle = "▶ " + sidebarTitle
	}
	sideLines := m.sidebarDocument()
	sideHeight := m.sidebarViewportHeight()
	sideTop := clamp(m.sideScroll[m.mode], 0, max(0, len(sideLines)-sideHeight))
	m.sideScroll[m.mode] = sideTop
	sideHeader := renderViewportLines([]string{renderModeTabs(m.mode, m.sideWidth), ""}, m.sideWidth, sidebarHeaderRows)
	sideBody := renderViewportLines(sideLines[sideTop:], m.sideWidth, sideHeight)
	sideContent := sideHeader
	if sideHeight > 0 {
		sideContent += "\n" + sideBody
	}
	footerRows := m.sidebarFooterRows()
	if footerRows > 0 {
		sideContent += "\n" + renderSidebarFooter(m, m.sideWidth)
	}
	sideBar := renderViewportLines(nil, 1, sidebarHeaderRows)
	if sideHeight > 0 {
		sideBar += "\n" + renderScrollbar(len(sideLines), sideHeight, sideTop, m.focus == focusSidebar)
	}
	if footerRows > 0 {
		sideBar += "\n" + renderViewportLines(nil, 1, footerRows)
	}
	sideInner := lipgloss.JoinHorizontal(lipgloss.Top, sideContent, sideBar)
	sidebarBox := renderTitledBox(sidebarTitle, m.sideWidth+1, m.termHeight, sideInner, sidebarAccent)

	dividerGlyph := "│"
	dividerColor := lipgloss.Color("8")
	if m.dragging == dragDivider {
		dividerGlyph = "┃"
		dividerColor = lipgloss.Color("6")
	}
	divider := lipgloss.NewStyle().Foreground(dividerColor).Render(
		strings.TrimSuffix(strings.Repeat(dividerGlyph+"\n", m.termHeight+2), "\n"),
	)
	panes := lipgloss.JoinHorizontal(lipgloss.Top, termBox, divider, sidebarBox)

	right := "F2 vista · F3 foco · Alt+←/→ ancho · Pg↑/Pg↓ scroll · F1 ayuda"
	if m.paused {
		right = renderChip(" PAUSADO ", lipgloss.Color("3")) + " " + right
	}
	focusLabel := "TERM"
	if m.focus == focusSidebar {
		focusLabel = "PANEL"
	}
	left := fmt.Sprintf(" %s · %s · %s · %s ", orDash(target), m.mode.label(), focusLabel, time.Now().Format("15:04:05"))
	statusBar := renderStatusBar(m.width, left, right)

	view := panes + "\n" + statusBar

	if m.showHelp {
		return renderHelpOverlay(m.width, m.height)
	}
	return view
}

func (m *tuiModel) applySplit() {
	usable := max(2, m.width-7)
	minWidth := minPaneContentWidth
	if usable < minPaneContentWidth*2 {
		minWidth = max(1, usable/3)
	}
	m.sideWidth = clamp(int(float64(usable)*m.splitRatio), minWidth, max(minWidth, usable-minWidth))
	m.termWidth = usable - m.sideWidth
}

func (m *tuiModel) setSideWidth(width int) {
	usable := max(2, m.width-7)
	minWidth := minPaneContentWidth
	if usable < minPaneContentWidth*2 {
		minWidth = max(1, usable/3)
	}
	width = clamp(width, minWidth, max(minWidth, usable-minWidth))
	if width == m.sideWidth {
		return
	}
	m.sideWidth = width
	m.termWidth = usable - width
	m.splitRatio = float64(width) / float64(usable)
	m.sidebar = renderSidebar(m)
	if m.emu != nil && m.ptmx != nil {
		m.emu.Resize(m.termWidth, m.termHeight)
		_ = pty.Setsize(m.ptmx, &pty.Winsize{Rows: uint16(m.termHeight), Cols: uint16(m.termWidth)})
	}
	m.clampScrolls()
}

func (m *tuiModel) sidebarViewportHeight() int {
	return max(0, m.termHeight-sidebarHeaderRows-m.sidebarFooterRows())
}

func (m *tuiModel) sidebarFooterRows() int {
	switch m.mode {
	case sidebarGraph:
		return 4
	case sidebarVault:
		return 5
	case sidebarChat:
		return 3
	}
	return 0
}

func renderSidebarFooter(m *tuiModel, width int) string {
	switch m.mode {
	case sidebarGraph:
		return renderGraphFooter(m, width)
	case sidebarVault:
		return renderVaultFooter(m, width)
	case sidebarChat:
		return renderChatComposer(m, width)
	default:
		return renderViewportLines(nil, width, m.sidebarFooterRows())
	}
}

func (m *tuiModel) handleMouse(msg tea.MouseEvent) {
	dividerX := m.termWidth + 3
	termBarX := m.termWidth + 1
	sideBarX := m.width - 2

	if msg.IsWheel() {
		delta := scrollStep
		if msg.Button == tea.MouseButtonWheelDown {
			delta = -scrollStep
		}
		if msg.X < dividerX {
			if m.mode == sidebarVault {
				m.clearVaultReveal()
			}
			m.focus = focusTerminal
			m.scrollTerminal(delta)
		} else if msg.X > dividerX {
			m.focus = focusSidebar
			m.scrollSidebar(-delta)
		}
		return
	}

	if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
		// Las pestañas parecen controles, así que también deben comportarse
		// como tales con mouse. El teclado conserva F2 como ruta primaria.
		if msg.Y == 1 {
			if mode, ok := sidebarModeAtX(msg.X-(dividerX+2), m.sideWidth); ok {
				if m.mode == sidebarVault && mode != sidebarVault {
					m.clearVaultReveal()
				}
				m.mode = mode
				m.focus = focusSidebar
				m.sidebar = renderSidebar(m)
				m.clampScrolls()
				return
			}
		}
		switch msg.X {
		case dividerX:
			m.dragging = dragDivider
		case termBarX:
			if m.mode == sidebarVault {
				m.clearVaultReveal()
			}
			m.focus = focusTerminal
			m.dragging = dragTerminalScrollbar
			m.dragTerminalScrollbar(msg.Y - 1)
		case sideBarX:
			m.focus = focusSidebar
			bodyY := msg.Y - 1 - sidebarHeaderRows
			if bodyY >= 0 && bodyY < m.sidebarViewportHeight() {
				m.dragging = dragSidebarScrollbar
				m.dragSidebarScrollbar(bodyY)
			}
		default:
			if msg.X < dividerX {
				if m.mode == sidebarVault {
					m.clearVaultReveal()
				}
				m.focus = focusTerminal
			} else {
				m.focus = focusSidebar
				if m.mode == sidebarGraph {
					bodyY := msg.Y - 1 - sidebarHeaderRows
					if bodyY >= 0 && bodyY < m.sidebarViewportHeight() {
						docLine := m.sideScroll[sidebarGraph] + bodyY
						rowIndex := docLine - graphHeaderRows
						if rowIndex >= 0 && rowIndex < len(m.graphRows) {
							m.graphCursor = rowIndex
							m.sidebar = renderSidebar(m)
						}
					}
				}
				if m.mode == sidebarVault {
					bodyY := msg.Y - 1 - sidebarHeaderRows
					if bodyY >= 0 && bodyY < m.sidebarViewportHeight() {
						docLine := m.sideScroll[sidebarVault] + bodyY
						rowIndex := docLine - vaultHeaderRows
						if rowIndex >= 0 && rowIndex < len(m.vaultRows) {
							if rowIndex != m.vaultCursor {
								m.clearVaultReveal()
							}
							m.vaultCursor = rowIndex
							m.sidebar = renderSidebar(m)
						}
					}
				}
			}
		}
		return
	}

	if msg.Action == tea.MouseActionMotion {
		switch m.dragging {
		case dragDivider:
			m.setSideWidth(m.width - msg.X - 4)
		case dragTerminalScrollbar:
			m.dragTerminalScrollbar(msg.Y - 1)
		case dragSidebarScrollbar:
			m.dragSidebarScrollbar(msg.Y - 1 - sidebarHeaderRows)
		}
		return
	}

	if msg.Action == tea.MouseActionRelease {
		m.dragging = dragNone
	}
}

func (m *tuiModel) scrollFocused(delta int) {
	if m.focus == focusTerminal {
		m.scrollTerminal(delta)
		return
	}
	m.scrollSidebar(-delta)
}

func (m *tuiModel) scrollFocusedToStart() {
	if m.focus == focusTerminal {
		m.termScroll = m.terminalScrollbackLen()
		return
	}
	m.sideScroll[m.mode] = 0
}

func (m *tuiModel) scrollFocusedToEnd() {
	if m.focus == focusTerminal {
		m.termScroll = 0
		return
	}
	m.scrollSidebarToEnd()
}

func (m *tuiModel) scrollTerminal(delta int) {
	m.termScroll = clamp(m.termScroll+delta, 0, m.terminalScrollbackLen())
}

func (m *tuiModel) scrollSidebar(delta int) {
	maxTop := max(0, len(m.sidebarDocument())-m.sidebarViewportHeight())
	m.sideScroll[m.mode] = clamp(m.sideScroll[m.mode]+delta, 0, maxTop)
}

func (m *tuiModel) scrollSidebarToEnd() {
	m.sideScroll[m.mode] = max(0, len(m.sidebarDocument())-m.sidebarViewportHeight())
}

func (m *tuiModel) dragTerminalScrollbar(y int) {
	maxTop := m.terminalScrollbackLen()
	top := scrollTopFromMouse(y, m.termHeight, maxTop)
	m.termScroll = maxTop - top
}

func (m *tuiModel) dragSidebarScrollbar(y int) {
	maxTop := max(0, len(m.sidebarDocument())-m.sidebarViewportHeight())
	m.sideScroll[m.mode] = scrollTopFromMouse(y, m.sidebarViewportHeight(), maxTop)
}

func (m *tuiModel) clampScrolls() {
	m.termScroll = clamp(m.termScroll, 0, m.terminalScrollbackLen())
	maxTop := max(0, len(m.sidebarDocument())-m.sidebarViewportHeight())
	m.sideScroll[m.mode] = clamp(m.sideScroll[m.mode], 0, maxTop)
}

func (m *tuiModel) terminalScrollbackLen() int {
	if m.emu == nil || m.emu.IsAltScreen() {
		return 0
	}
	return m.emu.ScrollbackLen()
}

// terminalViewport materializa solo las filas visibles. El scrollback puede
// contener 10k líneas; reconstruirlo entero en cada keypress haría lenta la
// terminal precisamente cuando más output produce una herramienta.
func (m *tuiModel) terminalViewport() ([]string, int, int) {
	if m.emu == nil {
		return nil, 0, m.termHeight
	}
	rendered := m.emu.Render()
	if m.termScroll == 0 {
		cursor := m.emu.CursorPosition()
		rendered = overlayCursor(rendered, cursor.X, cursor.Y)
	}
	screen := strings.Split(rendered, "\n")
	if len(screen) > m.termHeight {
		screen = screen[:m.termHeight]
	}
	for len(screen) < m.termHeight {
		screen = append(screen, "")
	}

	sbLen := m.terminalScrollbackLen()
	top := clamp(sbLen-m.termScroll, 0, sbLen)
	visible := make([]string, 0, m.termHeight)
	for docIndex := top; docIndex < top+m.termHeight; docIndex++ {
		if docIndex >= sbLen {
			visible = append(visible, screen[docIndex-sbLen])
			continue
		}
		line := m.emu.Scrollback().Line(docIndex)
		var b strings.Builder
		for i := range line {
			cell := &line[i]
			if cell.Width == 0 {
				continue
			}
			content := cell.Content
			if content == "" {
				content = " "
			}
			b.WriteString(cell.Style.Styled(content))
		}
		visible = append(visible, b.String())
	}
	return visible, top, sbLen + m.termHeight
}

func (m *tuiModel) sidebarDocument() []string {
	if m.sideWidth < 1 {
		return nil
	}
	return strings.Split(ansi.Wrap(m.sidebar, m.sideWidth, "/_:.'"), "\n")
}

func renderViewportLines(lines []string, width, height int) string {
	if height <= 0 {
		return ""
	}
	out := make([]string, height)
	for i := range height {
		line := ""
		if i < len(lines) {
			line = ansi.Cut(lines[i], 0, width)
		}
		out[i] = lipgloss.NewStyle().Width(width).MaxWidth(width).Render(line)
	}
	return strings.Join(out, "\n")
}

func renderScrollbar(total, height, top int, active bool) string {
	if height <= 0 {
		return ""
	}
	thumbSize, thumbTop := height, 0
	if total > height {
		thumbSize = max(1, height*height/total)
		thumbTop = clamp(top*(height-thumbSize)/(total-height), 0, height-thumbSize)
	}
	thumbColor := lipgloss.Color("7")
	if active {
		thumbColor = lipgloss.Color("6")
	}
	rows := make([]string, height)
	for i := range height {
		glyph := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render("░")
		if i >= thumbTop && i < thumbTop+thumbSize {
			glyph = lipgloss.NewStyle().Foreground(thumbColor).Render("█")
		}
		rows[i] = glyph
	}
	return strings.Join(rows, "\n")
}

func scrollTopFromMouse(y, height, maxTop int) int {
	if maxTop <= 0 || height <= 1 {
		return 0
	}
	y = clamp(y, 0, height-1)
	return y * maxTop / (height - 1)
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
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
	if lipgloss.Width(label) > width {
		label = ansi.Truncate(label, width, "")
	}
	dashes := width - 1 - lipgloss.Width(label)
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
func renderModeTabs(active sidebarMode, width int) string {
	labels := modeTabLabels(width)
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
	return ansi.Truncate(strings.Join(parts, ""), width, "")
}

func modeTabLabels(width int) []string {
	if width < 30 {
		return []string{"OVR", "GRF", "VLT", "CHAT"}
	}
	return []string{"Overview", "Graph", "Vault", "Chat"}
}

func sidebarModeAtX(x, width int) (sidebarMode, bool) {
	if x < 0 || x >= width {
		return sidebarOverview, false
	}
	offset := 0
	for i, label := range modeTabLabels(width) {
		tabWidth := lipgloss.Width(label) + 2 // Padding(0, 1) de renderModeTabs.
		if x >= offset && x < offset+tabWidth {
			return sidebarMode(i), true
		}
		offset += tabWidth
	}
	return sidebarOverview, false
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
		content = ansi.Truncate(content, width, "")
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
			"F3           alternar foco entre terminal y panel",
			"Alt+←/→      mover el divisor central (también puedes arrastrarlo)",
			"PgUp/PgDown  desplazar el pane enfocado; Ctrl+Home/End salta a los extremos",
			"Rueda        desplazar el pane bajo el puntero",
			"Esc          devolver el teclado a la terminal sin ocultar la vista actual",
			"Ctrl+P       pausar/reanudar el refresco del panel (para leer tranquilo)",
			"F1           esta ayuda — cualquier tecla la cierra",
			"Ctrl+Q       salir de ExitOne (el shell embebido se cierra con él)",
			"",
			"Graph: ↑/↓ o j/k selecciona · ←/→ o h/l pliega · Enter alterna",
			"       / filtra · c limpia filtro · r restablece · Esc vuelve al terminal",
			"Vault: ↑/↓ o j/k selecciona · ←/→ pliega · / filtra · r restablece",
			"       v + v revela solo la seleccionada por 10s; navegar la oculta",
			"Chat: Enter envía · ↑/↓ historial · Ctrl+C cancela · Ctrl+R reintenta",
			"      Ctrl+U limpia input · Ctrl+L limpia transcript · Ctrl+W borra palabra",
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
		renderAttackSurfaceGraph(&b, m, sessionID)
	case sidebarVault:
		renderVault(&b, m, sessionID)
	case sidebarChat:
		renderChat(&b, m)
	default:
		renderOverview(&b, m, sessionID)
	}

	return b.String()
}

func renderOverview(b *strings.Builder, m *tuiModel, sessionID string) {
	s := m.s
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	commandStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))

	// Jerarquía para un operador experto: acción primero, contexto mínimo,
	// después estado y cola. Nada de explicación introductoria de tooling.
	b.WriteString(heading.Render("NEXT") + "\n")
	var id, source, phase, risk, tool, cmd, explanation string
	var score float64
	topErr := s.DB.QueryRow(`
		SELECT id, source, phase_key, risk_level, tool,
		       command_template_rendered, explanation, score
		FROM candidate
		WHERE session_id = ? AND status = 'proposed'
		ORDER BY score DESC LIMIT 1`, sessionID,
	).Scan(&id, &source, &phase, &risk, &tool, &cmd, &explanation, &score)
	if topErr == nil {
		if cmd == "" {
			cmd = explanation
		}
		fmt.Fprintf(b, "%s %.2f  %s · %s/%s · %s\n", renderScoreBar(score), score, strings.ToUpper(tool), phase, risk, source)
		b.WriteString(commandStyle.Render("$ "+cmd) + "\n")
		b.WriteString(muted.Render("Ctrl+Space insert · exitone why "+firstN(id, 8)) + "\n")
	} else {
		b.WriteString(muted.Render("No pending candidate · ingest evidence") + "\n")
	}

	if m.narrationLoading || m.narration != "" {
		b.WriteString("\n" + heading.Render("WHY / RISK") + "\n")
		if m.narrationLoading {
			b.WriteString(renderChip(" razonando… ", lipgloss.Color("5")) + "\n")
		} else {
			b.WriteString(compactNarration(m.narration, m.sideWidth, 3) + "\n")
		}
	}

	b.WriteString("\n" + heading.Render("STATE") + "\n")
	if stages, err := stage.Estimate(s, sessionID); err == nil {
		for _, st := range stages {
			mark := "·"
			switch st.Status {
			case stage.Sufficient:
				mark = "✓"
			case stage.Active, stage.Partial:
				mark = "›"
			case stage.Blocked:
				mark = "!"
			case stage.Reopened:
				mark = "↻"
			}
			fmt.Fprintf(b, "%s %s · %s\n", mark, st.Name, stageStatusStyled(st.Status))
		}
	}

	b.WriteString("\n" + heading.Render("QUEUE") + "\n")
	rows, err := s.DB.Query(`
		SELECT phase_key, risk_level, command_template_rendered, explanation, score FROM candidate
		WHERE session_id = ? AND status = 'proposed' ORDER BY score DESC LIMIT 3 OFFSET 1`, sessionID)
	if err == nil {
		any := false
		for rows.Next() {
			any = true
			var phase, risk, cmd, explanation string
			var score float64
			rows.Scan(&phase, &risk, &cmd, &explanation, &score)
			if cmd == "" {
				cmd = explanation
			}
			fmt.Fprintf(b, "%s %.2f  %s/%s · %s\n", renderScoreBar(score), score, phase, risk, cmd)
		}
		rows.Close()
		if !any {
			b.WriteString(muted.Render("no additional candidates") + "\n")
		}
	}

	b.WriteString("\n" + heading.Render("OPEN PATHS") + "\n")
	orows, err := s.DB.Query(`
		SELECT op.path_key FROM objective_path op
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE mo.session_id = ? AND op.status = 'open'
		ORDER BY mo.created_at, op.created_at LIMIT 6`, sessionID)
	if err == nil {
		any := false
		for orows.Next() {
			any = true
			var path string
			orows.Scan(&path)
			b.WriteString("› " + path + "\n")
		}
		orows.Close()
		if !any {
			b.WriteString(muted.Render("none") + "\n")
		}
	}

	b.WriteString("\n" + heading.Render("LIVE") + "\n")
	var evTool, evAt string
	if err := s.DB.QueryRow(`
		SELECT e.tool_name, e.created_at FROM evidence e
		JOIN event ev ON ev.id = e.event_id
		WHERE ev.session_id = ? ORDER BY e.created_at DESC LIMIT 1`, sessionID).Scan(&evTool, &evAt); err == nil {
		fmt.Fprintf(b, "evidence %s · %s\n", evTool, relTime(evAt))
	} else {
		b.WriteString(muted.Render("no evidence yet") + "\n")
	}
	var jobStatus string
	if err := s.DB.QueryRow(`SELECT status FROM strategy_job WHERE session_id = ?`, sessionID).Scan(&jobStatus); err == nil {
		fmt.Fprintf(b, "strategy %s\n", jobStatus)
	}
}

// renderChat dibuja únicamente el transcript. El compositor queda fijo al
// pie del pane (renderChatComposer), así no desaparece cuando se consulta
// historial y su barra de scroll representa solo la conversación.
func renderChat(b *strings.Builder, m *tuiModel) {
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	b.WriteString(heading.Render("SESSION CHAT") + "  " + muted.Render("read-only · in-memory") + "\n")
	b.WriteString(muted.Render("Grounded in the current graph and evidence; never executes commands.") + "\n\n")
	if len(m.chatHistory) == 0 {
		b.WriteString(heading.Render("QUICK START") + "\n")
		b.WriteString("› ¿Qué falta por investigar?\n")
		b.WriteString("› ¿Qué evidencia respalda esta hipótesis?\n")
		b.WriteString("› ¿Qué relación existe entre host y servicio?\n")
		b.WriteString("\n" + muted.Render("Write below · Enter sends · ↑ recalls") + "\n")
	}
	for _, turn := range m.chatHistory {
		stamp := ""
		if !turn.startedAt.IsZero() {
			stamp = "  " + turn.startedAt.Format("15:04")
		}
		b.WriteString(heading.Render("YOU") + muted.Render(stamp) + "\n")
		b.WriteString(wrapText(turn.question, m.sideWidth) + "\n")
		switch {
		case turn.err != nil:
			b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1")).Render("ERROR") + "\n")
			b.WriteString(wrapText(compactChatError(turn.err), m.sideWidth) + "\n")
			b.WriteString(muted.Render("Ctrl+R retry") + "\n")
		case turn.answer != "":
			meta := "grounded"
			if turn.elapsed > 0 {
				meta += fmt.Sprintf(" · %.1fs", turn.elapsed.Seconds())
			}
			b.WriteString(heading.Render("EXITONE") + "  " + muted.Render(meta) + "\n")
			b.WriteString(renderChatAnswer(turn.answer) + "\n")
		default:
			elapsed := time.Since(turn.startedAt).Round(time.Second)
			b.WriteString(renderChip(" querying graph ", lipgloss.Color("5")) + muted.Render(" "+elapsed.String()) + "\n")
		}
		b.WriteString("\n")
	}
}

func renderChatComposer(m *tuiModel, width int) string {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	accent := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	divider := muted.Render(strings.Repeat("─", max(1, width)))
	prefix := "ASK › "
	available := max(1, width-lipgloss.Width(prefix))
	showCursor := m.focus == focusSidebar && !m.showHelp
	input := renderChatInput(m.chatInput, m.chatCursor, available, showCursor)
	line := accent.Render(prefix) + input

	hint := "Enter send · ↑ history · Ctrl+L clear · Esc terminal"
	if len([]rune(m.chatInput)) >= maxChatInputRunes {
		hint = fmt.Sprintf("input limit · %d chars · Ctrl+U clear", maxChatInputRunes)
	} else if m.chatAsking {
		hint = "query running · Ctrl+C cancel · draft next question"
	} else if lastChatFailed(m.chatHistory) {
		hint = "Enter send · Ctrl+R retry · Ctrl+L clear · Esc terminal"
	}
	return renderViewportLines([]string{divider, line, muted.Render(hint)}, width, 3)
}

func renderChatInput(input string, cursor, width int, showCursor bool) string {
	if width < 1 {
		return ""
	}
	runes := []rune(input)
	cursor = clamp(cursor, 0, len(runes))
	before := string(runes[:cursor])
	cursorColumn := lipgloss.Width(before)
	start := max(0, cursorColumn-width+1)
	visible := ansi.Cut(input+" ", start, start+width)
	if !showCursor {
		return lipgloss.NewStyle().Width(width).MaxWidth(width).Render(visible)
	}
	x := max(0, cursorColumn-start)
	left := ansi.Cut(visible, 0, x)
	at := ansi.Cut(visible, x, x+1)
	if at == "" {
		at = " "
	}
	right := ansi.Cut(visible, x+1, width)
	withCursor := left + "\x1b[7m" + at + "\x1b[27m" + right
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Render(withCursor)
}

func renderChatAnswer(answer string) string {
	answer = strings.ReplaceAll(answer, "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(answer), "\n")
	var out []string
	inCode := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCode = !inCode
			continue
		}
		if inCode {
			out = append(out, lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("│ "+line))
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			title := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			out = append(out, lipgloss.NewStyle().Bold(true).Render(title))
			continue
		}
		// El markdown pesado se ve ruidoso en un pane angosto; conservamos
		// listas y código, pero quitamos marcadores de énfasis redundantes.
		line = strings.ReplaceAll(strings.ReplaceAll(line, "**", ""), "__", "")
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func compactChatError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if strings.Contains(strings.ToLower(message), "context deadline exceeded") {
		return "The local model timed out after 90s. Retry or verify the LLM runtime."
	}
	if strings.Contains(strings.ToLower(message), "context canceled") {
		return "Query cancelled."
	}
	return truncate(message, 180)
}

func lastChatFailed(history []chatTurn) bool {
	return len(history) > 0 && history[len(history)-1].err != nil
}

type graphEntity struct {
	id, entityType, value, attrs string
}

type graphRelation struct {
	source, target, kind string
	confidence           float64
}

// renderAttackSurfaceGraph convierte el grafo persistido completo en un
// árbol navegable, no solo host→service. Los ciclos y relaciones múltiples
// se muestran como cross-links y cada entidad se materializa una sola vez.
// Dos queries reemplazan el patrón N+1 de la versión anterior.
func renderAttackSurfaceGraph(b *strings.Builder, m *tuiModel, sessionID string) {
	width := m.sideWidth
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	entities, relations, err := loadAttackSurfaceGraph(m.s, sessionID)
	if err != nil {
		m.graphRows = nil
		b.WriteString(heading.Render("ATTACK SURFACE") + "\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(truncate(sanitizeTerminalText(err.Error()), width)) + "\n\n")
		return
	}

	selected, hadSelection := m.selectedGraphRow()
	visible := graphVisibleSet(entities, relations, m.graphFilter)
	collapsed := m.graphCollapsed
	if strings.TrimSpace(m.graphFilter) != "" {
		// Un filtro nunca debe dejar un match escondido dentro de una rama
		// colapsada; el estado de colapso original se conserva al limpiarlo.
		collapsed = map[string]bool{}
	}
	rows := buildGraphRows(entities, relations, visible, collapsed)
	m.graphRows = rows
	m.graphCursor = clamp(m.graphCursor, 0, max(0, len(rows)-1))
	if hadSelection {
		matchedExact := false
		for i := range rows {
			if rows[i].entityID == selected.entityID && rows[i].parentID == selected.parentID &&
				rows[i].relation == selected.relation && rows[i].crossLink == selected.crossLink {
				m.graphCursor = i
				matchedExact = true
				break
			}
		}
		if !matchedExact {
			for i := range rows {
				if rows[i].entityID == selected.entityID && !rows[i].crossLink {
					m.graphCursor = i
					break
				}
			}
		}
	}

	hosts, services := 0, 0
	for _, entity := range entities {
		switch entity.entityType {
		case "host":
			hosts++
		case "service":
			services++
		}
	}
	title := heading.Render("ATTACK SURFACE")
	if m.graphFilter != "" {
		title += "  " + renderChip(" / "+sanitizeTerminalText(m.graphFilter)+" ", lipgloss.Color("4"))
	}
	b.WriteString(ansi.Truncate(title, width, "") + "\n")
	stats := fmt.Sprintf("%d nodes · %d links · %d hosts · %d services", len(entities), len(relations), hosts, services)
	if m.graphFilter != "" {
		stats += fmt.Sprintf(" · %d visible", countPrimaryGraphRows(rows))
	}
	b.WriteString(muted.Render(truncate(stats, width)) + "\n")
	b.WriteString(muted.Render(truncate("◈ host  ● service  ◆ identity  ◇ domain", width)) + "\n")

	if len(entities) == 0 {
		b.WriteString(muted.Render("No entities yet · ingest evidence to build the graph") + "\n")
		return
	}
	if len(rows) == 0 {
		b.WriteString(muted.Render("No matches · press c to clear the filter") + "\n")
		return
	}
	for i, row := range rows {
		b.WriteString(renderGraphRow(row, i == m.graphCursor, m.focus == focusSidebar, width) + "\n")
	}
}

func loadAttackSurfaceGraph(s *store.Store, sessionID string) (map[string]graphEntity, []graphRelation, error) {
	entities := make(map[string]graphEntity)
	rows, err := s.DB.Query(`
		SELECT id, type, canonical_value, attrs FROM entity
		WHERE session_id = ? ORDER BY type, canonical_value`, sessionID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var entity graphEntity
		if err := rows.Scan(&entity.id, &entity.entityType, &entity.value, &entity.attrs); err != nil {
			rows.Close()
			return nil, nil, err
		}
		entities[entity.id] = entity
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}

	rows, err = s.DB.Query(`
		SELECT r.source_entity_id, r.target_entity_id, r.kind, r.confidence
		FROM relationship r
		JOIN entity source ON source.id = r.source_entity_id
		JOIN entity target ON target.id = r.target_entity_id
		WHERE source.session_id = ? AND target.session_id = ? AND r.valid_to IS NULL
		ORDER BY r.kind, source.canonical_value, target.canonical_value`, sessionID, sessionID)
	if err != nil {
		return nil, nil, err
	}
	var relations []graphRelation
	for rows.Next() {
		var relation graphRelation
		if err := rows.Scan(&relation.source, &relation.target, &relation.kind, &relation.confidence); err != nil {
			rows.Close()
			return nil, nil, err
		}
		relations = append(relations, relation)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	return entities, relations, nil
}

func graphVisibleSet(entities map[string]graphEntity, relations []graphRelation, filter string) map[string]bool {
	visible := make(map[string]bool, len(entities))
	query := strings.ToLower(strings.TrimSpace(filter))
	if query == "" {
		for id := range entities {
			visible[id] = true
		}
		return visible
	}

	matched := make(map[string]bool)
	for id, entity := range entities {
		haystack := strings.ToLower(entity.entityType + " " + entity.value + " " + entity.attrs)
		if strings.Contains(haystack, query) {
			matched[id] = true
			visible[id] = true
		}
	}
	for _, relation := range relations {
		if strings.Contains(strings.ToLower(relation.kind), query) {
			matched[relation.source], matched[relation.target] = true, true
			visible[relation.source], visible[relation.target] = true, true
		}
	}

	// Ancestors explain where a result hangs in the attack surface; direct
	// children give one-hop operational context without expanding an entire
	// connected component for every search.
	parents := make(map[string][]string)
	for _, relation := range relations {
		parents[relation.target] = append(parents[relation.target], relation.source)
	}
	queue := make([]string, 0, len(matched))
	for id := range matched {
		queue = append(queue, id)
	}
	for head := 0; head < len(queue); head++ {
		id := queue[head]
		for _, parent := range parents[id] {
			if visible[parent] {
				continue
			}
			visible[parent] = true
			queue = append(queue, parent)
		}
	}
	for _, relation := range relations {
		if matched[relation.source] {
			visible[relation.target] = true
		}
	}
	return visible
}

func buildGraphRows(entities map[string]graphEntity, relations []graphRelation, visible map[string]bool, collapsed map[string]bool) []graphRow {
	outgoing := make(map[string][]graphRelation)
	incoming := make(map[string][]graphRelation)
	for _, relation := range relations {
		if !visible[relation.source] || !visible[relation.target] {
			continue
		}
		outgoing[relation.source] = append(outgoing[relation.source], relation)
		incoming[relation.target] = append(incoming[relation.target], relation)
	}
	for source := range outgoing {
		sort.SliceStable(outgoing[source], func(i, j int) bool {
			left, right := entities[outgoing[source][i].target], entities[outgoing[source][j].target]
			if graphTypePriority(left.entityType) != graphTypePriority(right.entityType) {
				return graphTypePriority(left.entityType) < graphTypePriority(right.entityType)
			}
			return strings.ToLower(left.value) < strings.ToLower(right.value)
		})
	}

	var roots []string
	for id := range visible {
		if _, ok := entities[id]; ok && len(incoming[id]) == 0 {
			roots = append(roots, id)
		}
	}
	sort.SliceStable(roots, func(i, j int) bool { return graphEntityLess(entities[roots[i]], entities[roots[j]]) })

	visited := make(map[string]bool)
	var result []graphRow
	var walk func(string, string, string, float64, int)
	walk = func(id, parentID, relation string, confidence float64, depth int) {
		entity, ok := entities[id]
		if !ok || !visible[id] {
			return
		}
		if visited[id] {
			result = append(result, graphRow{
				entityID: id, parentID: parentID, entityType: entity.entityType, value: entity.value,
				attrs: entity.attrs, relation: relation, confidence: confidence, depth: depth, incoming: len(incoming[id]),
				outgoing: len(outgoing[id]), crossLink: true,
			})
			return
		}
		visited[id] = true
		children := outgoing[id]
		expanded := !collapsed[id]
		result = append(result, graphRow{
			entityID: id, parentID: parentID, entityType: entity.entityType, value: entity.value,
			attrs: entity.attrs, relation: relation, confidence: confidence, depth: depth, children: len(children),
			incoming: len(incoming[id]), outgoing: len(outgoing[id]), expanded: expanded,
		})
		if !expanded {
			return
		}
		for _, child := range children {
			walk(child.target, id, child.kind, child.confidence, depth+1)
		}
	}

	for _, root := range roots {
		walk(root, "", "", 0, 0)
	}
	// Unrooted components (cycles) and orphans not reached from a root still
	// remain inspectable instead of silently disappearing. Reachability is
	// calculated independently of collapse state so children hidden by the
	// operator are not reintroduced below as false roots.
	topologyReachable := make(map[string]bool)
	var markReachable func(string)
	markReachable = func(id string) {
		if topologyReachable[id] {
			return
		}
		topologyReachable[id] = true
		for _, relation := range outgoing[id] {
			markReachable(relation.target)
		}
	}
	for _, root := range roots {
		markReachable(root)
	}
	var remainder []string
	for id := range visible {
		if !topologyReachable[id] {
			remainder = append(remainder, id)
		}
	}
	sort.SliceStable(remainder, func(i, j int) bool { return graphEntityLess(entities[remainder[i]], entities[remainder[j]]) })
	for _, id := range remainder {
		if !visited[id] {
			walk(id, "", "", 0, 0)
		}
	}
	return result
}

func graphEntityLess(left, right graphEntity) bool {
	if graphTypePriority(left.entityType) != graphTypePriority(right.entityType) {
		return graphTypePriority(left.entityType) < graphTypePriority(right.entityType)
	}
	return strings.ToLower(left.value) < strings.ToLower(right.value)
}

func graphTypePriority(entityType string) int {
	switch entityType {
	case "host":
		return 0
	case "domain", "hostname":
		return 1
	case "service":
		return 2
	case "endpoint", "share":
		return 3
	case "identity":
		return 4
	default:
		return 5
	}
}

func renderGraphRow(row graphRow, selected, focused bool, width int) string {
	marker := "  "
	if selected {
		marker = "› "
	}
	indent := strings.Repeat("  ", min(row.depth, 8))
	branch := ""
	if row.depth > 0 {
		branch = "└─"
	}
	toggle := "·"
	if row.crossLink {
		toggle = "↳"
	} else if row.children > 0 && row.expanded {
		toggle = "▾"
	} else if row.children > 0 {
		toggle = "▸"
	}
	relation := ""
	if row.relation != "" {
		relation = strings.ToLower(sanitizeTerminalText(row.relation)) + " "
	}
	icon, color := graphEntityIcon(row.entityType, row.attrs)
	value := sanitizeTerminalText(row.value)
	raw := fmt.Sprintf("%s%s%s %s%s %s", marker, indent, branch, toggle, icon, relation+value)
	if selected && focused {
		return lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("6")).
			Foreground(lipgloss.Color("0")).Width(width).Render(truncate(raw, width))
	}
	label := fmt.Sprintf("%s%s%s %s%s %s%s", marker, indent, branch, toggle,
		lipgloss.NewStyle().Foreground(color).Render(icon),
		lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(relation), value)
	label = truncate(label, width)
	if selected {
		label = lipgloss.NewStyle().Bold(true).Render(label)
	}
	return label
}

func graphEntityIcon(entityType, attrs string) (string, lipgloss.Color) {
	switch entityType {
	case "host":
		return "◈", lipgloss.Color("6")
	case "service":
		var values map[string]any
		_ = json.Unmarshal([]byte(attrs), &values)
		switch state := strings.ToLower(fmt.Sprint(values["state"])); state {
		case "open":
			return "●", lipgloss.Color("2")
		case "closed", "filtered":
			return "●", lipgloss.Color("8")
		default:
			return "●", lipgloss.Color("3")
		}
	case "identity":
		return "◆", lipgloss.Color("5")
	case "domain", "hostname":
		return "◇", lipgloss.Color("4")
	case "share":
		return "▣", lipgloss.Color("3")
	case "endpoint":
		return "○", lipgloss.Color("3")
	default:
		return "•", lipgloss.Color("7")
	}
}

func countPrimaryGraphRows(rows []graphRow) int {
	count := 0
	for _, row := range rows {
		if !row.crossLink {
			count++
		}
	}
	return count
}

func renderGraphFooter(m *tuiModel, width int) string {
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	accent := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	divider := muted.Render(strings.Repeat("─", max(1, width)))
	if m.graphFiltering {
		prefix := "FILTER › "
		input := renderChatInput(m.graphFilter, m.graphFilterCursor, max(1, width-lipgloss.Width(prefix)), true)
		results := fmt.Sprintf("%d visible nodes · live filter", countPrimaryGraphRows(m.graphRows))
		return renderViewportLines([]string{
			divider,
			accent.Render(prefix) + input,
			muted.Render(results),
			muted.Render("Enter apply · Esc close · Ctrl+U clear"),
		}, width, 4)
	}

	row, ok := m.selectedGraphRow()
	if !ok {
		return renderViewportLines([]string{
			divider,
			muted.Render("No node selected"),
			"",
			muted.Render("/ filter · c clear · r reset · Esc terminal"),
		}, width, 4)
	}
	identity := fmt.Sprintf("%s · %s", strings.ToUpper(sanitizeTerminalText(row.entityType)), sanitizeTerminalText(row.value))
	detail := formatGraphAttrs(row.attrs)
	if row.relation != "" {
		relation := strings.ToLower(sanitizeTerminalText(row.relation))
		relation += fmt.Sprintf("@%.2f", row.confidence)
		if detail != "" {
			detail += " · "
		}
		detail += "via=" + relation
	}
	links := fmt.Sprintf("links %d in/%d out", row.incoming, row.outgoing)
	if detail != "" {
		detail += " · "
	}
	detail += links
	return renderViewportLines([]string{
		divider,
		accent.Render(truncate(identity, width)),
		muted.Render(truncate(detail, width)),
		muted.Render("↑↓/jk select · ←→ fold · Enter toggle · / filter · r reset"),
	}, width, 4)
}

func formatGraphAttrs(attrs string) string {
	var values map[string]any
	if json.Unmarshal([]byte(attrs), &values) != nil || len(values) == 0 {
		return ""
	}
	preferred := []string{"state", "port", "protocol", "product", "version", "name"}
	var parts []string
	for _, key := range preferred {
		value, ok := values[key]
		if !ok || fmt.Sprint(value) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", key, sanitizeTerminalText(fmt.Sprint(value))))
	}
	return strings.Join(parts, " · ")
}

type vaultIdentity struct {
	id, value, provenance string
}

type vaultAttemptStats struct {
	count, successes, failures int
	lastResult, lastAt         string
}

// renderVault presenta identidades como grupos y credenciales como hijos.
// Todos los secretos llegan enmascarados; el valor claro de una credencial
// seleccionada solo se obtiene bajo confirmación explícita en el footer.
func renderVault(b *strings.Builder, m *tuiModel, sessionID string) {
	m.expireVaultReveal()
	width := m.sideWidth
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	identities, credentials, attempts, err := loadVaultData(m.s, sessionID)
	if err != nil {
		m.vaultRows = nil
		b.WriteString(heading.Render("IDENTITY VAULT") + "\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render(truncate(sanitizeTerminalText(err.Error()), width)) + "\n")
		b.WriteString(muted.Render("Secrets remain masked") + "\n")
		return
	}

	selectedKey := ""
	if selected, ok := m.selectedVaultRow(); ok {
		selectedKey = selected.key
	}
	rows := buildVaultRows(identities, credentials, attempts, m.vaultFilter, m.vaultCollapsed)
	m.vaultRows = rows
	m.vaultCursor = clamp(m.vaultCursor, 0, max(0, len(rows)-1))
	if selectedKey != "" {
		for i := range rows {
			if rows[i].key == selectedKey {
				m.vaultCursor = i
				break
			}
		}
	}
	if m.vaultRevealID != "" {
		selected, ok := m.selectedVaultRow()
		if !ok || selected.credentialID != m.vaultRevealID {
			m.clearVaultReveal()
		}
	}

	valid, invalid, incomplete := 0, 0, 0
	for _, credential := range credentials {
		switch credential.Status {
		case "valid":
			valid++
		case "invalid":
			invalid++
		}
		if credential.Identity == "" || credential.Service == "" {
			incomplete++
		}
	}
	title := heading.Render("IDENTITY VAULT")
	if m.vaultFilter != "" {
		title += "  " + renderChip(" / "+sanitizeTerminalText(m.vaultFilter)+" ", lipgloss.Color("4"))
	}
	b.WriteString(ansi.Truncate(title, width, "") + "\n")
	stats := fmt.Sprintf("%d identities · %d creds · %d valid · %d invalid · %d incomplete",
		len(identities), len(credentials), valid, invalid, incomplete)
	b.WriteString(muted.Render(truncate(stats, width)) + "\n")
	b.WriteString(muted.Render(truncate("◆ identity  ✓ valid  ? discovered  × invalid  ! stale", width)) + "\n")

	if len(identities) == 0 && len(credentials) == 0 {
		b.WriteString(muted.Render("No identities or credentials recorded") + "\n")
		return
	}
	if len(rows) == 0 {
		b.WriteString(muted.Render("No matches · press c to clear the filter") + "\n")
		return
	}
	for i, row := range rows {
		b.WriteString(renderVaultRow(row, i == m.vaultCursor, m.focus == focusSidebar, width) + "\n")
	}
}

func loadVaultData(s *store.Store, sessionID string) ([]vaultIdentity, []credentialstore.Credential, map[string]vaultAttemptStats, error) {
	rows, err := s.DB.Query(`
		SELECT id, canonical_value, attrs FROM entity
		WHERE session_id = ? AND type = 'identity'
		ORDER BY canonical_value`, sessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	var identities []vaultIdentity
	for rows.Next() {
		var identity vaultIdentity
		var attrs string
		if err := rows.Scan(&identity.id, &identity.value, &attrs); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		identity.provenance = provenanceLabel(attrs)
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, nil, nil, err
	}

	credentials, err := credentialstore.List(s, sessionID, false)
	if err != nil {
		return nil, nil, nil, err
	}
	attempts, err := loadVaultAttempts(s, sessionID)
	if err != nil {
		return nil, nil, nil, err
	}
	return identities, credentials, attempts, nil
}

func loadVaultAttempts(s *store.Store, sessionID string) (map[string]vaultAttemptStats, error) {
	rows, err := s.DB.Query(`
		SELECT a.credential_id, a.result, a.attempted_at
		FROM credential_attempt a
		JOIN credential c ON c.id = a.credential_id
		WHERE c.session_id = ?
		ORDER BY a.attempted_at`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stats := make(map[string]vaultAttemptStats)
	for rows.Next() {
		var credentialID, result, attemptedAt string
		if err := rows.Scan(&credentialID, &result, &attemptedAt); err != nil {
			return nil, err
		}
		stat := stats[credentialID]
		stat.count++
		switch result {
		case "success":
			stat.successes++
		case "fail":
			stat.failures++
		}
		stat.lastResult, stat.lastAt = result, attemptedAt
		stats[credentialID] = stat
	}
	return stats, rows.Err()
}

func buildVaultRows(identities []vaultIdentity, credentials []credentialstore.Credential, attempts map[string]vaultAttemptStats, filter string, collapsed map[string]bool) []vaultRow {
	identityByValue := make(map[string]vaultIdentity, len(identities))
	for _, identity := range identities {
		identityByValue[identity.value] = identity
	}
	grouped := make(map[string][]credentialstore.Credential)
	for _, credential := range credentials {
		grouped[credential.Identity] = append(grouped[credential.Identity], credential)
	}
	for identity := range grouped {
		sort.SliceStable(grouped[identity], func(i, j int) bool {
			left, right := grouped[identity][i], grouped[identity][j]
			if vaultStatusPriority(left.Status) != vaultStatusPriority(right.Status) {
				return vaultStatusPriority(left.Status) < vaultStatusPriority(right.Status)
			}
			return left.CreatedAt > right.CreatedAt
		})
	}

	query := strings.ToLower(strings.TrimSpace(filter))
	filterActive := query != ""
	var result []vaultRow
	appendIdentity := func(identity vaultIdentity, credentials []credentialstore.Credential, unlinked bool) {
		label := identity.value
		key := "identity:" + identity.id
		provenance := identity.provenance
		if unlinked {
			label, key, provenance = "UNLINKED", "identity:unlinked", "requires attribution"
		}
		identityMatches := query == "" || strings.Contains(strings.ToLower(label+" "+provenance), query)
		var matching []credentialstore.Credential
		for _, credential := range credentials {
			stat := attempts[credential.ID]
			haystack := strings.ToLower(strings.Join([]string{
				credential.ID, credential.Identity, credential.Service, credential.Status,
				credential.Source, stat.lastResult,
			}, " "))
			if identityMatches || strings.Contains(haystack, query) {
				matching = append(matching, credential)
			}
		}
		if !identityMatches && len(matching) == 0 {
			return
		}
		expanded := !collapsed[key] || filterActive
		result = append(result, vaultRow{
			kind: vaultIdentityRow, key: key, identityID: identity.id, identity: label,
			provenance: provenance, children: len(matching), expanded: expanded,
		})
		if !expanded {
			return
		}
		for _, credential := range matching {
			stat := attempts[credential.ID]
			result = append(result, vaultRow{
				kind: vaultCredentialRow, key: "credential:" + credential.ID, parentKey: key,
				credentialID: credential.ID, identity: credential.Identity, service: credential.Service,
				maskedValue: credential.Value, status: credential.Status, source: credential.Source,
				createdAt: credential.CreatedAt, lastResult: stat.lastResult, lastAttempt: stat.lastAt,
				attempts: stat.count, successes: stat.successes, failures: stat.failures,
			})
		}
	}

	for _, identity := range identities {
		appendIdentity(identity, grouped[identity.value], false)
		delete(grouped, identity.value)
	}
	// Includes credentials with no identity and defensive handling for a
	// dangling/unexpected identity label not present in the entity query.
	var unlinked []credentialstore.Credential
	for _, credentials := range grouped {
		unlinked = append(unlinked, credentials...)
	}
	if len(unlinked) > 0 {
		sort.SliceStable(unlinked, func(i, j int) bool { return unlinked[i].CreatedAt > unlinked[j].CreatedAt })
		appendIdentity(vaultIdentity{}, unlinked, true)
	}
	return result
}

func vaultStatusPriority(status string) int {
	switch status {
	case "valid":
		return 0
	case "discovered":
		return 1
	case "stale":
		return 2
	case "invalid":
		return 3
	default:
		return 4
	}
}

func renderVaultRow(row vaultRow, selected, focused bool, width int) string {
	marker := "  "
	if selected {
		marker = "› "
	}
	var raw string
	if row.kind == vaultIdentityRow {
		toggle := "·"
		if row.children > 0 && row.expanded {
			toggle = "▾"
		} else if row.children > 0 {
			toggle = "▸"
		}
		raw = fmt.Sprintf("%s%s ◆ %s  [%d]  %s", marker, toggle,
			sanitizeTerminalText(row.identity), row.children, sanitizeTerminalText(row.provenance))
	} else {
		icon, _ := vaultStatusIcon(row.status)
		service := row.service
		if service == "" {
			service = "unlinked-service"
		}
		raw = fmt.Sprintf("%s  └─ %s %s  %s  %s", marker, icon, firstN(row.credentialID, 8),
			sanitizeTerminalText(row.status), sanitizeTerminalText(service))
	}
	if selected && focused {
		return lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("6")).
			Foreground(lipgloss.Color("0")).Width(width).Render(truncate(raw, width))
	}
	if row.kind == vaultIdentityRow {
		return truncate(raw, width)
	}
	icon, color := vaultStatusIcon(row.status)
	plainIcon := strings.Index(raw, icon)
	if plainIcon < 0 {
		return truncate(raw, width)
	}
	label := raw[:plainIcon] + lipgloss.NewStyle().Foreground(color).Render(icon) + raw[plainIcon+len(icon):]
	label = truncate(label, width)
	if selected {
		label = lipgloss.NewStyle().Bold(true).Render(label)
	}
	return label
}

func vaultStatusIcon(status string) (string, lipgloss.Color) {
	switch status {
	case "valid":
		return "✓", lipgloss.Color("2")
	case "invalid":
		return "×", lipgloss.Color("1")
	case "stale":
		return "!", lipgloss.Color("3")
	default:
		return "?", lipgloss.Color("4")
	}
}

func renderVaultFooter(m *tuiModel, width int) string {
	m.expireVaultReveal()
	muted := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	accent := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	divider := muted.Render(strings.Repeat("─", max(1, width)))
	if m.vaultFiltering {
		prefix := "FILTER › "
		input := renderChatInput(m.vaultFilter, m.vaultFilterCursor, max(1, width-lipgloss.Width(prefix)), true)
		return renderViewportLines([]string{
			divider,
			accent.Render(prefix) + input,
			muted.Render(fmt.Sprintf("%d visible rows · secrets excluded from search", len(m.vaultRows))),
			muted.Render("Search: identity · service · status · source · attempt"),
			muted.Render("Enter apply · Esc close · Ctrl+U clear"),
		}, width, 5)
	}

	row, ok := m.selectedVaultRow()
	if !ok {
		return renderViewportLines([]string{
			divider, muted.Render("No identity or credential selected"), "", "",
			muted.Render("/ filter · c clear · r reset · Esc terminal"),
		}, width, 5)
	}
	if row.kind == vaultIdentityRow {
		return renderViewportLines([]string{
			divider,
			accent.Render(truncate("IDENTITY · "+sanitizeTerminalText(row.identity), width)),
			muted.Render(truncate("provenance="+sanitizeTerminalText(row.provenance), width)),
			muted.Render(fmt.Sprintf("%d linked credential(s)", row.children)),
			muted.Render("↑↓/jk select · ←→ fold · Enter toggle · / filter"),
		}, width, 5)
	}

	icon, color := vaultStatusIcon(row.status)
	title := fmt.Sprintf("CREDENTIAL · %s · %s %s", firstN(row.credentialID, 8), icon, strings.ToUpper(row.status))
	secretLine := "secret=" + strconv.Quote(row.maskedValue)
	hint := "v reveal · ↑↓ select (auto-hide) · / filter · Esc terminal"
	now := time.Now()
	switch {
	case m.vaultRevealID == row.credentialID && now.Before(m.vaultRevealUntil):
		secretLine = "SECRET=" + strconv.Quote(m.vaultRevealValue)
		remaining := max(1, int(time.Until(m.vaultRevealUntil).Seconds()))
		hint = fmt.Sprintf("REVEALED · hides in %ds · v hide now · navigation hides", remaining)
	case m.vaultRevealArmed == row.credentialID && now.Before(m.vaultArmUntil):
		remaining := max(1, int(time.Until(m.vaultArmUntil).Seconds()))
		secretLine = fmt.Sprintf("Press v again within %ds to reveal for %ds", remaining, int(vaultRevealDuration.Seconds()))
		hint = "two-step confirmation · Esc/navigation cancels"
	case m.vaultError != "":
		secretLine = "ERROR · " + sanitizeTerminalText(m.vaultError)
	}
	link := orDash(row.identity) + " → " + orDash(row.service)
	activity := fmt.Sprintf("%s · source=%s · attempts=%d (%d✓/%d×)", link, orDash(row.source), row.attempts, row.successes, row.failures)
	if row.lastResult != "" {
		activity += " · last=" + row.lastResult
		if row.lastAttempt != "" {
			activity += " " + relTime(row.lastAttempt)
		}
	}
	return renderViewportLines([]string{
		divider,
		lipgloss.NewStyle().Bold(true).Foreground(color).Render(truncate(title, width)),
		truncate(secretLine, width),
		muted.Render(truncate(sanitizeTerminalText(activity), width)),
		muted.Render(hint),
	}, width, 5)
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

func wrapText(s string, width int) string {
	if width < 1 || strings.TrimSpace(s) == "" {
		return ""
	}
	return ansi.Wrap(s, width, "/_:.')")
}

func compactNarration(s string, width, maxLines int) string {
	if width < 1 || maxLines < 1 {
		return ""
	}
	compact := strings.Join(strings.Fields(s), " ")
	lines := strings.Split(ansi.Wrap(compact, width, "/_:.')"), "\n")
	if len(lines) <= maxLines {
		return strings.Join(lines, "\n")
	}
	lines = lines[:maxLines]
	lines[maxLines-1] = ansi.Truncate(lines[maxLines-1], max(1, width-1), "") + "…"
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
	if n < 1 || lipgloss.Width(s) <= n {
		return s
	}
	return ansi.Truncate(s, n, "…")
}

// sanitizeTerminalText evita que valores procedentes de scans, modelos o
// nombres remotos inyecten secuencias de control en la propia TUI. También
// elimina controles bidi que podrían mostrar un identificador distinto del
// almacenado. El grafo sigue buscando sobre el valor crudo; solo se sanea la
// representación visual.
func sanitizeTerminalText(value string) string {
	value = ansi.Strip(value)
	value = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		case r >= 0x202a && r <= 0x202e:
			return -1
		case r >= 0x2066 && r <= 0x2069:
			return -1
		default:
			return r
		}
	}, value)
	return strings.Join(strings.Fields(value), " ")
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
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error en la TUI:", err)
		os.Exit(1)
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
	}
}
