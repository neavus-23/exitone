// exitone CLI — Slice 1 + 2 (sección L del plan): nmap/smbclient -> Evidence ->
// Investigation Model -> Methodology gap -> Candidate -> Strategy Ranker ->
// Command Engine. El humano decide y ejecuta; este binario nunca ejecuta
// comandos contra el target.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"context"

	"exitone/internal/debuglog"
	"exitone/internal/focus"
	"exitone/internal/hypothesis"
	"exitone/internal/ingestsource"
	"exitone/internal/investigation"
	"exitone/internal/llm"
	"exitone/internal/methodology"
	"exitone/internal/outcome"
	"exitone/internal/parsers"
	"exitone/internal/stage"
	"exitone/internal/store"
	"exitone/internal/strategy"

	"github.com/google/uuid"
)

// dbPath devuelve una ruta fija en el home del usuario, independiente del cwd
// desde el que se invoque exitone — necesario para que los shell hooks (que
// disparan `exitone ingest` automáticamente tras detectar un comando nmap/
// smbclient) funcionen sin importar en qué directorio estaba el operador.
func dbPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fatal("no se pudo resolver el home del usuario: %v", err)
	}
	dir := filepath.Join(home, ".exitone")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal("no se pudo crear %s: %v", dir, err)
	}
	return filepath.Join(dir, "exitone.db")
}

func main() {
	// Sin argumentos (o `exitone repl`) → modo interactivo: el operador queda
	// "dentro" del programa en vez de repetir `exitone` en cada comando.
	if len(os.Args) < 2 || os.Args[1] == "repl" {
		runConsole()
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	cwd, _ := os.Getwd()
	debuglog.Log("cli_invoked", map[string]any{"cmd": cmd, "args": args, "cwd": cwd})

	s, err := store.Open(dbPath())
	if err != nil {
		fatal("no se pudo abrir la base de datos: %v", err)
	}
	defer s.Close()

	dispatch(s, cmd, args)
}

// dispatch es el mismo switch de siempre, extraído para poder llamarlo tanto
// desde main() (modo comando único) como, indirectamente vía self-exec,
// desde el REPL (ver runRepl) — así el REPL reutiliza exactamente la misma
// lógica sin duplicarla.
func dispatch(s *store.Store, cmd string, args []string) {
	switch cmd {
	case "session":
		cmdSession(s, args)
	case "ingest":
		cmdIngest(s, args)
	case "next":
		cmdNext(s, args)
	case "why":
		cmdWhy(s, args)
	case "status":
		cmdStatus(s)
	case "accept":
		cmdAccept(s, args)
	case "resolve":
		cmdResolve(s, args)
	case "stages":
		cmdStages(s)
	case "dismiss":
		cmdDismiss(s, args)
	case "focus":
		cmdFocus(s, args)
	case "ask":
		cmdAsk(s, args)
	case "watch":
		cmdWatch(s, args)
	case "start":
		cmdStart(s, args)
	case "tui":
		cmdTUI(s)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`exitone — Slice 1 + 2

Uso:
  exitone session new <target-label>
  exitone ingest <archivo> [--tool <hint>] [--host <ip>] [--for-action <id-prefix>]
      (agnóstico: detecta nmap/smbclient por contenido; si no reconoce el
       formato, cae automáticamente a extracción Nivel 2 vía LLM local)
  exitone ingest identities <archivo.txt> --source <origen>
  exitone ingest watch <directorio>   (observa el directorio, ingiere cada archivo nuevo automáticamente — Ctrl+C para salir)
  exitone next [--raw]
  exitone why <candidate-id-prefix>
  exitone status
  exitone accept <candidate-id-prefix>
  exitone resolve <action-id-prefix> --result <fail|success>
  exitone stages
  exitone dismiss <candidate-id-prefix>
  exitone focus <hypothesis-or-objective-id-prefix>   (dónde invertir esfuerzo — siempre explícito, nunca inferido)
  exitone focus clear
  exitone focus   (sin argumentos: muestra el focus activo, si hay uno)
  exitone ask "<pregunta>"   (chat contextual anclado al estado real, vía LLM local)
  exitone watch [--interval <segundos>]   (dashboard en vivo, solo lectura)
  exitone start <target> [--tmux]   (arranca la app: terminal embebida + dashboard en vivo — sin tmux; --tmux usa el layout anterior de dos panes)
  exitone tui   (la app completa directamente, sesión ya activa)`)
}

// interactiveMode y consoleAbort son el ÚNICO puente entre la Control
// Console nueva (cmd/exitone/console_*.go) y los cmdXxx legacy, que llaman
// fatal()->os.Exit(1). Fuera de la consola (modo comando único) el
// comportamiento es idéntico al de siempre. Ver plan, sección B: el resto
// de la consola nunca usa panic/recover, solo legacyAdapter (console_bridge.go).
var interactiveMode bool

type consoleAbort string

func fatal(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	debuglog.Log("fatal_error", map[string]any{"message": msg})
	if interactiveMode {
		panic(consoleAbort(msg))
	}
	fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	os.Exit(1)
}

func currentSession(s *store.Store) string {
	id, ok, err := s.GetAppState("current_session")
	if err != nil {
		fatal("leer sesión activa: %v", err)
	}
	if !ok {
		fatal("no hay sesión activa — corre `exitone session new <target-label>` primero")
	}
	return id
}

func cmdSession(s *store.Store, args []string) {
	if len(args) < 2 || args[0] != "new" {
		fatal("uso: exitone session new <target-label> [--fresh]")
	}
	rest, flags := parseFlags(args[1:])
	if len(rest) < 1 {
		fatal("uso: exitone session new <target-label> [--fresh]")
	}
	label := rest[0]
	_, forceFresh := flags["fresh"]

	// Reanudar por defecto si ya existe una sesión abierta para este mismo
	// target — bug real encontrado revisando ultra_debug.log con el
	// operador: cada `exitone start <target>` (ej. al reabrir la TUI tras
	// salir con Ctrl+Q) creaba una sesión NUEVA de cero, perdiendo entidades,
	// objectives y etapas ya avanzadas — el investigador "volvía a
	// NOT_STARTED" sin haber hecho nada mal. --fresh fuerza una sesión
	// nueva de verdad cuando de verdad se quiere reiniciar.
	if !forceFresh {
		var existingID string
		err := s.DB.QueryRow(
			`SELECT id FROM session WHERE target_label = ? AND closed_at IS NULL ORDER BY started_at DESC LIMIT 1`,
			label,
		).Scan(&existingID)
		if err == nil {
			if err := s.SetAppState("current_session", existingID); err != nil {
				fatal("guardar sesión activa: %v", err)
			}
			fmt.Printf("Reanudando sesión existente: %s (%s)\n", label, existingID[:8])
			generateCandidates(s, existingID) // por si quedó algo pendiente sin generar
			return
		}
		if err != sql.ErrNoRows {
			fatal("consultar sesiones existentes: %v", err)
		}
	}

	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO session(id, target_label, started_at) VALUES (?, ?, ?)`,
		id, label, now,
	); err != nil {
		fatal("crear sesión: %v", err)
	}
	if err := s.SetAppState("current_session", id); err != nil {
		fatal("guardar sesión activa: %v", err)
	}
	fmt.Printf("Sesión creada: %s (%s)\n", label, id[:8])

	// Bootstrap (ver internal/investigation/bootstrap.go): crea la entidad
	// host del target y abre el objective 'initial_discovery' para que
	// `exitone next` tenga algo real que proponer desde el primer momento.
	hostID, _, err := investigation.EnsureHostEntity(s, id, label)
	if err != nil {
		fatal("crear entidad host inicial: %v", err)
	}
	if _, err := methodology.EvaluateTriggers(s, id, []string{hostID}); err != nil {
		fatal("abrir objective inicial: %v", err)
	}
	generateCandidates(s, id)
}

// parseFlags separa argumentos posicionales de flags --nombre valor.
func parseFlags(args []string) (positional []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 2 && a[:2] == "--" {
			name := a[2:]
			if i+1 < len(args) {
				flags[name] = args[i+1]
				i++
			} else {
				flags[name] = ""
			}
			continue
		}
		positional = append(positional, a)
	}
	return
}

// shellEventMeta es el JSON que los shell hooks (contrib/exitone-hooks.zsh)
// ya construyen a partir de datos que siempre tuvieron (preexec/precmd) pero
// nunca llegaban a la base de datos — Fase 1 del plan de arquitectura: cerrar
// la cadena de provenance Event→Evidence→Observation, que hasta ahora
// quedaba rota en la práctica porque evidence.event_id era NULL en los tres
// caminos reales de ingesta pese a que el hook sí conocía el comando exacto.
type shellEventMeta struct {
	Pane      string  `json:"pane"`
	Command   string  `json:"command"`
	Cwd       string  `json:"cwd"`
	StartedAt float64 `json:"started_at"`
	EndedAt   float64 `json:"ended_at"`
	ExitCode  int     `json:"exit_code"`
}

// resolveEvent crea la fila `event` correspondiente al comando de shell que
// disparó este ingest. Devuelve "" si no hay --event (ingest manual, o un
// futuro FileWatchEventSource sin comando asociado) — evidence.event_id
// sigue NULL en ese caso, legítimamente: esto no inventa un evento donde no
// existe, solo deja de descartar el que el hook sí reportó.
func resolveEvent(s *store.Store, sessionID, eventJSON string) string {
	if eventJSON == "" {
		return ""
	}
	var meta shellEventMeta
	if err := json.Unmarshal([]byte(eventJSON), &meta); err != nil {
		debuglog.LogError("resolve_event_parse", err, map[string]any{"raw": eventJSON})
		return ""
	}
	pane := meta.Pane
	if pane == "none" {
		pane = ""
	}
	id := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO event(id, session_id, tmux_pane_id, command_raw, cwd, started_at, ended_at, exit_code, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'shell_hook')`,
		id, sessionID, nullIfEmpty(pane), meta.Command, nullIfEmpty(meta.Cwd),
		nullIfEmpty(epochToRFC3339(meta.StartedAt)), nullIfEmpty(epochToRFC3339(meta.EndedAt)), meta.ExitCode,
	); err != nil {
		debuglog.LogError("resolve_event_insert", err, map[string]any{"raw": eventJSON})
		return ""
	}
	return id
}

func epochToRFC3339(epoch float64) string {
	if epoch == 0 {
		return ""
	}
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

func nullIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func cmdIngest(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone ingest <archivo> [--tool <hint>] [--host <ip>] [--for-action <id>]")
	}
	sessionID := currentSession(s)

	// 'identities' es la única forma explícita que se mantiene: es una lista
	// que el operador declara (no la salida de una herramienta), así que no
	// tiene sentido "detectarla" por contenido.
	if args[0] == "identities" {
		rest, flags := parseFlags(args[1:])
		if len(rest) < 1 {
			fatal("uso: exitone ingest identities <archivo> --source <origen>")
		}
		source := flags["source"]
		if source == "" {
			source = "manual"
		}
		eventID := resolveEvent(s, sessionID, flags["event"])
		ingestIdentities(s, sessionID, rest[0], eventID, source)
		return
	}

	// 'watch <directorio>' — Fase 5 del plan de arquitectura:
	// FileWatchEventSource. Observa el directorio y llama a `exitone ingest`
	// (self-exec, mismo patrón que el REPL) por cada archivo nuevo — nunca
	// decide qué es un hecho, solo entrega artefactos crudos al pipeline
	// existente. Bloquea hasta Ctrl+C.
	if args[0] == "watch" {
		if len(args) < 2 {
			fatal("uso: exitone ingest watch <directorio>")
		}
		cmdIngestWatch(args[1])
		return
	}

	rest, flags := parseFlags(args)
	if len(rest) < 1 {
		fatal("falta la ruta del archivo de evidencia")
	}
	path := rest[0]
	// --event <json>: metadata del comando de shell que produjo este archivo
	// (pane/command/cwd/started_at/ended_at/exit_code), ya construida por
	// contrib/exitone-hooks.zsh — ausente en un ingest manual, y ahí NULL en
	// evidence.event_id sigue siendo correcto.
	eventID := resolveEvent(s, sessionID, flags["event"])

	// Ingest agnóstico a la herramienta (sección 6 del plan, "Universal Output
	// Ingestion"): se detecta el formato por contenido en vez de exigir que el
	// operador (o el shell hook) sepan qué sub-parser corresponde a cada una
	// de las ~100 herramientas comunes de pentesting/CTF. --tool es solo una
	// pista opcional (ej. el nombre del binario tecleado, si el hook lo captó)
	// que ayuda al detector mas no lo determina por sí sola.
	content, err := os.ReadFile(path)
	if err != nil {
		fatal("abrir archivo de evidencia: %v", err)
	}
	toolHint := flags["tool"]

	// Camino genérico primero (sección "Qué se mejora" del plan): reconoce
	// forma de dato + alias de campo, sin importar qué herramienta produjo
	// el archivo. Es estrictamente más capaz que los parsers específicos de
	// abajo (cualquier XML/JSON/tabla con esos alias, no solo nmap/smbclient),
	// así que se intenta antes de caer a las rutas existentes.
	shape := parsers.DetectShape(content)
	debuglog.Log("ingest_detect_shape", map[string]any{"file": path, "shape": int(shape)})
	if genericIngest(s, sessionID, path, content, shape, eventID) {
		return
	}

	format := parsers.Detect(toolHint, content)
	debuglog.Log("ingest_detect", map[string]any{"file": path, "tool_hint": toolHint, "detected": string(format)})

	switch format {
	case parsers.FormatNmapGreppable:
		ingestNmap(s, sessionID, path, eventID, flags["for-action"])
	case parsers.FormatSmbclientListing:
		host := flags["host"]
		if host == "" {
			fatal("se detectó salida de smbclient pero falta --host <ip> (no se puede resolver la entidad host de forma agnóstica)")
		}
		ingestSmbclient(s, sessionID, path, eventID, host, flags["for-action"])
	default:
		hint := toolHint
		if hint == "" {
			hint = "unknown"
		}
		fmt.Printf("Formato no reconocido por ningún parser determinista — usando extracción Nivel 2 (LLM) para %q\n", hint)
		ingestRaw(s, sessionID, path, eventID, hint)
	}
}

// cliIngestSink es el ArtifactSink concreto para el CLI: reinvoca este mismo
// binario (self-exec, mismo patrón que repl.go) por cada archivo nuevo, en
// vez de llamar dispatch() in-process — así un error en un archivo no mata
// el watcher completo, y se reusa el 100% del pipeline de `exitone ingest`
// sin duplicar su lógica aquí.
type cliIngestSink struct{ selfPath string }

func (c cliIngestSink) Accept(path string) error {
	cmd := exec.Command(c.selfPath, "ingest", path)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	return err
}

// cmdIngestWatch implementa la Fase 5 del plan de arquitectura:
// FileWatchEventSource observando un directorio, bloqueando hasta Ctrl+C.
func cmdIngestWatch(dir string) {
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}
	src := &ingestsource.FileWatchEventSource{Dir: dir}
	fmt.Printf("Observando %s — Ctrl+C para salir. Cada archivo nuevo se ingiere automáticamente.\n", dir)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := src.Run(ctx, cliIngestSink{selfPath: selfPath}); err != nil && err != context.Canceled {
		fatal("observar directorio: %v", err)
	}
}

// genericIngest intenta el extractor genérico correspondiente a la forma
// detectada (XML/JSON/tabla — nunca por nombre de herramienta). Devuelve
// false si la forma no calzó con ningún alias de campo reconocible, para que
// cmdIngest caiga a las rutas específicas existentes sin romper nada.
func genericIngest(s *store.Store, sessionID, path string, content []byte, shape parsers.Shape, eventID string) bool {
	var result parsers.ScanResult
	var ok bool
	switch shape {
	case parsers.ShapeXML:
		result, ok = parsers.ExtractFromXML(content)
	case parsers.ShapeJSON:
		result, ok = parsers.ExtractFromJSON(content)
	case parsers.ShapeGenericTable:
		result, ok = parsers.ExtractFromGenericTable(content)
	default:
		return false
	}
	if !ok {
		return false
	}

	absPath, _ := filepath.Abs(path)
	res, err := investigation.ApplyScanResult(s, sessionID, absPath, eventID, result)
	if err != nil {
		fatal("ingerir evidencia (extractor genérico): %v", err)
	}
	afterIngest(s, sessionID, res, len(result.Services)+len(result.Endpoints))
	debuglog.Log("ingest_generic_scan", map[string]any{
		"session": sessionID, "file": absPath, "shape": int(shape),
		"hosts_found": len(result.Hosts), "services_found": len(result.Services), "endpoints_found": len(result.Endpoints),
		"new_entities": res.NewEntities, "new_relations": res.NewRelations,
	})

	pathResolved := len(result.Services) > 0 || len(result.Endpoints) > 0
	// El extractor genérico no sabe qué herramienta generó el archivo, pero
	// las acciones pendientes existentes sí guardan un `tool` conocido (ej.
	// "nmap") — se prueban esos nombres conocidos además de "generic_scan"
	// para no perder el auto-link de outcomes que ya funcionaba antes de
	// esta mejora.
	for _, tool := range []string{"nmap", "smbclient", "generic_scan"} {
		matched, outcomeID, err := outcome.AutoRecordPending(s, sessionID, tool, res, pathResolved)
		if err != nil {
			fatal("auto-registrar outcome: %v", err)
		}
		if matched {
			fmt.Printf("Outcome auto-vinculado a acción pendiente: %s\n", outcomeID[:8])
			debuglog.Log("outcome_auto_link", map[string]any{"tool": tool, "matched": matched, "outcome": outcomeID, "path_resolved": pathResolved})
			break
		}
	}

	generateCandidates(s, sessionID)
	if _, err := strategy.GenerateEndpointFollowupCandidates(s, sessionID, res.NewEntities); err != nil {
		fatal("generar candidatos de endpoint: %v", err)
	}
	return true
}

func ingestIdentities(s *store.Store, sessionID, path, eventID, source string) {
	f, err := os.Open(path)
	if err != nil {
		fatal("abrir archivo de evidencia: %v", err)
	}
	defer f.Close()

	names, err := parsers.ParseIdentityList(f)
	if err != nil {
		fatal("parsear identidades: %v", err)
	}
	absPath, _ := filepath.Abs(path)
	res, err := investigation.IngestIdentities(s, sessionID, absPath, eventID, source, names)
	if err != nil {
		fatal("ingerir identidades: %v", err)
	}
	fmt.Printf("Ingesta OK: %d identidades, %d entidades nuevas\n", len(names), len(res.NewEntities))
	debuglog.Log("ingest_identities", map[string]any{
		"session": sessionID, "source": source, "names": names, "new_entities": res.NewEntities,
	})

	// Fase 3 del plan de arquitectura: una identidad nueva ya no dispara una
	// reapertura de hipótesis por diff de conjuntos — es cobertura pendiente,
	// y generateCandidates() la refleja directamente (ver ssh.go:
	// candidateExists genera un candidato test_ssh_auth por cada par
	// servicio/identidad todavía no propuesto, sin pasar por ninguna
	// hypothesis). La reapertura genuina (hypothesis.Contradict) queda
	// reservada para cuando evidencia nueva contradiga específicamente un
	// cierre previo, no para "apareció una entidad nueva".
	generateCandidates(s, sessionID)
}

// ingestRaw es el camino de Nivel 2 (sección 6/8/J del plan): para output de
// herramientas sin parser determinista. Nunca promueve nada a FACT — cada
// Observation queda con status='candidate' y confidence acotada (ver
// internal/llm/extract.go). El operador debe revisar `exitone status` y
// corroborar antes de actuar sobre estas entidades.
func ingestRaw(s *store.Store, sessionID, path, eventID, toolHint string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("abrir archivo de evidencia: %v", err)
	}

	client := llm.New()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	obs, err := llm.ExtractObservations(ctx, client, toolHint, string(raw))
	if err != nil {
		debuglog.LogError("ingest_raw_llm_extract", err, map[string]any{"tool": toolHint, "raw_len": len(raw)})
		fatal("extracción Nivel 2 vía LLM falló: %v", err)
	}
	debuglog.Log("ingest_raw_llm_extract", map[string]any{"tool": toolHint, "raw_len": len(raw), "observations": obs})
	if len(obs) == 0 {
		fmt.Println("El LLM no identificó observaciones candidatas en este output.")
		return
	}

	absPath, _ := filepath.Abs(path)
	res, err := investigation.IngestGeneric(s, sessionID, absPath, eventID, toolHint, obs)
	if err != nil {
		fatal("ingerir evidencia Nivel 2: %v", err)
	}

	fmt.Printf("Extracción Nivel 2 (LLM, confianza ≤ 0.5, nunca FACT): %d observación(es) candidata(s)\n", len(obs))
	for _, o := range obs {
		fmt.Printf("  [%s] %q (confidence %.2f)\n", o.Kind, o.Value, o.Confidence)
	}
	fmt.Printf("%d entidad(es) nueva(s) creada(s), marcadas attrs.extracted_by=\"llm\"\n", len(res.NewEntities))

	// Deliberadamente NO se abre metodología ni se generan candidatos aquí
	// todavía: hacerlo trataría una inferencia de baja confianza con el mismo
	// peso que una observación determinista de Nivel 1 — gap conocido y
	// documentado (sección J), pendiente de una política de confianza mínima
	// antes de disparar el Candidate Generator sobre entidades type=llm.
}

func ingestNmap(s *store.Store, sessionID, path, eventID, forAction string) {
	f, err := os.Open(path)
	if err != nil {
		fatal("abrir archivo de evidencia: %v", err)
	}
	defer f.Close()

	ports, err := parsers.ParseNmapGreppable(f)
	if err != nil {
		fatal("parsear nmap: %v", err)
	}
	if len(ports) == 0 {
		fmt.Println("Advertencia: no se encontraron puertos abiertos en el archivo (¿formato -oG correcto?)")
	}

	absPath, _ := filepath.Abs(path)
	res, err := investigation.IngestNmap(s, sessionID, absPath, eventID, ports)
	if err != nil {
		fatal("ingerir evidencia: %v", err)
	}
	afterIngest(s, sessionID, res, len(ports))
	debuglog.Log("ingest_nmap", map[string]any{
		"session": sessionID, "file": absPath, "for_action": forAction,
		"ports_found": len(ports), "new_entities": res.NewEntities, "new_relations": res.NewRelations,
	})

	pathResolved := len(ports) > 0
	if forAction != "" {
		outcomeID, err := outcome.Record(s, forAction, res, pathResolved)
		if err != nil {
			fatal("registrar outcome: %v", err)
		}
		fmt.Printf("Outcome registrado: %s\n", outcomeID[:8])
		debuglog.Log("outcome_recorded_explicit", map[string]any{"action_prefix": forAction, "outcome": outcomeID, "path_resolved": pathResolved})
	} else {
		// Auto-ingesta (sin --for-action explícito, ej. disparada por el shell
		// hook): busca sola la acción 'awaiting_evidence' de esta herramienta.
		matched, outcomeID, err := outcome.AutoRecordPending(s, sessionID, "nmap", res, pathResolved)
		if err != nil {
			fatal("auto-registrar outcome: %v", err)
		}
		if matched {
			fmt.Printf("Outcome auto-vinculado a acción pendiente: %s\n", outcomeID[:8])
		}
		debuglog.Log("outcome_auto_link", map[string]any{"tool": "nmap", "matched": matched, "outcome": outcomeID, "path_resolved": pathResolved})
	}
	generateCandidates(s, sessionID)
}

func ingestSmbclient(s *store.Store, sessionID, path, eventID, host, forAction string) {
	f, err := os.Open(path)
	if err != nil {
		fatal("abrir archivo de evidencia: %v", err)
	}
	defer f.Close()

	listing, err := parsers.ParseSmbclientListing(f)
	if err != nil {
		fatal("parsear smbclient: %v", err)
	}

	absPath, _ := filepath.Abs(path)
	res, err := investigation.IngestSmbclient(s, sessionID, absPath, eventID, host, listing)
	if err != nil {
		fatal("ingerir evidencia: %v", err)
	}
	fmt.Printf("Ingesta OK: %d shares, dominio=%q, %d entidades nuevas, %d relaciones nuevas\n",
		len(listing.Shares), listing.Domain, len(res.NewEntities), len(res.NewRelations))

	openedObjectives, err := methodology.EvaluateTriggers(s, sessionID, res.NewEntities)
	if err != nil {
		fatal("evaluar metodología: %v", err)
	}
	if len(openedObjectives) > 0 {
		fmt.Printf("Nuevos methodology objectives abiertos (correlación cross-tool): %d\n", len(openedObjectives))
	}
	debuglog.Log("ingest_smbclient", map[string]any{
		"session": sessionID, "file": absPath, "host": host, "for_action": forAction,
		"shares": listing.Shares, "domain": listing.Domain,
		"new_entities": res.NewEntities, "new_relations": res.NewRelations,
		"opened_objectives": openedObjectives,
	})

	pathResolved := len(listing.Shares) > 0
	if forAction != "" {
		outcomeID, err := outcome.Record(s, forAction, res, pathResolved)
		if err != nil {
			fatal("registrar outcome: %v", err)
		}
		fmt.Printf("Outcome registrado: %s (path resuelto: %v)\n", outcomeID[:8], pathResolved)
		debuglog.Log("outcome_recorded_explicit", map[string]any{"action_prefix": forAction, "outcome": outcomeID, "path_resolved": pathResolved})
	} else {
		matched, outcomeID, err := outcome.AutoRecordPending(s, sessionID, "smbclient", res, pathResolved)
		if err != nil {
			fatal("auto-registrar outcome: %v", err)
		}
		if matched {
			fmt.Printf("Outcome auto-vinculado a acción pendiente: %s (path resuelto: %v)\n", outcomeID[:8], pathResolved)
		}
		debuglog.Log("outcome_auto_link", map[string]any{"tool": "smbclient", "matched": matched, "outcome": outcomeID, "path_resolved": pathResolved})
	}

	generateCandidates(s, sessionID)
}

// afterIngest evalúa metodología (abrir objectives) pero NUNCA genera
// candidatos por sí sola. Esto es deliberado (bug real encontrado probando
// contra el lab: sección Prueba 7 del protocolo de validación): si un ingest
// viene con --for-action, hay que registrar primero el OUTCOME —que puede
// marcar un objective_path como 'answered'— y solo DESPUÉS generar
// candidatos. Generarlos antes producía una sugerencia duplicada de una
// acción que el mismo ingest acababa de resolver.
func afterIngest(s *store.Store, sessionID string, res *investigation.IngestResult, portsFound int) {
	fmt.Printf("Ingesta OK: %d hallazgo(s), %d entidades nuevas, %d relaciones nuevas\n",
		portsFound, len(res.NewEntities), len(res.NewRelations))

	openedObjectives, err := methodology.EvaluateTriggers(s, sessionID, res.NewEntities)
	if err != nil {
		fatal("evaluar metodología: %v", err)
	}
	if len(openedObjectives) > 0 {
		fmt.Printf("Nuevos methodology objectives abiertos: %d\n", len(openedObjectives))
	}

	answeredPaths, err := methodology.EvaluateEndpointTriggers(s, sessionID, res.NewEntities)
	if err != nil {
		fatal("evaluar progreso de endpoints: %v", err)
	}
	if len(answeredPaths) > 0 {
		fmt.Printf("Objective paths de enumeración web progresados: %d\n", len(answeredPaths))
	}
}

func generateCandidates(s *store.Store, sessionID string) {
	bootstrapCreated, err := strategy.GenerateInitialDiscoveryCandidates(s, sessionID)
	if err != nil {
		fatal("generar candidato inicial: %v", err)
	}
	created, err := strategy.GenerateAndRankMethodologyCandidates(s, sessionID)
	if err != nil {
		fatal("generar candidatos: %v", err)
	}
	sshCreated, err := strategy.GenerateSSHAuthCandidates(s, sessionID)
	if err != nil {
		fatal("generar candidatos ssh: %v", err)
	}
	total := len(bootstrapCreated) + len(created) + len(sshCreated)
	if total > 0 {
		fmt.Printf("Candidatos generados: %d — corre `exitone next` para verlos\n", total)
	}
	debuglog.Log("generate_candidates", map[string]any{
		"session": sessionID, "bootstrap": bootstrapCreated, "methodology": created, "ssh": sshCreated,
	})
}

func cmdNext(s *store.Store, args []string) {
	_, flags := parseFlags(args)
	_, raw := flags["raw"]
	if !raw {
		for _, a := range args {
			if a == "--raw" {
				raw = true
			}
		}
	}

	sessionID := currentSession(s)
	// LEFT JOIN a objective_path para poder reordenar por `focus` cuando el
	// focus activo es un objective (Fase 2) — el candidato no guarda
	// objective_id directo, solo objective_path_id.
	rows, err := s.DB.Query(`
		SELECT c.id, c.source, c.tool, c.command_template_rendered, c.score, c.explanation,
		       c.hypothesis_id, op.objective_id
		FROM candidate c
		LEFT JOIN objective_path op ON op.id = c.objective_path_id
		WHERE c.session_id = ? AND c.status = 'proposed'
		ORDER BY c.score DESC`, sessionID)
	if err != nil {
		fatal("consultar candidatos: %v", err)
	}
	defer rows.Close()

	type candRow struct {
		id, source, tool, cmdRendered, explanation string
		score                                       float64
		hypothesisID, objectiveID                   sql.NullString
	}
	var all []candRow
	for rows.Next() {
		var c candRow
		if err := rows.Scan(&c.id, &c.source, &c.tool, &c.cmdRendered, &c.score, &c.explanation, &c.hypothesisID, &c.objectiveID); err != nil {
			fatal("leer candidato: %v", err)
		}
		all = append(all, c)
	}

	// `focus` reordena (NUNCA oculta) — los candidatos relacionados al focus
	// activo pasan primero, conservando el orden por score dentro de cada
	// grupo (partición estable, dos pasadas sobre la lista ya ordenada).
	f, err := focus.Get(s, sessionID)
	if err != nil {
		fatal("leer focus: %v", err)
	}
	ordered := all
	if f != nil {
		related := func(c candRow) bool {
			switch f.RefType {
			case "hypothesis":
				return c.hypothesisID.Valid && c.hypothesisID.String == f.RefID
			case "objective":
				return c.objectiveID.Valid && c.objectiveID.String == f.RefID
			}
			return false
		}
		var first, rest []candRow
		for _, c := range all {
			if related(c) {
				first = append(first, c)
			} else {
				rest = append(rest, c)
			}
		}
		ordered = append(first, rest...)
		if !raw && len(first) > 0 {
			fmt.Printf("Focus activo: %s %s — candidatos relacionados primero\n\n", f.RefType, f.RefID[:8])
		}
	}

	if !raw {
		if warning, err := strategy.DetectRabbitHole(s, sessionID); err != nil {
			fatal("evaluar rabbit-hole: %v", err)
		} else if warning != nil {
			printRabbitHoleWarning(warning, f)
		}
	}

	if len(ordered) == 0 && !raw {
		fmt.Println("No hay candidatos pendientes. Corre `exitone ingest nmap <archivo>` primero, o `exitone status`.")
		return
	}
	for i, c := range ordered {
		if raw {
			// --raw: solo el top-1, texto plano listo para insertar en el
			// buffer del shell (Ctrl+Space) — nunca se ejecuta desde aquí.
			if i == 0 {
				fmt.Println(c.cmdRendered)
			}
			continue
		}
		fmt.Printf("%d. [%s] %s — score %.2f (id %s)\n", i+1, c.source, c.tool, c.score, c.id[:8])
		fmt.Printf("   %s\n", c.cmdRendered)
	}
}

// printRabbitHoleWarning — sección K.3 del plan: `focus` NUNCA suprime el
// aviso, solo lo anota. Human-in-the-loop no significa "dejar de advertir
// cuando el operador elige seguir en una rama estancada" — el operador
// conserva la autoridad de seguir ahí, ExitOne conserva la obligación de
// decirlo.
func printRabbitHoleWarning(w *strategy.RabbitHoleWarning, f *focus.Focus) {
	focusedHere := f != nil && f.RefType == "objective" && f.RefID == w.StagnantObjectiveID
	if focusedHere {
		fmt.Printf("Operator focus: %s\n", w.StagnantIntentKey)
		fmt.Println("Branch appears stagnant.")
		fmt.Println("Recommendation retained because focus is explicit.")
		fmt.Printf("(%d intentos de %q sin evidencia nueva)\n\n", w.AttemptCount, w.StagnantIntentKey)
		return
	}
	fmt.Printf("⚠ Rama estancada: %d intentos de %q sin evidencia nueva.\n", w.AttemptCount, w.StagnantIntentKey)
	fmt.Printf("  Despriorizar esta rama. Investigar en su lugar: %s\n\n", w.AlternativeDescription)
}

func cmdWhy(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone why <candidate-id-prefix | hypothesis-id-prefix>")
	}
	prefix := args[0]
	var id, explanation, scoreTermsJSON string
	var score float64
	err := s.DB.QueryRow(`
		SELECT id, explanation, score, score_terms FROM candidate
		WHERE id LIKE ? || '%' ORDER BY created_at DESC LIMIT 1`, prefix,
	).Scan(&id, &explanation, &score, &scoreTermsJSON)
	if err == sql.ErrNoRows {
		// No es un candidato — se intenta como hipótesis (Fase 3 del plan:
		// `why` responde igual para ambos conceptos, cada uno con su propio
		// formato de explicación).
		exp, hypErr := hypothesis.Explain(s, prefix)
		if hypErr != nil {
			fatal("no se encontró un candidato ni una hipótesis con prefijo %q", prefix)
		}
		fmt.Printf("Hipótesis %s\n\nStatus: %s\n\n%s\n\n", prefix, strings.ToUpper(string(exp.Status)), exp.Statement)
		fmt.Printf("Supporting observations: %d\n", exp.SupportingObservations)
		fmt.Printf("Contradicting observations: %d\n", exp.ContradictingObservations)
		return
	}
	if err != nil {
		fatal("consultar candidato: %v", err)
	}
	fmt.Printf("Candidato %s — score %.2f\n\n%s\n\n", id[:8], score, explanation)
	var terms map[string]float64
	json.Unmarshal([]byte(scoreTermsJSON), &terms)
	fmt.Println("Términos del score:")
	for k, v := range terms {
		fmt.Printf("  %-22s %.2f\n", k, v)
	}
}

func cmdStatus(s *store.Store) {
	sessionID := currentSession(s)

	var label string
	s.DB.QueryRow(`SELECT target_label FROM session WHERE id = ?`, sessionID).Scan(&label)
	fmt.Printf("Sesión: %s\n\n", label)

	fmt.Println("Entidades:")
	rows, _ := s.DB.Query(`SELECT type, canonical_value, attrs FROM entity WHERE session_id = ? ORDER BY type, canonical_value`, sessionID)
	for rows.Next() {
		var t, v, attrsJSON string
		rows.Scan(&t, &v, &attrsJSON)
		marker := "confirmed"
		var attrs map[string]any
		if json.Unmarshal([]byte(attrsJSON), &attrs) == nil {
			if attrs["extracted_by"] == "llm" {
				conf, _ := attrs["confidence"].(float64)
				marker = fmt.Sprintf("INFERRED-LLM conf=%.2f", conf)
			} else if src, ok := attrs["source"].(string); ok && src != "" && src != "nmap" && src != "smbclient" {
				// source=manual/operator_hypothesis/etc: no es evidencia
				// determinista de una herramienta, es una asunción del
				// operador — no debe mostrarse como "confirmed" a secas.
				marker = fmt.Sprintf("USER_PROVIDED (%s)", src)
			}
		}
		fmt.Printf("  %-10s %-30s [%s]\n", t, v, marker)
	}
	rows.Close()

	fmt.Println("\nMethodology objectives:")
	oRows, _ := s.DB.Query(`SELECT id, intent_key, status FROM methodology_objective WHERE session_id = ?`, sessionID)
	for oRows.Next() {
		var oid, intent, status string
		oRows.Scan(&oid, &intent, &status)
		fmt.Printf("  %s [%s] (%s)\n", intent, status, oid[:8])
		pRows, _ := s.DB.Query(`SELECT path_key, status, description FROM objective_path WHERE objective_id = ?`, oid)
		for pRows.Next() {
			var pk, pstatus, desc string
			pRows.Scan(&pk, &pstatus, &desc)
			mark := "?"
			switch pstatus {
			case "answered":
				mark = "✓"
			case "blocked":
				mark = "x"
			}
			fmt.Printf("    %s %-22s %s\n", mark, pk, desc)
		}
		pRows.Close()
	}
	oRows.Close()
}

func cmdAccept(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone accept <candidate-id-prefix>")
	}
	prefix := args[0]
	var candID, sessionID, intentKey string
	var objectivePathID sql.NullString
	err := s.DB.QueryRow(
		`SELECT id, session_id, objective_path_id, intent_key FROM candidate WHERE id LIKE ? || '%' AND status = 'proposed' LIMIT 1`,
		prefix,
	).Scan(&candID, &sessionID, &objectivePathID, &intentKey)
	if err == sql.ErrNoRows {
		fatal("no se encontró un candidato pendiente con prefijo %q", prefix)
	}
	if err != nil {
		fatal("consultar candidato: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	actionID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO action(id, candidate_id, objective_path_id, executed_at) VALUES (?, ?, ?, ?)`,
		actionID, candID, objectivePathID, now,
	); err != nil {
		fatal("registrar acción: %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE candidate SET status = 'accepted' WHERE id = ?`, candID); err != nil {
		fatal("actualizar candidato: %v", err)
	}

	// Sección D1: para acciones que dependen de "qué identidades se conocen",
	// registramos TODO el conjunto conocido en ese instante como asunción —
	// no solo la identidad probada. Esto es lo que permite al Temporal
	// Reasoner calcular gap = known_now - known_at_test_time más adelante,
	// por comparación de conjuntos, sin interpretar texto.
	if intentKey == "test_ssh_auth" {
		idRows, err := s.DB.Query(`SELECT id FROM entity WHERE session_id = ? AND type = 'identity'`, sessionID)
		if err != nil {
			fatal("consultar identidades conocidas: %v", err)
		}
		for idRows.Next() {
			var entID string
			if err := idRows.Scan(&entID); err != nil {
				idRows.Close()
				fatal("leer identidad: %v", err)
			}
			assumptionID := uuid.NewString()
			if _, err := s.DB.Exec(
				`INSERT INTO action_assumption(id, action_id, entity_id, role) VALUES (?, ?, ?, 'known_identity')`,
				assumptionID, actionID, entID,
			); err != nil {
				idRows.Close()
				fatal("registrar asunción: %v", err)
			}
		}
		idRows.Close()
	}

	// Decision Context (sección D2): snapshot mínimo de lo conocido en este momento.
	var facts []string
	rows, _ := s.DB.Query(`SELECT type || ':' || canonical_value FROM entity WHERE session_id = ?`, sessionID)
	for rows.Next() {
		var f string
		rows.Scan(&f)
		facts = append(facts, f)
	}
	rows.Close()
	factsJSON, _ := json.Marshal(facts)

	motivating := ""
	if objectivePathID.Valid {
		motivating = objectivePathID.String
	}

	dcID := uuid.NewString()
	if _, err := s.DB.Exec(
		`INSERT INTO decision_context(id, action_id, known_facts_snapshot, known_unknowns_snapshot, motivating_objective, rationale_text)
		 VALUES (?, ?, ?, '[]', ?, 'aceptado vía exitone accept')`,
		dcID, actionID, string(factsJSON), motivating,
	); err != nil {
		fatal("registrar decision context: %v", err)
	}

	fmt.Printf("Acción registrada: %s (candidato %s aceptado)\n", actionID[:8], candID[:8])
	if intentKey == "test_ssh_auth" {
		fmt.Println("Cuando tengas el resultado, corre `exitone resolve " + actionID[:8] + " --result fail|success`.")
	} else {
		fmt.Println("Cuando tengas el resultado, ingiere la nueva evidencia con `--for-action " + actionID[:8] + "` para medir el outcome.")
	}
}

func cmdResolve(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone resolve <action-id-prefix> --result <fail|success>")
	}
	rest, flags := parseFlags(args)
	if len(rest) < 1 {
		fatal("uso: exitone resolve <action-id-prefix> --result <fail|success>")
	}
	result := flags["result"]
	if result == "" {
		fatal("falta --result <fail|success>")
	}
	sessionID := currentSession(s)

	// Fase 3 del plan de arquitectura: ya no se crea una hypothesis por cada
	// intento — la cobertura (qué identidades ya se probaron) la refleja
	// directamente la tabla `candidate` (ver internal/strategy/ssh.go).
	actionID, err := outcome.RecordManualResult(s, rest[0], result)
	if err != nil {
		fatal("registrar resultado: %v", err)
	}
	fmt.Printf("Resultado registrado: acción %s (%s)\n", actionID[:8], result)

	generateCandidates(s, sessionID)
}

func cmdDismiss(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone dismiss <candidate-id-prefix>")
	}
	res, err := s.DB.Exec(`UPDATE candidate SET status = 'dismissed' WHERE id LIKE ? || '%' AND status = 'proposed'`, args[0])
	if err != nil {
		fatal("descartar candidato: %v", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		fatal("no se encontró un candidato pendiente con prefijo %q", args[0])
	}
	fmt.Println("Candidato descartado.")
}

// cmdFocus — Fase 2 del plan de arquitectura: dónde quiere el operador
// invertir esfuerzo ahora mismo. Siempre explícito (esta función es la
// ÚNICA forma de fijarlo), nunca inferido — a diferencia de `stage`.
func cmdFocus(s *store.Store, args []string) {
	sessionID := currentSession(s)

	if len(args) == 0 {
		f, err := focus.Get(s, sessionID)
		if err != nil {
			fatal("leer focus: %v", err)
		}
		if f == nil {
			fmt.Println("Sin focus activo.")
			return
		}
		fmt.Printf("Focus activo: %s %s (fijado %s)\n", f.RefType, f.RefID[:8], f.SetAt)
		return
	}

	if args[0] == "clear" {
		if err := focus.Clear(s, sessionID); err != nil {
			fatal("limpiar focus: %v", err)
		}
		fmt.Println("Focus limpiado.")
		return
	}

	refType, refID, err := focus.Resolve(s, sessionID, args[0])
	if err != nil {
		fatal("%v", err)
	}
	if err := focus.Set(s, sessionID, refType, refID); err != nil {
		fatal("fijar focus: %v", err)
	}
	fmt.Printf("Focus fijado: %s %s\n", refType, refID[:8])
}

func cmdStages(s *store.Store) {
	sessionID := currentSession(s)
	stages, err := stage.Estimate(s, sessionID)
	if err != nil {
		fatal("estimar etapas: %v", err)
	}
	for _, st := range stages {
		fmt.Printf("%-24s %-12s %s\n", st.Name, st.Status, st.Reason)
	}
}

func cmdAsk(s *store.Store, args []string) {
	if len(args) < 1 {
		fatal("uso: exitone ask \"<pregunta>\"")
	}
	question := strings.Join(args, " ")
	sessionID := currentSession(s)

	contextSummary, err := llm.BuildContextSummary(s, sessionID)
	if err != nil {
		fatal("construir contexto: %v", err)
	}

	client := llm.New()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	answer, err := llm.Ask(ctx, client, s, sessionID, contextSummary, question)
	if err != nil {
		debuglog.LogError("ask_failed", err, map[string]any{"question": question})
		fatal("consulta al LLM falló: %v", err)
	}
	debuglog.Log("ask", map[string]any{"question": question, "context": contextSummary, "answer": answer})

	fmt.Println(answer)
}
