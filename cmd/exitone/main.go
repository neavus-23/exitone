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
	"strconv"
	"strings"
	"syscall"
	"time"

	"context"

	"exitone/internal/activity"
	credentialstore "exitone/internal/credential"
	"exitone/internal/debuglog"
	"exitone/internal/focus"
	"exitone/internal/hypothesis"
	"exitone/internal/ingestsource"
	"exitone/internal/investigation"
	"exitone/internal/llm"
	"exitone/internal/methodology"
	"exitone/internal/outcome"
	"exitone/internal/parsers"
	"exitone/internal/report"
	"exitone/internal/scope"
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fatal("no se pudo crear %s: %v", dir, err)
	}
	_ = os.Chmod(dir, 0o700)
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
	_ = os.Chmod(dbPath(), 0o600)

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
	case "observe-event":
		cmdObserveEvent(s, args)
	case "credential", "credentials":
		cmdCredential(s, args)
	case "observation", "observations":
		cmdObservation(s, args)
	case "hypothesis", "hypotheses":
		cmdHypothesis(s, args)
	case "objective", "objectives":
		cmdObjective(s, args)
	case "scope":
		cmdScope(s, args)
	case "report":
		cmdReport(s, args)
	case "strategy-worker":
		cmdStrategyWorker(s, args)
	case "events":
		cmdEvents(s, args)
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

// printUsage sigue el formato de industria de `nmap` (OPTIONS SUMMARY: lo
// que se imprime al correr la herramienta sin argumentos) — encabezados de
// sección en MAYÚSCULA, una línea por comando con "args: descripción corta"
// separados por ":", agrupados por tarea (no alfabético, no por nombre
// interno de función), y un bloque de EJEMPLOS al final con comandos reales
// copiables. Sin prosa envuelta en paréntesis multi-línea — si un comando
// necesita más detalle del que entra en una línea, para eso está
// `exitone help <comando>` (o `help <comando>` dentro de la consola).
func printUsage() {
	fmt.Println(`exitone ( investigación de seguridad asistida por IA — observa, correlaciona, sugiere; el humano decide y ejecuta )
Usage: exitone <comando> [opciones]

ARRANQUE:
  start [target] [--tmux] [--session-name <n>] [--detach]: abrir la TUI — sin target, ella pregunta qué workspace usar/crear
  tui: la TUI directo (mismo onboarding que start sin target)
  session new <target-label> [--fresh]: crear/resumir un workspace sin abrir la TUI

EVIDENCIA:
  ingest <archivo> [--tool <hint>] [--host <ip>]: ingerir evidencia — detecta el formato solo; --host solo si hay 2+ hosts conocidos
  ingest identities <archivo> --source <origen>: declarar identidades ya conocidas
  ingest watch <directorio>: observar un directorio e ingerir cada archivo nuevo automáticamente
  credential add --value <secreto> [--identity <ref>] [--service <ref>] [--source <ref>]: registrar una credencial
  credential list [--reveal]: listar credenciales (enmascaradas salvo --reveal)
  credential attempt [id] --result success|fail|unknown [--service <ref>]: registrar un intento — sin id, solo si hay 1 credencial
  credential update [id] [--identity <ref>] [--service <ref>]: vincular identidad/servicio a una credencial ya guardada
  report [--reveal] [--raw] [--out <archivo>]: informe final redactado por el LLM a partir de datos reales (--raw: versión determinista)

ESTRATEGIA:
  next [--raw]: próximas sugerencias, rankeadas por score
  why [candidate-id]: por qué se sugirió un candidato — sin id, solo si hay 1 pendiente
  accept [candidate-id]: aceptar un candidato, NUNCA lo ejecuta — sin id, solo si hay 1 pendiente
  resolve [action-id] --result fail|success: cerrar una acción aceptada con su resultado real
  dismiss [candidate-id]: descartar una sugerencia — sin id, solo si hay 1 pendiente
  focus [id|clear]: dónde invertir esfuerzo ahora — siempre explícito, nunca inferido a propósito
  hypothesis <list|open|support|contradict|confirm|refute> ...: ciclo explícito de hipótesis falsables
  objective <list|add|complete|abandon> [id]: objetivos finales del operador — complete/abandon sin id, solo si hay 1 abierto
  observation <list|confirm|reject> [id]: revisar observaciones candidatas del LLM — sin id, solo si hay 1 pendiente
  scope <add|list|remove> <patrón> [--out] [--note "..."]: qué assets están autorizados a tocarse

ESTADO:
  status: estado completo — entidades, relaciones, objectives
  stages: etapas de la investigación (NOT_STARTED/ACTIVE/SUFFICIENT/...)
  events [--tail N]: eventos recientes y su asociación automática con acciones
  watch [--interval <s>]: dashboard en vivo, solo lectura
  ask "<pregunta>": consulta en lenguaje natural anclada al estado real — también disponible sin salir de la TUI (modo Chat)

EJEMPLOS:
  exitone start
  exitone start 10.10.10.5
  exitone ingest nmap_scan.txt
  exitone accept
  exitone report --reveal --out informe.md

Ningún comando "sin id" adivina entre 2+ candidatos elegibles — ante
ambigüedad, sigue pidiendo el id explícito y los lista. Ayuda detallada de
un comando puntual (aliases incluidos): dentro de la consola (exitone sin
argumentos), "help <comando>".`)
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
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
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
	result, err := activity.Observe(s, activity.EventInput{
		SessionID: sessionID,
		Pane:      pane,
		Command:   meta.Command,
		Cwd:       meta.Cwd,
		StartedAt: epochToRFC3339(meta.StartedAt),
		EndedAt:   epochToRFC3339(meta.EndedAt),
		ExitCode:  meta.ExitCode,
		Source:    "shell_hook",
	})
	if err != nil {
		debuglog.LogError("resolve_event_insert", err, map[string]any{"raw": eventJSON})
		return ""
	}
	debuglog.Log("event_observed", map[string]any{
		"event": result.EventID, "link_status": result.LinkStatus,
		"action": result.ActionID, "candidate": result.CandidateID,
	})
	return result.EventID
}

func cmdObserveEvent(s *store.Store, args []string) {
	_, flags := parseFlags(args)
	if flags["event"] == "" {
		fatal("uso: exitone observe-event --event '<json>'")
	}
	eventID := resolveEvent(s, currentSession(s), flags["event"])
	if eventID == "" {
		fatal("no se pudo registrar el evento")
	}
	var status string
	_ = s.DB.QueryRow(`SELECT link_status FROM event WHERE id = ?`, eventID).Scan(&status)
	fmt.Printf("Evento observado: %s [%s]\n", eventID[:8], status)
}

func cmdCredential(s *store.Store, args []string) {
	if len(args) == 0 {
		fatal("uso: exitone credential <add|list|attempt|update> ...")
	}
	sessionID := currentSession(s)
	switch args[0] {
	case "update":
		rest, flags := parseFlags(args[1:])
		if flags["identity"] == "" && flags["service"] == "" {
			fatal("uso: exitone credential update [id] [--identity <ref>] [--service <ref>]")
		}
		ref := ""
		if len(rest) >= 1 {
			ref = rest[0]
		}
		id := mustSole(resolveSoleCredentialID(s, sessionID, ref), ref, "credencial")
		if err := credentialstore.SetLinks(s, sessionID, id, flags["identity"], flags["service"]); err != nil {
			fatal("actualizar credencial: %v", err)
		}
		fmt.Println("Credencial actualizada.")
	case "add":
		_, flags := parseFlags(args[1:])
		if flags["value"] == "" {
			fatal("uso: exitone credential add --value <secret> [--identity <ref>] [--service <ref>] [--source <ref>]")
		}
		id, err := credentialstore.Add(s, sessionID, flags["identity"], flags["service"], flags["value"], flags["source"])
		if err != nil {
			fatal("guardar credencial: %v", err)
		}
		fmt.Printf("Credencial guardada: %s (valor enmascarado por defecto)\n", id[:8])
	case "list":
		_, flags := parseFlags(args[1:])
		_, reveal := flags["reveal"]
		items, err := credentialstore.List(s, sessionID, reveal)
		if err != nil {
			fatal("listar credenciales: %v", err)
		}
		for _, c := range items {
			fmt.Printf("%s  identity=%q service=%q value=%q status=%s source=%q\n", c.ID[:8], c.Identity, c.Service, c.Value, c.Status, c.Source)
		}
		if len(items) == 0 {
			fmt.Println("No hay credenciales registradas.")
		}
	case "attempt":
		rest, flags := parseFlags(args[1:])
		if flags["result"] == "" {
			fatal("uso: exitone credential attempt [id] --result success|fail|unknown [--service <ref>] [--event <ref>]")
		}
		ref := ""
		if len(rest) >= 1 {
			ref = rest[0]
		}
		credID := mustSole(resolveSoleCredentialID(s, sessionID, ref), ref, "credencial")
		id, err := credentialstore.RecordAttempt(s, sessionID, credID, flags["service"], flags["event"], flags["result"])
		if err != nil {
			fatal("registrar intento: %v", err)
		}
		fmt.Printf("Intento de credencial registrado: %s\n", id[:8])
	default:
		fatal("subcomando credential desconocido: %s", args[0])
	}
}

func cmdScope(s *store.Store, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sessionID := currentSession(s)
	switch args[0] {
	case "list":
		rules, err := scope.List(s, sessionID)
		if err != nil {
			fatal("listar scope: %v", err)
		}
		for _, rule := range rules {
			mode := "IN"
			if !rule.InScope {
				mode = "OUT"
			}
			fmt.Printf("%s  %-3s  %-30s %s\n", rule.ID[:8], mode, rule.Pattern, rule.Note)
		}
		if len(rules) == 0 {
			fmt.Println("No hay reglas de scope registradas.")
		}
	case "add":
		rest, flags := parseFlags(args[1:])
		if len(rest) == 0 {
			fatal("uso: exitone scope add <pattern> [--out] [--note <texto>]")
		}
		_, out := flags["out"]
		id, err := scope.Add(s, sessionID, rest[0], !out, flags["note"])
		if err != nil {
			fatal("agregar scope: %v", err)
		}
		fmt.Printf("Regla de scope guardada: %s\n", id[:8])
	case "remove":
		if len(args) < 2 {
			fatal("uso: exitone scope remove <id|pattern>")
		}
		if err := scope.Remove(s, sessionID, args[1]); err != nil {
			fatal("eliminar scope: %v", err)
		}
		fmt.Println("Regla de scope eliminada.")
	default:
		fatal("subcomando scope desconocido: %s", args[0])
	}
}

// cmdReport genera el informe final de la investigación (sección
// "Persistencia y documentación" del pedido: reconstruir cronología,
// intentos fallidos, credenciales, hipótesis y outcomes). El dato de fondo
// SIEMPRE sale de filas reales (report.LoadFindings/LoadTimeline/etc.) —
// nunca inventado; por defecto, la prosa (resumen ejecutivo, narrativa de
// cada hallazgo, narrativa de la cronología) la redacta el LLM en llamadas
// pequeñas y acotadas por sección (mismo principio "Go razona, LLM redacta"
// que ask/guide/explain) — nunca en una sola llamada monolítica: se probó en
// vivo y un modelo local de 3B trunca y corrompe datos al pedirle reescribir
// el documento completo de una sola vez. `--raw` se salta la redacción y
// entrega el determinista tal cual — útil si el LLM local no está
// disponible o si se prefiere el dato crudo para procesar por script.
func cmdReport(s *store.Store, args []string) {
	_, flags := parseFlags(args)
	sessionID := currentSession(s)
	_, reveal := flags["reveal"]
	_, raw := flags["raw"]

	var md string
	var err error
	if raw {
		md, err = report.Generate(s, sessionID, reveal)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		client := llm.New()
		narrator := report.Narrator{
			Summary:  func(text string) (string, error) { return llm.SummarizeFindings(ctx, client, text) },
			Finding:  func(text string) (string, error) { return llm.NarrateFinding(ctx, client, text) },
			Timeline: func(text string) (string, error) { return llm.NarrateTimeline(ctx, client, text) },
		}
		md, err = report.GenerateNarrative(s, sessionID, reveal, narrator)
	}
	if err != nil {
		fatal("generar reporte: %v", err)
	}

	if out := flags["out"]; out != "" {
		if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
			fatal("escribir reporte en %s: %v", out, err)
		}
		fmt.Printf("Reporte escrito en %s\n", out)
		return
	}
	fmt.Print(md)
}

func cmdObservation(s *store.Store, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sessionID := currentSession(s)
	switch args[0] {
	case "list":
		rows, err := s.DB.Query(`SELECT o.id, o.kind, o.payload, o.confidence, o.status
			FROM observation o JOIN evidence ev ON ev.id = o.evidence_id
			LEFT JOIN event e ON e.id = ev.event_id
			WHERE (e.session_id = ? OR EXISTS (
				SELECT 1 FROM observation_entity oe JOIN entity en ON en.id = oe.entity_id
				WHERE oe.observation_id = o.id AND en.session_id = ?))
			ORDER BY ev.created_at DESC`, sessionID, sessionID)
		if err != nil {
			fatal("listar observaciones: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, kind, payload, status string
			var confidence float64
			if err := rows.Scan(&id, &kind, &payload, &confidence, &status); err != nil {
				fatal("leer observación: %v", err)
			}
			if kind == "credential" {
				payload = "<credential candidate redacted>"
			}
			fmt.Printf("%s  %-12s conf=%.2f status=%-10s %s\n", id[:8], kind, confidence, status, payload)
		}
	case "confirm", "reject":
		// <id> es opcional: si se omite y hay exactamente 1 observación
		// 'candidate' en la sesión, se usa esa (resolveObservationID).
		ref := ""
		if len(args) >= 2 {
			ref = args[1]
		}
		observationID := resolveObservationID(s, sessionID, ref)
		if args[0] == "reject" {
			if _, err := s.DB.Exec(`UPDATE observation SET status = 'superseded' WHERE id = ?`, observationID); err != nil {
				fatal("rechazar observación: %v", err)
			}
			fmt.Printf("Observación %s rechazada.\n", observationID[:8])
			return
		}
		if _, err := s.DB.Exec(`UPDATE observation SET status = 'active' WHERE id = ?`, observationID); err != nil {
			fatal("confirmar observación: %v", err)
		}
		rows, err := s.DB.Query(`SELECT entity_id FROM observation_entity WHERE observation_id = ?`, observationID)
		if err != nil {
			fatal("resolver entidades: %v", err)
		}
		var entityIDs []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			entityIDs = append(entityIDs, id)
		}
		rows.Close()
		if _, err := methodology.EvaluateTriggers(s, sessionID, entityIDs); err != nil {
			fatal("evaluar metodología confirmada: %v", err)
		}
		generateCandidates(s, sessionID)
		scheduleStrategyRefresh(s, sessionID)
		fmt.Printf("Observación %s confirmada; metodología reevaluada.\n", observationID[:8])
	default:
		fatal("subcomando observation desconocido: %s", args[0])
	}
}

func cmdStrategyWorker(s *store.Store, args []string) {
	if len(args) != 2 {
		fatal("uso interno: exitone strategy-worker <session-id> <revision>")
	}
	revision, err := strconv.ParseInt(args[1], 10, 64)
	if err != nil {
		fatal("revisión inválida: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	created, err := strategy.RunExploration(ctx, s, args[0], revision)
	if err != nil {
		debuglog.LogError("strategy_worker", err, map[string]any{"session": args[0], "revision": revision})
		fmt.Printf("strategy revision=%d status=failed error=%s\n", revision, debuglog.RedactText(err.Error()))
		return // degradación no fatal: la ingesta que encoló el trabajo ya terminó
	}
	debuglog.Log("strategy_worker", map[string]any{"session": args[0], "revision": revision, "created": created})
	var status string
	_ = s.DB.QueryRow(`SELECT status FROM strategy_job WHERE session_id = ? AND revision = ?`, args[0], revision).Scan(&status)
	fmt.Printf("strategy revision=%d status=%s candidates=%d\n", revision, status, created)
}

func cmdEvents(s *store.Store, args []string) {
	_, flags := parseFlags(args)
	limit := 20
	if flags["tail"] != "" {
		if parsed, err := strconv.Atoi(flags["tail"]); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	rows, err := s.DB.Query(`SELECT e.id, e.command_raw, e.exit_code, e.link_status, COALESCE(a.id,''), COALESCE(e.ended_at,'')
		FROM event e LEFT JOIN action_event ae ON ae.event_id=e.id LEFT JOIN action a ON a.id=ae.action_id
		WHERE e.session_id=? ORDER BY COALESCE(e.ended_at,e.started_at) DESC LIMIT ?`, currentSession(s), limit)
	if err != nil {
		fatal("listar eventos: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, command, link, actionID, ended string
		var exitCode int
		if err := rows.Scan(&id, &command, &exitCode, &link, &actionID, &ended); err != nil {
			fatal("leer evento: %v", err)
		}
		shortAction := "-"
		if len(actionID) >= 8 {
			shortAction = actionID[:8]
		}
		fmt.Printf("%s exit=%d link=%-9s action=%s %s  %s\n", id[:8], exitCode, link, shortAction, ended, debuglog.RedactText(command))
	}
}

func scheduleStrategyRefresh(s *store.Store, sessionID string) {
	revision, err := strategy.EnqueueExploration(s, sessionID)
	if err != nil {
		debuglog.LogError("strategy_enqueue", err, map[string]any{"session": sessionID})
		return
	}
	self, err := os.Executable()
	if err != nil {
		debuglog.LogError("strategy_spawn", err, nil)
		return
	}
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".exitone", "strategy-worker.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		debuglog.LogError("strategy_spawn", err, map[string]any{"log": logPath})
		return
	}
	cmd := exec.Command(self, "strategy-worker", sessionID, strconv.FormatInt(revision, 10))
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		debuglog.LogError("strategy_spawn", err, map[string]any{"session": sessionID, "revision": revision})
		return
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()
	fmt.Printf("Razonamiento exploratorio encolado en background (revisión %d).\n", revision)
}

func cmdHypothesis(s *store.Store, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sessionID := currentSession(s)
	switch args[0] {
	case "list":
		rows, err := s.DB.Query(`SELECT id, statement, status FROM hypothesis WHERE session_id = ? ORDER BY opened_at`, sessionID)
		if err != nil {
			fatal("listar hipótesis: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, statement, status string
			_ = rows.Scan(&id, &statement, &status)
			fmt.Printf("%s  [%s] %s\n", id[:8], status, statement)
		}
	case "open":
		// <entity-ref> se mantiene requerido a propósito: a diferencia de
		// support/contradict (dos IDs sueltos, nunca ambiguos entre sí),
		// acá el segundo argumento en adelante es TEXTO LIBRE (el statement)
		// — no hay forma confiable de distinguir "el operador omitió el
		// entity-ref" de "el statement da la casualidad de tener 1-2
		// palabras" solo contando argumentos. Auto-resolver esto arriesgaría
		// adivinar mal en silencio, justo lo que este rediseño evita en
		// todos los demás casos.
		if len(args) < 3 {
			fatal("uso: exitone hypothesis open <entity-ref> <statement>")
		}
		entityID := resolveAnyEntity(s, sessionID, args[1])
		id, err := hypothesis.Open(s, sessionID, entityID, strings.Join(args[2:], " "))
		if err != nil {
			fatal("abrir hipótesis: %v", err)
		}
		fmt.Printf("Hipótesis abierta: %s\n", id[:8])
	case "support", "contradict":
		// Ambos IDs son opcionales de forma independiente — cada uno se
		// resuelve solo si hay exactamente 1 candidata elegible de ese tipo.
		hypRef, obsRef := "", ""
		if len(args) >= 2 {
			hypRef = args[1]
		}
		if len(args) >= 3 {
			obsRef = args[2]
		}
		hypID := resolveHypothesisID(s, sessionID, hypRef)
		obsID := resolveObservationID(s, sessionID, obsRef)
		var err error
		if args[0] == "support" {
			err = hypothesis.Support(s, hypID, obsID)
		} else {
			err = hypothesis.Contradict(s, hypID, obsID)
		}
		if err != nil {
			fatal("actualizar hipótesis: %v", err)
		}
		fmt.Printf("Hipótesis %s actualizada con observación %s.\n", hypID[:8], obsID[:8])
	case "confirm", "refute":
		// <id> es opcional: si se omite y hay exactamente 1 hipótesis
		// 'untested' en la sesión, se usa esa (resolveHypothesisID).
		rest, flags := parseFlags(args[1:])
		ref := ""
		if len(rest) >= 1 {
			ref = rest[0]
		}
		id := resolveHypothesisID(s, sessionID, ref)
		details := hypothesis.FindingDetails{
			Severity:     flags["severity"],
			Remediation:  flags["remediation"],
			EvidenceNote: flags["evidence"],
		}
		var err error
		if args[0] == "confirm" {
			err = hypothesis.Confirm(s, id, details)
		} else {
			err = hypothesis.Refute(s, id, details)
		}
		if err != nil {
			fatal("cerrar hipótesis: %v", err)
		}
		fmt.Printf("Hipótesis %s cerrada como %s.\n", id[:8], args[0])
	default:
		fatal("subcomando hypothesis desconocido: %s", args[0])
	}
}

func cmdObjective(s *store.Store, args []string) {
	if len(args) == 0 {
		args = []string{"list"}
	}
	sessionID := currentSession(s)
	switch args[0] {
	case "list":
		rows, err := s.DB.Query(`SELECT id, statement, status, COALESCE(evidence_ref,'') FROM operator_objective WHERE session_id = ? ORDER BY created_at`, sessionID)
		if err != nil {
			fatal("listar objetivos: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var id, statement, status, evidence string
			_ = rows.Scan(&id, &statement, &status, &evidence)
			fmt.Printf("%s  [%s] %s evidence=%q\n", id[:8], status, statement, evidence)
		}
	case "add":
		if len(args) < 2 {
			fatal("uso: exitone objective add <statement>")
		}
		id := uuid.NewString()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`INSERT INTO operator_objective(id, session_id, statement, status, created_at) VALUES (?, ?, ?, 'open', ?)`, id, sessionID, strings.Join(args[1:], " "), now); err != nil {
			fatal("crear objetivo: %v", err)
		}
		fmt.Printf("Objetivo creado: %s\n", id[:8])
	case "complete", "abandon":
		rest, flags := parseFlags(args[1:])
		// <id> es opcional: si se omite y hay exactamente 1 objective
		// 'open' en la sesión, se usa ese — nunca si hay 0 o 2+.
		ref := ""
		if len(rest) >= 1 {
			ref = rest[0]
		}
		var ids []string
		if ref == "" {
			ids = resolveSole(s, `SELECT id FROM operator_objective WHERE session_id = ? AND status = 'open'`, sessionID)
		} else {
			ids = resolveSole(s, `SELECT id FROM operator_objective WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, ref)
		}
		id := mustSole(ids, ref, "objetivo")
		status := "completed"
		if args[0] == "abandon" {
			status = "abandoned"
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := s.DB.Exec(`UPDATE operator_objective SET status = ?, evidence_ref = ?, completed_at = ? WHERE id = ?`, status, nullIfEmpty(flags["evidence"]), now, id); err != nil {
			fatal("actualizar objetivo: %v", err)
		}
		fmt.Printf("Objetivo %s marcado %s.\n", id[:8], status)
	default:
		fatal("subcomando objective desconocido: %s", args[0])
	}
}

// resolveSole junta los IDs que matchean `query` — se usa tanto para el
// camino "ref vacío, ¿hay una sola elegible?" como para el de ref no vacío,
// donde antes se elegía en silencio la más reciente ante un prefijo
// ambiguo (bug real corregido de paso: ahora ambos caminos pasan por
// mustSole, que nunca adivina entre 2+).
func resolveSole(s *store.Store, query string, args ...any) []string {
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		fatal("consultar candidatos: %v", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			fatal("leer candidato: %v", err)
		}
		ids = append(ids, id)
	}
	return ids
}

func shortIDs(ids []string) string {
	var out []string
	for _, id := range ids {
		out = append(out, id[:8])
	}
	return strings.Join(out, ", ")
}

// mustSole exige EXACTAMENTE un resultado — nunca adivina entre varios, ni
// siquiera por score/fecha. `ref` es lo que tecleó el operador ("" si lo
// omitió, confiando en que haya una sola candidata elegible); `label` es
// solo para el mensaje de error (ej. "entidad", "hipótesis").
func mustSole(ids []string, ref, label string) string {
	switch len(ids) {
	case 1:
		return ids[0]
	case 0:
		if ref == "" {
			fatal("no hay ningún(a) %s elegible en la sesión — indicá el ID explícito", label)
		}
		fatal("%s %q no encontrado(a)", label, ref)
	default:
		if ref == "" {
			fatal("hay %d %s(s) elegibles — especificá cuál: %s", len(ids), label, shortIDs(ids))
		}
		fatal("%q es ambiguo — coincide con %d %s(s): %s", ref, len(ids), label, shortIDs(ids))
	}
	panic("unreachable") // fatal() siempre termina el proceso (panic o os.Exit)
}

// resolveAnyEntity — si `ref` viene vacío, solo funciona cuando hay
// EXACTAMENTE una entidad en la sesión (nunca adivina cuál "la más
// relevante" entre varias).
func resolveAnyEntity(s *store.Store, sessionID, ref string) string {
	var ids []string
	if ref == "" {
		ids = resolveSole(s, `SELECT id FROM entity WHERE session_id = ?`, sessionID)
	} else {
		ids = resolveSole(s, `SELECT id FROM entity WHERE session_id = ? AND (id LIKE ? || '%' OR canonical_value = ?)`, sessionID, ref, ref)
	}
	return mustSole(ids, ref, "entidad")
}

// resolveHypothesisID — si `ref` viene vacío, solo funciona cuando hay
// EXACTAMENTE una hipótesis `untested` en la sesión.
func resolveHypothesisID(s *store.Store, sessionID, ref string) string {
	var ids []string
	if ref == "" {
		ids = resolveSole(s, `SELECT id FROM hypothesis WHERE session_id = ? AND status = 'untested'`, sessionID)
	} else {
		ids = resolveSole(s, `SELECT id FROM hypothesis WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, ref)
	}
	return mustSole(ids, ref, "hipótesis")
}

// resolveSoleCredentialID — si `ref` viene vacío, solo funciona cuando hay
// EXACTAMENTE una credencial en la sesión; si no, la resolución de prefijo
// real (incluida la ambigüedad de un prefijo de 2+ letras) la sigue
// haciendo `credentialstore.RecordAttempt`/`SetLinks` — acá solo importa
// distinguir 0/1/2+ para decidir si hace falta pedir el ID.
func resolveSoleCredentialID(s *store.Store, sessionID, ref string) []string {
	if ref == "" {
		return resolveSole(s, `SELECT id FROM credential WHERE session_id = ?`, sessionID)
	}
	return resolveSole(s, `SELECT id FROM credential WHERE session_id = ? AND id LIKE ? || '%'`, sessionID, ref)
}

// resolveObservationID — si `ref` viene vacío, solo funciona cuando hay
// EXACTAMENTE una observación `candidate` (sin confirmar/rechazar todavía)
// en la sesión.
func resolveObservationID(s *store.Store, sessionID, ref string) string {
	var ids []string
	if ref == "" {
		ids = resolveSole(s, `SELECT DISTINCT o.id FROM observation o JOIN observation_entity oe ON oe.observation_id = o.id JOIN entity e ON e.id = oe.entity_id WHERE e.session_id = ? AND o.status = 'candidate'`, sessionID)
	} else {
		ids = resolveSole(s, `SELECT DISTINCT o.id FROM observation o JOIN observation_entity oe ON oe.observation_id = o.id JOIN entity e ON e.id = oe.entity_id WHERE e.session_id = ? AND o.id LIKE ? || '%'`, sessionID, ref)
	}
	return mustSole(ids, ref, "observación")
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
			// --host es requerido salvo cuando hay EXACTAMENTE un host
			// conocido en la sesión — el output de smbclient no trae la IP
			// del server en ningún lado agnóstico a la herramienta, así que
			// sigue sin poder resolverse "de forma agnóstica" salvo por
			// este atajo de sesión.
			hosts := resolveSole(s, `SELECT canonical_value FROM entity WHERE session_id = ? AND type = 'host'`, sessionID)
			host = mustSole(hosts, "", "host")
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
	matched, outcomeID := autoRecordOutcome(s, sessionID, eventID, "generic_scan", res, pathResolved)
	if matched {
		fmt.Printf("Outcome auto-vinculado al evento observado: %s\n", outcomeID[:8])
	}

	generateCandidates(s, sessionID)
	if _, err := strategy.GenerateEndpointFollowupCandidates(s, sessionID, res.NewEntities); err != nil {
		fatal("generar candidatos de endpoint: %v", err)
	}
	scheduleStrategyRefresh(s, sessionID)
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
	scheduleStrategyRefresh(s, sessionID)
}

// stripSelfReferentialNoise quita, antes de mandarlo al LLM, cualquier línea
// que sea ExitOne hablando de sí mismo (su propio prefijo "[exitone] ..." de
// auto-captura, o una invocación literal "exitone <subcomando>" tecleada por
// el operador dentro de una shell obtenida en el target) — sin esto, una
// transcripción de shell que incluya esas líneas (ej. el operador corriendo
// `exitone next` dentro de una reverse shell para chequear algo) hace que el
// LLM reporte "exitone" como una tecnología observada EN EL TARGET. Bug real
// encontrado validando contra HTB Nexus.
func stripSelfReferentialNoise(raw string) string {
	lines := strings.Split(raw, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[exitone]") {
			continue
		}
		if strings.Contains(trimmed, "/exitone-dev/bin/exitone ") || strings.HasPrefix(trimmed, "exitone ") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
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

	sanitized := stripSelfReferentialNoise(string(raw))
	obs, err := llm.ExtractObservations(ctx, client, toolHint, sanitized)
	if err != nil {
		debuglog.LogError("ingest_raw_llm_extract", err, map[string]any{"tool": toolHint, "raw_len": len(raw)})
		absPath, _ := filepath.Abs(path)
		if _, storeErr := investigation.IngestUnparsed(s, absPath, eventID, toolHint); storeErr != nil {
			fatal("conservar evidencia sin parsear: %v", storeErr)
		}
		fmt.Printf("Evidencia conservada sin parsear; el LLM no está disponible: %v\n", err)
		scheduleStrategyRefresh(s, sessionID)
		return
	}
	debuglog.Log("ingest_raw_llm_extract", map[string]any{"tool": toolHint, "raw_len": len(raw), "observation_count": len(obs)})
	if len(obs) == 0 {
		absPath, _ := filepath.Abs(path)
		if _, err := investigation.IngestUnparsed(s, absPath, eventID, toolHint); err != nil {
			fatal("conservar evidencia sin observaciones: %v", err)
		}
		fmt.Println("El LLM no identificó observaciones candidatas; la evidencia se conservó igualmente.")
		scheduleStrategyRefresh(s, sessionID)
		return
	}

	absPath, _ := filepath.Abs(path)
	res, err := investigation.IngestGeneric(s, sessionID, absPath, eventID, toolHint, obs)
	if err != nil {
		fatal("ingerir evidencia Nivel 2: %v", err)
	}

	fmt.Printf("Extracción Nivel 2 (LLM, confianza ≤ 0.5, nunca FACT): %d observación(es) candidata(s)\n", len(obs))
	for _, o := range obs {
		value := o.Value
		if o.Kind == "credential" {
			value = credentialstore.Mask(value)
		}
		fmt.Printf("  [%s] %q (confidence %.2f)\n", o.Kind, value, o.Confidence)
	}
	fmt.Printf("%d entidad(es) nueva(s) creada(s), marcadas attrs.extracted_by=\"llm\"\n", len(res.NewEntities))

	// Las entidades siguen sin abrir metodología automáticamente. La estrategia
	// exploratoria sí puede citarlas como asunciones de baja confianza.
	scheduleStrategyRefresh(s, sessionID)
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
		matched, outcomeID := autoRecordOutcome(s, sessionID, eventID, "nmap", res, pathResolved)
		if matched {
			fmt.Printf("Outcome auto-vinculado a acción pendiente: %s\n", outcomeID[:8])
		}
	}
	generateCandidates(s, sessionID)
	scheduleStrategyRefresh(s, sessionID)
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
		matched, outcomeID := autoRecordOutcome(s, sessionID, eventID, "smbclient", res, pathResolved)
		if matched {
			fmt.Printf("Outcome auto-vinculado a acción pendiente: %s (path resuelto: %v)\n", outcomeID[:8], pathResolved)
		}
	}

	generateCandidates(s, sessionID)
	scheduleStrategyRefresh(s, sessionID)
}

func autoRecordOutcome(s *store.Store, sessionID, eventID, tool string, res *investigation.IngestResult, pathResolved bool) (bool, string) {
	matched, outcomeID, err := outcome.AutoRecordForEvent(s, eventID, res, pathResolved)
	if err != nil {
		fatal("auto-registrar outcome por evento: %v", err)
	}
	if !matched {
		matched, outcomeID, err = outcome.AutoRecordPending(s, sessionID, tool, res, pathResolved)
		if err != nil {
			fatal("auto-registrar outcome por herramienta: %v", err)
		}
	}
	debuglog.Log("outcome_auto_link", map[string]any{
		"event": eventID, "tool": tool, "matched": matched,
		"outcome": outcomeID, "path_resolved": pathResolved,
	})
	return matched, outcomeID
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
		       c.kind, c.phase_key, c.confidence, c.risk_level, c.expected_evidence, c.assumptions,
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
		kind, phase, risk, expected, assumptions   string
		score, confidence                          float64
		hypothesisID, objectiveID                  sql.NullString
	}
	var all []candRow
	for rows.Next() {
		var c candRow
		if err := rows.Scan(&c.id, &c.source, &c.tool, &c.cmdRendered, &c.score, &c.explanation,
			&c.kind, &c.phase, &c.confidence, &c.risk, &c.expected, &c.assumptions,
			&c.hypothesisID, &c.objectiveID); err != nil {
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
			if c.kind == "command" && c.cmdRendered != "" {
				fmt.Println(c.cmdRendered)
				break
			}
			continue
		}
		fmt.Printf("%d. [%s/%s] phase=%s risk=%s confidence=%.2f score=%.2f (id %s)\n",
			i+1, c.source, c.kind, c.phase, c.risk, c.confidence, c.score, c.id[:8])
		if c.cmdRendered != "" {
			fmt.Printf("   %s\n", c.cmdRendered)
		} else {
			fmt.Printf("   %s\n", strings.ReplaceAll(c.explanation, "\n", " "))
		}
		if c.expected != "" {
			fmt.Printf("   evidencia esperada: %s\n", c.expected)
		}
		if target := candidateTargetHost(s, c.id); target != "" {
			if status, pattern, err := scope.Check(s, sessionID, target); err == nil && status == scope.Out {
				fmt.Printf("   ⚠ SCOPE: %s está EXCLUIDO por la regla %q (advertencia; no se bloquea técnicamente)\n", target, pattern)
			}
		}
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
	// <prefix> es opcional: si se omite y hay exactamente 1 candidato
	// 'proposed' en la sesión activa, se explica ese.
	prefix := ""
	if len(args) >= 1 {
		prefix = args[0]
	} else {
		sessionID := currentSession(s)
		ids := resolveSole(s, `SELECT id FROM candidate WHERE session_id = ? AND status = 'proposed'`, sessionID)
		prefix = mustSole(ids, "", "candidato")
	}
	var id, explanation, scoreTermsJSON, kind, phase, risk, expected, assumptions string
	var score, confidence float64
	err := s.DB.QueryRow(`
		SELECT id, explanation, score, score_terms, kind, phase_key, confidence, risk_level, expected_evidence, assumptions FROM candidate
		WHERE id LIKE ? || '%' ORDER BY created_at DESC LIMIT 1`, prefix,
	).Scan(&id, &explanation, &score, &scoreTermsJSON, &kind, &phase, &confidence, &risk, &expected, &assumptions)
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
	fmt.Printf("Candidato %s — %s / %s — risk %s — confidence %.2f — score %.2f\n\n%s\n\n", id[:8], kind, phase, risk, confidence, score, explanation)
	if expected != "" {
		fmt.Printf("Evidencia esperada: %s\n", expected)
	}
	if assumptions != "" && assumptions != "[]" {
		fmt.Printf("Asunciones: %s\n", assumptions)
	}
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
		if t == "credential_candidate" {
			v = credentialstore.Mask(v)
		}
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

	if credentials, err := credentialstore.List(s, sessionID, false); err == nil {
		fmt.Println("\nCredenciales (enmascaradas):")
		if len(credentials) == 0 {
			fmt.Println("  (ninguna)")
		}
		for _, c := range credentials {
			fmt.Printf("  %s identity=%q service=%q value=%q [%s]\n", c.ID[:8], c.Identity, c.Service, c.Value, c.Status)
		}
	}
	var revision int64
	var jobStatus, jobError string
	if err := s.DB.QueryRow(`SELECT revision, status, last_error FROM strategy_job WHERE session_id = ?`, sessionID).Scan(&revision, &jobStatus, &jobError); err == nil {
		fmt.Printf("\nEstrategia exploratoria: revision=%d status=%s", revision, jobStatus)
		if jobError != "" {
			fmt.Printf(" error=%q", jobError)
		}
		fmt.Println()
	}

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
	// <candidate-id-prefix> es opcional: si se omite y hay exactamente 1
	// candidato 'proposed' en la sesión activa, se acepta ese.
	prefix := ""
	if len(args) >= 1 {
		prefix = args[0]
	} else {
		sessionID := currentSession(s)
		ids := resolveSole(s, `SELECT id FROM candidate WHERE session_id = ? AND status = 'proposed'`, sessionID)
		prefix = mustSole(ids, "", "candidato")
	}
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
		`INSERT INTO action(id, candidate_id, objective_path_id, decided_at, executed_at, status)
		 VALUES (?, ?, ?, ?, NULL, 'planned')`,
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

	fmt.Printf("Decisión registrada: %s (candidato %s preparado, todavía no ejecutado)\n", actionID[:8], candID[:8])
	if intentKey == "test_ssh_auth" {
		fmt.Println("El hook marcará la ejecución al observar el comando. Sin hook, usa `exitone resolve " + actionID[:8] + " --result fail|success`.")
	} else {
		fmt.Println("El hook enlazará la evidencia automáticamente. Sin hook, ingiere con `--for-action " + actionID[:8] + "`.")
	}
}

func cmdResolve(s *store.Store, args []string) {
	rest, flags := parseFlags(args)
	result := flags["result"]
	if result == "" {
		fatal("uso: exitone resolve [action-id-prefix] --result <fail|success>")
	}
	sessionID := currentSession(s)

	// <action-id-prefix> es opcional: si se omite y hay exactamente 1
	// acción 'planned' (aceptada, todavía sin resultado) en la sesión, se
	// resuelve esa.
	actionRef := ""
	if len(rest) >= 1 {
		actionRef = rest[0]
	} else {
		ids := resolveSole(s, `SELECT a.id FROM action a JOIN candidate c ON c.id = a.candidate_id WHERE c.session_id = ? AND a.status = 'planned'`, sessionID)
		actionRef = mustSole(ids, "", "acción")
	}

	// Fase 3 del plan de arquitectura: ya no se crea una hypothesis por cada
	// intento — la cobertura (qué identidades ya se probaron) la refleja
	// directamente la tabla `candidate` (ver internal/strategy/ssh.go).
	actionID, err := outcome.RecordManualResult(s, actionRef, result)
	if err != nil {
		fatal("registrar resultado: %v", err)
	}
	fmt.Printf("Resultado registrado: acción %s (%s)\n", actionID[:8], result)

	generateCandidates(s, sessionID)
}

func cmdDismiss(s *store.Store, args []string) {
	// <candidate-id-prefix> es opcional: si se omite y hay exactamente 1
	// candidato 'proposed' en la sesión activa, se descarta ese.
	prefix := ""
	if len(args) >= 1 {
		prefix = args[0]
	} else {
		sessionID := currentSession(s)
		ids := resolveSole(s, `SELECT id FROM candidate WHERE session_id = ? AND status = 'proposed'`, sessionID)
		prefix = mustSole(ids, "", "candidato")
	}
	res, err := s.DB.Exec(`UPDATE candidate SET status = 'dismissed' WHERE id LIKE ? || '%' AND status = 'proposed'`, prefix)
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
