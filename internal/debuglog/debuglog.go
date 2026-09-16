// Package debuglog escribe un registro "ultra debug" en JSON-lines a
// ~/.exitone/ultra_debug.log (override con EXITONE_DEBUG_LOG). El objetivo
// es que cualquier sesión de prueba deje un rastro completo — cada comando
// invocado, cada decisión interna (conteos, candidatos con sus score_terms,
// auto-links, triggers de metodología, tráfico crudo con el LLM) y cada
// error — para poder diagnosticar sin tener que reconstruirlo a mano desde
// lo que el operador recuerde.
package debuglog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	mu   sync.Mutex
	file *os.File
	pid  = os.Getpid()
)

func path() string {
	if p := os.Getenv("EXITONE_DEBUG_LOG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "ultra_debug.log"
	}
	dir := filepath.Join(home, ".exitone")
	os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "ultra_debug.log")
}

func ensureOpen() {
	if file != nil {
		return
	}
	f, err := os.OpenFile(path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return // debug logging nunca debe romper el flujo principal
	}
	file = f
}

type entry struct {
	Timestamp string         `json:"ts"`
	PID       int            `json:"pid"`
	Args      []string       `json:"args"`
	Event     string         `json:"event"`
	Fields    map[string]any `json:"fields,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// Log escribe un evento estructurado. Nunca falla de forma visible — si el
// archivo no se puede abrir/escribir, se ignora silenciosamente (esto es
// telemetría de diagnóstico, no debe poder tumbar el CLI).
func Log(event string, fields map[string]any) {
	write(event, fields, "")
}

// LogError es igual que Log pero además adjunta el mensaje de error — usar
// justo antes de que el CLI aborte (fatal) o cuando una operación no crítica
// falla mas el flujo continúa.
func LogError(event string, err error, fields map[string]any) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	write(event, fields, msg)
}

func write(event string, fields map[string]any, errMsg string) {
	mu.Lock()
	defer mu.Unlock()
	ensureOpen()
	if file == nil {
		return
	}
	e := entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		PID:       pid,
		Args:      os.Args,
		Event:     event,
		Fields:    fields,
		Error:     errMsg,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	file.Write(b)
}
