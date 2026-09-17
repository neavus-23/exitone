// Package debuglog escribe un registro "ultra debug" en JSON-lines a
// ~/.exitone/ultra_debug.log (override con EXITONE_DEBUG_LOG). El objetivo
// es que cualquier sesión de prueba deje un rastro completo — cada comando
// invocado, cada decisión interna (conteos, candidatos con sus score_terms,
// auto-links y triggers de metodología. Los prompts/respuestas LLM crudos
// se excluyen deliberadamente para no duplicar evidencia o secretos) y cada
// error — para poder diagnosticar sin tener que reconstruirlo a mano desde
// lo que el operador recuerde.
package debuglog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	os.MkdirAll(dir, 0o700)
	_ = os.Chmod(dir, 0o700)
	return filepath.Join(dir, "ultra_debug.log")
}

func ensureOpen() {
	if file != nil {
		return
	}
	f, err := os.OpenFile(path(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
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
		Args:      redactArgs(os.Args),
		Event:     event,
		Fields:    redactMap(fields),
		Error:     redactString(errMsg),
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	file.Write(b)
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(--(?:password|pass|token|secret|api-key|value)(?:=|\s+))([^\s]+)`),
	regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)`),
	regexp.MustCompile(`(?i)("(?:password|pass|token|secret|api_key|secret_value)"\s*:\s*")([^"]*)(")`),
	regexp.MustCompile(`(?i)(\b(?:DB_)?(?:PASSWORD|PASS|TOKEN|SECRET|API_KEY)=)([^\s]+)`),
}

func redactString(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, `${1}<redacted>${3}`)
	}
	return value
}

// RedactText expone la misma política para vistas de eventos. La base puede
// conservar command_raw localmente, pero dashboards y logs no deben repetir
// secretos por defecto.
func RedactText(value string) string { return redactString(value) }

func redactArgs(args []string) []string {
	out := append([]string(nil), args...)
	sensitiveNext := false
	for i, arg := range out {
		if sensitiveNext {
			out[i] = "<redacted>"
			sensitiveNext = false
			continue
		}
		lower := strings.ToLower(arg)
		switch lower {
		case "--password", "--pass", "--token", "--secret", "--api-key", "--value":
			sensitiveNext = true
		}
		out[i] = redactString(out[i])
	}
	return out
}

func redactMap(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		lower := strings.ToLower(key)
		if lower == "password" || lower == "secret" || lower == "token" || lower == "secret_value" {
			out[key] = "<redacted>"
			continue
		}
		out[key] = redactAny(value)
	}
	return out
}

func redactAny(value any) any {
	switch v := value.(type) {
	case string:
		return redactString(v)
	case []string:
		out := make([]string, len(v))
		for i := range v {
			out[i] = redactString(v[i])
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = redactAny(v[i])
		}
		return out
	case map[string]any:
		return redactMap(v)
	default:
		return value
	}
}
