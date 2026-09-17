package main

import (
	"strings"

	"exitone/internal/console"
)

// sensitiveFlagNames — sección K del plan: detección POR TOKEN de flag
// exacto, nunca por substring de la línea cruda (ese enfoque disparaba
// falsos positivos como "--passive" solo por contener "pass").
var sensitiveFlagNames = map[string]bool{
	"--password": true,
	"--pass":     true,
	"--token":    true,
	"--secret":   true,
	"--api-key":  true,
	"--value":    true,
}

// isSensitiveLine decide si una línea NO debería persistirse en el
// historial — política real, mínima y extensible, nunca un stub que
// siempre devuelva false.
func isSensitiveLine(line string, spec *console.CommandSpec) bool {
	if spec != nil && spec.Sensitive {
		return true
	}
	for _, tok := range tokenizeConsoleLine(line) {
		flag := tok
		if i := strings.Index(tok, "="); i > 0 {
			flag = tok[:i]
		}
		if sensitiveFlagNames[strings.ToLower(flag)] {
			return true
		}
	}
	return false
}

// filteredHistory envuelve una history.Source real (el archivo persistente)
// e intercepta Write() para que una línea sensible NUNCA llegue a tocar
// disco. reeflective/readline llama a History.Write automáticamente en
// accept-line (ver history.go:581 de la librería) — no expone un hook
// "no guardes esta línea" utilizable desde fuera de sus propios keymaps, así
// que la única forma correcta de aplicar la política es interceptar la
// escritura en la fuente misma, en vez de intentar revertirla después.
type filteredHistory struct {
	inner readlineHistorySource
}

// readlineHistorySource replica la interfaz history.Source (Write/GetLine/
// Len/Dump) sin importar el paquete interno no exportado de la librería —
// readline.History (alias público) ya la satisface.
type readlineHistorySource interface {
	Write(line string) (int, error)
	GetLine(pos int) (string, error)
	Len() int
	Dump() any
}

func (f *filteredHistory) Write(line string) (int, error) {
	name, args := firstTokenAndRest(line)
	var spec *console.CommandSpec
	if consoleRegistry != nil {
		spec, _ = consoleRegistry.Resolve(name)
	}
	_ = args
	if isSensitiveLine(line, spec) {
		return f.inner.Len(), nil // se descarta silenciosamente, nunca toca disco
	}
	return f.inner.Write(line)
}

func (f *filteredHistory) GetLine(pos int) (string, error) { return f.inner.GetLine(pos) }
func (f *filteredHistory) Len() int                        { return f.inner.Len() }
func (f *filteredHistory) Dump() any                       { return f.inner.Dump() }

func firstTokenAndRest(line string) (string, []string) {
	tokens := tokenizeConsoleLine(line)
	if len(tokens) == 0 {
		return "", nil
	}
	return tokens[0], tokens[1:]
}
