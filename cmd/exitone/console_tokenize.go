package main

import "strings"

// tokenizeConsoleLine reemplaza a splitReplLine (que solo entendía comillas
// dobles, sin escape) — necesario para `search host:192.168.72.130 "texto
// con espacios"`, paths con espacios, y para que la detección de tokens
// sensibles (console_history.go) pueda operar sobre tokens reales en vez de
// substrings del string crudo. Sigue sin ser un lexer de shell completo: sin
// globbing, sin variables, sin subshells — comillas simples/dobles y
// backslash-escape simple alcanzan para todo lo que la consola necesita.
func tokenizeConsoleLine(line string) []string {
	var tokens []string
	var cur strings.Builder
	var quote rune // 0 = sin comillas, '\'' o '"' si estamos dentro de una
	escaped := false
	hasToken := false

	flush := func() {
		if hasToken {
			tokens = append(tokens, cur.String())
			cur.Reset()
			hasToken = false
		}
	}

	for _, r := range line {
		switch {
		case escaped:
			cur.WriteRune(r)
			hasToken = true
			escaped = false
		case r == '\\' && quote != '\'':
			// Backslash escapa el siguiente carácter, salvo dentro de
			// comillas simples (igual que en una shell POSIX real).
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
				hasToken = true
			}
		case r == '"' || r == '\'':
			quote = r
			hasToken = true // permite tokens vacíos entre comillas, ej. use ""
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			hasToken = true
		}
	}
	flush()
	return tokens
}
