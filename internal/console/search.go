package console

import "strings"

// Query es el resultado de parsear `search key:value key2:value2 texto
// libre` — sección 13 del pedido original. Los tokens ya vienen separados
// (tokenizeConsoleLine corrió antes, en cmd/exitone), así que ParseQuery
// recibe []string en vez de una línea cruda: es la misma responsabilidad,
// adaptada a que el tokenizador ya existe y no hace falta repetirlo aquí.
type Query struct {
	Text    string
	Filters map[string]string
}

// ParseQuery separa tokens "key:value" (sin espacios en la key ni la
// palabra reservada de dos puntos en medio del texto libre) del resto,
// que se une como texto libre para un LIKE simple.
func ParseQuery(tokens []string) Query {
	q := Query{Filters: map[string]string{}}
	var free []string
	for _, tok := range tokens {
		if key, value, ok := splitFilterToken(tok); ok {
			q.Filters[key] = value
			continue
		}
		free = append(free, tok)
	}
	q.Text = strings.Join(free, " ")
	return q
}

func splitFilterToken(tok string) (key, value string, ok bool) {
	i := strings.Index(tok, ":")
	if i <= 0 || i == len(tok)-1 {
		return "", "", false
	}
	return tok[:i], tok[i+1:], true
}
