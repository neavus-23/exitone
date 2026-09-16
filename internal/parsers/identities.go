package parsers

import (
	"bufio"
	"io"
	"strings"
)

// ParseIdentityList es un parser Nivel 1 mínimo para listas de identidades
// (una por línea) tal como las produciría netexec, ldapsearch o kerbrute tras
// su propio post-procesado. No intenta parsear el output crudo de esas
// herramientas todavía (Fase 2); esto deja lista la interfaz de ingestión de
// identidades para Slice 3 sin bloquear la validación de Evidence Reopening
// en un parser más específico que no es el foco de este slice.
func ParseIdentityList(r io.Reader) ([]string, error) {
	var names []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	return names, scanner.Err()
}
