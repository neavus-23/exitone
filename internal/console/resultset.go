package console

import (
	"fmt"
	"strconv"
)

// ResultRef es una fila de la última tabla que `show`/`search` imprimieron.
// El índice (posición en el slice) es SOLO una conveniencia de la sesión de
// consola — nunca una identidad persistente (sección 24 del pedido
// original: "Nunca uses el número como ID persistente").
type ResultRef struct {
	Type  ContextType
	ID    string
	Label string
	Value string // texto adicional de la fila (ej. "192.168.72.130:445 SMB") para mostrar en errores/confirmaciones
}

// ResultSet es la última tabla mostrada. Responsabilidad ÚNICA: resolver un
// índice numérico. No intenta IDs, hosts ni puertos — eso es trabajo de
// ResolveByIdentity (console_resolve.go, en cmd/exitone), una función
// completamente separada. Mezclar ambas responsabilidades en una sola
// función fue el problema señalado explícitamente en la revisión de este
// plan.
type ResultSet []ResultRef

// ResolveIndex acepta ÚNICAMENTE un token numérico ("0", "2", ...). Devuelve
// un error claro y distinto para "no es un número" vs "fuera de rango",
// nunca adivina.
func (rs ResultSet) ResolveIndex(token string) (*ResultRef, error) {
	n, err := strconv.Atoi(token)
	if err != nil {
		return nil, fmt.Errorf("%q no es un índice numérico", token)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no hay un result set activo — corre 'show' o 'search' primero")
	}
	if n < 0 || n >= len(rs) {
		return nil, fmt.Errorf("índice %d fuera de rango (0-%d)", n, len(rs)-1)
	}
	ref := rs[n]
	return &ref, nil
}
