// Package scope implementa el control de alcance explícito que un flujo de
// bug bounty (HackerOne) o un pentest interno con reglas de compromiso
// necesita: qué assets están autorizados a tocarse, y cuáles están
// EXPLÍCITAMENTE excluidos aunque aparezcan en el mismo host/dominio.
//
// Nunca inferido: como `focus`, esto es siempre una decisión explícita del
// operador (`scope add`), nunca algo que ExitOne deduzca del tráfico o de
// heurísticas. A diferencia de `focus`, no reordena nada — Check() clasifica
// en_scope/fuera_de_scope/desconocido, y son las capas de presentación
// (`show`, `next` contextual) las que deciden qué hacer con esa clasificación
// — nunca ocultan silenciosamente lo que está fuera de scope, solo lo marcan.
//
// Limitación honesta: el matching es substring/prefijo simple contra
// entity.canonical_value, NUNCA aritmética real de CIDR (ej. "10.0.0.0/8" no
// se expande a un rango — se trata como texto). Suficiente para dominios y
// IPs exactas/prefijos de un bug bounty típico; insuficiente para scopes de
// red completos con subredes reales.
package scope

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"exitone/internal/store"
)

type Rule struct {
	ID        string
	SessionID string
	Pattern   string
	InScope   bool
	Note      string
	CreatedAt string
}

// Status — resultado de Check(): "in" (alguna regla in-scope matchea),
// "out" (alguna regla de exclusión matchea — gana sobre "in" si ambas
// matchean, ver Check), "unknown" (ninguna regla dice nada de este valor).
type Status string

const (
	In      Status = "in"
	Out     Status = "out"
	Unknown Status = "unknown"
)

// Add registra una regla nueva. No deduplica ni fusiona con reglas
// existentes — cada `scope add` es una entrada nueva; `scope list` muestra
// todas, y el operador borra las que ya no aplican con `scope remove`.
func Add(s *store.Store, sessionID, pattern string, inScope bool, note string) (string, error) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	inScopeInt := 0
	if inScope {
		inScopeInt = 1
	}
	if _, err := s.DB.Exec(
		`INSERT INTO scope_rule(id, session_id, pattern, in_scope, note, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, sessionID, pattern, inScopeInt, note, now,
	); err != nil {
		return "", fmt.Errorf("insert scope_rule: %w", err)
	}
	return id, nil
}

// List devuelve todas las reglas de la sesión, más nuevas primero.
func List(s *store.Store, sessionID string) ([]Rule, error) {
	rows, err := s.DB.Query(
		`SELECT id, pattern, in_scope, note, created_at FROM scope_rule WHERE session_id = ? ORDER BY created_at DESC`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []Rule
	for rows.Next() {
		var r Rule
		var inScopeInt int
		if err := rows.Scan(&r.ID, &r.Pattern, &inScopeInt, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.SessionID = sessionID
		r.InScope = inScopeInt == 1
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// Remove borra por prefijo de ID o por coincidencia exacta de pattern —
// mismo espíritu que el resto de la CLI (prefijos cortos, nunca UUIDs
// completos a mano). Error explícito si no matchea nada o si matchea más de
// una regla (nunca borra "la que sea" — mismo principio que
// resolveWorkspaceToken: listar, nunca adivinar).
func Remove(s *store.Store, sessionID, idOrPattern string) error {
	rows, err := s.DB.Query(
		`SELECT id, pattern FROM scope_rule WHERE session_id = ? AND (id LIKE ? || '%' OR pattern = ?)`,
		sessionID, idOrPattern, idOrPattern,
	)
	if err != nil {
		return err
	}
	type match struct{ id, pattern string }
	var matches []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.id, &m.pattern); err != nil {
			rows.Close()
			return err
		}
		matches = append(matches, m)
	}
	rows.Close()

	switch len(matches) {
	case 0:
		return fmt.Errorf("no se encontró ninguna regla de scope con %q", idOrPattern)
	case 1:
		_, err := s.DB.Exec(`DELETE FROM scope_rule WHERE id = ?`, matches[0].id)
		return err
	default:
		var patterns []string
		for _, m := range matches {
			patterns = append(patterns, fmt.Sprintf("%s (%s)", m.id[:8], m.pattern))
		}
		return fmt.Errorf("%q coincide con %d reglas — usa el ID completo:\n\n    %s", idOrPattern, len(matches), strings.Join(patterns, "\n    "))
	}
}

// Check clasifica un valor (IP, dominio, etc.) contra las reglas de la
// sesión. Precedencia deliberada: una exclusión explícita (in_scope=0)
// SIEMPRE gana sobre una regla in-scope que también matchee — el ejemplo
// real de un bug bounty es "*.example.com está en scope, pero
// internal.example.com está explícitamente excluido"; si ambas reglas
// matchean, la exclusión debe ganar, nunca el orden de inserción.
func Check(s *store.Store, sessionID, value string) (Status, string, error) {
	rules, err := List(s, sessionID)
	if err != nil {
		return Unknown, "", err
	}
	if len(rules) == 0 {
		return Unknown, "", nil
	}

	var inMatch string
	for _, r := range rules {
		if !matches(r.Pattern, value) {
			continue
		}
		if !r.InScope {
			return Out, r.Pattern, nil // exclusión explícita: corta inmediatamente
		}
		if inMatch == "" {
			inMatch = r.Pattern
		}
	}
	if inMatch != "" {
		return In, inMatch, nil
	}
	return Unknown, "", nil
}

// matches — substring/prefijo simple, sin distinguir mayúsculas. Ver
// limitación honesta en el comentario del paquete.
func matches(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" || value == "" {
		return false
	}
	return value == pattern || strings.Contains(value, pattern) || strings.Contains(pattern, value)
}
