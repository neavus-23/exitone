// Package focus implementa el único concepto nuevo introducido por la
// disciplina de significado del plan de arquitectura: dónde quiere el
// operador invertir esfuerzo ahora mismo. Siempre explícito, nunca inferido
// — a diferencia de `stage` (coverage, inferido de conteos reales). `next`/
// `status` lo usan para REORDENAR resultados relacionados, nunca para
// ocultar el resto.
package focus

import (
	"database/sql"
	"fmt"
	"time"

	"exitone/internal/store"
)

type Focus struct {
	RefType string // hypothesis | objective
	RefID   string
	SetAt   string
}

// Resolve busca un id-prefix contra hypothesis y methodology_objective, en
// ese orden (mismo patrón `id LIKE ? || '%'` ya usado en el resto de la CLI
// para candidate/action) — MVP acota el alcance a estos dos tipos (ver N.5
// del plan: cada uno tiene una regla de reordenamiento obvia vía joins
// existentes; host/service todavía no).
func Resolve(s *store.Store, sessionID, refPrefix string) (refType, refID string, err error) {
	var id string
	err = s.DB.QueryRow(
		`SELECT id FROM hypothesis WHERE session_id = ? AND id LIKE ? || '%'`,
		sessionID, refPrefix,
	).Scan(&id)
	if err == nil {
		return "hypothesis", id, nil
	}
	if err != sql.ErrNoRows {
		return "", "", err
	}

	err = s.DB.QueryRow(
		`SELECT id FROM methodology_objective WHERE session_id = ? AND id LIKE ? || '%'`,
		sessionID, refPrefix,
	).Scan(&id)
	if err == nil {
		return "objective", id, nil
	}
	if err != sql.ErrNoRows {
		return "", "", err
	}
	return "", "", fmt.Errorf("no se encontró una hipótesis ni un objective con prefijo %q en esta sesión", refPrefix)
}

// Set fija el focus activo de la sesión (reemplaza cualquier focus anterior
// — un solo focus activo a la vez, mismo espíritu que app_state.current_session).
func Set(s *store.Store, sessionID, refType, refID string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(
		`INSERT INTO focus(session_id, ref_type, ref_id, set_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(session_id) DO UPDATE SET ref_type = excluded.ref_type, ref_id = excluded.ref_id, set_at = excluded.set_at`,
		sessionID, refType, refID, now,
	)
	return err
}

// Clear borra el focus activo, si existe. No es un error llamarla sin uno.
func Clear(s *store.Store, sessionID string) error {
	_, err := s.DB.Exec(`DELETE FROM focus WHERE session_id = ?`, sessionID)
	return err
}

// Get devuelve el focus activo, o nil si no hay ninguno (no es un error).
func Get(s *store.Store, sessionID string) (*Focus, error) {
	var f Focus
	err := s.DB.QueryRow(
		`SELECT ref_type, ref_id, set_at FROM focus WHERE session_id = ?`,
		sessionID,
	).Scan(&f.RefType, &f.RefID, &f.SetAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}
