package investigation

import (
	"time"

	"exitone/internal/store"
)

// EnsureHostEntity crea (o recupera) la entidad host del target de la sesión.
// Se llama al crear la sesión para que exista al menos una entidad desde el
// primer instante — sin esto, ninguna metodología puede dispararse antes de
// la primera ingesta manual, dejando a ExitOne sin nada que recomendar en el
// estado verdaderamente inicial (Prueba 1 del protocolo de validación CTF).
func EnsureHostEntity(s *store.Store, sessionID, targetLabel string) (entityID string, created bool, err error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.DB.Begin()
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()

	id, created, _, err := upsertEntity(tx, sessionID, "host", targetLabel, map[string]any{}, now)
	if err != nil {
		return "", false, err
	}
	if err := tx.Commit(); err != nil {
		return "", false, err
	}
	return id, created, nil
}
