// Package credential mantiene memoria explícita de secretos e intentos. Los
// valores se guardan localmente en texto por política del producto, pero las
// APIs de listado los enmascaran salvo que el operador solicite revelarlos.
package credential

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

type Credential struct {
	ID        string
	Identity  string
	Service   string
	Value     string
	Source    string
	Status    string
	CreatedAt string
}

func Add(s *store.Store, sessionID, identityRef, serviceRef, value, source string) (string, error) {
	identityID, err := resolveEntity(s, sessionID, identityRef, "identity")
	if err != nil {
		return "", err
	}
	serviceID, err := resolveEntity(s, sessionID, serviceRef, "service")
	if err != nil {
		return "", err
	}
	return AddWithEntityIDs(s, sessionID, identityID, serviceID, value, source)
}

// AddWithEntityIDs guarda una credencial vinculada directamente a entity IDs
// ya resueltos por el llamador — sin volver a buscarlos por tipo, a
// diferencia de Add (que espera un "ref" tecleado por el operador y solo
// acepta type='identity'/'service'). Es lo que usa la correlación
// automática de internal/investigation, donde el vínculo sale de la MISMA
// extracción que encontró la credencial (ej. un kind="principal" en el
// mismo lote del LLM) y puede ser de un tipo de entidad distinto a
// 'identity' — nunca un ref libre que haya que adivinar.
func AddWithEntityIDs(s *store.Store, sessionID, identityEntityID, serviceEntityID, value, source string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("el valor de la credencial no puede estar vacío")
	}
	sum := sha256.Sum256([]byte(value))
	fingerprint := hex.EncodeToString(sum[:])
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.Exec(`INSERT INTO credential(
		id, session_id, identity_entity_id, service_entity_id, secret_value,
		secret_fingerprint, source_ref, status, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, 'discovered', ?)`,
		id, sessionID, nullable(identityEntityID), nullable(serviceEntityID), value, fingerprint, source, now,
	)
	if err != nil {
		return "", fmt.Errorf("guardar credencial: %w", err)
	}
	return id, nil
}

// SetLinks vincula (o corrige) la identidad/servicio de una credencial ya
// guardada. Falta real detectada revisando el reporte final contra HTB
// Nexus: `Add` solo permite fijar identity/service AL MOMENTO de guardar la
// credencial, pero en la práctica una credencial a menudo se encuentra
// (ej. en el historial de git) ANTES de confirmar de quién es o para qué
// servicio sirve — y hasta ahora no había forma de completarlo después sin
// tocar SQL a mano. Solo actualiza el campo pedido (ref no vacía); nunca
// borra un link ya fijado.
func SetLinks(s *store.Store, sessionID, credentialRef, identityRef, serviceRef string) error {
	credentialID, err := resolveCredential(s, sessionID, credentialRef)
	if err != nil {
		return err
	}
	if identityRef != "" {
		identityID, err := resolveEntity(s, sessionID, identityRef, "identity")
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(`UPDATE credential SET identity_entity_id = ? WHERE id = ?`, nullable(identityID), credentialID); err != nil {
			return fmt.Errorf("vincular identidad: %w", err)
		}
	}
	if serviceRef != "" {
		serviceID, err := resolveEntity(s, sessionID, serviceRef, "service")
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(`UPDATE credential SET service_entity_id = ? WHERE id = ?`, nullable(serviceID), credentialID); err != nil {
			return fmt.Errorf("vincular servicio: %w", err)
		}
	}
	return nil
}

func List(s *store.Store, sessionID string, reveal bool) ([]Credential, error) {
	rows, err := s.DB.Query(`SELECT c.id,
		COALESCE(i.canonical_value,''), COALESCE(sv.canonical_value,''),
		c.secret_value, c.source_ref, c.status, c.created_at
		FROM credential c
		LEFT JOIN entity i ON i.id = c.identity_entity_id
		LEFT JOIN entity sv ON sv.id = c.service_entity_id
		WHERE c.session_id = ? ORDER BY c.created_at`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Identity, &c.Service, &c.Value, &c.Source, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		if !reveal {
			c.Value = Mask(c.Value)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Reveal devuelve un único secreto por ID exacto y sesión. La API separada
// evita que una UI tenga que pedir List(..., true) y cargar accidentalmente
// todas las credenciales en claro para revelar solo la seleccionada.
func Reveal(s *store.Store, sessionID, credentialID string) (string, error) {
	var value string
	err := s.DB.QueryRow(`
		SELECT secret_value FROM credential
		WHERE session_id = ? AND id = ?`, sessionID, credentialID).Scan(&value)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("credencial %q no encontrada", credentialID)
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func RecordAttempt(s *store.Store, sessionID, credentialRef, serviceRef, eventRef, result string) (string, error) {
	if result != "success" && result != "fail" && result != "unknown" {
		return "", fmt.Errorf("resultado debe ser success, fail o unknown")
	}
	credentialID, err := resolveCredential(s, sessionID, credentialRef)
	if err != nil {
		return "", err
	}
	serviceID, err := resolveEntity(s, sessionID, serviceRef, "service")
	if err != nil {
		return "", err
	}
	eventID := ""
	if eventRef != "" {
		err := s.DB.QueryRow(`SELECT id FROM event WHERE session_id = ? AND id LIKE ? || '%' ORDER BY ended_at DESC LIMIT 1`, sessionID, eventRef).Scan(&eventID)
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("evento %q no encontrado", eventRef)
		}
		if err != nil {
			return "", err
		}
	}
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO credential_attempt(id, credential_id, service_entity_id, event_id, result, attempted_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, credentialID, nullable(serviceID), nullable(eventID), result, now); err != nil {
		return "", err
	}
	if result == "success" || result == "fail" {
		status := "valid"
		if result == "fail" {
			status = "invalid"
		}
		_, _ = s.DB.Exec(`UPDATE credential SET status = ? WHERE id = ?`, status, credentialID)
	}
	return id, nil
}

func Mask(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}
	if len(runes) == 1 {
		return "*"
	}
	return string(runes[0]) + strings.Repeat("*", min(len(runes)-1, 11))
}

func resolveCredential(s *store.Store, sessionID, ref string) (string, error) {
	var id string
	err := s.DB.QueryRow(`SELECT id FROM credential WHERE session_id = ? AND id LIKE ? || '%' ORDER BY created_at DESC LIMIT 1`, sessionID, ref).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("credencial %q no encontrada", ref)
	}
	return id, err
}

func resolveEntity(s *store.Store, sessionID, ref, expectedType string) (string, error) {
	if ref == "" {
		return "", nil
	}
	var id string
	err := s.DB.QueryRow(`SELECT id FROM entity WHERE session_id = ? AND type = ?
		AND (id LIKE ? || '%' OR canonical_value = ?) ORDER BY last_seen DESC LIMIT 1`,
		sessionID, expectedType, ref, ref).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("entidad %s %q no encontrada", expectedType, ref)
	}
	return id, err
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
