// Package methodology evalúa triggers independientes de herramienta (sección F
// del plan). Cada definición dispara sobre un TIPO de entidad (no una
// herramienta concreta), lo que habilita la correlación cross-tool de Slice 2:
// una entidad 'domain' descubierta por smbclient abre un objective nuevo
// exactamente igual que si hubiera venido de cualquier otra fuente.
package methodology

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

type objectiveDef struct {
	IntentKey string
	// Trigger: tipo de entidad + predicado sobre sus attrs.
	EntityType string
	Matches    func(attrs map[string]any) bool
	Paths      []pathDef
}

type pathDef struct {
	Key         string
	Description string
}

var definitions = []objectiveDef{
	{
		// Bootstrap: se dispara sobre CUALQUIER entidad host, incluida la que
		// se crea automáticamente al abrir una sesión (ver cmdSession). Sin
		// esto, el Investigation State queda vacío sin ningún objective, y
		// ExitOne no tiene nada que recomendar como "primera acción" — un gap
		// real encontrado al intentar validar Prueba 1 (estado inicial vacío
		// debe producir un Action Intent).
		IntentKey:  "initial_discovery",
		EntityType: "host",
		Matches:    func(attrs map[string]any) bool { return true },
		Paths: []pathDef{
			{Key: "port_scan", Description: "Descubrir puertos/servicios expuestos"},
		},
	},
	{
		IntentKey:  "smb_enumeration",
		EntityType: "service",
		Matches: func(attrs map[string]any) bool {
			protocol, _ := attrs["protocol"].(string)
			return protocol == "smb" || protocol == "microsoft-ds" || protocol == "netbios-ssn"
		},
		Paths: []pathDef{
			{Key: "anonymous_access", Description: "Enumerar shares vía sesión anónima/null"},
			{Key: "authenticated_access", Description: "Enumerar shares con credenciales descubiertas"},
			{Key: "alternative_source", Description: "Inferir shares/dominio desde otra evidencia (LDAP, filtraciones, etc.)"},
		},
	},
	{
		// Slice 3: dispara sobre el servicio SSH. El path "credential_test" no
		// tiene un comando fijo — el Candidate Generator produce un candidato
		// por cada identidad conocida (ver strategy.GenerateSSHAuthCandidates).
		IntentKey:  "ssh_auth_investigation",
		EntityType: "service",
		Matches: func(attrs map[string]any) bool {
			protocol, _ := attrs["protocol"].(string)
			return protocol == "ssh"
		},
		Paths: []pathDef{
			{Key: "credential_test", Description: "Probar autenticación SSH con identidades conocidas"},
		},
	},
	{
		// Trigger sobre entidad HTTP. Sin candidatos todavía (no hay parser ni
		// template de Nivel 1 para curl/whatweb/ffuf — gap honesto, Fase 2 del
		// roadmap). El objective se abre igual para que quede visible como
		// "known unknown", tal como pide la sección 6/F del plan.
		IntentKey:  "http_enumeration",
		EntityType: "service",
		Matches: func(attrs map[string]any) bool {
			protocol, _ := attrs["protocol"].(string)
			return protocol == "http" || protocol == "https"
		},
		Paths: []pathDef{
			{Key: "technology", Description: "Identificar tecnología/stack del servidor web"},
			{Key: "application_structure", Description: "Mapear estructura de la aplicación (rutas, recursos)"},
			{Key: "endpoints", Description: "Descubrir endpoints no listados"},
			{Key: "auth_surface", Description: "Identificar superficie de autenticación"},
			{Key: "identities", Description: "Descubrir identidades expuestas por la aplicación"},
		},
	},
	{
		// Slice 2: se dispara sobre CUALQUIER entidad type=domain, sin importar
		// qué herramienta la descubrió (smbclient, ldapsearch, etc.) — esto es
		// la correlación cross-tool que Slice 2 debía validar.
		IntentKey:  "domain_identity_enumeration",
		EntityType: "domain",
		Matches:    func(attrs map[string]any) bool { return true },
		Paths: []pathDef{
			{Key: "anonymous_bind", Description: "Intentar bind LDAP anónimo para enumerar identidades"},
			{Key: "kerberos_user_enum", Description: "Enumerar usuarios válidos vía Kerberos pre-auth (sin credenciales)"},
			{Key: "authenticated_query", Description: "Consultar el dominio con credenciales ya descubiertas"},
		},
	},
}

// EvaluateTriggers revisa entidades nuevas y abre METHODOLOGY_OBJECTIVE +
// OBJECTIVE_PATH cuando alguna definición matchea. Devuelve los objective IDs
// recién abiertos.
func EvaluateTriggers(s *store.Store, sessionID string, newEntityIDs []string) ([]string, error) {
	if len(newEntityIDs) == 0 {
		return nil, nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var opened []string

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, entID := range newEntityIDs {
		var entType, attrsJSON string
		err := tx.QueryRow(`SELECT type, attrs FROM entity WHERE id = ?`, entID).Scan(&entType, &attrsJSON)
		if err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		var attrs map[string]any
		if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
			return nil, err
		}

		for _, def := range definitions {
			if def.EntityType != entType || !def.Matches(attrs) {
				continue
			}

			// Dedup: para triggers de tipo 'service', varias entidades de
			// servicio distintas pueden representar la MISMA capacidad a
			// nivel de host (ej. SMB expuesto en 139 y 445 simultáneamente —
			// encontrado probando contra un Windows real en el lab). Sin
			// esto se abren dos objectives idénticos y el Candidate
			// Generator produce un comando duplicado. Deduplicamos por host
			// cuando aplica; para otros tipos de entidad (ej. domain) el
			// dedup sigue siendo por entidad exacta.
			var existing string
			if def.EntityType == "service" {
				err = tx.QueryRow(`
					SELECT mo.id FROM methodology_objective mo
					JOIN relationship r ON r.target_entity_id = mo.trigger_entity_id AND r.kind = 'HAS_SERVICE'
					WHERE mo.intent_key = ? AND r.source_entity_id = (
						SELECT source_entity_id FROM relationship
						WHERE target_entity_id = ? AND kind = 'HAS_SERVICE' LIMIT 1
					)`, def.IntentKey, entID,
				).Scan(&existing)
			} else {
				err = tx.QueryRow(
					`SELECT id FROM methodology_objective WHERE trigger_entity_id = ? AND intent_key = ?`,
					entID, def.IntentKey,
				).Scan(&existing)
			}
			if err == nil {
				continue // ya abierto (misma entidad o mismo host), no duplicar
			}
			if err != sql.ErrNoRows {
				return nil, err
			}

			objID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO methodology_objective(id, session_id, intent_key, trigger_entity_id, status, created_at)
				 VALUES (?, ?, ?, ?, 'open', ?)`,
				objID, sessionID, def.IntentKey, entID, now,
			); err != nil {
				return nil, fmt.Errorf("insert objective: %w", err)
			}
			for _, p := range def.Paths {
				pathID := uuid.NewString()
				if _, err := tx.Exec(
					`INSERT INTO objective_path(id, objective_id, path_key, description, status, created_at)
					 VALUES (?, ?, ?, ?, 'open', ?)`,
					pathID, objID, p.Key, p.Description, now,
				); err != nil {
					return nil, fmt.Errorf("insert objective_path: %w", err)
				}
			}
			opened = append(opened, objID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return opened, nil
}

// EvaluateEndpointTriggers cierra el hueco honesto que dejaba
// "http_enumeration" (arriba: se abría el objective pero nada lo progresaba,
// ver `exitone stages` mostrando "http_mapping NOT_STARTED" pese a tener
// endpoints reales — encontrado validando dirb/ffuf contra Metasploitable3).
// Regla explícita y pequeña, en el mismo estilo que el resto del archivo: si
// una entidad nueva es type='endpoint', se resuelve a qué host pertenece
// (relationship HAS_ENDPOINT) y se marca 'answered' el objective_path
// "endpoints" del http_enumeration abierto para ese mismo host — nunca se
// inventa una metodología general de "cobertura web", solo esta correlación
// puntual. Devuelve los objective_path IDs marcados como respondidos.
func EvaluateEndpointTriggers(s *store.Store, sessionID string, newEntityIDs []string) ([]string, error) {
	if len(newEntityIDs) == 0 {
		return nil, nil
	}
	var answered []string

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, entID := range newEntityIDs {
		var entType string
		if err := tx.QueryRow(`SELECT type FROM entity WHERE id = ?`, entID).Scan(&entType); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
		if entType != "endpoint" {
			continue
		}

		var hostID string
		err := tx.QueryRow(
			`SELECT source_entity_id FROM relationship WHERE target_entity_id = ? AND kind = 'HAS_ENDPOINT' LIMIT 1`,
			entID,
		).Scan(&hostID)
		if err == sql.ErrNoRows {
			continue // endpoint sin host resuelto (no debería pasar, pero no es motivo para fallar la ingesta)
		}
		if err != nil {
			return nil, err
		}

		var pathID string
		err = tx.QueryRow(`
			SELECT op.id FROM objective_path op
			JOIN methodology_objective mo ON mo.id = op.objective_id
			JOIN relationship r ON r.target_entity_id = mo.trigger_entity_id AND r.kind = 'HAS_SERVICE'
			WHERE mo.session_id = ? AND mo.intent_key = 'http_enumeration' AND op.path_key = 'endpoints'
			  AND op.status = 'open' AND r.source_entity_id = ?
			LIMIT 1`, sessionID, hostID,
		).Scan(&pathID)
		if err == sql.ErrNoRows {
			continue // no hay (o ya no hay) objective http_enumeration abierto para este host
		}
		if err != nil {
			return nil, err
		}

		if _, err := tx.Exec(`UPDATE objective_path SET status = 'answered' WHERE id = ?`, pathID); err != nil {
			return nil, fmt.Errorf("marcar objective_path answered: %w", err)
		}
		answered = append(answered, pathID)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return answered, nil
}
