package investigation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"exitone/internal/parsers"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// ApplyScanResult es el único punto de entrada para volcar un ScanResult
// (producido por CUALQUIERA de los extractores genéricos de
// internal/parsers — XML, JSON o tabla, sin importar qué herramienta generó
// el archivo) al Investigation Model. Reemplaza la lógica de upsert que
// antes vivía duplicada dentro de IngestNmap, aplicando el patrón confirmado
// en report_host/report_service de Metasploit: el upsert de un Service
// cascada al upsert de su Host si todavía no se conocía (misma sesión, un
// solo paso), y cada campo tocado en cualquiera de los dos se registra
// también como Observation para no perder provenance.
func ApplyScanResult(s *store.Store, sessionID, rawOutputRef, eventID string, r parsers.ScanResult) (*IngestResult, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res := &IngestResult{}

	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	evidenceID := uuid.NewString()
	if _, err := tx.Exec(
		`INSERT INTO evidence(id, event_id, raw_output_ref, tool_name, parse_level, created_at)
		 VALUES (?, ?, ?, 'generic_scan', 1, ?)`,
		evidenceID, nullableString(eventID), rawOutputRef, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	hostIDs := map[string]string{}

	upsertHost := func(addr string, hostAttrs map[string]any) (string, error) {
		if id, ok := hostIDs[addr]; ok {
			return id, nil
		}
		id, created, changed, err := upsertEntity(tx, sessionID, "host", addr, hostAttrs, now)
		if err != nil {
			return "", err
		}
		hostIDs[addr] = id
		if created {
			res.NewEntities = append(res.NewEntities, id)
		}
		if created || changed {
			if err := recordHostFactObservation(tx, evidenceID, addr, hostAttrs, id); err != nil {
				return "", err
			}
		}
		return id, nil
	}

	for _, h := range r.Hosts {
		attrs := map[string]any{}
		if h.Hostname != "" {
			attrs["hostname"] = h.Hostname
		}
		for k, v := range h.Attrs {
			attrs[k] = v
		}
		if _, err := upsertHost(h.Address, attrs); err != nil {
			return nil, err
		}
	}

	for _, svc := range r.Services {
		if svc.HostAddress == "" || svc.Port == 0 {
			continue
		}
		// Cascada estilo report_service→report_host: si el host de este
		// servicio no fue observado por separado, se crea aquí mismo.
		hostID, err := upsertHost(svc.HostAddress, map[string]any{})
		if err != nil {
			return nil, err
		}

		proto := svc.Protocol
		if proto == "" {
			proto = "tcp"
		}
		serviceValue := fmt.Sprintf("%s:%d/%s", svc.HostAddress, svc.Port, proto)
		attrs := map[string]any{
			"port":  svc.Port,
			"proto": proto,
		}
		if svc.Name != "" {
			attrs["protocol"] = svc.Name
		}
		if svc.State != "" {
			attrs["state"] = svc.State
		}
		if svc.Version != "" {
			attrs["product"] = svc.Version
		}

		serviceID, svcCreated, svcChanged, err := upsertEntity(tx, sessionID, "service", serviceValue, attrs, now)
		if err != nil {
			return nil, err
		}
		if svcCreated {
			res.NewEntities = append(res.NewEntities, serviceID)
		}

		var serviceObsID string // hoisted: la relationship de abajo la referencia como provenance
		if svcCreated || svcChanged {
			serviceObsID = uuid.NewString()
			payload, _ := json.Marshal(map[string]any{
				"host": svc.HostAddress, "port": svc.Port, "proto": proto,
				"service": svc.Name, "state": svc.State, "product": svc.Version,
			})
			if _, err := tx.Exec(
				`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status)
				 VALUES (?, ?, 'open_port', ?, 1.0, 'active')`,
				serviceObsID, evidenceID, string(payload),
			); err != nil {
				return nil, fmt.Errorf("insert observation: %w", err)
			}
			if _, err := tx.Exec(
				`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?), (?, ?)`,
				serviceObsID, hostID, serviceObsID, serviceID,
			); err != nil {
				return nil, err
			}
		}

		if svcCreated {
			// Grieta de provenance corregida (Fase 1): antes se pasaba NULL
			// aquí pese a existir una observation en la misma transacción
			// (svcCreated implica svcCreated||svcChanged, así que
			// serviceObsID siempre está poblado en este punto).
			relID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO relationship(id, source_entity_id, target_entity_id, kind, confidence, supporting_observation_id, valid_from, valid_to)
				 VALUES (?, ?, ?, 'HAS_SERVICE', 1.0, ?, ?, NULL)`,
				relID, hostID, serviceID, nullableString(serviceObsID), now,
			); err != nil {
				return nil, fmt.Errorf("insert relationship: %w", err)
			}
			res.NewRelations = append(res.NewRelations, relID)
		}
	}

	for _, ep := range r.Endpoints {
		if ep.URL == "" {
			continue
		}
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Hostname() == "" {
			continue // URL sin host resoluble — se descarta en vez de inventar un host
		}

		// Mismo patrón de cascada que los servicios: el endpoint trae su
		// host embebido en la URL, así que se upserta aquí si hace falta.
		hostID, err := upsertHost(parsed.Hostname(), map[string]any{})
		if err != nil {
			return nil, err
		}

		attrs := map[string]any{}
		if ep.StatusCode != 0 {
			attrs["status"] = ep.StatusCode
		}
		if ep.Size != 0 {
			attrs["size"] = ep.Size
		}

		endpointID, epCreated, epChanged, err := upsertEntity(tx, sessionID, "endpoint", ep.URL, attrs, now)
		if err != nil {
			return nil, err
		}
		if epCreated {
			res.NewEntities = append(res.NewEntities, endpointID)
		}

		var endpointObsID string // hoisted, ver comentario equivalente en el bloque de services arriba
		if epCreated || epChanged {
			endpointObsID = uuid.NewString()
			payload, _ := json.Marshal(map[string]any{"url": ep.URL, "status": ep.StatusCode, "size": ep.Size})
			if _, err := tx.Exec(
				`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status)
				 VALUES (?, ?, 'endpoint_discovered', ?, 1.0, 'active')`,
				endpointObsID, evidenceID, string(payload),
			); err != nil {
				return nil, fmt.Errorf("insert observation: %w", err)
			}
			if _, err := tx.Exec(
				`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?), (?, ?)`,
				endpointObsID, hostID, endpointObsID, endpointID,
			); err != nil {
				return nil, err
			}
		}

		if epCreated {
			relID := uuid.NewString()
			if _, err := tx.Exec(
				`INSERT INTO relationship(id, source_entity_id, target_entity_id, kind, confidence, supporting_observation_id, valid_from, valid_to)
				 VALUES (?, ?, ?, 'HAS_ENDPOINT', 1.0, ?, ?, NULL)`,
				relID, hostID, endpointID, nullableString(endpointObsID), now,
			); err != nil {
				return nil, fmt.Errorf("insert relationship: %w", err)
			}
			res.NewRelations = append(res.NewRelations, relID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// recordHostFactObservation preserva provenance (principio explícito del
// spec: "Raw Evidence/Observations nunca se descartan") cada vez que un
// atributo de host se crea o cambia por upsert, sin importar qué extractor
// lo produjo.
func recordHostFactObservation(tx *sql.Tx, evidenceID, address string, attrs map[string]any, hostEntityID string) error {
	payload, _ := json.Marshal(map[string]any{"address": address, "attrs": attrs})
	obsID := uuid.NewString()
	if _, err := tx.Exec(
		`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status)
		 VALUES (?, ?, 'host_fact', ?, 1.0, 'active')`,
		obsID, evidenceID, string(payload),
	); err != nil {
		return fmt.Errorf("insert observation: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?)`,
		obsID, hostEntityID,
	); err != nil {
		return err
	}
	return nil
}
