package main

import (
	"exitone/internal/console"
	"exitone/internal/store"
)

// descendantEntityIDs devuelve el propio host más cualquier entidad
// alcanzable desde él vía HAS_SERVICE/HAS_ENDPOINT — usado tanto por `show`
// contextual como por la regla de "relacionado" de `next` dentro de un
// contexto Host (sección I del plan: "Host → candidate relacionado a
// entidades descendientes HAS_SERVICE/HAS_ENDPOINT").
func descendantEntityIDs(s *store.Store, hostEntityID string) ([]string, error) {
	ids := []string{hostEntityID}
	rows, err := s.DB.Query(
		`SELECT target_entity_id FROM relationship WHERE source_entity_id = ? AND kind IN ('HAS_SERVICE', 'HAS_ENDPOINT')`,
		hostEntityID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// relatedCandidateIDs implementa, en un solo lugar, las reglas
// deterministas de "relacionado" de la sección I del plan — reutilizado
// tanto por `show candidates` (filtro salvo --all) como por
// printCandidatesForViewContext (`next` contextual). Ninguno de los dos
// lee ni escribe la tabla `focus`; esto es pura relación de datos.
func relatedCandidateIDs(s *store.Store, sessionID string, ctx console.ConsoleContext) (map[string]bool, error) {
	related := map[string]bool{}

	addFromRows := func(rows interface {
		Next() bool
		Scan(...any) error
		Err() error
	}) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			related[id] = true
		}
		return rows.Err()
	}

	switch ctx.Type {
	case console.Hypothesis:
		rows, err := s.DB.Query(`SELECT id FROM candidate WHERE session_id = ? AND hypothesis_id = ?`, sessionID, ctx.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		if err := addFromRows(rows); err != nil {
			return nil, err
		}

	case console.Objective:
		rows, err := s.DB.Query(`
			SELECT c.id FROM candidate c
			JOIN objective_path op ON op.id = c.objective_path_id
			WHERE c.session_id = ? AND op.objective_id = ?`, sessionID, ctx.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		if err := addFromRows(rows); err != nil {
			return nil, err
		}

	case console.Service:
		if err := addRelatedByTriggerOrSubject(s, sessionID, []string{ctx.ID}, related); err != nil {
			return nil, err
		}

	case console.Host:
		descendants, err := descendantEntityIDs(s, ctx.ID)
		if err != nil {
			return nil, err
		}
		if err := addRelatedByTriggerOrSubject(s, sessionID, descendants, related); err != nil {
			return nil, err
		}

	case console.Candidate:
		related[ctx.ID] = true
	}

	return related, nil
}

// addRelatedByTriggerOrSubject cubre las reglas de Service/Host de la
// sección I: un candidate está relacionado si su objective_path apunta a un
// objective disparado por alguna de las entidades dadas, O si su hypothesis
// tiene subject_entity_id entre esas mismas entidades.
func addRelatedByTriggerOrSubject(s *store.Store, sessionID string, entityIDs []string, out map[string]bool) error {
	if len(entityIDs) == 0 {
		return nil
	}
	placeholders, args := inClause(entityIDs)
	args = append([]any{sessionID}, args...)
	args = append(args, args[1:]...) // el mismo IN (...) se usa dos veces (trigger y subject)

	query := `
		SELECT c.id FROM candidate c
		LEFT JOIN objective_path op ON op.id = c.objective_path_id
		LEFT JOIN methodology_objective mo ON mo.id = op.objective_id
		LEFT JOIN hypothesis h ON h.id = c.hypothesis_id
		WHERE c.session_id = ? AND (mo.trigger_entity_id IN (` + placeholders + `) OR h.subject_entity_id IN (` + placeholders + `))`

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		out[id] = true
	}
	return rows.Err()
}

// candidateTargetHost resuelve la dirección del host detrás de un
// candidate — vía el objective que lo disparó o la hypothesis a la que
// responde, subiendo un salto más si esa entidad es un service — para poder
// marcarlo con scopeLabel sin que el operador tenga que rastrear la cadena
// a mano. Devuelve "" si no se pudo resolver (candidate huérfano de ambos).
func candidateTargetHost(s *store.Store, candidateID string) string {
	var entityID string
	err := s.DB.QueryRow(`
		SELECT mo.trigger_entity_id FROM candidate c
		JOIN objective_path op ON op.id = c.objective_path_id
		JOIN methodology_objective mo ON mo.id = op.objective_id
		WHERE c.id = ?`, candidateID).Scan(&entityID)
	if err != nil {
		err = s.DB.QueryRow(`
			SELECT h.subject_entity_id FROM candidate c
			JOIN hypothesis h ON h.id = c.hypothesis_id
			WHERE c.id = ?`, candidateID).Scan(&entityID)
	}
	if err != nil {
		err = s.DB.QueryRow(`
			SELECT cb.ref_id FROM candidate_basis cb
			JOIN entity e ON e.id = cb.ref_id
			WHERE cb.candidate_id = ? AND cb.ref_type = 'entity'
			ORDER BY CASE e.type WHEN 'host' THEN 0 WHEN 'service' THEN 1 ELSE 2 END
			LIMIT 1`, candidateID).Scan(&entityID)
	}
	if err != nil || entityID == "" {
		return ""
	}

	var etype, value string
	if err := s.DB.QueryRow(`SELECT type, canonical_value FROM entity WHERE id = ?`, entityID).Scan(&etype, &value); err != nil {
		return ""
	}
	if etype == "host" {
		return value
	}

	var hostAddr string
	err = s.DB.QueryRow(`
		SELECT h.canonical_value FROM relationship r
		JOIN entity h ON h.id = r.source_entity_id
		WHERE r.target_entity_id = ? AND r.kind = 'HAS_SERVICE'`, entityID).Scan(&hostAddr)
	if err != nil && (etype == "domain" || etype == "hostname") {
		return value
	}
	return hostAddr
}

// inClause arma "?,?,?" + los args correspondientes para un IN (...).
func inClause(values []string) (string, []any) {
	placeholders := ""
	args := make([]any, len(values))
	for i, v := range values {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args[i] = v
	}
	return placeholders, args
}
