package investigation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"exitone/internal/credential"
	"exitone/internal/llm"
	"exitone/internal/store"

	"github.com/google/uuid"
)

// knownBenignShellNoise son mensajes rutinarios de cualquier shell obtenida
// vía netcat/reverse-shell (falta de tty real) — nunca indican una debilidad
// de seguridad por sí solos, así que nunca deben convertirse en
// weakness_candidate aunque el LLM los señale. Bug real encontrado
// validando contra HTB Nexus: el extractor Nivel 2 marcó literalmente
// "bash: cannot set terminal process group..." como una debilidad.
var knownBenignShellNoise = []string{
	"cannot set terminal process group",
	"no job control in this shell",
	"inappropriate ioctl for device",
}

func isBenignShellNoise(value string) bool {
	lower := strings.ToLower(value)
	for _, noise := range knownBenignShellNoise {
		if strings.Contains(lower, noise) {
			return true
		}
	}
	return false
}

// IngestGeneric registra evidencia de Nivel 2 (LLM-assisted, sección 6/8/J
// del plan): cada Observation queda marcada con status='candidate' — NUNCA
// 'active' como las de Nivel 1 — y con la confianza ya acotada por
// internal/llm.ExtractObservations. Las entidades sí se crean (para que
// aparezcan en el Investigation Model y el operador las vea), pero quedan
// etiquetadas attrs.extracted_by="llm" para que cualquier consumidor futuro
// pueda tratarlas con más cautela que una entidad de Nivel 1.
func IngestGeneric(s *store.Store, sessionID, rawOutputRef, eventID, toolName string, obs []llm.CandidateObservation) (*IngestResult, error) {
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
		 VALUES (?, ?, ?, ?, 2, ?)`,
		evidenceID, nullableString(eventID), rawOutputRef, toolName, now,
	); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	res.EvidenceID = evidenceID

	entityTypeByKind := map[string]string{
		"endpoint":   "endpoint",
		"identity":   "identity",
		"technology": "technology",
		"domain":     "domain",
		"credential": "credential_candidate",
		"weakness":   "weakness_candidate",
		"access":     "access_context",
		"principal":  "principal",
		"privilege":  "privilege",
		"objective":  "objective_result",
	}

	// Los candidatos de credencial se registran DESPUÉS de tx.Commit(): la
	// tabla `credential` no participa de esta transacción, y `credential.Add`
	// abre su propia conexión vía `s.DB` — llamarlo mientras `tx` todavía
	// tiene el único write-lock de SQLite abierto produce
	// "database is locked" (bug real encontrado arreglando el problema
	// anterior de los dos sistemas de credenciales separados).
	var credentialObs []llm.CandidateObservation

	// identityEntityIDs junta TODAS las identidades (kind="identity" o
	// "principal") vistas en este mismo lote de extracción — sin asumir que
	// el LLM las devuelve en el mismo orden en que aparecen en el texto (no
	// lo hace de forma confiable). Si el lote menciona EXACTAMENTE una
	// identidad, es razonable asumir que es la dueña de cualquier credencial
	// del mismo lote (mismo archivo, misma llamada al LLM) — igual que
	// `currentAddr` en internal/parsers/table.go asocia servicios al host
	// más reciente del mismo archivo. Si hay cero o más de una, no se
	// adivina cuál corresponde: queda sin vincular en vez de arriesgar un
	// link incorrecto. Nunca se le pide al operador que lo especifique a
	// mano si ya está en el mismo output — eso sería inconsistente con cómo
	// se auto-vinculan el resto de las relaciones (host↔service, etc.).
	var identityEntityIDs []string

	for _, o := range obs {
		// Ruido benigno conocido de cualquier shell sin tty real — nunca se
		// registra como weakness_candidate, sin importar qué haya dicho el LLM.
		if o.Kind == "weakness" && isBenignShellNoise(o.Value) {
			continue
		}

		// Un credential candidato del extractor genérico converge en la MISMA
		// tabla `credential` que usa `exitone credential add` — antes creaba
		// una entidad `credential_candidate` aparte, sin ningún vínculo con el
		// mecanismo real de credenciales (masking, `--reveal`, `attempt`).
		// Bug real encontrado validando contra HTB Nexus: dos sistemas de
		// credenciales que no se cruzaban entre sí.
		if o.Kind == "credential" {
			credentialObs = append(credentialObs, o)
			continue
		}

		entType, ok := entityTypeByKind[o.Kind]
		if !ok {
			entType = "candidate_fact" // kind="other" u otro valor no reconocido
		}

		payload, _ := json.Marshal(map[string]any{"kind": o.Kind, "value": o.Value, "tool": toolName})
		obsID := uuid.NewString()
		if _, err := tx.Exec(
			`INSERT INTO observation(id, evidence_id, kind, payload, confidence, status) VALUES (?, ?, ?, ?, ?, 'candidate')`,
			obsID, evidenceID, o.Kind, string(payload), o.Confidence,
		); err != nil {
			return nil, fmt.Errorf("insert observation: %w", err)
		}

		attrs := map[string]any{"extracted_by": "llm", "source_tool": toolName, "confidence": o.Confidence}
		entID, created, _, err := upsertEntity(tx, sessionID, entType, o.Value, attrs, now)
		if err != nil {
			return nil, err
		}
		if created {
			res.NewEntities = append(res.NewEntities, entID)
		}
		if _, err := tx.Exec(`INSERT INTO observation_entity(observation_id, entity_id) VALUES (?, ?)`, obsID, entID); err != nil {
			return nil, err
		}
		if o.Kind == "identity" || o.Kind == "principal" {
			identityEntityIDs = append(identityEntityIDs, entID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var solelyIdentifiedEntityID string
	if len(identityEntityIDs) == 1 {
		solelyIdentifiedEntityID = identityEntityIDs[0]
	}

	for _, o := range credentialObs {
		source := fmt.Sprintf("extracción Nivel 2 (LLM, confianza %.2f) de %s", o.Confidence, toolName)
		if _, err := credential.AddWithEntityIDs(s, sessionID, solelyIdentifiedEntityID, "", o.Value, source); err != nil {
			return res, fmt.Errorf("registrar credential candidate (evidencia ya guardada): %w", err)
		}
	}
	return res, nil
}

// IngestUnparsed conserva el artefacto aunque el LLM local no esté
// disponible o no encuentre observaciones. La ausencia del modelo nunca
// debe borrar telemetría ni convertir una ingesta válida en un fallo total.
func IngestUnparsed(s *store.Store, rawOutputRef, eventID, toolName string) (*IngestResult, error) {
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO evidence(id, event_id, raw_output_ref, tool_name, parse_level, created_at)
		VALUES (?, ?, ?, ?, 0, ?)`, id, nullableString(eventID), rawOutputRef, toolName, now); err != nil {
		return nil, fmt.Errorf("insert unparsed evidence: %w", err)
	}
	return &IngestResult{EvidenceID: id}, nil
}
