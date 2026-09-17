-- ExitOne domain schema — Slice 1 subset (sección D del plan de arquitectura).
-- SQLite + WAL. Relaciones explícitas y tipadas, sin arrays de UUID (ver Changelog v1->v2, punto 4).
-- Copia canónica embebida en el binario; db/schema.sql se mantiene como referencia legible
-- para revisión y como base de una futura migración a Postgres (sección K).

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    target_label TEXT NOT NULL,
    started_at TEXT NOT NULL,
    closed_at TEXT,
    state_revision INTEGER NOT NULL DEFAULT 0
);

-- Comando ejecutado directamente en el shell (via shell hooks). Ver también
-- interactive_session para programas interactivos (D3).
CREATE TABLE IF NOT EXISTS event (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    tmux_pane_id TEXT,
    command_raw TEXT NOT NULL,
    cwd TEXT,
    started_at TEXT,
    ended_at TEXT,
    exit_code INTEGER,
    source TEXT NOT NULL DEFAULT 'shell_hook', -- shell_hook | manual_ingest | pipe_pane
    fingerprint TEXT,
    link_status TEXT NOT NULL DEFAULT 'unmatched', -- unmatched | matched | ambiguous
    UNIQUE(session_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    event_id TEXT REFERENCES event(id),
    raw_output_ref TEXT NOT NULL, -- ruta al archivo de evidencia cruda (Nivel 3, provenance)
    tool_name TEXT NOT NULL,
    parse_level INTEGER NOT NULL, -- 1 = parser determinista, 2 = LLM-assisted
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observation (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    kind TEXT NOT NULL, -- ej. open_port, share, identity
    payload TEXT NOT NULL, -- JSON
    confidence REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' -- active | superseded
);

CREATE TABLE IF NOT EXISTS entity (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    type TEXT NOT NULL, -- host | service | identity | domain | share ...
    canonical_value TEXT NOT NULL,
    attrs TEXT NOT NULL DEFAULT '{}', -- JSON (ej. {"protocol":"smb","port":445})
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(session_id, type, canonical_value)
);

-- Vincula una observation a las entidades que menciona (many-to-many).
CREATE TABLE IF NOT EXISTS observation_entity (
    observation_id TEXT NOT NULL REFERENCES observation(id),
    entity_id TEXT NOT NULL REFERENCES entity(id),
    PRIMARY KEY (observation_id, entity_id)
);

CREATE TABLE IF NOT EXISTS relationship (
    id TEXT PRIMARY KEY,
    source_entity_id TEXT NOT NULL REFERENCES entity(id),
    target_entity_id TEXT NOT NULL REFERENCES entity(id),
    kind TEXT NOT NULL, -- HAS_SERVICE | MEMBER_OF | ... (ver sección D)
    confidence REAL NOT NULL,
    supporting_observation_id TEXT REFERENCES observation(id),
    valid_from TEXT NOT NULL,
    valid_to TEXT
);

CREATE TABLE IF NOT EXISTS methodology_objective (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    intent_key TEXT NOT NULL, -- ej. smb_enumeration
    trigger_entity_id TEXT NOT NULL REFERENCES entity(id),
    status TEXT NOT NULL DEFAULT 'open', -- open | answered
    created_at TEXT NOT NULL,
    phase_key TEXT NOT NULL DEFAULT 'enumeration'
);

-- Caminos alternativos por objective (sección F, punto 6 del changelog: sin bloqueo rígido).
CREATE TABLE IF NOT EXISTS objective_path (
    id TEXT PRIMARY KEY,
    objective_id TEXT NOT NULL REFERENCES methodology_objective(id),
    path_key TEXT NOT NULL, -- ej. anonymous_access
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open | answered | blocked | abandoned
    created_at TEXT NOT NULL
);

-- Candidatos generados por el Candidate Generator (sección G1, multi-fuente).
CREATE TABLE IF NOT EXISTS candidate (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    source TEXT NOT NULL, -- methodology | hypothesis | contradiction | reopening | novelty | llm_exploratory
    objective_path_id TEXT REFERENCES objective_path(id),
    intent_key TEXT NOT NULL, -- ej. enumerate_smb_shares
    parameters TEXT NOT NULL DEFAULT '{}', -- JSON: {target: {value, provenance}, ...}
    tool TEXT NOT NULL,
    command_template_rendered TEXT NOT NULL,
    score REAL NOT NULL,
    score_terms TEXT NOT NULL DEFAULT '{}', -- JSON: {novelty:.., relevance:.., ...} — para `why`
    explanation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'proposed', -- proposed | accepted | dismissed
    hypothesis_id TEXT REFERENCES hypothesis(id), -- solo para candidatos source='reopening'
    kind TEXT NOT NULL DEFAULT 'command', -- direction | technique | command
    phase_key TEXT NOT NULL DEFAULT 'enumeration',
    confidence REAL NOT NULL DEFAULT 1.0,
    risk_level TEXT NOT NULL DEFAULT 'low', -- low | medium | high | critical
    expected_evidence TEXT NOT NULL DEFAULT '',
    assumptions TEXT NOT NULL DEFAULT '[]',
    state_revision INTEGER NOT NULL DEFAULT 0,
    fingerprint TEXT
);

CREATE TABLE IF NOT EXISTS candidate_basis (
    candidate_id TEXT NOT NULL REFERENCES candidate(id) ON DELETE CASCADE,
    ref_type TEXT NOT NULL, -- evidence | observation | entity | hypothesis | objective | outcome
    ref_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'supports',
    PRIMARY KEY(candidate_id, ref_type, ref_id, role)
);

-- Hipótesis (sección D1/8): una conclusión provisional, cerrada a partir de
-- una ACTION concreta y las asunciones vigentes en ese momento. Nunca se
-- reabre interpretando texto — solo por comparación estructural de conjuntos
-- (ver internal/temporal).
-- `hypothesis` = una proposición falsable (Fase 3 del plan de arquitectura).
-- Estados categóricos, nunca una fuerza derivada por conteo de evidencia:
-- UNTESTED (recién abierta) | SUPPORTED (evidencia a favor, sin contradicción) |
-- DISPUTED (evidencia a favor Y en contra) | REFUTED (solo evidencia en
-- contra, cerrada) | CONFIRMED (cierre explícito, no automático) | REOPENED
-- (una observation 'contradicts' llegó DESPUÉS de un cierre CONFIRMED/REFUTED
-- — reapertura genuina, no "apareció una entidad nueva de cierto tipo").
CREATE TABLE IF NOT EXISTS hypothesis (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    statement TEXT NOT NULL,
    subject_entity_id TEXT NOT NULL REFERENCES entity(id), -- ej. el service SSH al que aplica
    status TEXT NOT NULL DEFAULT 'untested',
    confidence REAL NOT NULL DEFAULT 1.0,
    opened_at TEXT NOT NULL,
    closed_at TEXT
);

-- Provenance de una hipótesis al nivel correcto: una OBSERVATION concreta
-- (la afirmación atómica, ej. "445/tcp está abierto"), nunca a un EVIDENCE
-- completo (el artefacto crudo). Trazabilidad resultante:
-- Hypothesis → Observation → Evidence → Event.
CREATE TABLE IF NOT EXISTS hypothesis_observation (
    hypothesis_id TEXT NOT NULL REFERENCES hypothesis(id),
    observation_id TEXT NOT NULL REFERENCES observation(id),
    relation TEXT NOT NULL CHECK(relation IN ('supports','contradicts')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (hypothesis_id, observation_id)
);

-- Vincula una ACTION a la hipótesis que testeó/cerró/confirmó (sección D,
-- tipos de relación tipados: TESTED | INVALIDATES | SUPPORTS | REOPENS).
CREATE TABLE IF NOT EXISTS action_hypothesis (
    action_id TEXT NOT NULL REFERENCES action(id),
    hypothesis_id TEXT NOT NULL REFERENCES hypothesis(id),
    relation_kind TEXT NOT NULL,
    PRIMARY KEY (action_id, hypothesis_id, relation_kind)
);

-- status: 'awaiting_evidence' hasta que se registra un OUTCOME para esta
-- acción; 'resolved' después. Existe para que la auto-ingesta (disparada por
-- el propio comando tecleado, sin --for-action) pueda encontrar y cerrar la
-- acción correcta sola — bug real encontrado en la prueba contra el lab
-- (192.168.72.130): sin esto, la auto-ingesta no sabía qué ACTION cerrar y
-- volvía a generar un candidato ya resuelto.
CREATE TABLE IF NOT EXISTS action (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidate(id),
    objective_path_id TEXT REFERENCES objective_path(id),
    decided_at TEXT,
    executed_at TEXT,
    status TEXT NOT NULL DEFAULT 'planned' -- planned | executed | awaiting_evidence | resolved
);

CREATE TABLE IF NOT EXISTS action_event (
    action_id TEXT NOT NULL REFERENCES action(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES event(id) ON DELETE CASCADE,
    PRIMARY KEY(action_id, event_id)
);

-- Asunciones registradas en el momento de ejecutar la acción (sección D1 —
-- base de Evidence Reopening estructural, no interpretación de texto).
CREATE TABLE IF NOT EXISTS action_assumption (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES action(id),
    entity_id TEXT NOT NULL REFERENCES entity(id),
    role TEXT NOT NULL -- ej. known_identity, known_credential
);

CREATE TABLE IF NOT EXISTS decision_context (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES action(id),
    known_facts_snapshot TEXT NOT NULL, -- JSON
    known_unknowns_snapshot TEXT NOT NULL, -- JSON
    motivating_objective TEXT NOT NULL,
    rationale_text TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outcome (
    id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL REFERENCES action(id),
    new_entities INTEGER NOT NULL DEFAULT 0,
    new_relationships INTEGER NOT NULL DEFAULT 0,
    hypotheses_confirmed INTEGER NOT NULL DEFAULT 0,
    hypotheses_refuted INTEGER NOT NULL DEFAULT 0,
    contradictions_resolved INTEGER NOT NULL DEFAULT 0,
    computed_information_gain REAL NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL
);

-- Puntero a la sesión activa (para no tener que pasar --session en cada comando).
CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Fase 2 del plan de arquitectura: dónde quiere el operador invertir esfuerzo
-- ahora mismo — siempre explícito, nunca inferido (a diferencia de `stage`,
-- que es coverage inferido). Un solo focus activo por sesión; `next`/`status`
-- lo usan para REORDENAR resultados, nunca para ocultarlos.
CREATE TABLE IF NOT EXISTS focus (
    session_id TEXT PRIMARY KEY REFERENCES session(id),
    ref_type   TEXT NOT NULL, -- hypothesis | objective (ver plan N.5 sobre alcance)
    ref_id     TEXT NOT NULL,
    set_at     TEXT NOT NULL
);

-- El operador puede fijar objetivos finales sin convertirlos en facts ni
-- mezclarlos con objectives abiertos automáticamente por metodología.
CREATE TABLE IF NOT EXISTS operator_objective (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    statement TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open | completed | abandoned
    evidence_ref TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

-- Credenciales locales. `secret_value` se guarda en texto por decisión
-- explícita del operador; todos los consumidores deben enmascararlo salvo
-- que se solicite --reveal.
CREATE TABLE IF NOT EXISTS credential (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    identity_entity_id TEXT REFERENCES entity(id),
    service_entity_id TEXT REFERENCES entity(id),
    secret_value TEXT NOT NULL,
    secret_fingerprint TEXT NOT NULL,
    source_ref TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'discovered', -- discovered | valid | invalid | stale
    created_at TEXT NOT NULL,
    UNIQUE(session_id, secret_fingerprint, identity_entity_id, service_entity_id)
);

CREATE TABLE IF NOT EXISTS credential_attempt (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credential(id) ON DELETE CASCADE,
    service_entity_id TEXT REFERENCES entity(id),
    event_id TEXT REFERENCES event(id),
    result TEXT NOT NULL, -- success | fail | unknown
    attempted_at TEXT NOT NULL
);

-- Un solo trabajo de exploración vigente por sesión. Una ingesta nueva
-- reemplaza la revisión pendiente anterior; el worker descarta resultados
-- si la revisión cambia mientras el LLM está razonando.
CREATE TABLE IF NOT EXISTS strategy_job (
    session_id TEXT PRIMARY KEY REFERENCES session(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | running | completed | failed | stale
    last_error TEXT NOT NULL DEFAULT '',
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS schema_migration (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Scope tracking (flujo bug-bounty / pentest con reglas de compromiso): qué
-- assets están autorizados a tocarse. "pattern" es un match simple contra
-- entity.canonical_value (substring/prefijo, NUNCA aritmética real de CIDR
-- todavía — sección de limitaciones honestas). in_scope=0 es una exclusión
-- EXPLÍCITA (ej. "excluido del programa aunque resuelva al mismo dominio"),
-- no lo mismo que "no hay ninguna regla que lo mencione" (unknown).
CREATE TABLE IF NOT EXISTS scope_rule (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES session(id),
    pattern    TEXT NOT NULL,
    in_scope   INTEGER NOT NULL, -- 1 = in-scope, 0 = excluido explícitamente
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
