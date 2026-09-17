package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"exitone/internal/llm"
	"exitone/internal/store"

	"github.com/google/uuid"
)

const exploratorySystemPrompt = `Eres el módulo exploratorio de una capa cognitiva local para investigaciones de seguridad autorizadas dirigidas por una persona.
Recibes solo estado estructurado ya observado. Propón preguntas, técnicas o comandos que puedan reducir incertidumbre. No afirmes vulnerabilidades no confirmadas, no encadenes acciones y no ejecutes nada.
Responde exclusivamente con un array JSON de hasta 5 elementos:
[{"kind":"direction|technique|command","phase_key":"discovery|enumeration|analysis|hypotheses|validation|exploitation_guidance|post_access|privilege_access|objectives","intent_key":"...","tool":"","command":"","rationale":"...","expected_evidence":"...","assumptions":["..."],"confidence":0.0,"risk_level":"low|medium|high|critical","basis":[{"ref_type":"entity|hypothesis|objective|evidence|outcome","ref_id":"uuid","role":"supports"}]}]
Para kind=command incluye command; para direction/technique déjalo vacío. Usa solo IDs presentes en el contexto. El humano decide y ejecuta.`

type ProposalBasis struct {
	RefType string `json:"ref_type"`
	RefID   string `json:"ref_id"`
	Role    string `json:"role"`
}

type ExploratoryProposal struct {
	Kind             string          `json:"kind"`
	PhaseKey         string          `json:"phase_key"`
	IntentKey        string          `json:"intent_key"`
	Tool             string          `json:"tool"`
	Command          string          `json:"command"`
	Rationale        string          `json:"rationale"`
	ExpectedEvidence flexString      `json:"expected_evidence"`
	Assumptions      []string        `json:"assumptions"`
	Confidence       float64         `json:"confidence"`
	RiskLevel        string          `json:"risk_level"`
	Basis            []ProposalBasis `json:"basis"`
}

// flexString tolera que un modelo de 3B devuelva "expected_evidence" como un
// array de strings en vez del string único que pide el prompt (bug real
// observado en producción) — se normaliza uniendo con "; " en vez de fallar
// el parseo completo de la propuesta.
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*f = flexString(strings.Join(arr, "; "))
	return nil
}

func EnqueueExploration(s *store.Store, sessionID string) (int64, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE session SET state_revision = state_revision + 1 WHERE id = ?`, sessionID); err != nil {
		return 0, err
	}
	var revision int64
	if err := tx.QueryRow(`SELECT state_revision FROM session WHERE id = ?`, sessionID).Scan(&revision); err != nil {
		return 0, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`INSERT INTO strategy_job(session_id, revision, status, last_error, queued_at, started_at, finished_at)
		VALUES (?, ?, 'pending', '', ?, NULL, NULL)
		ON CONFLICT(session_id) DO UPDATE SET revision=excluded.revision, status='pending', last_error='', queued_at=excluded.queued_at, started_at=NULL, finished_at=NULL`,
		sessionID, revision, now); err != nil {
		return 0, err
	}
	return revision, tx.Commit()
}

func RunExploration(ctx context.Context, s *store.Store, sessionID string, revision int64) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.DB.Exec(`UPDATE strategy_job SET status='running', started_at=? WHERE session_id=? AND revision=? AND status='pending'`, now, sessionID, revision)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, nil
	}

	state, err := buildExploratoryState(s, sessionID)
	if err != nil {
		finishJob(s, sessionID, revision, "failed", err)
		return 0, err
	}
	raw, err := llm.New().Chat(ctx, exploratorySystemPrompt, state)
	if err != nil {
		finishJob(s, sessionID, revision, "failed", err)
		return 0, err
	}
	proposals, err := parseProposals(raw)
	if err != nil {
		finishJob(s, sessionID, revision, "failed", err)
		return 0, err
	}

	var current int64
	if err := s.DB.QueryRow(`SELECT state_revision FROM session WHERE id = ?`, sessionID).Scan(&current); err != nil {
		return 0, err
	}
	if current != revision {
		finishJob(s, sessionID, revision, "stale", nil)
		return 0, nil
	}

	created := 0
	for _, proposal := range proposals {
		ok, err := validateProposal(s, sessionID, &proposal)
		if err != nil {
			return created, err
		}
		if !ok {
			continue
		}
		inserted, err := insertExploratoryCandidate(s, sessionID, revision, proposal)
		if err != nil {
			return created, err
		}
		if inserted {
			created++
		}
	}
	finishJob(s, sessionID, revision, "completed", nil)
	return created, nil
}

func buildExploratoryState(s *store.Store, sessionID string) (string, error) {
	state := map[string]any{"session_id": sessionID}
	var entities []map[string]any
	rows, err := s.DB.Query(`SELECT id, type, canonical_value, attrs FROM entity WHERE session_id = ? ORDER BY type, canonical_value LIMIT 250`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id, typ, value, attrs string
		if err := rows.Scan(&id, &typ, &value, &attrs); err != nil {
			rows.Close()
			return "", err
		}
		if typ == "credential_candidate" {
			value = "<credential-candidate>"
		}
		entities = append(entities, map[string]any{"id": id, "type": typ, "value": value, "attrs": json.RawMessage(attrs)})
	}
	rows.Close()
	state["entities"] = entities

	var objectives []map[string]any
	rows, err = s.DB.Query(`SELECT id, intent_key, phase_key, status FROM methodology_objective WHERE session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id, intent, phase, status string
		_ = rows.Scan(&id, &intent, &phase, &status)
		objectives = append(objectives, map[string]any{"id": id, "intent": intent, "phase": phase, "status": status})
	}
	rows.Close()
	state["methodology_objectives"] = objectives

	var hypotheses []map[string]any
	rows, err = s.DB.Query(`SELECT id, statement, status FROM hypothesis WHERE session_id = ?`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var id, statement, status string
		_ = rows.Scan(&id, &statement, &status)
		hypotheses = append(hypotheses, map[string]any{"id": id, "statement": statement, "status": status})
	}
	rows.Close()
	state["hypotheses"] = hypotheses

	var prior []map[string]any
	rows, err = s.DB.Query(`SELECT c.intent_key, c.phase_key, a.status, COALESCE(o.computed_information_gain,0)
		FROM action a JOIN candidate c ON c.id=a.candidate_id LEFT JOIN outcome o ON o.action_id=a.id
		WHERE c.session_id=? ORDER BY COALESCE(a.executed_at,a.decided_at) DESC LIMIT 50`, sessionID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var intent, phase, status string
		var gain float64
		_ = rows.Scan(&intent, &phase, &status, &gain)
		prior = append(prior, map[string]any{"intent": intent, "phase": phase, "status": status, "information_value": gain})
	}
	rows.Close()
	state["historical_outcomes"] = prior

	b, err := json.Marshal(state)
	return string(b), err
}

func parseProposals(raw string) ([]ExploratoryProposal, error) {
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start < 0 || end < start {
		return nil, fmt.Errorf("respuesta exploratoria sin array JSON")
	}
	var proposals []ExploratoryProposal
	if err := json.Unmarshal([]byte(raw[start:end+1]), &proposals); err != nil {
		return nil, fmt.Errorf("parsear propuestas: %w", err)
	}
	if len(proposals) > 5 {
		proposals = proposals[:5]
	}
	return proposals, nil
}

func validateProposal(s *store.Store, sessionID string, p *ExploratoryProposal) (bool, error) {
	validKinds := map[string]bool{"direction": true, "technique": true, "command": true}
	validPhases := map[string]bool{"discovery": true, "enumeration": true, "analysis": true, "hypotheses": true, "validation": true, "exploitation_guidance": true, "post_access": true, "privilege_access": true, "objectives": true}
	validRisk := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !validKinds[p.Kind] || !validPhases[p.PhaseKey] || !validRisk[p.RiskLevel] || strings.TrimSpace(p.Rationale) == "" {
		return false, nil
	}
	if p.Kind == "command" && (strings.TrimSpace(p.Command) == "" || len(p.Command) > 2000) {
		return false, nil
	}
	if p.Kind != "command" {
		p.Command = ""
		p.Tool = ""
	}
	if p.IntentKey == "" {
		p.IntentKey = "explore_" + p.PhaseKey
	}
	if p.Confidence <= 0 || p.Confidence > 0.5 {
		p.Confidence = 0.5
	}
	for _, basis := range p.Basis {
		exists, err := referenceExists(s, sessionID, basis.RefType, basis.RefID)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
	}
	return true, nil
}

func insertExploratoryCandidate(s *store.Store, sessionID string, revision int64, p ExploratoryProposal) (bool, error) {
	material := strings.Join([]string{p.Kind, p.PhaseKey, p.IntentKey, p.Command, p.Rationale}, "\x00")
	sum := sha256.Sum256([]byte(material))
	fingerprint := hex.EncodeToString(sum[:])
	assumptions, _ := json.Marshal(p.Assumptions)
	terms := ScoreTerms{Novelty: 1, Relevance: 0.8, SourceConfidence: p.Confidence, HypothesisImpact: 0.4, ObjectiveImpact: 0.6, UncertaintyReduction: 0.7}
	termsJSON, _ := json.Marshal(terms)
	id := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.DB.Exec(`INSERT OR IGNORE INTO candidate(
		id, session_id, source, objective_path_id, intent_key, parameters, tool,
		command_template_rendered, score, score_terms, explanation, created_at,
		status, kind, phase_key, confidence, risk_level, expected_evidence,
		assumptions, state_revision, fingerprint
	) VALUES (?, ?, 'llm_exploratory', NULL, ?, '{}', ?, ?, ?, ?, ?, ?, 'proposed', ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, sessionID, p.IntentKey, p.Tool, p.Command, terms.UtilityScore(), string(termsJSON), p.Rationale, now,
		p.Kind, p.PhaseKey, p.Confidence, p.RiskLevel, string(p.ExpectedEvidence), string(assumptions), revision, fingerprint)
	if err != nil {
		return false, err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return false, nil
	}
	for _, basis := range p.Basis {
		role := basis.Role
		if role == "" {
			role = "supports"
		}
		_, _ = s.DB.Exec(`INSERT OR IGNORE INTO candidate_basis(candidate_id, ref_type, ref_id, role) VALUES (?, ?, ?, ?)`, id, basis.RefType, basis.RefID, role)
	}
	return true, nil
}

func referenceExists(s *store.Store, sessionID, refType, refID string) (bool, error) {
	queries := map[string]string{
		"entity":     `SELECT COUNT(*) FROM entity WHERE session_id=? AND id=?`,
		"hypothesis": `SELECT COUNT(*) FROM hypothesis WHERE session_id=? AND id=?`,
		"objective":  `SELECT COUNT(*) FROM methodology_objective WHERE session_id=? AND id=?`,
		"evidence":   `SELECT COUNT(*) FROM evidence ev LEFT JOIN event e ON e.id=ev.event_id WHERE e.session_id=? AND ev.id=?`,
		"outcome":    `SELECT COUNT(*) FROM outcome o JOIN action a ON a.id=o.action_id JOIN candidate c ON c.id=a.candidate_id WHERE c.session_id=? AND o.id=?`,
	}
	query, ok := queries[refType]
	if !ok {
		return false, nil
	}
	var n int
	err := s.DB.QueryRow(query, sessionID, refID).Scan(&n)
	return n > 0, err
}

func finishJob(s *store.Store, sessionID string, revision int64, status string, jobErr error) {
	message := ""
	if jobErr != nil {
		message = jobErr.Error()
	}
	_, _ = s.DB.Exec(`UPDATE strategy_job SET status=?, last_error=?, finished_at=? WHERE session_id=? AND revision=?`,
		status, message, time.Now().UTC().Format(time.RFC3339Nano), sessionID, revision)
}
