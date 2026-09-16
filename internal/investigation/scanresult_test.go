package investigation

import (
	"database/sql"
	"testing"
	"time"

	"exitone/internal/parsers"
	"exitone/internal/store"

	"github.com/google/uuid"
)

func newTestSession(t *testing.T) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	sessionID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO session(id, target_label, started_at) VALUES (?, ?, ?)`,
		sessionID, "test-target", now,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return s, sessionID
}

func sampleScanResult() parsers.ScanResult {
	return parsers.ScanResult{
		Hosts: []parsers.HostFact{{Address: "192.168.72.130", Hostname: "ubuntu-lab"}},
		Services: []parsers.ServiceFact{
			{HostAddress: "192.168.72.130", Protocol: "tcp", Port: 22, State: "open", Name: "ssh", Version: "OpenSSH 7.6p1"},
			{HostAddress: "192.168.72.130", Protocol: "tcp", Port: 80, State: "open", Name: "http", Version: "Apache 2.4.29"},
		},
	}
}

func countRows(t *testing.T, s *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

func TestApplyScanResult_CreatesHostAndServices(t *testing.T) {
	s, sessionID := newTestSession(t)

	res, err := ApplyScanResult(s, sessionID, "/tmp/scan.xml", "", sampleScanResult())
	if err != nil {
		t.Fatalf("ApplyScanResult: %v", err)
	}
	if len(res.NewEntities) != 3 { // 1 host + 2 services
		t.Errorf("new entities = %d, want 3: %v", len(res.NewEntities), res.NewEntities)
	}
	if len(res.NewRelations) != 2 {
		t.Errorf("new relations = %d, want 2", len(res.NewRelations))
	}

	hosts := countRows(t, s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'host'`, sessionID)
	if hosts != 1 {
		t.Errorf("host entity count = %d, want 1", hosts)
	}
	services := countRows(t, s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service'`, sessionID)
	if services != 2 {
		t.Errorf("service entity count = %d, want 2", services)
	}

	var hostname string
	if err := s.DB.QueryRow(
		`SELECT json_extract(attrs, '$.hostname') FROM entity WHERE session_id = ? AND type = 'host'`,
		sessionID,
	).Scan(&hostname); err != nil {
		t.Fatalf("query hostname attr: %v", err)
	}
	if hostname != "ubuntu-lab" {
		t.Errorf("host hostname attr = %q, want ubuntu-lab", hostname)
	}
}

// TestApplyScanResult_Idempotent valida el punto 3/4 del vertical slice del
// plan: re-ingerir el mismo escaneo dos veces no debe duplicar host/service
// (mismo comportamiento que report_host/report_service en Metasploit).
func TestApplyScanResult_Idempotent(t *testing.T) {
	s, sessionID := newTestSession(t)

	if _, err := ApplyScanResult(s, sessionID, "/tmp/scan1.xml", "", sampleScanResult()); err != nil {
		t.Fatalf("first ApplyScanResult: %v", err)
	}
	res2, err := ApplyScanResult(s, sessionID, "/tmp/scan2.xml", "", sampleScanResult())
	if err != nil {
		t.Fatalf("second ApplyScanResult: %v", err)
	}

	if len(res2.NewEntities) != 0 {
		t.Errorf("second ingest created new entities, want 0: %v", res2.NewEntities)
	}
	if len(res2.NewRelations) != 0 {
		t.Errorf("second ingest created new relations, want 0: %v", res2.NewRelations)
	}

	hosts := countRows(t, s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'host'`, sessionID)
	if hosts != 1 {
		t.Errorf("host entity count after re-ingest = %d, want 1 (no duplicate)", hosts)
	}
	services := countRows(t, s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'service'`, sessionID)
	if services != 2 {
		t.Errorf("service entity count after re-ingest = %d, want 2 (no duplicate)", services)
	}
}

// TestApplyScanResult_ServiceCascadesHostUpsert valida el patrón
// report_service→report_host de Metasploit: un ServiceFact cuyo host no fue
// observado por separado debe crear igual el host, en un solo ApplyScanResult.
func TestApplyScanResult_ServiceCascadesHostUpsert(t *testing.T) {
	s, sessionID := newTestSession(t)

	result := parsers.ScanResult{
		Services: []parsers.ServiceFact{
			{HostAddress: "10.0.0.9", Protocol: "tcp", Port: 445, Name: "smb"},
		},
	}
	res, err := ApplyScanResult(s, sessionID, "/tmp/scan.json", "", result)
	if err != nil {
		t.Fatalf("ApplyScanResult: %v", err)
	}
	if len(res.NewEntities) != 2 { // host cascada + service
		t.Fatalf("new entities = %d, want 2 (cascaded host + service): %v", len(res.NewEntities), res.NewEntities)
	}
	hosts := countRows(t, s, `SELECT COUNT(*) FROM entity WHERE session_id = ? AND type = 'host' AND canonical_value = '10.0.0.9'`, sessionID)
	if hosts != 1 {
		t.Errorf("cascaded host not created, count = %d", hosts)
	}
}

// TestApplyScanResult_ClosesProvenanceChain valida la Fase 1 del plan de
// arquitectura: evidence.event_id y relationship.supporting_observation_id
// deben quedar poblados cuando el llamador sí conoce el evento/comando que
// produjo la evidencia — antes de este fix, ambos quedaban NULL siempre, sin
// excepción, incluso cuando esa información existía.
func TestApplyScanResult_ClosesProvenanceChain(t *testing.T) {
	s, sessionID := newTestSession(t)

	// Simula un evento real ya insertado por resolveEvent (cmd/exitone/main.go).
	eventID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(
		`INSERT INTO event(id, session_id, command_raw, started_at, exit_code) VALUES (?, ?, ?, ?, 0)`,
		eventID, sessionID, "nmap -sV 192.168.72.130", now,
	); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	if _, err := ApplyScanResult(s, sessionID, "/tmp/scan.xml", eventID, sampleScanResult()); err != nil {
		t.Fatalf("ApplyScanResult: %v", err)
	}

	var evEventID string
	if err := s.DB.QueryRow(`SELECT event_id FROM evidence ORDER BY created_at DESC LIMIT 1`).Scan(&evEventID); err != nil {
		t.Fatalf("query evidence.event_id: %v", err)
	}
	if evEventID != eventID {
		t.Errorf("evidence.event_id = %q, want %q — la cadena Event→Evidence sigue rota", evEventID, eventID)
	}

	var relSupportingObs string
	if err := s.DB.QueryRow(
		`SELECT supporting_observation_id FROM relationship WHERE kind = 'HAS_SERVICE' LIMIT 1`,
	).Scan(&relSupportingObs); err != nil {
		t.Fatalf("query relationship.supporting_observation_id: %v", err)
	}
	if relSupportingObs == "" {
		t.Error("relationship.supporting_observation_id sigue NULL pese a existir una observation en la misma transacción")
	}

	// Sin eventID (ingest manual): NULL sigue siendo el resultado correcto,
	// no se debe inventar un evento donde no lo hay.
	if _, err := ApplyScanResult(s, sessionID, "/tmp/scan2.xml", "", parsers.ScanResult{
		Hosts: []parsers.HostFact{{Address: "10.0.0.50"}},
	}); err != nil {
		t.Fatalf("ApplyScanResult (sin evento): %v", err)
	}
	var noEventID sql.NullString
	if err := s.DB.QueryRow(
		`SELECT event_id FROM evidence WHERE raw_output_ref = '/tmp/scan2.xml'`,
	).Scan(&noEventID); err != nil {
		t.Fatalf("query evidence.event_id (sin evento): %v", err)
	}
	if noEventID.Valid {
		t.Errorf("evidence.event_id = %q, want NULL cuando no se pasó eventID", noEventID.String)
	}
}

// TestUpsertEntity_MergesChangedAttrsOnly valida el patrón
// report_host/report_service de Metasploit directamente sobre upsertEntity:
// solo se sobrescriben campos que cambiaron, nunca con un valor vacío.
func TestUpsertEntity_MergesChangedAttrsOnly(t *testing.T) {
	s, sessionID := newTestSession(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	id1, created1, changed1, err := upsertEntity(tx, sessionID, "host", "10.0.0.1", map[string]any{"os": "linux"}, now)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if !created1 || !changed1 {
		t.Fatalf("first upsert: created=%v changed=%v, want true/true", created1, changed1)
	}

	id2, created2, changed2, err := upsertEntity(tx, sessionID, "host", "10.0.0.1", map[string]any{"os": "linux", "arch": "x86_64"}, now)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id1 != id2 {
		t.Errorf("second upsert created a new entity id: %s vs %s", id1, id2)
	}
	if created2 {
		t.Errorf("second upsert reported created=true, want false")
	}
	if !changed2 {
		t.Errorf("second upsert reported changed=false, want true (new 'arch' field)")
	}

	id3, created3, changed3, err := upsertEntity(tx, sessionID, "host", "10.0.0.1", map[string]any{"os": "linux"}, now)
	if err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	if id3 != id1 || created3 || changed3 {
		t.Errorf("third upsert (no new info) = created=%v changed=%v, want false/false", created3, changed3)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
