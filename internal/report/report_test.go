package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"exitone/internal/store"
)

func newTestSession(t *testing.T) (*store.Store, string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sessionID := "sess-1"
	if _, err := s.DB.Exec(`INSERT INTO session(id, target_label, started_at) VALUES (?, 'target.example', ?)`, sessionID, now); err != nil {
		t.Fatal(err)
	}
	return s, sessionID
}

// TestLoadFindingsOrdersBySeverity cubre el bug real encontrado revisando el
// primer reporte generado contra HTB Nexus: los hallazgos deben salir con el
// más grave primero, nunca en el orden en que se confirmaron.
func TestLoadFindingsOrdersBySeverity(t *testing.T) {
	s, sessionID := newTestSession(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO entity(id, session_id, type, canonical_value, first_seen, last_seen) VALUES ('host-1', ?, 'host', '10.0.0.1', ?, ?)`, sessionID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`
		INSERT INTO hypothesis(id, session_id, statement, subject_entity_id, status, severity, remediation, evidence_note, opened_at, closed_at)
		VALUES
			('hyp-low', ?, 'Baja severidad', 'host-1', 'confirmed', 'low', 'parchear', 'prueba baja', ?, ?),
			('hyp-critical', ?, 'RCE confirmado', 'host-1', 'confirmed', 'critical', 'parchear ya', 'shell obtenida', ?, ?)`,
		sessionID, now, now, sessionID, now, now); err != nil {
		t.Fatal(err)
	}

	findings, err := LoadFindings(s, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("esperaba 2 hallazgos confirmados, obtuve %d", len(findings))
	}
	if findings[0].Severity != "critical" || findings[1].Severity != "low" {
		t.Fatalf("orden incorrecto: %s luego %s (esperaba critical, low)", findings[0].Severity, findings[1].Severity)
	}
}

// TestGenerateProducesAllSections confirma que el reporte determinista
// (--raw) nunca omite una sección en silencio, aunque esté vacía — cada una
// debe aparecer con su propio encabezado incluso sin datos.
func TestGenerateProducesAllSections(t *testing.T) {
	s, sessionID := newTestSession(t)
	md, err := Generate(s, sessionID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{
		"## Alcance autorizado",
		"## Resumen ejecutivo",
		"## Cobertura de la investigación",
		"## Hallazgos confirmados",
		"## Credenciales encontradas",
		"## Cronología completa",
		"## Preguntas de metodología sin responder",
	} {
		if !strings.Contains(md, header) {
			t.Errorf("reporte generado sin la sección %q", header)
		}
	}
}
