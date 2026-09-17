package activity

import (
	"testing"
	"time"

	"exitone/internal/store"

	"github.com/google/uuid"
)

func TestNormalizeCommand(t *testing.T) {
	got := NormalizeCommand("  nmap   -sV  10.0.0.1  # target inferido, verificar antes de ejecutar ")
	if got != "nmap -sV 10.0.0.1" {
		t.Fatalf("NormalizeCommand=%q", got)
	}
}

func TestObserveLinksExactlyOneCandidateAndIsIdempotent(t *testing.T) {
	s, err := store.Open(t.TempDir() + "/activity.db")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sessionID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.DB.Exec(`INSERT INTO session(id,target_label,started_at) VALUES (?, 'target', ?)`, sessionID, now); err != nil {
		t.Fatal(err)
	}
	candidateID := uuid.NewString()
	if _, err := s.DB.Exec(`INSERT INTO candidate(id,session_id,source,intent_key,parameters,tool,command_template_rendered,score,score_terms,explanation,created_at,status,phase_key)
		VALUES (?,?,'methodology','discover','{}','nmap','nmap -sV 10.0.0.1',1,'{}','test',?,'proposed','discovery')`, candidateID, sessionID, now); err != nil {
		t.Fatal(err)
	}
	in := EventInput{SessionID: sessionID, Pane: "%1", Command: "nmap  -sV 10.0.0.1", StartedAt: now, EndedAt: now, Source: "shell_hook"}
	first, err := Observe(s, in)
	if err != nil {
		t.Fatal(err)
	}
	if first.LinkStatus != "matched" || first.ActionID == "" || first.CandidateID != candidateID {
		t.Fatalf("resultado inesperado: %+v", first)
	}
	second, err := Observe(s, in)
	if err != nil {
		t.Fatal(err)
	}
	if second.EventID != first.EventID || second.ActionID != first.ActionID {
		t.Fatalf("observe no fue idempotente: first=%+v second=%+v", first, second)
	}
	var events, actions int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM event`).Scan(&events)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM action`).Scan(&actions)
	if events != 1 || actions != 1 {
		t.Fatalf("events=%d actions=%d", events, actions)
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint(EventInput{SessionID: "s", Pane: "%1", StartedAt: "1", Command: "nmap  10.0.0.1"})
	b := Fingerprint(EventInput{SessionID: "s", Pane: "%1", StartedAt: "1", Command: " nmap 10.0.0.1 "})
	if a != b {
		t.Fatalf("fingerprint debe ignorar whitespace: %s != %s", a, b)
	}
}
