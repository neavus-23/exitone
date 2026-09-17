package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestOpenMigratesLegacyActionTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE action (
		id TEXT PRIMARY KEY,
		candidate_id TEXT NOT NULL,
		objective_path_id TEXT,
		executed_at TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'awaiting_evidence'
	)`)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, column := range []string{"decided_at", "executed_at", "status"} {
		has, err := columnExists(t.Context(), s.DB, "action", column)
		if err != nil || !has {
			t.Fatalf("columna %s ausente, err=%v", column, err)
		}
	}
}
