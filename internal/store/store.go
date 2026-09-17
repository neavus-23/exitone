// Package store gives access to the ExitOne SQLite domain database
// (sección K/D del plan de arquitectura: SQLite+WAL, sin motor de grafos).
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

type Store struct {
	DB *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := applyMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	return &Store{DB: db}, nil
}

// applyMigrations actualiza bases creadas por versiones anteriores. SQLite
// no permite volver nullable una columna mediante ALTER COLUMN, por lo que
// `action` se reconstruye una sola vez para separar decisión de ejecución.
// Las comprobaciones por columna hacen la migración segura tanto para una
// base antigua como para una base nueva creada ya con el schema actual.
func applyMigrations(db *sql.DB) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migration(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}

	if err := applyMigrationV1(ctx, conn); err != nil {
		return err
	}
	if err := applyMigrationV2(ctx, conn); err != nil {
		return err
	}
	return nil
}

// applyMigrationV2 agrega severidad/remediación/prueba de impacto a
// `hypothesis` — el reporte final (`exitone report`) necesita estos campos
// para producir hallazgos con formato profesional, y deben ser explícitos
// (fijados por el operador al cerrar la hipótesis), nunca inferidos por el
// LLM ni por conteo.
func applyMigrationV2(ctx context.Context, conn *sql.Conn) error {
	var alreadyApplied int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migration WHERE version = 2`).Scan(&alreadyApplied); err != nil {
		return err
	}
	if alreadyApplied > 0 {
		return nil
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	columns := []struct{ table, column, definition string }{
		{"hypothesis", "severity", `TEXT NOT NULL DEFAULT ''`},
		{"hypothesis", "remediation", `TEXT NOT NULL DEFAULT ''`},
		{"hypothesis", "evidence_note", `TEXT NOT NULL DEFAULT ''`},
	}
	for _, c := range columns {
		has, err := columnExists(ctx, tx, c.table, c.column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, c.table, c.column, c.definition)); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migration(version, applied_at) VALUES (2, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func applyMigrationV1(ctx context.Context, conn *sql.Conn) error {
	var alreadyApplied int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migration WHERE version = 1`).Scan(&alreadyApplied); err != nil {
		return err
	}
	if alreadyApplied > 0 {
		return nil
	}

	// SQLite solo permite cambiar foreign_keys fuera de una transacción. La
	// migración completa sí es atómica: si una sentencia falla, se revierte
	// tanto la reconstrucción de action como todas las columnas e índices.
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`)
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	addColumn := func(table, column, definition string) error {
		has, err := columnExists(ctx, tx, table, column)
		if err != nil || has {
			return err
		}
		_, err = tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, definition))
		return err
	}

	columns := []struct{ table, column, definition string }{
		{"session", "state_revision", `INTEGER NOT NULL DEFAULT 0`},
		{"event", "fingerprint", `TEXT`},
		{"event", "link_status", `TEXT NOT NULL DEFAULT 'unmatched'`},
		{"methodology_objective", "phase_key", `TEXT NOT NULL DEFAULT 'enumeration'`},
		{"candidate", "kind", `TEXT NOT NULL DEFAULT 'command'`},
		{"candidate", "phase_key", `TEXT NOT NULL DEFAULT 'enumeration'`},
		{"candidate", "confidence", `REAL NOT NULL DEFAULT 1.0`},
		{"candidate", "risk_level", `TEXT NOT NULL DEFAULT 'low'`},
		{"candidate", "expected_evidence", `TEXT NOT NULL DEFAULT ''`},
		{"candidate", "assumptions", `TEXT NOT NULL DEFAULT '[]'`},
		{"candidate", "state_revision", `INTEGER NOT NULL DEFAULT 0`},
		{"candidate", "fingerprint", `TEXT`},
	}
	for _, c := range columns {
		if err := addColumn(c.table, c.column, c.definition); err != nil {
			return fmt.Errorf("add %s.%s: %w", c.table, c.column, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE methodology_objective SET phase_key = CASE
		WHEN intent_key = 'initial_discovery' THEN 'discovery'
		WHEN intent_key = 'ssh_auth_investigation' THEN 'validation'
		ELSE phase_key END`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE candidate SET phase_key = CASE
		WHEN intent_key = 'discover_exposed_services' THEN 'discovery'
		WHEN intent_key = 'test_ssh_auth' THEN 'validation'
		ELSE phase_key END`); err != nil {
		return err
	}

	actionMigrated, err := columnExists(ctx, tx, "action", "decided_at")
	if err != nil {
		return err
	}
	if !actionMigrated {
		statements := []string{
			`CREATE TABLE action_new (
				id TEXT PRIMARY KEY,
				candidate_id TEXT NOT NULL REFERENCES candidate(id),
				objective_path_id TEXT REFERENCES objective_path(id),
				decided_at TEXT,
				executed_at TEXT,
				status TEXT NOT NULL DEFAULT 'planned'
			)`,
			`INSERT INTO action_new(id, candidate_id, objective_path_id, decided_at, executed_at, status)
			 SELECT id, candidate_id, objective_path_id, executed_at, executed_at, status FROM action`,
			`DROP TABLE action`,
			`ALTER TABLE action_new RENAME TO action`,
		}
		for _, stmt := range statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate action: %w", err)
			}
		}
	}

	indexes := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_event_fingerprint ON event(session_id, fingerprint) WHERE fingerprint IS NOT NULL`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_candidate_fingerprint ON candidate(session_id, fingerprint) WHERE fingerprint IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_action_status ON action(status, executed_at)`,
	}
	for _, stmt := range indexes {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO schema_migration(version, applied_at) VALUES (1, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

type pragmaQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func columnExists(ctx context.Context, q pragmaQueryer, table, column string) (bool, error) {
	rows, err := q.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) Close() error {
	return s.DB.Close()
}

func (s *Store) SetAppState(key, value string) error {
	_, err := s.DB.Exec(
		`INSERT INTO app_state(key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

func (s *Store) GetAppState(key string) (string, bool, error) {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM app_state WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}
