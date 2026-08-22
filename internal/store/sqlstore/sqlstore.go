// Package sqlstore implements store.Store on top of database/sql.
//
// One implementation serves both supported backends: queries are written in
// SQLite-flavoured SQL with `?` placeholders and adapted per backend by
// dialect. Switching is a flag change (-db-driver / -db-dsn), not a code
// change. Timestamps are persisted as INTEGER unix microseconds and secrets as
// BLOB/BYTEA so neither backend needs driver-specific type handling.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dashdns/api/internal/config"
	"github.com/dashdns/api/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib" // postgres driver, registered as "pgx"
	_ "modernc.org/sqlite"             // CGO-free sqlite driver, registered as "sqlite"
)

// Store is the database/sql-backed store.Store.
type Store struct {
	db *sql.DB
	d  dialect
}

var _ store.Store = (*Store)(nil)

// Open connects to driver/dsn and applies the schema.
//
// driver is a config.Driver* constant, not a database/sql driver name: the
// mapping to the concrete driver ("sqlite", "pgx") lives here so callers never
// need to know which package registered it.
func Open(ctx context.Context, driver, dsn string) (*Store, error) {
	var (
		d          dialect
		sqlDriver  string
		maxOpen    int
		serialized bool
	)
	switch driver {
	case config.DriverSQLite:
		d, sqlDriver, serialized = sqliteDialect, "sqlite", true
	case config.DriverPostgres:
		d, sqlDriver, maxOpen = postgresDialect, "pgx", 16
	default:
		return nil, fmt.Errorf("sqlstore: unsupported driver %q", driver)
	}

	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open %s: %w", driver, err)
	}
	if serialized {
		// modernc sqlite handles concurrent readers fine but a single writer
		// avoids SQLITE_BUSY churn under the admin write path. WAL plus one
		// connection is the simplest correct setting for a controller whose
		// write volume is human-scale.
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(maxOpen)
		db.SetMaxIdleConns(maxOpen)
		db.SetConnMaxLifetime(30 * time.Minute)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlstore: ping %s: %w", driver, err)
	}

	s := &Store{db: db, d: d}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// DB exposes the underlying handle for diagnostics. Prefer the repository
// methods; this exists for health checks and tests.
func (s *Store) DB() *sql.DB { return s.db }

// Ping implements store.Store.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Close implements store.Store.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	for _, stmt := range splitStatements(s.d.schema) {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w (statement: %s)", err, firstLine(stmt))
		}
	}
	return nil
}

// splitStatements breaks the schema into individual statements. The DDL is
// ours and contains no semicolons inside literals, so a plain split is safe.
func splitStatements(schema string) []string {
	parts := strings.Split(schema, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// withTx runs fn inside a transaction, rolling back on error or panic.
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}
	return nil
}

func (s *Store) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) txExec(ctx context.Context, tx *sql.Tx, q string, args ...any) (sql.Result, error) {
	return tx.ExecContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) txQueryRow(ctx context.Context, tx *sql.Tx, q string, args ...any) *sql.Row {
	return tx.QueryRowContext(ctx, s.d.rebind(q), args...)
}

func (s *Store) txQuery(ctx context.Context, tx *sql.Tx, q string, args ...any) (*sql.Rows, error) {
	return tx.QueryContext(ctx, s.d.rebind(q), args...)
}

// --- time helpers -----------------------------------------------------------
//
// Both backends store timestamps as unix microseconds. Microsecond resolution
// is deliberate: Last-Modified on GET /api/policies is second-resolution
// anyway, and integers avoid every timezone and driver-parsing difference
// between SQLite and Postgres.

func toMicros(t time.Time) int64 { return t.UTC().UnixMicro() }

func fromMicros(v int64) time.Time { return time.UnixMicro(v).UTC() }

func toNullMicros(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: toMicros(*t), Valid: true}
}

func fromNullMicros(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMicros(v.Int64)
	return &t
}

// isUniqueViolation reports whether err is a duplicate-key error. The two
// drivers surface it differently and neither exposes a shared sentinel, so the
// check is textual; both substrings are stable parts of the drivers' error
// vocabulary (SQLITE_CONSTRAINT_UNIQUE / PostgreSQL SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key value")
}

// mapErr converts driver-level errors into store sentinels.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sql.ErrNoRows):
		return store.ErrNotFound
	case isUniqueViolation(err):
		return fmt.Errorf("%w: %v", store.ErrConflict, err)
	default:
		return err
	}
}
