package sqlstore

import (
	"strconv"
	"strings"
)

// dialect captures the handful of places where SQLite and Postgres differ.
// Every query in this package is written once, in SQLite-flavoured SQL with `?`
// placeholders, and adapted through here. Timestamps are stored as INTEGER unix
// microseconds and binary columns as BLOB/BYTEA so no driver-specific type
// conversion is needed on either backend.
type dialect struct {
	name string
	// numberedPlaceholders rewrites `?` to `$1, $2, ...` (Postgres).
	numberedPlaceholders bool
	// schema is the full DDL, applied inside a single transaction at startup.
	schema string
}

// rebind adapts a `?`-placeholder query to the dialect. No query in this
// package contains a literal `?` inside a string constant, so a plain scan is
// sufficient.
func (d dialect) rebind(query string) string {
	if !d.numberedPlaceholders {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] != '?' {
			b.WriteByte(query[i])
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

var sqliteDialect = dialect{
	name:                 "sqlite",
	numberedPlaceholders: false,
	schema: `
CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_revisions (
	tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
	revision   INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
	id         TEXT PRIMARY KEY,
	tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	client_ip  TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	UNIQUE (tenant_id, client_ip)
);

CREATE TABLE IF NOT EXISTS policy_domains (
	policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	domain    TEXT NOT NULL,
	PRIMARY KEY (policy_id, domain)
);

CREATE TABLE IF NOT EXISTS appliances (
	id          TEXT PRIMARY KEY,
	tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	token_id    TEXT NOT NULL UNIQUE,
	token_hash  BLOB NOT NULL,
	created_at  INTEGER NOT NULL,
	last_seen_at INTEGER,
	revoked_at   INTEGER,
	UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS admin_users (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	username      TEXT NOT NULL UNIQUE,
	role          TEXT NOT NULL,
	password_hash BLOB NOT NULL,
	password_salt BLOB NOT NULL,
	created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
	token_id      TEXT PRIMARY KEY,
	token_hash    BLOB NOT NULL,
	admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	created_at    INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_appliances_tenant ON appliances (tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions (expires_at);
`,
}

var postgresDialect = dialect{
	name:                 "postgres",
	numberedPlaceholders: true,
	schema: `
CREATE TABLE IF NOT EXISTS tenants (
	id         TEXT PRIMARY KEY,
	name       TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_revisions (
	tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
	revision   BIGINT NOT NULL,
	updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
	id         TEXT PRIMARY KEY,
	tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	client_ip  TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL,
	UNIQUE (tenant_id, client_ip)
);

CREATE TABLE IF NOT EXISTS policy_domains (
	policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	domain    TEXT NOT NULL,
	PRIMARY KEY (policy_id, domain)
);

CREATE TABLE IF NOT EXISTS appliances (
	id          TEXT PRIMARY KEY,
	tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	name        TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	token_id    TEXT NOT NULL UNIQUE,
	token_hash  BYTEA NOT NULL,
	created_at  BIGINT NOT NULL,
	last_seen_at BIGINT,
	revoked_at   BIGINT,
	UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS admin_users (
	id            TEXT PRIMARY KEY,
	tenant_id     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	username      TEXT NOT NULL UNIQUE,
	role          TEXT NOT NULL,
	password_hash BYTEA NOT NULL,
	password_salt BYTEA NOT NULL,
	created_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
	token_id      TEXT PRIMARY KEY,
	token_hash    BYTEA NOT NULL,
	admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
	created_at    BIGINT NOT NULL,
	expires_at    BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policies_tenant ON policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_appliances_tenant ON appliances (tenant_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions (expires_at);
`,
}
