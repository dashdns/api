# policy-controller

DNS policy control plane for [dnsd](https://github.com/dashdns/dnsd), the eBPF DNS proxy.

dnsd appliances poll this service with their `-ip-blocklist-url` flag and install the
returned per-IP domain blocklist into their `ip_blocklist` BPF map. This repository is
the write side of that contract: a small Go service with a management API, appliance
token issuance, optional multi-tenancy, and a cacheable read endpoint.

One binary covers both deployment shapes:

| Mode | Flag | Use |
| --- | --- | --- |
| single-tenant | *(default)* | self-hosted inside a customer VNET |
| multi-tenant | `-multi-tenant` | our central SaaS deployment |

---

## Quick start

```bash
go build -o policy-controller ./cmd/policy-controller

./policy-controller \
  -listen :8080 \
  -metrics-listen :9091 \
  -db-dsn 'file:policy-controller.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)' \
  -bootstrap-admin-user admin \
  -bootstrap-admin-password 'change-me-please'
```

The bootstrap admin is created only when the `admin_users` table is empty, and it is
created as a `superadmin`. Prefer the environment variable over the flag so the
password does not land in the process table:

```bash
export POLICY_CONTROLLER_BOOTSTRAP_ADMIN_PASSWORD='change-me-please'
```

Every flag has an environment equivalent: `POLICY_CONTROLLER_` + the flag name in
screaming snake case (`-db-driver` → `POLICY_CONTROLLER_DB_DRIVER`). Flags win over
the environment.

---

## Architecture

```
cmd/policy-controller/     entrypoint: flags, logging, signals
internal/config/           flag + env configuration
internal/server/           module wiring, listeners, bootstrap, /healthz /readyz /
internal/httpx/            router, middleware chain, JSON envelope, ETag handling
internal/auth/             appliance tokens, admin sessions, tenant resolution
internal/policy/           GET /api/policies + admin policy CRUD + validation
internal/appliance/        appliance registration and token lifecycle
internal/identity/         admin login/logout, tenant administration
internal/store/            repository interfaces (the storage seam)
internal/store/sqlstore/   database/sql implementation for SQLite and Postgres
internal/metrics/          Prometheus collectors
pkg/dnsdcontract/          the dnsd wire contract — importable by dnsd itself
```

Endpoint families are `httpx.Module` implementations mounted in
`internal/server/server.go`. Adding `/api/vpn-peers` later means writing a new package
with `Name()` and `RegisterRoutes()` and adding one line to `buildRouter` — the router,
middleware, auth and metrics wiring do not change.

---

## The dnsd contract

`GET /api/policies` returns exactly what dnsd's `fetchAndUpdateIPBlocklist` decodes.
The Go types live in `pkg/dnsdcontract/contract.go` and mirror dnsd's own declarations
field for field:

```go
type Entry struct {
    IP      string   `json:"ip"`
    Domains []string `json:"domains"`
}

type Response struct {
    Blocklist []Entry `json:"blocklist"`
}
```

```json
{
  "blocklist": [
    {
      "ip": "192.168.1.100",
      "domains": ["facebook.com", "instagram.com"]
    },
    {
      "ip": "192.168.1.101",
      "domains": ["youtube.com"]
    }
  ]
}
```

Guarantees the service upholds:

- **No extra fields.** The appliance payload is frozen. Admin responses use a different,
  richer shape (`internal/policy.View`) so this one never has to grow.
- **Never `null`.** An empty policy set serialises to `{"blocklist":[]}`, and every
  `domains` array is non-nil.
- **Deterministic ordering.** Entries are sorted by IP and domains are sorted within an
  entry, so identical state always produces identical bytes — which is what makes the
  ETag stable.
- **Only actionable entries.** A policy with zero domains produces no BPF map entries on
  the appliance, so it is omitted from this payload. It stays visible via the admin API.

### Validation rules

Input is rejected at the admin API rather than shipped to appliances that would silently
drop it:

| Rule | Reason |
| --- | --- |
| IPv4 only | dnsd's `BlockDomainForIP` keys the BPF map on a `uint32` built from four octets and rejects anything else |
| No IPv4-mapped IPv6 (`::ffff:10.0.0.1`) | dnsd never sees that form; accepting it would let one host appear as two policies |
| Bare hostnames only — no scheme, port, path or whitespace | dnsd hashes `"." + strings.ToLower(domain)` verbatim |
| No wildcards (`*`) | the BPF map matches exact hashed names |
| ASCII only — submit punycode (`xn--`) | same hashing reason |
| ≤ 253 chars per domain, ≤ 63 per label, ≤ 4096 domains per policy | keeps one bad call from bloating every appliance's refresh |

Domains are lowercased, de-duplicated, stripped of a trailing dot and sorted on the way in.

---

## Caching (ETag / Last-Modified)

Every appliance in a tenant asks for the same bytes on the same interval, so
`GET /api/policies` is built to be revalidated rather than re-downloaded.

Response headers:

```
ETag: "9f2c1a0b7e5d4c3b8a6f0e1d2c3b4a59"
Last-Modified: Sat, 23 Aug 2026 09:14:02 GMT
Cache-Control: private, no-cache
Vary: Authorization
X-Policy-Revision: 47
```

- **ETag** is a SHA-256 over the serialised payload. Content-derived, not revision-derived:
  a `PUT` that rewrites a policy with the same domains bumps the revision but leaves the
  ETag unchanged, so appliances correctly get a 304.
- **Last-Modified** is the tenant's last policy write at second resolution. Omitted for a
  tenant that has never had a policy written.
- **X-Policy-Revision** is a monotonic per-tenant counter. Useful for spotting a fleet
  stuck on a stale snapshot.
- Precedence follows RFC 9110: when `If-None-Match` is present, `If-Modified-Since` is
  ignored.

Server-side, the rendered payload is cached per tenant and rebuilt only when the tenant's
revision moves, so controller load scales with change rate rather than with fleet size.
`policy_controller_policy_snapshot_builds_total` versus `policy_controller_policy_fetches_total`
shows whether that is working.

```bash
# First poll: 200 with a body
curl -si -H "Authorization: Bearer $APPLIANCE_TOKEN" \
  http://localhost:8080/api/policies | head -12

# Revalidate: 304, no body
curl -si -H "Authorization: Bearer $APPLIANCE_TOKEN" \
  -H 'If-None-Match: "9f2c1a0b7e5d4c3b8a6f0e1d2c3b4a59"' \
  http://localhost:8080/api/policies
```

> **dnsd-side note.** As of the current dnsd `main.go`, `fetchAndUpdateIPBlocklist` sends
> a plain `client.Get` with no `Authorization` header and no `If-None-Match`, and it treats
> any non-200 status — including 304 — as an error. So today the caching headers are served
> but not consumed, and appliance auth must stay off unless dnsd is patched. See
> [dnsd integration](#dnsd-integration) below.

---

## Authentication

Two independent credential planes. They are unforgeable as each other: distinct token
prefixes, distinct tables, and each middleware only ever consults its own plane. An
appliance token presented to an admin route fails before any hash comparison happens.

| Plane | Credential | Reaches | Lifetime |
| --- | --- | --- | --- |
| Appliance | `dnsdap_<id>_<secret>` | `GET /api/policies` (read-only) | until revoked |
| Admin | `dnsdsn_<id>_<secret>` | `/api/admin/*` | `-admin-session-ttl`, default 12h |

Both are sent as `Authorization: Bearer <token>`.

Token format is `<prefix>_<16 hex id>_<43 char base64url secret>`. The ID is the public
half used for lookup; only the SHA-256 of the secret is stored. A plain hash is correct
here rather than a slow KDF — the secret is 256 bits of CSPRNG output, so it is not
brute-forceable, and this comparison runs on every appliance poll. Admin *passwords* use
PBKDF2-HMAC-SHA256 at 210,000 iterations (`crypto/pbkdf2`, stdlib since Go 1.24) with a
per-user salt.

Tokens are shown exactly once, at mint time. A lost token is replaced by rotation, never
recovered.

> **Parsing a token.** The secret is base64url, and that alphabet contains `-` **and `_`**.
> Split on the *first two* underscores only — never on every underscore, or you will
> reject roughly half of all valid tokens at random. See `auth.Split`.

### Flow

Both planes enter through the same header and diverge immediately on prefix:

```
                        Authorization: Bearer <token>
                                     │
                        ┌────────────┴────────────┐
                        │   which route family?   │
                        └────────────┬────────────┘
              /api/policies          │          /api/admin/*
                        ▼                         ▼
                 RequireAppliance           RequireAdmin
                        │                         │
              prefix == "dnsdap_" ?      prefix == "dnsdsn_" ?
                        │                         │
              appliances.token_id        admin_sessions.token_id
                        │                         │
              SHA-256(secret) match ?    SHA-256(secret) match ?
                        │                         │
                revoked_at IS NULL ?        expires_at > now ?
                        │                         │
                        ▼                         ▼
                Principal{appliance,      Principal{admin,
                          tenant}                  tenant, role}
                        │                         │
                        └────────────┬────────────┘
                                     ▼
                              ResolveTenant
                        single-tenant → -default-tenant
                        multi-tenant  → principal's tenant
                                        (superadmin may override
                                         with X-Tenant-ID)
                                     ▼
                                  handler
```

A failure at any step returns `401` with a `WWW-Authenticate` header and a `reason` in the
message — `missing`, `invalid`, `revoked` or `expired`. The two planes never fall through
to each other: an appliance token on an admin route is rejected at the prefix check,
before any database lookup or hash comparison happens.

### Appliance tokens

An appliance token is the credential a **dnsd instance** presents when it polls for its
blocklist. It is not just an on/off gate — it carries four distinct jobs:

1. **It selects the tenant.** `AuthenticateAppliance` resolves the token to an appliance
   record and takes `tenant_id` from it, and that is what decides whose blocklist gets
   served. In multi-tenant mode the token is the *only* answer to "who is asking" — without
   it every poller looks identical and there is no way to pick a tenant. This is why
   `-require-appliance-auth=false` is viable for single-tenant self-hosted deployments but
   not for the SaaS mode.
2. **It is individually revocable.** Decommissioning a node or containing a leaked secret
   is one call against that appliance, with no effect on the rest of the fleet. A single
   shared secret would mean rotating every node at once.
3. **It bounds authority.** The token reaches `GET /api/policies` and nothing else. A
   secret pulled off an edge node cannot write policy, mint further tokens, or read the
   management API.
4. **It reports liveness.** Each successful poll updates `last_seen_at` (throttled to about
   one write per minute), so `GET /api/admin/appliances` shows which nodes are actually
   fetching. A node that silently stopped polling is visible here before anyone notices
   stale enforcement.

Minting and use:

```
operator                policy-controller              dnsd @ edge-ist-01
   │                            │                              │
   │ POST /api/admin/appliances │                              │
   │ Bearer dnsdsn_…            │                              │
   ├───────────────────────────►│                              │
   │                        Mint("dnsdap")                     │
   │                        store SHA-256(secret) only         │
   │◄───────────────────────────┤                              │
   │ 201 {token:"dnsdap_…"}     │                              │
   │      ── shown ONCE ──      │                              │
   │                            │                              │
   ├──── out of band: config management / secret store ───────►│
   │                            │                              │
   │                            │   GET /api/policies          │
   │                            │   Bearer dnsdap_…            │
   │                            │◄─────────────────────────────┤
   │                            │   200 + ETag   (304 on the   │
   │                            ├──────────────►  next poll)   │
   │                        touch last_seen_at                 │
```

Revocation takes effect on the appliance's very next poll:

```
   │ POST /api/admin/appliances/{id}/revoke                     │
   ├───────────────────────────►│                              │
   │                        revoked_at = now                   │
   │                            │   GET /api/policies          │
   │                            │◄─────────────────────────────┤
   │                            │   401 (reason=revoked)       │
   │                            ├─────────────────────────────►│
```

Note what revocation does *not* do: it does not reach into the appliance and clear its BPF
maps. dnsd keeps enforcing the last blocklist it successfully installed. Revoking stops
future updates; it does not roll back current enforcement.

Rotation (`POST /api/admin/appliances/{id}/rotate`) mints a replacement and clears
`revoked_at`, so it doubles as the way to bring a revoked appliance back into service.
There is no overlap window — the old token stops working the instant the new one is
issued, so push the new value to the node before rotating if a gap in policy refresh
matters.

### Admin login flow

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/admin/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-please"}' | jq -r .token)

curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/auth/whoami
```

```json
{
  "token": "dnsdsn_4f3a91c07b2e5d68_kQ8x2mFv...",
  "expires_at": "2026-08-23T21:14:02Z",
  "expires_in_seconds": 43200,
  "principal": {
    "kind": "admin",
    "id": "usr_1c9f0a3d5e7b2f4860d1a3c5e7b90f2d",
    "username": "admin",
    "tenant_id": "default",
    "role": "superadmin"
  }
}
```

An unknown username burns the same PBKDF2 work as a known one, so login timing does not
enumerate accounts.

### Appliance auth toggle

`-require-appliance-auth` defaults to `true`. Set it to `false` for a closed-network
rollout where dnsd instances predate token support. Note the asymmetry: a credential that
*is* presented is always verified, even when the flag is off. That lets you roll tokens out
appliance by appliance and only flip the flag on once the fleet is covered.

### Roles and tenant isolation

| Role | Scope |
| --- | --- |
| `admin` | its own tenant only |
| `superadmin` | any tenant; the only role that may manage tenants |

Tenant resolution:

- **Single-tenant mode** — always `-default-tenant`. `X-Tenant-ID` is ignored, and the
  `/api/admin/tenants/*` routes are not mounted at all, so a misdirected call gets a clean
  404 instead of a half-working operation.
- **Multi-tenant mode** — the principal's own tenant, unless a superadmin overrides it with
  `X-Tenant-ID: acme`. A non-superadmin naming a foreign tenant gets 403.

---

## API reference

Base URL is `-listen` (default `:8080`). Metrics live on a separate port.

### Appliance plane

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/api/policies` | appliance token |

### Policy management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/admin/policies` | list all policies in the tenant |
| `POST` | `/api/admin/policies` | create a policy (409 if the IP already has one) |
| `GET` | `/api/admin/policies/{ip}` | fetch one policy |
| `PUT` | `/api/admin/policies/{ip}` | upsert: replace the domain set wholesale |
| `PATCH` | `/api/admin/policies/{ip}` | incremental `add` / `remove` |
| `DELETE` | `/api/admin/policies/{ip}` | remove the policy (204) |

### Appliance management

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/admin/appliances` | list registrations |
| `POST` | `/api/admin/appliances` | register and mint a token (201, token shown once) |
| `GET` | `/api/admin/appliances/{id}` | fetch one registration |
| `POST` | `/api/admin/appliances/{id}/rotate` | mint a replacement token; also clears revocation |
| `POST` | `/api/admin/appliances/{id}/revoke` | withdraw the token, keep the record (idempotent) |
| `DELETE` | `/api/admin/appliances/{id}` | delete the record entirely (204) |

### Identity and tenants

| Method | Path | Auth |
| --- | --- | --- |
| `POST` | `/api/admin/auth/login` | none — this is what mints the session |
| `POST` | `/api/admin/auth/logout` | admin |
| `GET` | `/api/admin/auth/whoami` | admin |
| `GET` `POST` | `/api/admin/tenants` | superadmin, multi-tenant mode only |
| `GET` `DELETE` | `/api/admin/tenants/{id}` | superadmin, multi-tenant mode only |

### Operational

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/healthz` | liveness — process only, never touches the database |
| `GET` | `/readyz` | readiness — pings the database, 503 when unreachable |
| `GET` | `/` | self-describing route index for this build |
| `GET` | `/metrics` | Prometheus, on `-metrics-listen` |

`/healthz` deliberately does not check the database: a database blip should mark the pod
unready, not get it restarted.

---

## Sample requests

Assume `$TOKEN` is an admin session token from the login flow above.

### Create a policy

```bash
curl -s -X POST http://localhost:8080/api/admin/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "ip": "192.168.1.100",
        "domains": ["facebook.com", "instagram.com", "TikTok.com."]
      }'
```

```json
{
  "id": "pol_7b3e1f9a0c2d4e6f8a1b3c5d7e9f0a2b",
  "tenant_id": "default",
  "ip": "192.168.1.100",
  "domains": ["facebook.com", "instagram.com", "tiktok.com"],
  "created_at": "2026-08-23T09:14:02.481922Z",
  "updated_at": "2026-08-23T09:14:02.481922Z"
}
```

Note the normalisation: `TikTok.com.` was lowercased and had its trailing dot stripped, and
the list came back sorted.

### Replace the domain set

```bash
curl -s -X PUT http://localhost:8080/api/admin/policies/192.168.1.100 \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["facebook.com"]}'
```

`PUT` is an upsert, so it also creates the policy if the IP has none. If the body carries an
`ip` field it must agree with the path — otherwise a copy-pasted payload could silently
rewrite a different host.

### Add and remove incrementally

```bash
curl -s -X PATCH http://localhost:8080/api/admin/policies/192.168.1.100 \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"add": ["x.com"], "remove": ["facebook.com"]}'
```

Removals are applied before additions, so a domain in both lists ends up present.

### Register an appliance

```bash
curl -s -X POST http://localhost:8080/api/admin/appliances \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "edge-ist-01", "description": "Istanbul edge node"}'
```

```json
{
  "appliance": {
    "id": "app_2d4f6a8c0e1b3d5f7a9c1e3b5d7f9a0c",
    "tenant_id": "default",
    "name": "edge-ist-01",
    "description": "Istanbul edge node",
    "token_id": "5e8b1c4a09f3d726",
    "revoked": false,
    "created_at": "2026-08-23T09:16:44.102331Z"
  },
  "token": "dnsdap_5e8b1c4a09f3d726_TfN2xQ...",
  "hint": "Store this token now; it cannot be retrieved again. Pass it to dnsd with -ip-blocklist-token (or DNSD_IP_BLOCKLIST_TOKEN)."
}
```

`token` appears in exactly two responses — create and rotate — and nowhere else in the API.

### Rotate, revoke and audit an appliance

```bash
APP_ID=app_2d4f6a8c0e1b3d5f7a9c1e3b5d7f9a0c

# Who is actually polling, and when did they last succeed?
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/admin/appliances \
  | jq '.appliances[] | {name, token_id, revoked, last_seen_at}'

# Replace the token (also clears a previous revocation)
curl -s -X POST "http://localhost:8080/api/admin/appliances/$APP_ID/rotate" \
  -H "Authorization: Bearer $TOKEN" | jq -r .token

# Stop this node from receiving updates, keep its record and history
curl -s -X POST "http://localhost:8080/api/admin/appliances/$APP_ID/revoke" \
  -H "Authorization: Bearer $TOKEN" | jq '{name, revoked, revoked_at}'
```

Revoke is idempotent, and it keeps the row so `last_seen_at` and the registration history
survive. Use `DELETE` only when you want the record gone entirely.

### Fetch the blocklist as an appliance

```bash
curl -s -H "Authorization: Bearer dnsdap_5e8b1c4a09f3d726_TfN2xQ..." \
  http://localhost:8080/api/policies
```

### Multi-tenant: superadmin acting on another tenant

```bash
curl -s http://localhost:8080/api/admin/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H 'X-Tenant-ID: acme'
```

### Error shape

Every endpoint returns the same envelope:

```json
{
  "error": "bad_request",
  "message": "invalid ip",
  "details": {
    "ip": "\"2001:db8::1\" is not IPv4; dnsd's per-IP blocklist is IPv4-only"
  }
}
```

`error` codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
`unsupported`, `payload_too_large`, `internal_error`. `details` is present only for
validation failures.

Request bodies are decoded strictly: unknown fields are rejected, the body is capped at
1 MiB, and trailing content after the first JSON value is an error.

---

## Storage

The persistence contract is `internal/store.Store` — a set of narrow repository interfaces.
Handlers never touch `database/sql`. `internal/store/sqlstore` is the one implementation
serving both backends.

Queries are written once, in SQLite-flavoured SQL with `?` placeholders, and adapted per
backend by a small dialect layer that rewrites placeholders to `$1, $2, …` for Postgres.
Two portability decisions keep it to that:

- **Timestamps are `INTEGER`/`BIGINT` unix microseconds**, not native date types — no
  timezone or driver-parsing differences between the two.
- **Secrets are `BLOB`/`BYTEA`** and scan into `[]byte` identically on both.

Switching backends is a flag change, not a code change.

### SQLite (default)

Driver: [`modernc.org/sqlite`](https://modernc.org/sqlite) — a pure-Go translation, so
**no CGO and no libsqlite3 on the build or runtime host**. `CGO_ENABLED=0` static builds
work as-is, which matters for the self-hosted appliance-adjacent deployment.

```bash
-db-driver sqlite \
-db-dsn 'file:policy-controller.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)'
```

The three pragmas are load-bearing:

| Pragma | Why |
| --- | --- |
| `journal_mode(WAL)` | readers do not block the writer |
| `busy_timeout(5000)` | wait rather than fail on a contended write |
| `foreign_keys(1)` | SQLite defaults FKs **off**; without this, deleting a tenant leaves orphan policies |

The pool is pinned to a single connection (`SetMaxOpenConns(1)`). SQLite allows one writer
regardless, and the write volume here is human-scale, so serialising avoids `SQLITE_BUSY`
churn entirely.

### Postgres

Driver: [`github.com/jackc/pgx/v5`](https://github.com/jackc/pgx) via its `stdlib`
`database/sql` adapter, registered as `pgx`.

```bash
-db-driver postgres \
-db-dsn 'postgres://policy:secret@db.internal:5432/policycontroller?sslmode=require'
```

Pool: 16 connections, 30-minute max lifetime.

> **Status:** the Postgres dialect, DDL and driver wiring are complete and compile, but the
> path has not yet been exercised against a live Postgres server. SQLite is the tested
> backend today. Run the store tests against a real instance before relying on it in
> production.

### Schema

Applied idempotently at startup (`CREATE TABLE IF NOT EXISTS`); there is no migration
tool yet.

```
tenants(id, name, created_at, updated_at)
tenant_revisions(tenant_id, revision, updated_at)
policies(id, tenant_id, client_ip, created_at, updated_at)   UNIQUE(tenant_id, client_ip)
policy_domains(policy_id, domain)                            PK(policy_id, domain)
appliances(id, tenant_id, name, description, token_id, token_hash, created_at,
           last_seen_at, revoked_at)                         UNIQUE(tenant_id, name)
admin_users(id, tenant_id, username, role, password_hash, password_salt, created_at)
admin_sessions(token_id, token_hash, admin_user_id, created_at, expires_at)
```

`tenant_revisions` is bumped inside the same transaction as every policy write. It is what
lets `GET /api/policies` decide whether its cached snapshot is still valid with a single
cheap read instead of a full table scan per poll.

---

## Metrics

Prometheus on `-metrics-listen` (default `:9091/metrics`). dnsd already owns `:9090/metrics`
on the node, so the port differs but the pattern — package-level collectors, default
registry, `promhttp.Handler()` — is the same.

All collectors are namespaced `policy_controller_`.

| Metric | Type | Labels | Notes |
| --- | --- | --- | --- |
| `http_requests_total` | counter | `route`, `method`, `code` | `route` is the matched **pattern**, never the raw path, so per-IP admin routes cannot explode cardinality |
| `http_request_duration_seconds` | histogram | `route`, `method` | |
| `policy_fetches_total` | counter | `tenant`, `outcome` | `outcome` is `modified` or `not_modified` — the direct measure of the caching win |
| `policy_snapshot_builds_total` | counter | `tenant` | full payload rebuilds; should be far below `policy_fetches_total` |
| `policies_total` | gauge | `tenant` | per-IP policies served |
| `policy_domains_total` | gauge | `tenant` | individual (IP, domain) rules — compare against dnsd's `dnsd_ip_blocklist_rules_count` |
| `policy_revision` | gauge | `tenant` | current revision; alert on a fleet stuck behind it |
| `auth_failures_total` | counter | `plane`, `reason` | `plane` = `appliance`\|`admin`; `reason` = `missing`\|`invalid`\|`revoked`\|`expired`\|`login` |
| `appliances_total` | gauge | `tenant`, `state` | `state` = `active`\|`revoked` |
| `tenants_total` | gauge | — | |
| `build_info` | gauge | `version`, `mode`, `db_driver` | always 1 |

The gauges are refreshed on write and at startup, not on a timer.

### Useful queries

```promql
# Cache effectiveness — should trend toward 1.0 with a healthy fleet
sum(rate(policy_controller_policy_fetches_total{outcome="not_modified"}[5m]))
  / sum(rate(policy_controller_policy_fetches_total[5m]))

# Control plane vs data plane drift: are appliances installing what we serve?
sum(policy_controller_policy_domains_total) - sum(dnsd_ip_blocklist_rules_count)

# Appliances failing auth — usually a revoked or un-rotated token
sum by (reason) (rate(policy_controller_auth_failures_total{plane="appliance"}[5m]))

# Latency
histogram_quantile(0.99,
  sum by (le, route) (rate(policy_controller_http_request_duration_seconds_bucket[5m])))
```

---

## Debugging

### Logs

Structured `log/slog`. One line per request with method, matched route, status, byte
count, duration and correlation ID.

```bash
./policy-controller -log-level debug -log-format json | jq .
```

Every request gets an `X-Request-ID`, honouring an inbound one if present and echoing it
on the response. Grep a single request end to end:

```bash
curl -s -H 'X-Request-ID: debug-me-1' -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/admin/policies
jq 'select(.request_id == "debug-me-1")' < policy-controller.log
```

### What is actually mounted

`GET /` returns this build's route table, including which modules registered. The fastest
way to confirm whether a deployment is in multi-tenant mode — the `/api/admin/tenants`
routes are absent in single-tenant builds:

```bash
curl -s http://localhost:8080/ | jq '.mode, (.routes[] | "\(.method) \(.pattern) [\(.module)]")'
```

### Is the appliance seeing fresh policy?

Three independent signals, cheapest first:

```bash
# 1. What revision are we serving?
curl -sI -H "Authorization: Bearer $APPLIANCE_TOKEN" \
  http://localhost:8080/api/policies | grep -i 'x-policy-revision\|etag\|last-modified'

# 2. When did this appliance last poll?
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/admin/appliances | jq '.appliances[] | {name, last_seen_at, revoked}'

# 3. Does the payload match what dnsd installed?
curl -s -H "Authorization: Bearer $APPLIANCE_TOKEN" \
  http://localhost:8080/api/policies | jq '[.blocklist[].domains | length] | add'
# compare against dnsd_ip_blocklist_rules_count on the appliance's :9090/metrics
```

`last_seen_at` is throttled to roughly one write per minute, so it is a liveness signal,
not a precise poll log.

### Verifying the contract by hand

The payload must survive dnsd's decoder unchanged. A quick structural check:

```bash
curl -s -H "Authorization: Bearer $APPLIANCE_TOKEN" http://localhost:8080/api/policies \
  | jq -e 'has("blocklist")
           and (.blocklist | type == "array")
           and (.blocklist | all(has("ip") and has("domains")
                                 and (.domains | type == "array")
                                 and (.ip | test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))))' \
  && echo "contract OK"
```

### Inspecting the database

```bash
sqlite3 policy-controller.db '.tables'
sqlite3 policy-controller.db 'SELECT client_ip, COUNT(*) FROM policies p
                              JOIN policy_domains d ON d.policy_id = p.id
                              GROUP BY client_ip;'
sqlite3 policy-controller.db 'SELECT tenant_id, revision, datetime(updated_at/1000000, "unixepoch")
                              FROM tenant_revisions;'
```

Timestamps are unix **microseconds**, hence the `/1000000` above.

Token hashes are SHA-256 and not reversible; to check whether a token is known, look up its
public ID (the middle segment) instead:

```bash
# token dnsdap_5e8b1c4a09f3d726_TfN2xQ... -> id 5e8b1c4a09f3d726
sqlite3 policy-controller.db "SELECT name, revoked_at FROM appliances WHERE token_id='5e8b1c4a09f3d726';"
```

### Common failures

| Symptom | Likely cause |
| --- | --- |
| dnsd logs `unexpected status code: 401` | appliance token missing or revoked, or `-require-appliance-auth` is on before the fleet has tokens |
| `401 reason=invalid` with a token that looks correct | a client splitting the token on *every* `_`; the base64url secret contains underscores about half the time |
| `401 reason=missing` | no `Authorization` header reached the server — usually an empty shell variable expanding to `Bearer ` |
| dnsd logs `unexpected status code: 304` | dnsd sent `If-None-Match` but treats non-200 as an error — it needs the patch below |
| Admin call returns 401 with `WWW-Authenticate` | session expired (`-admin-session-ttl`); log in again |
| Admin call returns 403 on `X-Tenant-ID` | non-superadmin crossing tenants |
| `409 conflict` on `POST /api/admin/policies` | IP already has a policy; use `PUT` or `PATCH` |
| `400` naming an IPv6 address | expected — dnsd's per-IP map is IPv4-only |
| Deleting a tenant leaves rows behind | `foreign_keys(1)` missing from the SQLite DSN |
| Policy changes never reach appliances | check `policy_revision` moved, then `last_seen_at`, then the appliance's own logs |

---

## dnsd integration

Point dnsd at this service:

```bash
dnsd -iface eth0 \
     -ip-blocklist-url http://policy-controller.internal:8080/api/policies \
     -ip-blocklist-interval 5m
```

Two features on this side are served but **not yet consumed** by dnsd, because
`fetchAndUpdateIPBlocklist` in dnsd's `main.go` currently issues a bare `client.Get` and
treats any non-200 status as an error:

1. **Appliance auth** — no `Authorization` header is sent, so `-require-appliance-auth`
   must stay `false` until dnsd learns an `-ip-blocklist-token` flag.
2. **Conditional requests** — no `If-None-Match` is sent, so every poll transfers the full
   body. Worse, if it *did* send one, the resulting 304 would be logged as an error and the
   refresh treated as failed.

A dnsd-side patch adding the token flag, an ETag cache and 304-as-no-op is the remaining
piece of this integration. Until it lands, run with `-require-appliance-auth=false` on a
trusted network.

---

## Configuration reference

| Flag | Default | Description |
| --- | --- | --- |
| `-listen` | `:8080` | policy + admin API address |
| `-metrics-listen` | `:9091` | Prometheus address; must differ from `-listen` |
| `-db-driver` | `sqlite` | `sqlite` or `postgres` |
| `-db-dsn` | `file:policy-controller.db?...` | driver-specific DSN |
| `-multi-tenant` | `false` | enable tenant isolation |
| `-default-tenant` | `default` | tenant used in single-tenant mode |
| `-require-appliance-auth` | `true` | require a Bearer token on `GET /api/policies` |
| `-bootstrap-admin-user` | — | admin created on an empty database |
| `-bootstrap-admin-password` | — | must be ≥ 12 characters; set both or neither |
| `-admin-session-ttl` | `12h` | admin session lifetime |
| `-read-timeout` | `10s` | |
| `-write-timeout` | `30s` | |
| `-idle-timeout` | `1m` | |
| `-shutdown-timeout` | `10s` | graceful shutdown grace period |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `-log-format` | `text` | `text` or `json` |
| `-version` | | print version and exit |
