# Admin dashboard (`/ui/`)

A plain HTML/CSS/JS console for the policy-controller API. No framework, no
build step, no CORS: the assets are embedded in the binary with `go:embed` and
served by the API listener itself, so the dashboard and the API share one
origin and one port.

| | |
|---|---|
| Source | `internal/ui/static/{index.html,app.css,app.js}` |
| Mount point | `GET /ui/` (same listener as `-listen`) |
| Toggle | `-ui` (default `true`) / `POLICY_CONTROLLER_UI` |
| Module | `internal/ui/module.go`, mounted in `internal/server/server.go` |

---

## 1. Build

```bash
cd /Users/emirozbir/go/src/dashdns/api
go build -o policy-controller ./cmd/policy-controller
```

`go:embed` reads `internal/ui/static/` **at compile time**, so the single
binary already contains the dashboard — nothing to copy at deploy time, and
`CGO_ENABLED=0` static builds still work.

## 2. Run

On an empty database, create the first admin at the same time; without it
`/api/admin/*` has no account to log in with. The password must be at least
12 characters.

```bash
./policy-controller \
  -listen :8080 \
  -metrics-listen :9091 \
  -bootstrap-admin-user admin \
  -bootstrap-admin-password 'change-me-please'
```

Multi-tenant mode (adds the Tenants tab and the `X-Tenant-ID` switcher in the
header, both superadmin-only):

```bash
./policy-controller -multi-tenant \
  -bootstrap-admin-user admin -bootstrap-admin-password 'change-me-please'
```

To run without the console — a pure JSON surface:

```bash
./policy-controller -ui=false      # /ui/ then returns the normal 404 body
```

## 3. Open it

```
http://localhost:8080/ui/
```

`http://localhost:8080/ui` redirects to the trailing-slash form. Log in with
the bootstrap credentials; the session token is kept in `sessionStorage` and
dropped on any `401`, which returns you to the login screen.

Note that `:9091` is the Prometheus listener only — the dashboard is not there.

## 4. What each screen calls

Every panel carries the endpoint it drives in small monospace text, and the
**request log** strip at the bottom of the window shows `method · path ·
status · X-Request-ID` for each call the page makes.

| Screen | Endpoints |
|---|---|
| Login / header / logout | `POST /api/admin/auth/login`, `GET /api/admin/auth/whoami`, `POST /api/admin/auth/logout` |
| **Policies** — table, filter, revision badge | `GET /api/admin/policies` |
| New policy form | `POST /api/admin/policies` |
| Edit panel — facts | `GET /api/admin/policies/{ip}` |
| Edit panel — *Replace all domains* | `PUT /api/admin/policies/{ip}` |
| Edit panel — *Incremental change* | `PATCH /api/admin/policies/{ip}` |
| Edit panel / row — *Delete* | `DELETE /api/admin/policies/{ip}` |
| **Appliances** — table | `GET /api/admin/appliances` |
| Register appliance | `POST /api/admin/appliances` |
| Row — Details / Rotate / Revoke / Delete | `GET`, `POST .../rotate`, `POST .../revoke`, `DELETE /api/admin/appliances/{id}` |
| **Tenants** (multi-tenant + superadmin) | `GET`/`POST /api/admin/tenants`, `GET`/`DELETE /api/admin/tenants/{id}` |
| **System** — Health card and route table | `GET /`, `GET /healthz`, `GET /readyz` |
| **System** — Session card | `GET /api/admin/auth/whoami` |
| **System** — Appliance plane probe | `GET` / `HEAD /api/policies` |

The probe is the one panel that does **not** use your session: paste an
appliance token (`dnsdap_…`) and it calls the appliance plane as dnsd would,
showing `ETag`, `Last-Modified` and `X-Policy-Revision`. The returned ETag is
fed back into the `If-None-Match` box, so clicking `GET` twice demonstrates the
`304` path. Leaving the token empty probes anonymously, which only succeeds on
a deployment running `-require-appliance-auth=false`.

## 5. Behaviour worth knowing

- **One-time tokens.** Create and Rotate return the appliance token exactly
  once. The dashboard shows it in a modal and never stores it; closing the
  modal clears the field. A lost token can only be rotated, not recovered.
- **Server-side normalisation.** Domains come back lowercased, de-duplicated
  and sorted, so the edit panel always refills from the response rather than
  from what you typed.
- **Strict decoder.** The API rejects unknown fields with `400`, so the request
  bodies are kept minimal (for example `description` is omitted when blank).
- **Tenant switching.** The `X-Tenant-ID` selector appears only for a
  `superadmin` in multi-tenant mode; sending that header as a plain `admin` is
  a `403`, so the UI never offers it.
- **IPv4 only.** The IP field is checked against the dotted-quad rule before
  the request goes out, mirroring the server rule; the server stays the
  authority on everything else.

## 6. Changing the UI

The static files are plain text — edit them and rebuild:

```bash
vim internal/ui/static/app.js
go build -o policy-controller ./cmd/policy-controller && ./policy-controller ...
```

Because the assets are embedded, a running binary will not pick up edits. The
responses carry `Cache-Control: no-cache`, so a normal browser reload is enough
after a restart; no hard refresh needed.

If you would rather serve the files from nginx or a CDN instead, they have no
dependency on the Go side beyond the same-origin assumption: copy
`internal/ui/static/` anywhere that proxies `/api`, `/healthz` and `/readyz` to
the controller. Serving them from a *different* origin would additionally
require CORS, which the controller deliberately does not implement.

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| `/ui/` returns `{"error":"not_found"}` | started with `-ui=false` (or `POLICY_CONTROLLER_UI=false`) |
| Login says `invalid username or password` on a fresh DB | no admin exists; restart with `-bootstrap-admin-user` / `-bootstrap-admin-password`. The flags are ignored once any admin exists. |
| Tenants tab missing | single-tenant mode, or the account is `admin` rather than `superadmin` |
| Kicked back to the login screen | session expired (`-admin-session-ttl`, default 12h) or the token was revoked |
| Probe returns `401 unauthorized` | the appliance token is missing, revoked or belongs to another deployment |
