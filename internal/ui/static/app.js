/* policy-controller dashboard.
 *
 * One file, no framework, no build step. Every panel maps onto one endpoint of
 * the contract in CONTRACT.md; the request log at the bottom shows exactly
 * which call each click made.
 *
 * Served from the API origin, so every fetch below is same-origin and relative.
 */
'use strict';

const $ = (id) => document.getElementById(id);
const SESSION_KEY = 'policy-controller.session';

const state = {
  token: null,
  expiresAt: null,
  principal: null,      // {kind,id,username,tenant_id,role}
  mode: 'single-tenant',
  version: '',
  routes: [],
  tenant: '',           // X-Tenant-ID override, superadmin only
  policies: [],
  revision: null,
  appliances: [],
  tenants: [],
  selectedIP: null,
};

const isSuperadmin = () => state.principal && state.principal.role === 'superadmin';
const isMultiTenant = () => state.mode === 'multi-tenant';

/* ── helpers ──────────────────────────────────────────────────────────── */

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function fmtTime(v) {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d) ? String(v) : d.toLocaleString();
}

function fmtDuration(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${s % 60}s`;
}

// The API sorts and de-duplicates domains itself; this only turns a textarea
// into a list, splitting on newlines, commas and spaces.
function parseDomains(text) {
  return text.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
}

// Mirrors the server rule: IPv4 dotted-quad only. Catching it here saves a
// round trip, but the server stays the authority.
function looksLikeIPv4(ip) {
  const parts = ip.split('.');
  return parts.length === 4 && parts.every((p) =>
    /^\d{1,3}$/.test(p) && Number(p) <= 255 && (p === '0' || !p.startsWith('0')));
}

let toastTimer = null;
function toast(message, kind) {
  const el = $('toast');
  el.textContent = message;
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, kind === 'bad' ? 8000 : 4000);
}

function logRequest(method, path, status, requestID) {
  const li = document.createElement('li');
  const cls = 's' + Math.floor(status / 100) + 'xx';
  const time = new Date().toLocaleTimeString();
  li.innerHTML = `${esc(time)}  <span class="${cls}">${esc(status)}</span>  ` +
    `${esc(method.padEnd(6))} ${esc(path)}  <span class="muted">${esc(requestID || '')}</span>`;
  const list = $('log-lines');
  list.prepend(li);
  while (list.children.length > 200) list.lastChild.remove();
}

/* ── API client ───────────────────────────────────────────────────────── */

class ApiError extends Error {
  constructor(status, body) {
    super((body && body.message) || `HTTP ${status}`);
    this.status = status;
    this.code = (body && body.error) || '';
    this.details = (body && body.details) || null;
  }
  // Field errors are the useful half of a 400; fold them into one line.
  get full() {
    if (!this.details) return this.message;
    const fields = Object.entries(this.details).map(([k, v]) => `${k}: ${v}`).join('; ');
    return `${this.message} (${fields})`;
  }
}

async function api(method, path, options = {}) {
  const { body, authenticate = true, token, tenantHeader = true, ifNoneMatch } = options;
  const headers = { 'Accept': 'application/json' };

  const bearer = token !== undefined ? token : (authenticate ? state.token : null);
  if (bearer) headers['Authorization'] = 'Bearer ' + bearer;
  // Only a superadmin may act on another tenant; sending the header as a
  // plain admin is a 403, so the UI never offers it.
  if (tenantHeader && state.tenant && isSuperadmin()) headers['X-Tenant-ID'] = state.tenant;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (ifNoneMatch) headers['If-None-Match'] = ifNoneMatch;

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store',
  });
  logRequest(method, path, res.status, res.headers.get('X-Request-ID'));

  let payload = null;
  if (res.status !== 204 && res.status !== 304 && method !== 'HEAD') {
    const text = await res.text();
    if (text) { try { payload = JSON.parse(text); } catch { payload = { raw: text }; } }
  }

  if (!res.ok && res.status !== 304) {
    const err = new ApiError(res.status, payload);
    // A dead session anywhere means the whole dashboard is dead; drop it and
    // go back to the login screen rather than failing panel by panel.
    if (res.status === 401 && authenticate && token === undefined) endSession(err.message);
    throw err;
  }
  return { status: res.status, headers: res.headers, body: payload };
}

const apiGet = (p, o) => api('GET', p, o).then((r) => r.body);

/* ── session ──────────────────────────────────────────────────────────── */

function saveSession() {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({
    token: state.token, expiresAt: state.expiresAt, principal: state.principal,
  }));
}

function loadSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return false;
    const s = JSON.parse(raw);
    if (!s.token) return false;
    if (s.expiresAt && new Date(s.expiresAt) <= new Date()) return false;
    state.token = s.token;
    state.expiresAt = s.expiresAt;
    state.principal = s.principal;
    return true;
  } catch { return false; }
}

function endSession(message) {
  state.token = null;
  state.expiresAt = null;
  state.principal = null;
  state.tenant = '';
  sessionStorage.removeItem(SESSION_KEY);
  $('app').hidden = true;
  $('login-screen').hidden = false;
  if (message) {
    $('login-error').textContent = message;
    $('login-error').hidden = false;
  }
}

async function doLogin(username, password) {
  const res = await api('POST', '/api/admin/auth/login', {
    body: { username, password }, authenticate: false, tenantHeader: false,
  });
  state.token = res.body.token;
  state.expiresAt = res.body.expires_at;
  state.principal = res.body.principal;
  saveSession();
}

async function doLogout() {
  try { await api('POST', '/api/admin/auth/logout'); } catch { /* logout is idempotent */ }
  endSession('');
  $('login-error').hidden = true;
}

/* ── boot ─────────────────────────────────────────────────────────────── */

async function loadIndex() {
  const idx = await apiGet('/', { authenticate: false, tenantHeader: false });
  state.mode = idx.mode || 'single-tenant';
  state.version = idx.version || '';
  state.routes = idx.routes || [];
  return idx;
}

async function enterApp() {
  // whoami both validates the stored token and refreshes the role, which may
  // have changed since the token was minted.
  state.principal = await apiGet('/api/admin/auth/whoami');
  saveSession();

  $('login-screen').hidden = true;
  $('app').hidden = false;

  $('hdr-version').textContent = state.version ? 'v' + state.version : '—';
  $('hdr-mode').textContent = state.mode;
  $('hdr-user').textContent = `${state.principal.username} · ${state.principal.role} · ${state.principal.tenant_id}`;

  const tenantsVisible = isMultiTenant() && isSuperadmin();
  document.querySelector('#tabs button[data-view="tenants"]').hidden = !tenantsVisible;
  $('hdr-tenant-wrap').hidden = !tenantsVisible;
  if (tenantsVisible) await refreshTenants();

  showView('policies');
  await refreshPolicies();
}

/* ── navigation ───────────────────────────────────────────────────────── */

const VIEWS = ['policies', 'appliances', 'tenants', 'system'];
const loaders = {
  policies: refreshPolicies,
  appliances: refreshAppliances,
  tenants: refreshTenants,
  system: refreshSystem,
};

function showView(name) {
  for (const v of VIEWS) $('view-' + v).hidden = v !== name;
  for (const b of document.querySelectorAll('#tabs button')) {
    b.classList.toggle('active', b.dataset.view === name);
  }
}

async function guard(fn) {
  try { await fn(); } catch (err) {
    if (err instanceof ApiError) {
      if (err.status !== 401) toast(`${err.status} ${err.code}: ${err.full}`, 'bad');
    } else {
      toast(String(err && err.message ? err.message : err), 'bad');
    }
  }
}

/* ── policies ─────────────────────────────────────────────────────────── */

async function refreshPolicies() {
  const data = await apiGet('/api/admin/policies');
  state.policies = data.policies || [];
  state.revision = data.revision;
  $('pol-count').textContent = `${data.count ?? state.policies.length} records`;
  $('pol-revision').textContent = `rev ${data.revision ?? '—'}`;
  renderPolicies();
}

function renderPolicies() {
  const needle = $('pol-filter').value.trim().toLowerCase();
  const rows = state.policies.filter((p) => !needle ||
    p.ip.includes(needle) || (p.domains || []).some((d) => d.includes(needle)));

  $('pol-rows').innerHTML = rows.map((p) => {
    const domains = p.domains || [];
    const shown = domains.slice(0, 6).map(esc).join(', ');
    const more = domains.length > 6 ? ` <span class="muted">+${domains.length - 6} more</span>` : '';
    return `<tr data-ip="${esc(p.ip)}" class="${p.ip === state.selectedIP ? 'selected' : ''}">
      <td class="mono">${esc(p.ip)}</td>
      <td class="domains">${shown || '<span class="muted">(empty)</span>'}${more}</td>
      <td class="mono">${domains.length}</td>
      <td class="mono">${esc(fmtTime(p.updated_at))}</td>
      <td class="actions">
        <button data-act="edit">Edit</button>
        <button data-act="delete" class="danger">Delete</button>
      </td></tr>`;
  }).join('');

  $('pol-empty').hidden = rows.length > 0;
  $('pol-empty').textContent = state.policies.length
    ? 'No policy matches the filter.' : 'No policies yet.';
}

async function openPolicy(ip) {
  const p = await apiGet('/api/admin/policies/' + encodeURIComponent(ip));
  state.selectedIP = p.ip;
  $('pol-detail-empty').hidden = true;
  $('pol-detail-body').hidden = false;
  $('pol-detail-reload').hidden = false;
  $('pol-detail-close').hidden = false;
  $('pol-detail-ip').textContent = p.ip;
  $('pol-detail-id').textContent = p.id;
  $('pol-detail-tenant').textContent = p.tenant_id;
  $('pol-detail-created').textContent = fmtTime(p.created_at);
  $('pol-detail-updated').textContent = fmtTime(p.updated_at);
  // Always refill from the response: the server normalises what we sent.
  $('pol-put-domains').value = (p.domains || []).join('\n');
  $('pol-patch-add').value = '';
  $('pol-patch-remove').value = '';
  renderPolicies();
}

function closePolicy() {
  state.selectedIP = null;
  $('pol-detail-body').hidden = true;
  $('pol-detail-reload').hidden = true;
  $('pol-detail-close').hidden = true;
  $('pol-detail-empty').hidden = false;
  $('pol-detail-ip').textContent = '—';
  renderPolicies();
}

/* ── appliances ───────────────────────────────────────────────────────── */

async function refreshAppliances() {
  const data = await apiGet('/api/admin/appliances');
  state.appliances = data.appliances || [];
  $('app-count').textContent = `${data.count ?? state.appliances.length} records`;
  $('app-rows').innerHTML = state.appliances.map((a) => `
    <tr data-id="${esc(a.id)}">
      <td>${esc(a.name)}${a.description ? `<div class="muted small">${esc(a.description)}</div>` : ''}
          <div class="muted small mono">${esc(a.id)}</div></td>
      <td><span class="badge ${a.revoked ? 'bad' : 'good'}">${a.revoked ? 'revoked' : 'active'}</span></td>
      <td class="mono">${esc(a.token_id)}</td>
      <td class="mono">${esc(fmtTime(a.created_at))}</td>
      <td class="mono">${esc(a.last_seen_at ? fmtTime(a.last_seen_at) : 'never')}</td>
      <td class="actions">
        <button data-act="show">Details</button>
        <button data-act="rotate">Rotate</button>
        <button data-act="revoke" ${a.revoked ? 'disabled' : ''}>Revoke</button>
        <button data-act="delete" class="danger">Delete</button>
      </td></tr>`).join('');
  $('app-empty').hidden = state.appliances.length > 0;
}

function showAppliance(view) {
  $('app-detail-empty').hidden = true;
  $('app-detail-json').hidden = false;
  $('app-detail-hint').hidden = false;
  $('app-detail-close').hidden = false;
  $('app-detail-json').textContent = JSON.stringify(view, null, 2);
}

// The token exists in exactly one response and is never stored anywhere by the
// dashboard -- it lives in the dialog and dies with it.
function showTokenModal(token, hint) {
  $('token-value').value = token;
  $('token-hint').textContent = hint || 'Store this token now; it cannot be retrieved again.';
  $('token-modal').showModal();
}

/* ── tenants ──────────────────────────────────────────────────────────── */

async function refreshTenants() {
  if (!(isMultiTenant() && isSuperadmin())) return;
  const data = await apiGet('/api/admin/tenants', { tenantHeader: false });
  state.tenants = data.tenants || [];
  $('ten-count').textContent = `${data.count ?? state.tenants.length} records`;
  $('ten-rows').innerHTML = state.tenants.map((t) => `
    <tr data-id="${esc(t.id)}">
      <td class="mono">${esc(t.id)}</td>
      <td>${esc(t.name)}</td>
      <td class="mono">${esc(fmtTime(t.created_at))}</td>
      <td class="mono">${esc(fmtTime(t.updated_at))}</td>
      <td class="actions">
        <button data-act="show">Details</button>
        <button data-act="delete" class="danger">Delete</button>
      </td></tr>`).join('');
  $('ten-empty').hidden = state.tenants.length > 0;
  renderTenantSwitch();
}

function renderTenantSwitch() {
  const sel = $('hdr-tenant');
  const home = state.principal ? state.principal.tenant_id : '';
  const ids = state.tenants.map((t) => t.id);
  if (home && !ids.includes(home)) ids.unshift(home);
  sel.innerHTML = ids.map((id) =>
    `<option value="${esc(id)}" ${id === (state.tenant || home) ? 'selected' : ''}>${esc(id)}</option>`
  ).join('');
}

/* ── system ───────────────────────────────────────────────────────────── */

async function refreshSystem() {
  const idx = await loadIndex();
  $('sys-service').textContent = idx.service || '—';
  $('sys-version').textContent = idx.version || '—';
  $('sys-mode').textContent = idx.mode || '—';
  $('sys-routes').innerHTML = (idx.routes || []).map((r) => `
    <tr><td class="mono">${esc(r.method)}</td><td class="mono">${esc(r.pattern)}</td>
        <td class="mono muted">${esc(r.module)}</td></tr>`).join('');

  const health = await apiGet('/healthz', { authenticate: false, tenantHeader: false });
  $('sys-health').innerHTML = `<span class="badge good">${esc(health.status)}</span>`;
  $('sys-uptime').textContent = fmtDuration(health.uptime_seconds);

  // readyz answers 503 when the database is unreachable, which is a status to
  // display rather than an error to throw.
  const ready = await api('GET', '/readyz', { authenticate: false, tenantHeader: false })
    .catch((err) => (err instanceof ApiError ? { body: { status: 'unavailable' } } : Promise.reject(err)));
  const ok = ready.body && ready.body.status === 'ready';
  $('sys-ready').innerHTML = `<span class="badge ${ok ? 'good' : 'bad'}">` +
    `${esc(ready.body ? (ready.body.status + (ready.body.reason ? ' — ' + ready.body.reason : '')) : '?')}</span>`;

  renderWhoami();
}

function renderWhoami() {
  const p = state.principal || {};
  $('who-kind').textContent = p.kind || '—';
  $('who-id').textContent = p.id || '—';
  $('who-username').textContent = p.username || '—';
  $('who-tenant').textContent = p.tenant_id || '—';
  $('who-role').textContent = p.role || '—';
  $('who-expires').textContent = fmtTime(state.expiresAt);
}

async function probePolicies(method) {
  const token = $('probe-token').value.trim();
  const etag = $('probe-etag').value.trim();
  const res = await api(method, '/api/policies', {
    token: token || null,          // null => no Authorization header at all
    tenantHeader: false,
    ifNoneMatch: etag || undefined,
  }).catch((err) => {
    if (err instanceof ApiError) {
      $('probe-status').innerHTML = `<span class="badge bad">${err.status} ${esc(err.code)}</span> ${esc(err.message)}`;
      $('probe-body').hidden = true;
      return null;
    }
    throw err;
  });
  if (!res) return;

  const cls = res.status === 200 ? 'good' : '';
  $('probe-status').innerHTML = `<span class="badge ${cls}">${res.status}</span>`;
  const newEtag = res.headers.get('ETag');
  $('probe-resp-etag').textContent = newEtag || '—';
  $('probe-rev').textContent = res.headers.get('X-Policy-Revision') || '—';
  $('probe-modified').textContent = res.headers.get('Last-Modified') || '—';
  // Feed the ETag back so the next click demonstrates the 304 path.
  if (newEtag) $('probe-etag').value = newEtag;

  if (res.body) {
    $('probe-body').hidden = false;
    $('probe-body').textContent = JSON.stringify(res.body, null, 2);
  } else {
    $('probe-body').hidden = true;
  }
}

/* ── wiring ───────────────────────────────────────────────────────────── */

function wire() {
  // login
  $('login-form').addEventListener('submit', (e) => {
    e.preventDefault();
    $('login-error').hidden = true;
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    doLogin($('login-username').value, $('login-password').value)
      .then(() => { $('login-password').value = ''; return enterApp(); })
      .catch((err) => {
        const msg = err instanceof ApiError ? err.full : String(err.message || err);
        $('login-error').textContent = msg;
        $('login-error').hidden = false;
      })
      .finally(() => { btn.disabled = false; });
  });

  $('btn-logout').addEventListener('click', () => guard(doLogout));

  // tabs
  $('tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-view]');
    if (!btn) return;
    showView(btn.dataset.view);
    guard(loaders[btn.dataset.view]);
  });

  // tenant switch
  $('hdr-tenant').addEventListener('change', (e) => {
    state.tenant = e.target.value;
    toast(`Acting on tenant "${state.tenant}"`, 'good');
    closePolicy();
    guard(async () => { await refreshPolicies(); await refreshAppliances(); });
  });

  // policies
  $('pol-refresh').addEventListener('click', () => guard(refreshPolicies));
  $('pol-filter').addEventListener('input', renderPolicies);

  $('pol-rows').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    const row = e.target.closest('tr[data-ip]');
    if (!row) return;
    const ip = row.dataset.ip;
    if (!btn || btn.dataset.act === 'edit') { guard(() => openPolicy(ip)); return; }
    if (btn.dataset.act === 'delete') {
      if (!confirm(`Delete the policy for ${ip}?`)) return;
      guard(async () => {
        await api('DELETE', '/api/admin/policies/' + encodeURIComponent(ip));
        if (state.selectedIP === ip) closePolicy();
        toast(`Policy ${ip} deleted.`, 'good');
        await refreshPolicies();
      });
    }
  });

  $('pol-create-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const ip = $('pol-new-ip').value.trim();
    const domains = parseDomains($('pol-new-domains').value);
    if (!looksLikeIPv4(ip)) { toast(`"${ip}" is not an IPv4 dotted-quad address.`, 'bad'); return; }
    if (!domains.length) { toast('A new policy must list at least one domain.', 'bad'); return; }
    guard(async () => {
      const res = await api('POST', '/api/admin/policies', { body: { ip, domains } });
      $('pol-new-ip').value = '';
      $('pol-new-domains').value = '';
      toast(`Policy ${res.body.ip} created with ${res.body.domains.length} domain(s).`, 'good');
      await refreshPolicies();
      await openPolicy(res.body.ip);
    });
  });

  $('pol-detail-reload').addEventListener('click', () => guard(() => openPolicy(state.selectedIP)));
  $('pol-detail-close').addEventListener('click', closePolicy);

  $('pol-put-btn').addEventListener('click', () => {
    const ip = state.selectedIP;
    const domains = parseDomains($('pol-put-domains').value);
    if (!domains.length && !confirm(`Empty the domain list of ${ip}? The policy itself stays.`)) return;
    guard(async () => {
      await api('PUT', '/api/admin/policies/' + encodeURIComponent(ip), { body: { ip, domains } });
      toast(`Policy ${ip} replaced.`, 'good');
      await refreshPolicies();
      await openPolicy(ip);
    });
  });

  $('pol-patch-btn').addEventListener('click', () => {
    const ip = state.selectedIP;
    const add = parseDomains($('pol-patch-add').value);
    const remove = parseDomains($('pol-patch-remove').value);
    if (!add.length && !remove.length) { toast('At least one of add or remove must be non-empty.', 'bad'); return; }
    guard(async () => {
      await api('PATCH', '/api/admin/policies/' + encodeURIComponent(ip), { body: { add, remove } });
      toast(`Policy ${ip} updated (+${add.length} / -${remove.length}).`, 'good');
      await refreshPolicies();
      await openPolicy(ip);
    });
  });

  $('pol-delete-btn').addEventListener('click', () => {
    const ip = state.selectedIP;
    if (!confirm(`Delete the policy for ${ip}?`)) return;
    guard(async () => {
      await api('DELETE', '/api/admin/policies/' + encodeURIComponent(ip));
      closePolicy();
      toast(`Policy ${ip} deleted.`, 'good');
      await refreshPolicies();
    });
  });

  // appliances
  $('app-refresh').addEventListener('click', () => guard(refreshAppliances));
  $('app-detail-close').addEventListener('click', () => {
    $('app-detail-json').hidden = true;
    $('app-detail-hint').hidden = true;
    $('app-detail-close').hidden = true;
    $('app-detail-empty').hidden = false;
  });

  $('app-rows').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    const row = e.target.closest('tr[data-id]');
    if (!row) return;
    const id = row.dataset.id;
    const base = '/api/admin/appliances/' + encodeURIComponent(id);
    const act = btn ? btn.dataset.act : 'show';

    if (act === 'show') { guard(async () => showAppliance(await apiGet(base))); return; }

    if (act === 'rotate') {
      if (!confirm('Rotate the token? The current token stops working immediately.')) return;
      guard(async () => {
        const res = await api('POST', base + '/rotate');
        showTokenModal(res.body.token, res.body.hint);
        await refreshAppliances();
      });
      return;
    }
    if (act === 'revoke') {
      if (!confirm('Revoke this appliance? Its record and history are kept.')) return;
      guard(async () => {
        const res = await api('POST', base + '/revoke');
        showAppliance(res.body);
        toast('Appliance revoked.', 'good');
        await refreshAppliances();
      });
      return;
    }
    if (act === 'delete') {
      if (!confirm('Delete this appliance record permanently?')) return;
      guard(async () => {
        await api('DELETE', base);
        toast('Appliance deleted.', 'good');
        await refreshAppliances();
      });
    }
  });

  $('app-create-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = $('app-new-name').value.trim();
    const description = $('app-new-desc').value.trim();
    if (!name || name.length > 128) { toast('Name must be 1-128 characters.', 'bad'); return; }
    guard(async () => {
      // description is optional, but the decoder rejects unknown fields only --
      // an empty string is accepted, so keep the body minimal anyway.
      const body = description ? { name, description } : { name };
      const res = await api('POST', '/api/admin/appliances', { body });
      $('app-new-name').value = '';
      $('app-new-desc').value = '';
      showTokenModal(res.body.token, res.body.hint);
      await refreshAppliances();
      showAppliance(res.body.appliance);
    });
  });

  // tenants
  $('ten-refresh').addEventListener('click', () => guard(refreshTenants));
  $('ten-detail-close').addEventListener('click', () => {
    $('ten-detail-json').hidden = true;
    $('ten-detail-hint').hidden = true;
    $('ten-detail-close').hidden = true;
    $('ten-detail-empty').hidden = false;
  });

  $('ten-rows').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    const row = e.target.closest('tr[data-id]');
    if (!row) return;
    const id = row.dataset.id;
    const act = btn ? btn.dataset.act : 'show';
    if (act === 'show') {
      guard(async () => {
        const t = await apiGet('/api/admin/tenants/' + encodeURIComponent(id), { tenantHeader: false });
        $('ten-detail-empty').hidden = true;
        $('ten-detail-json').hidden = false;
        $('ten-detail-hint').hidden = false;
        $('ten-detail-close').hidden = false;
        $('ten-detail-json').textContent = JSON.stringify(t, null, 2);
      });
      return;
    }
    if (act === 'delete') {
      if (!confirm(`Delete tenant "${id}"? Its policies, appliances and admins are deleted with it.`)) return;
      guard(async () => {
        await api('DELETE', '/api/admin/tenants/' + encodeURIComponent(id), { tenantHeader: false });
        if (state.tenant === id) state.tenant = '';
        toast(`Tenant ${id} deleted.`, 'good');
        await refreshTenants();
      });
    }
  });

  $('ten-create-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const id = $('ten-new-id').value.trim().toLowerCase();
    const name = $('ten-new-name').value.trim();
    guard(async () => {
      const body = name ? { id, name } : { id };
      await api('POST', '/api/admin/tenants', { body, tenantHeader: false });
      $('ten-new-id').value = '';
      $('ten-new-name').value = '';
      toast(`Tenant ${id} created.`, 'good');
      await refreshTenants();
    });
  });

  // system
  $('sys-refresh').addEventListener('click', () => guard(refreshSystem));
  $('who-refresh').addEventListener('click', () => guard(async () => {
    state.principal = await apiGet('/api/admin/auth/whoami');
    saveSession();
    renderWhoami();
    toast('Session is valid.', 'good');
  }));
  $('probe-get').addEventListener('click', () => guard(() => probePolicies('GET')));
  $('probe-head').addEventListener('click', () => guard(() => probePolicies('HEAD')));

  // token modal
  $('token-copy').addEventListener('click', async () => {
    const value = $('token-value').value;
    try {
      await navigator.clipboard.writeText(value);
      toast('Token copied to the clipboard.', 'good');
    } catch {
      $('token-value').select();
      toast('Copy failed; the token is selected, press Ctrl/Cmd+C.', 'bad');
    }
  });
  $('token-close').addEventListener('click', () => {
    $('token-value').value = '';
    $('token-modal').close();
  });

  // request log
  $('log-clear').addEventListener('click', () => { $('log-lines').innerHTML = ''; });
  $('log-toggle').addEventListener('click', (e) => {
    const collapsed = document.querySelector('.console').classList.toggle('collapsed');
    e.target.textContent = collapsed ? 'show' : 'hide';
  });
}

/* ── start ────────────────────────────────────────────────────────────── */

(async function main() {
  wire();
  try {
    await loadIndex();
    $('login-mode').textContent = `${state.mode} · v${state.version}`;
  } catch {
    $('login-mode').textContent = 'controller unreachable';
  }
  if (loadSession()) {
    // A stored token can still be revoked server-side; enterApp proves it with
    // whoami and falls back to the login screen if it is gone.
    try { await enterApp(); } catch { /* endSession already ran on 401 */ }
  }
})();
