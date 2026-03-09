"""
ChainTrap v2 — api/dashboard.py

REST API + Web Dashboard for Forensic Chain Viewer

Provides:
  GET  /api/chain              — Full blockchain with optional pagination
  GET  /api/chain/<index>      — Single block by index
  GET  /api/chain/verify       — Verify chain integrity
  GET  /api/events             — Structured event log (filterable)
  GET  /api/canary/status      — Canary token status
  GET  /api/status             — System status (monitor alive, stats)
  POST /api/response/quarantine — Trigger manual quarantine
  POST /api/response/lockdown   — Trigger network lockdown
  GET  /                       — Web dashboard (HTML5 SPA)

Run:
    python -m api.dashboard --port 5000
    python -m api.dashboard --port 5000 --host 0.0.0.0

Auth: CHAINTRAP_API_KEY env var (Bearer token). If not set, no auth required.
"""

from __future__ import annotations

import os
import sys
import json
import time
import hmac
import hashlib
import logging
import argparse
import functools
import threading
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))

logger = logging.getLogger("ChainTrap.dashboard")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _json(data: dict | list, status: int = 200) -> tuple[int, dict, bytes]:
    body = json.dumps(data, indent=2).encode()
    headers = {
        "Content-Type":  "application/json",
        "Content-Length": str(len(body)),
        "Cache-Control": "no-cache",
        "Access-Control-Allow-Origin": "*",
    }
    return status, headers, body


def _html(content: str) -> tuple[int, dict, bytes]:
    body = content.encode()
    headers = {
        "Content-Type":  "text/html; charset=utf-8",
        "Content-Length": str(len(body)),
    }
    return 200, headers, body


# ─────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────

def _load_chain(chain_path: Path) -> list[dict]:
    if not chain_path.exists():
        return []
    try:
        data = json.loads(chain_path.read_text())
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _load_events(events_path: Path) -> list[dict]:
    if not events_path.exists():
        return []
    events = []
    try:
        for line in events_path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return events


def _verify_chain(chain: list[dict]) -> dict:
    """Re-verify chain integrity inline."""
    if not chain:
        return {"valid": True, "blocks": 0, "message": "Empty chain"}

    import hashlib
    errors = []
    for i, block in enumerate(chain):
        # Recompute hash
        to_hash = {k: v for k, v in block.items() if k != "hash"}
        raw     = json.dumps(to_hash, sort_keys=True).encode()
        computed = hashlib.sha256(raw).hexdigest()
        if computed != block.get("hash"):
            errors.append(f"Block {i}: hash mismatch")
        # Check linkage
        if i > 0:
            expected_prev = chain[i-1].get("hash")
            if block.get("prev_hash") != expected_prev:
                errors.append(f"Block {i}: prev_hash broken")

    return {
        "valid":   len(errors) == 0,
        "blocks":  len(chain),
        "errors":  errors,
        "message": "Chain intact" if not errors else f"{len(errors)} error(s) found",
    }


def _load_canary_status(registry_path: Path) -> dict:
    if not registry_path.exists():
        return {"total_tokens": 0, "triggered": 0, "tokens": []}
    try:
        data = json.loads(registry_path.read_text())
        tokens = list(data.values())
        triggered = [t for t in tokens if t.get("triggered_at")]
        return {
            "total_tokens": len(tokens),
            "triggered": len(triggered),
            "tokens": triggered,
        }
    except Exception:
        return {"error": "Could not load canary registry"}


# ─────────────────────────────────────────────
# REQUEST HANDLER
# ─────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):

    chain_path:    Path
    events_path:   Path
    canary_path:   Path
    api_key:       Optional[str]

    def _auth_ok(self) -> bool:
        if not self.api_key:
            return True
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            return hmac.compare_digest(token, self.api_key)
        return False

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        if path == "/" or path == "/dashboard":
            status, headers, body = _html(DASHBOARD_HTML)
        elif path == "/api/status":
            status, headers, body = self._handle_status()
        elif path == "/api/chain":
            if not self._auth_ok():
                status, headers, body = _json({"error": "Unauthorized"}, 401)
            else:
                status, headers, body = self._handle_chain(qs)
        elif path.startswith("/api/chain/"):
            if not self._auth_ok():
                status, headers, body = _json({"error": "Unauthorized"}, 401)
            else:
                part = path.split("/api/chain/")[1]
                if part == "verify":
                    status, headers, body = self._handle_verify()
                else:
                    try:
                        idx = int(part)
                        status, headers, body = self._handle_block(idx)
                    except ValueError:
                        status, headers, body = _json({"error": "Invalid block index"}, 400)
        elif path == "/api/events":
            if not self._auth_ok():
                status, headers, body = _json({"error": "Unauthorized"}, 401)
            else:
                status, headers, body = self._handle_events(qs)
        elif path == "/api/canary/status":
            if not self._auth_ok():
                status, headers, body = _json({"error": "Unauthorized"}, 401)
            else:
                status, headers, body = self._handle_canary()
        else:
            status, headers, body = _json({"error": "Not found"}, 404)

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")

        if not self._auth_ok():
            status, headers, body = _json({"error": "Unauthorized"}, 401)
        elif path == "/api/response/quarantine":
            status, headers, body = self._handle_quarantine()
        elif path == "/api/response/lockdown":
            status, headers, body = self._handle_lockdown()
        else:
            status, headers, body = _json({"error": "Not found"}, 404)

        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # ── Route Handlers ──────────────────────────────────────────────────────

    def _handle_status(self) -> tuple:
        chain = _load_chain(self.chain_path)
        return _json({
            "status":        "running",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "chain_blocks":  len(chain),
            "chain_path":    str(self.chain_path),
            "events_path":   str(self.events_path),
            "version":       "2.0",
        })

    def _handle_chain(self, qs: dict) -> tuple:
        chain = _load_chain(self.chain_path)

        # Pagination
        try:
            page  = int(qs.get("page", [1])[0])
            limit = min(int(qs.get("limit", [50])[0]), 200)
        except (ValueError, IndexError):
            page, limit = 1, 50

        total  = len(chain)
        start  = (page - 1) * limit
        end    = start + limit
        paged  = chain[start:end]

        return _json({
            "total":    total,
            "page":     page,
            "limit":    limit,
            "pages":    max(1, (total + limit - 1) // limit),
            "blocks":   paged,
        })

    def _handle_block(self, idx: int) -> tuple:
        chain = _load_chain(self.chain_path)
        if idx < 0 or idx >= len(chain):
            return _json({"error": f"Block {idx} not found"}, 404)
        return _json(chain[idx])

    def _handle_verify(self) -> tuple:
        chain  = _load_chain(self.chain_path)
        result = _verify_chain(chain)
        return _json(result)

    def _handle_events(self, qs: dict) -> tuple:
        events = _load_events(self.events_path)

        # Filter
        event_type = qs.get("type", [None])[0]
        severity   = qs.get("severity", [None])[0]
        since      = qs.get("since", [None])[0]   # Unix timestamp

        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if severity:
            events = [e for e in events if e.get("severity") == severity]
        if since:
            try:
                since_ts = float(since)
                events = [e for e in events if e.get("timestamp", 0) >= since_ts]
            except ValueError:
                pass

        # Pagination
        try:
            page  = int(qs.get("page", [1])[0])
            limit = min(int(qs.get("limit", [100])[0]), 500)
        except (ValueError, IndexError):
            page, limit = 1, 100

        total  = len(events)
        start  = (page - 1) * limit
        paged  = events[start:start+limit]

        return _json({
            "total":  total,
            "page":   page,
            "limit":  limit,
            "events": paged,
        })

    def _handle_canary(self) -> tuple:
        result = _load_canary_status(self.canary_path)
        return _json(result)

    def _handle_quarantine(self) -> tuple:
        # Read body for target path
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(body)
            path = data.get("path")
        except Exception:
            path = None

        if not path:
            return _json({"error": "Missing 'path' in request body"}, 400)

        try:
            from core.platform_ops import atomic_quarantine
            target = Path(path)
            dest   = atomic_quarantine(target)
            return _json({"status": "quarantined", "destination": str(dest)})
        except Exception as e:
            return _json({"error": str(e)}, 500)

    def _handle_lockdown(self) -> tuple:
        try:
            from core.platform_ops import lockdown_network
            lockdown_network()
            return _json({"status": "network_lockdown_initiated"})
        except Exception as e:
            return _json({"error": str(e)}, 500)

    def log_message(self, fmt, *args) -> None:
        logger.debug("API: " + fmt, *args)


# ─────────────────────────────────────────────
# HTML DASHBOARD (Single-File SPA)
# ─────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ChainTrap v2 — Forensic Dashboard</title>
<style>
  :root {
    --bg:     #0d1117;
    --panel:  #161b22;
    --border: #30363d;
    --accent: #58a6ff;
    --danger: #f85149;
    --warn:   #e3b341;
    --ok:     #3fb950;
    --text:   #c9d1d9;
    --muted:  #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, monospace; min-height: 100vh; }
  header { background: var(--panel); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.2rem; font-weight: 600; color: var(--accent); }
  header .badge { background: var(--danger); color: #fff; font-size: .7rem; padding: 2px 8px; border-radius: 99px; font-weight: 700; }
  .badge.ok { background: var(--ok); }
  nav { display: flex; gap: 4px; padding: 12px 24px; border-bottom: 1px solid var(--border); }
  nav button { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: .85rem; }
  nav button.active, nav button:hover { border-color: var(--accent); color: var(--accent); }
  .main { padding: 24px; max-width: 1400px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .card .label { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }
  .card .value { font-size: 2rem; font-weight: 700; color: var(--accent); }
  .card .value.danger { color: var(--danger); }
  .card .value.ok { color: var(--ok); }
  .section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; }
  .section-header { padding: 12px 16px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: .9rem; display: flex; justify-content: space-between; align-items: center; }
  .section-body { padding: 0; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: .82rem; }
  th { padding: 10px 16px; text-align: left; color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); background: rgba(255,255,255,.02); }
  td { padding: 10px 16px; border-bottom: 1px solid rgba(48,54,61,.5); font-family: monospace; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88,166,255,.04); }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: 600; }
  .tag.critical { background: rgba(248,81,73,.15); color: var(--danger); }
  .tag.warning  { background: rgba(227,179,65,.15); color: var(--warn); }
  .tag.info     { background: rgba(88,166,255,.1); color: var(--accent); }
  .tag.ok       { background: rgba(63,185,80,.1); color: var(--ok); }
  pre { font-size: .78rem; line-height: 1.5; color: var(--text); white-space: pre-wrap; word-break: break-all; }
  .hash { font-family: monospace; font-size: .7rem; color: var(--muted); }
  button.action { background: var(--danger); border: none; color: #fff; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: .82rem; font-weight: 600; }
  button.action:hover { opacity: .85; }
  .refresh-btn { background: transparent; border: 1px solid var(--border); color: var(--muted); padding: 4px 12px; border-radius: 6px; cursor: pointer; font-size: .8rem; }
  .refresh-btn:hover { border-color: var(--accent); color: var(--accent); }
  .empty { padding: 40px; text-align: center; color: var(--muted); font-size: .9rem; }
  .pager { padding: 12px 16px; display: flex; gap: 8px; align-items: center; justify-content: flex-end; }
  .pager button { background: var(--panel); border: 1px solid var(--border); color: var(--text); padding: 4px 12px; border-radius: 4px; cursor: pointer; }
  .pager button:disabled { opacity: .4; cursor: default; }
  #tab-chain { display: block; } #tab-events { display: none; } #tab-canary { display: none; }
  .canary-row.triggered td { color: var(--danger); }
</style>
</head>
<body>

<header>
  <h1>🔗 ChainTrap v2</h1>
  <span class="badge ok" id="system-badge">●  Checking...</span>
  <span style="margin-left:auto;color:var(--muted);font-size:.8rem" id="last-refresh"></span>
</header>

<nav>
  <button class="active" onclick="showTab('chain', this)">⛓ Blockchain</button>
  <button onclick="showTab('events', this)">📋 Events</button>
  <button onclick="showTab('canary', this)">🪤 Canary Tokens</button>
  <button onclick="showTab('response', this)">🚨 Response</button>
</nav>

<div class="main">

  <!-- Stats row -->
  <div class="grid" id="stats-grid">
    <div class="card"><div class="label">Chain Blocks</div><div class="value" id="stat-blocks">—</div></div>
    <div class="card"><div class="label">Chain Status</div><div class="value ok" id="stat-chain">—</div></div>
    <div class="card"><div class="label">Events</div><div class="value" id="stat-events">—</div></div>
    <div class="card"><div class="label">Canary Tokens</div><div class="value" id="stat-canaries">—</div></div>
    <div class="card"><div class="label">Triggered</div><div class="value danger" id="stat-triggered">—</div></div>
  </div>

  <!-- Blockchain tab -->
  <div id="tab-chain">
    <div class="section">
      <div class="section-header">
        Blockchain Audit Trail
        <div style="display:flex;gap:8px;align-items:center">
          <span id="chain-verify-status"></span>
          <button class="refresh-btn" onclick="loadChain()">↻ Refresh</button>
        </div>
      </div>
      <div class="section-body">
        <table id="chain-table">
          <thead><tr><th>#</th><th>Timestamp</th><th>Event</th><th>Severity</th><th>Hash</th><th>Details</th></tr></thead>
          <tbody id="chain-body"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
        </table>
        <div class="pager" id="chain-pager"></div>
      </div>
    </div>
  </div>

  <!-- Events tab -->
  <div id="tab-events" style="display:none">
    <div class="section">
      <div class="section-header">
        Structured Event Log
        <button class="refresh-btn" onclick="loadEvents()">↻ Refresh</button>
      </div>
      <div class="section-body">
        <table>
          <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>File</th><th>Score</th><th>PID</th></tr></thead>
          <tbody id="events-body"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
        </table>
        <div class="pager" id="events-pager"></div>
      </div>
    </div>
  </div>

  <!-- Canary tab -->
  <div id="tab-canary" style="display:none">
    <div class="section">
      <div class="section-header">Canary Token Registry <button class="refresh-btn" onclick="loadCanary()">↻ Refresh</button></div>
      <div class="section-body">
        <table>
          <thead><tr><th>Token ID</th><th>File</th><th>Type</th><th>Status</th><th>Trigger IP</th><th>Delay</th></tr></thead>
          <tbody id="canary-body"><tr><td colspan="6" class="empty">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Response tab -->
  <div id="tab-response" style="display:none">
    <div class="section">
      <div class="section-header">Emergency Response Actions</div>
      <div style="padding:24px;display:flex;flex-direction:column;gap:16px;max-width:500px">
        <div>
          <p style="color:var(--muted);font-size:.85rem;margin-bottom:12px">
            These actions are immediate and irreversible. Use only during an active incident.
          </p>
        </div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <label style="font-size:.85rem;color:var(--muted)">File path to quarantine:</label>
          <input id="quarantine-path" type="text" placeholder="/path/to/suspicious/file"
            style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-family:monospace;font-size:.85rem;">
          <button class="action" onclick="doQuarantine()">⚠ Quarantine File</button>
        </div>
        <hr style="border-color:var(--border)">
        <div>
          <p style="color:var(--warn);font-size:.82rem;margin-bottom:10px">
            ⚠ Network lockdown will block ALL outbound connections on this host.
          </p>
          <button class="action" onclick="doLockdown()">🔒 Initiate Network Lockdown</button>
        </div>
        <div id="response-result" style="font-family:monospace;font-size:.8rem;color:var(--ok);display:none;padding:10px;background:var(--bg);border-radius:6px;border:1px solid var(--border)"></div>
      </div>
    </div>
  </div>

</div>

<script>
const API = '';  // same origin
let chainPage = 1, eventsPage = 1;

// ── Tab switching ──────────────────────────────────────
function showTab(name, btn) {
  ['chain','events','canary','response'].forEach(t => {
    document.getElementById('tab-' + t).style.display = t === name ? 'block' : 'none';
  });
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  if (name === 'chain')    loadChain();
  if (name === 'events')   loadEvents();
  if (name === 'canary')   loadCanary();
}

// ── Data loaders ──────────────────────────────────────
async function api(path) {
  const resp = await fetch(API + path, {
    headers: window._apiKey ? { 'Authorization': 'Bearer ' + window._apiKey } : {}
  });
  return resp.json();
}

async function loadStatus() {
  try {
    const s = await api('/api/status');
    document.getElementById('stat-blocks').textContent = s.chain_blocks ?? '—';
    document.getElementById('system-badge').textContent = '●  Running';
    document.getElementById('system-badge').className = 'badge ok';
    document.getElementById('last-refresh').textContent = 'Last refresh: ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('system-badge').textContent = '●  Offline';
    document.getElementById('system-badge').className = 'badge';
  }

  try {
    const v = await api('/api/chain/verify');
    const el = document.getElementById('stat-chain');
    el.textContent = v.valid ? '✓ Valid' : '✗ Broken';
    el.className = 'value ' + (v.valid ? 'ok' : 'danger');
    document.getElementById('chain-verify-status').innerHTML =
      '<span class="tag ' + (v.valid ? 'ok' : 'critical') + '">' + (v.valid ? '✓ Intact' : '✗ Tampered') + '</span>';
  } catch(e) {}

  try {
    const ev = await api('/api/events?limit=1');
    document.getElementById('stat-events').textContent = ev.total ?? '—';
  } catch(e) {}

  try {
    const c = await api('/api/canary/status');
    document.getElementById('stat-canaries').textContent = c.total_tokens ?? '—';
    document.getElementById('stat-triggered').textContent = c.triggered ?? '—';
  } catch(e) {}
}

async function loadChain() {
  try {
    const data = await api('/api/chain?page=' + chainPage + '&limit=50');
    const tbody = document.getElementById('chain-body');
    if (!data.blocks || data.blocks.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No blocks yet</td></tr>';
      return;
    }
    tbody.innerHTML = data.blocks.map(b => {
      const ts = new Date(b.timestamp * 1000).toLocaleString();
      const ev = b.data?.event || b.data?.event_type || '—';
      const sev = b.data?.severity || 'INFO';
      const sevClass = sev === 'CRITICAL' ? 'critical' : sev === 'WARNING' ? 'warning' : 'info';
      const hash = (b.hash || '').slice(0, 12) + '...';
      const details = b.data?.file_path || b.data?.decoy_path || b.data?.path || '';
      return '<tr>' +
        '<td>' + b.index + '</td>' +
        '<td>' + ts + '</td>' +
        '<td>' + ev + '</td>' +
        '<td><span class="tag ' + sevClass + '">' + sev + '</span></td>' +
        '<td class="hash">' + hash + '</td>' +
        '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">' + details + '</td>' +
        '</tr>';
    }).join('');
    renderPager('chain-pager', data, (p) => { chainPage = p; loadChain(); });
    loadStatus();
  } catch(e) {
    document.getElementById('chain-body').innerHTML =
      '<tr><td colspan="6" class="empty">Error loading chain: ' + e.message + '</td></tr>';
  }
}

async function loadEvents() {
  try {
    const data = await api('/api/events?page=' + eventsPage + '&limit=100');
    const tbody = document.getElementById('events-body');
    if (!data.events || data.events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No events logged yet</td></tr>';
      return;
    }
    tbody.innerHTML = data.events.slice().reverse().map(e => {
      const ts = e.timestamp ? new Date(e.timestamp * 1000).toLocaleString() : '—';
      const sev = e.severity || 'INFO';
      const sevClass = sev === 'CRITICAL' ? 'critical' : sev === 'WARNING' ? 'warning' : 'info';
      const score = e.score != null ? e.score.toFixed(3) : '—';
      const pid = e.pids ? e.pids.join(', ') : '—';
      const fp = (e.file_path || '').split('/').pop() || '—';
      return '<tr>' +
        '<td>' + ts + '</td>' +
        '<td>' + (e.event_type || '—') + '</td>' +
        '<td><span class="tag ' + sevClass + '">' + sev + '</span></td>' +
        '<td title="' + (e.file_path || '') + '">' + fp + '</td>' +
        '<td>' + score + '</td>' +
        '<td>' + pid + '</td>' +
        '</tr>';
    }).join('');
    renderPager('events-pager', data, (p) => { eventsPage = p; loadEvents(); });
  } catch(e) {
    document.getElementById('events-body').innerHTML =
      '<tr><td colspan="6" class="empty">Error: ' + e.message + '</td></tr>';
  }
}

async function loadCanary() {
  try {
    const data = await api('/api/canary/status');
    const tbody = document.getElementById('canary-body');
    if (!data.tokens || data.tokens.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No canary tokens registered</td></tr>';
      return;
    }
    tbody.innerHTML = data.tokens.map(t => {
      const triggered = t.triggered_at != null;
      const delay = triggered ?
        ((t.triggered_at - t.created_at) / 1000).toFixed(1) + 's after deploy' : '—';
      const status = triggered ?
        '<span class="tag critical">🔥 TRIGGERED</span>' :
        '<span class="tag info">⏳ Waiting</span>';
      const fp = (t.decoy_path || '').split('/').pop() || '—';
      return '<tr class="' + (triggered ? 'canary-row triggered' : 'canary-row') + '">' +
        '<td class="hash">' + (t.token_id || '').slice(0,12) + '...</td>' +
        '<td>' + fp + '</td>' +
        '<td>' + (t.token_type || '—') + '</td>' +
        '<td>' + status + '</td>' +
        '<td>' + (t.trigger_ip || '—') + '</td>' +
        '<td>' + delay + '</td>' +
        '</tr>';
    }).join('');
  } catch(e) {
    document.getElementById('canary-body').innerHTML =
      '<tr><td colspan="6" class="empty">Error: ' + e.message + '</td></tr>';
  }
}

function renderPager(id, data, onPage) {
  const el = document.getElementById(id);
  if (!el || data.pages <= 1) { if(el) el.innerHTML = ''; return; }
  el.innerHTML = '<span style="color:var(--muted);font-size:.8rem">Page ' + data.page + ' of ' + data.pages + '</span>' +
    '<button onclick="(' + onPage.toString() + ')(' + Math.max(1,data.page-1) + ')"' +
      (data.page <= 1 ? ' disabled' : '') + '>← Prev</button>' +
    '<button onclick="(' + onPage.toString() + ')(' + Math.min(data.pages,data.page+1) + ')"' +
      (data.page >= data.pages ? ' disabled' : '') + '>Next →</button>';
}

// ── Response actions ──────────────────────────────────
async function doQuarantine() {
  const path = document.getElementById('quarantine-path').value.trim();
  if (!path) { alert('Enter a file path'); return; }
  if (!confirm('Quarantine: ' + path + '?')) return;
  try {
    const resp = await fetch('/api/response/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json',
                 ...(window._apiKey ? {'Authorization':'Bearer '+window._apiKey} : {}) },
      body: JSON.stringify({ path })
    });
    const data = await resp.json();
    showResult(JSON.stringify(data, null, 2));
  } catch(e) { showResult('Error: ' + e.message); }
}

async function doLockdown() {
  if (!confirm('⚠️ NETWORK LOCKDOWN — This blocks ALL outbound traffic. Continue?')) return;
  try {
    const resp = await fetch('/api/response/lockdown', {
      method: 'POST',
      headers: window._apiKey ? {'Authorization':'Bearer '+window._apiKey} : {}
    });
    const data = await resp.json();
    showResult(JSON.stringify(data, null, 2));
  } catch(e) { showResult('Error: ' + e.message); }
}

function showResult(msg) {
  const el = document.getElementById('response-result');
  el.style.display = 'block';
  el.textContent = msg;
}

// ── Init ──────────────────────────────────────────────
loadStatus();
loadChain();
setInterval(loadStatus, 15000);  // Auto-refresh every 15s
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────
# SERVER RUNNER
# ─────────────────────────────────────────────

class DashboardServer:
    """Lightweight production dashboard server."""

    def __init__(
        self,
        host:         str  = "127.0.0.1",
        port:         int  = 5000,
        chain_path:   Optional[Path] = None,
        events_path:  Optional[Path] = None,
        canary_path:  Optional[Path] = None,
        api_key:      Optional[str]  = None,
    ):
        self.host        = host
        self.port        = port
        self.chain_path  = chain_path or (Path.home() / "ChainTrap" / "chain" / "chain.json")
        self.events_path = events_path or (Path.home() / "ChainTrap" / "logs" / "events.jsonl")
        self.canary_path = canary_path or (_ROOT / "chain"  / "canary_registry.json")
        self.api_key     = api_key or os.environ.get("CHAINTRAP_API_KEY")
        self._server:    Optional[HTTPServer] = None
        self._thread:    Optional[threading.Thread] = None

    def start(self, daemon: bool = True) -> None:
        chain_path  = self.chain_path
        events_path = self.events_path
        canary_path = self.canary_path
        api_key     = self.api_key

        class BoundHandler(DashboardHandler):
            pass
        BoundHandler.chain_path   = chain_path
        BoundHandler.events_path  = events_path
        BoundHandler.canary_path  = canary_path
        BoundHandler.api_key      = api_key

        self._server = HTTPServer((self.host, self.port), BoundHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=daemon,
            name="ChainTrapDashboard",
        )
        self._thread.start()

        url = f"http://{self.host}:{self.port}"
        print(f"📊  Dashboard:    {url}")
        print(f"🔗  Chain API:    {url}/api/chain")
        print(f"📋  Events API:   {url}/api/events")
        print(f"🪤  Canary API:   {url}/api/canary/status")
        if self.api_key:
            print(f"🔑  Auth:         Bearer <CHAINTRAP_API_KEY>")
        else:
            print(f"⚠   Auth:         DISABLED (set CHAINTRAP_API_KEY to enable)")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    def join(self) -> None:
        if self._thread:
            self._thread.join()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(message)s")

    parser = argparse.ArgumentParser(description="ChainTrap v2 Forensic Dashboard")
    parser.add_argument("--host",        default="127.0.0.1")
    parser.add_argument("--port",  "-p", type=int, default=5000)
    parser.add_argument("--chain",       type=Path, default=None,
                        help="Path to chain.json (auto-detected if omitted)")
    parser.add_argument("--events",      type=Path, default=None,
                        help="Path to events.jsonl (auto-detected if omitted)")
    parser.add_argument("--canary",      type=Path, default=None,
                        help="Path to canary_registry.json")
    args = parser.parse_args()

    server = DashboardServer(
        host=args.host,
        port=args.port,
        chain_path=args.chain,
        events_path=args.events,
        canary_path=args.canary,
    )
    server.start(daemon=False)

    print("\nPress Ctrl+C to stop.")
    try:
        server.join()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
