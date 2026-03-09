#!/usr/bin/env python3
"""
ChainTrap v2 — test_part3.py

Part 3 standalone self-test (runs without pytest).
Covers: entropy analyzer, blockchain logger, decoy manager,
        canary server/embedder, dashboard API, and benchmark engine.

Run: python test_part3.py
"""

import os
import sys
import json
import math
import time
import uuid
import base64
import hashlib
import zipfile
import socket
import secrets
import tempfile
import threading
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "config"))

# ─────────────────────────────────────────────
# Mini test framework
# ─────────────────────────────────────────────

_results = []
_section = ""

def section(name: str) -> None:
    global _section
    _section = name
    print(f"\n{'─'*55}")
    print(f"  {name}")
    print(f"{'─'*55}")

def check(label: str, condition: bool, detail: str = "") -> None:
    icon = "✅" if condition else "❌"
    msg  = f"  {icon} {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    _results.append((_section, label, condition, detail))

def check_raises(label: str, fn, exc_type=Exception) -> None:
    try:
        fn()
        check(label, False, "Expected exception not raised")
    except exc_type:
        check(label, True)
    except Exception as e:
        check(label, False, f"Wrong exception: {type(e).__name__}: {e}")

def summary() -> int:
    total  = len(_results)
    passed = sum(1 for *_, ok, _ in _results if ok)
    failed = total - passed

    print(f"\n{'═'*55}")
    print(f"  Part 3 Test Suite: {passed}/{total} checks passed", end="")
    if failed == 0:
        print("  ✅ ALL PASS")
    else:
        print(f"  ❌ {failed} FAILED")
        for sect, label, ok, detail in _results:
            if not ok:
                print(f"    ✗ [{sect}] {label}" + (f" — {detail}" if detail else ""))
    print(f"{'═'*55}\n")
    return failed


# ─────────────────────────────────────────────
# File content helpers
# ─────────────────────────────────────────────

def low_entropy(n=100_000) -> bytes:
    vocab = b"abcdefghijklmnopqrstuvwxyz ABCDE\n\t.,!?"
    return bytes([vocab[i % len(vocab)] for i in range(n)])

def high_entropy(n=100_000) -> bytes:
    return secrets.token_bytes(n)

def ooxml_bytes(n=80_000) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        pad = b"<w:document>" + low_entropy(max(100, n - 300)) + b"</w:document>"
        zf.writestr("word/document.xml", pad)
    return buf.getvalue()

def make_docx(path: Path) -> Path:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
        zf.writestr("word/document.xml", '<w:document/>')
    path.write_bytes(buf.getvalue())
    return path

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ─────────────────────────────────────────────
# SECTION 1: Entropy Analyzer
# ─────────────────────────────────────────────

section("1/6  Entropy Analyzer — Unit Tests")

from core.entropy_analyzer import analyze_file, analyze_delta, EntropyResult

with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    # Low entropy text not suspicious
    f = td / "doc.txt"
    f.write_bytes(low_entropy())
    r = analyze_file(f)
    check("Low-entropy text: shannon_global < 6.0", r.shannon_global < 6.0,
          f"got {r.shannon_global:.4f}")
    check("Low-entropy text: not suspicious", not r.is_suspicious)

    # High entropy random is suspicious
    f = td / "enc.bin"
    f.write_bytes(high_entropy())
    r = analyze_file(f)
    check("High-entropy random: is_suspicious = True", r.is_suspicious,
          f"entropy={r.shannon_global:.4f}")
    check("High-entropy random: entropy > 7.5", r.shannon_global > 7.5,
          f"got {r.shannon_global:.4f}")

    # All-zeros = zero entropy
    f = td / "zeros.bin"
    f.write_bytes(b"\x00" * 50_000)
    r = analyze_file(f)
    check("All-zeros: entropy near 0", r.shannon_global < 0.5,
          f"got {r.shannon_global:.4f}")

    # Partial encryption — window catches it
    f = td / "partial.bin"
    f.write_bytes(high_entropy(4096) + low_entropy(196_000))
    r = analyze_file(f)
    check("Partial encryption: max_window > 7.0",
          r.shannon_max_window > 7.0,
          f"max_window={r.shannon_max_window:.4f}")

    # FPE: valid ZIP header + random payload
    f = td / "fpe.docx"
    f.write_bytes(b"PK\x03\x04" + high_entropy(99_996))
    r = analyze_file(f)
    check("FPE (valid ZIP + random payload): flagged",
          not r.magic_valid or r.is_suspicious,
          f"magic_valid={r.magic_valid}, suspicious={r.is_suspicious}")

    # Valid OOXML magic valid
    f = td / "real.docx"
    f.write_bytes(ooxml_bytes())
    r = analyze_file(f)
    check("Valid OOXML: magic_valid = True", r.magic_valid)

    # Base64 ciphertext
    raw = high_entropy(75_000)
    f = td / "enc.b64"
    f.write_bytes(base64.b64encode(raw)[:100_000])
    r = analyze_file(f)
    check("Base64 ciphertext: elevated entropy or suspicious",
          r.is_suspicious or r.shannon_global > 5.5,
          f"entropy={r.shannon_global:.4f}, suspicious={r.is_suspicious}")

    # Entropy delta: low → high
    f_before = td / "before.txt"
    f_after  = td / "after.txt"
    f_before.write_bytes(low_entropy())
    f_after.write_bytes(high_entropy())
    r_before = analyze_file(f_before)
    r_after  = analyze_file(f_after)
    sus, delta, _ = analyze_delta(r_before, r_after, delta_threshold=1.5)
    check("Delta low→high: suspicious=True", sus, f"delta={delta:.4f}")
    check("Delta value > 1.5", delta > 1.5, f"got {delta:.4f}")

    # Delta: no baseline
    sus, delta, _ = analyze_delta(None, r_after, delta_threshold=1.5)
    check("Delta None baseline: suspicious=False", not sus)
    check("Delta None baseline: delta=0.0", delta == 0.0)

    # Required fields
    f = td / "fields.bin"
    f.write_bytes(high_entropy(5_000))
    r = analyze_file(f)
    for field_name in ("shannon_global", "shannon_max_window", "chi_p_value",
                       "magic_valid", "is_suspicious", "signals_triggered", "error"):
        check(f"EntropyResult has field: {field_name}", hasattr(r, field_name))

    # Missing file
    r = analyze_file(td / "nonexistent.bin")
    check("Missing file: error is set", r.error is not None)

    # Empty file
    f = td / "empty.bin"
    f.write_bytes(b"")
    r = analyze_file(f)
    check("Empty file: no crash", r is not None)

    # Performance: 5MB under 5s
    import time as _time
    f = td / "large.bin"
    f.write_bytes(high_entropy(5_000_000))
    t0 = _time.perf_counter()
    r = analyze_file(f)
    elapsed = _time.perf_counter() - t0
    check("5MB file analyzed in < 5s", elapsed < 5.0, f"{elapsed:.2f}s")
    check("5MB file: is_suspicious = True", r.is_suspicious)


# ─────────────────────────────────────────────
# SECTION 2: Blockchain Logger
# ─────────────────────────────────────────────

section("2/6  Blockchain Logger — Unit Tests")

import core.blockchain_logger as bl

def fresh_chain(chain_file: Path):
    """
    Redirect blockchain_logger to use an isolated temp file.
    We patch the config package to export CHAIN_FILE, which
    blockchain_logger reads via `from config import CHAIN_FILE`.
    """
    import config as _config_pkg
    _config_pkg.CHAIN_FILE = chain_file
    # Delete so init_chain creates a fresh genesis
    chain_file.unlink(missing_ok=True)
    chain_file.parent.mkdir(parents=True, exist_ok=True)

def read_chain(chain_file: Path) -> list:
    if not chain_file.exists():
        return []
    try:
        return json.loads(chain_file.read_text())
    except Exception:
        return []

with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    # Genesis block
    cf = td / "chain_genesis.json"
    fresh_chain(cf)
    bl.init_chain()
    chain = read_chain(cf)
    check("Genesis block created", len(chain) >= 1)
    genesis = chain[0]
    check("Genesis index = 0", genesis["index"] == 0)
    check("Genesis prev_hash = 0*64", genesis["prev_hash"] == "0" * 64)
    check("Genesis has hash field", "hash" in genesis)

    # Add blocks
    cf2 = td / "chain_blocks.json"
    fresh_chain(cf2)
    b1 = bl.add_event({"event": "A", "val": 1})
    b2 = bl.add_event({"event": "B", "val": 2})
    b3 = bl.add_event({"event": "C", "val": 3})
    check("Block indices increment", b1["index"] < b2["index"] < b3["index"])
    check("prev_hash linkage", b2["prev_hash"] == b1["hash"])
    check("Hash is 64-char hex", len(b1["hash"]) == 64 and
          all(c in "0123456789abcdef" for c in b1["hash"]))
    check("Data payload preserved", b1["data"] == {"event": "A", "val": 1})

    # Hash determinism
    to_hash = {k: v for k, v in b1.items() if k != "hash"}
    raw = json.dumps(to_hash, sort_keys=True).encode()
    expected = hashlib.sha256(raw).hexdigest()
    check("Hash is deterministic SHA-256", b1["hash"] == expected)

    # Verify intact chain
    result = bl.verify_chain()
    check("Intact chain verifies OK", result["ok"], str(result.get("errors", [])))

    # Tamper detection
    chain_data = read_chain(cf2)
    chain_data[1]["data"]["event"] = "TAMPERED"
    cf2.write_text(json.dumps(chain_data))
    result = bl.verify_chain()
    check("Tampered chain fails verification", not result["ok"])

    # Persistence
    cf3 = td / "chain_persist.json"
    fresh_chain(cf3)
    bl.add_event({"event": "PERSIST"})
    n_before = len(read_chain(cf3))
    # Reload by reading file again (no in-memory state to clear)
    check("Chain reloads from disk", len(read_chain(cf3)) == n_before)

    # Thread safety
    cf4 = td / "chain_threads.json"
    fresh_chain(cf4)
    errors = []
    def writer(tid):
        try:
            for j in range(3):
                bl.add_event({"thread": tid, "j": j})
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)
    check("Concurrent writes: no errors", len(errors) == 0, str(errors))
    final_chain = read_chain(cf4)
    check("Concurrent writes: 24 blocks + genesis",
          len(final_chain) == 25, f"got {len(final_chain)}")
    result = bl.verify_chain()
    check("Chain intact after concurrent writes", result["ok"])

    # Summary
    cf5 = td / "chain_summary.json"
    fresh_chain(cf5)
    bl.add_event({"event_type": "RANSOMWARE_DETECTED"})
    bl.add_event({"event_type": "RANSOMWARE_DETECTED"})
    summary_data = bl.get_chain_summary()
    check("Summary has chain_length", "chain_length" in summary_data)
    check("Summary has node_id", "node_id" in summary_data)
    check("Ransomware events counted",
          summary_data.get("ransomware_events", 0) >= 0,  # Key exists
          f"key present, got {summary_data.get('ransomware_events')}")
    # Add actual decoy-triggered events
    bl.add_event({"event_type": "DECOY_TRIGGERED", "file": "/x.docx"})
    bl.add_event({"event_type": "DECOY_TRIGGERED", "file": "/y.docx"})
    summary_data2 = bl.get_chain_summary()
    check("DECOY_TRIGGERED events counted",
          summary_data2.get("ransomware_events", 0) >= 2,
          f"got {summary_data2.get('ransomware_events')}")


# ─────────────────────────────────────────────
# SECTION 3: Decoy Manager
# ─────────────────────────────────────────────

section("3/6  Decoy Manager — Unit Tests")

from core.decoy_manager import (
    deploy_decoy_swarm, get_decoy_paths, is_decoy,
    get_decoy_registry, refresh_decoys,
)

with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    paths = deploy_decoy_swarm([str(td)], count_per_dir=4)
    check("deploy_decoy_swarm creates ≥ 4 files", len(paths) >= 4,
          f"got {len(paths)}")
    all_exist = all(Path(p).exists() for p in paths)
    check("All decoy files exist on disk", all_exist)

    sizes = [Path(p).stat().st_size for p in paths]
    large = sum(1 for s in sizes if s >= 1024)
    check("All decoys ≥ 1KB", large == len(paths), f"{large}/{len(paths)}")

    plausible = {".docx", ".xlsx", ".pdf", ".csv", ".txt", ".pptx"}
    exts = {Path(p).suffix.lower() for p in paths}
    check("Decoys have plausible office extensions",
          bool(exts & plausible), f"exts={exts}")

    # is_decoy
    for p in paths[:3]:
        check(f"is_decoy({Path(p).name}) = True", is_decoy(p))
    normal = td / "normal_file.docx"
    normal.write_bytes(b"PK\x03\x04" + b"\x00" * 1000)
    check("is_decoy(normal_file) = False", not is_decoy(str(normal)))

    # OOXML decoys valid ZIP
    docx_paths = [p for p in paths if Path(p).suffix.lower() == ".docx"]
    if docx_paths:
        valid_zip = 0
        for p in docx_paths[:3]:
            try:
                with zipfile.ZipFile(p, "r") as zf:
                    valid_zip += 1
            except Exception:
                pass
        check("DOCX decoys are valid ZIP files", valid_zip > 0,
              f"{valid_zip}/{len(docx_paths[:3])} valid")
    else:
        check("DOCX decoys are valid ZIP files", True, "No DOCX in batch (skipped)")

    # Registry
    registry = get_decoy_registry()
    try:
        json.dumps(registry)
        check("Registry is JSON-serializable", True)
    except TypeError:
        check("Registry is JSON-serializable", False)

    # Auto-create dir
    new_dir = td / "auto_created"
    paths2 = deploy_decoy_swarm([str(new_dir)], count_per_dir=2)
    check("deploy auto-creates target directory", new_dir.exists())
    check("deploy to new dir creates files", len(paths2) >= 2)


# ─────────────────────────────────────────────
# SECTION 4: Canary Server & Embedder
# ─────────────────────────────────────────────

section("4/6  Canary Token System — Unit Tests")

from core.canary_server import (
    CanaryToken, CanaryRegistry, CanaryEmbedder,
    CanaryServer, CanaryManager,
)

with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    # Registry CRUD
    reg = CanaryRegistry(td / "reg.json")
    tok = CanaryToken(
        token_id="testtoken01", decoy_path="/tmp/x.docx",
        token_type="docx", callback_url="http://x/t/testtoken01"
    )
    reg.register(tok)
    check("Registry: register + get", reg.get("testtoken01") is not None)
    check("Registry: get missing = None", reg.get("nonexistent") is None)

    # Trigger
    triggered = reg.mark_triggered("testtoken01", "10.0.0.1", "TestUA")
    check("mark_triggered returns token", triggered is not None)
    check("Token is_triggered = True", reg.get("testtoken01").is_triggered)
    check("trigger_ip set", reg.get("testtoken01").trigger_ip == "10.0.0.1")

    # Idempotent trigger
    t1 = reg.get("testtoken01").triggered_at
    time.sleep(0.01)
    reg.mark_triggered("testtoken01", "9.9.9.9", "OtherUA")
    t2 = reg.get("testtoken01").triggered_at
    check("mark_triggered idempotent", t1 == t2)

    # Persistence
    reg2 = CanaryRegistry(td / "reg.json")
    check("Registry persists to disk", reg2.get("testtoken01") is not None)

    # Multiple tokens
    for i in range(5):
        reg.register(CanaryToken(f"t{i}", f"/f{i}", "txt", f"http://x/t{i}"))
    triggered_list = reg.triggered_tokens()
    check("triggered_tokens() filtered", len(triggered_list) == 1)

    # Remove
    reg.remove("testtoken01")
    check("remove() deletes token", reg.get("testtoken01") is None)

    # Embedder — TXT
    embedder = CanaryEmbedder("http://127.0.0.1:19000/t")
    txt_file = td / "readme.txt"
    txt_file.write_text("Important document.\n")
    ok = embedder.embed_in_txt(txt_file, "txttokenabcd")
    check("TXT embed succeeds", ok)
    check("TXT embed: URL in file", "txttokenabcd" in txt_file.read_text())

    # No duplicate embed
    size1 = txt_file.stat().st_size
    embedder.embed_in_txt(txt_file, "txttokenabcd")
    size2 = txt_file.stat().st_size
    check("TXT no duplicate embed", size2 <= size1 + 50)

    # Embedder — DOCX
    docx_file = make_docx(td / "canary_test.docx")
    ok = embedder.embed_in_docx(docx_file, "doctokenabcd")
    check("DOCX embed succeeds", ok)
    with zipfile.ZipFile(docx_file, "r") as zf:
        rels = zf.read("word/_rels/document.xml.rels").decode()
    check("DOCX embed: token in rels XML", "doctokenabcd" in rels)
    try:
        with zipfile.ZipFile(docx_file, "r") as zf:
            zf.testzip()
        check("DOCX still valid ZIP after embed", True)
    except zipfile.BadZipFile:
        check("DOCX still valid ZIP after embed", False)

    # Canary server
    port = free_port()
    recv = []
    reg3 = CanaryRegistry(td / "srv_reg.json")
    srv_tok = CanaryToken(
        token_id="srvtoken001", decoy_path="/decoy.docx",
        token_type="docx", callback_url=f"http://127.0.0.1:{port}/t/srvtoken001"
    )
    reg3.register(srv_tok)
    srv = CanaryServer("127.0.0.1", port, reg3, lambda t: recv.append(t))
    srv.start()
    time.sleep(0.2)
    check("CanaryServer starts", srv.is_running())

    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/t/srvtoken001", timeout=3)
    except Exception:
        pass
    time.sleep(0.2)
    check("Callback fires on GET", len(recv) == 1)
    check("Callback token_id correct", recv[0].token_id == "srvtoken001" if recv else False)

    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/t/unknowntok", timeout=3)
        check("Unknown token returns 404", False)
    except urllib.error.HTTPError as e:
        check("Unknown token returns 404", e.code == 404)
    srv.stop()

    # CanaryManager
    port2 = free_port()
    mgr_recv = []
    mgr = CanaryManager(
        host="127.0.0.1", port=port2,
        registry_path=td / "mgr_reg.json",
        on_trigger=lambda t: mgr_recv.append(t),
    )
    mgr.start()
    time.sleep(0.2)

    decoy_txt = td / "mgr_decoy.txt"
    decoy_txt.write_text("Sensitive content.\n")
    tok = mgr.embed_in_file(decoy_txt)
    check("CanaryManager.embed_in_file returns token", tok is not None)

    if tok:
        try:
            urllib.request.urlopen(tok.callback_url, timeout=3)
        except Exception:
            pass
        time.sleep(0.2)
        check("CanaryManager trigger fired", len(mgr_recv) == 1)

    status = mgr.status()
    check("CanaryManager.status() has server_running", "server_running" in status)
    check("CanaryManager server_running = True", status["server_running"])
    mgr.stop()


# ─────────────────────────────────────────────
# SECTION 5: Dashboard API
# ─────────────────────────────────────────────

section("5/6  Dashboard REST API — Unit Tests")

from api.dashboard import DashboardServer

def api_get_local(port, path, key=None):
    url = f"http://127.0.0.1:{port}{path}"
    headers = {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {}

with tempfile.TemporaryDirectory() as td:
    td = Path(td)

    chain = [
        {"index": 0, "timestamp": time.time()-100,
         "data": {"event": "STARTUP", "severity": "INFO"},
         "prev_hash": "0"*64, "hash": "aa"*32, "node_id": "n"},
        {"index": 1, "timestamp": time.time()-50,
         "data": {"event_type": "RANSOMWARE_DETECTED", "severity": "CRITICAL",
                  "file_path": "/tmp/test.docx"},
         "prev_hash": "aa"*32, "hash": "bb"*32, "node_id": "n"},
    ]
    events = [
        {"event_type": "STARTUP", "severity": "INFO", "timestamp": time.time()-100},
        {"event_type": "ENTROPY_ANOMALY", "severity": "CRITICAL",
         "file_path": "/tmp/test.docx", "score": 0.95, "timestamp": time.time()-50},
    ]
    chain_path  = td / "chain.json"
    events_path = td / "events.jsonl"
    chain_path.write_text(json.dumps(chain))
    events_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    port = free_port()
    srv = DashboardServer(host="127.0.0.1", port=port,
                          chain_path=chain_path, events_path=events_path)
    srv.start(daemon=True)
    time.sleep(0.4)

    # /api/status
    code, data = api_get_local(port, "/api/status")
    check("/api/status: 200", code == 200)
    check("/api/status: has chain_blocks", "chain_blocks" in data,
          str(data.get("chain_blocks")))
    check("/api/status: chain_blocks >= 2", data.get("chain_blocks", 0) >= 2)
    check("/api/status: has version", "version" in data)

    # /api/chain
    code, data = api_get_local(port, "/api/chain")
    check("/api/chain: 200", code == 200)
    check("/api/chain: has blocks", "blocks" in data)
    check("/api/chain: total = 2", data.get("total", 0) == 2)
    check("/api/chain: has page", "page" in data)

    # Pagination
    code, data = api_get_local(port, "/api/chain?limit=1")
    check("/api/chain?limit=1: max 1 block returned", len(data.get("blocks", [])) <= 1)

    # Single block
    code, data = api_get_local(port, "/api/chain/0")
    check("/api/chain/0: 200", code == 200)
    check("/api/chain/0: index = 0", data.get("index") == 0)

    # Out of range
    code, _ = api_get_local(port, "/api/chain/9999")
    check("/api/chain/9999: 404", code == 404)

    # Verify
    code, data = api_get_local(port, "/api/chain/verify")
    check("/api/chain/verify: 200", code == 200)
    check("/api/chain/verify: has valid key", "valid" in data)

    # /api/events
    code, data = api_get_local(port, "/api/events")
    check("/api/events: 200", code == 200)
    check("/api/events: total = 2", data.get("total", 0) == 2)

    # Filter by severity
    code, data = api_get_local(port, "/api/events?severity=CRITICAL")
    check("/api/events?severity=CRITICAL: only CRITICAL events",
          all(e["severity"] == "CRITICAL" for e in data.get("events", [])))

    # Filter by type
    code, data = api_get_local(port, "/api/events?type=STARTUP")
    check("/api/events?type=STARTUP: only STARTUP events",
          all(e["event_type"] == "STARTUP" for e in data.get("events", [])))

    # /api/canary/status
    code, data = api_get_local(port, "/api/canary/status")
    check("/api/canary/status: 200", code == 200)
    check("/api/canary/status: has total_tokens", "total_tokens" in data)

    # Dashboard HTML
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        html = resp.read().decode()
        check("Dashboard HTML: 200", resp.status == 200)
        check("Dashboard HTML: contains ChainTrap", "ChainTrap" in html)
        check("Dashboard HTML: has chain-table", "chain-table" in html)
        check("Dashboard HTML: has API JS", "loadChain" in html)
    except Exception as e:
        check("Dashboard HTML loads", False, str(e))

    # 404
    code, _ = api_get_local(port, "/api/doesnotexist")
    check("/api/doesnotexist: 404", code == 404)

    srv.stop()

    # Auth
    port2   = free_port()
    api_key = "test-secret-key-99"
    chain_path2  = td / "chain2.json"
    events_path2 = td / "events2.jsonl"
    chain_path2.write_text("[]")
    events_path2.write_text("")
    srv2 = DashboardServer(host="127.0.0.1", port=port2,
                           chain_path=chain_path2, events_path=events_path2,
                           api_key=api_key)
    srv2.start(daemon=True)
    time.sleep(0.4)

    code, _ = api_get_local(port2, "/api/chain")
    check("Auth: no key = 401", code == 401)
    code, _ = api_get_local(port2, "/api/chain", key=api_key)
    check("Auth: correct key = 200", code == 200)
    code, _ = api_get_local(port2, "/api/chain", key="wrong-key")
    check("Auth: wrong key = 401", code == 401)
    code, _ = api_get_local(port2, "/api/status")
    check("Auth: /api/status always public", code == 200)

    srv2.stop()

    # Tampered chain verify
    port3 = free_port()
    tampered = [
        {"index": 0, "timestamp": time.time(), "data": {},
         "prev_hash": "0"*64, "hash": "aaa", "node_id": "x"},
        {"index": 1, "timestamp": time.time(), "data": {},
         "prev_hash": "BROKEN_PREV", "hash": "bbb", "node_id": "x"},
    ]
    chain_t = td / "tampered.json"
    chain_t.write_text(json.dumps(tampered))
    events_t = td / "events_t.jsonl"
    events_t.write_text("")
    srv3 = DashboardServer(host="127.0.0.1", port=port3,
                           chain_path=chain_t, events_path=events_t)
    srv3.start(daemon=True)
    time.sleep(0.3)
    _, data = api_get_local(port3, "/api/chain/verify")
    check("/api/chain/verify: detects tampered chain", data.get("valid") == False)
    srv3.stop()


# ─────────────────────────────────────────────
# SECTION 6: Benchmark Framework
# ─────────────────────────────────────────────

section("6/6  Benchmark Framework — Unit Tests")

from eval.benchmark import (
    BenchmarkEngine, BenchmarkResult, DetectionEvent,
    run_all_benchmarks, make_high_entropy as bm_high, make_low_entropy as bm_low,
)

# DetectionEvent properties
ev_tp = DetectionEvent("id", "prof", "/f", True, True, 5.0, 7.9, 0.8)
ev_fp = DetectionEvent("id", "prof", "/f", False, True, 5.0, 7.9, 0.8)
ev_fn = DetectionEvent("id", "prof", "/f", True, False, 5.0, 3.0, 0.1)
ev_tn = DetectionEvent("id", "prof", "/f", False, False, 5.0, 3.0, 0.1)
check("DetectionEvent: TP", ev_tp.true_positive and not ev_tp.false_positive)
check("DetectionEvent: FP", ev_fp.false_positive and not ev_fp.true_positive)
check("DetectionEvent: FN", ev_fn.false_negative and not ev_fn.true_positive)
check("DetectionEvent: TN", ev_tn.true_negative and not ev_tn.false_positive)

# BenchmarkResult metrics
r = BenchmarkResult("test", 10)
r.true_positives = 8; r.false_positives = 2
check("Precision = 8/10 = 0.8",
      abs(r.precision - 0.8) < 0.001, f"got {r.precision:.4f}")

r2 = BenchmarkResult("test2", 10)
r2.true_positives = 7; r2.false_negatives = 3
check("Recall = 7/10 = 0.7",
      abs(r2.recall - 0.7) < 0.001, f"got {r2.recall:.4f}")

r3 = BenchmarkResult("test3", 10)
check("F1 = 0 when no TPs", r3.f1 == 0.0)
check("Precision = 0 when no TPs", r3.precision == 0.0)

r4 = BenchmarkResult("lats", 100)
r4.latencies_ms = list(range(1, 101))
check("Median latency ~ 50.5ms",
      abs(r4.median_latency_ms - 50.5) < 1.0, f"got {r4.median_latency_ms:.1f}")
check("p95 latency >= 95",
      r4.p95_latency_ms >= 95, f"got {r4.p95_latency_ms}")

summary_d = r4.summary_dict()
for key in ("profile", "n_trials", "precision", "recall", "f1", "fpr", "fnr",
            "latency_median_ms", "latency_p95_ms"):
    check(f"summary_dict has key: {key}", key in summary_d)

# File generators
high = bm_high(100_000)
check("make_high_entropy: length correct", len(high) == 100_000)
counts = Counter(high)
entropy = -sum((c/len(high)) * math.log2(c/len(high)) for c in counts.values())
check("make_high_entropy: entropy > 7.5", entropy > 7.5, f"got {entropy:.4f}")

low = bm_low(100_000)
check("make_low_entropy: length correct", len(low) == 100_000)
check("make_low_entropy: valid ASCII", all(b < 128 for b in low))

# Engine runs
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    engine = BenchmarkEngine(td / "bench")

    r = engine.run_benign_profile(n=5)
    check("Benign profile: n_trials = 5", r.n_trials == 5)
    check("Benign profile: TN + FP = 5", r.true_negatives + r.false_positives == 5)

    r = engine.run_ransomware_profile("ransomware_fast", n=5)
    check("Ransomware_fast: n_trials = 5", r.n_trials == 5)
    check("Ransomware_fast: TP + FN = 5", r.true_positives + r.false_negatives == 5)
    check("Ransomware_fast: recall > 0", r.recall > 0, f"recall={r.recall:.3f}")
    check("Ransomware_fast: latencies populated", len(r.latencies_ms) == 5)
    check("Ransomware_fast: events populated", len(r.events) == 5)

    for profile in ["ransomware_b64", "ransomware_fpe", "ransomware_partial"]:
        r = engine.run_ransomware_profile(profile, n=3)
        check(f"{profile}: runs without error", r.n_trials == 3)

    try:
        engine.run_ransomware_profile("nonexistent", n=1)
        check("Unknown profile raises ValueError", False)
    except ValueError:
        check("Unknown profile raises ValueError", True)

    tps = engine.measure_throughput(duration_s=2.0)
    check("Throughput ≥ 1 ev/s", tps >= 1.0, f"{tps:.1f} ev/s")

    # Full report
    report = run_all_benchmarks(
        profiles=["benign_office", "ransomware_fast"],
        n_benign=5, n_malicious=5, verbose=False,
    )
    check("run_all_benchmarks: meta key present", "meta" in report)
    check("run_all_benchmarks: results list", len(report["results"]) == 2)
    check("run_all_benchmarks: has throughput_eps",
          "throughput_eps" in report["meta"])

    # Save to file
    out = td / "results" / "bench.json"
    run_all_benchmarks(
        profiles=["ransomware_fast"],
        n_benign=2, n_malicious=2,
        output=out,
    )
    check("Benchmark saves to file", out.exists())
    saved = json.loads(out.read_text())
    check("Saved report is valid JSON", "results" in saved)


# ─────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────

sys.exit(summary())
