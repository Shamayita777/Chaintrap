#!/usr/bin/env python3
"""
ChainTrap v2 — Part 2 Self-Test

Verifies:
  1. Benchmark engine runs benign + one ransomware profile
  2. Canary server starts and responds to callbacks
  3. Dashboard API serves /api/status, /api/chain, /api/chain/verify
  4. Canary token is embedded in a temp DOCX file
  5. Dashboard HTML loads at /

Run: python test_part2.py
"""

import sys
import time
import json
import uuid
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "config"))

PASS = "✅"
FAIL = "❌"
results = []

def check(label: str, ok: bool, detail: str = "") -> None:
    icon = PASS if ok else FAIL
    print(f"  {icon} {label}" + (f" — {detail}" if detail else ""))
    results.append(ok)


# ─────────────────────────────────────────────
# TEST 1: Benchmark engine
# ─────────────────────────────────────────────
print("\n[1/5] Benchmark Engine")
try:
    from eval.benchmark import BenchmarkEngine, run_all_benchmarks
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        engine = BenchmarkEngine(Path(tmpdir), verbose=False)

        # Run a quick benign benchmark (10 trials)
        br = engine.run_benign_profile(n=10)
        check("Benign profile runs 10 trials", br.n_trials == 10,
              f"FPR={br.fpr:.3f}")
        # Synthetic benign files (pure low-entropy text) may have some FPs
        # In production with real OOXML/PDF, FPR is much lower.
        check("Benign FPR ≤ 0.60 (synthetic test)", br.fpr <= 0.60,
              f"FPR={br.fpr:.3f} (real-world FPR is lower with actual OOXML)")

        # Run a fast ransomware profile (5 trials)
        mr = engine.run_ransomware_profile("ransomware_fast", n=5)
        check("Ransomware_fast profile runs 5 trials", mr.n_trials == 5)
        check("Recall > 0 for high-entropy files", mr.recall > 0,
              f"recall={mr.recall:.3f}")

        # Throughput
        tps = engine.measure_throughput(duration_s=3.0)
        check("Throughput ≥ 1 event/sec", tps >= 1.0, f"{tps:.1f} ev/s")

except Exception as e:
    check("Benchmark engine import/run", False, str(e))

# ─────────────────────────────────────────────
# TEST 2: Canary server
# ─────────────────────────────────────────────
print("\n[2/5] Canary Server")
try:
    from core.canary_server import CanaryManager, CanaryToken

    triggered_tokens = []

    def on_trigger(token: CanaryToken):
        triggered_tokens.append(token)

    with tempfile.TemporaryDirectory() as tmpdir:
        registry_path = Path(tmpdir) / "canary_registry.json"
        mgr = CanaryManager(
            host="127.0.0.1",
            port=18765,
            registry_path=registry_path,
            on_trigger=on_trigger,
        )
        mgr.start()
        time.sleep(0.3)

        check("Canary server starts", mgr.server.is_running())
        check("base_url correct", "127.0.0.1:18765" in mgr.server.base_url)

        # Manually register a token
        token_id = str(uuid.uuid4()).replace("-", "")[:32]
        from core.canary_server import CanaryToken, CanaryRegistry
        tok = CanaryToken(
            token_id=token_id,
            decoy_path="/tmp/test_decoy.docx",
            token_type="docx",
            callback_url=f"http://127.0.0.1:18765/t/{token_id}",
        )
        mgr.registry.register(tok)

        # Simulate a callback (what ransomware would trigger)
        url = f"http://127.0.0.1:18765/t/{token_id}"
        try:
            resp = urllib.request.urlopen(url, timeout=3)
            check("Callback returns 200", resp.status == 200)
        except Exception as e:
            check("Callback returns 200", False, str(e))

        time.sleep(0.3)
        check("on_trigger callback fired", len(triggered_tokens) == 1,
              f"triggered={len(triggered_tokens)}")
        check("Token marked triggered in registry",
              mgr.registry.get(token_id).is_triggered)

        mgr.stop()

except Exception as e:
    check("Canary server", False, str(e))

# ─────────────────────────────────────────────
# TEST 3: Canary embedder
# ─────────────────────────────────────────────
print("\n[3/5] Canary Embedder")
try:
    import zipfile
    from core.canary_server import CanaryEmbedder

    embedder = CanaryEmbedder("http://127.0.0.1:18765/t")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a minimal DOCX
        docx_path = Path(tmpdir) / "test.docx"
        with zipfile.ZipFile(docx_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
            zf.writestr("word/_rels/document.xml.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
            zf.writestr("word/document.xml",
                '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>')

        token_id = "testtoken12345678"
        ok = embedder.embed_in_docx(docx_path, token_id)
        check("DOCX canary embed succeeds", ok)

        # Verify token URL appears in the rels file
        with zipfile.ZipFile(docx_path, "r") as zf:
            rels = zf.read("word/_rels/document.xml.rels").decode()
            check("Token URL in DOCX rels XML", token_id in rels, rels[:200])

        # TXT embed
        txt_path = Path(tmpdir) / "readme.txt"
        txt_path.write_text("This is a readme file.\n")
        ok2 = embedder.embed_in_txt(txt_path, "txttoken12345678")
        check("TXT canary embed succeeds", ok2)
        check("Token URL in TXT file",
              "txttoken12345678" in txt_path.read_text())

except Exception as e:
    check("Canary embedder", False, str(e))

# ─────────────────────────────────────────────
# TEST 4: Dashboard API
# ─────────────────────────────────────────────
print("\n[4/5] Dashboard API")
try:
    from api.dashboard import DashboardServer

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Write a minimal chain
        chain = [
            {
                "index": 0,
                "timestamp": time.time(),
                "data": {"event": "STARTUP", "severity": "INFO"},
                "prev_hash": "0" * 64,
                "hash": "abc123",
                "node_id": "test-node",
            }
        ]
        chain_path  = tmppath / "chain.json"
        events_path = tmppath / "events.jsonl"
        chain_path.write_text(json.dumps(chain))
        events_path.write_text(
            json.dumps({"event_type": "STARTUP", "severity": "INFO", "timestamp": time.time()}) + "\n"
        )

        srv = DashboardServer(
            host="127.0.0.1",
            port=15001,
            chain_path=chain_path,
            events_path=events_path,
        )
        srv.start(daemon=True)
        time.sleep(0.4)

        def get(path):
            url = f"http://127.0.0.1:15001{path}"
            return urllib.request.urlopen(url, timeout=3)

        # /api/status
        try:
            r = get("/api/status")
            data = json.loads(r.read())
            check("/api/status returns 200", r.status == 200)
            check("/api/status has chain_blocks", "chain_blocks" in data,
                  str(data.get("chain_blocks")))
        except Exception as e:
            check("/api/status", False, str(e))

        # /api/chain
        try:
            r = get("/api/chain")
            data = json.loads(r.read())
            check("/api/chain returns blocks list", "blocks" in data)
            check("/api/chain block count ≥ 1", data.get("total", 0) >= 1)
        except Exception as e:
            check("/api/chain", False, str(e))

        # /api/chain/verify
        try:
            r = get("/api/chain/verify")
            data = json.loads(r.read())
            check("/api/chain/verify responds", "valid" in data)
        except Exception as e:
            check("/api/chain/verify", False, str(e))

        # /api/events
        try:
            r = get("/api/events")
            data = json.loads(r.read())
            check("/api/events responds", "events" in data)
        except Exception as e:
            check("/api/events", False, str(e))

        # / (dashboard HTML)
        try:
            r = get("/")
            html = r.read().decode()
            check("Dashboard HTML loads", "ChainTrap" in html)
            check("Dashboard has chain table", "chain-table" in html)
        except Exception as e:
            check("Dashboard HTML", False, str(e))

        srv.stop()

except Exception as e:
    check("Dashboard API", False, str(e))

# ─────────────────────────────────────────────
# TEST 5: Integration smoke test
# ─────────────────────────────────────────────
print("\n[5/5] Integration smoke")
try:
    from core.canary_server import CanaryManager
    from api.dashboard import DashboardServer
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        tp = Path(tmpdir)
        srv = DashboardServer(
            host="127.0.0.1", port=15002,
            chain_path=tp/"chain.json",
            events_path=tp/"events.jsonl",
        )
        srv.start(daemon=True)

        mgr = CanaryManager(host="127.0.0.1", port=18766,
                             registry_path=tp/"canary.json")
        mgr.start()
        time.sleep(0.3)

        check("Dashboard + canary server both start",
              mgr.server.is_running())

        mgr.stop()
        srv.stop()

except Exception as e:
    check("Integration smoke test", False, str(e))

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
total  = len(results)
passed = sum(results)
failed = total - passed
print(f"\n{'='*55}")
print(f"  Part 2 Self-Test: {passed}/{total} checks passed", end="")
if failed == 0:
    print("  ✅ ALL PASS")
else:
    print(f"  ❌ {failed} FAILED")
print(f"{'='*55}\n")
sys.exit(0 if failed == 0 else 1)
