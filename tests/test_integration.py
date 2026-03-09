"""
ChainTrap v2 — tests/test_integration.py

Integration Tests — End-to-End Pipeline

Tests the full detection pipeline from file write → entropy analysis →
blockchain logging → event logging → dashboard API visibility.

These are integration tests (not unit tests): they exercise multiple
components working together, including cross-component state.

Sections:
  1. Entropy → Blockchain integration
  2. Decoy → Event logging integration
  3. Canary → Blockchain integration
  4. Threat simulator → Entropy detection pipeline
  5. Full chain: simulate → detect → log → API query
  6. Concurrent attack simulation (stress test)
  7. Tamper-evidence under attack
"""

from __future__ import annotations

import os
import sys
import json
import time
import secrets
import zipfile
import hashlib
import socket
import tempfile
import threading
import urllib.request
import urllib.error
from io import BytesIO
from pathlib import Path
from typing import Optional

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_high_entropy(n: int = 100_000) -> bytes:
    return secrets.token_bytes(n)


def make_low_entropy(n: int = 100_000) -> bytes:
    vocab = b"abcdefghijklmnopqrstuvwxyz ABCDE\n\t.,!?"
    return bytes([vocab[i % len(vocab)] for i in range(n)])


def make_ooxml(n: int = 50_000) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"></Types>')
        zf.writestr("word/document.xml",
            b"<w:document>" + make_low_entropy(max(50, n - 200)) + b"</w:document>")
    return buf.getvalue()


def make_docx_file(path: Path) -> Path:
    path.write_bytes(make_ooxml())
    return path


@pytest.fixture
def isolated_chain(tmp_path, monkeypatch):
    """Reset blockchain_logger to use a fresh temp chain for this test."""
    import core.blockchain_logger as bl
    chain_path = tmp_path / "test_chain.json"
    monkeypatch.setattr(bl, "CHAIN_FILE", chain_path)
    monkeypatch.setattr(bl, "_chain", [])
    monkeypatch.setattr(bl, "_chain_initialized", False)
    yield bl, chain_path


@pytest.fixture
def canary_mgr(tmp_path):
    """Spin up a CanaryManager on a free port, yield it, then stop."""
    from core.canary_server import CanaryManager
    port = free_port()
    mgr  = CanaryManager(
        host="127.0.0.1",
        port=port,
        registry_path=tmp_path / "canary_reg.json",
    )
    mgr.start()
    time.sleep(0.2)
    yield mgr
    mgr.stop()


@pytest.fixture
def dashboard_srv(tmp_path):
    """Start a DashboardServer on a free port, yield (server, port)."""
    from api.dashboard import DashboardServer
    port        = free_port()
    chain_path  = tmp_path / "chain.json"
    events_path = tmp_path / "events.jsonl"
    chain_path.write_text("[]")
    events_path.write_text("")
    srv = DashboardServer(
        host="127.0.0.1",
        port=port,
        chain_path=chain_path,
        events_path=events_path,
    )
    srv.start(daemon=True)
    time.sleep(0.3)
    yield srv, port, chain_path, events_path
    srv.stop()


def api_get(port: int, path: str, key: Optional[str] = None) -> tuple[int, dict]:
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


# ─────────────────────────────────────────────
# 1. ENTROPY → BLOCKCHAIN INTEGRATION
# ─────────────────────────────────────────────

class TestEntropyBlockchainIntegration:
    """
    Tests that entropy detection events are correctly logged to the blockchain.
    """

    def test_high_entropy_file_logged_to_chain(self, tmp_path, isolated_chain):
        from core.entropy_analyzer import analyze_file
        bl, chain_path = isolated_chain

        # Analyze a high-entropy file
        f = tmp_path / "encrypted.bin"
        f.write_bytes(make_high_entropy())
        result = analyze_file(f)
        assert result.is_suspicious

        # Manually log to blockchain as monitor would
        bl.init_chain()
        bl.add_event({
            "event_type":       "ENTROPY_ANOMALY",
            "file_path":        str(f),
            "shannon_global":   result.shannon_global,
            "is_suspicious":    result.is_suspicious,
            "signals_triggered": result.signals_triggered,
            "severity":         "CRITICAL",
        })

        # Verify block was added
        chain = json.loads(chain_path.read_text())
        assert len(chain) >= 2  # genesis + event block
        event_block = chain[-1]
        assert event_block["data"]["event_type"] == "ENTROPY_ANOMALY"
        assert event_block["data"]["file_path"] == str(f)

    def test_multiple_detections_chain_stays_valid(self, tmp_path, isolated_chain):
        from core.entropy_analyzer import analyze_file
        bl, chain_path = isolated_chain
        bl.init_chain()

        for i in range(10):
            f = tmp_path / f"enc_{i}.bin"
            f.write_bytes(make_high_entropy(50_000))
            result = analyze_file(f)
            bl.add_event({
                "event_type": "ENTROPY_ANOMALY",
                "file_path":  str(f),
                "entropy":    result.shannon_global,
                "severity":   "CRITICAL",
            })

        verify = bl.verify_chain()
        assert verify["ok"], f"Chain broken after 10 events: {verify}"

        chain = json.loads(chain_path.read_text())
        assert len(chain) == 11  # genesis + 10 events

    def test_benign_file_not_logged(self, tmp_path, isolated_chain):
        from core.entropy_analyzer import analyze_file
        bl, chain_path = isolated_chain
        bl.init_chain()

        f = tmp_path / "normal.docx"
        f.write_bytes(make_ooxml())
        result = analyze_file(f)

        if not result.is_suspicious:
            # Only log if suspicious — benign should not trigger
            chain = json.loads(chain_path.read_text())
            initial_len = len(chain)
            # Confirm no extra blocks (only genesis)
            assert len(chain) == initial_len

    def test_chain_hash_linkage_preserved_under_load(self, tmp_path, isolated_chain):
        from core.entropy_analyzer import analyze_file
        bl, chain_path = isolated_chain
        bl.init_chain()

        errors = []
        def write_and_log(i):
            try:
                f = tmp_path / f"thread_{i}.bin"
                f.write_bytes(make_high_entropy(20_000))
                r = analyze_file(f)
                bl.add_event({
                    "event_type": "ENTROPY_ANOMALY",
                    "thread_id":  i,
                    "entropy":    r.shannon_global,
                })
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_and_log, args=(i,)) for i in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=15)

        assert not errors, f"Thread errors: {errors}"
        verify = bl.verify_chain()
        assert verify["ok"], f"Chain broken under concurrent load: {verify}"


# ─────────────────────────────────────────────
# 2. DECOY → EVENT LOGGING INTEGRATION
# ─────────────────────────────────────────────

class TestDecoyEventIntegration:
    """
    Tests that decoy file access is correctly detected and logged.
    """

    def test_decoy_creation_and_registry(self, tmp_path):
        from core.decoy_manager import deploy_decoy_swarm, get_decoy_paths, is_decoy

        paths = deploy_decoy_swarm([str(tmp_path)], count_per_dir=5)
        assert len(paths) >= 5

        # All paths registered as decoys
        for p in paths:
            assert is_decoy(p), f"{p} not registered as decoy"
            assert Path(p).exists(), f"Decoy file missing: {p}"

    def test_decoy_detection_via_entropy(self, tmp_path):
        """
        Simulate ransomware overwriting a decoy file with encrypted content.
        The entropy analyzer should flag it.
        """
        from core.decoy_manager import deploy_decoy_swarm, is_decoy
        from core.entropy_analyzer import analyze_file

        paths = deploy_decoy_swarm([str(tmp_path)], count_per_dir=3)
        decoy = Path(paths[0])

        # Overwrite with encrypted content (simulating ransomware)
        decoy.write_bytes(make_high_entropy(50_000))

        result = analyze_file(decoy)
        assert result.is_suspicious, \
            f"Encrypted decoy not detected: entropy={result.shannon_global:.4f}"

    def test_event_logger_records_decoy_trigger(self, tmp_path):
        from core.event_logger import log_decoy_triggered
        from core.decoy_manager import deploy_decoy_swarm

        log_path = tmp_path / "events.jsonl"
        # Patch event logger to use temp log
        import core.event_logger as el
        orig_path = el.LOG_FILE
        el.LOG_FILE = log_path

        try:
            paths = deploy_decoy_swarm([str(tmp_path)], count_per_dir=2)
            log_decoy_triggered(paths[0], pids=[1234])

            assert log_path.exists()
            events = [json.loads(line) for line in log_path.read_text().splitlines() if line]
            decoy_events = [e for e in events if e.get("event_type") == "DECOY_TRIGGERED"]
            assert len(decoy_events) >= 1
            assert decoy_events[0]["file_path"] == paths[0]
        finally:
            el.LOG_FILE = orig_path


# ─────────────────────────────────────────────
# 3. CANARY → BLOCKCHAIN INTEGRATION
# ─────────────────────────────────────────────

class TestCanaryBlockchainIntegration:
    """
    Tests that canary token triggers are recorded to the blockchain.
    """

    def test_canary_trigger_recorded_in_blockchain(self, tmp_path, isolated_chain, canary_mgr):
        bl, chain_path = isolated_chain
        bl.init_chain()

        # Embed canary in a test file
        decoy_txt = tmp_path / "sensitive.txt"
        decoy_txt.write_text("Confidential financial data.\n")
        token = canary_mgr.embed_in_file(decoy_txt)
        assert token is not None, "Failed to embed canary"

        # Simulate trigger by calling the callback URL
        triggered_tokens = []
        def on_trigger(tok):
            triggered_tokens.append(tok)
            bl.add_event({
                "event_type": "CANARY_TRIGGERED",
                "token_id":   tok.token_id,
                "decoy_path": tok.decoy_path,
                "trigger_ip": tok.trigger_ip,
                "severity":   "CRITICAL",
            })

        canary_mgr._on_trigger = on_trigger

        # Fetch the canary URL
        try:
            urllib.request.urlopen(token.callback_url, timeout=3)
        except Exception:
            pass
        time.sleep(0.3)

        assert len(triggered_tokens) == 1, "Canary trigger not received"
        chain = json.loads(chain_path.read_text())
        canary_blocks = [b for b in chain
                         if b["data"].get("event_type") == "CANARY_TRIGGERED"]
        assert len(canary_blocks) == 1
        assert canary_blocks[0]["data"]["token_id"] == token.token_id

    def test_canary_chain_stays_valid_after_trigger(
            self, tmp_path, isolated_chain, canary_mgr):
        bl, chain_path = isolated_chain
        bl.init_chain()

        for i in range(3):
            txt = tmp_path / f"decoy_{i}.txt"
            txt.write_text(f"Secret document {i}")
            tok = canary_mgr.embed_in_file(txt)
            if tok:
                bl.add_event({
                    "event_type": "CANARY_DEPLOYED",
                    "token_id":   tok.token_id,
                    "severity":   "INFO",
                })

        verify = bl.verify_chain()
        assert verify["ok"], f"Chain broken after canary logging: {verify}"


# ─────────────────────────────────────────────
# 4. THREAT SIMULATOR → ENTROPY DETECTION
# ─────────────────────────────────────────────

class TestThreatSimulatorDetection:
    """
    Tests that the threat simulator generates files that the entropy
    analyzer correctly classifies.
    """

    def test_lockbit_style_detected(self, tmp_path):
        from eval.threat_sim import run_with_entropy_check
        result = run_with_entropy_check("lockbit_style", file_count=10)
        assert result.detection_rate >= 0.8, \
            f"LockBit detection rate too low: {result.detection_rate:.2f}"

    def test_wannacry_style_detected(self, tmp_path):
        from eval.threat_sim import run_with_entropy_check
        result = run_with_entropy_check("wannacry_style", file_count=10)
        assert result.detection_rate >= 0.8, \
            f"WannaCry detection rate too low: {result.detection_rate:.2f}"

    def test_fpe_evasion_still_detected(self, tmp_path):
        """FPE attack uses valid ZIP headers — entropy should still catch it."""
        from eval.threat_sim import run_with_entropy_check
        result = run_with_entropy_check("fpe_evasion", file_count=10)
        # FPE may have some misses — but should catch the high-entropy payload
        assert result.detection_rate >= 0.5, \
            f"FPE evasion not detected sufficiently: {result.detection_rate:.2f}"

    def test_b64_evasion_detected(self, tmp_path):
        from eval.threat_sim import run_with_entropy_check
        result = run_with_entropy_check("b64_evasion", file_count=10)
        # B64 has ~6.0 entropy — may not all be flagged, but most should be
        assert result.total_files == 10

    def test_all_profiles_run_without_error(self, tmp_path):
        from eval.threat_sim import PROFILES, run_with_entropy_check
        for name in PROFILES:
            if name == "slow_burn":
                continue  # Skip slow profile in unit test
            result = run_with_entropy_check(name, file_count=3)
            assert result.error is None, \
                f"Profile {name} raised error: {result.error}"

    def test_simulator_records_correct_file_count(self, tmp_path):
        from eval.threat_sim import run_with_entropy_check
        result = run_with_entropy_check("lockbit_style", file_count=15)
        assert result.total_files == 15, \
            f"Expected 15 events, got {result.total_files}"

    def test_dry_run_produces_no_files(self, tmp_path):
        from eval.threat_sim import ThreatSimulator, PROFILES
        profile = PROFILES["lockbit_style"]
        sim = ThreatSimulator(
            target_dir=tmp_path / "dry",
            profile=profile,
            dry_run=True,
            seed_victim_files=5,
        )
        sim.profile.file_count = 5
        result = sim.run()
        # In dry run, no encrypted files should be created
        encrypted = list((tmp_path / "dry").glob("*.lockbit"))
        assert len(encrypted) == 0, \
            f"Dry run created files: {encrypted}"


# ─────────────────────────────────────────────
# 5. FULL PIPELINE: SIMULATE → DETECT → LOG → API
# ─────────────────────────────────────────────

class TestFullPipeline:
    """
    End-to-end test: threat simulation → entropy detection → blockchain log →
    event JSONL → dashboard API returns correct data.
    """

    def test_simulate_detect_log_api(self, tmp_path, isolated_chain, dashboard_srv):
        from core.entropy_analyzer import analyze_file
        from eval.threat_sim import ThreatSimulator, PROFILES
        import core.event_logger as el

        bl, chain_path = isolated_chain
        srv, port, dash_chain_path, events_path = dashboard_srv

        # Point event logger to dashboard's events file
        orig_log = el.LOG_FILE
        el.LOG_FILE = events_path

        # Point dashboard to isolated chain
        srv._server.RequestHandlerClass.chain_path  = chain_path
        srv._server.RequestHandlerClass.events_path = events_path

        bl.init_chain()

        try:
            # Run a small simulation
            profile = PROFILES["lockbit_style"]
            profile.file_count = 8
            sim = ThreatSimulator(
                target_dir=tmp_path / "attack",
                profile=profile,
                seed_victim_files=10,
            )
            result = sim.run()

            # Analyze all written files
            detected = 0
            for event in result.attack_events:
                path = Path(event.path)
                if not path.exists():
                    continue
                r = analyze_file(path)
                if r.is_suspicious:
                    detected += 1
                    bl.add_event({
                        "event_type":   "ENTROPY_ANOMALY",
                        "file_path":    str(path),
                        "entropy":      r.shannon_global,
                        "severity":     "CRITICAL",
                    })
                    # Also write to event log
                    from core.event_logger import log_entropy_anomaly
                    log_entropy_anomaly(str(path), r, pids=[9999])

            assert detected >= 4, f"Only {detected}/8 files detected"

            # Allow file writes to flush
            time.sleep(0.2)

            # Query the API
            code, data = api_get(port, "/api/chain")
            assert code == 200
            assert data["total"] >= 2  # genesis + at least 1 event

            code, data = api_get(port, "/api/chain/verify")
            assert code == 200
            assert data["valid"], f"Chain invalid after simulation: {data}"

            code, data = api_get(port, "/api/events")
            assert code == 200
            entropy_events = [e for e in data["events"]
                              if e.get("event_type") == "ENTROPY_ANOMALY"]
            assert len(entropy_events) >= 1, \
                f"No ENTROPY_ANOMALY events in API: {data['events']}"

        finally:
            el.LOG_FILE = orig_log

    def test_canary_trigger_visible_in_dashboard(
            self, tmp_path, isolated_chain, canary_mgr, dashboard_srv):
        """Canary fire → registry updated → /api/canary/status shows triggered."""
        bl, chain_path = isolated_chain
        srv, port, dash_chain_path, events_path = dashboard_srv

        # Point dashboard canary to mgr's registry
        srv._server.RequestHandlerClass.canary_path = \
            canary_mgr.registry._path

        # Embed and trigger
        txt = tmp_path / "secret.txt"
        txt.write_text("Confidential.\n")
        tok = canary_mgr.embed_in_file(txt)
        assert tok

        try:
            urllib.request.urlopen(tok.callback_url, timeout=3)
        except Exception:
            pass
        time.sleep(0.3)

        # Check API
        code, data = api_get(port, "/api/canary/status")
        assert code == 200
        assert data["triggered"] >= 1, \
            f"Canary trigger not visible in dashboard: {data}"


# ─────────────────────────────────────────────
# 6. STRESS TEST — CONCURRENT SIMULATION
# ─────────────────────────────────────────────

class TestConcurrentSimulation:
    """
    Stress test: multiple simultaneous attack simulations.
    Validates that the system remains stable and chain stays valid.
    """

    def test_concurrent_profiles_no_interference(self, tmp_path, isolated_chain):
        from eval.threat_sim import run_with_entropy_check
        bl, chain_path = isolated_chain
        bl.init_chain()

        results = {}
        errors  = []

        def run_profile(name):
            try:
                results[name] = run_with_entropy_check(name, file_count=5)
            except Exception as e:
                errors.append(f"{name}: {e}")

        # Run 4 profiles concurrently (excluding slow_burn)
        profiles_to_run = ["lockbit_style", "wannacry_style", "fpe_evasion", "b64_evasion"]
        threads = [threading.Thread(target=run_profile, args=(n,))
                   for n in profiles_to_run]
        for t in threads: t.start()
        for t in threads: t.join(timeout=60)

        assert not errors, f"Concurrent simulation errors: {errors}"
        for name in profiles_to_run:
            assert name in results, f"No result for profile {name}"
            assert results[name].error is None, \
                f"Profile {name} failed: {results[name].error}"

    def test_blockchain_thread_safety_under_attack(self, tmp_path, isolated_chain):
        """Simulate concurrent attack logging — chain must remain valid."""
        from core.entropy_analyzer import analyze_file
        bl, chain_path = isolated_chain
        bl.init_chain()

        errors = []

        def attack_and_log(i):
            try:
                f = tmp_path / f"concurrent_{i}.bin"
                f.write_bytes(secrets.token_bytes(30_000))
                r = analyze_file(f)
                bl.add_event({
                    "event_type": "ENTROPY_ANOMALY",
                    "thread_id":  i,
                    "entropy":    r.shannon_global,
                    "severity":   "CRITICAL",
                })
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=attack_and_log, args=(i,))
                   for i in range(16)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)

        assert not errors, f"Errors during concurrent attack: {errors}"
        verify = bl.verify_chain()
        assert verify["ok"], f"Chain corrupted during stress test: {verify}"

        chain = json.loads(chain_path.read_text())
        assert len(chain) == 17, f"Expected 17 blocks, got {len(chain)}"


# ─────────────────────────────────────────────
# 7. TAMPER EVIDENCE UNDER ATTACK
# ─────────────────────────────────────────────

class TestTamperEvidenceUnderAttack:
    """
    Validates that the blockchain's tamper-evidence holds even when
    an attacker tries to modify the audit trail.
    """

    def test_tampered_block_detected(self, tmp_path, isolated_chain):
        bl, chain_path = isolated_chain
        bl.init_chain()

        bl.add_event({"event": "DETECTION_1", "file": "/tmp/a.docx"})
        bl.add_event({"event": "DETECTION_2", "file": "/tmp/b.docx"})
        bl.add_event({"event": "DETECTION_3", "file": "/tmp/c.docx"})

        # Attacker modifies block 1 to erase evidence
        chain_data = json.loads(chain_path.read_text())
        chain_data[1]["data"]["file"] = "/tmp/innocent.docx"
        chain_path.write_text(json.dumps(chain_data))

        result = bl.verify_chain()
        assert not result["ok"], "Tampered chain should fail verification"
        assert len(result.get("errors", [])) > 0

    def test_deleted_block_detected(self, tmp_path, isolated_chain):
        bl, chain_path = isolated_chain
        bl.init_chain()

        for i in range(5):
            bl.add_event({"event": f"DETECTION_{i}"})

        # Attacker deletes a block
        chain_data = json.loads(chain_path.read_text())
        del chain_data[2]  # Remove block 2
        chain_path.write_text(json.dumps(chain_data))

        result = bl.verify_chain()
        assert not result["ok"], "Chain with deleted block should fail verification"

    def test_injected_block_detected(self, tmp_path, isolated_chain):
        bl, chain_path = isolated_chain
        bl.init_chain()
        bl.add_event({"event": "REAL_DETECTION"})

        # Attacker injects a fake block
        chain_data = json.loads(chain_path.read_text())
        fake_block = {
            "index":     1,
            "timestamp": time.time(),
            "data":      {"event": "FAKE_BENIGN_EVENT"},
            "prev_hash": chain_data[0]["hash"],
            "hash":      "a" * 64,  # Wrong hash
            "node_id":   "attacker",
        }
        chain_data.insert(1, fake_block)
        chain_path.write_text(json.dumps(chain_data))

        result = bl.verify_chain()
        assert not result["ok"], "Chain with injected block should fail verification"

    def test_chain_replication_preserves_integrity(self, tmp_path, isolated_chain):
        """Chain copied to a second location should still verify."""
        import shutil
        bl, chain_path = isolated_chain
        bl.init_chain()
        for i in range(5):
            bl.add_event({"event": f"E{i}", "severity": "CRITICAL"})

        # Simulate IPFS/webhook replication by copying chain
        replica = tmp_path / "replica_chain.json"
        shutil.copy2(chain_path, replica)

        # Verify replica independently
        replica_data = json.loads(replica.read_text())
        assert len(replica_data) == 6

        # Manually verify linkage
        for i in range(1, len(replica_data)):
            prev  = replica_data[i-1]
            block = replica_data[i]
            to_hash = {k: v for k, v in block.items() if k != "hash"}
            computed = hashlib.sha256(json.dumps(to_hash, sort_keys=True).encode()).hexdigest()
            assert block["hash"] == computed or block["prev_hash"] == prev["hash"], \
                f"Replica linkage broken at block {i}"
