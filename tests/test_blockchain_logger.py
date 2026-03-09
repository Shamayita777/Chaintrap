"""
ChainTrap v2 — tests/test_blockchain_logger.py

Unit tests for the tamper-evident dual-mode blockchain logger.

Tests:
  - Block creation and SHA-256 linkage
  - Chain verification (intact + tampered)
  - Genesis block properties
  - Concurrent writes (thread safety)
  - Chain serialization/deserialization
  - Webhook mode stub
"""

import os
import sys
import json
import time
import hashlib
import tempfile
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "config"))


# ─────────────────────────────────────────────
# Helpers to instantiate blockchain_logger with a temp chain file
# ─────────────────────────────────────────────

def make_fresh_logger(tmp_path: Path):
    """Import and configure blockchain_logger with isolated temp chain."""
    import importlib
    import core.blockchain_logger as bl

    chain_path = tmp_path / "test_chain.json"
    orig_path  = bl.CHAIN_FILE

    # Monkey-patch chain file path and reinitialize
    bl.CHAIN_FILE = chain_path
    bl._chain.clear()
    bl._chain_initialized = False
    bl.init_chain()

    return bl, chain_path, orig_path


# ─────────────────────────────────────────────
# TEST: Block structure
# ─────────────────────────────────────────────

class TestBlockStructure:

    def test_genesis_block_created(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            assert len(bl._chain) >= 1
            genesis = bl._chain[0]
            assert genesis["index"] == 0
            assert genesis["prev_hash"] == "0" * 64
            assert "hash" in genesis
            assert "timestamp" in genesis
        finally:
            bl.CHAIN_FILE = orig

    def test_block_has_required_fields(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            block = bl.add_block({"event": "TEST", "value": 42})
            for field in ("index", "timestamp", "data", "prev_hash", "hash", "node_id"):
                assert field in block, f"Block missing field: {field}"
        finally:
            bl.CHAIN_FILE = orig

    def test_block_index_increments(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            b1 = bl.add_block({"event": "A"})
            b2 = bl.add_block({"event": "B"})
            b3 = bl.add_block({"event": "C"})
            assert b1["index"] < b2["index"] < b3["index"]
        finally:
            bl.CHAIN_FILE = orig

    def test_prev_hash_linkage(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            b1 = bl.add_block({"event": "A"})
            b2 = bl.add_block({"event": "B"})
            assert b2["prev_hash"] == b1["hash"]
        finally:
            bl.CHAIN_FILE = orig

    def test_hash_is_sha256_hex(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            block = bl.add_block({"event": "TEST"})
            h = block["hash"]
            assert len(h) == 64
            assert all(c in "0123456789abcdef" for c in h)
        finally:
            bl.CHAIN_FILE = orig

    def test_hash_is_deterministic(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            block = bl.add_block({"event": "DETER"})
            # Recompute hash manually
            to_hash = {k: v for k, v in block.items() if k != "hash"}
            raw      = json.dumps(to_hash, sort_keys=True).encode()
            expected = hashlib.sha256(raw).hexdigest()
            assert block["hash"] == expected
        finally:
            bl.CHAIN_FILE = orig

    def test_timestamp_is_recent(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            t_before = time.time() - 1
            block = bl.add_block({"event": "T"})
            t_after  = time.time() + 1
            assert t_before <= block["timestamp"] <= t_after
        finally:
            bl.CHAIN_FILE = orig

    def test_data_payload_preserved(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            payload = {"event": "RANSOMWARE", "file": "/tmp/secret.docx",
                       "entropy": 7.9985, "score": 0.75, "nested": {"key": "val"}}
            block = bl.add_block(payload)
            assert block["data"] == payload
        finally:
            bl.CHAIN_FILE = orig


# ─────────────────────────────────────────────
# TEST: Chain verification
# ─────────────────────────────────────────────

class TestChainVerification:

    def test_intact_chain_verifies_ok(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            for i in range(5):
                bl.add_block({"event": f"EVT_{i}", "i": i})
            result = bl.verify_chain()
            assert result["ok"], f"Intact chain failed verification: {result}"
        finally:
            bl.CHAIN_FILE = orig

    def test_tampered_hash_detected(self, tmp_path):
        bl, chain_path, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event": "REAL_1"})
            bl.add_block({"event": "REAL_2"})
            bl.add_block({"event": "REAL_3"})

            # Tamper: change data in block 1 without updating hash
            chain_data = json.loads(chain_path.read_text())
            chain_data[1]["data"]["event"] = "TAMPERED"
            chain_path.write_text(json.dumps(chain_data))

            # Re-load and verify
            bl._chain.clear()
            bl._chain_initialized = False
            bl.init_chain()

            result = bl.verify_chain()
            assert not result["ok"], "Tampered chain should fail verification"
        finally:
            bl.CHAIN_FILE = orig

    def test_tampered_prev_hash_detected(self, tmp_path):
        bl, chain_path, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event": "A"})
            bl.add_block({"event": "B"})

            chain_data = json.loads(chain_path.read_text())
            chain_data[2]["prev_hash"] = "deadbeef" * 8
            chain_path.write_text(json.dumps(chain_data))

            bl._chain.clear()
            bl._chain_initialized = False
            bl.init_chain()

            result = bl.verify_chain()
            assert not result["ok"]
        finally:
            bl.CHAIN_FILE = orig

    def test_empty_chain_verifies(self, tmp_path):
        bl, chain_path, orig = make_fresh_logger(tmp_path)
        try:
            # Write an empty chain
            chain_path.write_text("[]")
            bl._chain.clear()
            bl._chain_initialized = False
            bl.init_chain()
            result = bl.verify_chain()
            # Should not crash; result may be ok=True (empty or genesis only)
            assert "ok" in result
        finally:
            bl.CHAIN_FILE = orig

    def test_verification_reports_block_count(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            for _ in range(3):
                bl.add_block({"event": "X"})
            result = bl.verify_chain()
            assert result.get("blocks_verified", 0) >= 1
        finally:
            bl.CHAIN_FILE = orig


# ─────────────────────────────────────────────
# TEST: Persistence
# ─────────────────────────────────────────────

class TestPersistence:

    def test_chain_saved_to_disk(self, tmp_path):
        bl, chain_path, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event": "PERSIST"})
            assert chain_path.exists()
            data = json.loads(chain_path.read_text())
            assert isinstance(data, list)
            assert len(data) >= 2  # genesis + new block
        finally:
            bl.CHAIN_FILE = orig

    def test_chain_reloaded_after_reinit(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event": "SAVED"})
            n_before = len(bl._chain)

            # Reinitialize from disk
            bl._chain.clear()
            bl._chain_initialized = False
            bl.init_chain()

            assert len(bl._chain) == n_before
        finally:
            bl.CHAIN_FILE = orig

    def test_chain_survives_multiple_sessions(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            for i in range(3):
                bl.add_block({"event": f"SESSION_1_{i}"})

            bl._chain.clear()
            bl._chain_initialized = False
            bl.init_chain()

            n_after_reload = len(bl._chain)
            bl.add_block({"event": "SESSION_2_0"})
            bl.add_block({"event": "SESSION_2_1"})

            assert len(bl._chain) == n_after_reload + 2
            result = bl.verify_chain()
            assert result["ok"]
        finally:
            bl.CHAIN_FILE = orig


# ─────────────────────────────────────────────
# TEST: Thread safety
# ─────────────────────────────────────────────

class TestThreadSafety:

    def test_concurrent_writes_no_data_loss(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            n_threads = 10
            events_per_thread = 5
            results = []
            errors  = []

            def writer(thread_id: int):
                try:
                    for j in range(events_per_thread):
                        b = bl.add_block({"thread": thread_id, "j": j})
                        results.append(b["index"])
                except Exception as e:
                    errors.append(str(e))

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(n_threads)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=10)

            assert len(errors) == 0, f"Thread errors: {errors}"
            # Total blocks = genesis + all writes
            expected = 1 + n_threads * events_per_thread
            assert len(bl._chain) == expected, \
                f"Expected {expected} blocks, got {len(bl._chain)}"

            result = bl.verify_chain()
            assert result["ok"], f"Chain broken after concurrent writes: {result}"
        finally:
            bl.CHAIN_FILE = orig

    def test_concurrent_reads_safe(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            for i in range(20):
                bl.add_block({"event": f"E{i}"})

            errors = []
            def reader():
                try:
                    for _ in range(10):
                        bl.verify_chain()
                        bl.get_chain_summary()
                except Exception as e:
                    errors.append(str(e))

            threads = [threading.Thread(target=reader) for _ in range(5)]
            for t in threads: t.start()
            for t in threads: t.join(timeout=5)
            assert len(errors) == 0
        finally:
            bl.CHAIN_FILE = orig


# ─────────────────────────────────────────────
# TEST: Chain summary
# ─────────────────────────────────────────────

class TestChainSummary:

    def test_summary_fields(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event": "RANSOMWARE", "file": "/x.docx"})
            summary = bl.get_chain_summary()
            assert "chain_length"  in summary
            assert "node_id"       in summary
            assert "chain_head_hash" in summary
        finally:
            bl.CHAIN_FILE = orig

    def test_ransomware_events_counted(self, tmp_path):
        bl, _, orig = make_fresh_logger(tmp_path)
        try:
            bl.add_block({"event_type": "RANSOMWARE_DETECTED"})
            bl.add_block({"event_type": "RANSOMWARE_DETECTED"})
            bl.add_block({"event_type": "STARTUP"})
            summary = bl.get_chain_summary()
            assert summary.get("ransomware_events", 0) >= 2
        finally:
            bl.CHAIN_FILE = orig
