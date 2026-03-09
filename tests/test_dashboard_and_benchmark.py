"""
ChainTrap v2 — tests/test_dashboard_and_benchmark.py

Tests for:
  - REST API dashboard: all endpoints, auth, pagination
  - Benchmark framework: profile outputs, metrics, serialization
"""

import os
import sys
import json
import time
import socket
import tempfile
import threading
import urllib.request
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "config"))

from api.dashboard import DashboardServer
from eval.benchmark import (
    BenchmarkEngine, BenchmarkResult, DetectionEvent,
    run_all_benchmarks, ALL_PROFILES,
    make_high_entropy, make_low_entropy,
)


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def api_get(port: int, path: str, api_key: str = None) -> tuple[int, dict]:
    url = f"http://127.0.0.1:{port}{path}"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def dashboard(tmp_path):
    """Start a dashboard server with minimal test data."""
    port = get_free_port()

    chain = [
        {"index": 0, "timestamp": time.time() - 100,
         "data": {"event": "STARTUP", "severity": "INFO"},
         "prev_hash": "0"*64, "hash": "genesis_hash_001", "node_id": "test"},
        {"index": 1, "timestamp": time.time() - 50,
         "data": {"event_type": "RANSOMWARE_DETECTED", "severity": "CRITICAL",
                  "file_path": "/tmp/victim.docx"},
         "prev_hash": "genesis_hash_001", "hash": "block_1_hash_xyz", "node_id": "test"},
    ]
    events = [
        {"event_type": "STARTUP", "severity": "INFO", "timestamp": time.time() - 100},
        {"event_type": "ENTROPY_ANOMALY", "severity": "CRITICAL",
         "file_path": "/tmp/victim.docx", "score": 0.95, "timestamp": time.time() - 50},
    ]

    chain_path  = tmp_path / "chain.json"
    events_path = tmp_path / "events.jsonl"
    chain_path.write_text(json.dumps(chain))
    events_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")

    srv = DashboardServer(
        host="127.0.0.1", port=port,
        chain_path=chain_path,
        events_path=events_path,
    )
    srv.start(daemon=True)
    time.sleep(0.3)

    yield port, tmp_path, srv

    srv.stop()


@pytest.fixture
def authed_dashboard(tmp_path):
    """Dashboard with API key auth enabled."""
    port    = get_free_port()
    api_key = "test-secret-key-12345"

    chain_path  = tmp_path / "chain.json"
    events_path = tmp_path / "events.jsonl"
    chain_path.write_text("[]")
    events_path.write_text("")

    srv = DashboardServer(
        host="127.0.0.1", port=port,
        chain_path=chain_path,
        events_path=events_path,
        api_key=api_key,
    )
    srv.start(daemon=True)
    time.sleep(0.3)

    yield port, api_key, srv

    srv.stop()


# ─────────────────────────────────────────────
# DASHBOARD: /api/status
# ─────────────────────────────────────────────

class TestDashboardStatus:

    def test_status_returns_200(self, dashboard):
        port, _, _ = dashboard
        code, data = api_get(port, "/api/status")
        assert code == 200

    def test_status_has_version(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/status")
        assert "version" in data

    def test_status_has_chain_blocks(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/status")
        assert "chain_blocks" in data
        assert data["chain_blocks"] >= 2

    def test_status_has_timestamp(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/status")
        assert "timestamp" in data


# ─────────────────────────────────────────────
# DASHBOARD: /api/chain
# ─────────────────────────────────────────────

class TestDashboardChain:

    def test_chain_returns_200(self, dashboard):
        port, _, _ = dashboard
        code, _ = api_get(port, "/api/chain")
        assert code == 200

    def test_chain_has_blocks(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/chain")
        assert "blocks" in data
        assert "total" in data
        assert data["total"] >= 2

    def test_chain_pagination_default(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/chain")
        assert "page" in data
        assert "limit" in data
        assert data["page"] == 1

    def test_chain_pagination_limit(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/chain?limit=1")
        assert len(data["blocks"]) <= 1

    def test_chain_single_block(self, dashboard):
        port, _, _ = dashboard
        code, data = api_get(port, "/api/chain/0")
        assert code == 200
        assert data["index"] == 0

    def test_chain_block_out_of_range(self, dashboard):
        port, _, _ = dashboard
        code, _ = api_get(port, "/api/chain/9999")
        assert code == 404

    def test_chain_verify_intact(self, dashboard):
        port, _, _ = dashboard
        code, data = api_get(port, "/api/chain/verify")
        assert code == 200
        assert "valid" in data

    def test_chain_verify_tampered(self, tmp_path):
        port = get_free_port()
        # Write a tampered chain (prev_hash broken)
        chain = [
            {"index": 0, "timestamp": time.time(),
             "data": {}, "prev_hash": "0"*64, "hash": "aaa", "node_id": "x"},
            {"index": 1, "timestamp": time.time(),
             "data": {}, "prev_hash": "WRONG_PREV", "hash": "bbb", "node_id": "x"},
        ]
        chain_path  = tmp_path / "tampered.json"
        events_path = tmp_path / "events.jsonl"
        chain_path.write_text(json.dumps(chain))
        events_path.write_text("")

        srv = DashboardServer(host="127.0.0.1", port=port,
                              chain_path=chain_path, events_path=events_path)
        srv.start(daemon=True)
        time.sleep(0.3)

        _, data = api_get(port, "/api/chain/verify")
        assert data["valid"] == False

        srv.stop()


# ─────────────────────────────────────────────
# DASHBOARD: /api/events
# ─────────────────────────────────────────────

class TestDashboardEvents:

    def test_events_returns_200(self, dashboard):
        port, _, _ = dashboard
        code, _ = api_get(port, "/api/events")
        assert code == 200

    def test_events_has_list(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/events")
        assert "events" in data
        assert isinstance(data["events"], list)

    def test_events_total_correct(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/events")
        assert data["total"] == 2

    def test_events_filter_by_severity(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/events?severity=CRITICAL")
        for ev in data["events"]:
            assert ev["severity"] == "CRITICAL"

    def test_events_filter_by_type(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/events?type=STARTUP")
        for ev in data["events"]:
            assert ev["event_type"] == "STARTUP"

    def test_events_pagination(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/events?limit=1")
        assert len(data["events"]) <= 1


# ─────────────────────────────────────────────
# DASHBOARD: /api/canary/status
# ─────────────────────────────────────────────

class TestDashboardCanary:

    def test_canary_endpoint_200(self, dashboard):
        port, _, _ = dashboard
        code, _ = api_get(port, "/api/canary/status")
        assert code == 200

    def test_canary_has_total_tokens(self, dashboard):
        port, _, _ = dashboard
        _, data = api_get(port, "/api/canary/status")
        assert "total_tokens" in data


# ─────────────────────────────────────────────
# DASHBOARD: HTML
# ─────────────────────────────────────────────

class TestDashboardHTML:

    def test_root_returns_html(self, dashboard):
        port, _, _ = dashboard
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        assert resp.status == 200
        assert "text/html" in resp.headers.get("Content-Type", "")

    def test_html_contains_chaintrap(self, dashboard):
        port, _, _ = dashboard
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()
        assert "ChainTrap" in html

    def test_404_for_unknown_path(self, dashboard):
        port, _, _ = dashboard
        code, _ = api_get(port, "/api/nonexistent")
        assert code == 404


# ─────────────────────────────────────────────
# DASHBOARD: Auth
# ─────────────────────────────────────────────

class TestDashboardAuth:

    def test_no_auth_rejects_chain(self, authed_dashboard):
        port, key, _ = authed_dashboard
        code, data = api_get(port, "/api/chain")   # No key
        assert code == 401

    def test_correct_key_grants_access(self, authed_dashboard):
        port, key, _ = authed_dashboard
        code, _ = api_get(port, "/api/chain", api_key=key)
        assert code == 200

    def test_wrong_key_rejected(self, authed_dashboard):
        port, key, _ = authed_dashboard
        code, _ = api_get(port, "/api/chain", api_key="wrong-key")
        assert code == 401

    def test_status_no_auth_required(self, authed_dashboard):
        """Status endpoint is always public (monitoring tools need it)."""
        port, _, _ = authed_dashboard
        code, _ = api_get(port, "/api/status")
        assert code == 200

    def test_html_no_auth_required(self, authed_dashboard):
        port, _, _ = authed_dashboard
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
        assert resp.status == 200


# ─────────────────────────────────────────────
# BENCHMARK: DetectionEvent and BenchmarkResult
# ─────────────────────────────────────────────

class TestBenchmarkDataClasses:

    def test_true_positive(self):
        ev = DetectionEvent("id", "prof", "/f", True, True, 5.0, 7.9, 0.8)
        assert ev.true_positive
        assert not ev.false_positive
        assert not ev.false_negative
        assert not ev.true_negative

    def test_false_positive(self):
        ev = DetectionEvent("id", "prof", "/f", False, True, 5.0, 7.9, 0.8)
        assert ev.false_positive
        assert not ev.true_positive

    def test_false_negative(self):
        ev = DetectionEvent("id", "prof", "/f", True, False, 5.0, 3.0, 0.1)
        assert ev.false_negative
        assert not ev.true_positive

    def test_benchmark_result_precision(self):
        r = BenchmarkResult("test", 10)
        r.true_positives = 8
        r.false_positives = 2
        assert r.precision == pytest.approx(0.8)

    def test_benchmark_result_recall(self):
        r = BenchmarkResult("test", 10)
        r.true_positives = 7
        r.false_negatives = 3
        assert r.recall == pytest.approx(0.7)

    def test_benchmark_result_f1(self):
        r = BenchmarkResult("test", 10)
        r.true_positives = 8
        r.false_positives = 2
        r.false_negatives = 2
        p, rec = 8/10, 8/10
        expected_f1 = 2 * p * rec / (p + rec)
        assert r.f1 == pytest.approx(expected_f1)

    def test_f1_zero_when_no_tp(self):
        r = BenchmarkResult("test", 10)
        r.false_negatives = 10
        assert r.f1 == 0.0

    def test_precision_zero_when_no_tp(self):
        r = BenchmarkResult("test", 10)
        r.false_positives = 5
        assert r.precision == 0.0

    def test_latency_percentiles(self):
        r = BenchmarkResult("test", 100)
        r.latencies_ms = list(range(1, 101))  # 1..100ms
        assert r.median_latency_ms == pytest.approx(50.5, abs=1.0)
        assert r.p95_latency_ms >= 95

    def test_summary_dict_keys(self):
        r = BenchmarkResult("test_profile", 50)
        r.true_positives = 45
        r.false_negatives = 5
        r.latencies_ms = [10.0, 20.0, 30.0]
        d = r.summary_dict()
        for key in ("profile", "n_trials", "precision", "recall", "f1",
                    "fpr", "fnr", "latency_median_ms", "latency_p95_ms"):
            assert key in d, f"Missing key in summary_dict: {key}"


# ─────────────────────────────────────────────
# BENCHMARK: Engine
# ─────────────────────────────────────────────

class TestBenchmarkEngine:

    def test_benign_profile_correct_count(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        r = engine.run_benign_profile(n=5)
        assert r.n_trials == 5
        assert r.true_negatives + r.false_positives == 5

    def test_ransomware_fast_profile(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        r = engine.run_ransomware_profile("ransomware_fast", n=5)
        assert r.n_trials == 5
        assert r.true_positives + r.false_negatives == 5

    def test_all_profiles_runnable(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        for profile in ["ransomware_fast", "ransomware_b64", "ransomware_fpe",
                        "ransomware_partial"]:
            r = engine.run_ransomware_profile(profile, n=3)
            assert r.n_trials == 3

    def test_latencies_populated(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        r = engine.run_ransomware_profile("ransomware_fast", n=5)
        assert len(r.latencies_ms) == 5
        assert all(l >= 0 for l in r.latencies_ms)

    def test_events_populated(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        r = engine.run_ransomware_profile("ransomware_fast", n=3)
        assert len(r.events) == 3

    def test_throughput_measurement(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        tps = engine.measure_throughput(duration_s=2.0)
        assert tps >= 1.0, f"Throughput too low: {tps}"

    def test_unknown_profile_raises(self, tmp_path):
        engine = BenchmarkEngine(tmp_path / "bench")
        with pytest.raises(ValueError):
            engine.run_ransomware_profile("nonexistent_profile", n=1)

    @pytest.mark.timeout(30)
    def test_run_all_quick(self, tmp_path):
        """Quick all-profile run with minimal n."""
        report = run_all_benchmarks(
            profiles=["benign_office", "ransomware_fast"],
            n_benign=5,
            n_malicious=5,
            verbose=False,
        )
        assert "meta" in report
        assert "results" in report
        assert len(report["results"]) == 2

    def test_report_saved_to_file(self, tmp_path):
        output = tmp_path / "results" / "bench.json"
        run_all_benchmarks(
            profiles=["ransomware_fast"],
            n_benign=3, n_malicious=3,
            output=output,
        )
        assert output.exists()
        data = json.loads(output.read_text())
        assert "results" in data

    def test_report_has_meta(self, tmp_path):
        report = run_all_benchmarks(
            profiles=["ransomware_fast"],
            n_benign=2, n_malicious=2,
        )
        meta = report["meta"]
        assert "chaintrap_version" in meta
        assert "timestamp" in meta
        assert "throughput_eps" in meta


# ─────────────────────────────────────────────
# BENCHMARK: File generators
# ─────────────────────────────────────────────

class TestFileGenerators:

    def test_high_entropy_is_random(self):
        data = make_high_entropy(100_000)
        assert len(data) == 100_000
        # Check entropy manually
        from collections import Counter
        import math
        counts = Counter(data)
        entropy = -sum((c/len(data)) * math.log2(c/len(data))
                       for c in counts.values())
        assert entropy > 7.5, f"High entropy bytes too low: {entropy}"

    def test_low_entropy_is_text(self):
        data = make_low_entropy(100_000)
        assert len(data) == 100_000
        # Should be decodable as ASCII
        try:
            data.decode("ascii")
        except UnicodeDecodeError:
            pytest.fail("Low entropy bytes are not valid ASCII text")
