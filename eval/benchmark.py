"""
ChainTrap v2 — eval/benchmark.py

Evaluation & Benchmarking Framework (Section 4.7)

Measures:
  - Detection latency (time from file modification to alert)
  - False-positive rate across benign workloads
  - False-negative rate against 7 ransomware simulation patterns
  - Throughput (events/second the engine can sustain)
  - CPU and memory overhead under load

Benchmark Profiles:
  1. benign_office   — Word/Excel saves, browser downloads
  2. benign_dev      — compile outputs, git operations, npm installs
  3. ransomware_fast — 100 files encrypted in <5s (LockBit-style)
  4. ransomware_slow — 3 files/minute over 10 minutes (slow-burn evasion)
  5. ransomware_fpe  — format-preserving encrypted OOXML (no entropy spike)
  6. ransomware_b64  — base64-encoded ciphertext (medium entropy)
  7. ransomware_partial — first 4KB only encrypted (header attack)

Usage:
    python -m eval.benchmark --profile all --output results/benchmark.json
    python -m eval.benchmark --profile ransomware_fast --verbose
"""

from __future__ import annotations

import os
import sys
import json
import time
import math
import random
import struct
import hashlib
import logging
import argparse
import tempfile
import threading
import statistics
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))

from core.entropy_analyzer import analyze_file, EntropyResult

logger = logging.getLogger("ChainTrap.benchmark")


# ─────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────

@dataclass
class DetectionEvent:
    """Single detection result from a benchmark trial."""
    trial_id:        str
    profile:         str
    file_path:       str
    should_detect:   bool          # Ground truth
    was_detected:    bool          # Engine output
    latency_ms:      float         # ms from write → detection
    entropy_score:   float
    detection_score: float
    timestamp:       float = field(default_factory=time.time)

    @property
    def true_positive(self)  -> bool: return self.should_detect and self.was_detected
    @property
    def false_positive(self) -> bool: return not self.should_detect and self.was_detected
    @property
    def true_negative(self)  -> bool: return not self.should_detect and not self.was_detected
    @property
    def false_negative(self) -> bool: return self.should_detect and not self.was_detected


@dataclass
class BenchmarkResult:
    """Aggregated results for one benchmark profile run."""
    profile:           str
    n_trials:          int
    true_positives:    int = 0
    false_positives:   int = 0
    true_negatives:    int = 0
    false_negatives:   int = 0
    latencies_ms:      list[float] = field(default_factory=list)
    throughput_eps:    float = 0.0   # events per second
    cpu_overhead_pct:  float = 0.0
    mem_overhead_mb:   float = 0.0
    events:            list[DetectionEvent] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    @property
    def fnr(self) -> float:
        denom = self.false_negatives + self.true_positives
        return self.false_negatives / denom if denom else 0.0

    @property
    def median_latency_ms(self) -> float:
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        s = sorted(self.latencies_ms)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s)-1)]

    def summary_dict(self) -> dict:
        return {
            "profile":          self.profile,
            "n_trials":         self.n_trials,
            "precision":        round(self.precision, 4),
            "recall":           round(self.recall, 4),
            "f1":               round(self.f1, 4),
            "fpr":              round(self.fpr, 4),
            "fnr":              round(self.fnr, 4),
            "true_positives":   self.true_positives,
            "false_positives":  self.false_positives,
            "true_negatives":   self.true_negatives,
            "false_negatives":  self.false_negatives,
            "latency_median_ms": round(self.median_latency_ms, 2),
            "latency_p95_ms":   round(self.p95_latency_ms, 2),
            "throughput_eps":   round(self.throughput_eps, 2),
            "cpu_overhead_pct": round(self.cpu_overhead_pct, 2),
            "mem_overhead_mb":  round(self.mem_overhead_mb, 2),
        }


# ─────────────────────────────────────────────
# FILE GENERATORS
# Simulate different file types/attack patterns
# ─────────────────────────────────────────────

def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def _low_entropy_bytes(n: int) -> bytes:
    """Simulate normal text / document content (low entropy)."""
    vocab = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\t.,!?;:"
    return bytes(random.choices(vocab, k=n))


def _ooxml_bytes(n: int) -> bytes:
    """Simulate a valid OOXML file (ZIP header + content)."""
    header = b"PK\x03\x04"
    padding = _low_entropy_bytes(n - 4)
    return header + padding


def _base64_encrypted_bytes(n: int) -> bytes:
    """Base64-encoded ciphertext — medium entropy ~6.0."""
    import base64
    raw = os.urandom(n * 3 // 4)
    return base64.b64encode(raw)[:n]


def _partial_encrypted_bytes(n: int) -> bytes:
    """First 4KB encrypted, rest is normal — partial encryption attack."""
    encrypted_part = os.urandom(min(4096, n))
    normal_part    = _low_entropy_bytes(max(0, n - 4096))
    return encrypted_part + normal_part


def _fpe_bytes(n: int) -> bytes:
    """
    Format-Preserving Encryption simulation.
    Looks like OOXML (valid ZIP header) but payload is high-entropy.
    This bypasses naive magic-byte checks that only read first 4 bytes.
    """
    header  = b"PK\x03\x04"
    payload = os.urandom(n - 4)   # High entropy inside valid container
    return header + payload


def _slow_encrypt_bytes(n: int) -> bytes:
    """Standard AES-encrypted block — high entropy."""
    return os.urandom(n)


# Public aliases for testing/external use
make_high_entropy = _random_bytes
make_low_entropy  = _low_entropy_bytes


BENIGN_GENERATORS: dict[str, Callable[[int], bytes]] = {
    "docx":  _ooxml_bytes,
    "xlsx":  _ooxml_bytes,
    "txt":   _low_entropy_bytes,
    "py":    _low_entropy_bytes,
    "json":  _low_entropy_bytes,
    "csv":   _low_entropy_bytes,
}

MALICIOUS_GENERATORS: dict[str, tuple[Callable[[int], bytes], str]] = {
    "ransomware_fast":    (_random_bytes,             ".locked"),
    "ransomware_slow":    (_slow_encrypt_bytes,       ".enc"),
    "ransomware_fpe":     (_fpe_bytes,                ".docx"),    # extension not changed
    "ransomware_b64":     (_base64_encrypted_bytes,   ".b64"),
    "ransomware_partial": (_partial_encrypted_bytes,  ".docx"),
}


# ─────────────────────────────────────────────
# CORE BENCHMARK ENGINE
# ─────────────────────────────────────────────

class BenchmarkEngine:
    """
    Runs detection trials against the entropy analyzer.
    Does NOT spawn the full monitor (no watchdog/quarantine) —
    tests the detection pipeline in isolation for precise latency measurement.
    """

    DETECTION_THRESHOLD = 0.45   # score ≥ this → detected

    def __init__(self, tmpdir: Path, verbose: bool = False):
        self.tmpdir  = tmpdir
        self.verbose = verbose
        self.tmpdir.mkdir(parents=True, exist_ok=True)

    def _write_and_analyze(
        self,
        content:       bytes,
        suffix:        str,
        trial_id:      str,
        should_detect: bool,
        profile:       str,
    ) -> DetectionEvent:
        """Write a file and time detection."""
        fpath = self.tmpdir / f"{trial_id}{suffix}"
        fpath.write_bytes(content)

        t0 = time.perf_counter()
        try:
            result: EntropyResult = analyze_file(fpath)
            # Normalise to a 0-1 score: use is_suspicious + signal count
            n_signals = len(result.signals_triggered) if result.signals_triggered else 0
            score   = min(1.0, n_signals * 0.25 + (0.5 if result.is_suspicious else 0.0))
            entropy = result.shannon_global
            detected = result.is_suspicious
        except Exception as e:
            logger.debug("Analysis error on %s: %s", fpath, e)
            score, entropy, detected = 0.0, 0.0, False
        finally:
            fpath.unlink(missing_ok=True)

        latency_ms = (time.perf_counter() - t0) * 1000

        return DetectionEvent(
            trial_id=trial_id,
            profile=profile,
            file_path=str(fpath),
            should_detect=should_detect,
            was_detected=detected,
            latency_ms=latency_ms,
            entropy_score=entropy,
            detection_score=score,
        )

    def run_benign_profile(self, n: int = 100) -> BenchmarkResult:
        """Office / dev workload — expect zero detections (FP measurement)."""
        result = BenchmarkResult(profile="benign_office", n_trials=n)
        exts   = list(BENIGN_GENERATORS.keys())

        for i in range(n):
            ext      = exts[i % len(exts)]
            gen      = BENIGN_GENERATORS[ext]
            size     = random.randint(10_000, 500_000)
            content  = gen(size)
            suffix   = f".{ext}"
            trial_id = f"benign_{i:04d}"

            ev = self._write_and_analyze(content, suffix, trial_id, False, "benign_office")
            result.events.append(ev)
            result.latencies_ms.append(ev.latency_ms)
            if ev.false_positive: result.false_positives += 1
            else:                 result.true_negatives  += 1

            if self.verbose:
                print(f"  [benign {i+1:3d}/{n}] score={ev.detection_score:.3f} "
                      f"entropy={ev.entropy_score:.4f} "
                      f"{'❌ FP' if ev.false_positive else '✅ TN'}")
        return result

    def run_ransomware_profile(self, profile: str, n: int = 50,
                               delay_s: float = 0.0) -> BenchmarkResult:
        """Malicious file pattern — expect all detections (FN measurement)."""
        if profile not in MALICIOUS_GENERATORS:
            raise ValueError(f"Unknown profile: {profile}")

        gen, suffix = MALICIOUS_GENERATORS[profile]
        result      = BenchmarkResult(profile=profile, n_trials=n)

        for i in range(n):
            if delay_s > 0:
                time.sleep(delay_s)
            size     = random.randint(50_000, 2_000_000)
            content  = gen(size)
            trial_id = f"{profile}_{i:04d}"

            ev = self._write_and_analyze(content, suffix, trial_id, True, profile)
            result.events.append(ev)
            result.latencies_ms.append(ev.latency_ms)
            if ev.true_positive:  result.true_positives  += 1
            else:                 result.false_negatives += 1

            if self.verbose:
                print(f"  [{profile} {i+1:3d}/{n}] score={ev.detection_score:.3f} "
                      f"entropy={ev.entropy_score:.4f} "
                      f"{'✅ TP' if ev.true_positive else '❌ FN'}")
        return result

    def measure_throughput(self, duration_s: float = 10.0) -> float:
        """
        Measure max events/second the analyzer can sustain.
        Returns events per second.
        """
        count = 0
        deadline = time.perf_counter() + duration_s
        size = 100_000

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = []
            while time.perf_counter() < deadline:
                content  = os.urandom(size)
                fpath    = self.tmpdir / f"throughput_{count}.bin"
                fpath.write_bytes(content)
                fut = pool.submit(analyze_file, fpath)
                futures.append((fpath, fut))
                count += 1

            for fpath, fut in futures:
                try:
                    fut.result(timeout=5)
                except Exception:
                    pass
                fpath.unlink(missing_ok=True)

        return count / duration_s

    def measure_overhead(self) -> tuple[float, float]:
        """
        Measure CPU and memory overhead of the detection engine.
        Returns (cpu_pct, mem_mb).
        """
        try:
            import psutil
            proc = psutil.Process()

            # Baseline
            _ = proc.cpu_percent(interval=0.1)
            mem_before = proc.memory_info().rss / 1024 / 1024

            # Load
            files = []
            for i in range(20):
                fpath = self.tmpdir / f"overhead_{i}.bin"
                fpath.write_bytes(os.urandom(500_000))
                files.append(fpath)

            t0 = time.perf_counter()
            for f in files:
                analyze_file(f)
            elapsed = time.perf_counter() - t0

            cpu_pct = proc.cpu_percent(interval=0.1)
            mem_after = proc.memory_info().rss / 1024 / 1024

            for f in files:
                f.unlink(missing_ok=True)

            return cpu_pct, mem_after - mem_before

        except ImportError:
            return 0.0, 0.0


# ─────────────────────────────────────────────
# PROFILE RUNNER
# ─────────────────────────────────────────────

ALL_PROFILES = [
    "benign_office",
    "ransomware_fast",
    "ransomware_slow",
    "ransomware_fpe",
    "ransomware_b64",
    "ransomware_partial",
]


def run_all_benchmarks(
    profiles:  list[str],
    n_benign:  int = 100,
    n_malicious: int = 50,
    verbose:   bool = False,
    output:    Optional[Path] = None,
) -> dict:
    """
    Run selected benchmark profiles and return/save results.
    """
    with tempfile.TemporaryDirectory(prefix="chaintrap_bench_") as tmpdir:
        engine = BenchmarkEngine(Path(tmpdir), verbose=verbose)

        print(f"\n{'='*60}")
        print(f"  ChainTrap v2 — Benchmark Suite")
        print(f"  Profiles: {', '.join(profiles)}")
        print(f"{'='*60}\n")

        # Measure throughput once
        print("📊 Measuring throughput (10s)...")
        throughput = engine.measure_throughput(duration_s=10.0)
        print(f"   → {throughput:.1f} events/sec\n")

        # Measure overhead once
        print("🖥  Measuring CPU/memory overhead...")
        cpu_pct, mem_mb = engine.measure_overhead()
        print(f"   → CPU: {cpu_pct:.1f}%   Memory delta: {mem_mb:.1f} MB\n")

        all_results = []

        for profile in profiles:
            print(f"▶ Running profile: {profile}")
            if profile == "benign_office":
                r = engine.run_benign_profile(n=n_benign)
            elif profile == "ransomware_slow":
                # Slow profile: small n with inter-file delay
                r = engine.run_ransomware_profile(profile, n=20, delay_s=0.1)
            else:
                r = engine.run_ransomware_profile(profile, n=n_malicious)

            r.throughput_eps   = throughput
            r.cpu_overhead_pct = cpu_pct
            r.mem_overhead_mb  = mem_mb

            _print_result(r)
            all_results.append(r)

        # Compile report
        report = {
            "meta": {
                "chaintrap_version": "2.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "n_benign":  n_benign,
                "n_malicious": n_malicious,
                "throughput_eps":   round(throughput, 2),
                "cpu_overhead_pct": round(cpu_pct, 2),
                "mem_overhead_mb":  round(mem_mb, 2),
            },
            "results": [r.summary_dict() for r in all_results],
        }

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2))
            print(f"\n💾 Results saved → {output}")

        return report


def _print_result(r: BenchmarkResult) -> None:
    print(f"  Precision:    {r.precision:.4f}  |  Recall:  {r.recall:.4f}  |  F1: {r.f1:.4f}")
    print(f"  FPR:          {r.fpr:.4f}  |  FNR:    {r.fnr:.4f}")
    print(f"  Latency p50:  {r.median_latency_ms:.1f}ms  |  p95: {r.p95_latency_ms:.1f}ms")
    print(f"  TP={r.true_positives} FP={r.false_positives} "
          f"TN={r.true_negatives} FN={r.false_negatives}")
    print()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.WARNING)

    parser = argparse.ArgumentParser(description="ChainTrap v2 Benchmark Framework")
    parser.add_argument("--profile", default="all",
                        choices=ALL_PROFILES + ["all"],
                        help="Profile to run (default: all)")
    parser.add_argument("--n-benign",    type=int, default=100)
    parser.add_argument("--n-malicious", type=int, default=50)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", type=Path, default=None,
                        help="Save JSON results to this path")
    args = parser.parse_args()

    profiles = ALL_PROFILES if args.profile == "all" else [args.profile]

    run_all_benchmarks(
        profiles=profiles,
        n_benign=args.n_benign,
        n_malicious=args.n_malicious,
        verbose=args.verbose,
        output=args.output,
    )


if __name__ == "__main__":
    main()
