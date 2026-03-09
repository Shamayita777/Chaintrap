"""
ChainTrap v2 — eval/threat_sim.py

Controlled Threat Simulation Framework

Simulates real ransomware attack patterns against a live ChainTrap monitor
to measure end-to-end detection performance under realistic conditions.

Attack Profiles (based on real ransomware families):
  1. lockbit_style    — Mass AES encryption, high throughput, renames to .lockbit
  2. conti_style      — Targets specific extensions (office files first), renames to .conti
  3. ryuk_style       — Slow burn, encrypted files renamed, network share enumeration
  4. blackcat_style   — Intermittent bursts with decoy file awareness
  5. wannacry_style   — Worm-style fast spread, .WNCRY extension
  6. fpe_evasion      — Format-preserving encryption, maintains valid headers
  7. slow_burn        — 1 file every 30–60s, tests BurstAccumulator
  8. partial_encrypt  — Only first N bytes encrypted (header attack)
  9. canary_triggered — Attack that touches decoy files (tests canary detection)

Usage:
    python -m eval.threat_sim --profile lockbit_style --target /tmp/test_dir
    python -m eval.threat_sim --profile all --target /tmp/test_dir --dry-run
    python -m eval.threat_sim --list-profiles

Architecture:
    ThreatSimulator runs in a subprocess, writing files to a watched directory.
    The ChainTrap monitor (running in the same process or separately) detects
    the attacks. SimulationResult captures detection timing and accuracy.

WARNING: This is a SIMULATION framework. It writes high-entropy random bytes
         to disk but does NOT perform real encryption or harm real files.
         Always run in an isolated temp directory.
"""

from __future__ import annotations

import os
import sys
import time
import json
import base64
import random
import secrets
import zipfile
import hashlib
import logging
import tempfile
import argparse
import threading
from io import BytesIO
from pathlib import Path
from typing import Optional, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

logger = logging.getLogger("ChainTrap.threat_sim")


# ─────────────────────────────────────────────
# SIMULATION DATA STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class AttackEvent:
    """A single file operation performed by the simulator."""
    timestamp:    float
    operation:    str          # "write", "rename", "delete", "create"
    path:         str
    size_bytes:   int = 0
    extension:    str = ""
    entropy_approx: float = 0.0  # Approximate entropy of written content

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DetectionResult:
    """Result of ChainTrap detecting (or missing) an attack event."""
    attack_event:     AttackEvent
    detected:         bool
    detection_method: str   # "entropy", "canary", "decoy_tripwire", "burst", "none"
    latency_ms:       float = 0.0
    false_positive:   bool  = False


@dataclass
class SimulationResult:
    """Full result of a threat simulation run."""
    profile:          str
    target_dir:       str
    start_time:       float
    end_time:         float
    total_files:      int = 0
    detected_events:  int = 0
    missed_events:    int = 0
    detection_events: list[DetectionResult] = field(default_factory=list)
    attack_events:    list[AttackEvent]     = field(default_factory=list)
    error:            Optional[str] = None

    @property
    def duration_s(self) -> float:
        return self.end_time - self.start_time

    @property
    def detection_rate(self) -> float:
        total = self.detected_events + self.missed_events
        return self.detected_events / total if total else 0.0

    @property
    def files_per_second(self) -> float:
        return self.total_files / self.duration_s if self.duration_s else 0.0

    def summary(self) -> dict:
        return {
            "profile":         self.profile,
            "duration_s":      round(self.duration_s, 2),
            "total_files":     self.total_files,
            "detected":        self.detected_events,
            "missed":          self.missed_events,
            "detection_rate":  round(self.detection_rate, 4),
            "files_per_second": round(self.files_per_second, 2),
            "error":           self.error,
        }


# ─────────────────────────────────────────────
# FILE CONTENT GENERATORS
# ─────────────────────────────────────────────

def _aes_sim(size: int) -> bytes:
    """Simulate AES-256 ciphertext: near-uniform, ~8.0 entropy."""
    return secrets.token_bytes(size)


def _low_entropy(size: int) -> bytes:
    """Normal plaintext content."""
    vocab = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\t.,!?;:0123456789"
    return bytes([vocab[i % len(vocab)] for i in range(size)])


def _ooxml_valid(size: int) -> bytes:
    """Valid OOXML ZIP file with low-entropy content inside."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml",
            b"<w:document>" + _low_entropy(max(100, size - 300)) + b"</w:document>")
    return buf.getvalue()


def _fpe_content(size: int) -> bytes:
    """Format-preserving: valid ZIP header, encrypted payload inside."""
    return b"PK\x03\x04" + secrets.token_bytes(size - 4)


def _b64_encrypted(size: int) -> bytes:
    """Base64-encoded ciphertext (medium entropy ~6.0)."""
    raw = secrets.token_bytes(size * 3 // 4)
    return base64.b64encode(raw)[:size]


def _partial_encrypted(size: int) -> bytes:
    """Only first 4KB encrypted, remainder is normal content."""
    header = secrets.token_bytes(min(4096, size))
    body   = _low_entropy(max(0, size - 4096))
    return header + body


# ─────────────────────────────────────────────
# ATTACK PROFILES
# ─────────────────────────────────────────────

@dataclass
class AttackProfile:
    """Defines a ransomware behavior pattern to simulate."""
    name:              str
    description:       str
    target_extensions: list[str]
    output_extension:  str
    file_count:        int
    file_size_range:   tuple[int, int]   # (min_bytes, max_bytes)
    delay_between_s:   float             # seconds between file operations
    burst_size:        int               # files per burst (1 = no bursting)
    burst_delay_s:     float             # delay between bursts
    content_fn:        Callable[[int], bytes]
    rename_originals:  bool = True       # True = rename original, False = write new file
    touch_decoys:      bool = False      # True = also open decoy files


PROFILES: dict[str, AttackProfile] = {
    "lockbit_style": AttackProfile(
        name="lockbit_style",
        description="LockBit 3.0: mass AES encryption, high speed, .lockbit extension",
        target_extensions=[".docx", ".xlsx", ".pdf", ".txt", ".csv"],
        output_extension=".lockbit",
        file_count=50,
        file_size_range=(50_000, 2_000_000),
        delay_between_s=0.0,
        burst_size=50,
        burst_delay_s=0.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "conti_style": AttackProfile(
        name="conti_style",
        description="Conti: targeted extension list, moderate speed, .conti extension",
        target_extensions=[".docx", ".xlsx", ".pptx", ".doc", ".xls"],
        output_extension=".conti",
        file_count=30,
        file_size_range=(100_000, 5_000_000),
        delay_between_s=0.02,
        burst_size=10,
        burst_delay_s=1.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "ryuk_style": AttackProfile(
        name="ryuk_style",
        description="Ryuk: slow methodical encryption, office files, .RYK extension",
        target_extensions=[".docx", ".xlsx", ".pdf", ".pptx", ".doc"],
        output_extension=".RYK",
        file_count=20,
        file_size_range=(200_000, 10_000_000),
        delay_between_s=0.5,
        burst_size=5,
        burst_delay_s=5.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "blackcat_style": AttackProfile(
        name="blackcat_style",
        description="BlackCat/ALPHV: intermittent bursts, .alphv extension",
        target_extensions=[".docx", ".xlsx", ".pdf", ".txt"],
        output_extension=".alphv",
        file_count=40,
        file_size_range=(10_000, 3_000_000),
        delay_between_s=0.0,
        burst_size=8,
        burst_delay_s=3.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "wannacry_style": AttackProfile(
        name="wannacry_style",
        description="WannaCry: fast worm-style spread, .WNCRY extension",
        target_extensions=[".docx", ".xlsx", ".pdf", ".mp4", ".jpg", ".zip"],
        output_extension=".WNCRY",
        file_count=100,
        file_size_range=(1_000, 500_000),
        delay_between_s=0.0,
        burst_size=100,
        burst_delay_s=0.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "fpe_evasion": AttackProfile(
        name="fpe_evasion",
        description="FPE: format-preserving encryption, maintains valid ZIP headers",
        target_extensions=[".docx", ".xlsx", ".pptx"],
        output_extension=".docx",  # Same extension — no rename
        file_count=20,
        file_size_range=(50_000, 1_000_000),
        delay_between_s=0.1,
        burst_size=20,
        burst_delay_s=0.0,
        content_fn=_fpe_content,
        rename_originals=False,
    ),
    "slow_burn": AttackProfile(
        name="slow_burn",
        description="Slow burn: 1 file every 2s, tests BurstAccumulator",
        target_extensions=[".docx", ".pdf", ".xlsx"],
        output_extension=".enc",
        file_count=15,
        file_size_range=(100_000, 2_000_000),
        delay_between_s=2.0,
        burst_size=1,
        burst_delay_s=0.0,
        content_fn=_aes_sim,
        rename_originals=True,
    ),
    "partial_encrypt": AttackProfile(
        name="partial_encrypt",
        description="Header attack: only first 4KB encrypted, tests window analysis",
        target_extensions=[".docx", ".xlsx", ".pdf"],
        output_extension=".locked",
        file_count=25,
        file_size_range=(200_000, 5_000_000),
        delay_between_s=0.05,
        burst_size=25,
        burst_delay_s=0.0,
        content_fn=_partial_encrypted,
        rename_originals=False,
    ),
    "b64_evasion": AttackProfile(
        name="b64_evasion",
        description="Base64 ciphertext: medium entropy ~6.0, tests chi-squared",
        target_extensions=[".txt", ".csv", ".log"],
        output_extension=".b64",
        file_count=20,
        file_size_range=(50_000, 500_000),
        delay_between_s=0.05,
        burst_size=20,
        burst_delay_s=0.0,
        content_fn=_b64_encrypted,
        rename_originals=True,
    ),
    "canary_triggered": AttackProfile(
        name="canary_triggered",
        description="Decoy-aware: attacks normal files but also opens canary decoys",
        target_extensions=[".docx", ".pdf", ".xlsx"],
        output_extension=".enc",
        file_count=10,
        file_size_range=(50_000, 500_000),
        delay_between_s=0.1,
        burst_size=5,
        burst_delay_s=1.0,
        content_fn=_aes_sim,
        rename_originals=True,
        touch_decoys=True,
    ),
}


# ─────────────────────────────────────────────
# THREAT SIMULATOR
# ─────────────────────────────────────────────

class ThreatSimulator:
    """
    Controlled ransomware attack simulator.

    Writes simulated attack files to a target directory according to
    an AttackProfile, recording all file operations for analysis.

    IMPORTANT: This does NOT encrypt real files. It writes synthetic
    high-entropy content to new files in the target directory only.
    """

    def __init__(
        self,
        target_dir:       Path,
        profile:          AttackProfile,
        on_event:         Optional[Callable[[AttackEvent], None]] = None,
        dry_run:          bool = False,
        seed_victim_files: int = 20,
    ):
        self.target_dir   = Path(target_dir)
        self.profile      = profile
        self.on_event     = on_event
        self.dry_run      = dry_run
        self.seed_count   = seed_victim_files
        self._events:     list[AttackEvent] = []
        self._stop_flag   = threading.Event()

    def _emit(self, event: AttackEvent) -> None:
        self._events.append(event)
        if self.on_event:
            self.on_event(event)

    def _seed_victim_files(self) -> list[Path]:
        """Create realistic victim files in target dir for attack to act on."""
        victims = []
        names = [
            "Q3_Financial_Report", "Employee_Salaries", "Client_Contracts",
            "Product_Roadmap", "Board_Presentation", "Budget_2025",
            "HR_Policy_Manual", "IP_Portfolio", "Sales_Pipeline",
            "Architecture_Overview", "Customer_Database", "Legal_Agreements",
            "Marketing_Strategy", "Research_Notes", "Investor_Deck",
            "Project_Timeline", "Vendor_Contracts", "Tax_Returns",
            "Security_Audit", "Merger_Documents",
        ]
        exts = self.profile.target_extensions or [".docx", ".xlsx", ".pdf"]

        for i in range(self.seed_count):
            name  = names[i % len(names)]
            ext   = exts[i % len(exts)]
            fname = f"{name}_{i:03d}{ext}"
            path  = self.target_dir / fname

            size  = random.randint(10_000, 100_000)
            if ext in (".docx", ".xlsx", ".pptx"):
                content = _ooxml_valid(size)
            else:
                content = _low_entropy(size)

            if not self.dry_run:
                path.write_bytes(content)
            victims.append(path)
            logger.debug("Seeded victim file: %s", fname)

        return victims

    def run(self) -> SimulationResult:
        """Execute the full attack simulation."""
        self.target_dir.mkdir(parents=True, exist_ok=True)

        result = SimulationResult(
            profile=self.profile.name,
            target_dir=str(self.target_dir),
            start_time=time.time(),
            end_time=0.0,
        )

        try:
            logger.info("Seeding %d victim files in %s", self.seed_count, self.target_dir)
            victims = self._seed_victim_files()

            # Give the monitor a moment to register baseline files
            if not self.dry_run:
                time.sleep(0.5)

            logger.info("Starting attack profile: %s", self.profile.name)
            self._run_attack(victims, result)

        except Exception as e:
            result.error = str(e)
            logger.error("Simulation error: %s", e)
        finally:
            result.end_time = time.time()
            result.attack_events = self._events
            result.total_files = len(self._events)

        return result

    def _run_attack(self, victims: list[Path], result: SimulationResult) -> None:
        profile = self.profile
        files_written = 0
        burst_count   = 0

        # Decoy files (for canary_triggered profile)
        decoy_paths = []
        if profile.touch_decoys:
            try:
                from core.decoy_manager import get_decoy_paths
                decoy_paths = [Path(p) for p in get_decoy_paths() if Path(p).exists()]
                logger.info("Found %d decoy files to touch", len(decoy_paths))
            except Exception:
                pass

        for i in range(profile.file_count):
            if self._stop_flag.is_set():
                break

            # Burst management
            if burst_count >= profile.burst_size and profile.burst_delay_s > 0:
                if not self.dry_run:
                    time.sleep(profile.burst_delay_s)
                burst_count = 0

            # Pick a victim file to "encrypt"
            victim = victims[i % len(victims)] if victims else None
            size   = random.randint(*profile.file_size_range)

            if profile.rename_originals and victim and victim.exists():
                # Simulate: overwrite victim with encrypted content, rename
                out_path = victim.with_suffix(profile.output_extension)
                content  = profile.content_fn(size)
                approx_entropy = 7.9 if profile.content_fn == _aes_sim else 5.0

                if not self.dry_run:
                    out_path.write_bytes(content)
                    # Optionally remove original (rename simulation)
                    if out_path != victim:
                        victim.unlink(missing_ok=True)

                event = AttackEvent(
                    timestamp=time.time(),
                    operation="write+rename",
                    path=str(out_path),
                    size_bytes=size,
                    extension=profile.output_extension,
                    entropy_approx=approx_entropy,
                )
            else:
                # Simulate: write new encrypted file alongside original
                fname = f"encrypted_{i:05d}{profile.output_extension}"
                out_path = self.target_dir / fname
                content  = profile.content_fn(size)

                if not self.dry_run:
                    out_path.write_bytes(content)

                event = AttackEvent(
                    timestamp=time.time(),
                    operation="write",
                    path=str(out_path),
                    size_bytes=size,
                    extension=profile.output_extension,
                    entropy_approx=7.9 if profile.content_fn == _aes_sim else 5.5,
                )

            self._emit(event)
            files_written += 1
            burst_count   += 1

            # Touch a decoy (canary_triggered profile)
            if profile.touch_decoys and decoy_paths and i % 3 == 0:
                decoy = random.choice(decoy_paths)
                try:
                    if not self.dry_run:
                        _ = decoy.read_bytes()  # Trigger canary via filesystem access
                    touch_event = AttackEvent(
                        timestamp=time.time(),
                        operation="read",
                        path=str(decoy),
                        size_bytes=decoy.stat().st_size if decoy.exists() else 0,
                        extension=decoy.suffix,
                        entropy_approx=0.0,
                    )
                    self._emit(touch_event)
                except Exception:
                    pass

            # Inter-file delay
            if profile.delay_between_s > 0 and not self.dry_run:
                time.sleep(profile.delay_between_s)

        logger.info("Attack simulation complete: %d files written", files_written)

    def stop(self) -> None:
        self._stop_flag.set()


# ─────────────────────────────────────────────
# SIMULATION HARNESS
# Runs simulator + evaluates ChainTrap detection
# ─────────────────────────────────────────────

class SimulationHarness:
    """
    End-to-end simulation harness.

    Runs a ThreatSimulator against a set of monitored directories,
    collects detection events from ChainTrap, and computes detection
    metrics (detection rate, latency, false negatives by attack type).
    """

    def __init__(self, monitored_dirs: list[Path]):
        self.monitored_dirs = monitored_dirs
        self._detected_files: set[str] = set()
        self._detection_times: dict[str, float] = {}

    def notify_detected(self, path: str, method: str = "entropy") -> None:
        """Called by the ChainTrap monitor when it detects a file."""
        self._detected_files.add(path)
        self._detection_times[path] = time.time()

    def run_profile(
        self,
        profile_name: str,
        file_count:   int = 20,
        dry_run:      bool = False,
    ) -> SimulationResult:
        """Run a single attack profile and return results."""
        if profile_name not in PROFILES:
            raise ValueError(f"Unknown profile: {profile_name}. "
                             f"Available: {sorted(PROFILES.keys())}")

        profile = PROFILES[profile_name]
        # Override file count for testing
        profile = AttackProfile(
            name=profile.name, description=profile.description,
            target_extensions=list(profile.target_extensions),
            output_extension=profile.output_extension,
            file_count=file_count,
            file_size_range=profile.file_size_range,
            delay_between_s=profile.delay_between_s,
            burst_size=profile.burst_size, burst_delay_s=profile.burst_delay_s,
            content_fn=PROFILES[profile_name].content_fn,
            rename_originals=profile.rename_originals,
            touch_decoys=profile.touch_decoys,
        )

        target = self.monitored_dirs[0] if self.monitored_dirs else Path(tempfile.mkdtemp())
        sim    = ThreatSimulator(
            target_dir=target,
            profile=profile,
            dry_run=dry_run,
            seed_victim_files=max(file_count, 20),
        )
        return sim.run()

    def run_all_profiles(
        self,
        file_count: int = 10,
        dry_run:    bool = False,
    ) -> dict[str, SimulationResult]:
        """Run all attack profiles and return results keyed by profile name."""
        results = {}
        for name in PROFILES:
            logger.info("Running profile: %s", name)
            with tempfile.TemporaryDirectory(prefix=f"chaintrap_sim_{name}_") as td:
                profile = PROFILES[name]
                overridden = AttackProfile(
                    name=profile.name, description=profile.description,
                    target_extensions=list(profile.target_extensions),
                    output_extension=profile.output_extension,
                    file_count=file_count,
                    file_size_range=profile.file_size_range,
                    delay_between_s=profile.delay_between_s,
                    burst_size=profile.burst_size, burst_delay_s=profile.burst_delay_s,
                    content_fn=profile.content_fn,
                    rename_originals=profile.rename_originals,
                    touch_decoys=profile.touch_decoys,
                )
                sim = ThreatSimulator(
                    target_dir=Path(td),
                    profile=overridden,
                    dry_run=dry_run,
                    seed_victim_files=max(file_count, 10),
                )
                results[name] = sim.run()
        return results


# ─────────────────────────────────────────────
# STANDALONE RUNNER (direct integration test)
# ─────────────────────────────────────────────

def run_with_entropy_check(
    profile_name: str,
    file_count:   int = 20,
    verbose:      bool = False,
) -> SimulationResult:
    """
    Run a simulation and pass each written file through the entropy analyzer
    to evaluate detection. Returns a populated SimulationResult.
    """
    from core.entropy_analyzer import analyze_file

    if profile_name not in PROFILES:
        raise ValueError(f"Unknown profile: {profile_name}")

    profile = PROFILES[profile_name]
    detected = []
    missed   = []

    def on_event(event: AttackEvent):
        if event.operation == "read":
            return  # canary touches — skip entropy check
        path = Path(event.path)
        if not path.exists():
            return
        try:
            result = analyze_file(path)
            if result.is_suspicious:
                detected.append(event)
                if verbose:
                    print(f"  ✅ DETECTED  {path.name:<40} "
                          f"entropy={result.shannon_global:.4f}")
            else:
                missed.append(event)
                if verbose:
                    print(f"  ❌ MISSED    {path.name:<40} "
                          f"entropy={result.shannon_global:.4f} "
                          f"signals={result.signals_triggered}")
        except Exception as e:
            missed.append(event)
            if verbose:
                print(f"  ⚠ ERROR     {path.name}: {e}")

    with tempfile.TemporaryDirectory(prefix="chaintrap_sim_") as td:
        overridden = AttackProfile(
            name=profile.name,
            description=profile.description,
            target_extensions=list(profile.target_extensions),
            output_extension=profile.output_extension,
            file_count=file_count,
            file_size_range=profile.file_size_range,
            delay_between_s=profile.delay_between_s,
            burst_size=profile.burst_size,
            burst_delay_s=profile.burst_delay_s,
            content_fn=profile.content_fn,
            rename_originals=profile.rename_originals,
            touch_decoys=profile.touch_decoys,
        )

        sim = ThreatSimulator(
            target_dir=Path(td),
            profile=overridden,
            on_event=on_event,
            seed_victim_files=max(file_count, 15),
        )
        result = sim.run()

    result.detected_events = len(detected)
    result.missed_events   = len(missed)
    return result


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s [%(name)s] %(message)s")

    parser = argparse.ArgumentParser(description="ChainTrap v2 Threat Simulator")
    parser.add_argument("--profile", default="lockbit_style",
                        help="Attack profile name (or 'all')")
    parser.add_argument("--list-profiles", action="store_true",
                        help="List all available attack profiles")
    parser.add_argument("--target", type=Path, default=None,
                        help="Target directory (default: temp dir)")
    parser.add_argument("--file-count", type=int, default=20,
                        help="Number of files to simulate")
    parser.add_argument("--dry-run", action="store_true",
                        help="Don't write files, just simulate")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output", type=Path, default=None,
                        help="Save JSON results to this path")
    args = parser.parse_args()

    if args.list_profiles:
        print("\nAvailable attack profiles:\n")
        for name, profile in PROFILES.items():
            print(f"  {name:<22} — {profile.description}")
        print()
        return

    profiles = list(PROFILES.keys()) if args.profile == "all" else [args.profile]

    all_results = {}
    for pname in profiles:
        print(f"\n{'='*60}")
        print(f"  Profile: {pname}")
        print(f"{'='*60}")
        result = run_with_entropy_check(
            pname, file_count=args.file_count, verbose=args.verbose
        )
        all_results[pname] = result.summary()
        s = result.summary()
        print(f"  Files:          {s['total_files']}")
        print(f"  Detected:       {s['detected']} / {s['total_files']}  "
              f"({s['detection_rate']*100:.1f}%)")
        print(f"  Files/sec:      {s['files_per_second']:.1f}")
        print(f"  Duration:       {s['duration_s']:.2f}s")
        if s.get("error"):
            print(f"  Error:          {s['error']}")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(all_results, indent=2))
        print(f"\n💾 Results saved → {args.output}")


if __name__ == "__main__":
    main()
