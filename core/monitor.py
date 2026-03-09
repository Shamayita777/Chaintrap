"""
ChainTrap v2 — core/monitor.py

Core Monitoring Engine — Production-Ready, Cross-Platform.

Patent Claim: "Unified multi-layer ransomware detection agent combining:
  (1) Honeyfile decoy tripwires with dynamic deployment,
  (2) Multi-signal entropy analysis with delta tracking and chi-squared validation,
  (3) Real-time filesystem event monitoring (inotify/FSEvents/ReadDirectoryChangesW),
  (4) New-file-burst detection for rename-and-re-encrypt evasion,
  (5) Time-window burst accumulator for slow-encryption evasion,
  (6) Automated process kill, atomic quarantine, and network isolation,
  (7) Blockchain-anchored tamper-evident forensic audit trail."

Evasion Countermeasures:
  ✅ Entropy sharing / low-entropy padding  → sliding-window + delta
  ✅ Format-Preserving Encryption (FPE)     → magic-byte + OOXML validation
  ✅ Decoy-aware ransomware                 → dynamic, realistic, attractive decoys
  ✅ Rename-and-re-encrypt                  → new-file creation burst detection
  ✅ Slow encryption (time-distributed)     → burst accumulator over time window
  ✅ Base64 ciphertext encoding             → chi-squared uniformity test
  ✅ Partial encryption                     → sliding-window segment analysis
"""

import os
import sys
import time
import hashlib
import logging
import threading
import smtplib
from pathlib import Path
from typing import Optional
from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor

# ── Add local paths ─────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))

from entropy_analyzer  import analyze_file, analyze_delta, EntropyResult
from blockchain_logger import init_chain, verify_chain, get_chain_summary
from decoy_manager     import (deploy_decoy_swarm, get_decoy_paths, is_decoy,
                                refresh_decoys, get_decoy_registry)
from platform_ops      import (find_pids_for_file, kill_process,
                                atomic_quarantine, lockdown_filesystem,
                                lockdown_network, send_desktop_notification,
                                preflight_setup)
from event_logger      import (log_startup, log_shutdown, log_decoy_triggered,
                                log_entropy_anomaly, log_burst_detection,
                                log_new_file_burst, log_process_kill,
                                log_quarantine, log_lockdown, log_magic_mismatch)

try:
    from watchdog.observers import Observer
    from watchdog.events    import (FileSystemEventHandler, FileModifiedEvent,
                                    FileCreatedEvent, FileDeletedEvent,
                                    FileMovedEvent)
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    logging.warning(
        "watchdog not installed — falling back to polling. "
        "Install: pip install watchdog"
    )

logger = logging.getLogger("ChainTrap.monitor")


# ─────────────────────────────────────────────
# BURST ACCUMULATOR
# Tracks anomalous events over a sliding time window.
# Detects slow-encryption attacks (one file per minute).
# ─────────────────────────────────────────────
class BurstAccumulator:
    """
    Sliding-window event accumulator.

    Patent Claim: "Time-windowed anomaly accumulation providing detection
                   of slow encryption attacks that space individual file
                   modifications to remain below per-event thresholds."
    """

    def __init__(self, window_seconds: int = 600, threshold: int = 3):
        self.window_seconds = window_seconds
        self.threshold      = threshold
        self._events: deque = deque()   # (timestamp, file_path) tuples
        self._lock  = threading.Lock()

    def record(self, file_path: str) -> tuple[bool, int, list[str]]:
        """
        Record an anomalous event.
        Returns (threshold_breached, current_count, file_paths_in_window).
        """
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            self._events.append((now, file_path))
            # Evict events outside window
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()

            count = len(self._events)
            paths = [p for _, p in self._events]

        breached = count >= self.threshold
        return breached, count, paths

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


# ─────────────────────────────────────────────
# NEW-FILE BURST TRACKER
# Detects rename-and-re-encrypt patterns:
# ransomware creates new .enc/.locked files without modifying originals.
# ─────────────────────────────────────────────
class NewFileBurstTracker:
    """
    Track new file creation events for burst detection.

    Patent Claim: "Filesystem new-file-creation burst detection as a
                   complementary signal to modification-based entropy analysis,
                   detecting ransomware variants that create new encrypted files
                   rather than modifying originals in-place."
    """
    SUSPICIOUS_EXTENSIONS = {
        ".enc", ".locked", ".crypt", ".crypto", ".encrypted",
        ".zzz", ".xxx", ".aaa", ".abc", ".xyz", ".ecc",
        ".locky", ".cerber", ".zepto", ".thor", ".wallet",
        ".odin", ".shit", ".lol", ".wncry", ".wcry",
        ".onion", ".darkness", ".nochance", ".pay2me",
    }

    def __init__(self, window_seconds: int = 60, threshold: int = 5):
        self.window_seconds = window_seconds
        self.threshold      = threshold
        self._events: deque = deque()
        self._lock  = threading.Lock()

    def record_new_file(self, path: str) -> tuple[bool, list[str]]:
        """
        Record a new file creation event.
        Returns (burst_detected, new_files_in_window).
        """
        ext = Path(path).suffix.lower()
        is_suspicious_ext = ext in self.SUSPICIOUS_EXTENSIONS

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            self._events.append((now, path, is_suspicious_ext))
            while self._events and self._events[0][0] < cutoff:
                self._events.popleft()

            recent_paths   = [p for _, p, _ in self._events]
            suspicious_new = [p for _, p, s in self._events if s]

        # Trigger if many suspicious-extension files appear
        if len(suspicious_new) >= 3:
            return True, suspicious_new

        # Or if general new-file rate is very high (>= threshold)
        if len(recent_paths) >= self.threshold:
            return True, recent_paths

        return False, []


# ─────────────────────────────────────────────
# FILE STATE TRACKER
# Tracks per-file: sha256, last entropy result
# Used for entropy delta calculation.
# ─────────────────────────────────────────────
class FileStateTracker:
    """Thread-safe store of per-file state for delta analysis."""

    def __init__(self):
        self._state: dict[str, dict] = {}
        self._lock  = threading.Lock()

    def get(self, path: str) -> Optional[dict]:
        with self._lock:
            return self._state.get(path)

    def update(self, path: str, sha256: str, entropy_result: EntropyResult) -> None:
        with self._lock:
            self._state[path] = {
                "sha256":         sha256,
                "entropy_result": entropy_result,
                "last_seen":      time.time(),
            }

    def remove(self, path: str) -> None:
        with self._lock:
            self._state.pop(path, None)


# ─────────────────────────────────────────────
# MAIN WATCHDOG HANDLER
# ─────────────────────────────────────────────
class ChainTrapHandler(FileSystemEventHandler if HAS_WATCHDOG else object):
    """
    Filesystem event handler for both decoy and protected directories.

    Routes events to the appropriate analysis pipeline:
    - Decoy file events:    Immediate high-severity alert
    - Protected file events: Full entropy + delta analysis
    - New file events:       Rename-and-re-encrypt burst detection
    """

    def __init__(self, config: dict, state_tracker: FileStateTracker,
                 burst_acc: BurstAccumulator, new_file_tracker: NewFileBurstTracker,
                 quarantine_dir: str, protected_dirs: list, lockdown_done: list):
        super().__init__()
        self.config            = config
        self.state             = state_tracker
        self.burst             = burst_acc
        self.new_files         = new_file_tracker
        self.quarantine_dir    = quarantine_dir
        self.protected_dirs    = protected_dirs
        self._lockdown_done    = lockdown_done   # shared mutable list acting as flag
        self._alert_lock       = threading.Lock()

    def _is_whitelisted(self, path: str) -> bool:
        ext = Path(path).suffix.lower()
        return ext in self.config.get("whitelist_ext", set())

    def _sha256(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # ── Watchdog event dispatchers ────────────────────────────────────────
    def on_modified(self, event):
        if event.is_directory:
            return
        threading.Thread(
            target=self._handle_modification,
            args=(event.src_path,),
            daemon=True
        ).start()

    def on_created(self, event):
        if event.is_directory:
            return
        threading.Thread(
            target=self._handle_new_file,
            args=(event.src_path,),
            daemon=True
        ).start()

    def on_moved(self, event):
        if event.is_directory:
            return
        # A file moved OUT of protected dir is suspicious
        threading.Thread(
            target=self._handle_move,
            args=(event.src_path, event.dest_path),
            daemon=True
        ).start()

    # ── Core modification handler ─────────────────────────────────────────
    def _handle_modification(self, path: str) -> None:
        """
        Main analysis pipeline for file modification events.

        Flow:
          1. Skip whitelisted extensions
          2. Compute SHA-256; skip if unchanged (spurious event)
          3. If decoy → immediate CRITICAL alert
          4. Run full entropy analysis (global + windows + chi² + magic)
          5. Compute entropy delta vs previous observation
          6. If any signal fires → containment pipeline
          7. Record in burst accumulator → slow-encryption check
        """
        if not Path(path).is_file():
            return
        if self._is_whitelisted(path):
            return

        path = str(Path(path).resolve())
        curr_hash = self._sha256(path)
        if curr_hash is None:
            return

        # Check if hash actually changed (watchdog can fire spuriously)
        prev_state = self.state.get(path)
        if prev_state and prev_state["sha256"] == curr_hash:
            return

        # ── Decoy file: any modification = immediate alert ─────────────
        if is_decoy(path):
            logger.critical(f"[DECOY TRIGGERED] {path}")
            entropy_result = analyze_file(path, **self._entropy_kwargs())
            prev_hash = prev_state["sha256"] if prev_state else None
            log_decoy_triggered(path, "modified", entropy_result, prev_hash, curr_hash)
            self.state.update(path, curr_hash, entropy_result)
            self._containment_pipeline(path, entropy_result, is_decoy_file=True)
            return

        # ── Protected file: full multi-signal analysis ─────────────────
        entropy_result = analyze_file(path, **self._entropy_kwargs())
        prev_result    = prev_state.get("entropy_result") if prev_state else None

        # Entropy delta analysis
        delta_suspicious, delta_val, delta_desc = analyze_delta(
            prev_result, entropy_result,
            delta_threshold=self.config.get("entropy_delta_threshold", 1.5)
        )

        self.state.update(path, curr_hash, entropy_result)

        # Magic mismatch — highest confidence signal regardless of entropy
        if not entropy_result.magic_valid:
            log_magic_mismatch(path,
                               Path(path).suffix.lower(),
                               entropy_result.detected_magic or "unknown")

        should_act = (
            entropy_result.is_suspicious
            or delta_suspicious
            or not entropy_result.magic_valid
        )

        if should_act:
            reason = entropy_result.signals_triggered.copy()
            if delta_suspicious:
                reason.append(delta_desc)
            if not entropy_result.magic_valid:
                reason.append(f"magic_mismatch:{entropy_result.detected_magic}")

            log_entropy_anomaly(path, entropy_result,
                                delta_value=delta_val,
                                is_decoy=False)
            self._containment_pipeline(path, entropy_result, is_decoy_file=False)
            logger.warning(f"[ANOMALY] {path} | signals={reason}")

        # Record in burst accumulator regardless (even sub-threshold events)
        # if entropy is mildly elevated (> 6.0) — accumulates slow attacks
        if entropy_result.shannon_global > 6.0:
            burst_breached, burst_count, burst_paths = self.burst.record(path)
            if burst_breached:
                log_burst_detection(burst_paths,
                                    self.config.get("burst_window_seconds", 600),
                                    burst_count)
                logger.critical(
                    f"[BURST] {burst_count} events in window — triggering lockdown."
                )
                self._containment_pipeline(path, entropy_result,
                                           is_decoy_file=False,
                                           force_lockdown=True)

    def _handle_new_file(self, path: str) -> None:
        """
        Handle new file creation events.
        Detects rename-and-re-encrypt ransomware pattern.
        """
        if not Path(path).is_file():
            return

        path = str(Path(path).resolve())
        burst_detected, burst_files = self.new_files.record_new_file(path)

        if burst_detected:
            log_new_file_burst(burst_files, self.new_files.window_seconds)
            logger.warning(f"[NEW-FILE BURST] {len(burst_files)} new files — possible rename-encrypt attack")

            # Analyze the new files for entropy
            for fp in burst_files[-5:]:  # Check most recent 5
                try:
                    er = analyze_file(fp, **self._entropy_kwargs())
                    if er.is_suspicious or not er.magic_valid:
                        log_entropy_anomaly(fp, er, is_decoy=False)
                        self._containment_pipeline(fp, er, is_decoy_file=False)
                except Exception:
                    pass

        # Also initialize state for this new file
        h = self._sha256(path)
        if h:
            er = analyze_file(path, **self._entropy_kwargs())
            self.state.update(path, h, er)

    def _handle_move(self, src: str, dst: str) -> None:
        """
        Handle file move/rename events.
        If a file is moved OUT of a protected directory, log it.
        """
        # Treat destination as a new file creation
        self._handle_new_file(dst)
        # Clean up state for source
        self.state.remove(src)

    # ── Entropy analysis kwargs from config ───────────────────────────────
    def _entropy_kwargs(self) -> dict:
        return {
            "chi_p_threshold":      self.config.get("chi_p_value_threshold", 0.01),
            "entropy_abs_threshold": self.config.get("entropy_absolute_threshold", 7.2),
        }

    # ── Containment pipeline ──────────────────────────────────────────────
    def _containment_pipeline(self,
                               path: str,
                               entropy_result: EntropyResult,
                               is_decoy_file: bool = False,
                               force_lockdown: bool = False) -> None:
        """
        Execute the full containment sequence:
          1. Kill offending processes
          2. Quarantine file
          3. Desktop notification
          4. Email alert (if configured)
          5. System lockdown (if configured and not already done)

        Thread-safe: Only one lockdown is ever executed.
        """
        with self._alert_lock:
            # Step 1: Find and kill processes holding the file
            pids = find_pids_for_file(path)
            for pid in pids:
                success = kill_process(pid)
                log_process_kill(pid, path, success)

            # Step 2: Quarantine
            dest = atomic_quarantine(path, self.quarantine_dir)
            log_quarantine(path, dest, dest is not None)

            # Step 3: Desktop notification
            severity = "🚨 DECOY TRIGGERED" if is_decoy_file else "⚠️ ANOMALY DETECTED"
            msg = (
                f"{severity}\n"
                f"File: {Path(path).name}\n"
                f"Entropy: {entropy_result.shannon_global:.4f}\n"
                f"Signals: {', '.join(entropy_result.signals_triggered[:3])}"
            )
            send_desktop_notification("ChainTrap Alert", msg)

            # Step 4: Email alert
            if self.config.get("alert_email_enabled"):
                self._send_email_alert(path, entropy_result, is_decoy_file)

            # Step 5: System lockdown (once only)
            should_lockdown = (
                self.config.get("auto_lockdown", True)
                and (is_decoy_file or force_lockdown or
                     entropy_result.suspicion_score >= 0.7)
                and not self._lockdown_done
            )

            if should_lockdown:
                self._lockdown_done.append(True)  # Mark done

                # Filesystem lockdown
                lockdown_filesystem(self.protected_dirs)
                log_lockdown("filesystem", self.protected_dirs)

                # Network lockdown
                net_actions = lockdown_network()
                log_lockdown("network", net_actions)

    def _send_email_alert(self, path: str, entropy_result: EntropyResult,
                           is_decoy: bool) -> None:
        """Send email alert — non-fatal if it fails."""
        try:
            cfg = self.config
            from_addr = cfg.get("alert_email_from", "")
            password  = cfg.get("alert_email_password", "")
            to_addr   = cfg.get("alert_email_to", from_addr)
            if not from_addr or not password:
                return

            msg = EmailMessage()
            msg["Subject"] = (
                "[ChainTrap CRITICAL] Decoy Triggered" if is_decoy
                else "[ChainTrap HIGH] Entropy Anomaly Detected"
            )
            msg["From"] = from_addr
            msg["To"]   = to_addr
            msg.set_content(
                f"ChainTrap Detection Report\n"
                f"{'='*40}\n"
                f"Time:    {datetime.now(timezone.utc).isoformat()}\n"
                f"File:    {path}\n"
                f"Is Decoy: {is_decoy}\n"
                f"Entropy: {entropy_result.shannon_global:.4f}\n"
                f"Score:   {entropy_result.suspicion_score:.4f}\n"
                f"Signals: {entropy_result.signals_triggered}\n"
                f"{'='*40}\n"
                f"Immediate action recommended.\n"
            )

            import smtplib
            with smtplib.SMTP_SSL(
                cfg.get("alert_email_smtp", "smtp.gmail.com"),
                cfg.get("alert_email_port", 465)
            ) as smtp:
                smtp.login(from_addr, password)
                smtp.send_message(msg)
        except Exception as e:
            logger.warning(f"Email alert failed: {e}")


# ─────────────────────────────────────────────
# MONITOR ENGINE
# ─────────────────────────────────────────────
class ChainTrapMonitor:
    """
    Main monitoring engine.
    Call `start()` to begin monitoring. Blocks until KeyboardInterrupt.
    """

    VERSION = "2.0"

    def __init__(self, config: Optional[dict] = None):
        self.config = config or self._load_config()
        self._state          = FileStateTracker()
        self._burst          = BurstAccumulator(
            window_seconds=self.config.get("burst_window_seconds", 600),
            threshold=self.config.get("burst_event_threshold", 3)
        )
        self._new_files      = NewFileBurstTracker()
        self._lockdown_done  = []   # Mutable list as simple flag
        self._observers      = []
        self._running        = False
        self._decoy_paths    = []

    def _load_config(self) -> dict:
        """Load config from config module."""
        try:
            import config as cfg
            return {
                "entropy_absolute_threshold": cfg.ENTROPY_ABSOLUTE_THRESHOLD,
                "entropy_delta_threshold":    cfg.ENTROPY_DELTA_THRESHOLD,
                "chi_p_value_threshold":      cfg.CHI_P_VALUE_THRESHOLD,
                "burst_window_seconds":       cfg.BURST_WINDOW_SECONDS,
                "burst_event_threshold":      cfg.BURST_EVENT_THRESHOLD,
                "auto_lockdown":              cfg.AUTO_LOCKDOWN,
                "whitelist_ext":              cfg.WHITELIST_EXT,
                "decoy_dirs":                 cfg.DECOY_DIRS,
                "protected_dirs":             cfg.PROTECTED_DIRS,
                "alert_email_enabled":        cfg.ALERT_EMAIL_ENABLED,
                "alert_email_from":           cfg.ALERT_EMAIL_FROM,
                "alert_email_password":       cfg.ALERT_EMAIL_PASSWORD,
                "alert_email_to":             cfg.ALERT_EMAIL_TO,
                "alert_email_smtp":           cfg.ALERT_EMAIL_SMTP,
                "alert_email_port":           cfg.ALERT_EMAIL_PORT,
                "canary_token_url":           cfg.CANARY_TOKEN_BASE_URL if cfg.CANARY_TOKEN_ENABLED else "",
                "quarantine_dir":             str(cfg.QUARANTINE_DIR),
                "base_dir":                   str(cfg.BASE_DIR),
                "log_dir":                    str(cfg.LOG_DIR),
                "chain_dir":                  str(cfg.CHAIN_DIR),
            }
        except ImportError:
            logger.warning("Config module not found. Using defaults.")
            home = Path.home()
            return {
                "entropy_absolute_threshold": 7.2,
                "entropy_delta_threshold":    1.5,
                "chi_p_value_threshold":      0.01,
                "burst_window_seconds":       600,
                "burst_event_threshold":      3,
                "auto_lockdown":              True,
                "whitelist_ext":              {".jpg", ".jpeg", ".png", ".mp4", ".zip", ".gz"},
                "decoy_dirs":                 [str(home / "Documents"), str(home / "Desktop")],
                "protected_dirs":             [str(home / "Documents")],
                "alert_email_enabled":        False,
                "canary_token_url":           "",
                "quarantine_dir":             str(home / "ChainTrap" / "quarantine"),
                "base_dir":                   str(home / "ChainTrap"),
                "log_dir":                    str(home / "ChainTrap" / "logs"),
                "chain_dir":                  str(home / "ChainTrap" / "chain"),
            }

    def _preflight(self) -> None:
        """Setup directories, verify blockchain, deploy decoys."""
        cfg = self.config
        preflight_setup(
            cfg["base_dir"],
            cfg["quarantine_dir"],
            cfg["log_dir"],
            cfg["chain_dir"],
        )

        # Initialize and verify blockchain
        init_chain()
        result = verify_chain()
        if not result["ok"]:
            logger.critical(f"[CHAIN INTEGRITY FAILURE] {result['errors']}")
        else:
            logger.info(f"Blockchain verified: {result['chain_length']} blocks intact.")

        summary = get_chain_summary()
        logger.info(f"Chain summary: {summary}")

        # Deploy decoy swarm
        canary_url = cfg.get("canary_token_url", "")
        self._decoy_paths = deploy_decoy_swarm(
            directories=cfg["decoy_dirs"],
            count_per_dir=3,
            canary_url=canary_url,
        )
        logger.info(f"Decoy swarm: {len(self._decoy_paths)} files deployed.")

    def _build_handler(self) -> ChainTrapHandler:
        return ChainTrapHandler(
            config=self.config,
            state_tracker=self._state,
            burst_acc=self._burst,
            new_file_tracker=self._new_files,
            quarantine_dir=self.config["quarantine_dir"],
            protected_dirs=self.config["protected_dirs"],
            lockdown_done=self._lockdown_done,
        )

    def _seed_initial_state(self) -> None:
        """
        Compute baseline SHA-256 and entropy for all monitored files
        before the main loop starts. Required for delta analysis.
        """
        all_dirs = set(self.config["decoy_dirs"] + self.config["protected_dirs"])
        logger.info("Seeding initial file state (SHA-256 + entropy baseline)...")
        count = 0
        for d in all_dirs:
            dp = Path(d)
            if not dp.exists():
                continue
            for fp in dp.rglob("*"):
                if not fp.is_file():
                    continue
                ext = fp.suffix.lower()
                if ext in self.config.get("whitelist_ext", set()):
                    continue
                try:
                    h = hashlib.sha256()
                    with open(fp, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    sha = h.hexdigest()
                    er = analyze_file(
                        str(fp),
                        chi_p_threshold=self.config.get("chi_p_value_threshold", 0.01),
                        entropy_abs_threshold=self.config.get("entropy_absolute_threshold", 7.2),
                    )
                    self._state.update(str(fp), sha, er)
                    count += 1
                except Exception:
                    pass
        logger.info(f"Baseline state seeded for {count} files.")

    def start(self) -> None:
        """
        Start ChainTrap monitoring. Blocks until KeyboardInterrupt or stop().
        """
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(sys.stdout),
            ]
        )

        print(f"\n{'═'*60}")
        print(f"  ChainTrap v{self.VERSION} — Ransomware Detection & Protection")
        print(f"{'═'*60}")

        self._preflight()
        self._seed_initial_state()

        handler = self._build_handler()

        # Collect all directories to watch
        all_watch_dirs = list(set(
            self.config["decoy_dirs"] + self.config["protected_dirs"]
        ))

        monitored = []
        for d in all_watch_dirs:
            if not Path(d).exists():
                logger.warning(f"Watch directory does not exist (skipping): {d}")
                continue
            monitored.append(d)

        if not monitored:
            logger.error("No valid directories to monitor. Exiting.")
            return

        # Log startup event
        log_startup(
            version=self.VERSION,
            monitored_dirs=monitored,
            decoy_count=len(self._decoy_paths),
        )

        print(f"\n[✓] Monitoring {len(monitored)} directories:")
        for d in monitored:
            role = "(DECOY+PROTECTED)" if d in self.config["protected_dirs"] else "(DECOY)"
            print(f"    {d}  {role}")
        print(f"\n[✓] {len(self._decoy_paths)} decoy files deployed")
        print(f"[✓] Blockchain: {get_chain_summary()['chain_length']} blocks")
        print(f"\n[⚡] Detection thresholds:")
        print(f"    Entropy absolute: {self.config['entropy_absolute_threshold']}")
        print(f"    Entropy delta:    {self.config['entropy_delta_threshold']}")
        print(f"    Burst window:     {self.config['burst_window_seconds']}s / "
              f"{self.config['burst_event_threshold']} events")
        print(f"\n[ChainTrap ACTIVE — Press Ctrl+C to stop]\n")

        if HAS_WATCHDOG:
            # Watchdog mode: kernel-level events (inotify/FSEvents/ReadDirectoryChangesW)
            for d in monitored:
                obs = Observer()
                obs.schedule(handler, d, recursive=True)
                obs.start()
                self._observers.append(obs)
                logger.info(f"Watchdog observer started: {d}")
        else:
            # Polling fallback
            logger.warning("Watchdog not available. Using polling (slower). pip install watchdog")
            self._polling_loop(monitored)
            return

        self._running = True
        try:
            while self._running:
                time.sleep(1)
                for obs in self._observers:
                    if not obs.is_alive():
                        logger.error("Observer died unexpectedly. Restarting...")
                        obs.start()
        except KeyboardInterrupt:
            print("\n[ChainTrap] Shutdown requested.")
        finally:
            self.stop()

    def _polling_loop(self, directories: list) -> None:
        """
        Polling fallback when watchdog is not available.
        Slower but functional on any platform.
        """
        interval = self.config.get("scan_interval_seconds", 2.0)
        handler  = self._build_handler()

        # Build initial snapshot
        snapshots: dict[str, str] = {}
        for d in directories:
            for fp in Path(d).rglob("*"):
                if fp.is_file():
                    h = hashlib.sha256(fp.read_bytes()).hexdigest() if fp.stat().st_size < 50_000_000 else ""
                    snapshots[str(fp)] = h

        self._running = True
        try:
            while self._running:
                time.sleep(interval)
                current_files = set()
                for d in directories:
                    for fp in Path(d).rglob("*"):
                        if not fp.is_file():
                            continue
                        path_str = str(fp)
                        current_files.add(path_str)
                        try:
                            h = hashlib.sha256(fp.read_bytes()).hexdigest()
                        except Exception:
                            continue
                        if path_str not in snapshots:
                            # New file
                            handler._handle_new_file(path_str)
                            snapshots[path_str] = h
                        elif snapshots[path_str] != h:
                            # Modified
                            handler._handle_modification(path_str)
                            snapshots[path_str] = h
                # Removed files
                for p in set(snapshots) - current_files:
                    del snapshots[p]
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stop all observers."""
        self._running = False
        for obs in self._observers:
            try:
                obs.stop()
                obs.join(timeout=3)
            except Exception:
                pass
        log_shutdown("user_interrupt")
        print("\n[ChainTrap] Stopped. Blockchain verified:")
        result = verify_chain()
        if result["ok"]:
            print(f"  ✅ Chain intact ({result['chain_length']} blocks)")
        else:
            print(f"  ❌ Chain anomalies: {result['errors']}")
        summary = get_chain_summary()
        print(f"  Ransomware events recorded: {summary['ransomware_events']}")
        print()
