"""
ChainTrap v2 — core/event_logger.py

Structured Event Logger (JSONL format).

Writes one JSON object per line to events.jsonl.
JSONL (JSON Lines) is ideal for streaming, appending, and forensic analysis.
Each line is a complete, self-contained event record.

Also integrates with the blockchain logger to record each detection event
as an immutable block.
"""

import os
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Any
from importlib import import_module
try:
    cfg = import_module("config.config")
    LOG_FILE = cfg.LOG_FILE
except Exception:
    # fallback for tests
    LOG_FILE = "chaintrap_events.log"
logger = logging.getLogger("ChainTrap.events")
_write_lock = threading.Lock()


# ─────────────────────────────────────────────
# EVENT TYPES
# ─────────────────────────────────────────────
class EventType:
    STARTUP         = "SYSTEM_STARTUP"
    SHUTDOWN        = "SYSTEM_SHUTDOWN"
    CHAIN_VERIFIED  = "CHAIN_VERIFIED"
    CHAIN_TAMPERED  = "CHAIN_TAMPERED"
    DECOY_DEPLOYED  = "DECOY_DEPLOYED"
    DECOY_TRIGGERED = "DECOY_TRIGGERED"       # Decoy file modified → fast alert
    FILE_MODIFIED   = "FILE_MODIFIED"          # Protected file modified
    ENTROPY_SPIKE   = "ENTROPY_SPIKE" 
    ENTROPY_ANOMALY = "ENTROPY_ANOMALY"         # Single file anomaly
    ENTROPY_DELTA   = "ENTROPY_DELTA"          # Entropy delta threshold crossed
    BURST_DETECTED  = "BURST_DETECTED"         # Multiple anomalies in time window
    PROCESS_KILLED  = "PROCESS_KILLED"
    FILE_QUARANTINED = "FILE_QUARANTINED"
    LOCKDOWN_FS     = "LOCKDOWN_FILESYSTEM"
    LOCKDOWN_NET    = "LOCKDOWN_NETWORK"
    MAGIC_MISMATCH  = "MAGIC_MISMATCH"
    FALSE_POSITIVE  = "FALSE_POSITIVE"         # Manually flagged as FP
    CANARY_FIRED    = "CANARY_FIRED"


def _log_path() -> Path:
    """Resolve log file path."""
    return Path(LOG_FILE)


def _sha256_file(path: str) -> Optional[str]:
    """Compute SHA-256 of a file, streaming for large files."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_event(event: dict) -> None:
    """Append a single event to the JSONL log file."""
    log_file = _log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)

    with _write_lock:
        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=True, default=str) + "\n")
        except OSError as e:
            logger.error(f"Failed to write event log: {e}")


def _blockchain_record(event: dict) -> Optional[dict]:
    """
    Record event on blockchain. Non-fatal if blockchain fails.
    Returns the new block or None.
    """
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from blockchain_logger import add_event
        return add_event(event)
    except Exception as e:
        logger.warning(f"Blockchain record failed: {e}")
        return None


# ─────────────────────────────────────────────
# PUBLIC LOGGING API
# ─────────────────────────────────────────────
def log_startup(version: str = "2.0",
                monitored_dirs: Optional[list] = None,
                decoy_count: int = 0) -> None:
    event = {
        "event_type":      EventType.STARTUP,
        "timestamp":       _now_iso(),
        "version":         version,
        "monitored_dirs":  monitored_dirs or [],
        "decoy_count":     decoy_count,
    }
    _write_event(event)
    _blockchain_record(event)
    logger.info(f"ChainTrap v{version} started. Monitoring {len(monitored_dirs or [])} directories.")


def log_shutdown(reason: str = "user_interrupt") -> None:
    event = {
        "event_type": EventType.SHUTDOWN,
        "timestamp":  _now_iso(),
        "reason":     reason,
    }
    _write_event(event)
    _blockchain_record(event)


def log_decoy_triggered(
    file_path: str,
    event_kind: str = "modified",
    entropy_result: Any = None,
    prev_hash: Optional[str] = None,
    curr_hash: Optional[str] = None,
    pids: Optional[list] = None,
) -> dict:
    """
    Log a decoy file trigger event. This is the highest-priority alert.
    Any modification to a decoy = instant suspicious event.
    """
    event = {
        "event_type":      EventType.DECOY_TRIGGERED,
        "timestamp":       _now_iso(),
        "severity":        "CRITICAL",
        "file_path":       file_path,
        "event_kind":      event_kind,
        "prev_sha256":     prev_hash,
        "curr_sha256":     curr_hash,
        "entropy_global":  getattr(entropy_result, "shannon_global", None),
        "entropy_windows": getattr(entropy_result, "shannon_windows", None),
        "chi_p_value":     getattr(entropy_result, "chi_p_value", None),
        "magic_valid":     getattr(entropy_result, "magic_valid", None),
        "signals":         getattr(entropy_result, "signals_triggered", []),
        "pids": pids or [],
    }
    _write_event(event)
    _blockchain_record(event)
    logger.critical(
        f"[DECOY TRIGGERED] {file_path} | "
        f"kind={event_kind} | "
        f"entropy={getattr(entropy_result, 'shannon_global', 'N/A')}"
    )
    return event

def log_entropy_anomaly(
    file_path: str,
    entropy_result: Any,
    delta_value: Optional[float] = None,
    is_decoy: bool = False,
    pids: Optional[list] = None,
) -> dict:
    """Log a single-file entropy anomaly detection event."""
    etype = EventType.DECOY_TRIGGERED if is_decoy else EventType.ENTROPY_ANOMALY
    severity = "CRITICAL" if is_decoy else "HIGH"

    event = {
        "event_type":       etype,
        "timestamp":        _now_iso(),
        "severity":         severity,
        "file_path":        file_path,
        "file_size":        getattr(entropy_result, "file_size", None),
        "entropy_global":   getattr(entropy_result, "shannon_global", None),
        "entropy_max_win":  getattr(entropy_result, "shannon_max_window", None),
        "entropy_windows":  getattr(entropy_result, "shannon_windows", None),
        "entropy_delta":    delta_value,
        "chi_p_value":      getattr(entropy_result, "chi_p_value", None),
        "chi_statistic":    getattr(entropy_result, "chi_statistic", None),
        "magic_valid":      getattr(entropy_result, "magic_valid", None),
        "detected_magic":   getattr(entropy_result, "detected_magic", None),
        "signals":          getattr(entropy_result, "signals_triggered", []),
        "suspicion_score":  getattr(entropy_result, "suspicion_score", None),
        "is_decoy":         is_decoy,
        "sha256":           _sha256_file(file_path),
        "pids": pids or [],
    }
    _write_event(event)
    _blockchain_record(event)
    logger.warning(
        f"[{'DECOY' if is_decoy else 'ANOMALY'}] {file_path} | "
        f"entropy={getattr(entropy_result, 'shannon_global', '?'):.4f} | "
        f"score={getattr(entropy_result, 'suspicion_score', 0):.2f}"
    )
    return event


def log_burst_detection(
    file_paths: list[str],
    window_seconds: int,
    event_count: int,
) -> dict:
    """
    Log a burst detection event: N anomalies in time window.
    This is the slow-encryption evasion countermeasure.
    """
    event = {
        "event_type":     EventType.BURST_DETECTED,
        "timestamp":      _now_iso(),
        "severity":       "CRITICAL",
        "file_paths":     file_paths,
        "window_seconds": window_seconds,
        "event_count":    event_count,
        "description":    (
            f"{event_count} anomalous file events detected within "
            f"{window_seconds}s window — consistent with time-distributed "
            f"(slow) ransomware encryption."
        ),
    }
    _write_event(event)
    _blockchain_record(event)
    logger.critical(
        f"[BURST] {event_count} events in {window_seconds}s — slow-encryption attack likely."
    )
    return event


def log_new_file_burst(
    new_files: list[str],
    window_seconds: int,
) -> dict:
    """
    Log a burst of new file creations (rename-and-re-encrypt pattern).
    Ransomware that creates new .enc/.locked files without modifying originals.
    """
    event = {
        "event_type":     "NEW_FILE_BURST",
        "timestamp":      _now_iso(),
        "severity":       "HIGH",
        "new_files":      new_files,
        "window_seconds": window_seconds,
        "description":    (
            f"{len(new_files)} new files created in {window_seconds}s — "
            f"possible rename-and-re-encrypt ransomware pattern."
        ),
    }
    _write_event(event)
    _blockchain_record(event)
    logger.warning(
        f"[RENAME-ENCRYPT] {len(new_files)} new files in {window_seconds}s"
    )
    return event


def log_process_kill(pid: int, file_path: str, success: bool) -> None:
    event = {
        "event_type": EventType.PROCESS_KILLED,
        "timestamp":  _now_iso(),
        "pid":        pid,
        "file_path":  file_path,
        "success":    success,
    }
    _write_event(event)
    _blockchain_record(event)


def log_quarantine(src_path: str, dest_path: Optional[str], success: bool) -> None:
    event = {
        "event_type": EventType.FILE_QUARANTINED,
        "timestamp":  _now_iso(),
        "src_path":   src_path,
        "dest_path":  dest_path,
        "success":    success,
        "sha256":     _sha256_file(dest_path) if dest_path and success else None,
    }
    _write_event(event)
    _blockchain_record(event)
    if success:
        logger.info(f"[QUARANTINE] {src_path} → {dest_path}")
    else:
        logger.error(f"[QUARANTINE FAILED] {src_path}")


def log_lockdown(lockdown_type: str, details: Any) -> None:
    etype = EventType.LOCKDOWN_FS if lockdown_type == "filesystem" else EventType.LOCKDOWN_NET
    event = {
        "event_type": etype,
        "timestamp":  _now_iso(),
        "type":       lockdown_type,
        "details":    details,
    }
    _write_event(event)
    _blockchain_record(event)
    logger.critical(f"[LOCKDOWN:{lockdown_type.upper()}] {details}")


def log_magic_mismatch(file_path: str, ext: str, detected: str) -> None:
    event = {
        "event_type":    EventType.MAGIC_MISMATCH,
        "timestamp":     _now_iso(),
        "severity":      "HIGH",
        "file_path":     file_path,
        "extension":     ext,
        "detected_type": detected,
        "description":   (
            f"File header does not match extension '{ext}'. "
            f"Detected as: '{detected}'. Possible FPE or ransomware rename."
        ),
    }
    _write_event(event)
    _blockchain_record(event)
    logger.warning(f"[MAGIC MISMATCH] {file_path}: declared={ext}, actual={detected}")


def read_events(last_n: int = 50) -> list[dict]:
    """Read the last N events from the JSONL log."""
    log_file = _log_path()
    if not log_file.exists():
        return []
    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        events = []
        for line in lines[-last_n:]:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events
    except Exception:
        return []
