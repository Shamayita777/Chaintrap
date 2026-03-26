"""
ChainTrap v2 — core/platform_ops.py

Cross-Platform OS Operations Abstraction Layer.

Patent Claim: "Platform-independent endpoint containment operations
               including process termination, atomic file quarantine
               with OS-native immutability enforcement, and coordinated
               network isolation across macOS, Windows, and Linux."

Replaces all hardcoded macOS-specific calls with platform-branching
implementations. Every public function works on macOS, Windows, Linux.
"""

import os
import sys
import stat
import signal
import shutil
import logging
import platform
import subprocess
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ChainTrap.platform")

PLATFORM = platform.system()   # 'Darwin' | 'Windows' | 'Linux'
IS_MACOS   = PLATFORM == "Darwin"
IS_WINDOWS = PLATFORM == "Windows"
IS_LINUX   = PLATFORM == "Linux"


# ─────────────────────────────────────────────
# PROCESS IDENTIFICATION
# ─────────────────────────────────────────────
def find_pids_for_file(path: str) -> list[int]:
    """
    Find all PIDs that currently have `path` open.
    Also finds PIDs writing to the PARENT DIRECTORY (catches
    ransomware that opens/closes files rapidly without holding them open).
    """
    pids: set[int] = set()
    parent_dir = str(Path(path).parent)

    # ── macOS / Linux: lsof ──────────────────────────────────────────────
    if not IS_WINDOWS:
        # Check both the specific file AND its parent directory
        for target in [path, parent_dir]:
            try:
                out = subprocess.check_output(
                    ["lsof", "-t", target],
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                ).decode(errors="ignore")
                for line in out.splitlines():
                    line = line.strip()
                    if line.isdigit():
                        pids.add(int(line))
            except (subprocess.CalledProcessError, FileNotFoundError,
                    subprocess.TimeoutExpired):
                pass

    # ── psutil fallback (all platforms) ──────────────────────────────────
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "open_files", "cwd"]):
            try:
                # Check open files
                for f in proc.info.get("open_files") or []:
                    fpath = getattr(f, "path", None)
                    if fpath and (fpath == path or fpath.startswith(parent_dir)):
                        pids.add(proc.pid)
                # Check if process is running FROM the attacked directory
                cwd = proc.info.get("cwd") or ""
                if cwd and cwd.startswith(parent_dir):
                    pids.add(proc.pid)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except ImportError:
        pass

    # Exclude our own PID — never kill ChainTrap itself
    pids.discard(os.getpid())

    return list(pids)


# ─────────────────────────────────────────────
# PROCESS TERMINATION
# ─────────────────────────────────────────────
def kill_process(pid: int) -> bool:
    """
    Forcefully terminate a process by PID.
    macOS/Linux: SIGKILL
    Windows:     TerminateProcess via psutil or taskkill
    """
    if IS_WINDOWS:
        return _kill_windows(pid)
    else:
        return _kill_posix(pid)


def kill_all_accessing_processes(path: str) -> list:
    """
    Kill ALL processes currently accessing a file or its directory.
    Returns list of PIDs killed.
    """
    pids = find_pids_for_file(path)
    killed_pids = []

    for pid in pids:
        if kill_process(pid):
            killed_pids.append(pid)
            logger.critical(f"[HARD-STOP] Killed PID {pid} (was accessing {path})")

    if not killed_pids:
        logger.warning(
            f"[HARD-STOP] No PIDs found for {path} via lsof/psutil. "
            f"Ransomware may be opening+closing files too fast. "
            f"Filesystem lockdown will still prevent further writes."
        )

    return killed_pids


def _kill_posix(pid: int) -> bool:
    """Send SIGKILL on macOS/Linux."""
    try:
        os.kill(pid, signal.SIGKILL)
        logger.warning(f"[KILL] SIGKILL sent to PID {pid}")
        return True
    except ProcessLookupError:
        logger.debug(f"PID {pid} already dead.")
        return False
    except PermissionError:
        logger.error(f"Cannot kill PID {pid}: permission denied (try sudo).")
        return False
    except Exception as e:
        logger.error(f"Kill PID {pid} failed: {e}")
        return False


def _kill_windows(pid: int) -> bool:
    """Terminate process on Windows."""
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.kill()
        logger.warning(f"[KILL] Windows process {pid} terminated via psutil.")
        return True
    except ImportError:
        pass
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, timeout=5
        )
        if result.returncode == 0:
            logger.warning(f"[KILL] taskkill /F /PID {pid} succeeded.")
            return True
    except Exception as e:
        logger.error(f"taskkill failed for PID {pid}: {e}")
    return False


# ─────────────────────────────────────────────
# IMMEDIATE FILE LOCK
# Applied to every suspicious file BEFORE quarantine
# ─────────────────────────────────────────────
def lock_file_immediately(path: str) -> bool:
    """
    Make a file read-only immediately upon detection.

    This is the FAST response — called before quarantine.
    Prevents the next write to this specific file from completing.

    Returns True if successfully locked.
    """
    try:
        if not Path(path).exists():
            return False
        # Remove write permission for everyone
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        logger.info(f"[LOCK] Immediate write-lock applied: {path}")
        return True
    except Exception as e:
        logger.warning(f"[LOCK] Could not lock {path}: {e}")
        return False


# ─────────────────────────────────────────────
# FILE QUARANTINE
# ─────────────────────────────────────────────
def atomic_quarantine(src_path: str, quarantine_dir: str) -> Optional[str]:
    """
    Move file to quarantine directory atomically and lock it.

    Steps:
      1. Make source read-only (slows ransomware)
      2. Attempt os.rename() (atomic if same filesystem)
      3. Fall back to shutil.move() (cross-filesystem)
      4. Apply immutability flag to quarantined file
      5. Return destination path or None on failure
    """
    dest_dir = Path(quarantine_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    src = Path(src_path)
    if not src.exists():
        logger.warning(f"Quarantine source gone: {src_path}")
        return None

    ts = str(int(os.getenv("_CHAINTRAP_TEST_TS", "") or 0) or
              int(__import__("time").time()))
    dest_name = f"{ts}_{src.name}"
    dest = dest_dir / dest_name

    # Step 1: make source read-only
    try:
        os.chmod(src_path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except Exception:
        pass

    # Step 2: atomic rename (same filesystem)
    try:
        src.rename(dest)
        logger.info(f"[QUARANTINE] rename: {src_path} → {dest}")
        _lock_file(str(dest))
        return str(dest)
    except OSError:
        pass

    # Step 3: shutil.move (cross-filesystem fallback)
    try:
        shutil.move(str(src), str(dest))
        logger.info(f"[QUARANTINE] move: {src_path} → {dest}")
        _lock_file(str(dest))
        return str(dest)
    except Exception as e:
        logger.error(f"[QUARANTINE] Failed to move {src_path}: {e}")
        return None


def _lock_file(path: str) -> None:
    """Apply OS-native immutability flag to quarantined file."""
    try:
        os.chmod(path, stat.S_IREAD)
    except Exception:
        pass

    if IS_MACOS:
        try:
            subprocess.run(["chflags", "uchg", path],
                           check=False, timeout=3, capture_output=True)
        except Exception:
            pass
    elif IS_LINUX:
        try:
            subprocess.run(["chattr", "+i", path],
                           check=False, timeout=3, capture_output=True)
        except Exception:
            pass
    elif IS_WINDOWS:
        try:
            subprocess.run(
                ["icacls", path, "/deny", "Everyone:(W,D,DC)"],
                check=False, timeout=3, capture_output=True
            )
        except Exception:
            pass


def unlock_file(path: str) -> None:
    """Remove immutability flag (for testing / recovery only)."""
    try:
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
    except Exception:
        pass
    if IS_MACOS:
        try:
            subprocess.run(["chflags", "nouchg", path],
                           check=False, timeout=3, capture_output=True)
        except Exception:
            pass
    elif IS_LINUX:
        try:
            subprocess.run(["chattr", "-i", path],
                           check=False, timeout=3, capture_output=True)
        except Exception:
            pass
    elif IS_WINDOWS:
        try:
            subprocess.run(
                ["icacls", path, "/grant", "Everyone:(F)"],
                check=False, timeout=3, capture_output=True
            )
        except Exception:
            pass


# ─────────────────────────────────────────────
# SYSTEM LOCKDOWN
# ─────────────────────────────────────────────
def lockdown_filesystem(protected_paths: list[str],
                        extra_dirs: Optional[list[str]] = None) -> None:
    """
    Restrict write access to protected directories AND any extra
    directories that are actively being attacked.

    FIX: The original only locked self.config["protected_dirs"].
    If the attack target is NOT in that list (e.g. demo_target/),
    the lockdown did nothing to the attacked folder.

    Now: we lock both configured protected_dirs AND the parent directory
    of whatever file triggered detection.

    macOS/Linux: chmod 444 (read+execute only — no writes)
    Windows:     icacls deny write
    """
    all_paths = list(protected_paths)
    if extra_dirs:
        all_paths.extend(extra_dirs)

    # Deduplicate
    seen = set()
    unique_paths = []
    for p in all_paths:
        rp = str(Path(p).resolve())
        if rp not in seen and Path(rp).exists():
            seen.add(rp)
            unique_paths.append(rp)

    logger.critical(
        f"[LOCKDOWN] Restricting write access to {len(unique_paths)} path(s): "
        f"{unique_paths}"
    )

    for p in unique_paths:
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["icacls", p, "/deny", "Everyone:(W)", "/T"],
                    check=False, timeout=10, capture_output=True
                )
            else:
                subprocess.run(
                    ["chmod", "-R", "444", p],
                    check=False, timeout=10, capture_output=True
                )
            logger.info(f"[LOCKDOWN] Write-locked: {p}")
        except Exception as e:
            logger.error(f"[LOCKDOWN] Failed to lock {p}: {e}")


def lockdown_network() -> list[str]:
    """Sever network connectivity to contain C2 communications."""
    logger.critical("[LOCKDOWN] Severing network connectivity.")
    actions = []

    if IS_MACOS:
        for iface in ["en0", "en1", "en2"]:
            try:
                r = subprocess.run(
                    ["networksetup", "-setairportpower", iface, "off"],
                    check=False, timeout=5, capture_output=True
                )
                if r.returncode == 0:
                    actions.append(f"macos_wifi_off:{iface}")
            except Exception:
                pass
        try:
            r = subprocess.run(
                ["networksetup", "-setv4off", "Ethernet"],
                check=False, timeout=5, capture_output=True
            )
            if r.returncode == 0:
                actions.append("macos_ethernet_off")
        except Exception:
            pass

    elif IS_LINUX:
        try:
            r = subprocess.run(
                ["nmcli", "networking", "off"],
                check=False, timeout=5, capture_output=True
            )
            if r.returncode == 0:
                actions.append("linux_nmcli_off")
        except FileNotFoundError:
            pass
        for iface in ["eth0", "eth1", "wlan0", "wlp2s0", "ens33", "enp0s3"]:
            try:
                r = subprocess.run(
                    ["ip", "link", "set", iface, "down"],
                    check=False, timeout=3, capture_output=True
                )
                if r.returncode == 0:
                    actions.append(f"linux_iface_down:{iface}")
            except Exception:
                pass

    elif IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.splitlines():
                if "Connected" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = " ".join(parts[3:])
                        try:
                            subprocess.run(
                                ["netsh", "interface", "set", "interface",
                                 iface_name, "disable"],
                                check=False, timeout=5, capture_output=True
                            )
                            actions.append(f"windows_iface_disabled:{iface_name}")
                        except Exception:
                            pass
        except Exception:
            pass

    if not actions:
        logger.warning(
            "[LOCKDOWN] Network: no interfaces disabled "
            "(may need elevated privileges — filesystem lockdown still active)."
        )
    else:
        logger.critical(f"[LOCKDOWN] Network actions: {actions}")

    return actions


# ─────────────────────────────────────────────
# DESKTOP NOTIFICATIONS
# ─────────────────────────────────────────────
def send_desktop_notification(title: str, message: str) -> bool:
    if IS_MACOS:
        return _notify_macos(title, message)
    elif IS_LINUX:
        return _notify_linux(title, message)
    elif IS_WINDOWS:
        return _notify_windows(title, message)
    return False


def _notify_macos(title: str, body: str) -> bool:
    body_escaped  = body.replace('"', '\\"').replace("'", "\\'")
    title_escaped = title.replace('"', '\\"')
    script = f'display notification "{body_escaped}" with title "{title_escaped}"'
    try:
        subprocess.run(["osascript", "-e", script],
                       check=False, timeout=5, capture_output=True)
        return True
    except Exception:
        return False


def _notify_linux(title: str, body: str) -> bool:
    try:
        subprocess.run(["notify-send", "--urgency=critical", title, body],
                       check=False, timeout=5, capture_output=True)
        return True
    except FileNotFoundError:
        try:
            subprocess.run(["zenity", "--warning",
                            f"--title={title}", f"--text={body}"],
                           check=False, timeout=5, capture_output=True)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _notify_windows(title: str, body: str) -> bool:
    script = f"""
$xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
    [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$xml.SelectSingleNode('//text[@id=1]').InnerText = '{title}'
$xml.SelectSingleNode('//text[@id=2]').InnerText = '{body}'
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('ChainTrap').Show($toast)
"""
    try:
        subprocess.run(["powershell", "-Command", script],
                       check=False, timeout=5, capture_output=True)
        return True
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(
                0, body, f"[CHAINTRAP ALERT] {title}", 0x10 | 0x1000)
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────
# DIRECTORY / PATH UTILITIES
# ─────────────────────────────────────────────
def ensure_dir_writable(path: str) -> bool:
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        test_file = Path(path) / ".chaintrap_write_test"
        test_file.touch()
        test_file.unlink()
        return True
    except Exception:
        return False


def preflight_setup(base_dir: str, quarantine_dir: str,
                    log_dir: str, chain_dir: str) -> None:
    """Ensure all ChainTrap directories exist with correct permissions."""
    for d in [base_dir, log_dir, chain_dir]:
        Path(d).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o750)
        except Exception:
            pass
    Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(quarantine_dir, 0o700)
    except Exception:
        pass
    logger.debug("Preflight setup complete.")