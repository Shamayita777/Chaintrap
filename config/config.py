"""
ChainTrap v2 — config/config.py
Cross-platform configuration manager.
Resolves all paths at runtime based on OS. No hardcoded user paths.

Patent Claim Support:
  - Abstracted platform layer enabling cross-platform deployment
  - All runtime paths derived from environment, not hardcoded
"""

import os
import sys
import platform
import json
from pathlib import Path


# ─────────────────────────────────────────────
# PLATFORM DETECTION
# ─────────────────────────────────────────────
PLATFORM = platform.system()   # 'Darwin' | 'Windows' | 'Linux'
IS_MACOS   = PLATFORM == "Darwin"
IS_WINDOWS = PLATFORM == "Windows"
IS_LINUX   = PLATFORM == "Linux"


# ─────────────────────────────────────────────
# BASE PATHS (runtime-resolved, cross-platform)
# ─────────────────────────────────────────────
HOME_DIR = Path.home()

# ChainTrap installs itself under HOME/ChainTrap by default;
# override via CHAINTRAP_BASE env variable for enterprise deployments.
BASE_DIR = Path(os.environ.get("CHAINTRAP_BASE", HOME_DIR / "ChainTrap")).resolve()

CHAIN_DIR      = BASE_DIR / "chain"
LOG_DIR        = BASE_DIR / "logs"
QUARANTINE_DIR = BASE_DIR / "quarantine"
DECOY_BASE_DIR = BASE_DIR / "decoys"
CONFIG_FILE    = BASE_DIR / "chaintrap.json"

LOG_FILE       = LOG_DIR / "events.jsonl"       # JSON-Lines for streaming appends
CHAIN_FILE     = CHAIN_DIR / "local_chain.json"


# ─────────────────────────────────────────────
# DECOY DISTRIBUTION DIRECTORIES
# Decoys are spread across real user directories for
# maximum tripwire coverage (patent claim: adaptive placement).
# ─────────────────────────────────────────────
def _default_decoy_dirs() -> list:
    """Return OS-appropriate decoy drop directories."""
    if IS_WINDOWS:
        user = Path(os.environ.get("USERPROFILE", HOME_DIR))
        return [
            str(user / "Documents"),
            str(user / "Desktop"),
            str(user / "Downloads"),
            str(user / "Pictures"),
            str(BASE_DIR / "decoys"),
        ]
    elif IS_MACOS:
        return [
            str(HOME_DIR / "Documents"),
            str(HOME_DIR / "Desktop"),
            str(HOME_DIR / "Downloads"),
            str(HOME_DIR / "Pictures"),
            str(BASE_DIR / "decoys"),
        ]
    else:  # Linux / other Unix
        return [
            str(HOME_DIR / "Documents"),
            str(HOME_DIR / "Desktop"),
            str(HOME_DIR / "Downloads"),
            str(HOME_DIR),
            str(BASE_DIR / "decoys"),
        ]


def _default_protected_dirs() -> list:
    """Real user directories we actively protect (not just tripwires)."""
    if IS_WINDOWS:
        user = Path(os.environ.get("USERPROFILE", HOME_DIR))
        return [str(user / "Documents"), str(user / "Desktop")]
    elif IS_MACOS:
        return [str(HOME_DIR / "Documents"), str(HOME_DIR / "Desktop")]
    else:
        return [str(HOME_DIR / "Documents"), str(HOME_DIR)]


# ─────────────────────────────────────────────
# DETECTION THRESHOLDS (tunable via config JSON)
# ─────────────────────────────────────────────
ENTROPY_ABSOLUTE_THRESHOLD = 7.2     # Bits — raised from naive 6.5
ENTROPY_DELTA_THRESHOLD    = 1.5     # Min jump in entropy between two hash events
WINDOW_SIZE_BYTES          = 4096    # Sliding window for segment entropy
CHI_P_VALUE_THRESHOLD      = 0.01    # p < 0.01 → reject null (data is random)
MAGIC_MISMATCH_ALERT       = True    # Alert on file-header / extension mismatch
BURST_WINDOW_SECONDS       = 600     # 10-minute window for slow-encryption detection
BURST_EVENT_THRESHOLD      = 3       # N anomalous events in window → lockdown
SCAN_INTERVAL_SECONDS      = 0.5     # Polling interval (used only as fallback)
MAX_WORKERS                = 64      # Thread pool ceiling
AUTO_LOCKDOWN              = True    # Network + FS lockdown on confirmed attack


# ─────────────────────────────────────────────
# WHITELIST
# Never quarantine or alert on these extensions.
# ─────────────────────────────────────────────
WHITELIST_EXT = {
    # Already-compressed / already-encrypted — entropy naturally high
    ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar",
    # Multimedia
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".flac", ".aac",
    # Images (lossy compressed)
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    # System / binary objects — high entropy expected
    ".so", ".dll", ".dylib", ".pyc",
}


# ─────────────────────────────────────────────
# BLOCKCHAIN REMOTE REPLICATION
# At minimum, events are appended to a remote endpoint.
# Supports: local-only (dev), IPFS, HTTP webhook, file-socket
# ─────────────────────────────────────────────
BLOCKCHAIN_MODE = os.environ.get("CHAINTRAP_CHAIN_MODE", "local")
# "local"   → chain.json only (dev/test — NOT production)
# "ipfs"    → pin each block to IPFS via local daemon / Infura
# "webhook" → POST each block JSON to BLOCKCHAIN_WEBHOOK_URL
# "dual"    → local + webhook simultaneously (recommended production)

BLOCKCHAIN_WEBHOOK_URL = os.environ.get(
    "CHAINTRAP_WEBHOOK_URL",
    ""   # e.g. "https://your-server.com/api/chaintrap/block"
)

IPFS_API_URL = os.environ.get(
    "CHAINTRAP_IPFS_URL",
    "http://127.0.0.1:5001"
)


# ─────────────────────────────────────────────
# ALERT CONFIGURATION
# ─────────────────────────────────────────────
ALERT_EMAIL_ENABLED  = False
ALERT_EMAIL_FROM     = os.environ.get("CHAINTRAP_EMAIL", "")
ALERT_EMAIL_PASSWORD = os.environ.get("CHAINTRAP_PASS", "")
ALERT_EMAIL_TO       = os.environ.get("CHAINTRAP_EMAIL_TO", ALERT_EMAIL_FROM)
ALERT_EMAIL_SMTP     = "smtp.gmail.com"
ALERT_EMAIL_PORT     = 465

# Desktop notifications (OS-native)
ALERT_DESKTOP_ENABLED = True


# ─────────────────────────────────────────────
# CANARY TOKEN SERVER
# HTTP beacon embedded in decoy files.
# When a decoy is opened/exfiltrated, the token fires.
# ─────────────────────────────────────────────
CANARY_TOKEN_ENABLED = False
CANARY_TOKEN_BASE_URL = os.environ.get(
    "CHAINTRAP_CANARY_URL",
    "https://canarytokens.org/generate"
)


# ─────────────────────────────────────────────
# USER-OVERRIDABLE CONFIG (loaded from chaintrap.json)
# ─────────────────────────────────────────────
def load_user_config() -> dict:
    """
    Load user config overrides from BASE_DIR/chaintrap.json.
    Merges onto defaults. Called once at startup.
    """
    if not CONFIG_FILE.exists():
        return {}
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def write_default_config():
    """Write a default chaintrap.json template if none exists."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        return
    defaults = {
        "entropy_absolute_threshold": ENTROPY_ABSOLUTE_THRESHOLD,
        "entropy_delta_threshold": ENTROPY_DELTA_THRESHOLD,
        "chi_p_value_threshold": CHI_P_VALUE_THRESHOLD,
        "burst_window_seconds": BURST_WINDOW_SECONDS,
        "burst_event_threshold": BURST_EVENT_THRESHOLD,
        "auto_lockdown": AUTO_LOCKDOWN,
        "blockchain_mode": BLOCKCHAIN_MODE,
        "blockchain_webhook_url": BLOCKCHAIN_WEBHOOK_URL,
        "alert_email_enabled": ALERT_EMAIL_ENABLED,
        "alert_desktop_enabled": ALERT_DESKTOP_ENABLED,
        "canary_token_enabled": CANARY_TOKEN_ENABLED,
        "decoy_dirs": _default_decoy_dirs(),
        "protected_dirs": _default_protected_dirs(),
        "whitelist_ext": sorted(WHITELIST_EXT),
        "comment": (
            "Edit this file to customize ChainTrap. "
            "Restart ChainTrap for changes to take effect."
        ),
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(defaults, f, indent=2)
    print(f"[ChainTrap] Default config written to {CONFIG_FILE}")


# Apply user overrides at import time
_user = load_user_config()
ENTROPY_ABSOLUTE_THRESHOLD = _user.get("entropy_absolute_threshold", ENTROPY_ABSOLUTE_THRESHOLD)
ENTROPY_DELTA_THRESHOLD    = _user.get("entropy_delta_threshold", ENTROPY_DELTA_THRESHOLD)
CHI_P_VALUE_THRESHOLD      = _user.get("chi_p_value_threshold", CHI_P_VALUE_THRESHOLD)
BURST_WINDOW_SECONDS       = _user.get("burst_window_seconds", BURST_WINDOW_SECONDS)
BURST_EVENT_THRESHOLD      = _user.get("burst_event_threshold", BURST_EVENT_THRESHOLD)
AUTO_LOCKDOWN              = _user.get("auto_lockdown", AUTO_LOCKDOWN)
BLOCKCHAIN_MODE            = _user.get("blockchain_mode", BLOCKCHAIN_MODE)
BLOCKCHAIN_WEBHOOK_URL     = _user.get("blockchain_webhook_url", BLOCKCHAIN_WEBHOOK_URL)
ALERT_EMAIL_ENABLED        = _user.get("alert_email_enabled", ALERT_EMAIL_ENABLED)
ALERT_DESKTOP_ENABLED      = _user.get("alert_desktop_enabled", ALERT_DESKTOP_ENABLED)
CANARY_TOKEN_ENABLED       = _user.get("canary_token_enabled", CANARY_TOKEN_ENABLED)

# Directory lists (resolved at runtime)
DECOY_DIRS     = [d for d in _user.get("decoy_dirs", _default_decoy_dirs()) if Path(d).exists() or True]
PROTECTED_DIRS = [d for d in _user.get("protected_dirs", _default_protected_dirs()) if Path(d).exists() or True]
WHITELIST_EXT  = set(_user.get("whitelist_ext", sorted(WHITELIST_EXT)))
