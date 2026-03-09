"""
ChainTrap v2 — core/blockchain_logger.py

Tamper-Evident Dual-Mode Blockchain Logger.

Patent Claim: "Cryptographically linked audit log with dual-mode replication
               — local SHA-256 linked chain plus remote append-only ledger —
               ensuring tamper evidence survives compromise of the endpoint."

Modes:
  "local"   → chain.json (development only — NOT tamper-resistant)
  "webhook" → each block POST-ed to remote HTTPS endpoint
  "dual"    → local chain.json + webhook simultaneously (production)
  "ipfs"    → each block pinned to IPFS, CID stored in local chain

All modes maintain local chain for offline forensic verification.
The remote copy is the tamper-evident anchor.

Block Schema:
  {
    "index":     int,           # Monotonically increasing
    "timestamp": float,         # Unix epoch (UTC)
    "data":      dict,          # Event payload
    "prev_hash": str,           # SHA-256 of previous block
    "hash":      str,           # SHA-256 of this block (excl. "hash" field)
    "node_id":   str,           # Machine fingerprint (non-PII)
  }
"""

import os
import json
import time
import uuid
import hashlib
import logging
import platform
import threading
from pathlib import Path
from typing import Optional, Any
from datetime import datetime, timezone
from importlib import import_module

try:
    cfg = import_module("config.config")
    CHAIN_FILE = cfg.CHAIN_FILE
except Exception:
    # fallback for test isolation
    CHAIN_FILE = str(Path.home() / "ChainTrap" / "chain" / "local_chain.json")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

logger = logging.getLogger("ChainTrap.blockchain")

# ─────────────────────────────────────────────
# NODE FINGERPRINT
# Stable per-machine ID using MAC address + hostname hash.
# Non-PII — only used to correlate blocks from same endpoint.
# ─────────────────────────────────────────────
def _node_id() -> str:
    """Generate stable, non-PII node identifier."""
    mac = str(uuid.getnode())
    host = platform.node()
    raw = f"{mac}:{host}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


NODE_ID = _node_id()

# Thread lock for chain write operations
_chain_lock = threading.Lock()
_chain = []

# ─────────────────────────────────────────────
# BLOCK OPERATIONS
# ─────────────────────────────────────────────
def _block_hash(block: dict) -> str:
    """Compute SHA-256 over all block fields except 'hash' itself."""
    payload = {k: v for k, v in block.items() if k != "hash"}
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _create_block(index: int, data: Any, prev_hash: str) -> dict:
    """Create and sign a new chain block."""
    block = {
        "index": index,
        "timestamp": time.time(),
        "data": data,
        "prev_hash": prev_hash,
        "node_id": NODE_ID,
    }
    block["hash"] = _block_hash(block)
    return block

def _genesis_block() -> dict:
    return _create_block(
        index=0,
        data={"event_type": "GENESIS"},
        prev_hash="0" * 64,
    )

# ─────────────────────────────────────────────
# LOCAL CHAIN (JSON file)
# ─────────────────────────────────────────────
def _chain_path() -> Path:
    """Resolve chain file path from module-level CHAIN_FILE."""
    return Path(CHAIN_FILE)


def _load_chain() -> list:
    path = _chain_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        chain = [_genesis_block()]
        _save_chain(chain)
        logger.info("Genesis block created.")
        return chain
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Chain file corrupted: {e}. Reinitializing.")
        chain = [_genesis_block()]
        _save_chain(chain)
        return chain


def _save_chain(chain: list) -> None:
    path = _chain_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(chain, f, indent=2)
        tmp.replace(path)   # Atomic rename
    except OSError as e:
        logger.error(f"Failed to persist chain: {e}")


# ─────────────────────────────────────────────
# REMOTE REPLICATION
# ─────────────────────────────────────────────
def _post_to_webhook(block: dict, url: str) -> bool:
    """
    POST block to remote webhook endpoint.

    The remote server is the tamper-resistant anchor.
    Even if the attacker deletes the local chain, the remote
    copy contains all events up to the point of the attack.
    """
    if not HAS_REQUESTS:
        logger.warning("requests library not installed. Install: pip install requests")
        return False
    if not url:
        return False
    try:
        resp = requests.post(
            url,
            json=block,
            timeout=5,
            headers={
                "Content-Type":  "application/json",
                "X-ChainTrap-Node": NODE_ID,
                "X-ChainTrap-Version": "2.0",
            }
        )
        if resp.status_code in (200, 201, 202, 204):
            logger.debug(f"Block {block['index']} replicated to webhook.")
            return True
        else:
            logger.warning(f"Webhook returned {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        logger.warning(f"Webhook replication failed: {e}")
        return False


def _pin_to_ipfs(block: dict, api_url: str) -> Optional[str]:
    """
    Pin block JSON to IPFS via local daemon or Infura API.
    Returns CID on success, None on failure.

    IPFS provides content-addressed, decentralized storage.
    The CID is a cryptographic commitment to the block content.
    """
    if not HAS_REQUESTS:
        return None
    if not api_url:
        return None
    try:
        payload = json.dumps(block, sort_keys=True).encode("utf-8")
        resp = requests.post(
            f"{api_url.rstrip('/')}/api/v0/add",
            files={"file": ("block.json", payload, "application/json")},
            timeout=10,
        )
        if resp.status_code == 200:
            cid = resp.json().get("Hash")
            logger.info(f"Block {block['index']} pinned to IPFS: {cid}")
            return cid
        return None
    except Exception as e:
        logger.warning(f"IPFS pin failed: {e}")
        return None


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────
def init_chain() -> dict:
    global _chain

    with _chain_lock:
        _chain = _load_chain()

        if not _chain:
            genesis = _genesis_block()
            _chain = [genesis]
            _save_chain(_chain)

    return _chain[0]

def add_event(event_data: dict) -> dict:
    """
    Add a ransomware detection event to the chain.

    This is the primary public API. Call this whenever a detection
    event occurs. The function:
      1. Appends block to local chain.json
      2. Replicates to remote (webhook / IPFS) based on config mode.
      3. Returns the new block for logging.

    Args:
        event_data: Dict containing all event fields (see monitor.py)

    Returns:
        The newly created and signed block.

    Thread-safe: Uses lock on local chain write.
    """
    # Import config at call time (not module import) to allow config reloads
    try:
        from config import (
            BLOCKCHAIN_MODE,
            BLOCKCHAIN_WEBHOOK_URL,
            IPFS_API_URL,
        )
    except ImportError:
        BLOCKCHAIN_MODE = "local"
        BLOCKCHAIN_WEBHOOK_URL = ""
        IPFS_API_URL = "http://127.0.0.1:5001"

    with _chain_lock:
        chain = _load_chain()
        prev_hash = chain[-1]["hash"]
        new_block = _create_block(
            index=len(chain),
            data=event_data,
            prev_hash=prev_hash,
        )
        chain.append(new_block)
        _save_chain(chain)

    logger.info(
        f"Block #{new_block['index']} added. "
        f"Hash: {new_block['hash'][:12]}... "
        f"Mode: {BLOCKCHAIN_MODE}"
    )

    # Remote replication (non-blocking via thread)
    def _replicate():
        if BLOCKCHAIN_MODE in ("webhook", "dual"):
            success = _post_to_webhook(new_block, BLOCKCHAIN_WEBHOOK_URL)
            if not success and BLOCKCHAIN_MODE == "dual":
                # Log replication failure — forensically significant
                logger.error(
                    f"REPLICATION FAILURE for block #{new_block['index']}. "
                    f"Local chain intact but remote anchor NOT updated. "
                    f"This may indicate network disruption by ransomware."
                )

        if BLOCKCHAIN_MODE == "ipfs":
            cid = _pin_to_ipfs(new_block, IPFS_API_URL)
            if cid:
                # Store CID in local chain for cross-reference
                with _chain_lock:
                    c = _load_chain()
                    for blk in c:
                        if blk["index"] == new_block["index"]:
                            blk["ipfs_cid"] = cid
                    _save_chain(c)

    threading.Thread(target=_replicate, daemon=True).start()
    return new_block
def add_block(data: dict) -> dict:
    """
    Compatibility wrapper for test suite.
    """
    block = add_event(data)

    global _chain
    with _chain_lock:
        _chain = _load_chain()

    return block

def verify_chain() -> dict:
    """
    Verify the integrity of the entire local chain.

    Checks:
      1. Each block's hash is correctly computed.
      2. Each block's prev_hash matches the previous block's hash.
      3. Genesis block is intact.

    Returns:
        {
          "ok": bool,
          "blocks_verified": int,
          "errors": list[str],
          "chain_length": int,
        }
    """
    with _chain_lock:
        chain = _load_chain()

    errors = []

    # Check genesis
    genesis = chain[0]
    if genesis["prev_hash"] != "0" * 64:
        errors.append("GENESIS block prev_hash tampered.")

    for i in range(len(chain)):
        blk = chain[i]
        # Verify self-hash
        computed = _block_hash(blk)
        if computed != blk.get("hash"):
            errors.append(
                f"Block {i}: hash mismatch "
                f"(stored={blk.get('hash', 'MISSING')[:12]}..., "
                f"computed={computed[:12]}...)"
            )

        # Verify chain linkage
        if i > 0:
            prev = chain[i - 1]
            if blk.get("prev_hash") != prev.get("hash"):
                errors.append(
                    f"Block {i}: prev_hash broken "
                    f"(points to {blk.get('prev_hash','?')[:12]}..., "
                    f"actual prev={prev.get('hash','?')[:12]}...)"
                )

    return {
        "ok": len(errors) == 0,
        "blocks_verified": len(chain),
        "errors": errors,
        "chain_length": len(chain),
    }


def get_chain_summary() -> dict:
    """Return summary statistics about the chain."""
    with _chain_lock:
        chain = _load_chain()

    ransomware_events = [
        b for b in chain
        if isinstance(b.get("data"), dict)
        and b["data"].get("event_type") in ("DECOY_TRIGGERED", "PROTECTED_TRIGGERED", "RANSOMWARE_DETECTED",)
    ]

    return {
        "chain_length":      len(chain),
        "node_id":           NODE_ID,
        "genesis_timestamp": chain[0].get("timestamp"),
        "latest_timestamp": chain[-1].get("timestamp") if len(chain) > 1 else None,
        "ransomware_events": len(ransomware_events),
        "chain_head_hash":   chain[-1].get("hash", "")[:16] + "...",
    }


def print_chain(last_n: int = 10) -> None:
    """Pretty-print the last N blocks to stdout."""
    with _chain_lock:
        chain = _load_chain()

    print(f"\n{'═'*60}")
    print(f"  ChainTrap Local Blockchain  — {len(chain)} blocks  [Node: {NODE_ID}]")
    print(f"{'═'*60}")
    for blk in chain[-last_n:]:
        print(json.dumps(blk, indent=2, default=str))
        print("─" * 60)
# Initialize chain when module loads
try:
    init_chain()
except Exception:
    pass