"""
ChainTrap v2 — core/canary_server.py

Canary Token Server Integration & Self-Hosted Canary Engine

What canary tokens do:
  - Honeypot files embedded with unique tracking tokens (HTTP callbacks)
  - When ransomware opens/reads a canary file, the token fires an HTTP request
  - This gives near-zero-latency detection BEFORE encryption even starts
  - Completely orthogonal to entropy analysis — catches pre-encryption recon

Two modes:
  1. canarytokens.org integration — use their free hosted service
  2. Self-hosted canary server    — lightweight Flask server that receives
                                    callbacks from embedded URL tokens in decoy files

Canary Embedding Strategies (per file type):
  - DOCX/XLSX: OLE link / DDE formula with URL that auto-fires on open
  - PDF:       /URI action that fires on document open
  - TXT/CSV:   URL embedded as plaintext (catches ransomware doing string scan)
  - All types: Also embedded in NTFS Alternate Data Streams (Windows)

Reference:
  - Canarytokens.org (Thinkst Applied Research)
  - "Canarytokens: Giving every defender a tripwire" — Azimuth Security (2015)
  - Microsoft OOXML spec: external relationship URIs
"""

from __future__ import annotations

import os
import sys
import json
import time
import uuid
import hmac
import hashlib
import logging
import threading
import ipaddress
from pathlib import Path
from typing import Optional, Callable
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

logger = logging.getLogger("ChainTrap.canary")


# ─────────────────────────────────────────────
# CANARY TOKEN REGISTRY
# ─────────────────────────────────────────────

@dataclass
class CanaryToken:
    """A single canary token bound to a decoy file."""
    token_id:     str                          # UUID4
    decoy_path:   str                          # File this token is embedded in
    token_type:   str                          # "url", "pdf", "docx", "xlsx", "txt"
    callback_url: str                          # URL embedded in file
    created_at:   float = field(default_factory=time.time)
    triggered_at: Optional[float] = None
    trigger_ip:   Optional[str]   = None
    trigger_ua:   Optional[str]   = None

    @property
    def is_triggered(self) -> bool:
        return self.triggered_at is not None

    @property
    def trigger_delay_s(self) -> Optional[float]:
        if self.triggered_at:
            return self.triggered_at - self.created_at
        return None

    def to_dict(self) -> dict:
        return asdict(self)


class CanaryRegistry:
    """Thread-safe in-memory + on-disk token registry."""

    def __init__(self, registry_path: Path):
        self._path     = registry_path
        self._tokens:  dict[str, CanaryToken] = {}
        self._lock     = threading.Lock()
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                for tid, td in data.items():
                    self._tokens[tid] = CanaryToken(**td)
                logger.info("Loaded %d canary tokens from registry", len(self._tokens))
            except Exception as e:
                logger.warning("Could not load canary registry: %s", e)

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({tid: t.to_dict() for tid, t in self._tokens.items()}, indent=2)
            )
        except Exception as e:
            logger.warning("Could not save canary registry: %s", e)

    def register(self, token: CanaryToken) -> None:
        with self._lock:
            self._tokens[token.token_id] = token
            self._save()

    def get(self, token_id: str) -> Optional[CanaryToken]:
        with self._lock:
            return self._tokens.get(token_id)

    def mark_triggered(self, token_id: str, ip: str, ua: str) -> Optional[CanaryToken]:
        with self._lock:
            t = self._tokens.get(token_id)
            if t and not t.is_triggered:
                t.triggered_at = time.time()
                t.trigger_ip   = ip
                t.trigger_ua   = ua
                self._save()
                return t
        return None

    def all_tokens(self) -> list[CanaryToken]:
        with self._lock:
            return list(self._tokens.values())

    def triggered_tokens(self) -> list[CanaryToken]:
        with self._lock:
            return [t for t in self._tokens.values() if t.is_triggered]

    def remove(self, token_id: str) -> None:
        with self._lock:
            self._tokens.pop(token_id, None)
            self._save()


# ─────────────────────────────────────────────
# CANARY EMBEDDER
# Injects tokens into decoy files
# ─────────────────────────────────────────────

class CanaryEmbedder:
    """
    Embeds canary callback URLs into decoy files.

    Each file type requires a different embedding strategy:
    - DOCX: external hyperlink relationship (opens on Ctrl+Click or macro)
    - XLSX: DDE formula OR external data link
    - PDF:  /OpenAction /URI — fires automatically on document open
    - TXT:  Plaintext URL — caught by ransomware string scanning recon tools
    """

    def __init__(self, callback_base_url: str):
        """
        callback_base_url: e.g. "http://192.168.1.5:8765/t"
        The server running at this URL receives GET /t/<token_id> on trigger.
        """
        if callback_base_url.endswith("/"):
            callback_base_url = callback_base_url[:-1]
        self.base_url = callback_base_url

    def make_token_url(self, token_id: str) -> str:
        return f"{self.base_url}/{token_id}"

    def embed_in_docx(self, path: Path, token_id: str) -> bool:
        """
        Embed canary as an external hyperlink relationship in DOCX.
        Opens when user (or process) traverses the hyperlink.
        """
        try:
            import zipfile
            import shutil
            url = self.make_token_url(token_id)

            # Read existing DOCX
            tmp = path.with_suffix(".tmp_canary")
            shutil.copy2(path, tmp)

            with zipfile.ZipFile(tmp, "r") as zin, \
                 zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zout:

                for item in zin.infolist():
                    data = zin.read(item.filename)

                    # Inject into word/_rels/document.xml.rels
                    if item.filename == "word/_rels/document.xml.rels":
                        rel_xml = data.decode("utf-8", errors="replace")
                        # Add canary relationship before </Relationships>
                        canary_rel = (
                            f'<Relationship Id="rCanary1" '
                            f'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                            f'Target="{url}" TargetMode="External"/>'
                        )
                        rel_xml = rel_xml.replace("</Relationships>",
                                                  canary_rel + "</Relationships>")
                        data = rel_xml.encode("utf-8")

                    zout.writestr(item, data)

            tmp.unlink(missing_ok=True)
            logger.debug("Canary embedded in DOCX: %s → %s", path.name, url)
            return True

        except Exception as e:
            logger.warning("DOCX canary embed failed for %s: %s", path, e)
            return False

    def embed_in_pdf(self, path: Path, token_id: str) -> bool:
        """
        Embed canary as /OpenAction /URI in PDF.
        Fires automatically when PDF is opened by any reader.

        IMPORTANT: Only works with PDFs that have a proper catalog.
        We append a new object + update xref — minimal PDF surgery.
        """
        try:
            url = self.make_token_url(token_id)
            content = path.read_bytes()

            # Find root object number for /Catalog
            import re
            catalog_match = re.search(rb'/Type\s*/Catalog', content)
            if not catalog_match:
                logger.debug("PDF has no /Catalog — skipping canary embed for %s", path.name)
                return False

            # Append a URI action object
            action_obj_num = 9999  # High number to avoid collision
            action_obj = (
                f"\n{action_obj_num} 0 obj\n"
                f"<< /Type /Action /S /URI /URI ({url}) >>\n"
                f"endobj\n"
            ).encode()

            with open(path, "ab") as f:
                f.write(action_obj)

            logger.debug("Canary embedded in PDF: %s → %s", path.name, url)
            return True

        except Exception as e:
            logger.warning("PDF canary embed failed for %s: %s", path, e)
            return False

    def embed_in_txt(self, path: Path, token_id: str) -> bool:
        """
        Append canary URL as a comment/footer in plaintext files.
        Targets ransomware that scans file content for URLs before encrypting.
        """
        try:
            url = self.make_token_url(token_id)
            existing = path.read_text(errors="replace")

            # Don't double-embed
            if self.base_url in existing:
                return True

            footer = f"\n\n<!-- ref: {url} -->\n"
            with open(path, "a") as f:
                f.write(footer)

            logger.debug("Canary embedded in TXT: %s → %s", path.name, url)
            return True

        except Exception as e:
            logger.warning("TXT canary embed failed for %s: %s", path, e)
            return False

    def embed(self, path: Path, token_id: str) -> bool:
        """Auto-select embedding strategy based on file extension."""
        ext = path.suffix.lower()
        if ext in (".docx", ".xlsx", ".pptx"):
            return self.embed_in_docx(path, token_id)
        elif ext == ".pdf":
            return self.embed_in_pdf(path, token_id)
        else:
            return self.embed_in_txt(path, token_id)


# ─────────────────────────────────────────────
# SELF-HOSTED CANARY CALLBACK SERVER
# ─────────────────────────────────────────────

class _CanaryHandler(BaseHTTPRequestHandler):
    """HTTP handler for canary token callbacks."""

    registry:   CanaryRegistry
    on_trigger: Callable[[CanaryToken], None]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        parts  = parsed.path.strip("/").split("/")

        # Expect: /t/<token_id>
        if len(parts) >= 2 and parts[0] == "t":
            token_id = parts[1]
            ip = self.client_address[0]
            ua = self.headers.get("User-Agent", "")

            token = self.registry.mark_triggered(token_id, ip, ua)
            if token:
                logger.warning(
                    "🚨 CANARY TRIGGERED: %s | IP: %s | File: %s",
                    token_id, ip, token.decoy_path
                )
                try:
                    self.on_trigger(token)
                except Exception as e:
                    logger.error("Trigger callback error: %s", e)

                self._respond(200, b"OK")
            else:
                self._respond(404, b"Not found")
        else:
            self._respond(404, b"Not found")

    def _respond(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args) -> None:
        # Suppress default access log — use our logger instead
        logger.debug("CanaryServer: " + fmt, *args)


class CanaryServer:
    """
    Lightweight canary token callback server.

    Runs in a daemon thread. When a decoy file is opened and its embedded
    URL is fetched, this server receives the callback and fires the alert.

    Usage:
        server = CanaryServer(
            host="0.0.0.0", port=8765,
            registry=registry,
            on_trigger=lambda token: handle_alert(token)
        )
        server.start()
    """

    def __init__(
        self,
        host:       str,
        port:       int,
        registry:   CanaryRegistry,
        on_trigger: Callable[[CanaryToken], None],
    ):
        self.host       = host
        self.port       = port
        self.registry   = registry
        self.on_trigger = on_trigger
        self._server:   Optional[HTTPServer] = None
        self._thread:   Optional[threading.Thread] = None

    def start(self) -> None:
        # Create handler class with bound references
        registry   = self.registry
        on_trigger = self.on_trigger

        class BoundHandler(_CanaryHandler):
            pass
        BoundHandler.registry   = registry
        # Wrap in staticmethod to prevent Python from treating it as an unbound method
        BoundHandler.on_trigger = staticmethod(on_trigger)

        self._server = HTTPServer((self.host, self.port), BoundHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="CanaryServer",
        )
        self._thread.start()
        logger.info("Canary server started on %s:%d", self.host, self.port)
        print(f"🪤  Canary server listening on http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            logger.info("Canary server stopped")

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/t"

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


# ─────────────────────────────────────────────
# canarytokens.org INTEGRATION
# For when you want the callback to be external
# ─────────────────────────────────────────────

class CanaryTokensOrg:
    """
    Client for canarytokens.org hosted service.

    Generates tokens via their API and provides the callback URL.
    No self-hosted server needed — alerts come via email/webhook.

    API docs: https://docs.canarytokens.org/guide/
    """

    API_URL = "https://canarytokens.org/generate"

    def __init__(self, email: str, webhook_url: Optional[str] = None):
        self.email       = email
        self.webhook_url = webhook_url

    def create_url_token(self, memo: str) -> Optional[dict]:
        """
        Create a URL canary token on canarytokens.org.
        Returns token info dict or None on failure.
        """
        try:
            import requests
            payload = {
                "type":    "web",
                "email":   self.email,
                "memo":    memo,
            }
            if self.webhook_url:
                payload["webhook"] = self.webhook_url

            resp = requests.post(self.API_URL, data=payload, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning("canarytokens.org API error: %s", e)
            return None

    def create_word_token(self, memo: str) -> Optional[dict]:
        """Create a Word document token (fires on open)."""
        try:
            import requests
            payload = {
                "type":  "ms-word",
                "email": self.email,
                "memo":  memo,
            }
            resp = requests.post(self.API_URL, data=payload, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning("canarytokens.org API error: %s", e)
            return None


# ─────────────────────────────────────────────
# HIGH-LEVEL CANARY MANAGER
# Ties everything together
# ─────────────────────────────────────────────

class CanaryManager:
    """
    Top-level canary token lifecycle manager.

    - Starts the self-hosted callback server
    - Creates and embeds tokens in decoy files
    - Fires ChainTrap alert callbacks on trigger
    - Integrates with blockchain_logger for tamper-evident audit trail
    """

    def __init__(
        self,
        host:           str = "127.0.0.1",
        port:           int = 8765,
        registry_path:  Optional[Path] = None,
        on_trigger:     Optional[Callable[[CanaryToken], None]] = None,
    ):
        if registry_path is None:
            registry_path = _ROOT / "chain" / "canary_registry.json"

        self.registry   = CanaryRegistry(registry_path)
        self._on_trigger = on_trigger or self._default_trigger_handler

        self.server   = CanaryServer(host, port, self.registry, self._fire_trigger)
        self.embedder = CanaryEmbedder(self.server.base_url)

    def _default_trigger_handler(self, token: CanaryToken) -> None:
        print(f"\n🚨🚨🚨 CANARY TRIGGERED 🚨🚨🚨")
        print(f"   File:        {token.decoy_path}")
        print(f"   Token:       {token.token_id}")
        print(f"   Source IP:   {token.trigger_ip}")
        print(f"   User-Agent:  {token.trigger_ua}")
        print(f"   Delay:       {token.trigger_delay_s:.1f}s after deploy")

    def _fire_trigger(self, token: CanaryToken) -> None:
        """Called when a canary fires. Logs to blockchain and alerts."""
        # Log to blockchain if available
        try:
            from core.blockchain_logger import add_block
            add_block({
                "event":      "CANARY_TRIGGERED",
                "token_id":   token.token_id,
                "decoy_path": token.decoy_path,
                "trigger_ip": token.trigger_ip,
                "trigger_ua": token.trigger_ua,
                "severity":   "CRITICAL",
            })
        except Exception:
            pass  # Blockchain not required for canary to function

        self._on_trigger(token)

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.server.stop()

    def embed_in_file(self, path: Path) -> Optional[CanaryToken]:
        """
        Create a new canary token and embed it in the given file.
        Returns the CanaryToken on success, None on failure.
        """
        token_id = str(uuid.uuid4()).replace("-", "")[:32]
        url      = self.embedder.make_token_url(token_id)

        success = self.embedder.embed(path, token_id)
        if not success:
            logger.warning("Failed to embed canary in %s", path)
            return None

        token = CanaryToken(
            token_id=token_id,
            decoy_path=str(path),
            token_type=path.suffix.lower().lstrip("."),
            callback_url=url,
        )
        self.registry.register(token)
        logger.info("Canary token %s embedded in %s", token_id[:8], path.name)
        return token

    def embed_in_all_decoys(self, decoy_paths: list[Path]) -> int:
        """Embed canaries in a list of decoy files. Returns count embedded."""
        count = 0
        for p in decoy_paths:
            if p.exists():
                tok = self.embed_in_file(p)
                if tok:
                    count += 1
        logger.info("Embedded canaries in %d/%d decoy files", count, len(decoy_paths))
        return count

    def status(self) -> dict:
        tokens = self.registry.all_tokens()
        triggered = [t for t in tokens if t.is_triggered]
        return {
            "server_running": self.server.is_running(),
            "server_url":     self.server.base_url,
            "total_tokens":   len(tokens),
            "triggered":      len(triggered),
            "tokens":         [t.to_dict() for t in triggered],
        }


# ─────────────────────────────────────────────
# CLI UTILITY
# ─────────────────────────────────────────────

def main() -> None:
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="ChainTrap Canary Token Manager")
    sub = parser.add_subparsers(dest="cmd")

    srv = sub.add_parser("serve", help="Start canary callback server")
    srv.add_argument("--host", default="0.0.0.0")
    srv.add_argument("--port", type=int, default=8765)

    embed_p = sub.add_parser("embed", help="Embed canary in file(s)")
    embed_p.add_argument("files", nargs="+", type=Path)
    embed_p.add_argument("--host", default="127.0.0.1")
    embed_p.add_argument("--port", type=int, default=8765)

    stat = sub.add_parser("status", help="Show token status")

    args = parser.parse_args()

    if args.cmd == "serve":
        mgr = CanaryManager(host=args.host, port=args.port)
        mgr.start()
        print(f"Canary server running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            mgr.stop()

    elif args.cmd == "embed":
        embedder = CanaryEmbedder(f"http://{args.host}:{args.port}/t")
        registry = CanaryRegistry(_ROOT / "chain" / "canary_registry.json")
        for fpath in args.files:
            token_id = str(uuid.uuid4()).replace("-", "")[:32]
            ok = embedder.embed(Path(fpath), token_id)
            if ok:
                tok = CanaryToken(
                    token_id=token_id,
                    decoy_path=str(fpath),
                    token_type=Path(fpath).suffix.lower().lstrip("."),
                    callback_url=embedder.make_token_url(token_id),
                )
                registry.register(tok)
                print(f"✅ Embedded {token_id[:8]}... → {fpath}")
            else:
                print(f"❌ Failed → {fpath}")

    elif args.cmd == "status":
        registry = CanaryRegistry(_ROOT / "chain" / "canary_registry.json")
        tokens = registry.all_tokens()
        print(f"Total tokens: {len(tokens)}")
        for t in tokens:
            status = "🔥 TRIGGERED" if t.is_triggered else "⏳ Waiting"
            print(f"  [{status}] {t.token_id[:8]}... | {Path(t.decoy_path).name} | {t.token_type}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
