"""
ChainTrap v2 — tests/test_decoy_and_canary.py

Tests for:
  - DecoyManager: dynamic honeyfile generation, realism, OOXML validity
  - CanaryServer: token registration, callback dispatch, registry persistence
  - CanaryEmbedder: DOCX/TXT injection
"""

import os
import sys
import json
import time
import uuid
import zipfile
import tempfile
import threading
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "config"))

from core.decoy_manager import (
    deploy_decoy_swarm, get_decoy_paths, is_decoy,
    get_decoy_registry, refresh_decoys,
)
from core.canary_server import (
    CanaryToken, CanaryRegistry, CanaryEmbedder,
    CanaryServer, CanaryManager,
)


# ─────────────────────────────────────────────
# DECOY MANAGER TESTS
# ─────────────────────────────────────────────

class TestDecoyManager:

    def test_deploy_creates_files(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=5)
        assert len(paths) >= 5
        for p in paths:
            assert Path(p).exists(), f"Decoy file missing: {p}"

    def test_decoy_files_have_plausible_names(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=10)
        plausible_exts = {".docx", ".xlsx", ".pdf", ".csv", ".txt", ".pptx"}
        extensions = {Path(p).suffix.lower() for p in paths}
        # At least some should be common office formats
        assert extensions & plausible_exts, \
            f"No plausible office extensions in decoys: {extensions}"

    def test_decoy_files_have_content(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=5)
        for p in paths:
            size = Path(p).stat().st_size
            assert size >= 1024, f"Decoy file too small: {p} ({size} bytes)"

    def test_decoy_files_min_50kb(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=5)
        sizes = [Path(p).stat().st_size for p in paths]
        # At least half should be >= 50KB
        large = sum(1 for s in sizes if s >= 50_000)
        assert large >= len(paths) // 2, \
            f"Decoys too small: sizes={sizes}"

    def test_is_decoy_returns_true_for_deployed(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=3)
        for p in paths:
            assert is_decoy(p), f"is_decoy returned False for deployed file: {p}"

    def test_is_decoy_returns_false_for_normal(self, tmp_path):
        normal = tmp_path / "normal.docx"
        normal.write_bytes(b"PK\x03\x04" + b"\x00" * 1000)
        assert not is_decoy(str(normal))

    def test_get_decoy_paths_returns_deployed(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=4)
        registered = get_decoy_paths(str(tmp_path))
        for p in paths:
            assert p in registered or Path(p).name in [Path(r).name for r in registered]

    def test_docx_decoy_valid_ooxml(self, tmp_path):
        """DOCX decoys must be valid ZIP (ransomware-attractive)."""
        paths = deploy_decoy_swarm(str(tmp_path), count=20)
        docx_paths = [p for p in paths if Path(p).suffix.lower() == ".docx"]

        if not docx_paths:
            pytest.skip("No .docx decoys generated in this batch")

        valid_count = 0
        for p in docx_paths[:5]:
            try:
                with zipfile.ZipFile(p, "r") as zf:
                    names = zf.namelist()
                    if any("document.xml" in n or "Content_Types" in n for n in names):
                        valid_count += 1
            except Exception:
                pass

        assert valid_count > 0, "No valid OOXML structure in .docx decoys"

    def test_deploy_count_respected(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=7)
        assert len(paths) >= 7

    def test_deploy_to_nonexistent_dir_creates_it(self, tmp_path):
        new_dir = tmp_path / "new_decoy_dir"
        assert not new_dir.exists()
        paths = deploy_decoy_swarm(str(new_dir), count=3)
        assert new_dir.exists()
        assert len(paths) >= 3

    def test_refresh_decoys_replaces_old(self, tmp_path):
        paths1 = deploy_decoy_swarm(str(tmp_path), count=3)
        names1 = {Path(p).name for p in paths1}

        # Delete all decoys to simulate ransomware attack on decoys
        for p in paths1:
            try:
                Path(p).unlink()
            except Exception:
                pass

        refresh_decoys(str(tmp_path))
        paths2 = get_decoy_paths(str(tmp_path))
        # New decoys should exist
        existing = [p for p in paths2 if Path(p).exists()]
        assert len(existing) >= 1

    def test_decoy_registry_serializable(self, tmp_path):
        paths = deploy_decoy_swarm(str(tmp_path), count=3)
        registry = get_decoy_registry(str(tmp_path))
        # Registry should be JSON-serializable
        try:
            json.dumps(registry)
        except TypeError as e:
            pytest.fail(f"Registry not JSON-serializable: {e}")


# ─────────────────────────────────────────────
# CANARY REGISTRY TESTS
# ─────────────────────────────────────────────

class TestCanaryRegistry:

    def test_register_and_retrieve(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        tok = CanaryToken(
            token_id="abc123", decoy_path="/tmp/x.docx",
            token_type="docx", callback_url="http://x/t/abc123"
        )
        reg.register(tok)
        retrieved = reg.get("abc123")
        assert retrieved is not None
        assert retrieved.token_id == "abc123"
        assert retrieved.decoy_path == "/tmp/x.docx"

    def test_get_missing_returns_none(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        assert reg.get("nonexistent") is None

    def test_mark_triggered(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        tok = CanaryToken(
            token_id="tok1", decoy_path="/x",
            token_type="txt", callback_url="http://x/t/tok1"
        )
        reg.register(tok)

        triggered = reg.mark_triggered("tok1", "10.0.0.1", "TestUA/1.0")
        assert triggered is not None
        assert triggered.is_triggered
        assert triggered.trigger_ip == "10.0.0.1"
        assert triggered.trigger_ua == "TestUA/1.0"

    def test_mark_triggered_idempotent(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        tok = CanaryToken(
            token_id="tok2", decoy_path="/y",
            token_type="txt", callback_url="http://y/t/tok2"
        )
        reg.register(tok)
        reg.mark_triggered("tok2", "1.1.1.1", "UA1")
        first_time = reg.get("tok2").triggered_at

        # Second trigger should NOT update (already triggered)
        time.sleep(0.01)
        reg.mark_triggered("tok2", "2.2.2.2", "UA2")
        second_time = reg.get("tok2").triggered_at
        assert first_time == second_time  # timestamp unchanged

    def test_registry_persists_to_disk(self, tmp_path):
        path = tmp_path / "persist_reg.json"
        reg = CanaryRegistry(path)
        tok = CanaryToken(
            token_id="persist1", decoy_path="/z",
            token_type="pdf", callback_url="http://z/t/persist1"
        )
        reg.register(tok)
        assert path.exists()
        data = json.loads(path.read_text())
        assert "persist1" in data

    def test_registry_loads_from_disk(self, tmp_path):
        path = tmp_path / "load_reg.json"
        reg1 = CanaryRegistry(path)
        tok = CanaryToken(
            token_id="load1", decoy_path="/w",
            token_type="txt", callback_url="http://w/t/load1"
        )
        reg1.register(tok)

        # Load into a fresh registry
        reg2 = CanaryRegistry(path)
        retrieved = reg2.get("load1")
        assert retrieved is not None
        assert retrieved.decoy_path == "/w"

    def test_all_tokens_list(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        for i in range(5):
            reg.register(CanaryToken(
                token_id=f"t{i}", decoy_path=f"/f{i}",
                token_type="txt", callback_url=f"http://x/t/t{i}"
            ))
        tokens = reg.all_tokens()
        assert len(tokens) == 5

    def test_triggered_tokens_filtered(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        for i in range(4):
            reg.register(CanaryToken(
                token_id=f"t{i}", decoy_path=f"/f{i}",
                token_type="txt", callback_url=f"http://x/t/t{i}"
            ))
        reg.mark_triggered("t1", "1.1.1.1", "UA")
        reg.mark_triggered("t3", "2.2.2.2", "UA")

        triggered = reg.triggered_tokens()
        assert len(triggered) == 2
        assert all(t.is_triggered for t in triggered)

    def test_remove_token(self, tmp_path):
        reg = CanaryRegistry(tmp_path / "reg.json")
        reg.register(CanaryToken(
            token_id="remove_me", decoy_path="/x",
            token_type="txt", callback_url="http://x/t/remove_me"
        ))
        reg.remove("remove_me")
        assert reg.get("remove_me") is None


# ─────────────────────────────────────────────
# CANARY EMBEDDER TESTS
# ─────────────────────────────────────────────

class TestCanaryEmbedder:

    BASE_URL = "http://127.0.0.1:19999/t"

    def _make_docx(self, path: Path) -> Path:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
            zf.writestr("word/_rels/document.xml.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
            zf.writestr("word/document.xml",
                '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p></w:p></w:body></w:document>')
        return path

    def test_txt_embed_inserts_url(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = tmp_path / "readme.txt"
        f.write_text("This is a readme.\n")
        token_id = "txttoken0001"
        ok = embedder.embed_in_txt(f, token_id)
        assert ok
        content = f.read_text()
        assert token_id in content

    def test_txt_embed_no_duplicate(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = tmp_path / "readme.txt"
        f.write_text("Content.\n")
        embedder.embed_in_txt(f, "tok_dup_01")
        size1 = f.stat().st_size
        embedder.embed_in_txt(f, "tok_dup_01")  # Second embed
        size2 = f.stat().st_size
        # File should not grow significantly on duplicate embed
        # (base URL already present)
        assert size2 <= size1 + 100

    def test_docx_embed_succeeds(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = self._make_docx(tmp_path / "test.docx")
        ok = embedder.embed_in_docx(f, "doctok0001")
        assert ok

    def test_docx_embed_url_in_rels(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = self._make_docx(tmp_path / "test2.docx")
        token_id = "doccheck001"
        embedder.embed_in_docx(f, token_id)
        with zipfile.ZipFile(f, "r") as zf:
            rels = zf.read("word/_rels/document.xml.rels").decode()
        assert token_id in rels

    def test_docx_still_valid_zip_after_embed(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = self._make_docx(tmp_path / "valid.docx")
        embedder.embed_in_docx(f, "validtok0001")
        # Should still be a valid ZIP after embedding
        try:
            with zipfile.ZipFile(f, "r") as zf:
                zf.testzip()
        except zipfile.BadZipFile:
            pytest.fail("DOCX is not a valid ZIP after canary embed")

    def test_embed_auto_select_txt(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = tmp_path / "notes.txt"
        f.write_text("Notes here.\n")
        ok = embedder.embed(f, "autotok001")
        assert ok
        assert "autotok001" in f.read_text()

    def test_embed_auto_select_docx(self, tmp_path):
        embedder = CanaryEmbedder(self.BASE_URL)
        f = self._make_docx(tmp_path / "auto.docx")
        ok = embedder.embed(f, "autotok002")
        assert ok


# ─────────────────────────────────────────────
# CANARY SERVER TESTS
# ─────────────────────────────────────────────

class TestCanaryServer:

    def _get_free_port(self) -> int:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_server_starts_and_stops(self, tmp_path):
        port = self._get_free_port()
        reg  = CanaryRegistry(tmp_path / "reg.json")
        srv  = CanaryServer("127.0.0.1", port, reg, lambda t: None)
        srv.start()
        time.sleep(0.2)
        assert srv.is_running()
        srv.stop()

    def test_callback_fires_on_get(self, tmp_path):
        port     = self._get_free_port()
        reg      = CanaryRegistry(tmp_path / "reg.json")
        received = []

        tok = CanaryToken(
            token_id="firetok01",
            decoy_path="/decoy.docx",
            token_type="docx",
            callback_url=f"http://127.0.0.1:{port}/t/firetok01",
        )
        reg.register(tok)

        srv = CanaryServer("127.0.0.1", port, reg, lambda t: received.append(t))
        srv.start()
        time.sleep(0.2)

        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/t/firetok01", timeout=3)
        except Exception:
            pass

        time.sleep(0.2)
        assert len(received) == 1
        assert received[0].token_id == "firetok01"

        srv.stop()

    def test_callback_404_for_unknown_token(self, tmp_path):
        port = self._get_free_port()
        reg  = CanaryRegistry(tmp_path / "reg.json")
        srv  = CanaryServer("127.0.0.1", port, reg, lambda t: None)
        srv.start()
        time.sleep(0.2)

        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/t/doesnotexist", timeout=3)
            assert False, "Expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
        finally:
            srv.stop()

    def test_base_url_property(self, tmp_path):
        port = self._get_free_port()
        reg  = CanaryRegistry(tmp_path / "reg.json")
        srv  = CanaryServer("127.0.0.1", port, reg, lambda t: None)
        assert str(port) in srv.base_url
        assert "127.0.0.1" in srv.base_url


# ─────────────────────────────────────────────
# CANARY MANAGER INTEGRATION TESTS
# ─────────────────────────────────────────────

class TestCanaryManager:

    def _get_free_port(self) -> int:
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _make_docx(self, path: Path) -> Path:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
            zf.writestr("word/_rels/document.xml.rels",
                '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
            zf.writestr("word/document.xml", '<w:document/>')
        return path

    def test_manager_embeds_and_triggers(self, tmp_path):
        port = self._get_free_port()
        triggered = []

        mgr = CanaryManager(
            host="127.0.0.1", port=port,
            registry_path=tmp_path / "mgr_reg.json",
            on_trigger=lambda t: triggered.append(t),
        )
        mgr.start()
        time.sleep(0.2)

        # Embed in a TXT file
        decoy = tmp_path / "important.txt"
        decoy.write_text("Sensitive data here.\n")
        tok = mgr.embed_in_file(decoy)
        assert tok is not None

        # Simulate ransomware fetching the URL
        try:
            urllib.request.urlopen(tok.callback_url, timeout=3)
        except Exception:
            pass

        time.sleep(0.2)
        assert len(triggered) == 1
        assert triggered[0].token_id == tok.token_id
        mgr.stop()

    def test_embed_in_all_decoys(self, tmp_path):
        port = self._get_free_port()
        mgr = CanaryManager(
            host="127.0.0.1", port=port,
            registry_path=tmp_path / "batch_reg.json",
        )
        mgr.start()
        time.sleep(0.1)

        decoys = []
        for i in range(3):
            f = tmp_path / f"decoy_{i}.txt"
            f.write_text(f"Decoy {i}\n")
            decoys.append(f)

        count = mgr.embed_in_all_decoys(decoys)
        assert count == 3

        mgr.stop()

    def test_status_dict_structure(self, tmp_path):
        port = self._get_free_port()
        mgr = CanaryManager(
            host="127.0.0.1", port=port,
            registry_path=tmp_path / "status_reg.json",
        )
        mgr.start()
        time.sleep(0.1)

        status = mgr.status()
        assert "server_running" in status
        assert "total_tokens" in status
        assert "triggered" in status
        assert status["server_running"] is True

        mgr.stop()
