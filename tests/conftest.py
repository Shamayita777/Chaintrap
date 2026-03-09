"""
ChainTrap v2 — tests/conftest.py

Shared pytest fixtures and configuration.
"""
import sys
import os
from pathlib import Path

# Ensure project root is importable
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "core"))
sys.path.insert(0, str(_ROOT / "config"))

import pytest


@pytest.fixture(autouse=True)
def isolate_blockchain(monkeypatch, tmp_path):
    """
    Automatically isolate blockchain_logger chain file for every test.
    Prevents tests from polluting the real chain.json.
    """
    try:
        import core.blockchain_logger as bl
        orig_path  = bl.CHAIN_FILE
        orig_chain = bl._chain.copy() if hasattr(bl, "_chain") else []
        orig_init  = getattr(bl, "_chain_initialized", False)

        new_path = tmp_path / "isolated_chain.json"
        bl.CHAIN_FILE         = new_path
        bl._chain             = []
        bl._chain_initialized = False

        yield

        # Restore
        bl.CHAIN_FILE         = orig_path
        bl._chain             = orig_chain
        bl._chain_initialized = orig_init
    except ImportError:
        yield
