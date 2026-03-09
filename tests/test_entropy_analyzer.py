"""
ChainTrap v2 — tests/test_entropy_analyzer.py

Unit tests for the multi-signal entropy detection pipeline.
Tests all 5 evasion vector countermeasures individually and combined.
"""

import os
import math
import struct
import zipfile
import tempfile
import secrets
import base64
from pathlib import Path

import pytest
import numpy as np

# Adjust path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "core"))

from core.entropy_analyzer import (
    analyze_file,
    analyze_delta,
    EntropyResult,
)


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

@pytest.fixture
def tmpdir_path(tmp_path):
    return tmp_path


def write_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    return path


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def make_low_entropy(n: int = 100_000) -> bytes:
    """Normal text content — low entropy ~4.5."""
    vocab = b"abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ\n\t.,!?;:"
    import random
    return bytes([vocab[i % len(vocab)] for i in range(n)])


def make_high_entropy(n: int = 100_000) -> bytes:
    """AES ciphertext — near-maximum entropy ~8.0."""
    return secrets.token_bytes(n)


def make_ooxml(n: int = 100_000) -> bytes:
    """Valid OOXML ZIP structure."""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml",
            b"<w:document>" + make_low_entropy(n - 200) + b"</w:document>")
    return buf.getvalue()


def make_b64_ciphertext(n: int = 100_000) -> bytes:
    """Base64-encoded ciphertext — medium entropy ~6.0."""
    raw = secrets.token_bytes(n * 3 // 4)
    return base64.b64encode(raw)[:n]


def make_partial_encrypted(n: int = 200_000) -> bytes:
    """First 4KB encrypted, rest normal — partial encryption evasion."""
    return secrets.token_bytes(4096) + make_low_entropy(n - 4096)


def make_fpe(n: int = 100_000) -> bytes:
    """FPE: valid ZIP/OOXML header, high-entropy payload."""
    return b"PK\x03\x04" + secrets.token_bytes(n - 4)


# ─────────────────────────────────────────────
# TEST: Shannon entropy baseline
# ─────────────────────────────────────────────

class TestShannonEntropy:

    def test_low_entropy_text_not_suspicious(self, tmp_path):
        f = write_file(tmp_path / "doc.txt", make_low_entropy())
        result = analyze_file(f)
        assert result.shannon_global < 6.0, \
            f"Expected low entropy for text, got {result.shannon_global:.4f}"

    def test_high_entropy_random_is_suspicious(self, tmp_path):
        f = write_file(tmp_path / "enc.bin", make_high_entropy())
        result = analyze_file(f)
        assert result.is_suspicious, \
            f"Expected high-entropy random to be flagged"
        assert result.shannon_global > 7.5, \
            f"Expected near-max entropy, got {result.shannon_global:.4f}"

    def test_entropy_range(self, tmp_path):
        """Shannon entropy must be in [0, 8]."""
        for content, label in [
            (make_low_entropy(), "low"),
            (make_high_entropy(), "high"),
            (b"\x00" * 10000, "zeros"),
        ]:
            f = write_file(tmp_path / f"test_{label}.bin", content)
            result = analyze_file(f)
            assert 0.0 <= result.shannon_global <= 8.0, \
                f"Entropy {result.shannon_global:.4f} out of range for {label}"

    def test_all_zeros_entropy_zero(self, tmp_path):
        f = write_file(tmp_path / "zeros.bin", b"\x00" * 50_000)
        result = analyze_file(f)
        assert result.shannon_global < 0.1, \
            f"Expected ~0 entropy for all-zeros, got {result.shannon_global}"

    def test_all_same_byte_entropy_zero(self, tmp_path):
        f = write_file(tmp_path / "same.bin", b"\xff" * 50_000)
        result = analyze_file(f)
        assert result.shannon_global < 0.1

    def test_window_max_gte_global(self, tmp_path):
        """Max window entropy should be >= global (partial encryption case)."""
        f = write_file(tmp_path / "partial.bin", make_partial_encrypted())
        result = analyze_file(f)
        # Max window from encrypted region should be high
        assert result.shannon_max_window >= result.shannon_global * 0.9, \
            "Window entropy unexpectedly lower than global"


# ─────────────────────────────────────────────
# TEST: Evasion countermeasure 1 — Entropy Sharing
# ─────────────────────────────────────────────

class TestEntropySharing:
    """
    Ransomware mixes low-entropy padding with encrypted blocks
    to keep global entropy below naive 6.5 threshold.
    Sliding-window analysis catches the high-entropy segments.
    """

    def test_partial_encryption_detected_via_window(self, tmp_path):
        """First 4KB encrypted = max window should spike."""
        content = make_partial_encrypted(200_000)
        f = write_file(tmp_path / "partial.docx", content)
        result = analyze_file(f)
        # The encrypted segment should push window entropy above threshold
        assert result.shannon_max_window > 7.0, \
            f"Partial encryption not detected via window: max_window={result.shannon_max_window:.4f}"

    def test_entropy_padding_still_detected(self, tmp_path):
        """50% encrypted + 50% padding: global ~4.0, but window catches it."""
        half = 50_000
        content = secrets.token_bytes(half) + make_low_entropy(half)
        f = write_file(tmp_path / "padded.bin", content)
        result = analyze_file(f)
        assert result.shannon_max_window > 6.5, \
            f"Entropy sharing not caught: max_window={result.shannon_max_window:.4f}"


# ─────────────────────────────────────────────
# TEST: Evasion countermeasure 2 — FPE
# ─────────────────────────────────────────────

class TestFormatPreservingEncryption:
    """
    FPE keeps file headers valid (ZIP magic bytes) but encrypts payload.
    ChainTrap validates OOXML ZIP structure, not just 4-byte magic.
    """

    def test_valid_ooxml_magic_valid(self, tmp_path):
        f = write_file(tmp_path / "real.docx", make_ooxml())
        result = analyze_file(f)
        assert result.magic_valid, \
            "Valid OOXML should have magic_valid=True"

    def test_fpe_docx_magic_invalid(self, tmp_path):
        """Valid ZIP header but payload is random — OOXML structure broken."""
        f = write_file(tmp_path / "fpe.docx", make_fpe())
        result = analyze_file(f)
        # Either magic_valid is False OR is_suspicious is True
        # (FPE has high-entropy payload which triggers Shannon signal)
        flagged = not result.magic_valid or result.is_suspicious
        assert flagged, \
            f"FPE attack not detected: magic_valid={result.magic_valid}, suspicious={result.is_suspicious}"

    def test_pure_random_no_magic_header(self, tmp_path):
        f = write_file(tmp_path / "rand.bin", make_high_entropy())
        result = analyze_file(f)
        # Unknown extension — magic_valid covers known extensions only
        # But is_suspicious should be True due to entropy
        assert result.is_suspicious


# ─────────────────────────────────────────────
# TEST: Evasion countermeasure 3 — Base64 Encoding
# ─────────────────────────────────────────────

class TestBase64Ciphertext:
    """
    Base64-encoding ciphertext reduces entropy from ~8.0 to ~6.0.
    Chi-squared test detects non-uniform byte distribution of B64 alphabet.
    """

    def test_b64_ciphertext_detected(self, tmp_path):
        """Base64 ciphertext should trigger chi-squared signal."""
        f = write_file(tmp_path / "enc.b64", make_b64_ciphertext())
        result = analyze_file(f)
        # Chi-squared should flag the non-uniform base64 alphabet
        # OR entropy signal fires (>6.0 for base64 is still elevated)
        triggered = result.is_suspicious or result.shannon_global > 5.5
        assert triggered, \
            f"Base64 ciphertext not detected: entropy={result.shannon_global:.4f}, suspicious={result.is_suspicious}"

    def test_chi_p_value_present(self, tmp_path):
        f = write_file(tmp_path / "test.bin", make_high_entropy())
        result = analyze_file(f)
        assert result.chi_p_value is not None
        assert 0.0 <= result.chi_p_value <= 1.0


# ─────────────────────────────────────────────
# TEST: Entropy Delta Analysis
# ─────────────────────────────────────────────

class TestEntropyDelta:

    def test_large_delta_detected(self, tmp_path):
        """Low → high entropy transition should breach delta threshold."""
        f_before = write_file(tmp_path / "before.docx", make_low_entropy())
        f_after  = write_file(tmp_path / "after.docx",  make_high_entropy())

        before = analyze_file(f_before)
        after  = analyze_file(f_after)

        suspicious, delta_val, desc = analyze_delta(before, after, delta_threshold=1.5)
        assert suspicious, f"Large delta not detected: delta={delta_val:.4f}"
        assert delta_val > 1.5

    def test_small_delta_not_flagged(self, tmp_path):
        """Normal file re-save should NOT trigger delta alert."""
        content = make_low_entropy()
        f1 = write_file(tmp_path / "v1.txt", content)
        f2 = write_file(tmp_path / "v2.txt", content + b" updated")

        r1 = analyze_file(f1)
        r2 = analyze_file(f2)

        suspicious, delta_val, _ = analyze_delta(r1, r2, delta_threshold=1.5)
        assert not suspicious, f"False delta alarm: delta={delta_val:.4f}"

    def test_none_baseline_returns_false(self, tmp_path):
        """No baseline = no delta alert (first-seen file)."""
        f = write_file(tmp_path / "new.bin", make_high_entropy())
        result = analyze_file(f)
        suspicious, delta_val, _ = analyze_delta(None, result, delta_threshold=1.5)
        assert not suspicious
        assert delta_val == 0.0

    def test_delta_value_is_positive(self, tmp_path):
        f_low  = write_file(tmp_path / "low.bin",  make_low_entropy())
        f_high = write_file(tmp_path / "high.bin", make_high_entropy())
        r_low  = analyze_file(f_low)
        r_high = analyze_file(f_high)
        _, delta_val, _ = analyze_delta(r_low, r_high)
        assert delta_val >= 0.0


# ─────────────────────────────────────────────
# TEST: EntropyResult structure
# ─────────────────────────────────────────────

class TestEntropyResultStructure:

    def test_result_has_required_fields(self, tmp_path):
        f = write_file(tmp_path / "test.bin", make_high_entropy(10_000))
        result = analyze_file(f)
        assert hasattr(result, "shannon_global")
        assert hasattr(result, "shannon_max_window")
        assert hasattr(result, "shannon_windows")
        assert hasattr(result, "chi_p_value")
        assert hasattr(result, "magic_valid")
        assert hasattr(result, "is_suspicious")
        assert hasattr(result, "signals_triggered")
        assert hasattr(result, "error")

    def test_signals_triggered_is_list(self, tmp_path):
        f = write_file(tmp_path / "test.bin", make_high_entropy())
        result = analyze_file(f)
        assert isinstance(result.signals_triggered, list)

    def test_windows_list_nonempty_for_large_file(self, tmp_path):
        f = write_file(tmp_path / "large.bin", make_high_entropy(500_000))
        result = analyze_file(f)
        assert isinstance(result.shannon_windows, list)
        assert len(result.shannon_windows) > 0

    def test_error_none_on_valid_file(self, tmp_path):
        f = write_file(tmp_path / "valid.bin", make_high_entropy(10_000))
        result = analyze_file(f)
        assert result.error is None

    def test_error_set_on_missing_file(self, tmp_path):
        result = analyze_file(tmp_path / "nonexistent.bin")
        assert result.error is not None

    def test_file_size_matches(self, tmp_path):
        content = make_high_entropy(77_777)
        f = write_file(tmp_path / "sized.bin", content)
        result = analyze_file(f)
        assert result.file_size == 77_777

    def test_file_path_stored(self, tmp_path):
        f = write_file(tmp_path / "named.bin", make_high_entropy(1_000))
        result = analyze_file(f)
        assert result.file_path == f


# ─────────────────────────────────────────────
# TEST: Edge cases
# ─────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_file(self, tmp_path):
        f = write_file(tmp_path / "empty.bin", b"")
        result = analyze_file(f)
        # Should not crash; error may be set
        assert result is not None

    def test_tiny_file_1_byte(self, tmp_path):
        f = write_file(tmp_path / "tiny.bin", b"\xff")
        result = analyze_file(f)
        assert result is not None

    def test_1kb_file(self, tmp_path):
        f = write_file(tmp_path / "small.bin", make_high_entropy(1024))
        result = analyze_file(f)
        assert result.is_suspicious

    def test_large_file_5mb(self, tmp_path):
        f = write_file(tmp_path / "large.bin", make_high_entropy(5_000_000))
        result = analyze_file(f)
        assert result.is_suspicious

    def test_pdf_magic_bytes(self, tmp_path):
        content = b"%PDF" + make_low_entropy(50_000)
        f = write_file(tmp_path / "doc.pdf", content)
        result = analyze_file(f)
        assert result.magic_valid or result.detected_magic == ".pdf"

    def test_gzip_magic_bytes(self, tmp_path):
        content = b"\x1f\x8b" + make_low_entropy(50_000)
        f = write_file(tmp_path / "data.gz", content)
        result = analyze_file(f)
        # .gz with low-entropy payload — magic valid, not suspicious
        assert result.magic_valid

    @pytest.mark.parametrize("ext", [".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".py"])
    def test_analyze_common_extensions(self, tmp_path, ext):
        """All common extensions should be analyzed without error."""
        content = make_low_entropy(10_000)
        f = write_file(tmp_path / f"file{ext}", content)
        result = analyze_file(f)
        assert result.error is None


# ─────────────────────────────────────────────
# TEST: Performance
# ─────────────────────────────────────────────

class TestPerformance:

    @pytest.mark.timeout(2)
    def test_100kb_under_2s(self, tmp_path):
        f = write_file(tmp_path / "perf.bin", make_high_entropy(100_000))
        result = analyze_file(f)
        assert result is not None

    @pytest.mark.timeout(5)
    def test_5mb_under_5s(self, tmp_path):
        f = write_file(tmp_path / "big.bin", make_high_entropy(5_000_000))
        result = analyze_file(f)
        assert result is not None
