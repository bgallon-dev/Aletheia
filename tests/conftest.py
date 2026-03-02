"""Shared fixtures and helpers for the Aletheia test suite."""

from __future__ import annotations

import hashlib
import random
import struct
import tempfile
from pathlib import Path
from typing import List

import pytest


# ---------------------------------------------------------------------------
# ALBC binary format builders (consolidated from per-file duplicates)
# ---------------------------------------------------------------------------

def build_albc_v1(
    payload: bytes,
    window: int = 64,
    step: int = 16,
    m: int = 1,
    quant: int = 0,
) -> bytes:
    """Build a valid ALBC v1 binary blob from a raw barcode payload."""
    header = b"ALBC0001"
    header += struct.pack("<I", window)
    header += struct.pack("<I", step)
    header += struct.pack("<I", m)
    header += struct.pack("<I", quant)
    header += struct.pack("<Q", len(payload))
    return header + payload


def build_albc_v2(
    payload: bytes,
    raw_entropy: List[float],
    window: int = 64,
    step: int = 16,
    m: int = 1,
    quant: int = 0,
) -> bytes:
    """Build a valid ALBC v2 binary blob (quantized + raw f64 entropy)."""
    raw_data_offset = 40 + len(payload)
    header = b"ALBC0002"
    header += struct.pack("<I", window)
    header += struct.pack("<I", step)
    header += struct.pack("<I", m)
    header += struct.pack("<I", quant)
    header += struct.pack("<Q", len(payload))
    header += struct.pack("<Q", raw_data_offset)
    raw_bytes = struct.pack(f"<{len(raw_entropy)}d", *raw_entropy)
    return header + payload + raw_bytes


# ---------------------------------------------------------------------------
# File fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def deterministic_file(tmp_path: Path) -> Path:
    """1 MB binary file generated from a fixed seed (always identical content)."""
    rng = random.Random(0xDEADBEEF)
    data = bytes(rng.randrange(256) for _ in range(1024 * 1024))
    p = tmp_path / "deterministic_1mb.bin"
    p.write_bytes(data)
    return p


@pytest.fixture
def zeroes_file(tmp_path: Path) -> Path:
    """1 MB of 0x00 bytes."""
    p = tmp_path / "zeroes_1mb.bin"
    p.write_bytes(b"\x00" * 1024 * 1024)
    return p


@pytest.fixture
def small_file(tmp_path: Path) -> Path:
    """Small text-like file for fast unit tests."""
    p = tmp_path / "small.bin"
    p.write_bytes(b"ABCDEFGH" * 256)  # 2 KB
    return p


# ---------------------------------------------------------------------------
# Repository fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def initialized_repo(tmp_path: Path):
    """AletheiaRepository fully initialized in a temp directory."""
    from aletheia.repository import AletheiaRepository

    return AletheiaRepository(str(tmp_path), auto_init=True)


# ---------------------------------------------------------------------------
# Dummy scanner (no Odin binary required)
# ---------------------------------------------------------------------------

class DummyScanner:
    """Simulates OdinScanner for unit tests that don't need the real binary."""

    def __init__(self, payload: bytes = b"\x01\x02\x03\x04"):
        self.payload = payload
        self.scan_calls: list = []

    def scan(self, file_path: str, **kwargs) -> tuple:
        self.scan_calls.append({"file_path": file_path, **kwargs})
        albc = build_albc_v1(self.payload)
        tmp = tempfile.NamedTemporaryFile(suffix=".albc", delete=False)
        tmp.write(albc)
        tmp.close()
        return albc, tmp.name


@pytest.fixture
def dummy_scanner() -> DummyScanner:
    """Return a DummyScanner with a default 4-byte payload."""
    return DummyScanner()


# ---------------------------------------------------------------------------
# Minimal artifact record dict helper
# ---------------------------------------------------------------------------

def minimal_record(
    content_object_id: str = "a" * 64,
    barcode_object_id: str = "b" * 64,
    filename: str = "test.bin",
) -> dict:
    """Return a minimal valid ArtifactRecord dict."""
    return {
        "record_version": "aletheia/ar/1",
        "content_object_id": content_object_id,
        "barcode_object_id": barcode_object_id,
        "scan_params": {
            "window_size_bytes": 65536,
            "step_size_bytes": 16384,
            "m_block_size": 1,
            "quant_version": "v0",
            "barcode_len": 16,
        },
        "created_at_unix_ms": 1700000000000,
        "metadata": {
            "original_filename": filename,
            "ingested_from": "local",
            "chain_of_custody": "single_node",
        },
    }


# ---------------------------------------------------------------------------
# Goldens directory path helper
# ---------------------------------------------------------------------------

GOLDENS_DIR = Path(__file__).parent / "fixtures" / "goldens"
