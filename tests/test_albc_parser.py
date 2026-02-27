import struct
from typing import List

from aletheia.ingest import ALBCParser


def _build_albc_v1(payload: bytes, window: int = 64, step: int = 16, m: int = 1) -> bytes:
    header = b"ALBC0001"
    header += struct.pack("<I", window)
    header += struct.pack("<I", step)
    header += struct.pack("<I", m)
    header += struct.pack("<I", 0)
    header += struct.pack("<Q", len(payload))
    return header + payload


def _build_albc_v2(
    payload: bytes,
    raw_entropy: List[float],
    window: int = 64,
    step: int = 16,
    m: int = 1,
) -> bytes:
    raw_data_offset = 40 + len(payload)
    header = b"ALBC0002"
    header += struct.pack("<I", window)
    header += struct.pack("<I", step)
    header += struct.pack("<I", m)
    header += struct.pack("<I", 0)
    header += struct.pack("<Q", len(payload))
    header += struct.pack("<Q", raw_data_offset)
    raw_bytes = struct.pack(f"<{len(raw_entropy)}d", *raw_entropy)
    return header + payload + raw_bytes


def test_detect_version_v1_and_v2():
    assert ALBCParser.detect_version(_build_albc_v1(b"\x01")) == 1
    assert ALBCParser.detect_version(_build_albc_v2(b"\x01", [0.1])) == 2
    assert ALBCParser.detect_version(b"BADMAGIC") is None


def test_parse_full_rejects_truncated_payload():
    payload = b"\x01\x02"
    albc = _build_albc_v1(payload)
    truncated = albc[:-1]
    assert ALBCParser.parse_full(truncated) is None


def test_parse_full_with_raw_extracts_raw_entropy():
    raw_entropy = [0.1, 0.2, 0.3]
    payload = b"\x10\x20\x30"
    parsed = ALBCParser.parse_full_with_raw(_build_albc_v2(payload, raw_entropy))
    assert parsed is not None
    assert parsed["barcode_payload"] == payload
    assert parsed["raw_entropy"] == raw_entropy


def test_compare_barcodes_merges_adjacent_windows():
    baseline = bytes([10, 20, 30, 40, 50, 60])
    suspect = bytes([10, 99, 88, 40, 77, 60])
    regions = ALBCParser.compare_barcodes(baseline, suspect, window_size=64, step_size=16)
    assert regions == [
        (1, 2, 16, 96),
        (4, 4, 64, 128),
    ]


def test_compare_barcodes_raw_honors_threshold_and_merges():
    baseline = [0.0, 0.5, 0.5, 0.5, 1.0]
    suspect = [0.0, 0.8, 0.1, 0.5, 1.4]
    regions = ALBCParser.compare_barcodes_raw(
        baseline,
        suspect,
        window_size=64,
        step_size=16,
        threshold=0.25,
    )
    assert regions == [
        (1, 2, 16, 96),
        (4, 4, 64, 128),
    ]
