import struct

from aletheia.ingest import OdinScanner


def _build_albc_v1(payload: bytes, window: int = 64, step: int = 16, m: int = 1) -> bytes:
    header = b"ALBC0001"
    header += struct.pack("<I", window)
    header += struct.pack("<I", step)
    header += struct.pack("<I", m)
    header += struct.pack("<I", 0)  # quant version v0
    header += struct.pack("<Q", len(payload))
    return header + payload


def test_diff_identical_files(tmp_path):
    payload = bytes([10, 20, 30, 40])
    file1 = tmp_path / "a.albc"
    file2 = tmp_path / "b.albc"
    file1.write_bytes(_build_albc_v1(payload))
    file2.write_bytes(_build_albc_v1(payload))

    scanner = OdinScanner(require_binary=False)
    result = scanner.diff(str(file1), str(file2))

    assert result["windows_compared"] == 4
    assert result["avg_delta_raw"] == 0
    assert result["rms_delta_raw"] == 0
    assert result["max_delta_raw"] == 0
    assert result["windows_above_threshold"] == 0


def test_diff_threshold_counts(tmp_path):
    file1 = tmp_path / "base.albc"
    file2 = tmp_path / "suspect.albc"
    file1.write_bytes(_build_albc_v1(bytes([10, 20, 30, 40])))
    file2.write_bytes(_build_albc_v1(bytes([12, 18, 40, 40])))

    scanner = OdinScanner(require_binary=False)
    result = scanner.diff(str(file1), str(file2), threshold=5.0)

    # Deltas: [2, 2, 10, 0]
    assert result["windows_compared"] == 4
    assert result["max_delta_raw"] == 10
    assert result["max_delta_window"] == 2
    assert result["windows_above_threshold"] == 1
