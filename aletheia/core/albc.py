"""ALBC binary format parser/writer for portable barcode exchange."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .barcode import compare_quantized_payloads, compare_raw_entropy
from .types import BarcodeResult, ScanParams


class ALBCParser:
    """Parser for ALBC (Aletheia Barcode) binary format."""

    MAGIC_V1 = b"ALBC0001"
    MAGIC_V2 = b"ALBC0002"
    HEADER_SIZE_V1 = 32
    HEADER_SIZE_V2 = 40

    @staticmethod
    def detect_version(data: bytes) -> Optional[int]:
        if len(data) < 8:
            return None
        magic = data[0:8]
        if magic == ALBCParser.MAGIC_V1:
            return 1
        if magic == ALBCParser.MAGIC_V2:
            return 2
        return None

    @staticmethod
    def get_header_size(version: int) -> int:
        return ALBCParser.HEADER_SIZE_V1 if version == 1 else ALBCParser.HEADER_SIZE_V2

    @staticmethod
    def parse_header(albc_data: bytes) -> Optional[Dict[str, Any]]:
        version = ALBCParser.detect_version(albc_data)
        if version is None:
            return None

        header_size = ALBCParser.get_header_size(version)
        if len(albc_data) < header_size:
            return None

        window_size_bytes = struct.unpack("<I", albc_data[8:12])[0]
        step_size_bytes = struct.unpack("<I", albc_data[12:16])[0]
        m_block_size = struct.unpack("<I", albc_data[16:20])[0]
        quant_version = struct.unpack("<I", albc_data[20:24])[0]
        barcode_len = struct.unpack("<Q", albc_data[24:32])[0]

        result = {
            "format_version": version,
            "header_size": header_size,
            "window_size_bytes": window_size_bytes,
            "step_size_bytes": step_size_bytes,
            "m_block_size": m_block_size,
            "quant_version": f"v{quant_version}",
            "barcode_len": barcode_len,
            "raw_data_offset": 0,
        }
        if version == 2:
            result["raw_data_offset"] = struct.unpack("<Q", albc_data[32:40])[0]
        return result

    @staticmethod
    def parse_full(albc_data: bytes) -> Optional[Dict[str, Any]]:
        header = ALBCParser.parse_header(albc_data)
        if header is None:
            return None

        header_size = int(header["header_size"])
        barcode_len = int(header["barcode_len"])
        required_size = header_size + barcode_len
        if len(albc_data) < required_size:
            return None

        payload = albc_data[header_size : header_size + barcode_len]
        return {**header, "barcode_payload": payload}

    @staticmethod
    def parse_full_with_raw(albc_data: bytes) -> Optional[Dict[str, Any]]:
        result = ALBCParser.parse_full(albc_data)
        if result is None:
            return None

        raw_offset = int(result.get("raw_data_offset", 0))
        if raw_offset > 0 and result["format_version"] == 2:
            barcode_len = int(result["barcode_len"])
            raw_size = barcode_len * 8
            if raw_offset + raw_size > len(albc_data):
                return None
            raw_bytes = albc_data[raw_offset : raw_offset + raw_size]
            result["raw_entropy"] = list(struct.unpack(f"<{barcode_len}d", raw_bytes))

        return result

    @staticmethod
    def parse_header_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        with open(file_path, "rb") as file_handle:
            header_bytes = file_handle.read(ALBCParser.HEADER_SIZE_V2)
        return ALBCParser.parse_header(header_bytes)

    @staticmethod
    def parse_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        header = ALBCParser.parse_header_from_file(file_path)
        if header is None:
            return None

        header_size = int(header["header_size"])
        expected_len = int(header["barcode_len"])
        with open(file_path, "rb") as file_handle:
            file_handle.seek(header_size)
            payload = file_handle.read(expected_len)

        if len(payload) != expected_len:
            return None
        return {**header, "barcode_payload": payload}

    @staticmethod
    def parse_from_file_with_raw(file_path: Path) -> Optional[Dict[str, Any]]:
        result = ALBCParser.parse_from_file(file_path)
        if result is None:
            return None

        raw_offset = int(result.get("raw_data_offset", 0))
        if raw_offset > 0 and result["format_version"] == 2:
            barcode_len = int(result["barcode_len"])
            raw_size = barcode_len * 8
            file_size = file_path.stat().st_size
            if raw_offset + raw_size > file_size:
                return None

            with open(file_path, "rb") as file_handle:
                file_handle.seek(raw_offset)
                raw_bytes = file_handle.read(raw_size)
            if len(raw_bytes) != raw_size:
                return None
            result["raw_entropy"] = list(struct.unpack(f"<{barcode_len}d", raw_bytes))
        return result

    @staticmethod
    def compare_barcodes(
        baseline_payload: bytes,
        actual_payload: bytes,
        window_size: int,
        step_size: int,
    ) -> List[Tuple[int, int, int, int]]:
        comparison = compare_quantized_payloads(
            baseline_payload=baseline_payload,
            actual_payload=actual_payload,
            window_size=window_size,
            step_size=step_size,
        )
        return comparison.to_legacy_tuples()

    @staticmethod
    def compare_barcodes_raw(
        baseline_raw: Sequence[float],
        actual_raw: Sequence[float],
        window_size: int,
        step_size: int,
        threshold: float = 1e-9,
    ) -> List[Tuple[int, int, int, int]]:
        comparison = compare_raw_entropy(
            baseline_raw=baseline_raw,
            actual_raw=actual_raw,
            window_size=window_size,
            step_size=step_size,
            threshold=threshold,
        )
        return comparison.to_legacy_tuples()

    @staticmethod
    def parse_to_result(
        parsed: Mapping[str, Any],
        source_path: Optional[str] = None,
    ) -> BarcodeResult:
        raw_entropy = parsed.get("raw_entropy")
        if raw_entropy is not None and isinstance(raw_entropy, list):
            normalized_raw = [float(value) for value in raw_entropy]
        else:
            normalized_raw = None

        scan_params = ScanParams(
            window_size_bytes=int(parsed.get("window_size_bytes", 65536)),
            step_size_bytes=int(parsed.get("step_size_bytes", 16384)),
            m_block_size=int(parsed.get("m_block_size", 1)),
            format_version=int(parsed.get("format_version", 1)),
            quant_version=str(parsed.get("quant_version", "v0")),
        )
        payload = parsed.get("barcode_payload", b"")
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError("barcode_payload must be bytes")
        return BarcodeResult(
            scan_params=scan_params,
            barcode_payload=bytes(payload),
            raw_entropy=normalized_raw,
            source_path=source_path,
        )


def _quant_version_to_int(quant_version: str) -> int:
    normalized = quant_version.strip().lower()
    if normalized.startswith("v"):
        normalized = normalized[1:]
    try:
        return int(normalized)
    except ValueError as exc:
        raise ValueError(f"Unsupported quant_version '{quant_version}'") from exc


def build_albc_bytes(result: BarcodeResult) -> bytes:
    """Serialize a barcode result to ALBC bytes."""
    payload = result.barcode_payload
    params = result.scan_params
    quant_version_int = _quant_version_to_int(params.quant_version)

    header = bytearray()
    if params.format_version == 1:
        header.extend(ALBCParser.MAGIC_V1)
    elif params.format_version == 2:
        header.extend(ALBCParser.MAGIC_V2)
    else:
        raise ValueError(f"Unsupported ALBC format version: {params.format_version}")

    header.extend(struct.pack("<I", params.window_size_bytes))
    header.extend(struct.pack("<I", params.step_size_bytes))
    header.extend(struct.pack("<I", params.m_block_size))
    header.extend(struct.pack("<I", quant_version_int))
    header.extend(struct.pack("<Q", len(payload)))

    body = bytearray(payload)
    if params.format_version == 2:
        raw_entropy = result.raw_entropy or []
        raw_offset = 40 + len(payload) if raw_entropy else 0
        header.extend(struct.pack("<Q", raw_offset))
        if raw_entropy:
            body.extend(struct.pack(f"<{len(raw_entropy)}d", *raw_entropy))

    return bytes(header + body)


def save_albc(path: str, result: BarcodeResult) -> None:
    """Write an ALBC file from a core barcode result."""
    Path(path).write_bytes(build_albc_bytes(result))


def load_albc(path: str) -> BarcodeResult:
    """Load an ALBC file as a core barcode result."""
    parsed = ALBCParser.parse_from_file_with_raw(Path(path))
    if parsed is None:
        raise ValueError(f"Invalid or truncated ALBC file: {path}")
    return ALBCParser.parse_to_result(parsed, source_path=str(path))
