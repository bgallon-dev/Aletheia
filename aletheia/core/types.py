"""Core value objects for storage-independent barcode operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class ScanParams:
    """Scan configuration shared across scanners and ALBC serialization."""

    window_size_bytes: int = 65536
    step_size_bytes: int = 16384
    m_block_size: int = 1
    threads: int = 0
    format_version: int = 1
    quant_version: str = "v0"

    def __post_init__(self) -> None:
        if self.window_size_bytes <= 0:
            raise ValueError("window_size_bytes must be > 0")
        if self.step_size_bytes <= 0 or self.step_size_bytes > self.window_size_bytes:
            raise ValueError("step_size_bytes must be in range (0, window_size_bytes]")
        if self.m_block_size <= 0:
            raise ValueError("m_block_size must be > 0")
        if self.format_version not in (1, 2):
            raise ValueError("format_version must be 1 or 2")

    @property
    def window_size(self) -> int:
        """Convenience alias for API ergonomics."""
        return self.window_size_bytes

    @property
    def step_size(self) -> int:
        """Convenience alias for API ergonomics."""
        return self.step_size_bytes


@dataclass(frozen=True)
class BarcodeResult:
    """Result of scanning a file into an ALBC-compatible barcode."""

    scan_params: ScanParams
    barcode_payload: bytes
    raw_entropy: Optional[List[float]] = None
    source_path: Optional[str] = None

    @property
    def barcode_len(self) -> int:
        return len(self.barcode_payload)


@dataclass(frozen=True)
class ModifiedRegion:
    """A contiguous modified region derived from differing entropy windows."""

    start_window: int
    end_window: int
    start_byte: int
    end_byte: int
    magnitude: float

    def to_legacy_tuple(self) -> Tuple[int, int, int, int]:
        return (self.start_window, self.end_window, self.start_byte, self.end_byte)


@dataclass(frozen=True)
class BarcodeComparison:
    """Rich comparison output used by the primitive-first API."""

    identical: bool
    regions: List[ModifiedRegion] = field(default_factory=list)
    summary: str = ""
    windows_compared: int = 0

    def to_legacy_tuples(self) -> List[Tuple[int, int, int, int]]:
        return [region.to_legacy_tuple() for region in self.regions]


@dataclass(frozen=True)
class DiffStats:
    """Pairwise delta metrics for two barcode payloads."""

    windows_compared: int
    avg_delta_raw: float
    avg_delta_normalized: float
    rms_delta_raw: float
    rms_delta_normalized: float
    max_delta_raw: float
    max_delta_normalized: float
    max_delta_window: int
    windows_above_threshold: int
    threshold: float


def regions_to_legacy_tuples(
    regions: Sequence[ModifiedRegion],
) -> List[Tuple[int, int, int, int]]:
    return [region.to_legacy_tuple() for region in regions]
