"""Primitive-first Aletheia API with no repository/database dependency."""

from .albc import ALBCParser, load_albc, save_albc
from .barcode import compare_barcodes, compare_quantized_payloads, compare_raw_entropy
from .scanner import DEFAULT_SCANNER_TIMEOUT_SECONDS, OdinScanner, scan_file
from .types import (
    BarcodeComparison,
    BarcodeResult,
    DiffStats,
    ModifiedRegion,
    ScanParams,
)

__all__ = [
    "ALBCParser",
    "BarcodeComparison",
    "BarcodeResult",
    "DEFAULT_SCANNER_TIMEOUT_SECONDS",
    "DiffStats",
    "ModifiedRegion",
    "OdinScanner",
    "ScanParams",
    "compare_barcodes",
    "compare_quantized_payloads",
    "compare_raw_entropy",
    "load_albc",
    "save_albc",
    "scan_file",
]
