"""Storage-independent barcode comparison primitives."""

from __future__ import annotations

import math
from typing import List, Sequence

from .types import BarcodeComparison, BarcodeResult, DiffStats, ModifiedRegion


def _summarize_regions(regions: Sequence[ModifiedRegion]) -> str:
    if not regions:
        return "No differences detected."
    if len(regions) == 1:
        region = regions[0]
        return (
            f"1 modified region: bytes {region.start_byte}-{region.end_byte} "
            f"(windows {region.start_window}-{region.end_window})."
        )
    return f"{len(regions)} modified regions detected."


def _merge_differing_windows(
    differing_windows: Sequence[int],
    magnitudes: Sequence[float],
    window_size: int,
    step_size: int,
) -> List[ModifiedRegion]:
    if not differing_windows:
        return []

    regions: List[ModifiedRegion] = []
    region_start = differing_windows[0]
    region_end = differing_windows[0]
    region_magnitudes: List[float] = [magnitudes[0]]

    for idx, window_idx in enumerate(differing_windows[1:], 1):
        if window_idx == region_end + 1:
            region_end = window_idx
            region_magnitudes.append(magnitudes[idx])
            continue

        regions.append(
            ModifiedRegion(
                start_window=region_start,
                end_window=region_end,
                start_byte=region_start * step_size,
                end_byte=region_end * step_size + window_size,
                magnitude=float(sum(region_magnitudes) / len(region_magnitudes)),
            )
        )

        region_start = window_idx
        region_end = window_idx
        region_magnitudes = [magnitudes[idx]]

    regions.append(
        ModifiedRegion(
            start_window=region_start,
            end_window=region_end,
            start_byte=region_start * step_size,
            end_byte=region_end * step_size + window_size,
            magnitude=float(sum(region_magnitudes) / len(region_magnitudes)),
        )
    )
    return regions


def compare_quantized_payloads(
    baseline_payload: bytes,
    actual_payload: bytes,
    window_size: int,
    step_size: int,
) -> BarcodeComparison:
    """Compare quantized barcode payload bytes and localize modified regions."""
    baseline_len = len(baseline_payload)
    actual_len = len(actual_payload)

    if baseline_len != actual_len:
        if baseline_len == 0:
            return BarcodeComparison(
                identical=(actual_len == 0),
                regions=[],
                summary="No comparable windows.",
                windows_compared=0,
            )
        total_bytes = baseline_len * step_size + (window_size - step_size)
        region = ModifiedRegion(
            start_window=0,
            end_window=baseline_len - 1,
            start_byte=0,
            end_byte=total_bytes,
            magnitude=1.0,
        )
        return BarcodeComparison(
            identical=False,
            regions=[region],
            summary="Barcode lengths differ; full baseline range marked as modified.",
            windows_compared=min(baseline_len, actual_len),
        )

    if baseline_payload == actual_payload:
        return BarcodeComparison(
            identical=True,
            regions=[],
            summary="No differences detected.",
            windows_compared=baseline_len,
        )

    differing_windows: List[int] = []
    magnitudes: List[float] = []
    for idx, (baseline_value, actual_value) in enumerate(zip(baseline_payload, actual_payload)):
        if baseline_value != actual_value:
            differing_windows.append(idx)
            magnitudes.append(abs(baseline_value - actual_value) / 255.0)

    regions = _merge_differing_windows(differing_windows, magnitudes, window_size, step_size)
    return BarcodeComparison(
        identical=False,
        regions=regions,
        summary=_summarize_regions(regions),
        windows_compared=baseline_len,
    )


def compare_raw_entropy(
    baseline_raw: Sequence[float],
    actual_raw: Sequence[float],
    window_size: int,
    step_size: int,
    threshold: float = 1e-9,
) -> BarcodeComparison:
    """Compare raw entropy arrays and localize regions above threshold."""
    baseline_len = len(baseline_raw)
    actual_len = len(actual_raw)

    if baseline_len != actual_len:
        comparable = min(baseline_len, actual_len)
        if comparable == 0:
            return BarcodeComparison(
                identical=(baseline_len == actual_len),
                regions=[],
                summary="No comparable windows.",
                windows_compared=0,
            )
        total_bytes = comparable * step_size + (window_size - step_size)
        region = ModifiedRegion(
            start_window=0,
            end_window=comparable - 1,
            start_byte=0,
            end_byte=total_bytes,
            magnitude=1.0,
        )
        return BarcodeComparison(
            identical=False,
            regions=[region],
            summary="Raw arrays differ in length; comparable range marked as modified.",
            windows_compared=comparable,
        )

    differing_windows: List[int] = []
    magnitudes: List[float] = []
    for idx, (baseline_value, actual_value) in enumerate(zip(baseline_raw, actual_raw)):
        delta = abs(baseline_value - actual_value)
        if delta > threshold:
            differing_windows.append(idx)
            magnitudes.append(delta)

    if not differing_windows:
        return BarcodeComparison(
            identical=True,
            regions=[],
            summary="No differences detected.",
            windows_compared=baseline_len,
        )

    regions = _merge_differing_windows(differing_windows, magnitudes, window_size, step_size)
    return BarcodeComparison(
        identical=False,
        regions=regions,
        summary=_summarize_regions(regions),
        windows_compared=baseline_len,
    )


def compare_barcodes(
    baseline: BarcodeResult,
    current: BarcodeResult,
    raw_threshold: float = 1e-9,
) -> BarcodeComparison:
    """
    Compare two full barcode results.

    Prefers raw-entropy comparison when both results carry raw values.
    Falls back to quantized payload byte comparison otherwise.
    """
    if baseline.raw_entropy is not None and current.raw_entropy is not None:
        return compare_raw_entropy(
            baseline.raw_entropy,
            current.raw_entropy,
            baseline.scan_params.window_size_bytes,
            baseline.scan_params.step_size_bytes,
            threshold=raw_threshold,
        )
    return compare_quantized_payloads(
        baseline.barcode_payload,
        current.barcode_payload,
        baseline.scan_params.window_size_bytes,
        baseline.scan_params.step_size_bytes,
    )


def compute_diff_stats(
    baseline_payload: bytes,
    actual_payload: bytes,
    threshold: float = 0.0,
) -> DiffStats:
    """Compute pairwise delta metrics for two quantized barcode payloads."""
    windows_compared = min(len(baseline_payload), len(actual_payload))
    if windows_compared == 0:
        raise ValueError("No comparable windows in barcode payloads")

    deltas = [
        abs(baseline_payload[idx] - actual_payload[idx]) for idx in range(windows_compared)
    ]
    avg_delta = sum(deltas) / windows_compared
    rms_delta = math.sqrt(sum(delta * delta for delta in deltas) / windows_compared)
    max_delta = max(deltas)
    max_delta_window = deltas.index(max_delta)
    windows_above_threshold = sum(1 for delta in deltas if delta > threshold)

    return DiffStats(
        windows_compared=windows_compared,
        avg_delta_raw=avg_delta,
        avg_delta_normalized=avg_delta / 255.0,
        rms_delta_raw=rms_delta,
        rms_delta_normalized=rms_delta / 255.0,
        max_delta_raw=float(max_delta),
        max_delta_normalized=float(max_delta) / 255.0,
        max_delta_window=max_delta_window,
        windows_above_threshold=windows_above_threshold,
        threshold=float(threshold),
    )
