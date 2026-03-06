"""Pure-Python entropy calculation fallback for environments without Odin binary."""

from __future__ import annotations

import math
from pathlib import Path
from typing import List, Sequence


def shannon_entropy(window: bytes, m_block_size: int = 1) -> float:
    """Compute Shannon entropy (bits/symbol) for a byte window."""
    if not window:
        return 0.0
    if m_block_size <= 1:
        counts = [0] * 256
        for value in window:
            counts[value] += 1
        total = len(window)
        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)
        return entropy

    counts = {}
    total = 0
    last_start = len(window) - m_block_size + 1
    if last_start <= 0:
        return 0.0
    for start in range(last_start):
        symbol = window[start : start + m_block_size]
        counts[symbol] = counts.get(symbol, 0) + 1
        total += 1
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def sliding_entropy(
    data: bytes,
    window_size: int,
    step_size: int,
    m_block_size: int = 1,
) -> List[float]:
    """Compute entropy values over a sliding window."""
    if window_size <= 0:
        raise ValueError("window_size must be > 0")
    if step_size <= 0:
        raise ValueError("step_size must be > 0")
    if step_size > window_size:
        raise ValueError("step_size must be <= window_size")

    if len(data) < window_size:
        return []

    values: List[float] = []
    last_start = len(data) - window_size
    for start in range(0, last_start + 1, step_size):
        values.append(shannon_entropy(data[start : start + window_size], m_block_size=m_block_size))
    return values


def quantize_entropy(values: Sequence[float], m_block_size: int = 1) -> bytes:
    """Quantize entropy values to u8 compatible with ALBC v1/v2 payloads."""
    if m_block_size <= 0:
        raise ValueError("m_block_size must be > 0")
    max_entropy = 8.0 * m_block_size
    quantized = bytearray()
    for value in values:
        normalized = 0.0 if max_entropy == 0 else max(0.0, min(1.0, value / max_entropy))
        quantized.append(int(round(normalized * 255.0)))
    return bytes(quantized)


def scan_file_entropy(
    file_path: str,
    window_size: int,
    step_size: int,
    m_block_size: int = 1,
    start_byte: int = 0,
    end_byte: int = 0,
) -> List[float]:
    """Compute sliding-window entropy for a file range using Python fallback."""
    data = Path(file_path).read_bytes()

    if start_byte < 0:
        raise ValueError("start_byte must be >= 0")
    if end_byte < 0:
        raise ValueError("end_byte must be >= 0")
    if end_byte and end_byte < start_byte:
        raise ValueError("end_byte must be >= start_byte")

    if end_byte == 0:
        clipped = data[start_byte:]
    else:
        clipped = data[start_byte:end_byte]

    return sliding_entropy(
        clipped,
        window_size=window_size,
        step_size=step_size,
        m_block_size=m_block_size,
    )
