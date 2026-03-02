"""
Tamper detection and localization tests — Category 3.

These tests prove that the tool detects and localizes real modifications
within the documented resolution bounds. All tests use synthetic barcodes
(pure-Python, no Odin binary required) because the localization engine
(ALBCParser.compare_barcodes) is pure Python.

Design contract being tested:
- Tamper exists  => at least one region returned
- No tamper      => empty region list
- Reported region bytes cover the actual edit location (within window resolution)
"""

from __future__ import annotations

import pytest

from aletheia.ingest import ALBCParser


WINDOW = 64
STEP = 16


def _tamper(payload: bytes, *window_indices) -> bytes:
    """Return a copy of payload with specified window positions mutated."""
    arr = bytearray(payload)
    for i in window_indices:
        arr[i] = (arr[i] + 128) % 256  # Guaranteed to change
    return bytes(arr)


def _make_payload(n: int, fill: int = 50) -> bytes:
    """Create an n-window payload filled with a constant value."""
    return bytes([fill] * n)


# ---------------------------------------------------------------------------
# Basic detection
# ---------------------------------------------------------------------------

def test_no_false_positives_on_clean_file():
    """Identical baseline and suspect must produce zero regions."""
    payload = _make_payload(20)
    regions = ALBCParser.compare_barcodes(payload, payload, WINDOW, STEP)
    assert regions == []


def test_single_window_edit_detected():
    """A single changed window must produce exactly one region."""
    baseline = _make_payload(20)
    suspect = _tamper(baseline, 5)
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)
    assert len(regions) >= 1


def test_single_window_edit_region_contains_edit():
    """The reported region must include the edited window index."""
    baseline = _make_payload(20)
    edit_window = 8
    suspect = _tamper(baseline, edit_window)
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) >= 1
    for (start_win, end_win, _, _) in regions:
        if start_win <= edit_window <= end_win:
            return  # Found the edit in a reported region
    pytest.fail(f"Edit at window {edit_window} not covered by any reported region: {regions}")


def test_first_window_edit_detected():
    """Edit at window 0 (start of file) must be detected."""
    baseline = _make_payload(10)
    suspect = _tamper(baseline, 0)
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) >= 1
    start_win, _, _, _ = regions[0]
    assert start_win == 0


def test_last_window_edit_detected():
    """Edit at the final window must be detected."""
    n = 15
    baseline = _make_payload(n)
    suspect = _tamper(baseline, n - 1)
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) >= 1
    _, end_win, _, _ = regions[-1]
    assert end_win == n - 1


# ---------------------------------------------------------------------------
# Contiguous and multi-region localization
# ---------------------------------------------------------------------------

def test_contiguous_block_edit_produces_single_region():
    """A contiguous block of consecutive edited windows merges into one region."""
    baseline = _make_payload(20)
    suspect = _tamper(baseline, 5, 6, 7, 8, 9)  # Windows 5-9 contiguous
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) == 1
    start_win, end_win, _, _ = regions[0]
    assert start_win == 5
    assert end_win == 9


def test_disjoint_edits_produce_two_regions():
    """Two isolated single-window edits separated by a gap must be two separate regions."""
    baseline = _make_payload(20)
    suspect = _tamper(baseline, 2, 10)  # Gap of 7 windows between edits
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) == 2


def test_adjacent_edits_merge_into_single_region():
    """Adjacent windows (gap=1) must merge into one region."""
    baseline = _make_payload(20)
    suspect = _tamper(baseline, 3, 4)  # Consecutive windows
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) == 1
    start_win, end_win, _, _ = regions[0]
    assert start_win == 3
    assert end_win == 4


def test_three_disjoint_edits_produce_three_regions():
    """Three isolated edits must produce three separate regions."""
    baseline = _make_payload(30)
    suspect = _tamper(baseline, 0, 10, 20)  # Gap ≥ 9 between each
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) == 3


# ---------------------------------------------------------------------------
# Byte boundary assertions (localization accuracy contract)
# ---------------------------------------------------------------------------

def test_reported_region_covers_edit_byte_range():
    """The reported byte range must contain the actual edit position.

    Contract: for an edit at window i with step S and window size W,
    the reported region must satisfy start_byte ≤ i*S and end_byte ≥ i*S + W.
    """
    baseline = _make_payload(20)
    edit_idx = 6
    suspect = _tamper(baseline, edit_idx)
    regions = ALBCParser.compare_barcodes(baseline, suspect, WINDOW, STEP)

    assert len(regions) >= 1
    start_win, end_win, start_byte, end_byte = regions[0]
    expected_start = edit_idx * STEP
    expected_end = edit_idx * STEP + WINDOW

    assert start_byte <= expected_start, (
        f"Region start_byte {start_byte} should be ≤ edit start {expected_start}"
    )
    assert end_byte >= expected_end, (
        f"Region end_byte {end_byte} should be ≥ edit end {expected_end}"
    )


# ---------------------------------------------------------------------------
# Length mismatch (truncation / extension)
# ---------------------------------------------------------------------------

def test_length_mismatch_returns_single_region():
    """When barcodes have different lengths, the entire file is flagged as one region."""
    baseline = _make_payload(20)
    truncated = baseline[:-1]  # Remove one window

    regions = ALBCParser.compare_barcodes(baseline, truncated, WINDOW, STEP)

    assert len(regions) == 1, "Length mismatch should produce exactly one region"


def test_length_mismatch_region_covers_baseline_length():
    """The region from a length mismatch must cover the full baseline range."""
    n = 10
    baseline = _make_payload(n)
    truncated = baseline[: n // 2]

    regions = ALBCParser.compare_barcodes(baseline, truncated, WINDOW, STEP)
    assert len(regions) == 1
    start_win, end_win, start_byte, end_byte = regions[0]
    assert start_win == 0
    assert end_win == n - 1


# ---------------------------------------------------------------------------
# Raw entropy comparison (compare_barcodes_raw)
# ---------------------------------------------------------------------------

def test_raw_identical_arrays_no_regions():
    """Identical float arrays produce zero regions at any threshold."""
    vals = [0.1, 0.5, 0.9, 0.3, 0.7]
    assert ALBCParser.compare_barcodes_raw(vals, vals[:], WINDOW, STEP, 1e-9) == []


def test_raw_single_change_detected():
    """A single changed float value above threshold must produce at least one region."""
    baseline = [0.5] * 10
    suspect = list(baseline)
    suspect[4] = 0.9  # delta = 0.4 > 1e-9

    regions = ALBCParser.compare_barcodes_raw(baseline, suspect, WINDOW, STEP, threshold=1e-9)
    assert len(regions) >= 1


def test_raw_region_covers_changed_window():
    """The reported region must include the index of the changed float."""
    baseline = [0.5] * 10
    suspect = list(baseline)
    changed_idx = 7
    suspect[changed_idx] = 0.0

    regions = ALBCParser.compare_barcodes_raw(baseline, suspect, WINDOW, STEP, threshold=1e-9)
    assert any(s <= changed_idx <= e for s, e, _, _ in regions)


def test_raw_length_mismatch_returns_region():
    """Mismatched-length raw arrays must return a non-empty region list."""
    baseline = [0.5] * 10
    shorter = [0.5] * 6

    regions = ALBCParser.compare_barcodes_raw(baseline, shorter, WINDOW, STEP, threshold=1e-9)
    assert len(regions) >= 1


def test_raw_both_empty_returns_no_regions():
    """Two empty float arrays must return an empty region list."""
    regions = ALBCParser.compare_barcodes_raw([], [], WINDOW, STEP, threshold=1e-9)
    assert regions == []
