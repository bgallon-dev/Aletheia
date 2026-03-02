"""
aletheia/algorithms.py
======================
Single source of truth for all algorithm version constants and
determinism-critical parameters.

A future engineer can answer "if I run ingest again next week on the same file,
do I get the same artifact_id?" by reading this file alone.

Versioning rule
---------------
When ANY constant here changes in a way that alters ingest or verify output:
  1. Add a new constant (e.g. ALGO_BARCODE_V2 = "barcode:v2").
  2. Leave the old constant unchanged — existing records must stay readable.
  3. Update consumers to use the new constant.
  4. Add a migration note to docs/contract.md Section 7.

Never rename or delete an existing constant.
"""

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Artifact-ID derivation
# ---------------------------------------------------------------------------

# Prefix frozen into the derivation formula:
#   SHA-256(ARTIFACT_ID_PREFIX || content_bytes || barcode_bytes)
# Changing this value would invalidate ALL existing artifact IDs.
ARTIFACT_ID_PREFIX: bytes = b"ALETHEIA_AR_V1"

# Human-readable token for the artifact-ID derivation algorithm.
ALGO_RECORD_V1: str = "record:v1"

# ---------------------------------------------------------------------------
# Barcode algorithm
# ---------------------------------------------------------------------------

# Python-side token for the entropy-barcode pipeline currently in use.
# The Odin binary's internal quantisation version is stored separately in
# ScanParams.quant_version (parsed from ALBC header bytes 20-23).
# Together they uniquely identify the barcode algorithm:
#   algo_version  → which Python-level pipeline spec
#   quant_version → which Odin-internal quantisation scheme
ALGO_BARCODE_V1: str = "barcode:v1"

# ---------------------------------------------------------------------------
# Zoom-scan strategy
# ---------------------------------------------------------------------------

ALGO_ZOOM_V1: str = "zoom:v1"


@dataclass(frozen=True)
class ZoomStrategy:
    """Immutable parameters for the fine-resolution zoom scan.

    All four fields are determinism-critical: changing any one alters
    which byte ranges are reported as modified during verification.

    To introduce new zoom parameters:
      1. Define ALGO_ZOOM_V2 = "zoom:v2".
      2. Create ZOOM_V2 = ZoomStrategy(..., version=ALGO_ZOOM_V2).
      3. Update ArtifactVerifier to select the right strategy.
      4. Leave ZOOM_V1 and ALGO_ZOOM_V1 unchanged.
    """

    window_size: int
    step_size: int
    margin_windows: int
    raw_threshold: float
    version: str = ALGO_ZOOM_V1


# Canonical zoom strategy instance — the only one that should be imported
# by verify.py for all active verifications.
ZOOM_V1 = ZoomStrategy(
    window_size=8192,     # 8 KiB
    step_size=2048,       # 2 KiB
    margin_windows=2,     # windows of context before/after each coarse region
    raw_threshold=1e-9,   # min abs(delta) in raw f64 entropy to count as a difference
)
