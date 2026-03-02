"""
Aletheia Repository Ingest - Content-Addressed Storage with Barcode Verification

This module implements the complete ingest workflow:
1. Run Odin scanner to produce .albc barcode
2. Compute content_object_id and barcode_object_id
3. Store both objects (deduplicated)
4. Parse .albc header for scan parameters
5. Build Artifact Record JSON (aletheia/ar/1)
6. Derive artifact_id from canonical hash
7. Insert into SQLite index
"""

import hashlib
import json
import logging
import os
import struct
import subprocess
import tempfile
import math
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List, Union
from shutil import which
from .utils import hash_and_copy_file

from .algorithms import ARTIFACT_ID_PREFIX, ALGO_BARCODE_V1
from .domain import ArtifactRecord, ScanParams
from .repository import AletheiaRepository, RepositoryNotInitializedError


try:
    from .identity import IdentityLink, IdentityError

    IDENTITY_AVAILABLE = True
except ImportError:
    IDENTITY_AVAILABLE = False


DEFAULT_SCANNER_TIMEOUT_SECONDS = 600
logger = logging.getLogger(__name__)


class ALBCParser:
    """Parser for ALBC (Aletheia Barcode) binary format."""

    MAGIC_V1 = b"ALBC0001"
    MAGIC_V2 = b"ALBC0002"
    HEADER_SIZE_V1 = 32
    HEADER_SIZE_V2 = 40  # Adds raw_data_offset field

    @staticmethod
    def detect_version(data: bytes) -> Optional[int]:
        """Detect ALBC format version from magic bytes."""
        if len(data) < 8:
            return None
        magic = data[0:8]
        if magic == ALBCParser.MAGIC_V1:
            return 1
        elif magic == ALBCParser.MAGIC_V2:
            return 2
        return None

    @staticmethod
    def parse_header(albc_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC header from binary data (version-aware).

        Only validates header bytes are present - does NOT validate payload length.
        Use parse_full() when you need payload validation.

        Header layout v1 (little-endian, 32 bytes):
          0..7   : magic "ALBC0001" (8 bytes)
          8..11  : window_size_bytes u32
          12..15 : step_size_bytes   u32
          16..19 : m_block_size      u32
          20..23 : quant_version     u32
          24..31 : barcode_len       u64
          32..   : quantized barcode bytes

        Header layout v2 (little-endian, 40 bytes):
          0..31  : same as v1
          32..39 : raw_data_offset   u64 (0 if no raw data)
          40..   : quantized barcode bytes
          ???..  : raw f64 array (at raw_data_offset, if non-zero)
        """
        version = ALBCParser.detect_version(albc_data)
        if version is None:
            return None

        header_size = (
            ALBCParser.HEADER_SIZE_V1 if version == 1 else ALBCParser.HEADER_SIZE_V2
        )

        # Only check we have enough bytes for the HEADER
        if len(albc_data) < header_size:
            return None

        # Parse header fields
        window_size_bytes = struct.unpack("<I", albc_data[8:12])[0]
        step_size_bytes = struct.unpack("<I", albc_data[12:16])[0]
        m_block_size = struct.unpack("<I", albc_data[16:20])[0]
        quant_version = struct.unpack("<I", albc_data[20:24])[0]
        barcode_len = struct.unpack("<Q", albc_data[24:32])[0]

        result = {
            "format_version": version,
            "header_size": header_size,  # Useful for callers
            "window_size_bytes": window_size_bytes,
            "step_size_bytes": step_size_bytes,
            "m_block_size": m_block_size,
            "quant_version": f"v{quant_version}",
            "barcode_len": barcode_len,
            "raw_data_offset": 0,
        }

        if version == 2:
            result["raw_data_offset"] = struct.unpack("<Q", albc_data[32:40])[0]

        # NO payload length validation here - that's parse_full's job
        return result

    @staticmethod
    def get_header_size(version: int) -> int:
        """Get header size for a specific format version."""
        return ALBCParser.HEADER_SIZE_V1 if version == 1 else ALBCParser.HEADER_SIZE_V2

    @staticmethod
    def parse_full(albc_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC header AND payload. Validates total file length.

        Returns None if file is truncated or malformed.
        """
        header = ALBCParser.parse_header(albc_data)
        if header is None:
            return None

        header_size = header["header_size"]
        barcode_len = header["barcode_len"]

        # Validate we have enough data for the payload
        required_size = header_size + barcode_len
        if len(albc_data) < required_size:
            return None  # Truncated file

        payload = albc_data[header_size : header_size + barcode_len]

        # Belt-and-suspenders: verify slice returned expected length
        # (This should always pass given the check above, but makes intent explicit)
        assert len(payload) == barcode_len, "Slice length mismatch"

        return {**header, "barcode_payload": payload}

    @staticmethod
    def parse_full_with_raw(albc_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC including raw f64 data (v2 only).

        Returns dict with 'barcode_payload' (bytes) and optionally 'raw_entropy' (list of floats).
        """
        result = ALBCParser.parse_full(albc_data)
        if result is None:
            return None

        raw_offset = result.get("raw_data_offset", 0)
        if raw_offset > 0 and result["format_version"] == 2:
            barcode_len = result["barcode_len"]
            raw_size = barcode_len * 8
            if raw_offset + raw_size > len(albc_data):
                return None
            raw_bytes = albc_data[raw_offset : raw_offset + raw_size]
            # Unpack as little-endian f64 array
            result["raw_entropy"] = list(struct.unpack(f"<{barcode_len}d", raw_bytes))

        return result

    @staticmethod
    def parse_header_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC header directly from file (without loading entire file).

        Reads up to 40 bytes (max header size for v2), detects version,
        and parses accordingly.

        Does NOT validate that file length matches barcode_len (use parse_from_file for that).
        """
        # Read enough bytes for the largest header (v2 = 40 bytes)
        max_header_size = ALBCParser.HEADER_SIZE_V2

        with open(file_path, "rb") as f:
            header_bytes = f.read(max_header_size)

        # Delegate to parse_header which handles version detection
        return ALBCParser.parse_header(header_bytes)

    @staticmethod
    def parse_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC directly from file (memory-efficient for large barcodes).

        Returns None if file is missing, has invalid header, or is truncated.
        """
        header = ALBCParser.parse_header_from_file(file_path)
        if header is None:
            return None

        # Use the header_size from parsed header (version-aware)
        header_size = header["header_size"]
        expected_len = header["barcode_len"]

        with open(file_path, "rb") as f:
            f.seek(header_size)
            # FIX: Read exactly barcode_len bytes, not to EOF
            # This is critical for v2 format which appends raw f64 data after quant payload
            payload = f.read(expected_len)

        # Validate payload length matches header claim
        actual_len = len(payload)
        if actual_len != expected_len:
            # Could log: f"ALBC truncated: expected {expected_len} bytes, got {actual_len}"
            return None

        return {**header, "barcode_payload": payload}

    @staticmethod
    def parse_from_file_with_raw(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC from file including raw f64 data (v2 only).

        Memory-efficient: reads quant and raw sections separately without loading entire file.

        Returns dict with 'barcode_payload' (bytes) and optionally 'raw_entropy' (list of floats).
        """
        result = ALBCParser.parse_from_file(file_path)
        if result is None:
            return None

        raw_offset = result.get("raw_data_offset", 0)
        if raw_offset > 0 and result["format_version"] == 2:
            barcode_len = result["barcode_len"]
            raw_size = barcode_len * 8  # 8 bytes per f64

            file_size = file_path.stat().st_size
            if raw_offset + raw_size > file_size:
                return None

            with open(file_path, "rb") as f:
                f.seek(raw_offset)
                raw_bytes = f.read(raw_size)

            if len(raw_bytes) == raw_size:
                # Unpack as little-endian f64 array
                result["raw_entropy"] = list(
                    struct.unpack(f"<{barcode_len}d", raw_bytes)
                )

        return result

    @staticmethod
    def compare_barcodes(
        baseline_payload: bytes, actual_payload: bytes, window_size: int, step_size: int
    ) -> List[Tuple[int, int, int, int]]:
        """
        Compare two barcode payloads and return regions that differ.

        Each barcode byte represents the quantized entropy of one window.
        Windows overlap by (window_size - step_size) bytes.

        Args:
            baseline_payload: Expected barcode bytes (from stored artifact)
            actual_payload: Actual barcode bytes (from current file)
            window_size: Window size in bytes used during scanning
            step_size: Step size in bytes used during scanning

        Returns:
            List of (start_window, end_window, start_byte, end_byte) tuples
            representing contiguous regions of difference.
            Empty list if barcodes are identical or incomparable.
        """
        if len(baseline_payload) != len(actual_payload):
            # Lengths differ - can't do window-by-window comparison
            # Return entire file as one region
            total_bytes = len(baseline_payload) * step_size + (window_size - step_size)
            return [(0, len(baseline_payload) - 1, 0, total_bytes)]

        if baseline_payload == actual_payload:
            return []

        # Find windows that differ
        differing_windows = []
        for i in range(len(baseline_payload)):
            if baseline_payload[i] != actual_payload[i]:
                differing_windows.append(i)

        if not differing_windows:
            return []

        # Merge adjacent windows into contiguous regions
        regions = []
        region_start = differing_windows[0]
        region_end = differing_windows[0]

        for window_idx in differing_windows[1:]:
            if window_idx == region_end + 1:
                # Contiguous - extend region
                region_end = window_idx
            else:
                # Gap - save current region, start new one
                start_byte = region_start * step_size
                end_byte = region_end * step_size + window_size
                regions.append((region_start, region_end, start_byte, end_byte))
                region_start = window_idx
                region_end = window_idx

        # Don't forget the last region
        start_byte = region_start * step_size
        end_byte = region_end * step_size + window_size
        regions.append((region_start, region_end, start_byte, end_byte))

        return regions

    @staticmethod
    def compare_barcodes_raw(
        baseline_raw: List[float],
        actual_raw: List[float],
        window_size: int,
        step_size: int,
        threshold: float = 1e-9,
    ) -> List[Tuple[int, int, int, int]]:
        """
        Compare raw entropy arrays and return contiguous differing regions.

        A window is considered different when abs(delta) > threshold.
        """
        if len(baseline_raw) != len(actual_raw):
            comparable = min(len(baseline_raw), len(actual_raw))
            if comparable == 0:
                return []
            total_bytes = comparable * step_size + (window_size - step_size)
            return [(0, comparable - 1, 0, total_bytes)]

        differing_windows = [
            i
            for i, (a, b) in enumerate(zip(baseline_raw, actual_raw))
            if abs(a - b) > threshold
        ]
        if not differing_windows:
            return []

        regions: List[Tuple[int, int, int, int]] = []
        region_start = differing_windows[0]
        region_end = differing_windows[0]

        for window_idx in differing_windows[1:]:
            if window_idx == region_end + 1:
                region_end = window_idx
                continue

            start_byte = region_start * step_size
            end_byte = region_end * step_size + window_size
            regions.append((region_start, region_end, start_byte, end_byte))
            region_start = window_idx
            region_end = window_idx

        start_byte = region_start * step_size
        end_byte = region_end * step_size + window_size
        regions.append((region_start, region_end, start_byte, end_byte))
        return regions


class ArtifactRecordBuilder:
    """Builder for Aletheia Artifact Records (aletheia/ar/1)."""

    VERSION = ArtifactRecord.VERSION

    @staticmethod
    def build(
        content_object_id: str,
        barcode_object_id: str,
        scan_params: Union[ScanParams, Dict[str, Any]],
        created_at_unix_ms: int,
        original_filename: str,
    ) -> Dict[str, Any]:
        """Build a complete Artifact Record."""
        scan_params_obj = (
            scan_params if isinstance(scan_params, ScanParams) else ScanParams.from_dict(scan_params)
        )
        record = ArtifactRecord(
            record_version=ArtifactRecordBuilder.VERSION,
            content_object_id=content_object_id,
            barcode_object_id=barcode_object_id,
            scan_params=scan_params_obj,
            created_at_unix_ms=created_at_unix_ms,
            metadata=ArtifactRecord.default_metadata(original_filename),
        )
        return record.to_dict()

    @staticmethod
    def derive_artifact_id(content_object_id: str, barcode_object_id: str) -> str:
        """
        Derive deterministic artifact_id for record-level deduplication.

        Same file + same scan params = same barcode_object_id = same artifact_id.
        This enables idempotent ingestion: re-ingesting the same file with
        identical parameters will deduplicate at the record level.

        Formula: SHA-256("ALETHEIA_AR_V1" || content_object_id || barcode_object_id)
        """
        prefix = ARTIFACT_ID_PREFIX
        content_bytes = bytes.fromhex(content_object_id)
        barcode_bytes = bytes.fromhex(barcode_object_id)

        data = prefix + content_bytes + barcode_bytes
        return hashlib.sha256(data).hexdigest()


class OdinScanner:
    """Interface to Odin entropy scanner."""

    def __init__(
        self, odin_binary: Optional[str] = None, require_binary: bool = True
    ):
        """
        Initialize scanner.

        Args:
            odin_binary: Path to compiled Odin entropy binary.
                        If None, assumes 'entropy' in PATH or looks in relative paths.
            require_binary: If False, skip binary resolution for parser-only operations.
        """
        if require_binary:
            self.odin_binary = odin_binary or self._find_binary()
        else:
            self.odin_binary = odin_binary or ""

    def _find_binary(self) -> str:
        """Locate the Odin entropy scanner binary."""
        env_path = os.environ.get("ODIN_BINARY")
        if env_path and self._check_binary(env_path):
            return env_path
        candidates = [
            "entropy",
            "entropy.exe",
            "odin_entropy/entropy",
            "odin_entropy/entropy.exe",
            "../odin_entropy/entropy",
            "../odin_entropy/entropy.exe",
            "../entropy/odin_entropy/entropy",
            "../entropy/odin_entropy/entropy.exe",
            "../../entropy/odin_entropy/entropy",
            "../../entropy/odin_entropy/entropy.exe",
        ]

        for candidate in candidates:
            if self._check_binary(candidate):
                return candidate

        raise FileNotFoundError(
            "Could not locate Odin entropy scanner binary. "
            "Please compile it first or specify path with ODIN_BINARY environment variable."
        )

    def _check_binary(self, path: str) -> bool:
        """Check if binary exists and is executable."""
        # First try PATH resolution
        if which(path) is not None:
            return True

        # Check if file exists at given path
        p = Path(path)
        if not p.exists():
            return False

        # Try running without args - accept exit codes 0 or 2
        try:
            result = subprocess.run([str(p)], capture_output=True, timeout=2)
            return result.returncode in [0, 2]
        except Exception:
            return False

    def scan(
        self,
        file_path: str,
        window_size: int = 65536,  # 64KB default
        step_size: int = 16384,  # 16KB default
        m: int = 1,
        threads: int = 0,
        verbose: bool = True,
        start_byte: int = 0,
        end_byte: int = 0,
        output_format: int = 1,  # NEW: ALBC format version (1 or 2)
        timeout_seconds: int = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    ) -> Tuple[bytes, str]:
        """
        Run Odin scanner on file.

        Args:
            file_path: Path to file to scan
            window_size: Sliding window size in bytes
            step_size: Step size between windows
            m: Block size for entropy calculation (1=bytes, 2=pairs, etc.)
            threads: Number of threads (0=auto)
            verbose: Print progress info
            start_byte: Start offset for partial scan (0=beginning)
            end_byte: End offset for partial scan (0=end of file)
            output_format: ALBC output format version (1=quantized, 2=quantized+raw)
            timeout_seconds: Scanner subprocess timeout in seconds

        Returns:
            (albc_bytes, temp_path): The barcode data and temporary file path
        """
        with tempfile.NamedTemporaryFile(suffix=".albc", delete=False) as tmp:
            tmp_path = tmp.name

        cmd = [
            self.odin_binary,
            file_path,  # Input file comes right after binary (no "scan" subcommand)
            "--window",
            str(window_size),
            "--step",
            str(step_size),
            "--m",
            str(m),
            "--output",
            tmp_path,
        ]

        if threads > 0:
            cmd.extend(["--threads", str(threads)])

        if start_byte > 0:
            cmd.extend(["--start", str(start_byte)])

        if end_byte > 0:
            cmd.extend(["--end", str(end_byte)])

        # NEW: Add format version flag for v2+
        if output_format >= 2:
            cmd.extend(["--format", str(output_format)])

        if not verbose:
            cmd.append("--quiet")

        if verbose:
            logger.info("Running scanner command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout_seconds,
            )

            if verbose and result.stdout:
                logger.info("%s", result.stdout.rstrip())

            # Read the generated barcode file
            albc_bytes = Path(tmp_path).read_bytes()
            return albc_bytes, tmp_path

        except subprocess.TimeoutExpired as e:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise TimeoutError(
                f"Scanner timed out after {timeout_seconds}s for file: {file_path}"
            ) from e
        except subprocess.CalledProcessError as e:
            logger.error("Scanner error: %s", (e.stderr or "").strip())
            # Clean up temp file
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise
        except Exception:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise

    def diff(
        self, file1_path: str, file2_path: str, threshold: float = 0.0
    ) -> Dict[str, Any]:
        """
        Compare two barcode files in Python using ALBC parser output.

        Args:
            file1_path: Path to first .albc file (baseline)
            file2_path: Path to second .albc file (actual)
            threshold: Minimum delta to report (default: 0)

        Returns:
            Dict with comparison results:
            {
                "file1": str,
                "file2": str,
                "windows_compared": int,
                "avg_delta_raw": float,
                "avg_delta_normalized": float,
                "rms_delta_raw": float,
                "rms_delta_normalized": float,
                "max_delta_raw": float,
                "max_delta_normalized": float,
                "max_delta_window": int,
                "windows_above_threshold": int,
                "threshold": float
            }

        Raises:
            ValueError: If ALBC files are invalid or incomparable
        """
        parser = ALBCParser()
        parsed1 = parser.parse_from_file(Path(file1_path))
        parsed2 = parser.parse_from_file(Path(file2_path))

        if parsed1 is None:
            raise ValueError(f"Invalid or truncated ALBC file: {file1_path}")
        if parsed2 is None:
            raise ValueError(f"Invalid or truncated ALBC file: {file2_path}")

        payload1 = parsed1.get("barcode_payload", b"")
        payload2 = parsed2.get("barcode_payload", b"")

        windows_compared = min(len(payload1), len(payload2))
        if windows_compared == 0:
            raise ValueError("No comparable windows in ALBC files")

        deltas = [
            abs(payload1[i] - payload2[i])
            for i in range(windows_compared)
        ]
        avg_delta = sum(deltas) / windows_compared
        rms_delta = math.sqrt(sum(d * d for d in deltas) / windows_compared)
        max_delta = max(deltas)
        max_delta_window = deltas.index(max_delta)
        windows_above_threshold = sum(1 for d in deltas if d > threshold)

        return {
            "file1": str(file1_path),
            "file2": str(file2_path),
            "windows_compared": windows_compared,
            "avg_delta_raw": avg_delta,
            "avg_delta_normalized": avg_delta / 255.0,
            "rms_delta_raw": rms_delta,
            "rms_delta_normalized": rms_delta / 255.0,
            "max_delta_raw": float(max_delta),
            "max_delta_normalized": float(max_delta) / 255.0,
            "max_delta_window": max_delta_window,
            "windows_above_threshold": windows_above_threshold,
            "threshold": float(threshold),
        }


class IngestPipeline:
    """Complete ingest pipeline for Aletheia repository."""

    def __init__(
        self,
        repo_root: str = ".",
        odin_binary: Optional[str] = None,
        auto_init: bool = True,
    ):
        """
        Initialize ingest pipeline.

        Args:
            repo_root: Repository root directory
            odin_binary: Path to Odin scanner binary (optional)
            auto_init: Auto-initialize repository if not set up
        """
        try:
            self.repo = AletheiaRepository(repo_root, auto_init=auto_init)
        except RepositoryNotInitializedError as e:
            logger.error("Repository initialization failed: %s", e)
            raise

        self.scanner = OdinScanner(odin_binary)
        self.parser = ALBCParser()
        self.identity: Optional[IdentityLink] = None
        if IDENTITY_AVAILABLE:
            try:
                self.identity = IdentityLink()
            except Exception:
                pass  # Identity system not configured, signing disabled

    def _load_defaults(self) -> Dict[str, Any]:
        """Load default scan parameters from config.json."""
        if self.repo.config_path.exists():
            with open(self.repo.config_path, "r") as f:
                config = json.load(f)
                return config.get("defaults", {})
        return {}

    def ingest(
        self,
        file_path: str,
        window_size: int = 65536,
        step_size: int = 16384,
        m: int = 1,
        threads: int = 0,
        verbose: bool = True,
        keep_temp: bool = False,
        sign_with: Optional[str] = None,
        passphrase: Optional[str] = None,
        output_format: int = 1,  # NEW: ALBC format version
    ) -> str:
        """
        Ingest a file into the repository.

        Args:
            file_path: Path to file to ingest
            window_size: Sliding window size
            step_size: Step size between windows
            m: Block size for entropy calculation
            threads: Number of threads (0=auto)
            verbose: Print progress info
            keep_temp: Keep temporary files after ingest
            sign_with: Optional key_id to sign the artifact record
            passphrase: Passphrase for signing key
            output_format: ALBC format version (1 or 2)

        Returns:
            artifact_id: The unique identifier for this artifact
        """
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        snapshot_path = self.repo.tmp_dir / f"snapshot.{uuid.uuid4().hex}.bin"
        temp_albc_path: Optional[str] = None

        if verbose:
            logger.info("=== Ingesting: %s ===", file_path_obj.name)

        try:
            # Step 1: Snapshot source and hash in a single pass.
            if verbose:
                logger.info("[1/7] Capturing immutable ingest snapshot...")
            content_object_id, file_size = hash_and_copy_file(file_path_obj, snapshot_path)

            # Step 2: Run Odin scanner against snapshot (not mutable source file).
            if verbose:
                logger.info(
                    "[2/7] Running Odin scanner (window=%s, step=%s, m=%s)...",
                    window_size,
                    step_size,
                    m,
                )
            albc_bytes, temp_albc_path = self.scanner.scan(
                str(snapshot_path),
                window_size=window_size,
                step_size=step_size,
                m=m,
                threads=threads,
                verbose=verbose,
                output_format=output_format,
            )

            # Step 3: Content hash was computed from snapshot.
            if verbose:
                logger.info("[3/7] Finalizing content hash...")
                size_mb = file_size / (1024 * 1024)
                logger.info("  File size: %s bytes (%.2f MB)", f"{file_size:,}", size_mb)
                logger.info("  content_object_id: %s...", content_object_id[:16])

            # Step 4: Compute barcode hash (barcodes are small, can use in-memory)
            if verbose:
                logger.info("[4/7] Computing barcode hash...")
            barcode_object_id = hashlib.sha256(albc_bytes).hexdigest()

            if verbose:
                barcode_size_kb = len(albc_bytes) / 1024
                logger.info(
                    "  Barcode size: %s bytes (%.2f KB)",
                    f"{len(albc_bytes):,}",
                    barcode_size_kb,
                )
                logger.info("  barcode_object_id: %s...", barcode_object_id[:16])

            # Derive artifact_id early for idempotency check
            artifact_id = ArtifactRecordBuilder.derive_artifact_id(
                content_object_id, barcode_object_id
            )

            # Check if artifact already exists (strict idempotent ingest)
            if self.repo.artifact_exists(artifact_id):
                self.repo.ensure_artifact_indexed(artifact_id)

                if verbose:
                    logger.info("Artifact already exists: %s...", artifact_id[:16])
                    logger.info("  Skipping re-ingestion (idempotent operation)")
                    logger.info("  Content:     %s", content_object_id)
                    logger.info("  Barcode:     %s", barcode_object_id)
                return artifact_id

            # Step 5: Store content object from immutable snapshot.
            if verbose:
                logger.info("[5/7] Storing content object (streaming)...")
            stored_content_id, stored_size = self.repo.store_object_from_file(
                str(snapshot_path), "content"
            )
            if stored_content_id != content_object_id or stored_size != file_size:
                raise ValueError(
                    "Stored content hash/size mismatch against ingest snapshot. "
                    f"expected=({content_object_id}, {file_size}), "
                    f"actual=({stored_content_id}, {stored_size})"
                )

            # Step 6: Store barcode object (small, can use in-memory)
            if verbose:
                logger.info("[6/7] Storing barcode object...")
            self.repo.store_object(albc_bytes, "barcode")

            # Step 7: Parse ALBC header (only reads 32-40 bytes depending on version)
            if verbose:
                logger.info("[7/7] Parsing barcode header...")
            header = self.parser.parse_header(albc_bytes)
            if header is None:
                raise ValueError("Failed to parse ALBC header")

            scan_params = ScanParams.from_albc_header(header, algo_version=ALGO_BARCODE_V1)

            if verbose:
                logger.info(
                    "  Scan params: WS=%s, SS=%s, m=%s",
                    scan_params.window_size_bytes,
                    scan_params.step_size_bytes,
                    scan_params.m_block_size,
                )
                logger.info("  Format version: ALBC000%s", scan_params.format_version)

            # Finalize: Build and store artifact record
            if verbose:
                logger.info("[final] Building Artifact Record...")

            created_at_unix_ms = int(datetime.utcnow().timestamp() * 1000)

            artifact_record = ArtifactRecordBuilder.build(
                content_object_id=content_object_id,
                barcode_object_id=barcode_object_id,
                scan_params=scan_params,
                created_at_unix_ms=created_at_unix_ms,
                original_filename=file_path_obj.name,
            )

            # NEW: Sign artifact record if requested
            if sign_with:
                if verbose:
                    logger.info("[final-sign] Signing artifact record with key: %s...", sign_with)

                if not self.identity:
                    raise ValueError(
                        "Identity system not available. Install cryptography package."
                    )

                try:
                    signature_block = self.identity.sign_artifact_record(
                        artifact_record, key_id=sign_with, passphrase=passphrase
                    )
                    artifact_record["identity_link"] = signature_block

                    if verbose:
                        logger.info("  Signed by:    %s", signature_block["key_id"])
                        logger.info("  Fingerprint:  %s", signature_block["fingerprint"])
                        logger.info("  Signed at:    %s", signature_block["signed_at"])

                except Exception as e:
                    raise ValueError(f"Failed to sign artifact: {e}")

            if verbose:
                logger.info("  artifact_id: %s...", artifact_id[:16])

            self.repo.store_artifact(artifact_id, artifact_record)

            if verbose:
                logger.info("Successfully ingested: %s", file_path_obj.name)
                logger.info("  Artifact ID: %s", artifact_id)
                logger.info("  Content:     %s", content_object_id)
                logger.info("  Barcode:     %s", barcode_object_id)
                logger.info("  Record:      records/%s.json", artifact_id)

            return artifact_id

        finally:
            # Cleanup temp barcode file unless requested to keep
            if temp_albc_path and not keep_temp:
                try:
                    Path(temp_albc_path).unlink()
                except OSError:
                    pass
            # Snapshot is always temporary.
            try:
                snapshot_path.unlink()
            except OSError:
                pass


