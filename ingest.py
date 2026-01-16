#!/usr/bin/env python3
"""
Aletheia Repository Ingest - Content-Addressed Storage with Barcode Verification

Usage:
    python ingest.py <file>

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
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List
from shutil import which
from utils import compute_file_hash

from repository import AletheiaRepository, RepositoryNotInitializedError


try:
    from identity import IdentityLink, IdentityError

    IDENTITY_AVAILABLE = True
except ImportError:
    IDENTITY_AVAILABLE = False


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
            raw_bytes = albc_data[raw_offset : raw_offset + barcode_len * 8]
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


class ArtifactRecordBuilder:
    """Builder for Aletheia Artifact Records (aletheia/ar/1)."""

    VERSION = "aletheia/ar/1"

    @staticmethod
    def build(
        content_object_id: str,
        barcode_object_id: str,
        scan_params: Dict[str, Any],
        created_at_unix_ms: int,
        original_filename: str,
    ) -> Dict[str, Any]:
        """Build a complete Artifact Record."""
        return {
            "record_version": ArtifactRecordBuilder.VERSION,
            "content_object_id": content_object_id,
            "barcode_object_id": barcode_object_id,
            "scan_params": scan_params,
            "created_at_unix_ms": created_at_unix_ms,
            "metadata": {
                "original_filename": original_filename,
                "ingested_from": "local",
                "chain_of_custody": "single_node",
            },
        }

    @staticmethod
    def derive_artifact_id(content_object_id: str, barcode_object_id: str) -> str:
        """
        Derive deterministic artifact_id for record-level deduplication.

        Same file + same scan params = same barcode_object_id = same artifact_id.
        This enables idempotent ingestion: re-ingesting the same file with
        identical parameters will deduplicate at the record level.

        Formula: SHA-256("ALETHEIA_AR_V1" || content_object_id || barcode_object_id)
        """
        prefix = b"ALETHEIA_AR_V1"
        content_bytes = bytes.fromhex(content_object_id)
        barcode_bytes = bytes.fromhex(barcode_object_id)

        data = prefix + content_bytes + barcode_bytes
        return hashlib.sha256(data).hexdigest()


class OdinScanner:
    """Interface to Odin entropy scanner."""

    def __init__(self, odin_binary: Optional[str] = None):
        """
        Initialize scanner.

        Args:
            odin_binary: Path to compiled Odin entropy binary.
                        If None, assumes 'entropy' in PATH or looks in relative paths.
        """
        self.odin_binary = odin_binary or self._find_binary()

    def _find_binary(self) -> str:
        """Locate the Odin entropy scanner binary."""
        # Check common locations
        candidates = [
            "entropy",
            "entropy.exe",
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
            print(f"  Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            if verbose and result.stdout:
                print(result.stdout, end="")

            # Read the generated barcode file
            albc_bytes = Path(tmp_path).read_bytes()
            return albc_bytes, tmp_path

        except subprocess.CalledProcessError as e:
            print(f"Scanner error: {e.stderr}", file=sys.stderr)
            # Clean up temp file
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            raise

    def diff(
        self, file1_path: str, file2_path: str, threshold: float = 0.0
    ) -> Dict[str, Any]:
        """
        Compare two barcode files using Odin entropy diff.

        This delegates to the Odin binary rather than reimplementing
        comparison logic in Python - single source of truth.

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
            subprocess.CalledProcessError: If diff command fails
            json.JSONDecodeError: If output parsing fails
        """
        cmd = [self.odin_binary, "diff", file1_path, file2_path, "--json"]

        if threshold > 0:
            cmd.extend(["--threshold", str(threshold)])

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        return json.loads(result.stdout)


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
            print(f"Error: {e}", file=sys.stderr)
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

        if verbose:
            print(f"\n=== Ingesting: {file_path_obj.name} ===\n")

        # Step 1: Run Odin scanner (generates barcode file)
        if verbose:
            print(
                f"[1/7] Running Odin scanner (window={window_size}, step={step_size}, m={m})..."
            )
        albc_bytes, temp_albc_path = self.scanner.scan(
            file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            threads=threads,
            verbose=verbose,
            output_format=output_format,  # NEW: Pass format version
        )

        try:
            # Step 2: Compute content hash (streaming - no RAM limit)
            if verbose:
                print("[2/7] Computing content hash (streaming)...")
            content_object_id, file_size = compute_file_hash(file_path_obj)

            if verbose:
                size_mb = file_size / (1024 * 1024)
                print(f"  File size: {file_size:,} bytes ({size_mb:.2f} MB)")
                print(f"  content_object_id: {content_object_id[:16]}...")

            # Step 3: Compute barcode hash (barcodes are small, can use in-memory)
            if verbose:
                print("[3/7] Computing barcode hash...")
            barcode_object_id = hashlib.sha256(albc_bytes).hexdigest()

            if verbose:
                barcode_size_kb = len(albc_bytes) / 1024
                print(
                    f"  Barcode size: {len(albc_bytes):,} bytes ({barcode_size_kb:.2f} KB)"
                )
                print(f"  barcode_object_id: {barcode_object_id[:16]}...")

            # Derive artifact_id early for idempotency check
            artifact_id = ArtifactRecordBuilder.derive_artifact_id(
                content_object_id, barcode_object_id
            )

            # Check if artifact already exists (strict idempotent ingest)
            if self.repo.artifact_exists(artifact_id):
                self.repo.ensure_artifact_indexed(artifact_id)

                if verbose:
                    print(f"\n⊙ Artifact already exists: {artifact_id[:16]}...")
                    print(f"  Skipping re-ingestion (idempotent operation)")
                    print(f"  Content:     {content_object_id}")
                    print(f"  Barcode:     {barcode_object_id}")
                return artifact_id

            # Step 4: Store content object (streaming copy - only reads file once more)
            if verbose:
                print("[4/7] Storing content object (streaming)...")
            self.repo.store_object_from_file(file_path, "content")

            # Step 5: Store barcode object (small, can use in-memory)
            if verbose:
                print("[5/7] Storing barcode object...")
            self.repo.store_object(albc_bytes, "barcode")

            # Step 6: Parse ALBC header (only reads 32-40 bytes depending on version)
            if verbose:
                print("[6/7] Parsing barcode header...")
            header = self.parser.parse_header(albc_bytes)
            if header is None:
                raise ValueError("Failed to parse ALBC header")

            # Build scan_params with canonical _bytes key names
            scan_params = {
                "window_size_bytes": header["window_size_bytes"],
                "step_size_bytes": header["step_size_bytes"],
                "m_block_size": header["m_block_size"],
                "quant_version": header["quant_version"],
                "barcode_len": header["barcode_len"],
                "format_version": header.get("format_version", 1),
                "raw_data_offset": header.get("raw_data_offset", 0),
            }

            if verbose:
                print(
                    f"  Scan params: WS={scan_params['window_size_bytes']}, SS={scan_params['step_size_bytes']}, m={scan_params['m_block_size']}"
                )
                print(f"  Format version: ALBC000{scan_params['format_version']}")

            # Step 7: Build and store artifact record
            if verbose:
                print("[7/7] Building Artifact Record...")

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
                    print(f"[7b/7] Signing artifact record with key: {sign_with}...")

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
                        print(f"  Signed by:    {signature_block['key_id']}")
                        print(f"  Fingerprint:  {signature_block['fingerprint']}")
                        print(f"  Signed at:    {signature_block['signed_at']}")

                except Exception as e:
                    raise ValueError(f"Failed to sign artifact: {e}")

            if verbose:
                print(f"  artifact_id: {artifact_id[:16]}...")

            self.repo.store_artifact(artifact_id, artifact_record)

            if verbose:
                print(f"\n✓ Successfully ingested: {file_path_obj.name}")
                print(f"  Artifact ID: {artifact_id}")
                print(f"  Content:     {content_object_id}")
                print(f"  Barcode:     {barcode_object_id}")
                print(f"  Record:      records/{artifact_id}.json")

            return artifact_id

        finally:
            # Cleanup temp barcode file unless requested to keep
            if not keep_temp:
                try:
                    Path(temp_albc_path).unlink()
                except OSError:
                    pass


# Update main() CLI argument parsing:


def main():
    """CLI entry point for repo ingest."""
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <file> [options]")
        print("Options:")
        print("  --window <size>    Window size (default: 65536)")
        print("  --step <size>      Step size (default: 16384)")
        print("  --m <size>         Block size (default: 1)")
        print("  --threads <n>      Thread count (default: auto)")
        print("  --format <version> ALBC format version: 1 or 2 (default: 1)")
        print("  --repo <path>      Repository root (default: .)")
        print("  --quiet            Suppress output")
        sys.exit(1)

    file_path = sys.argv[1]

    kwargs = {
        "window_size": 65536,
        "step_size": 16384,
        "m": 1,
        "threads": 0,
        "verbose": True,
        "keep_temp": False,
        "output_format": 1,  # NEW: Default to v1
    }
    repo_root = "."
    auto_init = True

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if arg == "--window" and i + 1 < len(sys.argv):
            kwargs["window_size"] = int(sys.argv[i + 1])
            i += 2
        elif arg == "--step" and i + 1 < len(sys.argv):
            kwargs["step_size"] = int(sys.argv[i + 1])
            i += 2
        elif arg == "--m" and i + 1 < len(sys.argv):
            kwargs["m"] = int(sys.argv[i + 1])
            i += 2
        elif arg == "--threads" and i + 1 < len(sys.argv):
            kwargs["threads"] = int(sys.argv[i + 1])
            i += 2
        elif arg == "--format" and i + 1 < len(sys.argv):  # NEW
            kwargs["output_format"] = int(sys.argv[i + 1])
            i += 2
        elif arg == "--repo" and i + 1 < len(sys.argv):
            repo_root = sys.argv[i + 1]
            i += 2
        elif arg == "--quiet":
            kwargs["verbose"] = False
            i += 1
        elif arg == "--keep-temp":
            kwargs["keep_temp"] = True
            i += 1
        elif arg == "--no-init":
            auto_init = False
            i += 1
        else:
            i += 1

    try:
        pipeline = IngestPipeline(repo_root=repo_root, auto_init=auto_init)
        artifact_id = pipeline.ingest(file_path, **kwargs)
        sys.exit(0)
    except RepositoryNotInitializedError:
        # Already printed error message
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
