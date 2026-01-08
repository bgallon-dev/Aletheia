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


class ALBCParser:
    """Parser for ALBC (Aletheia Barcode) binary format."""
    
    MAGIC = b'ALBC0001'
    HEADER_SIZE = 32
    
    @staticmethod
    def parse_header(albc_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC header from binary data.
        
        Header layout (little-endian):
          0..7   : magic "ALBC0001" (8 bytes)
          8..11  : window_size_bytes u32
          12..15 : step_size_bytes   u32
          16..19 : m_block_size      u32
          20..23 : quant_version     u32
          24..31 : barcode_len       u64
          32..   : quantized barcode bytes
        """
        if len(albc_data) < ALBCParser.HEADER_SIZE:
            return None
        
        magic = albc_data[0:8]
        if magic != ALBCParser.MAGIC:
            return None
        
        # Unpack header fields (little-endian)
        window_size_bytes = struct.unpack('<I', albc_data[8:12])[0]
        step_size_bytes = struct.unpack('<I', albc_data[12:16])[0]
        m_block_size = struct.unpack('<I', albc_data[16:20])[0]
        quant_version = struct.unpack('<I', albc_data[20:24])[0]
        barcode_len = struct.unpack('<Q', albc_data[24:32])[0]
        
        # Validate
        expected_size = ALBCParser.HEADER_SIZE + barcode_len
        if len(albc_data) != expected_size:
            return None
        
        return {
            "window_size_bytes": window_size_bytes,
            "step_size_bytes": step_size_bytes,
            "m_block_size": m_block_size,
            "quant_version": f"v{quant_version}",
            "barcode_len": barcode_len
        }
    
    @staticmethod
    def parse_header_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC header directly from file (without loading entire file).
        
        Only reads the 32-byte header, leaving the rest on disk.
        """
        with open(file_path, 'rb') as f:
            header_bytes = f.read(ALBCParser.HEADER_SIZE)
            if len(header_bytes) < ALBCParser.HEADER_SIZE:
                return None
            
            return ALBCParser.parse_header(header_bytes)
    
    @staticmethod
    def parse_full(albc_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC from bytes (for small barcodes or when already in memory).
        
        For large barcodes, consider using parse_from_file() instead.
        """
        header = ALBCParser.parse_header(albc_data)
        if header is None:
            return None
        
        payload = albc_data[ALBCParser.HEADER_SIZE:]
        
        return {
            **header,
            "barcode_payload": payload
        }
    
    @staticmethod
    def parse_from_file(file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse ALBC directly from file (memory-efficient for large barcodes).
        
        Loads entire payload into memory. For extremely large barcodes,
        consider adding a streaming comparison API.
        """
        header = ALBCParser.parse_header_from_file(file_path)
        if header is None:
            return None
        
        with open(file_path, 'rb') as f:
            f.seek(ALBCParser.HEADER_SIZE)
            payload = f.read()
        
        return {
            **header,
            "barcode_payload": payload
        }
    
    @staticmethod
    def compare_barcodes(
        baseline_payload: bytes,
        actual_payload: bytes,
        window_size: int,
        step_size: int
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
        original_filename: str
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
                "chain_of_custody": "single_node"
            }
        }
    
    @staticmethod
    def derive_artifact_id(
        content_object_id: str,
        barcode_object_id: str
    ) -> str:
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
            result = subprocess.run(
                [str(p)],
                capture_output=True,
                timeout=2
            )
            return result.returncode in [0, 2]
        except Exception:
            return False
    
    def scan(
        self,
        file_path: str,
        window_size: int = 65536,  # 64KB default
        step_size: int = 16384,    # 16KB default
        m: int = 1,
        threads: int = 0,
        verbose: bool = True,
        start_byte: int = 0,  # NEW: byte range start
        end_byte: int = 0,    # NEW: byte range end (0 = scan to end)
    ) -> Tuple[bytes, str]:
        """
        Run Odin scanner on file.
        
        Args:
            file_path: Path to file to scan
            window_size: Window size in bytes
            step_size: Step size in bytes
            m: Block size for entropy calculation
            threads: Number of threads (0 = auto)
            verbose: Print verbose output
            start_byte: Starting byte offset for range scan (0 = from beginning)
            end_byte: Ending byte offset for range scan (0 = to end of file)
        
        Returns:
            (albc_bytes, temp_path): The barcode data and temporary file path
        """
        with tempfile.NamedTemporaryFile(suffix=".albc", delete=False) as tmp:
            tmp_path = tmp.name
        
        cmd = [
            self.odin_binary,
            "scan",
            file_path,
            "--window", str(window_size),
            "--step", str(step_size),
            "--m", str(m),
            "--out", tmp_path
        ]
        
        if threads > 0:
            cmd.extend(["--threads", str(threads)])
        
        if not verbose:
            cmd.append("--quiet")
        
        # NEW: Add byte range parameters
        if start_byte > 0:
            cmd.extend(["--start", str(start_byte)])
        if end_byte > 0:
            cmd.extend(["--end", str(end_byte)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            if verbose and result.stdout:
                print(result.stdout, end='')
            
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
        self,
        file1_path: str,
        file2_path: str,
        threshold: float = 0.0
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
        cmd = [
            self.odin_binary,
            "diff",
            file1_path,
            file2_path,
            "--json"
        ]
        
        if threshold > 0:
            cmd.extend(["--threshold", str(threshold)])
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        return json.loads(result.stdout)


class IngestPipeline:
    """Complete ingest pipeline for Aletheia repository."""
    
    def __init__(self, repo_root: str = ".", odin_binary: Optional[str] = None, auto_init: bool = True):
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
    
    def ingest(
        self,
        file_path: str,
        window_size: int = 65536,
        step_size: int = 16384,
        m: int = 1,
        threads: int = 0,
        verbose: bool = True,
        keep_temp: bool = False
    ) -> str:
        """Complete ingest workflow (streaming, handles arbitrary file sizes)."""
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if verbose:
            print(f"\n=== Ingesting: {file_path_obj.name} ===\n")
        
        # Step 1: Run Odin scanner (generates barcode file)
        if verbose:
            print(f"[1/7] Running Odin scanner (window={window_size}, step={step_size}, m={m})...")
        albc_bytes, temp_albc_path = self.scanner.scan(
            file_path, window_size, step_size, m, threads, verbose=False
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
                print(f"  Barcode size: {len(albc_bytes):,} bytes ({barcode_size_kb:.2f} KB)")
                print(f"  barcode_object_id: {barcode_object_id[:16]}...")
            
            # Derive artifact_id early for idempotency check
            artifact_id = ArtifactRecordBuilder.derive_artifact_id(
                content_object_id,
                barcode_object_id
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
            
            # Step 6: Parse ALBC header (only reads 32 bytes)
            if verbose:
                print("[6/7] Parsing barcode header...")
            scan_params = self.parser.parse_header(albc_bytes)
            if scan_params is None:
                raise ValueError("Failed to parse ALBC header")
            
            if verbose:
                print(f"  Scan params: {scan_params}")
            
            # Step 7: Build and store artifact record
            if verbose:
                print("[7/7] Building Artifact Record...")
            
            created_at_unix_ms = int(datetime.utcnow().timestamp() * 1000)
            
            artifact_record = ArtifactRecordBuilder.build(
                content_object_id=content_object_id,
                barcode_object_id=barcode_object_id,
                scan_params=scan_params,
                created_at_unix_ms=created_at_unix_ms,
                original_filename=file_path_obj.name
            )
            
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


def main():
    """CLI entry point for repo ingest."""
    if len(sys.argv) < 2:
        print("Usage: python ingest.py <file> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print("  --window <bytes>     Window size (default: 65536)", file=sys.stderr)
        print("  --step <bytes>       Step size (default: 16384)", file=sys.stderr)
        print("  --m <1|2>            Block size (default: 1)", file=sys.stderr)
        print("  --threads <N>        Thread count (default: auto)", file=sys.stderr)
        print("  --repo <path>        Repository root (default: .)", file=sys.stderr)
        print("  --no-auto-init       Don't auto-initialize repository", file=sys.stderr)
        print("  --quiet              Suppress output", file=sys.stderr)
        print("  --keep-temp          Keep temporary .albc file", file=sys.stderr)
        sys.exit(2)
    
    # Parse arguments (simple implementation)
    file_path = sys.argv[1]
    
    kwargs = {
        'window_size': 65536,
        'step_size': 16384,
        'm': 1,
        'threads': 0,
        'verbose': True,
        'keep_temp': False
    }
    repo_root = "."
    auto_init = True
    
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--window' and i + 1 < len(sys.argv):
            kwargs['window_size'] = int(sys.argv[i + 1])
            i += 2
        elif arg == '--step' and i + 1 < len(sys.argv):
            kwargs['step_size'] = int(sys.argv[i + 1])
            i += 2
        elif arg == '--m' and i + 1 < len(sys.argv):
            kwargs['m'] = int(sys.argv[i + 1])
            i += 2
        elif arg == '--threads' and i + 1 < len(sys.argv):
            kwargs['threads'] = int(sys.argv[i + 1])
            i += 2
        elif arg == '--repo' and i + 1 < len(sys.argv):
            repo_root = sys.argv[i + 1]
            i += 2
        elif arg == '--no-auto-init':
            auto_init = False
            i += 1
        elif arg == '--quiet':
            kwargs['verbose'] = False
            i += 1
        elif arg == '--keep-temp':
            kwargs['keep_temp'] = True
            i += 1
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            sys.exit(2)
    
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