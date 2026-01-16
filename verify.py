#!/usr/bin/env python3
"""
Aletheia Repository Verify - Cryptographic and Forensic Verification with Zoom Scan

Usage:
    python verify.py <artifact_id> --file <path>

Verification performs two independent checks:
1. Cryptographic: SHA-256(file) == content_object_id
2. Forensic: Recompute barcode and compare to barcode_object_id

If forensic check fails with coarse resolution, automatically performs
"Zoom Scan" - a finer resolution scan on the affected regions using the
stored baseline content object for comparison.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

from repository import AletheiaRepository, RepositoryNotInitializedError
from ingest import OdinScanner, ALBCParser
from utils import compute_file_hash


# Zoom scan parameters (8× finer resolution than baseline)
ZOOM_WINDOW_SIZE = 8192  # 8 KiB
ZOOM_STEP_SIZE = 2048  # 2 KiB
ZOOM_MARGIN_WINDOWS = 2  # Include 2 windows before/after for context

try:
    from identity import IdentityLink, SignatureInvalidError

    IDENTITY_AVAILABLE = True
except ImportError:
    IDENTITY_AVAILABLE = False


class ZoomRegion:
    """Represents a region requiring zoom scan."""

    def __init__(
        self,
        coarse_start_window: int,
        coarse_end_window: int,
        coarse_start_byte: int,
        coarse_end_byte: int,
        coarse_window_size: int,
        coarse_step_size: int,
    ):
        self.coarse_start_window = coarse_start_window
        self.coarse_end_window = coarse_end_window
        self.coarse_start_byte = coarse_start_byte
        self.coarse_end_byte = coarse_end_byte
        self.coarse_window_size = coarse_window_size
        self.coarse_step_size = coarse_step_size

        # Zoom scan bounds (computed with margin)
        self.zoom_start_byte = 0
        self.zoom_end_byte = 0

        # Zoom scan results
        self.fine_regions: List[Tuple[int, int, int, int]] = []


class VerificationResult:
    """Result of artifact verification."""

    def __init__(self):
        self.cryptographic_match = False
        self.forensic_match = False
        self.forensic_skipped = False
        self.forensic_skip_reason: Optional[str] = None
        self.content_hash_expected = ""
        self.content_hash_actual = ""
        self.barcode_hash_expected = ""
        self.barcode_hash_actual = ""
        self.error: Optional[str] = None
        self.localization = (
            []
        )  # List of (start_window, end_window, start_byte, end_byte)
        self.warnings = []  # List of warning messages

        # Zoom scan results
        self.zoom_performed = False
        self.zoom_regions: List[ZoomRegion] = []

        # NEW: Signature verification results
        self.signature_present = False
        self.signature_valid = False
        self.signature_key_id: Optional[str] = None
        self.signature_fingerprint: Optional[str] = None
        self.signature_signed_at: Optional[str] = None
        self.signature_error: Optional[str] = None

    def passed(self) -> bool:
        """Check if verification passed."""
        if self.error:
            return False
        if self.forensic_skipped:
            return self.cryptographic_match
        # Note: Signature check is informational, not required for pass
        return self.cryptographic_match and self.forensic_match

    @staticmethod
    def _format_bytes(byte_count: int) -> str:
        """Format byte count in human-readable form."""
        if byte_count < 1024:
            return f"{byte_count} bytes"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.2f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"

    def format_report(self, verbose: bool = True) -> str:
        """Format verification report."""
        lines = []

        # Overall status
        if self.passed():
            if self.forensic_skipped:
                lines.append("⚠ VERIFICATION PASSED (partial)")
            else:
                lines.append("✓ VERIFICATION PASSED")
        else:
            lines.append("✗ VERIFICATION FAILED")

        if self.error:
            lines.append(f"\nError: {self.error}")
            return "\n".join(lines)

        # Warnings
        if self.warnings:
            lines.append("\n[Warnings]")
            for warning in self.warnings:
                lines.append(f"  ⚠ {warning}")

        # Cryptographic check
        lines.append("\n[1/2] Cryptographic Identity Check")
        if self.cryptographic_match:
            lines.append("  ✓ Content hash matches")
        else:
            lines.append("  ✗ Content hash mismatch")

        if verbose:
            lines.append(f"    Expected: {self.content_hash_expected}")
            lines.append(f"    Actual:   {self.content_hash_actual}")

        # Forensic check
        lines.append("\n[2/2] Forensic Identity Check (Barcode)")
        if self.forensic_skipped:
            lines.append(f"  ⊘ SKIPPED: {self.forensic_skip_reason}")
        elif self.forensic_match:
            lines.append("  ✓ Barcode hash matches")
        else:
            lines.append("  ✗ Barcode hash mismatch")

        if verbose and not self.forensic_skipped:
            lines.append(f"    Expected: {self.barcode_hash_expected}")
            lines.append(f"    Actual:   {self.barcode_hash_actual}")

        # Coarse localization (if barcode differs)
        if not self.forensic_match and not self.forensic_skipped and self.localization:
            lines.append("\n[Coarse Localization]")
            lines.append(
                f"  Detected {len(self.localization)} modified region(s) at baseline resolution:"
            )

            for i, (start_win, end_win, start_byte, end_byte) in enumerate(
                self.localization, 1
            ):
                window_count = end_win - start_win + 1
                byte_count = end_byte - start_byte

                lines.append(f"\n  Region {i}:")
                lines.append(
                    f"    Windows:  {start_win} - {end_win} ({window_count} windows)"
                )
                lines.append(
                    f"    Bytes:    {start_byte} - {end_byte} ({self._format_bytes(byte_count)})"
                )

        # Zoom scan results
        if self.zoom_performed and self.zoom_regions:
            lines.append("\n[Zoom Scan - High Resolution Localization]")
            lines.append(
                f"  Resolution: WS={ZOOM_WINDOW_SIZE} bytes ({ZOOM_WINDOW_SIZE // 1024} KiB), "
                f"SS={ZOOM_STEP_SIZE} bytes ({ZOOM_STEP_SIZE // 1024} KiB)"
            )
            lines.append(f"  Analyzed {len(self.zoom_regions)} coarse region(s)\n")

            for i, zoom_region in enumerate(self.zoom_regions, 1):
                lines.append(
                    f"  Zoom Region {i} (from coarse windows {zoom_region.coarse_start_window}-{zoom_region.coarse_end_window}):"
                )
                lines.append(
                    f"    Scan range: bytes {zoom_region.zoom_start_byte} - {zoom_region.zoom_end_byte}"
                )

                if zoom_region.fine_regions:
                    lines.append(
                        f"    Found {len(zoom_region.fine_regions)} fine-grained difference(s):"
                    )
                    for j, (start_win, end_win, start_byte, end_byte) in enumerate(
                        zoom_region.fine_regions, 1
                    ):
                        window_count = end_win - start_win + 1
                        byte_count = end_byte - start_byte

                        # Adjust byte offsets to be relative to original file
                        abs_start_byte = zoom_region.zoom_start_byte + start_byte
                        abs_end_byte = zoom_region.zoom_start_byte + end_byte

                        lines.append(f"\n      Difference {j}:")
                        lines.append(
                            f"        Windows:  {start_win} - {end_win} ({window_count} windows @ zoom resolution)"
                        )
                        lines.append(
                            f"        Bytes:    {abs_start_byte} - {abs_end_byte} ({self._format_bytes(byte_count)})"
                        )
                else:
                    lines.append(
                        f"    No fine-grained differences (coarse mismatch may be quantization artifact)"
                    )

        # NEW: Signature verification section
        if self.signature_present:
            lines.append("\n[3/3] Identity Link (Signature)")
            if self.signature_valid:
                lines.append("  ✓ Signature valid")
                lines.append(f"    Signed by:   {self.signature_key_id}")
                lines.append(f"    Fingerprint: {self.signature_fingerprint}")
                lines.append(f"    Signed at:   {self.signature_signed_at}")
            else:
                lines.append("  ✗ Signature INVALID")
                if self.signature_error:
                    lines.append(f"    Error: {self.signature_error}")
        else:
            lines.append("\n[3/3] Identity Link (Signature)")
            lines.append("  ⊘ No signature present")

        return "\n".join(lines)


class ArtifactVerifier:
    """Verify artifacts against repository records."""

    def __init__(self, repo_root: str = "."):
        """Initialize verifier."""
        try:
            self.repo = AletheiaRepository(repo_root, auto_init=False)
        except RepositoryNotInitializedError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise

        self.scanner = OdinScanner()
        self.parser = ALBCParser()
        self.identity: Optional[IdentityLink] = None
        if IDENTITY_AVAILABLE:
            try:
                self.identity = IdentityLink()
            except Exception:
                pass

    def verify(
        self,
        artifact_id: str,
        file_path: str,
        verbose: bool = True,
        enable_zoom: bool = True,
        trusted_keys: Optional[Dict[str, str]] = None,
    ) -> VerificationResult:
        """
        Verify a file against its stored artifact record.

        Args:
            artifact_id: The artifact ID to verify against
            file_path: Path to the file to verify
            verbose: Print progress info
            enable_zoom: Enable zoom scan on forensic mismatch
            trusted_keys: Optional dict of key_id -> public_key_b64 for signature verification

        Returns:
            VerificationResult with cryptographic and forensic verification status
        """
        result = VerificationResult()

        # Load artifact record
        record_path = self.repo.records_dir / f"{artifact_id}.json"
        if not record_path.exists():
            result.error = f"Artifact not found: {artifact_id}"
            return result

        try:
            with open(record_path, "r") as f:
                record = json.load(f)
        except Exception as e:
            result.error = f"Failed to load artifact record: {e}"
            return result

        # Check file exists
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            result.error = f"File not found: {file_path}"
            return result

        if verbose:
            print(f"\n=== Verifying: {file_path_obj.name} ===")
            print(f"Artifact ID: {artifact_id}\n")

        # Step 1: Cryptographic verification
        if verbose:
            print("[1/2] Cryptographic identity check...")

        # Use shared utility - DRY principle
        file_hash, file_size = compute_file_hash(file_path_obj)

        result.content_hash_actual = file_hash
        result.content_hash_expected = record["content_object_id"]
        result.cryptographic_match = (
            result.content_hash_actual == result.content_hash_expected
        )

        if verbose:
            status = "✓ PASS" if result.cryptographic_match else "✗ FAIL"
            size_mb = file_size / (1024 * 1024)
            print(f"  {status}: Content hash ({file_size:,} bytes, {size_mb:.2f} MB)")

        # Step 2: Forensic verification (barcode)
        if verbose:
            print("\n[2/2] Forensic identity check (barcode)...")

        try:
            # Extract scan parameters from record (with legacy fallback)
            scan_params = record.get("scan_params", {})

            # Canonical keys use _bytes suffix; legacy keys don't
            window_size = scan_params.get(
                "window_size_bytes", scan_params.get("window_size", 65536)
            )
            step_size = scan_params.get(
                "step_size_bytes", scan_params.get("step_size", 16384)
            )
            m = scan_params.get("m_block_size", 1)
            stored_format_version = scan_params.get("format_version", 1)

            if verbose:
                print(
                    f"  Scan params: window={window_size}, step={step_size}, m={m}, format=v{stored_format_version}"
                )

            # Re-scan with MATCHING format version
            albc_bytes, temp_path = self.scanner.scan(
                file_path,
                window_size=window_size,
                step_size=step_size,
                m=m,
                threads=0,
                verbose=False,
                output_format=stored_format_version,
            )

            # Clean up temp file
            try:
                Path(temp_path).unlink()
            except OSError:
                pass

            # Compare barcode hash
            result.barcode_hash_actual = hashlib.sha256(albc_bytes).hexdigest()
            result.barcode_hash_expected = record.get("barcode_object_id", "")
            result.forensic_match = (
                result.barcode_hash_actual == result.barcode_hash_expected
            )

            if verbose:
                status = "✓ PASS" if result.forensic_match else "✗ FAIL"
                print(f"  {status}: Barcode hash")

            # Coarse localization if barcode mismatch
            if not result.forensic_match:
                if verbose:
                    print("\n[Coarse Localization] Analyzing modified regions...")

                # Load stored barcode from object store
                stored_albc = self.repo.get_object_bytes(
                    result.barcode_hash_expected, obj_type_hint="barcode"
                )
                if stored_albc:
                    # Parse both barcodes
                    stored_parsed = self.parser.parse_full(stored_albc)
                    actual_parsed = self.parser.parse_full(albc_bytes)

                    if stored_parsed and actual_parsed:
                        # Compare payloads and get coarse localization
                        result.localization = self.parser.compare_barcodes(
                            stored_parsed["barcode_payload"],
                            actual_parsed["barcode_payload"],
                            window_size,
                            step_size,
                        )

                        if verbose and result.localization:
                            print(
                                f"  Found {len(result.localization)} modified region(s)"
                            )

                        # Step 3: Zoom scan if enabled and we have coarse regions
                        if enable_zoom and result.localization:
                            if verbose:
                                print(
                                    "\n[Zoom Scan] Performing high-resolution analysis..."
                                )

                            self._perform_zoom_scan(
                                result,
                                file_path,
                                record,
                                window_size,
                                step_size,
                                m,
                                verbose,
                            )

        except Exception as e:
            result.error = f"Barcode verification failed: {e}"
            return result

        # NEW: Step 3 - Verify signature if present
        identity_link = record.get("identity_link")
        if identity_link:
            result.signature_present = True

            if verbose:
                print("\n[3/3] Identity link verification...")

            if self.identity:
                sig_result = self.identity.verify_signature(
                    record,
                    identity_link,
                    trusted_keys=trusted_keys,
                )

                result.signature_valid = sig_result["valid"]
                result.signature_key_id = sig_result.get("key_id")
                result.signature_fingerprint = sig_result.get("fingerprint")
                result.signature_signed_at = sig_result.get("signed_at")
                result.signature_error = sig_result.get("error")

                if verbose:
                    status = "✓ PASS" if result.signature_valid else "✗ FAIL"
                    print(f"  {status}: Signature verification")
            else:
                result.signature_error = "Identity system not available"
                if verbose:
                    print("  ⚠ Cannot verify: Identity system not available")

        return result

    def _perform_zoom_scan(
        self,
        result: VerificationResult,
        suspect_file_path: str,
        record: Dict[str, Any],
        coarse_window_size: int,
        coarse_step_size: int,
        m: int,
        verbose: bool,
    ) -> None:
        """
        Perform zoom scan on modified regions.

        Uses stored baseline content object for comparison at finer resolution.

        PERFORMANCE (Issue #3 - Teleportation vs Streaming):
        Uses file.seek() to jump directly to modified regions instead of
        streaming from byte 0. For a 50GB file with corruption at end,
        this makes the difference between instant and 5+ minutes.
        """
        result.zoom_performed = True

        # Get baseline content object PATH (not bytes!) - avoid RAM issues
        baseline_object_id = record["content_object_id"]
        baseline_path = self.repo.get_object_path(baseline_object_id)

        if not baseline_path:
            result.warnings.append(
                f"Cannot perform zoom scan: baseline object not found: {baseline_object_id}"
            )
            if verbose:
                print("  Warning: Cannot perform zoom scan - baseline object not found")
            return

        try:
            suspect_size = Path(suspect_file_path).stat().st_size
            baseline_size = baseline_path.stat().st_size

            # Process each coarse region
            for (
                coarse_start_win,
                coarse_end_win,
                coarse_start_byte,
                coarse_end_byte,
            ) in result.localization:
                zoom_region = ZoomRegion(
                    coarse_start_win,
                    coarse_end_win,
                    coarse_start_byte,
                    coarse_end_byte,
                    coarse_window_size,
                    coarse_step_size,
                )

                # Compute zoom scan bounds with margin
                margin_bytes = ZOOM_MARGIN_WINDOWS * coarse_step_size
                zoom_start = max(0, coarse_start_byte - margin_bytes)
                zoom_end = min(suspect_size, coarse_end_byte + margin_bytes)

                # Ensure baseline has sufficient data
                zoom_end = min(zoom_end, baseline_size)

                if zoom_start >= zoom_end:
                    continue

                zoom_region.zoom_start_byte = zoom_start
                zoom_region.zoom_end_byte = zoom_end

                if verbose:
                    print(
                        f"  Zooming into region: bytes {zoom_start:,}-{zoom_end:,} "
                        f"({self._format_file_size(zoom_end - zoom_start)})"
                    )

                # FIX #3: Use seeking instead of streaming from byte 0
                # For a 50GB file with corruption at byte 49GB:
                # - Streaming: Read 49GB (minutes)
                # - Seeking: Instant teleportation

                # Scan baseline at zoom resolution using byte range
                try:
                    baseline_albc, baseline_temp = self.scanner.scan(
                        str(baseline_path),
                        window_size=ZOOM_WINDOW_SIZE,
                        step_size=ZOOM_STEP_SIZE,
                        m=m,
                        threads=0,
                        verbose=False,
                        start_byte=zoom_start,  # Scanner will seek() to this offset
                        end_byte=zoom_end,
                    )

                    # Scan suspect at zoom resolution
                    suspect_albc, suspect_temp = self.scanner.scan(
                        suspect_file_path,
                        window_size=ZOOM_WINDOW_SIZE,
                        step_size=ZOOM_STEP_SIZE,
                        m=m,
                        threads=0,
                        verbose=False,
                        start_byte=zoom_start,  # Scanner will seek() to this offset
                        end_byte=zoom_end,
                    )

                    # Clean up temp files
                    for temp_path in [baseline_temp, suspect_temp]:
                        try:
                            Path(temp_path).unlink()
                        except OSError:
                            pass

                    # Parse and compare zoom barcodes
                    baseline_parsed = self.parser.parse_full(baseline_albc)
                    suspect_parsed = self.parser.parse_full(suspect_albc)

                    if baseline_parsed and suspect_parsed:
                        # Compare barcodes to find fine-grained differences
                        baseline_bc = baseline_parsed.get("barcode_payload", b"")
                        suspect_bc = suspect_parsed.get("barcode_payload", b"")

                        # Find differing windows
                        fine_regions = []
                        num_windows = min(len(baseline_bc), len(suspect_bc))

                        in_diff = False
                        diff_start_win = 0

                        for win_idx in range(num_windows):
                            if baseline_bc[win_idx] != suspect_bc[win_idx]:
                                if not in_diff:
                                    in_diff = True
                                    diff_start_win = win_idx
                            else:
                                if in_diff:
                                    # End of difference region
                                    # Store RELATIVE byte offsets (relative to zoom_start_byte)
                                    # format_report() will add zoom_start_byte when displaying
                                    start_byte = diff_start_win * ZOOM_STEP_SIZE
                                    end_byte = (
                                        win_idx * ZOOM_STEP_SIZE + ZOOM_WINDOW_SIZE
                                    )
                                    fine_regions.append(
                                        (diff_start_win, win_idx, start_byte, end_byte)
                                    )
                                    in_diff = False

                        # Handle difference extending to end
                        if in_diff:
                            # Store RELATIVE byte offsets
                            start_byte = diff_start_win * ZOOM_STEP_SIZE
                            end_byte = num_windows * ZOOM_STEP_SIZE + ZOOM_WINDOW_SIZE
                            fine_regions.append(
                                (diff_start_win, num_windows, start_byte, end_byte)
                            )

                        zoom_region.fine_regions = fine_regions

                        if verbose:
                            if fine_regions:
                                print(
                                    f"    Found {len(fine_regions)} fine-grained difference(s)"
                                )
                                for (
                                    start_win,
                                    end_win,
                                    start_byte,
                                    end_byte,
                                ) in fine_regions[:3]:
                                    # Add zoom_start_byte for absolute display
                                    abs_start = zoom_region.zoom_start_byte + start_byte
                                    abs_end = zoom_region.zoom_start_byte + end_byte
                                    print(
                                        f"      Windows {start_win}-{end_win}: bytes {abs_start:,}-{abs_end:,}"
                                    )
                                if len(fine_regions) > 3:
                                    print(f"      ... and {len(fine_regions) - 3} more")
                            else:
                                print(f"    No fine-grained differences detected")

                except Exception as e:
                    if verbose:
                        print(f"    ⚠ Zoom scan failed for this region: {e}")

                result.zoom_regions.append(zoom_region)

        except Exception as e:
            result.warnings.append(f"Zoom scan error: {e}")
            if verbose:
                print(f"  Warning: Zoom scan encountered error: {e}")

    @staticmethod
    def _format_file_size(byte_count: int) -> str:
        """Format file size in human-readable form."""
        if byte_count < 1024:
            return f"{byte_count} bytes"
        elif byte_count < 1024 * 1024:
            return f"{byte_count / 1024:.2f} KB"
        elif byte_count < 1024 * 1024 * 1024:
            return f"{byte_count / (1024 * 1024):.2f} MB"
        else:
            return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def main():
    """CLI entry point for verification."""
    if len(sys.argv) < 3:
        print(
            "Usage: python verify.py <artifact_id> --file <path> [options]",
            file=sys.stderr,
        )
        print("\nOptions:", file=sys.stderr)
        print("  --repo <path>    Repository root (default: .)", file=sys.stderr)
        print("  --quiet          Suppress verbose output", file=sys.stderr)
        print(
            "  --no-zoom        Disable zoom scan (only coarse localization)",
            file=sys.stderr,
        )
        sys.exit(2)

    artifact_id = sys.argv[1]
    file_path = None
    repo_root = "."
    verbose = True
    enable_zoom = True

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--file" and i + 1 < len(sys.argv):
            file_path = sys.argv[i + 1]
            i += 2
        elif arg == "--repo" and i + 1 < len(sys.argv):
            repo_root = sys.argv[i + 1]
            i += 2
        elif arg == "--quiet":
            verbose = False
            i += 1
        elif arg == "--no-zoom":
            enable_zoom = False
            i += 1
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            sys.exit(2)

    if not file_path:
        print("Error: --file <path> is required", file=sys.stderr)
        sys.exit(2)

    try:
        verifier = ArtifactVerifier(repo_root=repo_root)
        result = verifier.verify(
            artifact_id, file_path, verbose=verbose, enable_zoom=enable_zoom
        )

        if verbose:
            print()

        print(result.format_report(verbose=verbose))

        sys.exit(0 if result.passed() else 1)

    except RepositoryNotInitializedError:
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
