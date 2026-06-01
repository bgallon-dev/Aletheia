"""Scanner interfaces for barcode generation."""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from shutil import which
from typing import Any, Dict, Optional, Tuple

from .albc import ALBCParser, build_albc_bytes
from .barcode import compute_diff_stats
from .entropy import quantize_entropy, scan_file_entropy
from .types import BarcodeResult, ScanParams

DEFAULT_SCANNER_TIMEOUT_SECONDS = 600
logger = logging.getLogger(__name__)


class OdinScanner:
    """Interface to external Odin entropy scanner binary."""

    def __init__(
        self,
        odin_binary: Optional[str] = None,
        require_binary: bool = True,
    ):
        if odin_binary:
            self.odin_binary = odin_binary
            return

        # Always attempt discovery so a working binary is used when present.
        # When discovery fails we keep an empty path and defer to the pure-Python
        # entropy fallback at scan time; only raise when the caller insists the
        # native binary must exist (require_binary=True, e.g. ``doctor``).
        try:
            self.odin_binary = self._find_binary()
        except FileNotFoundError:
            if require_binary:
                raise
            self.odin_binary = ""

    def _find_binary(self) -> str:
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
            "Could not find Odin entropy scanner binary. "
            "Please compile it first or specify path with ODIN_BINARY environment variable."
        )

    def _check_binary(self, path: str) -> bool:
        # Resolve via PATH first, then treat ``path`` as a direct/relative path.
        resolved = which(path)
        if resolved is None and not Path(path).exists():
            return False

        target = resolved or path
        # Existence is NOT sufficient: a present-but-unrunnable binary (e.g. blocked
        # by Windows Application Control / Smart App Control, or wrong architecture)
        # must be reported as unavailable so callers fall back to the Python scanner
        # and ``doctor`` reports the real state. Probe by actually invoking it.
        try:
            result = subprocess.run([str(target)], capture_output=True, timeout=5)
            return result.returncode in (0, 2)
        except Exception:
            return False

    def scan(
        self,
        file_path: str,
        window_size: int = 65536,
        step_size: int = 16384,
        m: int = 1,
        threads: int = 0,
        verbose: bool = True,
        start_byte: int = 0,
        end_byte: int = 0,
        output_format: int = 1,
        timeout_seconds: int = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    ) -> Tuple[bytes, str]:
        """Run Odin scanner and return ALBC bytes and temporary output path.

        Falls back to the pure-Python entropy scanner when the native binary is
        unavailable (not found, blocked by OS policy, or otherwise unrunnable),
        so ingest/verify keep working without the compiled binary.
        """
        if not self.odin_binary:
            return self._scan_python_to_albc(
                file_path,
                window_size=window_size,
                step_size=step_size,
                m=m,
                output_format=output_format,
                start_byte=start_byte,
                end_byte=end_byte,
            )

        with tempfile.NamedTemporaryFile(suffix=".albc", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        cmd = [
            self.odin_binary,
            file_path,
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
            albc_bytes = Path(tmp_path).read_bytes()
            return albc_bytes, tmp_path
        except subprocess.TimeoutExpired as exc:
            Path(tmp_path).unlink(missing_ok=True)
            raise TimeoutError(
                f"Scanner timed out after {timeout_seconds}s for file: {file_path}"
            ) from exc
        except OSError as exc:
            # Binary could not be launched: missing (WinError 2), blocked by
            # Application Control (WinError 4551), bad arch, etc. Degrade to the
            # pure-Python entropy scanner instead of failing the whole operation.
            Path(tmp_path).unlink(missing_ok=True)
            logger.warning(
                "Native Odin scanner could not be executed (%s); "
                "falling back to pure-Python entropy scanner.",
                exc,
            )
            return self._scan_python_to_albc(
                file_path,
                window_size=window_size,
                step_size=step_size,
                m=m,
                output_format=output_format,
                start_byte=start_byte,
                end_byte=end_byte,
            )
        except subprocess.CalledProcessError:
            Path(tmp_path).unlink(missing_ok=True)
            raise
        except Exception:
            Path(tmp_path).unlink(missing_ok=True)
            raise

    def _scan_python_to_albc(
        self,
        file_path: str,
        window_size: int,
        step_size: int,
        m: int,
        output_format: int,
        start_byte: int = 0,
        end_byte: int = 0,
    ) -> Tuple[bytes, str]:
        """Compute a barcode with the Python scanner and write it as ALBC bytes.

        Mirrors the native ``scan`` contract: returns (albc_bytes, temp_path) so
        callers can hash the bytes and clean up the temp file as usual.
        """
        result = _scan_file_python(
            file_path=file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            output_format=output_format,
            start_byte=start_byte,
            end_byte=end_byte,
        )
        albc_bytes = build_albc_bytes(result)
        with tempfile.NamedTemporaryFile(suffix=".albc", delete=False) as tmp_file:
            tmp_file.write(albc_bytes)
            tmp_path = tmp_file.name
        return albc_bytes, tmp_path

    def diff(
        self,
        file1_path: str,
        file2_path: str,
        threshold: float = 0.0,
    ) -> Dict[str, Any]:
        """Compare two ALBC files and emit delta metrics."""
        parsed1 = ALBCParser.parse_from_file(Path(file1_path))
        parsed2 = ALBCParser.parse_from_file(Path(file2_path))
        if parsed1 is None:
            raise ValueError(f"Invalid or truncated ALBC file: {file1_path}")
        if parsed2 is None:
            raise ValueError(f"Invalid or truncated ALBC file: {file2_path}")

        payload1 = parsed1.get("barcode_payload", b"")
        payload2 = parsed2.get("barcode_payload", b"")
        if not isinstance(payload1, (bytes, bytearray)) or not isinstance(
            payload2, (bytes, bytearray)
        ):
            raise ValueError("Invalid ALBC payload type")

        stats = compute_diff_stats(bytes(payload1), bytes(payload2), threshold=threshold)
        return {
            "file1": str(file1_path),
            "file2": str(file2_path),
            "windows_compared": stats.windows_compared,
            "avg_delta_raw": stats.avg_delta_raw,
            "avg_delta_normalized": stats.avg_delta_normalized,
            "rms_delta_raw": stats.rms_delta_raw,
            "rms_delta_normalized": stats.rms_delta_normalized,
            "max_delta_raw": stats.max_delta_raw,
            "max_delta_normalized": stats.max_delta_normalized,
            "max_delta_window": stats.max_delta_window,
            "windows_above_threshold": stats.windows_above_threshold,
            "threshold": stats.threshold,
        }


def probe_scanner(odin_binary: Optional[str] = None) -> Tuple[bool, str]:
    """Report native-scanner availability without raising.

    Returns ``(True, path)`` when a runnable native binary is found, or
    ``(False, reason)`` when scanning will use the pure-Python fallback.
    """
    try:
        scanner = OdinScanner(odin_binary=odin_binary, require_binary=True)
    except FileNotFoundError as exc:
        return False, str(exc)
    if not scanner.odin_binary:
        return False, "no runnable native scanner binary found"
    return True, scanner.odin_binary


def _parse_scan_result(albc_bytes: bytes, source_path: str) -> BarcodeResult:
    parsed = ALBCParser.parse_full_with_raw(albc_bytes)
    if parsed is None:
        raise ValueError("Failed to parse scanner ALBC output")
    return ALBCParser.parse_to_result(parsed, source_path=source_path)


def _scan_file_python(
    file_path: str,
    window_size: int,
    step_size: int,
    m: int,
    output_format: int,
    start_byte: int = 0,
    end_byte: int = 0,
) -> BarcodeResult:
    raw_entropy = scan_file_entropy(
        file_path=file_path,
        window_size=window_size,
        step_size=step_size,
        m_block_size=m,
        start_byte=start_byte,
        end_byte=end_byte,
    )
    payload = quantize_entropy(raw_entropy, m_block_size=m)
    scan_params = ScanParams(
        window_size_bytes=window_size,
        step_size_bytes=step_size,
        m_block_size=m,
        format_version=output_format,
        quant_version="v0",
    )
    return BarcodeResult(
        scan_params=scan_params,
        barcode_payload=payload,
        raw_entropy=raw_entropy if output_format >= 2 else None,
        source_path=file_path,
    )


def scan_file(
    file_path: str,
    window_size: int = 65536,
    step_size: int = 16384,
    m: int = 1,
    threads: int = 0,
    output_format: int = 1,
    odin_binary: Optional[str] = None,
    timeout_seconds: int = DEFAULT_SCANNER_TIMEOUT_SECONDS,
    start_byte: int = 0,
    end_byte: int = 0,
    prefer_python: bool = False,
) -> BarcodeResult:
    """Compute a barcode result from file input using Odin or Python fallback."""
    if prefer_python:
        return _scan_file_python(
            file_path=file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            output_format=output_format,
            start_byte=start_byte,
            end_byte=end_byte,
        )

    temp_path: Optional[str] = None
    try:
        scanner = OdinScanner(odin_binary=odin_binary, require_binary=True)
        albc_bytes, temp_path = scanner.scan(
            file_path=file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            threads=threads,
            verbose=False,
            start_byte=start_byte,
            end_byte=end_byte,
            output_format=output_format,
            timeout_seconds=timeout_seconds,
        )
        return _parse_scan_result(albc_bytes, source_path=file_path)
    except FileNotFoundError:
        logger.warning("Odin binary not found; falling back to pure-Python entropy scanner.")
        return _scan_file_python(
            file_path=file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            output_format=output_format,
            start_byte=start_byte,
            end_byte=end_byte,
        )
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
