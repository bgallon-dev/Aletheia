"""Artifact-oriented application layer built on top of core primitives and repository storage."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Type, Union

from ..algorithms import ALGO_BARCODE_V1, ARTIFACT_ID_PREFIX
from ..core.albc import ALBCParser
from ..core.scanner import OdinScanner
from ..domain import ArtifactRecord, ScanParams
from .repository import AletheiaRepository, RepositoryNotInitializedError
from ..utils import hash_and_copy_file

try:
    from .identity import IdentityLink

    IDENTITY_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    IDENTITY_AVAILABLE = False
    IdentityLink = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    """Outcome of a single ingest operation.

    ``deduplicated`` is ``True`` when the artifact already existed and ingestion was a
    no-op (idempotent). ``signed`` reflects whether the stored record carries an
    identity signature.
    """

    artifact_id: str
    deduplicated: bool
    signed: bool
    content_object_id: str
    barcode_object_id: str
    created_at_unix_ms: int
    original_filename: str


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
        *,
        source: str = "local",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        scan_params_obj = (
            scan_params
            if isinstance(scan_params, ScanParams)
            else ScanParams.from_dict(scan_params)
        )
        metadata = ArtifactRecord.default_metadata(original_filename)
        metadata["ingested_from"] = source
        if extra_metadata:
            metadata = {**metadata, **extra_metadata}
            # original_filename is authoritative and must not be caller-overridable.
            metadata["original_filename"] = original_filename
        record = ArtifactRecord(
            record_version=ArtifactRecordBuilder.VERSION,
            content_object_id=content_object_id,
            barcode_object_id=barcode_object_id,
            scan_params=scan_params_obj,
            created_at_unix_ms=created_at_unix_ms,
            metadata=metadata,
        )
        return record.to_dict()

    @staticmethod
    def derive_artifact_id(content_object_id: str, barcode_object_id: str) -> str:
        prefix = ARTIFACT_ID_PREFIX
        content_bytes = bytes.fromhex(content_object_id)
        barcode_bytes = bytes.fromhex(barcode_object_id)
        data = prefix + content_bytes + barcode_bytes
        return hashlib.sha256(data).hexdigest()


class IngestPipeline:
    """Complete ingest pipeline for Aletheia repository."""

    def __init__(
        self,
        repo_root: str = "aletheia_repo",
        odin_binary: Optional[str] = None,
        auto_init: bool = True,
        repository_cls: Type[AletheiaRepository] = AletheiaRepository,
        scanner_factory: Optional[Callable[[Optional[str]], Any]] = None,
        identity_factory: Optional[Callable[[], Any]] = None,
        identity_available: bool = IDENTITY_AVAILABLE,
    ):
        try:
            self.repo = repository_cls(repo_root, auto_init=auto_init)
        except RepositoryNotInitializedError as exc:
            logger.error("Repository initialization failed: %s", exc)
            raise

        if scanner_factory is not None:
            self.scanner = scanner_factory(odin_binary)
        else:
            # require_binary=False: construction succeeds even when the native
            # binary is absent/blocked; scan() then uses the Python fallback.
            self.scanner = OdinScanner(odin_binary, require_binary=False)

        self.parser = ALBCParser()
        self.identity = None
        if identity_available:
            if identity_factory is not None:
                try:
                    self.identity = identity_factory()
                except Exception:
                    self.identity = None
            elif IDENTITY_AVAILABLE and IdentityLink is not None:
                try:
                    self.identity = IdentityLink()
                except Exception:
                    self.identity = None

    def _load_defaults(self) -> Dict[str, Any]:
        if self.repo.config_path.exists():
            with open(self.repo.config_path, "r") as config_file:
                config = json.load(config_file)
                return config.get("defaults", {})
        return {}

    def _load_existing_record(self, artifact_id: str) -> Optional[ArtifactRecord]:
        """Best-effort load of a stored record (used on the idempotent dedupe path).

        Returns ``None`` if the record cannot be read; ingest then stays a successful
        idempotent no-op (returning partial result fields). Use ``audit`` to detect a
        genuinely corrupt/missing record.
        """
        record_path = self.repo.records_dir / f"{artifact_id}.json"
        try:
            with open(record_path, "r") as record_file:
                raw = json.load(record_file)
        except (OSError, ValueError) as exc:
            logger.warning(
                "Artifact %s... is indexed but its record could not be read (%s); "
                "returning idempotent duplicate result with partial fields.",
                artifact_id[:16],
                exc,
            )
            return None
        return ArtifactRecord.from_dict(raw)

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
        output_format: int = 1,
        *,
        source: str = "local",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Ingest a file and return its artifact_id.

        Backward-compatible thin wrapper around :meth:`ingest_result`.
        """
        return self.ingest_result(
            file_path,
            window_size=window_size,
            step_size=step_size,
            m=m,
            threads=threads,
            verbose=verbose,
            keep_temp=keep_temp,
            sign_with=sign_with,
            passphrase=passphrase,
            output_format=output_format,
            source=source,
            metadata=metadata,
        ).artifact_id

    def ingest_result(
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
        output_format: int = 1,
        *,
        source: str = "local",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IngestResult:
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        snapshot_path = self.repo.tmp_dir / f"snapshot.{uuid.uuid4().hex}.bin"
        temp_albc_path: Optional[str] = None

        if verbose:
            logger.info("=== Ingesting: %s ===", file_path_obj.name)

        try:
            if verbose:
                logger.info("[1/7] Capturing immutable ingest snapshot...")
            content_object_id, file_size = hash_and_copy_file(file_path_obj, snapshot_path)

            if verbose:
                logger.info(
                    "[2/7] Running scanner (window=%s, step=%s, m=%s)...",
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

            if verbose:
                logger.info("[3/7] Finalizing content hash...")
                size_mb = file_size / (1024 * 1024)
                logger.info("  File size: %s bytes (%.2f MB)", f"{file_size:,}", size_mb)
                logger.info("  content_object_id: %s...", content_object_id[:16])

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

            artifact_id = ArtifactRecordBuilder.derive_artifact_id(
                content_object_id,
                barcode_object_id,
            )

            if self.repo.artifact_exists(artifact_id):
                self.repo.ensure_artifact_indexed(artifact_id)
                if verbose:
                    logger.info("Artifact already exists: %s...", artifact_id[:16])
                    logger.info("  Skipping re-ingestion (idempotent operation)")
                existing = self._load_existing_record(artifact_id)
                return IngestResult(
                    artifact_id=artifact_id,
                    deduplicated=True,
                    signed=existing.identity_link is not None if existing else False,
                    content_object_id=content_object_id,
                    barcode_object_id=barcode_object_id,
                    created_at_unix_ms=existing.created_at_unix_ms if existing else 0,
                    original_filename=(
                        existing.metadata.get("original_filename", file_path_obj.name)
                        if existing
                        else file_path_obj.name
                    ),
                )

            if verbose:
                logger.info("[5/7] Storing content object (streaming)...")
            stored_content_id, stored_size = self.repo.store_object_from_file(
                str(snapshot_path),
                "content",
            )
            if stored_content_id != content_object_id or stored_size != file_size:
                raise ValueError(
                    "Stored content hash/size mismatch against ingest snapshot. "
                    f"expected=({content_object_id}, {file_size}), "
                    f"actual=({stored_content_id}, {stored_size})"
                )

            if verbose:
                logger.info("[6/7] Storing barcode object...")
            self.repo.store_object(albc_bytes, "barcode")

            if verbose:
                logger.info("[7/7] Parsing barcode header...")
            header = self.parser.parse_header(albc_bytes)
            if header is None:
                raise ValueError("Failed to parse ALBC header")

            scan_params = ScanParams.from_albc_header(header, algo_version=ALGO_BARCODE_V1)

            created_at_unix_ms = int(datetime.utcnow().timestamp() * 1000)
            artifact_record = ArtifactRecordBuilder.build(
                content_object_id=content_object_id,
                barcode_object_id=barcode_object_id,
                scan_params=scan_params,
                created_at_unix_ms=created_at_unix_ms,
                original_filename=file_path_obj.name,
                source=source,
                extra_metadata=metadata,
            )

            if sign_with:
                if not self.identity:
                    raise ValueError(
                        "Identity system not available. Install cryptography package."
                    )
                signature_block = self.identity.sign_artifact_record(
                    artifact_record,
                    key_id=sign_with,
                    passphrase=passphrase,
                )
                artifact_record["identity_link"] = signature_block

            self.repo.store_artifact(artifact_id, artifact_record)
            if verbose:
                logger.info("Successfully ingested: %s", file_path_obj.name)
                logger.info("  Artifact ID: %s", artifact_id)
            return IngestResult(
                artifact_id=artifact_id,
                deduplicated=False,
                signed="identity_link" in artifact_record,
                content_object_id=content_object_id,
                barcode_object_id=barcode_object_id,
                created_at_unix_ms=created_at_unix_ms,
                original_filename=file_path_obj.name,
            )
        finally:
            if temp_albc_path and not keep_temp:
                Path(temp_albc_path).unlink(missing_ok=True)
            snapshot_path.unlink(missing_ok=True)
