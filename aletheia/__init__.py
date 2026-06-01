"""Aletheia package.

Public, stable entry points for embedding Aletheia in other pipelines (e.g. ingesting
OCR outputs as they are produced). The recommended call is :func:`ingest_file`::

    from aletheia import ingest_file

    result = ingest_file(
        "page_0003.txt",
        repo="ocr_repo",
        metadata={"ocr": {"source_document_id": "doc-42", "page": 3,
                          "engine": "tesseract", "engine_version": "5.3.4",
                          "confidence": 0.97}},
    )
    print(result.artifact_id, result.deduplicated)
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import ArtifactRecord, ScanParams, SchemaValidationError
from .ingest import IngestPipeline
from .store.artifacts import IngestResult
from .store.repository import (
    AletheiaRepository,
    BrokenArtifactError,
    ImmutabilityError,
    IntegrityError,
    ObjectNotFoundError,
    RepositoryError,
    RepositoryNotInitializedError,
)
from .store.verify import ArtifactVerifier

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ingest_file",
    "IngestPipeline",
    "IngestResult",
    "AletheiaRepository",
    "ArtifactVerifier",
    "ArtifactRecord",
    "ScanParams",
    "SchemaValidationError",
    "RepositoryError",
    "RepositoryNotInitializedError",
    "ImmutabilityError",
    "ObjectNotFoundError",
    "BrokenArtifactError",
    "IntegrityError",
]


def ingest_file(
    file_path: str,
    repo: str = ".",
    *,
    source: str = "ocr",
    metadata: Optional[Dict[str, Any]] = None,
    sign_with: Optional[str] = None,
    passphrase: Optional[str] = None,
    window_size: int = 65536,
    step_size: int = 16384,
    m: int = 1,
    threads: int = 0,
    output_format: int = 1,
    verbose: bool = False,
    odin_binary: Optional[str] = None,
    auto_init: bool = True,
) -> IngestResult:
    """Ingest a single file into an Aletheia repository and return an :class:`IngestResult`.

    Convenience wrapper for pipeline integration. Defaults ``source="ocr"`` and quiet
    output; pass ``metadata`` (e.g. an ``{"ocr": {...}}`` provenance block) to record
    chain-of-custody details. Ingestion is idempotent: re-ingesting identical content
    returns the existing artifact with ``deduplicated=True``.
    """
    pipeline = IngestPipeline(repo_root=repo, odin_binary=odin_binary, auto_init=auto_init)
    return pipeline.ingest_result(
        file_path,
        window_size=window_size,
        step_size=step_size,
        m=m,
        threads=threads,
        verbose=verbose,
        sign_with=sign_with,
        passphrase=passphrase,
        output_format=output_format,
        source=source,
        metadata=metadata,
    )
