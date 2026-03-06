"""Backward-compatible ingest module.

Canonical implementations now live in:
- ``aletheia.core`` (ALBC parsing + scanner primitives)
- ``aletheia.store.artifacts`` (repository ingest orchestration)
"""

from __future__ import annotations

from typing import Optional

from .core.albc import ALBCParser
from .core.scanner import DEFAULT_SCANNER_TIMEOUT_SECONDS, OdinScanner
from .store.artifacts import ArtifactRecordBuilder
from .store.artifacts import IngestPipeline as _StoreIngestPipeline
from .store.repository import AletheiaRepository, RepositoryNotInitializedError

try:
    from .store.identity import IdentityLink

    IDENTITY_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    IdentityLink = None  # type: ignore[assignment]
    IDENTITY_AVAILABLE = False


class IngestPipeline(_StoreIngestPipeline):
    """Compatibility wrapper preserving historical monkeypatch hooks in tests."""

    def __init__(
        self,
        repo_root: str = ".",
        odin_binary: Optional[str] = None,
        auto_init: bool = True,
    ):
        identity_factory = IdentityLink if IDENTITY_AVAILABLE else None
        super().__init__(
            repo_root=repo_root,
            odin_binary=odin_binary,
            auto_init=auto_init,
            repository_cls=AletheiaRepository,
            scanner_factory=lambda binary: OdinScanner(binary),
            identity_factory=identity_factory,
            identity_available=IDENTITY_AVAILABLE,
        )


__all__ = [
    "ALBCParser",
    "ArtifactRecordBuilder",
    "AletheiaRepository",
    "DEFAULT_SCANNER_TIMEOUT_SECONDS",
    "IDENTITY_AVAILABLE",
    "IngestPipeline",
    "OdinScanner",
    "RepositoryNotInitializedError",
]
