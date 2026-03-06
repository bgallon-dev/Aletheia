"""Application layer: persistence, artifact orchestration, and verification."""

from .artifacts import ArtifactRecordBuilder, IngestPipeline
from .identity import (
    CRYPTO_AVAILABLE,
    IdentityError,
    IdentityLink,
    KeyNotFoundError,
    SignatureInvalidError,
    build_signed_artifact_record,
    validate_key_id,
)
from .repository import (
    AletheiaRepository,
    BrokenArtifactError,
    ImmutabilityError,
    IntegrityError,
    ObjectNotFoundError,
    RepositoryError,
    RepositoryNotInitializedError,
)
from .verify import ArtifactVerifier, VerificationResult, ZoomRegion

__all__ = [
    "AletheiaRepository",
    "ArtifactRecordBuilder",
    "ArtifactVerifier",
    "BrokenArtifactError",
    "CRYPTO_AVAILABLE",
    "IdentityError",
    "IdentityLink",
    "ImmutabilityError",
    "IngestPipeline",
    "IntegrityError",
    "KeyNotFoundError",
    "ObjectNotFoundError",
    "RepositoryError",
    "RepositoryNotInitializedError",
    "SignatureInvalidError",
    "VerificationResult",
    "ZoomRegion",
    "build_signed_artifact_record",
    "validate_key_id",
]
