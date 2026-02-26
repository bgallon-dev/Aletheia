"""Typed domain objects for persistent Aletheia schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Mapping, Optional


class SchemaValidationError(ValueError):
    """Raised when persisted schema payloads are malformed."""


def _as_int(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise SchemaValidationError(f"{field_name} must be an integer") from exc


def _as_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise SchemaValidationError(f"{field_name} must be a boolean")


@dataclass(frozen=True)
class RepoStorageConfig:
    """Storage-level repository configuration."""

    hash_algorithm: Literal["sha256"]
    object_fanout: int

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RepoStorageConfig":
        hash_algorithm = str(payload.get("hash_algorithm", "sha256"))
        if hash_algorithm != "sha256":
            raise SchemaValidationError(
                "repo.storage.hash_algorithm must be 'sha256'"
            )

        object_fanout = _as_int(payload.get("object_fanout", 2), "repo.storage.object_fanout")
        if object_fanout != 2:
            raise SchemaValidationError("repo.storage.object_fanout must be 2")

        return cls(hash_algorithm=hash_algorithm, object_fanout=object_fanout)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash_algorithm": self.hash_algorithm,
            "object_fanout": self.object_fanout,
        }


@dataclass(frozen=True)
class RepoImmutabilityConfig:
    """Immutability policy for artifact records and index rows."""

    enforce: bool
    allow_overwrite: bool

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RepoImmutabilityConfig":
        return cls(
            enforce=_as_bool(payload.get("enforce", True), "repo.immutability.enforce"),
            allow_overwrite=_as_bool(
                payload.get("allow_overwrite", False),
                "repo.immutability.allow_overwrite",
            ),
        )

    def to_dict(self) -> Dict[str, bool]:
        return {
            "enforce": self.enforce,
            "allow_overwrite": self.allow_overwrite,
        }


@dataclass(frozen=True)
class RepoConfig:
    """Typed representation of repository config.json."""

    VERSION = "aletheia/repo/1"

    version: str
    storage: RepoStorageConfig
    immutability: RepoImmutabilityConfig
    created_at_unix_ms: Optional[int]

    @classmethod
    def default(cls, created_at_unix_ms: Optional[int] = None) -> "RepoConfig":
        return cls(
            version=cls.VERSION,
            storage=RepoStorageConfig(hash_algorithm="sha256", object_fanout=2),
            immutability=RepoImmutabilityConfig(enforce=True, allow_overwrite=False),
            created_at_unix_ms=created_at_unix_ms,
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RepoConfig":
        version = str(payload.get("version", ""))
        if version != cls.VERSION:
            raise SchemaValidationError(f"repo.version must be '{cls.VERSION}'")

        storage_payload = payload.get("storage", {})
        if not isinstance(storage_payload, Mapping):
            raise SchemaValidationError("repo.storage must be an object")

        immutability_payload = payload.get("immutability", {})
        if not isinstance(immutability_payload, Mapping):
            raise SchemaValidationError("repo.immutability must be an object")

        created_at_value = payload.get("created_at_unix_ms", payload.get("created_at"))
        if created_at_value is None:
            created_at_unix_ms: Optional[int] = None
        else:
            created_at_unix_ms = _as_int(created_at_value, "repo.created_at_unix_ms")
            if created_at_unix_ms < 0:
                raise SchemaValidationError("repo.created_at_unix_ms must be >= 0")

        return cls(
            version=version,
            storage=RepoStorageConfig.from_dict(storage_payload),
            immutability=RepoImmutabilityConfig.from_dict(immutability_payload),
            created_at_unix_ms=created_at_unix_ms,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "storage": self.storage.to_dict(),
            "immutability": self.immutability.to_dict(),
            "created_at_unix_ms": self.created_at_unix_ms,
        }


@dataclass(frozen=True)
class ScanParams:
    """Normalized scan parameters persisted in artifact records."""

    window_size_bytes: int
    step_size_bytes: int
    m_block_size: int
    quant_version: str
    barcode_len: int
    format_version: int = 1
    raw_data_offset: int = 0

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ScanParams":
        window_size_bytes = _as_int(
            payload.get("window_size_bytes", payload.get("window_size", 65536)),
            "scan_params.window_size_bytes",
        )
        step_size_bytes = _as_int(
            payload.get("step_size_bytes", payload.get("step_size", 16384)),
            "scan_params.step_size_bytes",
        )
        m_block_size = _as_int(payload.get("m_block_size", 1), "scan_params.m_block_size")
        barcode_len = _as_int(payload.get("barcode_len", 0), "scan_params.barcode_len")
        format_version = _as_int(
            payload.get("format_version", 1), "scan_params.format_version"
        )
        raw_data_offset = _as_int(
            payload.get("raw_data_offset", 0), "scan_params.raw_data_offset"
        )
        quant_version = str(payload.get("quant_version", "v0"))
        return cls(
            window_size_bytes=window_size_bytes,
            step_size_bytes=step_size_bytes,
            m_block_size=m_block_size,
            quant_version=quant_version,
            barcode_len=barcode_len,
            format_version=format_version,
            raw_data_offset=raw_data_offset,
        )

    @classmethod
    def from_albc_header(cls, header: Mapping[str, Any]) -> "ScanParams":
        return cls(
            window_size_bytes=_as_int(
                header.get("window_size_bytes"), "header.window_size_bytes"
            ),
            step_size_bytes=_as_int(header.get("step_size_bytes"), "header.step_size_bytes"),
            m_block_size=_as_int(header.get("m_block_size", 1), "header.m_block_size"),
            quant_version=str(header.get("quant_version", "v0")),
            barcode_len=_as_int(header.get("barcode_len", 0), "header.barcode_len"),
            format_version=_as_int(header.get("format_version", 1), "header.format_version"),
            raw_data_offset=_as_int(
                header.get("raw_data_offset", 0), "header.raw_data_offset"
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "window_size_bytes": self.window_size_bytes,
            "step_size_bytes": self.step_size_bytes,
            "m_block_size": self.m_block_size,
            "quant_version": self.quant_version,
            "barcode_len": self.barcode_len,
            "format_version": self.format_version,
            "raw_data_offset": self.raw_data_offset,
        }


@dataclass(frozen=True)
class IdentitySignature:
    """Identity signature block embedded in artifact records."""

    VERSION = "aletheia/sig/ed25519/1"

    key_id: str
    fingerprint: str
    signed_at: str
    signature_b64: str
    signed_fields: List[str]
    signature_version: str = VERSION

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "IdentitySignature":
        try:
            key_id = str(payload["key_id"])
            fingerprint = str(payload["fingerprint"])
            signed_at = str(payload["signed_at"])
            signature_b64 = str(payload["signature_b64"])
        except KeyError as exc:
            raise SchemaValidationError(f"identity_link missing field: {exc.args[0]}") from exc

        signature_version = str(payload.get("signature_version", cls.VERSION))
        signed_fields_raw = payload.get("signed_fields", [])
        if not isinstance(signed_fields_raw, list):
            raise SchemaValidationError("identity_link.signed_fields must be a list")
        signed_fields = [str(field) for field in signed_fields_raw]
        return cls(
            key_id=key_id,
            fingerprint=fingerprint,
            signed_at=signed_at,
            signature_b64=signature_b64,
            signed_fields=signed_fields,
            signature_version=signature_version,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_version": self.signature_version,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "signed_at": self.signed_at,
            "signature_b64": self.signature_b64,
            "signed_fields": list(self.signed_fields),
        }


@dataclass(frozen=True)
class ArtifactRecord:
    """Typed representation of artifact records persisted in records/*.json."""

    VERSION = "aletheia/ar/1"

    content_object_id: str
    barcode_object_id: str
    scan_params: ScanParams
    created_at_unix_ms: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    record_version: str = VERSION
    identity_link: Optional[IdentitySignature] = None

    @staticmethod
    def default_metadata(original_filename: str) -> Dict[str, str]:
        return {
            "original_filename": original_filename,
            "ingested_from": "local",
            "chain_of_custody": "single_node",
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ArtifactRecord":
        try:
            content_object_id = str(payload["content_object_id"])
            barcode_object_id = str(payload["barcode_object_id"])
        except KeyError as exc:
            raise SchemaValidationError(
                f"artifact record missing field: {exc.args[0]}"
            ) from exc

        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            raise SchemaValidationError("artifact record metadata must be an object")

        scan_params_payload = payload.get("scan_params", {})
        if not isinstance(scan_params_payload, Mapping):
            raise SchemaValidationError("artifact record scan_params must be an object")

        identity_payload = payload.get("identity_link")
        identity_link = (
            IdentitySignature.from_dict(identity_payload)
            if isinstance(identity_payload, Mapping)
            else None
        )

        return cls(
            record_version=str(payload.get("record_version", cls.VERSION)),
            content_object_id=content_object_id,
            barcode_object_id=barcode_object_id,
            scan_params=ScanParams.from_dict(scan_params_payload),
            created_at_unix_ms=_as_int(
                payload.get("created_at_unix_ms", 0), "artifact_record.created_at_unix_ms"
            ),
            metadata=dict(metadata),
            identity_link=identity_link,
        )

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "record_version": self.record_version,
            "content_object_id": self.content_object_id,
            "barcode_object_id": self.barcode_object_id,
            "scan_params": self.scan_params.to_dict(),
            "created_at_unix_ms": self.created_at_unix_ms,
            "metadata": dict(self.metadata),
        }
        if self.identity_link is not None:
            payload["identity_link"] = self.identity_link.to_dict()
        return payload
