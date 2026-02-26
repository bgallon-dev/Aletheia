import pytest

from aletheia.domain import (
    ArtifactRecord,
    IdentitySignature,
    RepoConfig,
    ScanParams,
    SchemaValidationError,
)


def test_scan_params_from_legacy_keys_normalizes_to_canonical_shape():
    params = ScanParams.from_dict(
        {
            "window_size": 4096,
            "step_size": 1024,
            "m_block_size": 2,
            "quant_version": "v2",
            "barcode_len": 42,
        }
    )
    assert params.window_size_bytes == 4096
    assert params.step_size_bytes == 1024
    assert params.format_version == 1
    assert params.to_dict()["window_size_bytes"] == 4096
    assert "window_size" not in params.to_dict()


def test_identity_signature_round_trip_preserves_fields():
    signature = IdentitySignature(
        key_id="analyst-demo",
        fingerprint="f" * 64,
        signed_at="2026-01-01T00:00:00Z",
        signature_b64="YmFzZTY0",
        signed_fields=["content_object_id", "barcode_object_id"],
    )
    encoded = signature.to_dict()
    decoded = IdentitySignature.from_dict(encoded)
    assert decoded == signature


def test_artifact_record_round_trip_with_signature():
    record = ArtifactRecord(
        content_object_id="a" * 64,
        barcode_object_id="b" * 64,
        scan_params=ScanParams(
            window_size_bytes=65536,
            step_size_bytes=16384,
            m_block_size=1,
            quant_version="v0",
            barcode_len=128,
            format_version=2,
            raw_data_offset=40,
        ),
        created_at_unix_ms=1700000000000,
        metadata=ArtifactRecord.default_metadata("demo.bin"),
        identity_link=IdentitySignature(
            key_id="analyst-demo",
            fingerprint="c" * 64,
            signed_at="2026-01-01T00:00:00Z",
            signature_b64="YWJj",
            signed_fields=["record_version", "content_object_id"],
        ),
    )
    loaded = ArtifactRecord.from_dict(record.to_dict())
    assert loaded == record


def test_artifact_record_rejects_bad_scan_params_shape():
    with pytest.raises(SchemaValidationError):
        ArtifactRecord.from_dict(
            {
                "record_version": "aletheia/ar/1",
                "content_object_id": "a" * 64,
                "barcode_object_id": "b" * 64,
                "scan_params": "bad",
                "created_at_unix_ms": 1700000000000,
                "metadata": {},
            }
        )


def test_repo_config_round_trip():
    payload = {
        "version": "aletheia/repo/1",
        "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
        "immutability": {"enforce": True, "allow_overwrite": False},
        "created_at_unix_ms": 1700000000000,
    }
    config = RepoConfig.from_dict(payload)
    assert config.to_dict() == payload


def test_repo_config_accepts_legacy_created_at_field():
    config = RepoConfig.from_dict(
        {
            "version": "aletheia/repo/1",
            "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
            "immutability": {"enforce": True, "allow_overwrite": False},
            "created_at": 1700000000000,
        }
    )
    assert config.created_at_unix_ms == 1700000000000


def test_repo_config_rejects_wrong_storage_contract():
    with pytest.raises(SchemaValidationError):
        RepoConfig.from_dict(
            {
                "version": "aletheia/repo/1",
                "storage": {"hash_algorithm": "sha512", "object_fanout": 4},
                "immutability": {"enforce": True, "allow_overwrite": False},
                "created_at_unix_ms": 1700000000000,
            }
        )
