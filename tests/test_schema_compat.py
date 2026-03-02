"""
Schema and compatibility tests — Category 4.

Prove that the output is a stable artifact: required fields are enforced,
invalid values fail cleanly, and unknown/legacy values are handled gracefully.
"""

from __future__ import annotations

import pytest

from aletheia.domain import (
    ArtifactRecord,
    IdentitySignature,
    RepoConfig,
    RepoImmutabilityConfig,
    RepoStorageConfig,
    ScanParams,
    SchemaValidationError,
)

from conftest import minimal_record


# ---------------------------------------------------------------------------
# ArtifactRecord required fields
# ---------------------------------------------------------------------------

def test_artifact_record_missing_content_object_id_raises():
    record = minimal_record()
    del record["content_object_id"]
    with pytest.raises(SchemaValidationError, match="content_object_id"):
        ArtifactRecord.from_dict(record)


def test_artifact_record_missing_barcode_object_id_raises():
    record = minimal_record()
    del record["barcode_object_id"]
    with pytest.raises(SchemaValidationError, match="barcode_object_id"):
        ArtifactRecord.from_dict(record)


def test_artifact_record_non_dict_metadata_raises():
    record = minimal_record()
    record["metadata"] = "not-a-dict"
    with pytest.raises(SchemaValidationError):
        ArtifactRecord.from_dict(record)


def test_artifact_record_non_dict_scan_params_raises():
    record = minimal_record()
    record["scan_params"] = "string-not-a-dict"
    with pytest.raises(SchemaValidationError):
        ArtifactRecord.from_dict(record)


def test_artifact_record_unknown_record_version_is_accepted():
    """Unknown record_version should be stored as-is (pass-through design).

    The system does not validate record_version in ArtifactRecord.from_dict
    to allow forward-compatible reads of newer records.
    """
    record = minimal_record()
    record["record_version"] = "aletheia/ar/v999"
    parsed = ArtifactRecord.from_dict(record)
    assert parsed.record_version == "aletheia/ar/v999"


# ---------------------------------------------------------------------------
# ScanParams validation
# ---------------------------------------------------------------------------

def test_scan_params_step_greater_than_window_raises():
    with pytest.raises(SchemaValidationError, match="step_size_bytes"):
        ScanParams.from_dict(
            {"window_size_bytes": 64, "step_size_bytes": 128, "m_block_size": 1,
             "quant_version": "v0", "barcode_len": 10}
        )


def test_scan_params_step_equal_to_window_is_valid():
    """step_size == window_size is explicitly allowed (no overlap)."""
    sp = ScanParams.from_dict(
        {"window_size_bytes": 64, "step_size_bytes": 64, "m_block_size": 1,
         "quant_version": "v0", "barcode_len": 10}
    )
    assert sp.step_size_bytes == 64


def test_scan_params_step_zero_raises():
    with pytest.raises(SchemaValidationError, match="step_size_bytes"):
        ScanParams.from_dict(
            {"window_size_bytes": 64, "step_size_bytes": 0, "m_block_size": 1,
             "quant_version": "v0", "barcode_len": 10}
        )


def test_scan_params_unknown_format_version_raises():
    with pytest.raises(SchemaValidationError, match="format_version"):
        ScanParams.from_dict(
            {"window_size_bytes": 64, "step_size_bytes": 16, "m_block_size": 1,
             "quant_version": "v0", "barcode_len": 10, "format_version": 99}
        )


def test_scan_params_format_version_1_and_2_accepted():
    for fv in (1, 2):
        sp = ScanParams.from_dict(
            {"window_size_bytes": 64, "step_size_bytes": 16, "m_block_size": 1,
             "quant_version": "v0", "barcode_len": 10, "format_version": fv}
        )
        assert sp.format_version == fv


def test_scan_params_legacy_window_size_key_normalized():
    """'window_size' (without _bytes) is a legacy key that must still be accepted."""
    sp = ScanParams.from_dict(
        {"window_size": 65536, "step_size": 16384, "m_block_size": 1,
         "quant_version": "v0", "barcode_len": 10}
    )
    assert sp.window_size_bytes == 65536
    assert sp.step_size_bytes == 16384


def test_scan_params_non_integer_window_size_raises():
    with pytest.raises(SchemaValidationError):
        ScanParams.from_dict(
            {"window_size_bytes": "big", "step_size_bytes": 16, "m_block_size": 1,
             "quant_version": "v0", "barcode_len": 10}
        )


# ---------------------------------------------------------------------------
# RepoConfig validation
# ---------------------------------------------------------------------------

def test_repo_config_wrong_version_string_raises():
    d = {
        "version": "aletheia/repo/99",
        "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
        "immutability": {"enforce": True, "allow_overwrite": False},
    }
    with pytest.raises(SchemaValidationError, match="version"):
        RepoConfig.from_dict(d)


def test_repo_config_wrong_hash_algorithm_raises():
    d = {
        "version": "aletheia/repo/1",
        "storage": {"hash_algorithm": "md5", "object_fanout": 2},
        "immutability": {"enforce": True, "allow_overwrite": False},
    }
    with pytest.raises(SchemaValidationError, match="hash_algorithm"):
        RepoConfig.from_dict(d)


def test_repo_config_wrong_object_fanout_raises():
    d = {
        "version": "aletheia/repo/1",
        "storage": {"hash_algorithm": "sha256", "object_fanout": 4},
        "immutability": {"enforce": True, "allow_overwrite": False},
    }
    with pytest.raises(SchemaValidationError, match="object_fanout"):
        RepoConfig.from_dict(d)


def test_repo_config_non_bool_enforce_raises():
    d = {
        "version": "aletheia/repo/1",
        "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
        "immutability": {"enforce": "yes", "allow_overwrite": False},
    }
    with pytest.raises(SchemaValidationError, match="enforce"):
        RepoConfig.from_dict(d)


def test_repo_config_negative_created_at_raises():
    d = {
        "version": "aletheia/repo/1",
        "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
        "immutability": {"enforce": True, "allow_overwrite": False},
        "created_at_unix_ms": -1,
    }
    with pytest.raises(SchemaValidationError, match="created_at_unix_ms"):
        RepoConfig.from_dict(d)


def test_repo_config_round_trip():
    config = RepoConfig.default(created_at_unix_ms=1700000000000)
    assert RepoConfig.from_dict(config.to_dict()) == config


# ---------------------------------------------------------------------------
# IdentitySignature validation
# ---------------------------------------------------------------------------

def test_identity_signature_missing_key_id_raises():
    d = {
        "fingerprint": "abc",
        "signed_at": "2024-01-01T00:00:00Z",
        "signature_b64": "AAAA",
    }
    with pytest.raises(SchemaValidationError, match="key_id"):
        IdentitySignature.from_dict(d)


def test_identity_signature_missing_fingerprint_raises():
    d = {
        "key_id": "test-key",
        "signed_at": "2024-01-01T00:00:00Z",
        "signature_b64": "AAAA",
    }
    with pytest.raises(SchemaValidationError, match="fingerprint"):
        IdentitySignature.from_dict(d)


def test_identity_signature_missing_signature_b64_raises():
    d = {
        "key_id": "test-key",
        "fingerprint": "abc",
        "signed_at": "2024-01-01T00:00:00Z",
    }
    with pytest.raises(SchemaValidationError, match="signature_b64"):
        IdentitySignature.from_dict(d)


def test_identity_signature_signed_fields_non_list_raises():
    d = {
        "key_id": "test-key",
        "fingerprint": "abc",
        "signed_at": "2024-01-01T00:00:00Z",
        "signature_b64": "AAAA",
        "signed_fields": "not-a-list",
    }
    with pytest.raises(SchemaValidationError, match="signed_fields"):
        IdentitySignature.from_dict(d)


def test_identity_signature_round_trip_preserves_all_fields():
    d = {
        "signature_version": "aletheia/sig/ed25519/1",
        "key_id": "analyst-001",
        "fingerprint": "deadbeef",
        "signed_at": "2024-01-01T00:00:00Z",
        "signature_b64": "AAAAAAAAAAAAAAAA",
        "signed_fields": ["content_object_id", "barcode_object_id"],
    }
    sig = IdentitySignature.from_dict(d)
    assert sig.to_dict() == d
