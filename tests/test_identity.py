import pytest

from aletheia.store.identity import (
    CRYPTO_AVAILABLE,
    IdentityError,
    IdentityLink,
    validate_key_id,
)


def test_validate_key_id_rejects_path_traversal():
    with pytest.raises(IdentityError):
        validate_key_id("../bad")


@pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="cryptography dependency not installed")
def test_verify_signature_accepts_legacy_fingerprint(tmp_path):
    identity = IdentityLink(key_dir=tmp_path)
    identity.generate_key("analyst_demo", passphrase="secret")

    record = {
        "record_version": "aletheia/ar/1",
        "content_object_id": "a" * 64,
        "barcode_object_id": "b" * 64,
        "scan_params": {
            "window_size_bytes": 65536,
            "step_size_bytes": 16384,
            "m_block_size": 1,
            "quant_version": "v0",
            "barcode_len": 16,
        },
        "created_at_unix_ms": 1700000000000,
    }
    signature_block = identity.sign_artifact_record(
        record, key_id="analyst_demo", passphrase="secret"
    )
    signature_block["fingerprint"] = signature_block["fingerprint"][:16]

    verify_result = identity.verify_signature(record, signature_block)
    assert verify_result["valid"] is True
