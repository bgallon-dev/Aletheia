"""
Signing and verification tests — Category 6.

Proves that chain-of-custody claims are real:
- Valid signatures verify correctly.
- Any tampering with the record breaks verification.
- Wrong key fails verification.
- Key management operations work correctly.
- The canonicalization step is stable (same record → same bytes signed).

All tests require the `cryptography` package and are skipped if unavailable.
"""

from __future__ import annotations

import base64

import pytest

from aletheia.store.identity import CRYPTO_AVAILABLE, IdentityError, IdentityLink, validate_key_id

from conftest import minimal_record


pytestmark = pytest.mark.skipif(
    not CRYPTO_AVAILABLE,
    reason="cryptography package not installed",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(tmp_path):
    return IdentityLink(key_dir=tmp_path)


def _generate_and_sign(tmp_path, key_id="test-key", passphrase="s3cr3t"):
    identity = _make_identity(tmp_path)
    identity.generate_key(key_id, passphrase=passphrase)
    record = minimal_record()
    sig = identity.sign_artifact_record(record, key_id=key_id, passphrase=passphrase)
    return identity, record, sig


# ---------------------------------------------------------------------------
# Sign → verify round-trip
# ---------------------------------------------------------------------------

def test_sign_and_verify_roundtrip(tmp_path):
    identity, record, sig = _generate_and_sign(tmp_path)
    result = identity.verify_signature(record, sig)
    assert result["valid"] is True
    assert result["error"] is None


def test_sign_and_verify_key_id_preserved(tmp_path):
    identity, record, sig = _generate_and_sign(tmp_path, key_id="analyst-alice-2025")
    result = identity.verify_signature(record, sig)
    assert result["key_id"] == "analyst-alice-2025"


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_tampered_content_object_id_fails_verification(tmp_path):
    """Mutating content_object_id after signing must break verification."""
    identity, record, sig = _generate_and_sign(tmp_path)
    tampered = dict(record)
    tampered["content_object_id"] = "f" * 64  # Changed
    result = identity.verify_signature(tampered, sig)
    assert result["valid"] is False


def test_tampered_barcode_object_id_fails_verification(tmp_path):
    identity, record, sig = _generate_and_sign(tmp_path)
    tampered = dict(record)
    tampered["barcode_object_id"] = "0" * 64
    result = identity.verify_signature(tampered, sig)
    assert result["valid"] is False


def test_tampered_signature_b64_fails_verification(tmp_path):
    """Corrupting one character of the base64 signature must fail verification."""
    identity, record, sig = _generate_and_sign(tmp_path)
    bad_sig = dict(sig)
    # Flip the first character of the base64 signature
    original_b64 = bad_sig["signature_b64"]
    first_char = original_b64[0]
    flipped = "B" if first_char != "B" else "C"
    bad_sig["signature_b64"] = flipped + original_b64[1:]
    result = identity.verify_signature(record, bad_sig)
    assert result["valid"] is False


def test_wrong_public_key_fails_verification(tmp_path):
    """Verifying with a different key's public key must fail."""
    identity = _make_identity(tmp_path)
    identity.generate_key("key-a", passphrase="pass-a")
    identity.generate_key("key-b", passphrase="pass-b")

    record = minimal_record()
    sig_a = identity.sign_artifact_record(record, key_id="key-a", passphrase="pass-a")

    # Verify with key-b's public key injected as the trusted key for key-a
    key_b_info = identity.get_public_key("key-b")
    trusted = {"key-a": key_b_info["public_key_b64"]}

    result = identity.verify_signature(record, sig_a, trusted_keys=trusted)
    assert result["valid"] is False


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def test_duplicate_key_id_raises(tmp_path):
    identity = _make_identity(tmp_path)
    identity.generate_key("my-key", passphrase="p")
    with pytest.raises(IdentityError):
        identity.generate_key("my-key", passphrase="p")


def test_encrypted_key_requires_passphrase(tmp_path):
    identity = _make_identity(tmp_path)
    identity.generate_key("encrypted-key", passphrase="secret")
    record = minimal_record()
    with pytest.raises(IdentityError):
        identity.sign_artifact_record(record, key_id="encrypted-key", passphrase=None)


def test_wrong_passphrase_raises(tmp_path):
    identity = _make_identity(tmp_path)
    identity.generate_key("locked-key", passphrase="correct-password")
    record = minimal_record()
    with pytest.raises(IdentityError):
        identity.sign_artifact_record(record, key_id="locked-key", passphrase="wrong-password")


def test_list_keys_returns_generated_key(tmp_path):
    identity = _make_identity(tmp_path)
    identity.generate_key("visible-key", passphrase="p")
    keys = identity.list_keys()
    key_ids = [k["key_id"] for k in keys]
    assert "visible-key" in key_ids


def test_list_keys_empty_when_no_keys(tmp_path):
    identity = _make_identity(tmp_path)
    assert identity.list_keys() == []


def test_get_public_key_fingerprint_matches_private_key(tmp_path):
    identity = _make_identity(tmp_path)
    gen_result = identity.generate_key("fp-key", passphrase="p")
    pub_info = identity.get_public_key("fp-key")
    assert pub_info["fingerprint"] == gen_result["fingerprint"]


# ---------------------------------------------------------------------------
# Canonicalization stability
# ---------------------------------------------------------------------------

def test_canonicalization_same_record_produces_same_message(tmp_path):
    """Signing the same record twice must use the same canonical bytes.

    This validates that no random nonce or timestamp is mixed into the
    signed message (the Ed25519 algorithm itself is deterministic).
    """
    identity = _make_identity(tmp_path)
    identity.generate_key("canon-key", passphrase="p")

    record = minimal_record()

    sig1 = identity.sign_artifact_record(record, key_id="canon-key", passphrase="p")
    sig2 = identity.sign_artifact_record(record, key_id="canon-key", passphrase="p")

    # Both signatures should verify (deterministic signing with Ed25519)
    assert identity.verify_signature(record, sig1)["valid"] is True
    assert identity.verify_signature(record, sig2)["valid"] is True

    # Extract the signed canonical message for both calls and compare
    # We do this by calling _build_canonical_message directly
    from aletheia.domain import ArtifactRecord

    record_obj = ArtifactRecord.from_dict(record)
    signed_fields = sig1["signed_fields"]
    msg1 = identity._build_canonical_message(record_obj.to_dict(), signed_fields)
    msg2 = identity._build_canonical_message(record_obj.to_dict(), signed_fields)
    assert msg1 == msg2, "Canonical message differs between calls — canonicalization is unstable"


# ---------------------------------------------------------------------------
# validate_key_id
# ---------------------------------------------------------------------------

def test_validate_key_id_accepts_alphanumeric():
    validate_key_id("analyst2024")  # No error


def test_validate_key_id_accepts_separators():
    validate_key_id("analyst-alice.2024_v1")  # No error


def test_validate_key_id_rejects_path_traversal():
    with pytest.raises(IdentityError):
        validate_key_id("../etc/passwd")


def test_validate_key_id_rejects_slash():
    with pytest.raises(IdentityError):
        validate_key_id("a/b")


def test_validate_key_id_rejects_spaces():
    with pytest.raises(IdentityError):
        validate_key_id("key id")


def test_validate_key_id_rejects_empty_string():
    with pytest.raises(IdentityError):
        validate_key_id("")


def test_validate_key_id_starts_with_alphanumeric():
    """Key ID must begin with a letter or digit."""
    with pytest.raises(IdentityError):
        validate_key_id("-starts-with-dash")
