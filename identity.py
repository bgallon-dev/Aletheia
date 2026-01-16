#!/usr/bin/env python3
"""
Aletheia Identity Link - Digital Signatures for Artifact Records

Provides cryptographic proof that a specific identity authorized a record.
Uses Ed25519 for signatures (fast, secure, small signatures).

Trust Model:
  - Private key: Held by the historian/analyst (never leaves their machine)
  - Public key: Distributed to verifiers (embedded in repository config)
  - Signature: Proves the record was authorized by the key holder

Key Storage:
  - Private keys: ~/.aletheia/keys/{key_id}.key (encrypted with passphrase)
  - Public keys: Repository config.json or separate keyring
"""

import base64
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

# Use cryptography library (widely available, audited)
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# Key file locations
DEFAULT_KEY_DIR = Path.home() / ".aletheia" / "keys"
KEY_FILE_EXTENSION = ".key"
PUBKEY_FILE_EXTENSION = ".pub"


class IdentityError(Exception):
    """Base exception for identity operations."""

    pass


class KeyNotFoundError(IdentityError):
    """Raised when a key cannot be found."""

    pass


class SignatureInvalidError(IdentityError):
    """Raised when a signature fails verification."""

    pass


class IdentityLink:
    """
    Digital signature system for Aletheia artifact records.

    Uses Ed25519 signatures for:
    - Fast signing/verification
    - Small signature size (64 bytes)
    - Strong security guarantees
    """

    SIGNATURE_VERSION = "aletheia/sig/ed25519/1"

    def __init__(self, key_dir: Optional[Path] = None):
        """
        Initialize identity system.

        Args:
            key_dir: Directory for key storage (default: ~/.aletheia/keys)
        """
        if not CRYPTO_AVAILABLE:
            raise IdentityError(
                "cryptography library not installed. "
                "Install with: pip install cryptography"
            )

        self.key_dir = key_dir or DEFAULT_KEY_DIR
        self.key_dir.mkdir(parents=True, exist_ok=True)

    # =========================================================================
    # KEY GENERATION
    # =========================================================================

    def generate_key(
        self,
        key_id: str,
        passphrase: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a new Ed25519 keypair.

        Args:
            key_id: Unique identifier for this key (e.g., "analyst-alice-2024")
            passphrase: Optional passphrase to encrypt private key at rest
            metadata: Optional metadata (name, email, organization, etc.)

        Returns:
            Dict with key_id, public_key_b64, fingerprint, created_at

        Raises:
            IdentityError: If key_id already exists
        """
        private_key_path = self.key_dir / f"{key_id}{KEY_FILE_EXTENSION}"
        public_key_path = self.key_dir / f"{key_id}{PUBKEY_FILE_EXTENSION}"

        if private_key_path.exists():
            raise IdentityError(f"Key already exists: {key_id}")

        # Generate keypair
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize public key
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        public_key_b64 = base64.b64encode(public_key_bytes).decode("ascii")

        # Compute fingerprint (SHA-256 of public key, truncated)
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]

        # Serialize private key (encrypted if passphrase provided)
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            encryption = serialization.NoEncryption()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        # Build key file with metadata
        created_at = datetime.utcnow().isoformat() + "Z"

        key_file_content = {
            "version": "aletheia/key/1",
            "key_id": key_id,
            "algorithm": "Ed25519",
            "fingerprint": fingerprint,
            "public_key_b64": public_key_b64,
            "created_at": created_at,
            "encrypted": passphrase is not None,
            "metadata": metadata or {},
            "private_key_pem": private_key_pem.decode("ascii"),
        }

        # Write private key file (restricted permissions)
        private_key_path.write_text(json.dumps(key_file_content, indent=2))

        # Restrict permissions on private key (Unix only)
        try:
            os.chmod(private_key_path, 0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support Unix permissions

        # Write public key file (for distribution)
        public_key_content = {
            "version": "aletheia/pubkey/1",
            "key_id": key_id,
            "algorithm": "Ed25519",
            "fingerprint": fingerprint,
            "public_key_b64": public_key_b64,
            "created_at": created_at,
            "metadata": metadata or {},
        }
        public_key_path.write_text(json.dumps(public_key_content, indent=2))

        return {
            "key_id": key_id,
            "fingerprint": fingerprint,
            "public_key_b64": public_key_b64,
            "created_at": created_at,
            "private_key_path": str(private_key_path),
            "public_key_path": str(public_key_path),
        }

    def list_keys(self) -> List[Dict[str, Any]]:
        """List all available keys."""
        keys = []

        for key_file in self.key_dir.glob(f"*{KEY_FILE_EXTENSION}"):
            try:
                content = json.loads(key_file.read_text())
                keys.append(
                    {
                        "key_id": content.get("key_id"),
                        "fingerprint": content.get("fingerprint"),
                        "algorithm": content.get("algorithm"),
                        "created_at": content.get("created_at"),
                        "encrypted": content.get("encrypted", False),
                        "metadata": content.get("metadata", {}),
                    }
                )
            except (json.JSONDecodeError, KeyError):
                continue

        return keys

    def get_public_key(self, key_id: str) -> Dict[str, Any]:
        """
        Get public key info for a key_id.

        Returns dict with public_key_b64, fingerprint, metadata.
        """
        # Try public key file first
        public_key_path = self.key_dir / f"{key_id}{PUBKEY_FILE_EXTENSION}"
        if public_key_path.exists():
            return json.loads(public_key_path.read_text())

        # Fall back to private key file
        private_key_path = self.key_dir / f"{key_id}{KEY_FILE_EXTENSION}"
        if private_key_path.exists():
            content = json.loads(private_key_path.read_text())
            return {
                "version": "aletheia/pubkey/1",
                "key_id": content["key_id"],
                "algorithm": content["algorithm"],
                "fingerprint": content["fingerprint"],
                "public_key_b64": content["public_key_b64"],
                "created_at": content["created_at"],
                "metadata": content.get("metadata", {}),
            }

        raise KeyNotFoundError(f"Key not found: {key_id}")

    # =========================================================================
    # SIGNING
    # =========================================================================

    def _load_private_key(
        self, key_id: str, passphrase: Optional[str] = None
    ) -> Tuple[Ed25519PrivateKey, Dict[str, Any]]:
        """Load private key from file."""
        key_path = self.key_dir / f"{key_id}{KEY_FILE_EXTENSION}"

        if not key_path.exists():
            raise KeyNotFoundError(f"Private key not found: {key_id}")

        content = json.loads(key_path.read_text())

        # Check if encrypted
        if content.get("encrypted") and not passphrase:
            raise IdentityError(f"Key {key_id} is encrypted. Passphrase required.")

        # Load private key
        private_key_pem = content["private_key_pem"].encode("ascii")

        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=passphrase.encode() if passphrase else None,
                backend=default_backend(),
            )
        except Exception as e:
            raise IdentityError(f"Failed to load key {key_id}: {e}")

        return private_key, content

    def sign_artifact_record(
        self, record: Dict[str, Any], key_id: str, passphrase: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Sign an artifact record.

        The signature covers a canonical JSON representation of the record,
        ensuring any modification invalidates the signature.

        Args:
            record: Artifact record dict (from ArtifactRecordBuilder)
            key_id: Key ID to sign with
            passphrase: Passphrase if key is encrypted

        Returns:
            Signature block to add to record:
            {
                "signature_version": "aletheia/sig/ed25519/1",
                "key_id": "analyst-alice-2024",
                "fingerprint": "a1b2c3d4e5f67890",
                "signed_at": "2024-01-15T10:30:00Z",
                "signature_b64": "base64-encoded-signature",
                "signed_fields": ["content_object_id", "barcode_object_id", ...]
            }
        """
        # Load private key
        private_key, key_content = self._load_private_key(key_id, passphrase)

        # Build canonical message to sign
        # We sign specific fields to allow adding non-signed metadata later
        signed_fields = [
            "record_version",
            "content_object_id",
            "barcode_object_id",
            "scan_params",
            "created_at_unix_ms",
        ]

        canonical_data = self._build_canonical_message(record, signed_fields)

        # Sign
        signature_bytes = private_key.sign(canonical_data)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        signed_at = datetime.utcnow().isoformat() + "Z"

        return {
            "signature_version": self.SIGNATURE_VERSION,
            "key_id": key_id,
            "fingerprint": key_content["fingerprint"],
            "signed_at": signed_at,
            "signature_b64": signature_b64,
            "signed_fields": signed_fields,
        }

    def _build_canonical_message(
        self, record: Dict[str, Any], fields: List[str]
    ) -> bytes:
        """
        Build canonical byte representation for signing.

        Uses sorted JSON with no whitespace for deterministic output.
        """
        # Extract only the fields we're signing
        signed_data = {}
        for field in fields:
            if field in record:
                signed_data[field] = record[field]

        # Canonical JSON: sorted keys, no whitespace, UTF-8
        canonical_json = json.dumps(signed_data, sort_keys=True, separators=(",", ":"))

        # Prefix with version to prevent cross-protocol attacks
        message = f"ALETHEIA_SIG_V1:{canonical_json}"

        return message.encode("utf-8")

    # =========================================================================
    # VERIFICATION
    # =========================================================================

    def verify_signature(
        self,
        record: Dict[str, Any],
        signature_block: Dict[str, Any],
        trusted_keys: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Verify a signature on an artifact record.

        Args:
            record: Artifact record dict
            signature_block: Signature block from record["identity_link"]
            trusted_keys: Optional dict of key_id -> public_key_b64
                         If None, loads from local key directory

        Returns:
            Verification result:
            {
                "valid": True/False,
                "key_id": "analyst-alice-2024",
                "fingerprint": "a1b2c3d4e5f67890",
                "signed_at": "2024-01-15T10:30:00Z",
                "error": None or "error message"
            }
        """
        result = {
            "valid": False,
            "key_id": signature_block.get("key_id"),
            "fingerprint": signature_block.get("fingerprint"),
            "signed_at": signature_block.get("signed_at"),
            "error": None,
        }

        try:
            # Get public key
            key_id = signature_block.get("key_id")
            if not key_id:
                result["error"] = "Missing key_id in signature"
                return result

            # Load public key
            if trusted_keys and key_id in trusted_keys:
                public_key_b64 = trusted_keys[key_id]
            else:
                try:
                    key_info = self.get_public_key(key_id)
                    public_key_b64 = key_info["public_key_b64"]
                except KeyNotFoundError:
                    result["error"] = f"Public key not found: {key_id}"
                    return result

            # Decode public key
            public_key_bytes = base64.b64decode(public_key_b64)
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Verify fingerprint matches
            expected_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
            if signature_block.get("fingerprint") != expected_fingerprint:
                result["error"] = "Fingerprint mismatch"
                return result

            # Rebuild canonical message
            signed_fields = signature_block.get("signed_fields", [])
            canonical_data = self._build_canonical_message(record, signed_fields)

            # Decode signature
            signature_b64 = signature_block.get("signature_b64")
            if not signature_b64:
                result["error"] = "Missing signature"
                return result

            signature_bytes = base64.b64decode(signature_b64)

            # Verify
            public_key.verify(signature_bytes, canonical_data)

            result["valid"] = True
            return result

        except Exception as e:
            result["error"] = f"Verification failed: {e}"
            return result

    # =========================================================================
    # KEYRING MANAGEMENT (for repository-level trust)
    # =========================================================================

    def export_public_key(self, key_id: str) -> str:
        """Export public key as JSON string for distribution."""
        key_info = self.get_public_key(key_id)
        return json.dumps(key_info, indent=2)

    def import_public_key(self, key_json: str) -> str:
        """
        Import a public key from JSON.

        Returns the key_id of the imported key.
        """
        key_info = json.loads(key_json)

        key_id = key_info.get("key_id")
        if not key_id:
            raise IdentityError("Invalid key file: missing key_id")

        # Validate it's a public key
        if "private_key_pem" in key_info:
            raise IdentityError("Cannot import private key as public key")

        if "public_key_b64" not in key_info:
            raise IdentityError("Invalid key file: missing public_key_b64")

        # Write to key directory
        public_key_path = self.key_dir / f"{key_id}{PUBKEY_FILE_EXTENSION}"
        public_key_path.write_text(json.dumps(key_info, indent=2))

        return key_id


def build_signed_artifact_record(
    content_object_id: str,
    barcode_object_id: str,
    scan_params: Dict[str, Any],
    created_at_unix_ms: int,
    original_filename: str,
    key_id: str,
    passphrase: Optional[str] = None,
    key_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Build and sign an artifact record in one step.

    Convenience function combining ArtifactRecordBuilder + signing.
    """
    from ingest import ArtifactRecordBuilder

    # Build base record
    record = ArtifactRecordBuilder.build(
        content_object_id=content_object_id,
        barcode_object_id=barcode_object_id,
        scan_params=scan_params,
        created_at_unix_ms=created_at_unix_ms,
        original_filename=original_filename,
    )

    # Sign it
    identity = IdentityLink(key_dir=key_dir)
    signature_block = identity.sign_artifact_record(record, key_id, passphrase)

    # Add signature to record
    record["identity_link"] = signature_block

    return record
