# Aletheia

# Aletheia Repository

Content-addressed storage with entropic barcode verification for forensic-grade file integrity.

## Overview

Aletheia provides cryptographic and forensic verification of files through:

1. **Cryptographic Identity**: SHA-256 content hashing
2. **Forensic Identity**: Entropy-based "barcode" signatures that detect modifications and localize changes
3. **Identity Link**: Optional Ed25519 digital signatures binding artifacts to analyst identities

## Installation

```bash
# 1. Compile the Odin entropy scanner
odin build entropy.odin -file -o:speed -out:entropy.exe

# 2. (Optional) Install cryptography for digital signatures
pip install cryptography

# 3. Initialize repository (auto-created on first ingest)
python repo.py ingest <any-file>
```

## Quick Start

```bash
# Ingest a file
python repo.py ingest document.pdf

# Verify the file later
python repo.py verify <artifact_id> --file document.pdf

# List all artifacts
python repo.py list

# Run integrity audit
python repo.py audit
```

## Commands

### `repo ingest <file>`

Ingest a file into the repository with entropy barcode generation.

```bash
python repo.py ingest example.pdf
python repo.py ingest example.pdf --window 65536 --step 16384 --m 1
python repo.py ingest large_video.mp4 --threads 8

# With digital signature
python repo.py ingest evidence.pdf --sign analyst-alice --passphrase

# High-precision mode (stores raw f64 entropy values for forensic zoom)
python repo.py ingest evidence.pdf --format 2
```

**Options:**

| Option             | Description                                            |
| ------------------ | ------------------------------------------------------ |
| `--window <bytes>` | Entropy window size (default: 65536 / 64KB)            |
| `--step <bytes>`   | Step size between windows (default: 16384 / 16KB)      |
| `--m <1\|2>`       | Block size for entropy calculation (default: 1)        |
| `--threads <N>`    | Thread count for parallel scanning (default: auto)     |
| `--format <1\|2>`  | ALBC format version (1=quantized, 2=quantized+raw f64) |
| `--repo <path>`    | Repository root directory (default: .)                 |
| `--no-auto-init`   | Don't auto-initialize repository                       |
| `--quiet`          | Suppress verbose output                                |
| `--keep-temp`      | Keep temporary .albc barcode file                      |
| `--sign <key_id>`  | Sign artifact with specified key                       |
| `--passphrase`     | Prompt for key passphrase                              |

**Format Versions:**

- **Format 1 (default)**: Stores quantized u8 entropy values (1 byte per window). Suitable for most use cases.
- **Format 2**: Stores both quantized u8 AND raw f64 entropy values. Required for sub-quantization precision during forensic zoom scans. Larger file size but detects changes below the u8 quantization threshold (Δ < 0.001 entropy).

**Idempotent**: Re-ingesting the same file with identical parameters produces the same artifact ID.

### `repo verify <artifact_id> --file <path>`

Verify a file against a stored artifact with three independent checks:

```bash
python repo.py verify abc123... --file document.pdf
python repo.py verify abc123... --file document.pdf --no-zoom
```

**Verification Checks:**

1. **Cryptographic**: `SHA-256(file) == content_object_id`
2. **Forensic**: Recompute barcode, compare to `barcode_object_id`
3. **Identity Link**: Verify Ed25519 signature (if present)

**Options:**

| Option          | Description                                  |
| --------------- | -------------------------------------------- |
| `--file <path>` | File to verify (required)                    |
| `--repo <path>` | Repository root (default: .)                 |
| `--quiet`       | Suppress verbose output                      |
| `--no-zoom`     | Disable zoom scan (coarse localization only) |

**Zoom Scan**: When forensic check fails, automatically performs high-resolution analysis on modified regions (8× finer than baseline) to precisely localize changes. If the baseline was ingested with `--format 2`, zoom scan uses raw f64 comparison for sub-quantization precision.

### `repo show <artifact_id>`

Display detailed artifact information.

```bash
python repo.py show abc123def456...
```

### `repo list`

List recent artifacts with scan parameters.

```bash
python repo.py list
python repo.py list --limit 100
```

### `repo identity <subcommand>`

Manage signing keys for identity links.

```bash
# Generate a new signing key
python repo.py identity generate analyst-alice --name "Alice Smith" --email alice@example.com

# Generate with passphrase protection
python repo.py identity generate analyst-bob --passphrase

# List available keys
python repo.py identity list

# Export public key for distribution
python repo.py identity export analyst-alice > alice-public.json

# Import a public key from colleague
python repo.py identity import colleague-public.json
```

**Subcommands:**

| Subcommand          | Description                          |
| ------------------- | ------------------------------------ |
| `generate <key_id>` | Generate new Ed25519 signing keypair |
| `list`              | List all available keys              |
| `export <key_id>`   | Export public key as JSON            |
| `import <file>`     | Import a public key                  |

**Key Generation Options:**

| Option            | Description                      |
| ----------------- | -------------------------------- |
| `--name <name>`   | Key owner name                   |
| `--email <email>` | Key owner email                  |
| `--org <org>`     | Organization                     |
| `--passphrase`    | Prompt for encryption passphrase |

### `repo audit`

Deep integrity audit of all repository objects.

```bash
python repo.py audit
python repo.py audit --no-orphans    # Skip orphan file detection
python repo.py audit --json          # Output as JSON
python repo.py audit --output report.txt
```

**Options:**

| Option            | Description                  |
| ----------------- | ---------------------------- |
| `--no-orphans`    | Skip orphaned file detection |
| `--json`          | Output report as JSON        |
| `--output <file>` | Write report to file         |
| `--repo <path>`   | Repository root (default: .) |
| `--quiet`         | Suppress progress output     |

**Audit Checks:**

- **Missing Objects**: Database entries with no file on disk (DATA LOSS)
- **Corrupted Objects**: Files where hash ≠ object_id (BIT ROT / TAMPERING)
- **Orphaned Objects**: Files on disk not in database (JUNK DATA)

### `repo rebuild`

Rebuild SQLite index from filesystem (disaster recovery).

```bash
python repo.py rebuild
python repo.py rebuild --verify    # Re-hash all objects (slow but thorough)
python repo.py rebuild --strict    # Stop on first broken artifact
```

### `repo cleanup`

Clean up abandoned temporary files.

```bash
python repo.py cleanup
python repo.py cleanup --max-age 48  # Files older than 48 hours
```

## Verification Output

### Successful Verification (with Signature)

```
✓ VERIFICATION PASSED

[1/2] Cryptographic Identity Check
  ✓ Content hash matches
    Expected: a1b2c3d4...
    Actual:   a1b2c3d4...

[2/2] Forensic Identity Check (Barcode)
  ✓ Barcode hash matches

[3/3] Identity Link (Signature)
  ✓ Signature valid
    Signed by:   analyst-alice
    Fingerprint: a1b2c3d4e5f67890
    Signed at:   2024-01-15T10:30:00Z
```

### Failed Verification with Zoom Scan

```
✗ VERIFICATION FAILED

[1/2] Cryptographic Identity Check
  ✗ Content hash mismatch

[2/2] Forensic Identity Check (Barcode)
  ✗ Barcode hash mismatch

[Coarse Localization]
  Detected 1 modified region(s) at baseline resolution:

  Region 1:
    Windows:  1024 - 1028 (5 windows)
    Bytes:    16777216 - 16842752 (64.0 KB)

[Zoom Scan - High Resolution Localization]
  Resolution: WS=8192 bytes (8 KiB), SS=2048 bytes (2 KiB)
  Analyzed 1 coarse region(s)

  Zoom Region 1 (from coarse windows 1024-1028):
    Scan range: bytes 16744448 - 16875520
    Found 1 fine-grained difference(s):

      Difference 1:
        Windows:  12 - 14 (3 windows @ zoom resolution)
        Bytes:    16769024 - 16781312 (12.0 KB)

[3/3] Identity Link (Signature)
  ⊘ No signature present
```

### Audit Report Example

```
======================================================================
              ALETHEIA FORENSIC INTEGRITY REPORT
======================================================================

  Repository:    /path/to/repo
  Generated:     2024-01-15T10:30:00Z
  Duration:      12.34 seconds

  ╔═══════════════════════════════════════════════════════════════╗
  ║  ✓  STATUS: HEALTHY - ALL OBJECTS VERIFIED                    ║
  ╚═══════════════════════════════════════════════════════════════╝

----------------------------------------------------------------------
  SUMMARY
----------------------------------------------------------------------
  Total Objects Indexed:    1,234
  Verified OK:              1,234
  Missing (Data Loss):      0
  Corrupted (Bit Rot):      0
  Orphaned (Junk):          3
```

## Architecture

### Content-Addressed Storage

Files are stored by their SHA-256 hash with 2-character fanout:

```
objects/
├── a1/a1b2c3d4e5f6...  # Content file
├── cd/cdef0123...      # Barcode file
```

### Artifact Records

JSON records link content + barcode + metadata + optional signature:

```json
{
  "record_version": "aletheia/ar/1",
  "content_object_id": "a1b2c3d4...",
  "barcode_object_id": "cdef0123...",
  "scan_params": {
    "window_size_bytes": 65536,
    "step_size_bytes": 16384,
    "m_block_size": 1,
    "quant_version": "v0",
    "barcode_len": 1024,
    "format_version": 2
  },
  "created_at_unix_ms": 1699999999000,
  "metadata": {
    "original_filename": "document.pdf"
  },
  "identity_link": {
    "signature_version": "aletheia/sig/ed25519/1",
    "key_id": "analyst-alice",
    "fingerprint": "a1b2c3d4e5f67890",
    "signed_at": "2024-01-15T10:30:00Z",
    "signature_b64": "base64-encoded-signature",
    "signed_fields": ["content_object_id", "barcode_object_id", "..."]
  }
}
```

### Directory Structure

```
alethaia_repo/
├── objects/          # Content-addressed objects (2-char fanout)
│   ├── a1/a1b2...    # Content files
│   └── cd/cdef...    # Barcode files
├── records/          # Artifact records (JSON)
│   └── <artifact_id>.json
├── tmp/              # Temporary files (auto-cleaned)
├── config.json       # Repository configuration
└── index.sqlite3     # SQLite index for fast queries

~/.aletheia/
└── keys/             # Signing keys (user home directory)
    ├── analyst-alice.key   # Private key (encrypted)
    └── analyst-alice.pub   # Public key (distributable)
```

## Identity System

### Trust Model

- **Private Key**: Held by the historian/analyst (never leaves their machine)
- **Public Key**: Distributed to verifiers (shared via export/import)
- **Signature**: Proves the record was authorized by the key holder

### Key Security

- Private keys stored in `~/.aletheia/keys/`
- Optional passphrase encryption (recommended for production)
- Unix file permissions set to 0600 (owner read/write only)

### Workflow

```bash
# Analyst generates their key
python repo.py identity generate analyst-alice --passphrase

# Analyst ingests and signs evidence
python repo.py ingest evidence.pdf --sign analyst-alice --passphrase

# Analyst exports public key for verifiers
python repo.py identity export analyst-alice > alice-public.json

# Verifier imports analyst's public key
python repo.py identity import alice-public.json

# Verifier can now verify signed artifacts
python repo.py verify <artifact_id> --file evidence.pdf
```

## Performance Notes

### Large File Support

- **Streaming I/O**: Files are hashed and copied in chunks (8MB default), never fully loaded into RAM
- **Memory-Mapped Scanning**: Odin scanner uses OS virtual memory for files of any size
- **Single-Pass Ingest**: Hash computed while copying (halves disk I/O vs hash-then-copy)

### Zoom Scan Optimization

- Uses `file.seek()` to jump directly to modified regions
- For a 50GB file with corruption at byte 49GB: instant (vs. streaming from byte 0)

### Audit Performance

- Streaming cursor iteration (no fetchall trap)
- PRAGMA synchronous=OFF during rebuild (safe because idempotent)
- O(1) orphan detection via in-memory set

## Barcode Format (ALBC)

### ALBC v1 (Standard) - 32-byte header + quantized bytes

```
Offset  Size  Field
0       8     Magic "ALBC0001"
8       4     window_size_bytes (u32 LE)
12      4     step_size_bytes (u32 LE)
16      4     m_block_size (u32 LE)
20      4     quant_version (u32 LE)
24      8     barcode_len (u64 LE)
32      N     Quantized entropy values (1 byte per window)
```

### ALBC v2 (Extended) - 40-byte header + quantized + raw f64

```
Offset  Size  Field
0       8     Magic "ALBC0002"
8       4     window_size_bytes (u32 LE)
12      4     step_size_bytes (u32 LE)
16      4     m_block_size (u32 LE)
20      4     quant_version (u32 LE)
24      8     barcode_len (u64 LE)
32      8     raw_data_offset (u64 LE) - offset to f64 array (0 if not present)
40      N     Quantized entropy values (1 byte per window)
40+N    N*8   Raw f64 entropy values (8 bytes per window)
```

**When to use ALBC v2:**

- Forensic investigations requiring sub-quantization precision
- Detection of changes with entropy delta < 0.001
- Zoom scan comparisons needing exact entropy values

## Direct Module Usage

### Ingest Pipeline

```python
from ingest import IngestPipeline

pipeline = IngestPipeline(repo_root=".")
artifact_id = pipeline.ingest(
    "document.pdf",
    window_size=65536,
    step_size=16384,
    output_format=2,  # Use ALBC v2 for high precision
    sign_with="analyst-alice",
    passphrase="secret"
)
```

### Verification

```python
from verify import ArtifactVerifier

verifier = ArtifactVerifier(repo_root=".")
result = verifier.verify(artifact_id, "document.pdf", enable_zoom=True)

if result.passed():
    print("Verification passed")
    if result.signature_valid:
        print(f"Signed by: {result.signature_key_id}")
else:
    print(result.format_report())
```

### Identity Operations

```python
from identity import IdentityLink

identity = IdentityLink()

# Generate key
key_info = identity.generate_key(
    "analyst-alice",
    passphrase="secret",
    metadata={"name": "Alice Smith", "email": "alice@example.com"}
)

# Sign a record
signature_block = identity.sign_artifact_record(record, "analyst-alice", "secret")

# Verify signature
result = identity.verify_signature(record, signature_block)
print(f"Valid: {result['valid']}")
```

### Repository Operations

```python
from repository import AletheiaRepository

repo = AletheiaRepository(".", auto_init=True)

# Store content
content_id, size = repo.store_object_from_file("large_file.bin", "content")

# Stream large objects (memory-safe)
for chunk in repo.get_object_stream(content_id):
    process(chunk)

# Random access
with repo.get_object_handle(content_id) as f:
    f.seek(50 * 1024 * 1024 * 1024)  # Jump to 50GB mark
    data = f.read(512)

# Audit integrity
stats = repo.audit_objects(verbose=True, check_orphans=True)
```

## Requirements

- Python 3.8+
- Odin entropy scanner (compiled binary)
- Optional: `cryptography` package for digital signatures

```bash
pip install cryptography  # For identity/signature features
```
