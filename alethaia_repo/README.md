# Aletheia Repository

Content-addressed storage with entropic barcode verification for forensic-grade file integrity.

## Overview

Aletheia provides cryptographic and forensic verification of files through:

1. **Cryptographic Identity**: SHA-256 content hashing
2. **Forensic Identity**: Entropy-based "barcode" signatures that detect modifications and localize changes

## Installation

```bash
# 1. Compile the Odin entropy scanner
cd ../entropy/odin_entropy
odin build . -out:entropy.exe

# 2. Initialize repository (auto-created on first ingest)
cd ../../alethaia_repo
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
```

## Commands

### `repo ingest <file>`

Ingest a file into the repository with entropy barcode generation.

```bash
python repo.py ingest example.pdf
python repo.py ingest example.pdf --window 65536 --step 16384 --m 1
python repo.py ingest large_video.mp4 --threads 8
```

**Options:**

- `--window <bytes>` - Entropy window size (default: 65536 / 64KB)
- `--step <bytes>` - Step size between windows (default: 16384 / 16KB)
- `--m <1|2>` - Block size for entropy calculation (default: 1)
- `--threads <N>` - Thread count for parallel scanning (default: auto)
- `--repo <path>` - Repository root directory (default: .)
- `--no-auto-init` - Don't auto-initialize repository
- `--quiet` - Suppress verbose output
- `--keep-temp` - Keep temporary .albc barcode file

**Idempotent**: Re-ingesting the same file with identical parameters produces the same artifact ID.

### `repo verify <artifact_id> --file <path>`

Verify a file against a stored artifact with two independent checks:

```bash
python repo.py verify abc123... --file document.pdf
python repo.py verify abc123... --file document.pdf --no-zoom
```

**Verification Checks:**

1. **Cryptographic**: `SHA-256(file) == content_object_id`
2. **Forensic**: Recompute barcode, compare to `barcode_object_id`

**Options:**

- `--file <path>` - File to verify (required)
- `--repo <path>` - Repository root (default: .)
- `--quiet` - Suppress verbose output
- `--no-zoom` - Disable zoom scan (coarse localization only)

**Zoom Scan**: When forensic check fails, automatically performs high-resolution analysis on modified regions (8× finer than baseline) to precisely localize changes.

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

### `repo rebuild`

Rebuild SQLite index from filesystem (disaster recovery).

```bash
python repo.py rebuild
python repo.py rebuild --verify    # Re-hash all objects (slow but thorough)
python repo.py rebuild --strict    # Stop on first broken artifact
```

### `repo audit`

Deep integrity audit of all repository objects.

```bash
python repo.py audit
python repo.py audit --no-orphans  # Skip orphan file detection
```

## Verification Output

### Successful Verification

```
✓ VERIFICATION PASSED

[1/2] Cryptographic Identity Check
  ✓ Content hash matches
    Expected: a1b2c3d4...
    Actual:   a1b2c3d4...

[2/2] Forensic Identity Check (Barcode)
  ✓ Barcode hash matches
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

JSON records link content + barcode + metadata:

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
    "barcode_len": 1024
  },
  "created_at_unix_ms": 1699999999000,
  "metadata": {
    "original_filename": "document.pdf"
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
```

## Performance Notes

### Large File Support

- **Streaming I/O**: Files are hashed and copied in chunks (8MB default), never fully loaded into RAM
- **Memory-Mapped Scanning**: Odin scanner uses OS virtual memory for files of any size
- **Single-Pass Ingest**: Hash computed while copying (halves disk I/O vs hash-then-copy)

### Zoom Scan Optimization

- Uses `file.seek()` to jump directly to modified regions
- For a 50GB file with corruption at byte 49GB: instant (vs. streaming from byte 0)

## Barcode Format (ALBC)

32-byte header + quantized entropy bytes:

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

## Direct Module Usage

### Ingest Pipeline

```python
from ingest import IngestPipeline

pipeline = IngestPipeline(repo_root=".")
artifact_id = pipeline.ingest("document.pdf", window_size=65536, step_size=16384)
```

### Verification

```python
from verify import ArtifactVerifier

verifier = ArtifactVerifier(repo_root=".")
result = verifier.verify(artifact_id, "document.pdf", enable_zoom=True)

if result.passed():
    print("Verification passed")
else:
    print(result.format_report())
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
```
