# Aletheia Interface Contract — v0.1

> This document is the normative description of what Aletheia accepts, produces, and
> guarantees. Automated workflows should be built against this contract, not the README.

---

## 1. Purpose

Aletheia produces and verifies **artifact records**: cryptographic + forensic proofs
that a file existed, in a specific state, at a specific time.  Every record is
content-addressed, optionally signed, and stored in an append-only repository.

---

## 2. Input Contract

### 2.1 Artifacts

| Command   | Primary input                                        |
|-----------|------------------------------------------------------|
| `ingest`  | One file path (regular file, any format)             |
| `verify`  | One file path + `--baseline <artifact_id>`           |
| `diff`    | Two artifact IDs from stored repository records       |
| `audit`   | Repository root (no file argument)                   |

Directory-level batch ingest is not yet supported; call `ingest` per file.

### 2.2 Policy & Configuration

All parameters have CLI equivalents.  Repository-level defaults live in
`{repo}/config.json`.

#### Scan parameters (ingest only; verify reuses stored baseline parameters)

| Flag              | Default    | Description                        |
|-------------------|------------|------------------------------------|
| `--window BYTES`  | `65536`    | Entropy window size (bytes)        |
| `--step BYTES`    | `16384`    | Slide step size (bytes)            |
| `--m BLOCKSIZE`   | `1`        | M-block size                       |
| `--threads N`     | `0` (auto) | Worker threads for scanner         |
| `--format {1,2}`  | `1`        | ALBC binary format version         |

#### Global CLI options (all commands; must appear before subcommand)

| Flag              | Default | Description                              |
|-------------------|---------|------------------------------------------|
| `--repo DIR`      | `.`     | Repository root directory                |
| `--verbose`, `-v` | off     | Enable verbose command output            |
| `--debug`         | off     | Print full exception tracebacks          |

#### Signing & verification policy

| Flag                    | Scope   | Description                                    |
|-------------------------|---------|------------------------------------------------|
| `--sign KEY_ID`         | ingest  | Attach Ed25519 signature using named key       |
| `--passphrase`          | ingest  | Prompt for key passphrase (interactive)        |
| `--require-signature`   | verify  | Fail if no valid signature is present          |
| `--no-zoom`             | verify  | Skip fine-resolution zoom scan                 |

#### Repository config (`config.json`, set at `init` time)

```json
{
  "version": "aletheia/repo/1",
  "storage":     { "hash_algorithm": "sha256", "object_fanout": 2 },
  "immutability": { "enforce": true, "allow_overwrite": false }
}
```

`enforce: true` + `allow_overwrite: false` is the default and **strongly recommended**
for production.  Disabling immutability is irreversible for existing records.

### 2.3 Baseline Record (verify)

`verify` takes a file path positional argument plus `--baseline <artifact_id>` (64-hex
SHA-256 string). The baseline record must already exist in the repository. Trusted public
keys for signature verification are imported via `aletheia identity import`.

---

## 3. Output Contract

### 3.1 Machine-Readable Record (JSON)

Written to `{repo}/records/{artifact_id}.json` on every successful `ingest`.

```jsonc
{
  "record_version":      "aletheia/ar/1",        // stable schema key
  "content_object_id":   "<sha256-hex>",          // SHA-256 of original file
  "barcode_object_id":   "<sha256-hex>",          // SHA-256 of .albc barcode
  "scan_params": {
    "window_size_bytes": 65536,
    "step_size_bytes":   16384,
    "m_block_size":      1,
    "quant_version":     "v0",
    "barcode_len":       <int>,
    "format_version":    1,
    "raw_data_offset":   0
  },
  "created_at_unix_ms":  <int>,
  "metadata": {
    "original_filename": "<string>",
    "ingested_from":     "<string>",
    "chain_of_custody":  []
  },
  "identity_link": null  // or IdentitySignature block if signed
}
```

`identity_link` (when present):

```jsonc
{
  "key_id":          "<string>",
  "fingerprint":     "<sha256-hex of public key>",
  "signed_at":       "<ISO 8601>",
  "signature_b64":   "<base64>",
  "signed_fields":   ["record_version","content_object_id","barcode_object_id",
                      "scan_params","created_at_unix_ms"],
  "signature_version": "aletheia/sig/ed25519/1"
}
```

**Stability**: `record_version` is the schema discriminator.  Fields may be added in
future minor versions; existing fields will not be removed or renamed within a major
version.

### 3.2 Binary Object (ALBC)

The raw entropy barcode is stored as a content-addressed object at
`{repo}/objects/{XX}/{sha256-hex}`. Retrieve it via object ID (shown in `inspect`,
with `show` as a compatibility alias).
Format is ALBC v1 (quantized u8) or v2 (quantized u8 + raw f64); version depends on
`--format` at ingest time.

### 3.3 Terminal Report (stdout)

`verify` always writes a human-readable report to stdout:

```
Verification Report
  Cryptographic match : PASS | FAIL
  Forensic match      : PASS | FAIL | SKIPPED
  Zoom performed      : yes | no
  Signature           : VALID | INVALID | ABSENT | REQUIRED-ABSENT
  Changed regions     : [{start_byte}–{end_byte}, ...]
```

`audit` writes a status banner + summary table + recommendations.

### 3.4 JSON Report (`--json`)

Available on `audit` and `diff`. Written to stdout (redirect to capture).

Audit JSON keys include: `report_type`, `generated_at` (ISO 8601), `repository`,
`status`, `summary`, `findings`.

Diff JSON keys include: `artifact_id_1`, `artifact_id_2`, `identical`,
`differing_regions`.

### 3.5 Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Success |
| `1`  | Verification/tamper failure (integrity mismatch, invalid signature) |
| `2`  | User error (bad args, missing file, unknown key, repo not initialized) |
| `3`  | System error (permission denied, OS I/O errors) |
| `4`  | Internal/unexpected error |

Exit codes are **stable**. All automated callers should check exit codes, not stdout.

---

## 4. Side Effects

| Effect                                      | Command(s)          | Reversible? |
|---------------------------------------------|---------------------|-------------|
| Write content object to `objects/`          | ingest              | No (CAS)    |
| Write artifact record to `records/`         | ingest              | No (immutable by default) |
| Update `index.sqlite3`                       | ingest, rebuild     | Via `rebuild` |
| Write to `tmp/` during scan                 | ingest              | Yes (auto-cleaned after 24 h) |
| Write key files to `~/.aletheia/keys/`      | identity generate   | Manual delete |
| **Audit log** (append-only event stream)    | —                   | *Planned — not yet implemented* |

Aletheia never modifies the **source file** passed to `ingest` or `verify`.

---

## 5. Stability Guarantees

- `artifact_id` derivation formula is frozen: `SHA-256("ALETHEIA_AR_V1" ‖ content_bytes ‖ barcode_bytes)`.
- Exit codes `0` / `1` / `2` / `3` / `4` are stable.
- JSON field names in `record_version: aletheia/ar/1` records are stable.
- The ALBC binary magic bytes (`ALBC0001`, `ALBC0002`) identify format versions permanently.
- Scan parameters stored in a record are always used verbatim during re-verification.

**Not yet stable**: HTML/PDF report output, `--json` schema shape, batch-ingest API.

---

## 6. Versioning

| Artifact                | Current version          | Named constant                  |
|-------------------------|--------------------------|---------------------------------|
| Package                 | 0.1.0                    | `__version__`                   |
| Artifact record schema  | `aletheia/ar/1`          | `ArtifactRecord.VERSION`        |
| Repository config       | `aletheia/repo/1`        | `RepoConfig.VERSION`            |
| Signature block         | `aletheia/sig/ed25519/1` | `IdentitySignature.VERSION`     |
| ALBC format             | v1 / v2                  | `ScanParams.format_version`     |
| Barcode algorithm       | `barcode:v1`             | `algorithms.ALGO_BARCODE_V1`    |
| Zoom-scan strategy      | `zoom:v1`                | `algorithms.ALGO_ZOOM_V1`       |
| ID derivation           | `record:v1`              | `algorithms.ALGO_RECORD_V1`     |
| This contract           | v0.1                     | —                               |

Breaking changes in any versioned schema will increment the version string.
Old records remain readable; the CLI will report the schema version on `inspect` (`show` alias).

---

## 7. Algorithm Versions

This table answers: "If I run ingest again next week on the same file, do I get the
same artifact_id?"

| Token        | Constant (`algorithms.py`) | What it covers |
|--------------|----------------------------|----------------|
| `record:v1`  | `ALGO_RECORD_V1`           | artifact_id derivation: `SHA-256("ALETHEIA_AR_V1" ‖ content_bytes ‖ barcode_bytes)` |
| `barcode:v1` | `ALGO_BARCODE_V1`          | Entropy-barcode pipeline (Odin binary, u8 quantisation). Stored as `scan_params.algo_version` in every artifact record. |
| `zoom:v1`    | `ALGO_ZOOM_V1`             | Zoom-scan strategy: WS=8192 bytes, SS=2048 bytes, margin=2 windows, raw_threshold=1e-9 |

### Versioning invariant

When any determinism-critical parameter changes:

1. **Add** a new constant (`ALGO_BARCODE_V2 = "barcode:v2"`) — never rename the old one.
2. **Update** consumers to use the new constant.
3. **Add** a new row to this table.
4. **Add** a migration note to Section 6.

### Backwards compatibility

Records ingested before the `algo_version` field was introduced read back as
`"barcode:v1"` (the default in `ScanParams.from_dict`).  The artifact_id derivation
formula is frozen — the same bytes always produce the same ID regardless of which
version of Aletheia is running.
