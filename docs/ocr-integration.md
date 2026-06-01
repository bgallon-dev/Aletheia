# OCR Pipeline Integration

> How to plug Aletheia into an OCR pipeline so every OCR output gets a cryptographic +
> forensic provenance record (an *artifact record*) as it is produced. See
> [`contract.md`](contract.md) for the normative input/output contract; this guide is the
> practical quickstart.

Aletheia is designed to be **called per output** by the OCR pipeline — either by importing
the Python API (same process) or by invoking the CLI as a subprocess. There is no daemon
or watcher to keep alive. Ingestion is **idempotent**: re-ingesting identical content is a
no-op that returns the existing artifact (`deduplicated=True` / `status: "duplicate"`).

---

## Option A — Python API (recommended for in-process pipelines)

```python
from aletheia import ingest_file

result = ingest_file(
    "out/page_0003.txt",
    repo="ocr_repo",                 # repository root (auto-initialized)
    source="ocr",                    # stored as metadata.ingested_from (default)
    metadata={
        "ocr": {
            "source_document_id": "doc-42",
            "source_filename": "scan.pdf",
            "page": 3,
            "page_count": 10,
            "engine": "tesseract",
            "engine_version": "5.3.4",
            "language": "eng",
            "confidence": 0.97,
            "job_id": "job-2026-06-01-7",
            "output_type": "txt",
        }
    },
)

print(result.artifact_id)     # 64-hex content+barcode-derived id
print(result.deduplicated)    # False on first ingest, True on a re-run of identical bytes
print(result.signed)          # True if the record carries an identity signature
```

`ingest_file(...)` returns an `IngestResult` (frozen dataclass): `artifact_id`,
`deduplicated`, `signed`, `content_object_id`, `barcode_object_id`, `created_at_unix_ms`,
`original_filename`. Store `artifact_id` alongside your OCR output so you can later
`verify` it.

To sign each artifact with an analyst key, pass `sign_with="<key_id>"` (and `passphrase=`
if the key is encrypted). For lower-level control (custom scanner binary, batching over one
pipeline instance), use `IngestPipeline(...).ingest_result(...)` directly.

### Verifying later

```python
from aletheia import ArtifactVerifier

verifier = ArtifactVerifier(repo_root="ocr_repo")
report = verifier.verify(result.artifact_id, "out/page_0003.txt")
assert report.passed()
```

---

## Option B — CLI subprocess (language-agnostic)

Invoke `aletheia ingest <file> --json` and parse stdout. With `--json`, **stdout contains
only the JSON result**; all logging goes to stderr, so parsing is safe.

```python
import json
import subprocess

proc = subprocess.run(
    [
        "aletheia", "--repo", "ocr_repo", "ingest", "out/page_0003.txt",
        "--json", "--source", "ocr",
        "--meta", "ocr.source_document_id=doc-42",
        "--meta", "ocr.page=3",            # numeric/bool values are JSON-typed automatically
        "--meta", "ocr.confidence=0.97",
        "--meta-json", '{"ocr": {"engine": "tesseract", "engine_version": "5.3.4"}}',
    ],
    capture_output=True,
    text=True,
)

if proc.returncode != 0:
    raise RuntimeError(f"aletheia ingest failed ({proc.returncode}): {proc.stderr}")

record = json.loads(proc.stdout)
print(record["artifact_id"], record["status"])   # status: "new" | "duplicate"
```

Notes:
- `--meta KEY=VALUE` is repeatable; **dotted keys nest** (`ocr.page=3` → `{"ocr":{"page":3}}`).
  Values are parsed as JSON when possible (so `3` is an int, `true` a bool), otherwise kept
  as a string. `--meta` entries override `--meta-json`.
- `--meta-json` accepts a JSON object literal or `@path/to/meta.json`.
- Always branch on the **exit code** (see contract §3.5), not on stdout text.

---

## Option C — Batch a directory (`ingest-dir`)

Hand Aletheia a directory and let it ingest everything that matches your globs — useful for
ingesting all outputs of a completed OCR job at once. Temp/partial files and dotfiles are
skipped by default.

```bash
aletheia --repo ocr_repo ingest-dir out/job-7 \
  --recursive --include "*.txt" --include "*.hocr" \
  --source ocr --meta job_id=job-7 --json
```

`--json` prints one summary object:

```jsonc
{
  "directory": "out/job-7",
  "summary": { "total": 12, "ingested": 10, "duplicates": 2, "failed": 0 },
  "results": [ { "artifact_id": "...", "status": "new", "file": "out/job-7/page_0001.txt", ... } ],
  "errors":  []
}
```

Exit code is `0` when nothing failed, `2` if any file failed (the summary is still printed
so it doubles as the error report). Use `--fail-fast` to stop at the first failure. Default
excludes are `*.tmp`, `*.part`, `*.partial`, `*.crdownload`, and dotfiles — pass
`--no-default-excludes` to disable, or add more with `--exclude GLOB`.

---

## Operational tips

- **Write-then-ingest**: ingest a file only after the OCR engine has finished writing it
  (e.g. write to `*.tmp` then atomically rename). For `ingest-dir`, the default excludes
  already skip common partial-write suffixes.
- **Idempotency / retries**: safe to re-call on the same output — you'll get the same
  `artifact_id` back with `status: "duplicate"`.
- **Provenance**: keep OCR fields under the `metadata.ocr` namespace (additive,
  `record_version` stays `aletheia/ar/1`); `original_filename` is always the real file name
  and cannot be overridden.
- **Stability**: the §3.6 JSON keys are the v0.1 shape and will only be extended
  additively. Pin behavior to exit codes and documented keys.
