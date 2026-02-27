# Aletheia Portfolio Demo (5 Steps)

This demo shows a complete ingest, verification, tamper detection, and signature policy workflow.

## 0. Install the CLI

```bash
pip install -e .
```

## 1. Generate a signing identity

```bash
aletheia identity generate analyst-demo --name "Demo Analyst" --email demo@example.com
```

## 2. Ingest a file with signature and ALBC v2

```bash
aletheia ingest demo_input.bin --sign analyst-demo --passphrase --format 2
```

Save the printed `Artifact ID` from command output.

## 3. Verify clean file (expected PASS)

```bash
aletheia verify <ARTIFACT_ID> --file demo_input.bin --require-signature
```

Expected:
- Content hash matches
- Barcode hash matches
- Signature valid
- Overall verification passed

## 4. Tamper with a copy and verify (expected FAIL + localization)

```bash
copy demo_input.bin demo_input_tampered.bin
```

Edit a few bytes in `demo_input_tampered.bin`, then run:

```bash
aletheia verify <ARTIFACT_ID> --file demo_input_tampered.bin
```

Expected:
- Content hash mismatch
- Barcode mismatch
- Coarse and zoom localization output

## 5. Signature policy check (expected FAIL when unsigned)

Ingest without `--sign`:

```bash
aletheia ingest unsigned_input.bin
aletheia verify <UNSIGNED_ARTIFACT_ID> --file unsigned_input.bin --require-signature
```

Expected:
- Verification fails because signature is required but missing

