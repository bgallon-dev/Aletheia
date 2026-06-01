"""Documentation drift guards for README and contract docs."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPO_ROOT / "README.md"
CONTRACT_PATH = REPO_ROOT / "docs" / "contract.md"


def _read(path: Path) -> str:
    data = path.read_bytes()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252")


def test_readme_uses_current_verify_cli_shape() -> None:
    readme = _read(README_PATH)
    assert "aletheia verify <path> --baseline <artifact_id>" in readme
    assert "verify <artifact_id> --file" not in readme
    assert "--file <path>" not in readme


def test_readme_uses_current_diff_cli_shape() -> None:
    readme = _read(README_PATH)
    assert "aletheia diff <artifact_id_1> <artifact_id_2>" in readme
    assert "diff <file1.albc> <file2.albc>" not in readme
    assert "--threshold" not in readme


def test_readme_python_floor_matches_project() -> None:
    readme = _read(README_PATH)
    assert "Python 3.9+" in readme


def test_contract_includes_current_verify_diff_terms() -> None:
    contract = _read(CONTRACT_PATH)
    assert "--baseline <artifact_id>" in contract
    assert "Two artifact IDs from stored repository records" in contract


def test_contract_exit_codes_match_cli_contract() -> None:
    contract = _read(CONTRACT_PATH)
    assert "| `0`  | Success |" in contract
    assert "| `1`  | Verification/tamper failure" in contract
    assert "| `2`  | User error" in contract
    assert "| `3`  | System error" in contract
    assert "| `4`  | Internal/unexpected error" in contract


def test_contract_documents_ocr_ingest_features() -> None:
    contract = _read(CONTRACT_PATH)
    assert "ingest-dir" in contract
    assert "metadata.ingested_from" in contract
    assert "Ingest JSON Result" in contract
    assert '"status"' in contract
    assert '"ocr"' in contract


def test_ocr_integration_guide_exists_and_documents_entrypoints() -> None:
    guide = REPO_ROOT / "docs" / "ocr-integration.md"
    assert guide.exists()
    text = _read(guide)
    assert "ingest_file" in text
    assert "--json" in text
    assert "ingest-dir" in text
