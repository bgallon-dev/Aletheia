import json

import pytest

from aletheia.repository import AletheiaRepository, ImmutabilityError


def _record_payload(content_object_id: str, barcode_object_id: str, filename: str) -> dict:
    return {
        "record_version": "aletheia/ar/1",
        "content_object_id": content_object_id,
        "barcode_object_id": barcode_object_id,
        "scan_params": {
            "window_size_bytes": 65536,
            "step_size_bytes": 16384,
            "m_block_size": 1,
            "quant_version": "v0",
            "barcode_len": 16,
        },
        "created_at_unix_ms": 1700000000000,
        "metadata": {
            "original_filename": filename,
            "ingested_from": "local",
            "chain_of_custody": "single_node",
        },
    }


def _object_ids(repo: AletheiaRepository, suffix: str) -> tuple:
    content_object_id = repo.store_object(f"content-{suffix}".encode("utf-8"), "content")
    barcode_object_id = repo.store_object(f"barcode-{suffix}".encode("utf-8"), "barcode")
    return content_object_id, barcode_object_id


def _set_immutability(repo: AletheiaRepository, enforce: bool, allow_overwrite: bool) -> None:
    config = json.loads(repo.config_path.read_text())
    config["immutability"] = {
        "enforce": enforce,
        "allow_overwrite": allow_overwrite,
    }
    repo.config_path.write_text(json.dumps(config, indent=2))
    repo.config = repo.load_config(set_created_at_if_missing=False)
    repo.object_fanout = repo.config.storage.object_fanout


def test_repository_init_writes_repo_config_schema(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)

    config = json.loads(repo.config_path.read_text())
    assert config["version"] == "aletheia/repo/1"
    assert config["storage"] == {"hash_algorithm": "sha256", "object_fanout": 2}
    assert config["immutability"] == {"enforce": True, "allow_overwrite": False}
    assert isinstance(config["created_at_unix_ms"], int)
    assert config["created_at_unix_ms"] > 0
    assert repo.config.created_at_unix_ms == config["created_at_unix_ms"]


def test_repository_backfills_created_at_unix_ms_when_missing(tmp_path):
    tmp_path.joinpath("objects").mkdir(parents=True)
    tmp_path.joinpath("records").mkdir()
    tmp_path.joinpath("tmp").mkdir()
    tmp_path.joinpath("config.json").write_text(
        json.dumps(
            {
                "version": "aletheia/repo/1",
                "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
                "immutability": {"enforce": True, "allow_overwrite": False},
                "created_at": None,
            },
            indent=2,
        )
    )

    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    config = json.loads(repo.config_path.read_text())
    assert "created_at" not in config
    assert isinstance(config["created_at_unix_ms"], int)
    assert repo.config.created_at_unix_ms == config["created_at_unix_ms"]


def test_store_artifact_rejects_semantic_overwrite_when_immutable(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    artifact_id = "a" * 64
    content_object_id, barcode_object_id = _object_ids(repo, "first")

    record = _record_payload(content_object_id, barcode_object_id, "first.bin")
    repo.store_artifact(artifact_id, record)

    updated_record = dict(record)
    updated_record["metadata"] = dict(record["metadata"])
    updated_record["metadata"]["original_filename"] = "changed.bin"

    with pytest.raises(ImmutabilityError):
        repo.store_artifact(artifact_id, updated_record)


def test_store_artifact_allows_idempotent_rewrite(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    artifact_id = "b" * 64
    content_object_id, barcode_object_id = _object_ids(repo, "stable")
    record = _record_payload(content_object_id, barcode_object_id, "stable.bin")

    repo.store_artifact(artifact_id, record)
    repo.store_artifact(artifact_id, record)

    conn = repo._connect()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?", (artifact_id,))
    assert cursor.fetchone()[0] == 1
    conn.close()


def test_allow_overwrite_true_still_blocks_semantic_changes_when_enforced(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    _set_immutability(repo, enforce=True, allow_overwrite=True)

    artifact_id = "c" * 64
    content_object_id, barcode_object_id = _object_ids(repo, "strict")
    record = _record_payload(content_object_id, barcode_object_id, "strict.bin")
    repo.store_artifact(artifact_id, record)

    changed = dict(record)
    changed["metadata"] = dict(record["metadata"])
    changed["metadata"]["chain_of_custody"] = "multi_node"

    with pytest.raises(ImmutabilityError):
        repo.store_artifact(artifact_id, changed)
