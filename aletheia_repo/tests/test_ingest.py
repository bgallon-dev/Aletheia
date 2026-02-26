import hashlib
import struct
import tempfile
from pathlib import Path

import pytest

from aletheia import ingest as ingest_module
from aletheia.repository import AletheiaRepository, RepositoryError
from aletheia.utils import compute_file_hash


def _build_albc_v1(payload: bytes) -> bytes:
    header = b"ALBC0001"
    header += struct.pack("<I", 64)
    header += struct.pack("<I", 16)
    header += struct.pack("<I", 1)
    header += struct.pack("<I", 0)
    header += struct.pack("<Q", len(payload))
    return header + payload


class _DummyScanner:
    def __init__(self):
        self.scan_paths = []

    def scan(self, file_path: str, **kwargs):
        self.scan_paths.append(file_path)
        payload = bytes([1, 2, 3, 4])
        albc = _build_albc_v1(payload)
        tmp = tempfile.NamedTemporaryFile(suffix=".albc", delete=False)
        tmp.write(albc)
        tmp.close()
        return albc, tmp.name


class _DummyRepo:
    def __init__(self, repo_root: str, auto_init: bool = True):
        self.root = Path(repo_root)
        self.tmp_dir = self.root / "tmp"
        self.records_dir = self.root / "records"
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.content_store_paths = []
        self.records = {}

    def artifact_exists(self, artifact_id: str) -> bool:
        return artifact_id in self.records

    def ensure_artifact_indexed(self, artifact_id: str):
        return True

    def store_object_from_file(self, file_path: str, obj_type: str):
        self.content_store_paths.append(file_path)
        return compute_file_hash(Path(file_path))

    def store_object(self, data: bytes, obj_type: str):
        return hashlib.sha256(data).hexdigest()

    def store_artifact(self, artifact_id: str, record):
        self.records[artifact_id] = record


def test_repository_rejects_invalid_object_id(tmp_path):
    repo = AletheiaRepository(str(tmp_path), auto_init=True)
    with pytest.raises(RepositoryError):
        repo.get_object_path("../bad")


def test_ingest_uses_snapshot_for_scan_and_store(monkeypatch, tmp_path):
    scanner = _DummyScanner()
    monkeypatch.setattr(ingest_module, "OdinScanner", lambda *args, **kwargs: scanner)
    monkeypatch.setattr(ingest_module, "AletheiaRepository", _DummyRepo)
    monkeypatch.setattr(ingest_module, "IDENTITY_AVAILABLE", False)

    source = tmp_path / "source.bin"
    source.write_bytes(b"demo-bytes" * 1024)

    pipeline = ingest_module.IngestPipeline(repo_root=str(tmp_path))
    artifact_id = pipeline.ingest(str(source), verbose=False)

    assert artifact_id
    assert len(scanner.scan_paths) == 1
    scan_path = Path(scanner.scan_paths[0])
    assert scan_path != source
    assert scan_path.parent == tmp_path / "tmp"
    assert not scan_path.exists()  # Snapshot is cleaned after ingest.

    assert len(pipeline.repo.content_store_paths) == 1
    stored_path = Path(pipeline.repo.content_store_paths[0])
    assert stored_path.parent == tmp_path / "tmp"
    assert not stored_path.exists()
