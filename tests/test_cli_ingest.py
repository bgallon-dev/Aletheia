"""In-process tests for CLI ingest helpers, JSON output, and ingest-dir batch."""

from __future__ import annotations

import json
import struct
import sys
import tempfile

import pytest

from aletheia.cli.main import _iter_ingest_files, _parse_meta_args, main

# --- dummy scanner (avoids the Odin binary) ---


def _albc_v1(payload: bytes = b"\x01\x02\x03\x04") -> bytes:
    header = b"ALBC0001"
    header += struct.pack("<I", 64)
    header += struct.pack("<I", 16)
    header += struct.pack("<I", 1)
    header += struct.pack("<I", 0)
    header += struct.pack("<Q", len(payload))
    return header + payload


class _DummyScanner:
    def scan(self, file_path: str, **kwargs):
        albc = _albc_v1()
        tmp = tempfile.NamedTemporaryFile(suffix=".albc", delete=False)
        tmp.write(albc)
        tmp.close()
        return albc, tmp.name


def _run_main(argv, monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", ["aletheia", *argv])
    return main()


def _last_json(captured_out: str) -> dict:
    lines = [line for line in captured_out.splitlines() if line.strip()]
    return json.loads(lines[-1])


# --- _parse_meta_args ---


def test_parse_meta_typed_and_nested():
    meta = _parse_meta_args(["ocr.page=3", "ocr.confidence=0.97", "engine=tesseract"], None)
    assert meta == {"ocr": {"page": 3, "confidence": 0.97}, "engine": "tesseract"}


def test_parse_meta_json_base_with_override_and_merge():
    meta = _parse_meta_args(["ocr.page=4"], '{"ocr": {"page": 1, "engine": "x"}, "j": 1}')
    assert meta["ocr"]["page"] == 4  # --meta overrides --meta-json
    assert meta["ocr"]["engine"] == "x"  # deep-merge preserves siblings
    assert meta["j"] == 1


def test_parse_meta_string_fallback():
    assert _parse_meta_args(["note=hello world"], None)["note"] == "hello world"


def test_parse_meta_missing_equals_raises():
    with pytest.raises(ValueError):
        _parse_meta_args(["NOEQUALS"], None)


def test_parse_meta_empty_key_raises():
    with pytest.raises(ValueError):
        _parse_meta_args(["=v"], None)


def test_parse_meta_json_non_object_raises():
    with pytest.raises(ValueError):
        _parse_meta_args(None, "[1, 2, 3]")


def test_parse_meta_json_from_file(tmp_path):
    p = tmp_path / "m.json"
    p.write_text('{"ocr": {"engine": "tess"}}')
    assert _parse_meta_args(None, f"@{p}")["ocr"]["engine"] == "tess"


def test_parse_meta_nested_conflict_raises():
    with pytest.raises(ValueError):
        _parse_meta_args(["a=1", "a.b=2"], None)


# --- _iter_ingest_files ---


def _make_tree(root):
    (root / "a.txt").write_text("a")
    (root / "b.json").write_text("b")
    (root / "c.tmp").write_text("c")
    (root / ".hidden.txt").write_text("h")
    sub = root / "sub"
    sub.mkdir()
    (sub / "d.txt").write_text("d")
    dot = root / ".git"
    dot.mkdir()
    (dot / "config").write_text("x")


def test_iter_files_non_recursive_no_filters(tmp_path):
    _make_tree(tmp_path)
    names = {f.name for f in _iter_ingest_files(tmp_path, [], [], recursive=False)}
    assert names == {"a.txt", "b.json", "c.tmp", ".hidden.txt"}


def test_iter_files_include_filter(tmp_path):
    _make_tree(tmp_path)
    names = {f.name for f in _iter_ingest_files(tmp_path, ["*.txt"], [], recursive=False)}
    assert names == {"a.txt", ".hidden.txt"}


def test_iter_files_exclude_tmp_and_dotfiles(tmp_path):
    _make_tree(tmp_path)
    names = {f.name for f in _iter_ingest_files(tmp_path, [], ["*.tmp", ".*"], recursive=False)}
    assert names == {"a.txt", "b.json"}


def test_iter_files_recursive_skips_dot_directories(tmp_path):
    _make_tree(tmp_path)
    names = {f.name for f in _iter_ingest_files(tmp_path, ["*"], [".*"], recursive=True)}
    assert "d.txt" in names  # sub/d.txt picked up recursively
    assert "config" not in names  # .git/config skipped (under a dot-directory)
    assert ".hidden.txt" not in names  # excluded by .*


# --- ingest --json ---


def test_ingest_json_output_shape_and_cleanliness(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("aletheia.ingest.OdinScanner", lambda *a, **k: _DummyScanner())
    f = tmp_path / "page.txt"
    f.write_text("hello ocr")
    repo = tmp_path / "repo"

    rc = _run_main(
        [
            "--repo",
            str(repo),
            "ingest",
            str(f),
            "--json",
            "--source",
            "ocr",
            "--meta",
            "ocr.page=3",
        ],
        monkeypatch,
    )
    out = capsys.readouterr().out
    assert rc == 0
    lines = [line for line in out.splitlines() if line.strip()]
    assert len(lines) == 1  # stdout carries ONLY the JSON result
    data = json.loads(lines[0])
    assert set(data.keys()) == {
        "artifact_id",
        "status",
        "signed",
        "content_object_id",
        "barcode_object_id",
        "created_at_unix_ms",
        "original_filename",
        "source",
        "record_version",
    }
    assert data["status"] == "new"
    assert data["source"] == "ocr"
    assert data["original_filename"] == "page.txt"
    assert data["record_version"] == "aletheia/ar/1"
    assert data["signed"] is False

    # Re-ingest identical content -> duplicate, same id.
    rc2 = _run_main(["--repo", str(repo), "ingest", str(f), "--json"], monkeypatch)
    data2 = _last_json(capsys.readouterr().out)
    assert rc2 == 0
    assert data2["status"] == "duplicate"
    assert data2["artifact_id"] == data["artifact_id"]


# --- ingest-dir --json ---


def test_ingest_dir_json_summary_and_idempotency(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("aletheia.ingest.OdinScanner", lambda *a, **k: _DummyScanner())
    src = tmp_path / "out"
    src.mkdir()
    (src / "p1.txt").write_text("one")
    (src / "p2.txt").write_text("two")
    (src / "skip.tmp").write_text("partial")  # excluded by default
    repo = tmp_path / "repo"

    rc = _run_main(
        ["--repo", str(repo), "ingest-dir", str(src), "--include", "*.txt", "--json"],
        monkeypatch,
    )
    data = _last_json(capsys.readouterr().out)
    assert rc == 0
    assert data["summary"] == {"total": 2, "ingested": 2, "duplicates": 0, "failed": 0}
    assert {r["file"] for r in data["results"]} == {str(src / "p1.txt"), str(src / "p2.txt")}
    assert data["errors"] == []

    rc2 = _run_main(
        ["--repo", str(repo), "ingest-dir", str(src), "--include", "*.txt", "--json"],
        monkeypatch,
    )
    data2 = _last_json(capsys.readouterr().out)
    assert rc2 == 0
    assert data2["summary"]["duplicates"] == 2
    assert data2["summary"]["ingested"] == 0


def test_ingest_dir_missing_directory_returns_user_error(tmp_path, monkeypatch, capsys):
    rc = _run_main(["--repo", str(tmp_path), "ingest-dir", str(tmp_path / "nope")], monkeypatch)
    capsys.readouterr()
    assert rc == 2
