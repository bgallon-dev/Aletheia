"""Tests for default repository path (aletheia_repo) and auto-migration.

Plan coverage:
- Running init without --repo creates repo under ./aletheia_repo (not project root).
- Legacy root repo data is auto-migrated into ./aletheia_repo on default startup.
- Overwrite conflicts resolve with root/source content winning.
- Explicit --repo usage does NOT trigger auto-migration.
- Updated CLI help text reflects new default path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aletheia.store.repository import (
    AletheiaRepository,
    migrate_legacy_root_data,
)

# Directory containing the aletheia package (so subprocess tests can find it).
_PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Python API: default constructor path
# ---------------------------------------------------------------------------


def test_repository_default_is_aletheia_repo(tmp_path):
    """AletheiaRepository() without arguments defaults to aletheia_repo."""
    import os

    orig = os.getcwd()
    try:
        os.chdir(tmp_path)
        repo = AletheiaRepository(auto_init=True)
        assert repo.root == Path("aletheia_repo")
        assert (tmp_path / "aletheia_repo" / "config.json").exists()
        assert (tmp_path / "aletheia_repo" / "objects").exists()
        assert (tmp_path / "aletheia_repo" / "records").exists()
        assert (tmp_path / "aletheia_repo" / "tmp").exists()
    finally:
        os.chdir(orig)


# ---------------------------------------------------------------------------
# migrate_legacy_root_data unit tests
# ---------------------------------------------------------------------------


def _make_legacy_root(base: Path) -> Path:
    """Create a minimal legacy repo layout at *base*."""
    obj_name = "a" * 64
    (base / "objects" / "ab").mkdir(parents=True)
    (base / "objects" / "ab" / obj_name).write_bytes(b"object-content")
    (base / "records").mkdir(parents=True)
    (base / "records" / "artifact.json").write_text('{"record_version": "aletheia/ar/1"}')
    (base / "tmp").mkdir(parents=True)
    config = {"version": "aletheia/repo/1"}
    (base / "config.json").write_text(json.dumps(config))
    (base / "index.sqlite3").write_bytes(b"fakedb")
    return base


def test_migrate_moves_dirs_and_files(tmp_path):
    """migrate_legacy_root_data copies all expected items to dest."""
    root = tmp_path / "root"
    root.mkdir()
    dest = tmp_path / "aletheia_repo"
    _make_legacy_root(root)

    result = migrate_legacy_root_data(root, dest)

    assert result is True
    assert (dest / "config.json").exists()
    assert (dest / "index.sqlite3").exists()
    assert (dest / "objects" / "ab" / ("a" * 64)).exists()
    assert (dest / "records" / "artifact.json").exists()


def test_migrate_deletes_source_after_copy(tmp_path):
    """Source items are removed after successful copy."""
    root = tmp_path / "root"
    root.mkdir()
    dest = tmp_path / "aletheia_repo"
    _make_legacy_root(root)

    migrate_legacy_root_data(root, dest)

    assert not (root / "config.json").exists()
    assert not (root / "index.sqlite3").exists()
    assert not (root / "objects").exists()
    assert not (root / "records").exists()
    assert not (root / "tmp").exists()


def test_migrate_source_wins_on_conflict(tmp_path):
    """Source content overwrites existing destination content."""
    root = tmp_path / "root"
    root.mkdir()
    dest = tmp_path / "aletheia_repo"
    dest.mkdir()
    _make_legacy_root(root)

    # Pre-populate dest with stale content
    (dest / "config.json").write_text('{"version": "stale"}')

    migrate_legacy_root_data(root, dest)

    # Source version must win
    assert json.loads((dest / "config.json").read_text())["version"] == "aletheia/repo/1"


def test_migrate_no_legacy_marker_returns_false(tmp_path):
    """Returns False when no config.json exists in root (nothing to migrate)."""
    root = tmp_path / "root"
    root.mkdir()
    dest = tmp_path / "aletheia_repo"

    result = migrate_legacy_root_data(root, dest)

    assert result is False
    assert not dest.exists()


def test_migrate_idempotent_second_call_noop(tmp_path):
    """Second call after migration completes is a safe no-op (returns False)."""
    root = tmp_path / "root"
    root.mkdir()
    dest = tmp_path / "aletheia_repo"
    _make_legacy_root(root)

    migrate_legacy_root_data(root, dest)
    result2 = migrate_legacy_root_data(root, dest)

    assert result2 is False


def test_migrate_same_dir_noop(tmp_path):
    """Does not migrate when root and dest resolve to the same path."""
    result = migrate_legacy_root_data(tmp_path, tmp_path)
    assert result is False


# ---------------------------------------------------------------------------
# CLI integration tests (subprocess)
# ---------------------------------------------------------------------------


def _run(*args: str, cwd: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(_PROJECT_ROOT)}
    return subprocess.run(
        [sys.executable, "-m", "aletheia", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
    )


def test_cli_init_without_repo_creates_aletheia_repo(tmp_path):
    """aletheia init (no --repo) creates the repo under ./aletheia_repo."""
    result = _run("init", cwd=str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "aletheia_repo").is_dir()
    assert (tmp_path / "aletheia_repo" / "config.json").exists()
    # Should NOT create repo at project root level
    assert not (tmp_path / "config.json").exists()


def test_cli_init_with_explicit_repo_dot_uses_root(tmp_path):
    """aletheia --repo . init creates repo at the project root (legacy)."""
    result = _run("--repo", ".", "init", cwd=str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "config.json").exists()
    # Should NOT create aletheia_repo automatically
    assert not (tmp_path / "aletheia_repo").exists()


def test_cli_explicit_repo_does_not_trigger_migration(tmp_path):
    """Explicit --repo usage must not trigger auto-migration."""
    # Place legacy data at root
    (tmp_path / "config.json").write_text('{"version": "aletheia/repo/1"}')
    (tmp_path / "objects").mkdir()
    (tmp_path / "records").mkdir()
    (tmp_path / "tmp").mkdir()

    dest = tmp_path / "custom_repo"
    result = _run("--repo", str(dest), "init", cwd=str(tmp_path))
    assert result.returncode == 0

    # Legacy config.json at root must still be there (migration was NOT run)
    assert (tmp_path / "config.json").exists()


def test_cli_default_repo_auto_migrates_legacy_data(tmp_path):
    """Default startup migrates legacy root data into aletheia_repo."""
    # Create a valid legacy repo at the project root using the Python API.
    AletheiaRepository(str(tmp_path), auto_init=True)
    assert (tmp_path / "config.json").exists()

    # Run init with default repo — migration should fire then init aletheia_repo.
    result = _run("init", cwd=str(tmp_path))
    assert result.returncode == 0

    # Data should now be in aletheia_repo
    assert (tmp_path / "aletheia_repo" / "objects").exists()
    assert (tmp_path / "aletheia_repo" / "records").exists()
    assert (tmp_path / "aletheia_repo" / "config.json").exists()
    # Legacy items should be gone from root
    assert not (tmp_path / "config.json").exists()
    assert not (tmp_path / "objects").exists()


def test_cli_help_mentions_aletheia_repo(tmp_path):
    """--help output should mention aletheia_repo as the default."""
    result = _run("--help", cwd=str(tmp_path))
    assert result.returncode == 0
    assert "aletheia_repo" in result.stdout
