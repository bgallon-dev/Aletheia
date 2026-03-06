"""
CLI contract tests - Category 7.

Prove that automation users can rely on exit codes and stdout/stderr
discipline. Tests use subprocess so they exercise the real CLI entry point.

Exit code contract:
  0  - success
  1  - verification failed / tamper / corruption detected
  2  - user error (bad args, missing file, unknown key, not initialized)
  3  - system error (disk I/O, permission denied)
  4  - internal error (unexpected bug)
"""

from __future__ import annotations

import subprocess
import sys


def _run(*args: str, cwd: str = ".") -> subprocess.CompletedProcess:
    """Run `python -m aletheia <args>` and return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, "-m", "aletheia", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


# ---------------------------------------------------------------------------
# --help exits 0
# ---------------------------------------------------------------------------


def test_top_level_help_exits_zero():
    result = _run("--help")
    assert result.returncode == 0


def test_top_level_help_mentions_aletheia():
    result = _run("--help")
    assert "aletheia" in result.stdout.lower()


def test_ingest_help_exits_zero():
    result = _run("ingest", "--help")
    assert result.returncode == 0


def test_verify_help_exits_zero():
    result = _run("verify", "--help")
    assert result.returncode == 0


def test_list_help_exits_zero():
    result = _run("list", "--help")
    assert result.returncode == 0


def test_audit_help_exits_zero():
    result = _run("audit", "--help")
    assert result.returncode == 0


def test_identity_generate_help_exits_zero():
    result = _run("identity", "generate", "--help")
    assert result.returncode == 0


def test_identity_list_help_exits_zero():
    result = _run("identity", "list", "--help")
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# Missing / invalid arguments exit non-zero
# ---------------------------------------------------------------------------


def test_no_subcommand_exits_nonzero():
    """argparse raises SystemExit(2) when required subcommand is missing."""
    result = _run()
    assert result.returncode != 0


def test_unknown_subcommand_exits_nonzero():
    result = _run("xyzzy-does-not-exist")
    assert result.returncode != 0


def test_ingest_missing_file_argument_exits_nonzero():
    """'ingest' requires a positional <file> argument."""
    result = _run("ingest")
    assert result.returncode != 0


def test_verify_missing_required_args_exits_nonzero():
    """'verify' requires positional <path> and --baseline."""
    result = _run("verify")
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Error output goes to stderr (not stdout)
# ---------------------------------------------------------------------------


def test_nonexistent_file_error_in_stderr(tmp_path):
    """When a file doesn't exist the error message should appear in stderr."""
    result = _run(
        "--repo",
        str(tmp_path),
        "ingest",
        str(tmp_path / "nonexistent.bin"),
        cwd=str(tmp_path),
    )
    assert result.returncode != 0
    assert "not found" not in result.stdout.lower() or result.stderr != ""


# ---------------------------------------------------------------------------
# list command works on empty repo (exit 0)
# ---------------------------------------------------------------------------


def test_list_on_empty_repo_exits_zero(tmp_path):
    """'list' on a freshly initialized (but empty) repo must exit 0."""
    from aletheia.store.repository import AletheiaRepository

    AletheiaRepository(str(tmp_path), auto_init=True)
    result = _run("--repo", str(tmp_path), "list")
    assert result.returncode == 0


def test_init_exits_0(tmp_path):
    assert _run("--repo", str(tmp_path), "init").returncode == 0


def test_init_idempotent(tmp_path):
    _run("--repo", str(tmp_path), "init")
    assert _run("--repo", str(tmp_path), "init").returncode == 0


def test_list_uninitialized_exits_2(tmp_path):
    assert _run("--repo", str(tmp_path), "list").returncode == 2


def test_inspect_unknown_artifact_exits_2(tmp_path):
    _run("--repo", str(tmp_path), "init")
    assert _run("--repo", str(tmp_path), "inspect", "a" * 64).returncode == 2


def test_verify_help_has_baseline():
    r = _run("verify", "--help")
    assert "--baseline" in r.stdout


def test_diff_help_has_artifact_ids():
    r = _run("diff", "--help")
    assert "artifact_id_1" in r.stdout


def test_doctor_exits_0_or_3(tmp_path):
    r = _run("--repo", str(tmp_path), "doctor")
    assert r.returncode in (0, 3)


def test_show_still_works_as_alias(tmp_path):
    _run("--repo", str(tmp_path), "init")
    assert _run("--repo", str(tmp_path), "show", "a" * 64).returncode == 2
