#!/usr/bin/env python3
"""
Aletheia Repository CLI - Unified interface for all repository operations

Usage:
    repo ingest <file> [options]
    repo verify <artifact_id> --file <path> [options]
    repo show <artifact_id> [options]
    repo list [options]
    repo diff <file1.albc> <file2.albc> [options]
    repo cleanup [options]
    repo rebuild [options]
    repo audit [options]
    repo identity <subcommand> [options]
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from repository import AletheiaRepository, RepositoryNotInitializedError
from ingest import IngestPipeline
from verify import ArtifactVerifier


def parse_common_args(args: list) -> tuple[list, dict]:
    """
    Extract common arguments (--repo, --quiet) from args.

    Returns:
        (remaining_args, common_opts) where common_opts = {'repo_root': str, 'verbose': bool}
    """
    remaining = []
    repo_root = "."
    verbose = True

    i = 0
    while i < len(args):
        if args[i] == "--repo" and i + 1 < len(args):
            repo_root = args[i + 1]
            i += 2
        elif args[i] == "--quiet":
            verbose = False
            i += 1
        else:
            remaining.append(args[i])
            i += 1

    return remaining, {"repo_root": repo_root, "verbose": verbose}


def cmd_ingest(args: list) -> int:
    """Ingest command - now calls IngestPipeline directly."""
    if len(args) < 1:
        print("Usage: repo ingest <file> [options]")
        print("Options:")
        print("  --window <size>      Window size (default: 65536)")
        print("  --step <size>        Step size (default: 16384)")
        print("  --m <size>           Block size (default: 1)")
        print("  --threads <n>        Thread count (default: auto)")
        print("  --format <version>   ALBC format: 1 (quantized) or 2 (quantized+raw)")
        print("  --sign <key_id>      Sign with identity key")
        print("  --passphrase         Prompt for signing passphrase")
        print("  --repo <path>        Repository root (default: .)")
        print("  --quiet              Suppress output")
        return 1

    file_path = args[0]
    remaining, common = parse_common_args(args[1:])

    # Parse ingest-specific args
    kwargs = {
        "window_size": 65536,
        "step_size": 16384,
        "m": 1,
        "threads": 0,
        "verbose": common["verbose"],
        "keep_temp": False,
        "sign_with": None,
        "passphrase": None,
        "output_format": 1,  # NEW: Default to v1
    }
    auto_init = True
    prompt_passphrase = False

    i = 0
    while i < len(remaining):
        arg = remaining[i]

        if arg == "--window" and i + 1 < len(remaining):
            kwargs["window_size"] = int(remaining[i + 1])
            i += 2
        elif arg == "--step" and i + 1 < len(remaining):
            kwargs["step_size"] = int(remaining[i + 1])
            i += 2
        elif arg == "--m" and i + 1 < len(remaining):
            kwargs["m"] = int(remaining[i + 1])
            i += 2
        elif arg == "--threads" and i + 1 < len(remaining):
            kwargs["threads"] = int(remaining[i + 1])
            i += 2
        elif arg == "--format" and i + 1 < len(remaining):  # NEW
            kwargs["output_format"] = int(remaining[i + 1])
            i += 2
        elif arg == "--sign" and i + 1 < len(remaining):
            kwargs["sign_with"] = remaining[i + 1]
            i += 2
        elif arg == "--passphrase":
            prompt_passphrase = True
            i += 1
        elif arg == "--keep-temp":
            kwargs["keep_temp"] = True
            i += 1
        elif arg == "--no-init":
            auto_init = False
            i += 1
        else:
            i += 1

    # NEW: Prompt for passphrase if requested
    if prompt_passphrase and kwargs["sign_with"]:
        import getpass

        kwargs["passphrase"] = getpass.getpass(
            f"Passphrase for key '{kwargs['sign_with']}': "
        )

    try:
        pipeline = IngestPipeline(repo_root=common["repo_root"], auto_init=auto_init)
        artifact_id = pipeline.ingest(file_path, **kwargs)
        return 0
    except RepositoryNotInitializedError:
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common["verbose"]:
            import traceback

            traceback.print_exc()
        return 1


def cmd_verify(args: list) -> int:
    """Verify command - now calls ArtifactVerifier directly."""
    if len(args) < 1:
        print(
            "Usage: repo verify <artifact_id> --file <path> [options]", file=sys.stderr
        )
        print("\nOptions:", file=sys.stderr)
        print("  --repo <path>    Repository root (default: .)", file=sys.stderr)
        print("  --quiet          Suppress verbose output", file=sys.stderr)
        return 2

    artifact_id = args[0]
    remaining, common = parse_common_args(args[1:])

    file_path = None
    i = 0
    while i < len(remaining):
        if remaining[i] == "--file" and i + 1 < len(remaining):
            file_path = remaining[i + 1]
            i += 2
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2

    if not file_path:
        print("Error: --file <path> is required", file=sys.stderr)
        return 2

    try:
        verifier = ArtifactVerifier(repo_root=common["repo_root"])
        result = verifier.verify(artifact_id, file_path, verbose=common["verbose"])

        if common["verbose"]:
            print()

        print(result.format_report(verbose=common["verbose"]))

        return 0 if result.passed() else 1

    except RepositoryNotInitializedError:
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common["verbose"]:
            import traceback

            traceback.print_exc()
        return 1


def cmd_show(args: list) -> int:
    """Show artifact details."""
    if len(args) < 1:
        print("Usage: repo show <artifact_id> [--repo <path>]", file=sys.stderr)
        return 2

    artifact_id = args[0]
    remaining, common = parse_common_args(args[1:])

    if remaining:
        print(f"Unknown argument: {remaining[0]}", file=sys.stderr)
        return 2

    try:
        repo = AletheiaRepository(common["repo_root"], auto_init=False)

        # Load artifact record
        record_path = repo.records_dir / f"{artifact_id}.json"
        if not record_path.exists():
            print(f"Error: Artifact not found: {artifact_id}", file=sys.stderr)
            return 1

        with open(record_path, "r") as f:
            record = json.load(f)

        # Display record
        print(f"\n=== Artifact: {artifact_id} ===\n")

        print(f"Record Version: {record.get('record_version', 'unknown')}")
        print(
            f"Created At:     {format_timestamp(record.get('created_at_unix_ms', 0))}"
        )
        print(f"Record Path:    {record_path.relative_to(repo.root)}")

        print(f"\nContent Object:  {record['content_object_id']}")
        print(f"Barcode Object:  {record.get('barcode_object_id', 'N/A')}")

        scan_params = record.get("scan_params", {})
        if scan_params:
            # Extract with legacy fallback (canonical keys use _bytes suffix)
            window_size = scan_params.get(
                "window_size_bytes", scan_params.get("window_size")
            )
            step_size = scan_params.get("step_size_bytes", scan_params.get("step_size"))
            m_block = scan_params.get("m_block_size")
            quant_ver = scan_params.get("quant_version")
            barcode_len = scan_params.get("barcode_len")
            format_ver = scan_params.get("format_version", 1)

            print(f"\nScan Parameters:")
            print(
                f"  Window Size:   {window_size} bytes"
                if window_size
                else "  Window Size:   N/A"
            )
            print(
                f"  Step Size:     {step_size} bytes"
                if step_size
                else "  Step Size:     N/A"
            )
            print(
                f"  Block Size:    m={m_block}" if m_block else "  Block Size:    N/A"
            )
            print(
                f"  Quantization:  {quant_ver}" if quant_ver else "  Quantization:  N/A"
            )
            print(
                f"  Barcode Len:   {barcode_len} windows"
                if barcode_len
                else "  Barcode Len:   N/A"
            )
            print(f"  Format:        ALBC v{format_ver}")

        metadata = record.get("metadata", {})
        if metadata:
            print(f"\nMetadata:")
            print(f"  Original File: {metadata.get('original_filename', 'N/A')}")
            print(f"  Ingested From: {metadata.get('ingested_from', 'N/A')}")
            print(f"  Chain:         {metadata.get('chain_of_custody', 'N/A')}")

        print()
        return 0

    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def cmd_list(args: list) -> int:
    """List recent artifacts."""
    remaining, common = parse_common_args(args)

    limit = 20
    i = 0
    while i < len(remaining):
        if remaining[i] == "--limit" and i + 1 < len(remaining):
            try:
                limit = int(remaining[i + 1])
            except ValueError:
                print(f"Error: Invalid limit: {remaining[i + 1]}", file=sys.stderr)
                return 2
            i += 2
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2

    try:
        repo = AletheiaRepository(common["repo_root"], auto_init=False)

        # Query artifacts ordered by creation time
        conn = repo._connect()
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT artifact_id, created_at_unix_ms, window_size_bytes, 
                   step_size_bytes, m_block_size, record_path
            FROM artifacts
            ORDER BY created_at_unix_ms DESC
            LIMIT ?
        """,
            (limit,),
        )

        artifacts = cursor.fetchall()
        conn.close()

        if not artifacts:
            print("No artifacts found in repository.")
            return 0

        print(f"\n=== Recent Artifacts (showing {len(artifacts)}) ===\n")

        # Table header
        print(
            f"{'Artifact ID':<16}  {'Created':<19}  {'Scan Params':<20}  {'Record Path'}"
        )
        print("-" * 100)

        for artifact in artifacts:
            artifact_id_short = artifact["artifact_id"][:14]
            created = format_timestamp(artifact["created_at_unix_ms"])

            ws = artifact.get("window_size_bytes")
            ss = artifact.get("step_size_bytes")
            m = artifact.get("m_block_size")

            if ws and ss and m:
                scan_params = f"WS={ws//1024}K SS={ss//1024}K m={m}"
            else:
                scan_params = "N/A"

            record_path = (
                Path(artifact["record_path"]).name if artifact["record_path"] else "N/A"
            )

            print(f"{artifact_id_short}..  {created}  {scan_params:<20}  {record_path}")

        print()
        return 0

    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


def cmd_cleanup(args: list) -> int:
    """Clean up abandoned temp files."""
    remaining, common = parse_common_args(args)

    max_age_hours = 24
    i = 0
    while i < len(remaining):
        if remaining[i] == "--max-age" and i + 1 < len(remaining):
            try:
                max_age_hours = int(remaining[i + 1])
            except ValueError:
                print(f"Error: Invalid max-age: {remaining[i + 1]}", file=sys.stderr)
                return 2
            i += 2
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2

    try:
        repo = AletheiaRepository(common["repo_root"], auto_init=False)
        deleted = repo.cleanup_tmp_directory(max_age_hours)

        print(
            f"Cleaned up {deleted} abandoned temp file(s) older than {max_age_hours}h"
        )
        return 0

    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_rebuild(args: list) -> int:
    """Rebuild index from filesystem (disaster recovery)."""
    remaining, common = parse_common_args(args)

    continue_on_error = True
    verify_objects = False
    i = 0
    while i < len(remaining):
        if remaining[i] == "--strict":
            continue_on_error = False
            i += 1
        elif remaining[i] == "--verify":
            verify_objects = True
            i += 1
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2

    try:
        repo = AletheiaRepository(common["repo_root"], auto_init=False)

        if common["verbose"]:
            print("\n⚠️  WARNING: This will rebuild the entire index from scratch.")
            print(
                "   This is a disaster recovery operation for when the database is lost.\n"
            )

        stats = repo.rebuild_index(
            verbose=common["verbose"],
            continue_on_error=continue_on_error,
            verify_objects=verify_objects,
        )

        # Return non-zero if there were broken artifacts
        if stats["broken"] > 0:
            return 1

        return 0

    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common["verbose"]:
            import traceback

            traceback.print_exc()
        return 1


def cmd_audit(args: list) -> int:
    """
    Comprehensive repository audit - generates forensic integrity report.

    Checks for:
    - Orphaned Objects: Files on disk not in database (junk data)
    - Missing Objects: Database entries with no file on disk (data loss)
    - Corrupted Objects: Files where hash != object_id (bit rot/tampering)
    """
    remaining, common = parse_common_args(args)

    check_orphans = True
    output_json = False
    output_file = None

    i = 0
    while i < len(remaining):
        if remaining[i] == "--no-orphans":
            check_orphans = False
            i += 1
        elif remaining[i] == "--json":
            output_json = True
            i += 1
        elif remaining[i] == "--output" and i + 1 < len(remaining):
            output_file = remaining[i + 1]
            i += 2
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            print("\nUsage: repo audit [options]", file=sys.stderr)
            print("\nOptions:", file=sys.stderr)
            print("  --no-orphans     Skip orphaned file check", file=sys.stderr)
            print("  --json           Output report as JSON", file=sys.stderr)
            print("  --output <file>  Write report to file", file=sys.stderr)
            print("  --repo <path>    Repository root (default: .)", file=sys.stderr)
            print("  --quiet          Suppress progress output", file=sys.stderr)
            return 2

    try:
        repo = AletheiaRepository(common["repo_root"], auto_init=False)

        # Run the audit
        start_time = time.time()
        stats = repo.audit_objects(
            verbose=common["verbose"], check_orphans=check_orphans
        )
        end_time = time.time()

        # Generate forensic report
        report = generate_forensic_report(
            repo=repo,
            stats=stats,
            duration=end_time - start_time,
            check_orphans=check_orphans,
        )

        # Output report
        if output_json:
            report_text = json.dumps(report, indent=2)
        else:
            report_text = format_forensic_report(report, verbose=common["verbose"])

        if output_file:
            Path(output_file).write_text(report_text)
            if common["verbose"]:
                print(f"\nReport written to: {output_file}")
        else:
            print(report_text)

        # Return non-zero if there were integrity issues
        has_issues = (
            len(stats.get("corrupted", [])) > 0
            or len(stats.get("missing_files", [])) > 0
        )
        return 1 if has_issues else 0

    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common["verbose"]:
            import traceback

            traceback.print_exc()
        return 1


def cmd_diff(args: list) -> int:
    """Compare two barcode files using Odin entropy diff."""
    if len(args) < 2:
        print("Usage: repo diff <file1.albc> <file2.albc> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print(
            "  --threshold <N>  Only report differences > threshold (default: 0)",
            file=sys.stderr,
        )
        print("  --json           Output results as JSON", file=sys.stderr)
        print("  --quiet          Suppress verbose output", file=sys.stderr)
        return 2

    file1_path = args[0]
    file2_path = args[1]
    remaining, common = parse_common_args(args[2:])

    threshold = 0.0
    json_output = False

    i = 0
    while i < len(remaining):
        if remaining[i] == "--threshold" and i + 1 < len(remaining):
            try:
                threshold = float(remaining[i + 1])
            except ValueError:
                print(f"Error: Invalid threshold: {remaining[i + 1]}", file=sys.stderr)
                return 2
            i += 2
        elif remaining[i] == "--json":
            json_output = True
            i += 1
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2

    # Validate files exist
    if not Path(file1_path).exists():
        print(f"Error: File not found: {file1_path}", file=sys.stderr)
        return 1
    if not Path(file2_path).exists():
        print(f"Error: File not found: {file2_path}", file=sys.stderr)
        return 1

    try:
        from ingest import OdinScanner

        scanner = OdinScanner()
        result = scanner.diff(file1_path, file2_path, threshold=threshold)

        if json_output:
            print(json.dumps(result, indent=2))
        else:
            # Human-readable output
            print(f"\n=== Barcode Comparison ===\n")
            print(f"File 1: {result.get('file1', file1_path)}")
            print(f"File 2: {result.get('file2', file2_path)}")
            print()
            print(f"Windows compared:  {result.get('windows_compared', 'N/A')}")
            print()

            avg_norm = result.get("avg_delta_normalized", 0) * 100
            rms_norm = result.get("rms_delta_normalized", 0) * 100
            max_norm = result.get("max_delta_normalized", 0) * 100

            print(
                f"Average ΔQ:        {result.get('avg_delta_raw', 0):.4f}  ({avg_norm:.2f}% of range)"
            )
            print(
                f"RMS ΔQ:            {result.get('rms_delta_raw', 0):.4f}  ({rms_norm:.2f}% of range)"
            )
            print(
                f"Max ΔQ:            {result.get('max_delta_raw', 0):.4f}  ({max_norm:.2f}% of range) at window {result.get('max_delta_window', 'N/A')}"
            )

            if threshold > 0:
                print()
                windows_above = result.get("windows_above_threshold", 0)
                total_windows = result.get("windows_compared", 1)
                pct = (windows_above / total_windows * 100) if total_windows > 0 else 0
                print(f"Windows > threshold: {windows_above} ({pct:.2f}%)")

            print()

        return 0

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common["verbose"]:
            import traceback

            traceback.print_exc()
        return 1


def generate_forensic_report(
    repo: AletheiaRepository,
    stats: Dict[str, Any],
    duration: float,
    check_orphans: bool,
) -> Dict[str, Any]:
    """Generate structured forensic report from audit stats."""

    # Determine overall status
    has_data_loss = len(stats.get("missing_files", [])) > 0
    has_corruption = len(stats.get("corrupted", [])) > 0
    has_orphans = len(stats.get("orphaned_files", [])) > 0

    if has_data_loss or has_corruption:
        status = "CRITICAL"
        status_message = "Data integrity compromised - immediate action required"
    elif has_orphans:
        status = "WARNING"
        status_message = "Orphaned files detected - cleanup recommended"
    else:
        status = "HEALTHY"
        status_message = "All objects verified successfully"

    # Calculate storage stats
    total_verified_bytes = 0
    orphaned_bytes = 0

    for obj_id in stats.get("orphaned_files", []):
        obj_path = repo._object_path(obj_id)
        if obj_path.exists():
            try:
                orphaned_bytes += obj_path.stat().st_size
            except OSError:
                pass

    # Build report structure
    report = {
        "report_type": "aletheia/forensic-audit/1",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "repository": str(repo.root.absolute()),
        "audit_duration_seconds": round(duration, 2),
        "status": {
            "code": status,
            "message": status_message,
            "healthy": status == "HEALTHY",
        },
        "summary": {
            "total_objects": stats.get("total_objects", 0),
            "verified_ok": stats.get("verified", 0),
            "missing_count": len(stats.get("missing_files", [])),
            "corrupted_count": len(stats.get("corrupted", [])),
            "orphaned_count": (
                len(stats.get("orphaned_files", [])) if check_orphans else "not_checked"
            ),
        },
        "missing_objects": {
            "description": "Database entries with no file on disk (DATA LOSS)",
            "severity": "CRITICAL",
            "count": len(stats.get("missing_files", [])),
            "objects": stats.get("missing_files", []),
        },
        "corrupted_objects": {
            "description": "Files where current hash does not match object_id (BIT ROT / TAMPERING)",
            "severity": "CRITICAL",
            "count": len(stats.get("corrupted", [])),
            "objects": stats.get("corrupted", []),
        },
        "orphaned_objects": {
            "description": "Files on disk not referenced in database (JUNK DATA)",
            "severity": "LOW",
            "count": (
                len(stats.get("orphaned_files", [])) if check_orphans else "not_checked"
            ),
            "wasted_bytes": orphaned_bytes if check_orphans else "not_checked",
            "objects": stats.get("orphaned_files", []) if check_orphans else [],
        },
        "recommendations": [],
    }

    # Generate recommendations
    if has_data_loss:
        report["recommendations"].append(
            {
                "priority": "CRITICAL",
                "action": "RESTORE_FROM_BACKUP",
                "description": f"{len(stats.get('missing_files', []))} object(s) are missing from disk. "
                "Restore from backup immediately or re-ingest original files.",
            }
        )

    if has_corruption:
        report["recommendations"].append(
            {
                "priority": "CRITICAL",
                "action": "INVESTIGATE_CORRUPTION",
                "description": f"{len(stats.get('corrupted', []))} object(s) have hash mismatches. "
                "This indicates bit rot, disk failure, or tampering. "
                "Investigate storage hardware and restore from backup.",
            }
        )

    if has_orphans and orphaned_bytes > 0:
        report["recommendations"].append(
            {
                "priority": "LOW",
                "action": "CLEANUP_ORPHANS",
                "description": f"{len(stats.get('orphaned_files', []))} orphaned file(s) "
                f"({format_bytes(orphaned_bytes)}) can be safely deleted. "
                "These files are not referenced by any artifact.",
            }
        )

    if not report["recommendations"]:
        report["recommendations"].append(
            {
                "priority": "INFO",
                "action": "NONE_REQUIRED",
                "description": "Repository is healthy. No action required.",
            }
        )

    return report


def format_forensic_report(report: Dict[str, Any], verbose: bool = True) -> str:
    """Format forensic report as human-readable text."""
    lines = []

    # Header
    lines.append("")
    lines.append("=" * 70)
    lines.append("              ALETHEIA FORENSIC INTEGRITY REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Repository:    {report['repository']}")
    lines.append(f"  Generated:     {report['generated_at']}")
    lines.append(f"  Duration:      {report['audit_duration_seconds']} seconds")
    lines.append("")

    # Status banner
    status = report["status"]
    if status["code"] == "CRITICAL":
        lines.append(
            "  ╔═══════════════════════════════════════════════════════════════╗"
        )
        lines.append(
            "  ║  ⚠️  STATUS: CRITICAL - DATA INTEGRITY COMPROMISED            ║"
        )
        lines.append(
            "  ╚═══════════════════════════════════════════════════════════════╝"
        )
    elif status["code"] == "WARNING":
        lines.append(
            "  ╔═══════════════════════════════════════════════════════════════╗"
        )
        lines.append(
            "  ║  ⚡ STATUS: WARNING - CLEANUP RECOMMENDED                     ║"
        )
        lines.append(
            "  ╚═══════════════════════════════════════════════════════════════╝"
        )
    else:
        lines.append(
            "  ╔═══════════════════════════════════════════════════════════════╗"
        )
        lines.append(
            "  ║  ✓  STATUS: HEALTHY - ALL OBJECTS VERIFIED                    ║"
        )
        lines.append(
            "  ╚═══════════════════════════════════════════════════════════════╝"
        )

    lines.append("")

    # Summary table
    lines.append("-" * 70)
    lines.append("  SUMMARY")
    lines.append("-" * 70)
    summary = report["summary"]
    lines.append(f"  Total Objects Indexed:    {summary['total_objects']:,}")
    lines.append(f"  Verified OK:              {summary['verified_ok']:,}")
    lines.append(f"  Missing (Data Loss):      {summary['missing_count']:,}")
    lines.append(f"  Corrupted (Bit Rot):      {summary['corrupted_count']:,}")
    orphan_count = summary["orphaned_count"]
    if orphan_count == "not_checked":
        lines.append(f"  Orphaned (Junk):          [not checked]")
    else:
        lines.append(f"  Orphaned (Junk):          {orphan_count:,}")
    lines.append("")

    # Missing Objects Section
    missing = report["missing_objects"]
    if missing["count"] > 0:
        lines.append("-" * 70)
        lines.append("  🔴 MISSING OBJECTS (DATA LOSS)")
        lines.append("-" * 70)
        lines.append(f"  Severity:    {missing['severity']}")
        lines.append(f"  Description: {missing['description']}")
        lines.append(f"  Count:       {missing['count']}")
        lines.append("")
        if verbose:
            lines.append("  Affected Object IDs:")
            for obj_id in missing["objects"][:20]:
                lines.append(f"    • {obj_id}")
            if len(missing["objects"]) > 20:
                lines.append(f"    ... and {len(missing['objects']) - 20} more")
        lines.append("")

    # Corrupted Objects Section
    corrupted = report["corrupted_objects"]
    if corrupted["count"] > 0:
        lines.append("-" * 70)
        lines.append("  🔴 CORRUPTED OBJECTS (INTEGRITY FAILURE)")
        lines.append("-" * 70)
        lines.append(f"  Severity:    {corrupted['severity']}")
        lines.append(f"  Description: {corrupted['description']}")
        lines.append(f"  Count:       {corrupted['count']}")
        lines.append("")
        if verbose:
            lines.append("  Affected Objects:")
            for obj in corrupted["objects"][:20]:
                if isinstance(obj, dict):
                    lines.append(f"    • {obj.get('object_id', 'unknown')[:48]}...")
                    lines.append(f"      Reason: {obj.get('reason', 'unknown')}")
                else:
                    lines.append(f"    • {obj}")
            if len(corrupted["objects"]) > 20:
                lines.append(f"    ... and {len(corrupted['objects']) - 20} more")
        lines.append("")

    # Orphaned Objects Section
    orphaned = report["orphaned_objects"]
    if orphaned["count"] != "not_checked" and orphaned["count"] > 0:
        lines.append("-" * 70)
        lines.append("  🟡 ORPHANED OBJECTS (JUNK DATA)")
        lines.append("-" * 70)
        lines.append(f"  Severity:    {orphaned['severity']}")
        lines.append(f"  Description: {orphaned['description']}")
        lines.append(f"  Count:       {orphaned['count']}")
        wasted = orphaned.get("wasted_bytes", 0)
        if wasted and wasted != "not_checked":
            lines.append(f"  Wasted Space: {format_bytes(wasted)}")
        lines.append("")
        if verbose and orphaned["objects"]:
            lines.append("  Orphaned Object IDs:")
            for obj_id in orphaned["objects"][:20]:
                lines.append(f"    • {obj_id}")
            if len(orphaned["objects"]) > 20:
                lines.append(f"    ... and {len(orphaned['objects']) - 20} more")
        lines.append("")

    # Recommendations Section
    lines.append("-" * 70)
    lines.append("  RECOMMENDATIONS")
    lines.append("-" * 70)
    for rec in report["recommendations"]:
        priority_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "LOW": "🟡", "INFO": "🟢"}.get(
            rec["priority"], "⚪"
        )

        lines.append(f"  {priority_icon} [{rec['priority']}] {rec['action']}")
        lines.append(f"     {rec['description']}")
        lines.append("")

    # Footer
    lines.append("=" * 70)
    lines.append(f"  Report generated by Aletheia Forensic Audit")
    lines.append(f"  {report['generated_at']}")
    lines.append("=" * 70)
    lines.append("")

    return "\n".join(lines)


def format_bytes(byte_count: int) -> str:
    """Format byte count in human-readable form."""
    if byte_count < 1024:
        return f"{byte_count} bytes"
    elif byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    elif byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.1f} MB"
    else:
        return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def format_timestamp(unix_ms: int) -> str:
    """Format Unix milliseconds to readable timestamp."""
    if unix_ms == 0:
        return "N/A"
    try:
        dt = datetime.utcfromtimestamp(unix_ms / 1000)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return "Invalid"


def print_usage():
    """Print usage information."""
    print(__doc__)


def cmd_identity(args: list) -> int:
    """Identity management commands."""
    if len(args) < 1:
        print("Usage: repo identity <subcommand> [options]", file=sys.stderr)
        print("\nSubcommands:", file=sys.stderr)
        print("  generate <key_id>    Generate new signing key", file=sys.stderr)
        print("  list                 List available keys", file=sys.stderr)
        print(
            "  export <key_id>      Export public key for distribution", file=sys.stderr
        )
        print("  import <file>        Import a public key", file=sys.stderr)
        return 2

    subcommand = args[0]
    sub_args = args[1:]

    try:
        from identity import IdentityLink, CRYPTO_AVAILABLE

        if not CRYPTO_AVAILABLE:
            print("Error: cryptography library not installed.", file=sys.stderr)
            print("Install with: pip install cryptography", file=sys.stderr)
            return 1

        identity = IdentityLink()

        if subcommand == "generate":
            return _identity_generate(identity, sub_args)
        elif subcommand == "list":
            return _identity_list(identity, sub_args)
        elif subcommand == "export":
            return _identity_export(identity, sub_args)
        elif subcommand == "import":
            return _identity_import(identity, sub_args)
        else:
            print(f"Unknown subcommand: {subcommand}", file=sys.stderr)
            return 2

    except ImportError:
        print("Error: Identity module not available.", file=sys.stderr)
        return 1


def _identity_generate(identity, args: list) -> int:
    """Generate a new signing key."""
    if len(args) < 1:
        print("Usage: repo identity generate <key_id> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print("  --name <name>        Key owner name", file=sys.stderr)
        print("  --email <email>      Key owner email", file=sys.stderr)
        print("  --org <org>          Organization", file=sys.stderr)
        print(
            "  --passphrase         Prompt for encryption passphrase", file=sys.stderr
        )
        return 2

    key_id = args[0]
    metadata = {}
    use_passphrase = False

    i = 1
    while i < len(args):
        if args[i] == "--name" and i + 1 < len(args):
            metadata["name"] = args[i + 1]
            i += 2
        elif args[i] == "--email" and i + 1 < len(args):
            metadata["email"] = args[i + 1]
            i += 2
        elif args[i] == "--org" and i + 1 < len(args):
            metadata["organization"] = args[i + 1]
            i += 2
        elif args[i] == "--passphrase":
            use_passphrase = True
            i += 1
        else:
            print(f"Unknown argument: {args[i]}", file=sys.stderr)
            return 2

    passphrase = None
    if use_passphrase:
        import getpass

        passphrase = getpass.getpass("Enter passphrase for key encryption: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Error: Passphrases don't match", file=sys.stderr)
            return 1

    try:
        result = identity.generate_key(key_id, passphrase=passphrase, metadata=metadata)

        print(f"\n✓ Generated new signing key: {key_id}")
        print(f"  Fingerprint:   {result['fingerprint']}")
        print(f"  Private key:   {result['private_key_path']}")
        print(f"  Public key:    {result['public_key_path']}")
        print(f"\n⚠️  Keep your private key secure! Back it up safely.")
        print(f"   Share the public key with verifiers.")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _identity_list(identity, args: list) -> int:
    """List available keys."""
    keys = identity.list_keys()

    if not keys:
        print("No keys found.")
        print(f"\nKey directory: {identity.key_dir}")
        print("Generate a key with: repo identity generate <key_id>")
        return 0

    print(f"\n=== Available Signing Keys ===\n")
    print(f"{'Key ID':<30}  {'Fingerprint':<18}  {'Encrypted':<10}  {'Created'}")
    print("-" * 90)

    for key in keys:
        encrypted = "Yes" if key.get("encrypted") else "No"
        created = key.get("created_at", "N/A")[:10]
        print(
            f"{key['key_id']:<30}  {key['fingerprint']:<18}  {encrypted:<10}  {created}"
        )

    print(f"\nKey directory: {identity.key_dir}")
    return 0


def _identity_export(identity, args: list) -> int:
    """Export public key."""
    if len(args) < 1:
        print("Usage: repo identity export <key_id>", file=sys.stderr)
        return 2

    key_id = args[0]

    try:
        key_json = identity.export_public_key(key_id)
        print(key_json)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def _identity_import(identity, args: list) -> int:
    """Import public key."""
    if len(args) < 1:
        print("Usage: repo identity import <file>", file=sys.stderr)
        return 2

    file_path = args[0]

    try:
        key_json = Path(file_path).read_text()
        key_id = identity.import_public_key(key_json)
        print(f"✓ Imported public key: {key_id}")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


# Update the commands dict in main()
def main():
    """Main CLI dispatcher."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(2)

    command = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "ingest": cmd_ingest,
        "verify": cmd_verify,
        "show": cmd_show,
        "list": cmd_list,
        "cleanup": cmd_cleanup,
        "rebuild": cmd_rebuild,
        "audit": cmd_audit,
        "identity": cmd_identity,
        "diff": cmd_diff,  # NEW
        "help": lambda _: (print_usage(), 0)[1],
        "--help": lambda _: (print_usage(), 0)[1],
        "-h": lambda _: (print_usage(), 0)[1],
    }

    if command not in commands:
        print(f"Error: Unknown command: {command}", file=sys.stderr)
        print_usage()
        sys.exit(2)

    exit_code = commands[command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
