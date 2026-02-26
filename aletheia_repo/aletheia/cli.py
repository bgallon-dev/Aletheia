#!/usr/bin/env python3
"""
Aletheia Repository CLI - Unified interface for all repository operations
"""

import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
import logging
import functools
import argparse

from .domain import ArtifactRecord, SchemaValidationError
from .repository import AletheiaRepository, RepositoryNotInitializedError
from .ingest import IngestPipeline
from .verify import ArtifactVerifier


def setup_logging(verbose: bool = True, debug: bool = False):
    """Configure logging level based on verbosity flags."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


logger = logging.getLogger(__name__)


# =============================================================================
# SIMPLIFIED DECORATOR - Only handles exceptions, not argument parsing
# =============================================================================

def command_handler(func):
    """Decorator that handles exception catching for all commands."""
    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        try:
            return func(args)
        except RepositoryNotInitializedError as e:
            logger.error(f"Repository not initialized: {e}")
            return 1
        except Exception as e:
            logger.error(f"{e}")
            if getattr(args, 'debug', False):
                import traceback
                traceback.print_exc()
            return 1
    return wrapper


# =============================================================================
# COMMAND IMPLEMENTATIONS - Each receives parsed argparse.Namespace
# =============================================================================

@command_handler
def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest a file into the repository."""
    
    # Handle passphrase prompt if requested
    passphrase = None
    if args.passphrase and args.sign:
        import getpass
        passphrase = getpass.getpass("Enter passphrase for signing key: ")
    
    pipeline = IngestPipeline(repo_root=args.repo, auto_init=not args.no_auto_init)
    artifact_id = pipeline.ingest(
        file_path=args.file,
        window_size=args.window,
        step_size=args.step,
        m=args.m,
        threads=args.threads,
        verbose=not args.quiet,
        keep_temp=args.keep_temp,
        sign_with=args.sign,
        passphrase=passphrase,
        output_format=args.format,
    )
    
    if not args.quiet:
        print(f"\n✓ Ingested: {artifact_id}")
    return 0


@command_handler
def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a file against its artifact record."""
    verifier = ArtifactVerifier(repo_root=args.repo)
    result = verifier.verify(
        args.artifact_id,
        args.file,
        verbose=not args.quiet,
        enable_zoom=not args.no_zoom,
        require_signature=args.require_signature,
    )
    
    if not args.quiet:
        print()
    print(result.format_report(verbose=not args.quiet))
    
    return 0 if result.passed() else 1


@command_handler
def cmd_list(args: argparse.Namespace) -> int:
    """List recent artifacts."""
    repo = AletheiaRepository(args.repo, auto_init=False)
    artifacts = repo.get_recent_artifacts(limit=args.limit)
    
    if not artifacts:
        print("No artifacts found in repository.")
        return 0
    
    print(f"\n=== Recent Artifacts (showing {len(artifacts)}) ===\n")
    print(f"{'Artifact ID':<16}  {'Created':<19}  {'Scan Params':<20}  {'Record Path'}")
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
        
        record_path = Path(artifact["record_path"]).name if artifact["record_path"] else "N/A"
        print(f"{artifact_id_short}..  {created}  {scan_params:<20}  {record_path}")
    
    print()
    return 0


@command_handler
def cmd_show(args: argparse.Namespace) -> int:
    """Show artifact details."""
    repo = AletheiaRepository(args.repo, auto_init=False)

    # Load artifact record
    record_path = repo.records_dir / f"{args.artifact_id}.json"
    if not record_path.exists():
        print(f"Error: Artifact not found: {args.artifact_id}", file=sys.stderr)
        return 1

    with open(record_path, "r") as f:
        raw_record = json.load(f)
    try:
        record = ArtifactRecord.from_dict(raw_record)
    except SchemaValidationError as e:
        print(f"Error: Invalid artifact record schema: {e}", file=sys.stderr)
        return 1

    # Display record
    print(f"\n=== Artifact: {args.artifact_id} ===\n")

    print(f"Record Version: {record.record_version}")
    print(f"Created At:     {format_timestamp(record.created_at_unix_ms)}")
    print(f"Record Path:    {record_path.relative_to(repo.root)}")

    print(f"\nContent Object:  {record.content_object_id}")
    print(f"Barcode Object:  {record.barcode_object_id}")

    scan_params = record.scan_params
    print(f"\nScan Parameters:")
    print(f"  Window Size:   {scan_params.window_size_bytes} bytes")
    print(f"  Step Size:     {scan_params.step_size_bytes} bytes")
    print(f"  Block Size:    m={scan_params.m_block_size}")
    print(f"  Quantization:  {scan_params.quant_version}")
    print(f"  Barcode Len:   {scan_params.barcode_len} windows")
    print(f"  Format:        ALBC v{scan_params.format_version}")

    metadata = record.metadata
    if metadata:
        print(f"\nMetadata:")
        print(f"  Original File: {metadata.get('original_filename', 'N/A')}")
        print(f"  Ingested From: {metadata.get('ingested_from', 'N/A')}")
        print(f"  Chain:         {metadata.get('chain_of_custody', 'N/A')}")

    print()
    return 0


@command_handler
def cmd_cleanup(args: argparse.Namespace) -> int:
    """Clean up abandoned temp files."""
    repo = AletheiaRepository(args.repo, auto_init=False)
    deleted = repo.cleanup_tmp_directory(args.max_age)

    if not args.quiet:
        print(f"Cleaned up {deleted} abandoned temp file(s) older than {args.max_age}h")
    return 0


@command_handler
def cmd_rebuild(args: argparse.Namespace) -> int:
    """Rebuild index from filesystem (disaster recovery)."""
    repo = AletheiaRepository(args.repo, auto_init=False)

    if not args.quiet:
        print("\n⚠️  WARNING: This will rebuild the entire index from scratch.")
        print("   This is a disaster recovery operation for when the database is lost.\n")

    stats = repo.rebuild_index(
        verbose=not args.quiet,
        continue_on_error=not args.strict,
        verify_objects=args.verify,
    )

    # Return non-zero if there were broken artifacts
    if stats["broken"] > 0:
        return 1

    return 0


@command_handler
def cmd_audit(args: argparse.Namespace) -> int:
    """
    Comprehensive repository audit - generates forensic integrity report.

    Checks for:
    - Orphaned Objects: Files on disk not in database (junk data)
    - Missing Objects: Database entries with no file on disk (data loss)
    - Corrupted Objects: Files where hash != object_id (bit rot/tampering)
    """
    repo = AletheiaRepository(args.repo, auto_init=False)

    # Run the audit
    check_orphans = not args.no_orphans
    start_time = time.time()
    stats = repo.audit_objects(verbose=not args.quiet, check_orphans=check_orphans)
    end_time = time.time()

    # Generate forensic report
    report = generate_forensic_report(
        repo=repo,
        stats=stats,
        duration=end_time - start_time,
        check_orphans=check_orphans,
    )

    # Output report
    if args.json:
        report_text = json.dumps(report, indent=2)
    else:
        report_text = format_forensic_report(report, verbose=not args.quiet)

    if args.output:
        Path(args.output).write_text(report_text)
        if not args.quiet:
            print(f"\nReport written to: {args.output}")
    else:
        print(report_text)

    # Return non-zero if there were integrity issues
    has_issues = (
        len(stats.get("corrupted", [])) > 0
        or len(stats.get("missing_files", [])) > 0
    )
    return 1 if has_issues else 0


@command_handler
def cmd_diff(args: argparse.Namespace) -> int:
    """Compare two barcode files using Odin entropy diff."""
    # Validate files exist
    if not Path(args.file1).exists():
        print(f"Error: File not found: {args.file1}", file=sys.stderr)
        return 1
    if not Path(args.file2).exists():
        print(f"Error: File not found: {args.file2}", file=sys.stderr)
        return 1

    from .ingest import OdinScanner

    scanner = OdinScanner(require_binary=False)
    result = scanner.diff(args.file1, args.file2, threshold=args.threshold)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # Human-readable output
        print(f"\n=== Barcode Comparison ===\n")
        print(f"File 1: {result.get('file1', args.file1)}")
        print(f"File 2: {result.get('file2', args.file2)}")
        print()
        print(f"Windows compared:  {result.get('windows_compared', 'N/A')}")
        print()

        avg_norm = result.get("avg_delta_normalized", 0) * 100
        rms_norm = result.get("rms_delta_normalized", 0) * 100
        max_norm = result.get("max_delta_normalized", 0) * 100

        print(f"Average ΔQ:        {result.get('avg_delta_raw', 0):.4f}  ({avg_norm:.2f}% of range)")
        print(f"RMS ΔQ:            {result.get('rms_delta_raw', 0):.4f}  ({rms_norm:.2f}% of range)")
        print(f"Max ΔQ:            {result.get('max_delta_raw', 0):.4f}  ({max_norm:.2f}% of range) at window {result.get('max_delta_window', 'N/A')}")

        if args.threshold > 0:
            print()
            windows_above = result.get("windows_above_threshold", 0)
            total_windows = result.get("windows_compared", 1)
            pct = (windows_above / total_windows * 100) if total_windows > 0 else 0
            print(f"Windows > threshold: {windows_above} ({pct:.2f}%)")

        print()

    return 0


# =============================================================================
# IDENTITY COMMANDS - Each subcommand has its own decorated handler
# =============================================================================

def _get_identity():
    """Helper to get IdentityLink instance with proper error handling."""
    from .identity import IdentityLink, CRYPTO_AVAILABLE

    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography library not installed. Install with: pip install cryptography"
        )
    return IdentityLink()


@command_handler
def cmd_identity_generate(args: argparse.Namespace) -> int:
    """Generate a new signing key."""
    identity = _get_identity()
    
    metadata = {}
    if args.name:
        metadata["name"] = args.name
    if args.email:
        metadata["email"] = args.email
    if args.org:
        metadata["organization"] = args.org

    passphrase = None
    if args.use_passphrase:
        import getpass
        passphrase = getpass.getpass("Enter passphrase for key encryption: ")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            print("Error: Passphrases don't match", file=sys.stderr)
            return 1

    result = identity.generate_key(args.key_id, passphrase=passphrase, metadata=metadata)

    print(f"\n✓ Generated new signing key: {args.key_id}")
    print(f"  Fingerprint:   {result['fingerprint']}")
    print(f"  Private key:   {result['private_key_path']}")
    print(f"  Public key:    {result['public_key_path']}")
    if not args.use_passphrase:
        print("\n⚠️  Key stored without passphrase encryption (--no-passphrase).")
    print(f"\n⚠️  Keep your private key secure! Back it up safely.")
    print(f"   Share the public key with verifiers.")
    return 0


@command_handler
def cmd_identity_list(args: argparse.Namespace) -> int:
    """List available keys."""
    identity = _get_identity()
    keys = identity.list_keys()

    if not keys:
        print("No keys found.")
        print(f"\nKey directory: {identity.key_dir}")
        print("Generate a key with: aletheia identity generate <key_id>")
        return 0

    print(f"\n=== Available Signing Keys ===\n")
    print(f"{'Key ID':<30}  {'Fingerprint':<18}  {'Encrypted':<10}  {'Created'}")
    print("-" * 90)

    for key in keys:
        encrypted = "Yes" if key.get("encrypted") else "No"
        created = key.get("created_at", "N/A")[:10]
        print(f"{key['key_id']:<30}  {key['fingerprint']:<18}  {encrypted:<10}  {created}")

    print(f"\nKey directory: {identity.key_dir}")
    return 0


@command_handler
def cmd_identity_export(args: argparse.Namespace) -> int:
    """Export public key."""
    identity = _get_identity()
    key_json = identity.export_public_key(args.key_id)
    print(key_json)
    return 0


@command_handler
def cmd_identity_import(args: argparse.Namespace) -> int:
    """Import public key."""
    identity = _get_identity()
    key_json = Path(args.file).read_text()
    key_id = identity.import_public_key(key_json)
    print(f"✓ Imported public key: {key_id}")
    return 0


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


# =============================================================================
# MAIN - Uses argparse subparsers for clean dispatch
# =============================================================================

def main():
    """Main CLI entry point using argparse subparsers."""
    
    # Top-level parser with global options
    parser = argparse.ArgumentParser(
        prog="aletheia",
        description="Aletheia Repository CLI - Content-addressed storage with forensic verification"
    )
    parser.add_argument("--repo", default=".", help="Repository root directory")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    parser.add_argument("--debug", action="store_true", help="Show full tracebacks on error")
    
    # Create subparsers - this replaces the manual dispatch dictionary
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")
    
    # --- ingest ---
    p_ingest = subparsers.add_parser("ingest", help="Ingest a file into the repository")
    p_ingest.add_argument("file", help="File to ingest")
    p_ingest.add_argument("--window", type=int, default=65536, help="Window size in bytes")
    p_ingest.add_argument("--step", type=int, default=16384, help="Step size in bytes")
    p_ingest.add_argument("--m", type=int, default=1, help="Block size for entropy calculation")
    p_ingest.add_argument("--threads", type=int, default=0, help="Thread count (0=auto)")
    p_ingest.add_argument("--format", type=int, choices=[1, 2], default=1, help="ALBC format version")
    p_ingest.add_argument("--keep-temp", action="store_true", help="Keep temporary .albc file")
    p_ingest.add_argument("--no-auto-init", action="store_true", help="Fail if repository is not initialized")
    p_ingest.add_argument("--sign", metavar="KEY_ID", help="Sign with this key ID")
    p_ingest.add_argument("--passphrase", action="store_true", help="Prompt for signing passphrase")
    p_ingest.set_defaults(func=cmd_ingest)
    
    # --- verify ---
    p_verify = subparsers.add_parser("verify", help="Verify a file against its artifact record")
    p_verify.add_argument("artifact_id", help="Artifact ID to verify against")
    p_verify.add_argument("--file", required=True, help="File to verify")
    p_verify.add_argument("--no-zoom", action="store_true", help="Disable zoom scan")
    p_verify.add_argument("--require-signature", action="store_true", help="Fail verification if signature is missing or invalid")
    p_verify.set_defaults(func=cmd_verify)
    
    # --- list ---
    p_list = subparsers.add_parser("list", help="List recent artifacts")
    p_list.add_argument("--limit", type=int, default=20, help="Max artifacts to show")
    p_list.set_defaults(func=cmd_list)
    
    # --- show ---
    p_show = subparsers.add_parser("show", help="Show artifact details")
    p_show.add_argument("artifact_id", help="Artifact ID to display")
    p_show.set_defaults(func=cmd_show)
    
    # --- audit ---
    p_audit = subparsers.add_parser("audit", help="Run forensic integrity audit")
    p_audit.add_argument("--no-orphans", action="store_true", help="Skip orphan check")
    p_audit.add_argument("--json", action="store_true", help="Output as JSON")
    p_audit.add_argument("--output", metavar="FILE", help="Write report to file")
    p_audit.set_defaults(func=cmd_audit)
    
    # --- cleanup ---
    p_cleanup = subparsers.add_parser("cleanup", help="Clean up abandoned temp files")
    p_cleanup.add_argument("--max-age", type=int, default=24, help="Max age in hours (default: 24)")
    p_cleanup.set_defaults(func=cmd_cleanup)
    
    # --- rebuild ---
    p_rebuild = subparsers.add_parser("rebuild", help="Rebuild index from filesystem (disaster recovery)")
    p_rebuild.add_argument("--strict", action="store_true", help="Stop on first error")
    p_rebuild.add_argument("--verify", action="store_true", help="Verify object hashes")
    p_rebuild.set_defaults(func=cmd_rebuild)
    
    # --- diff ---
    p_diff = subparsers.add_parser("diff", help="Compare two barcode files")
    p_diff.add_argument("file1", help="First barcode file (.albc)")
    p_diff.add_argument("file2", help="Second barcode file (.albc)")
    p_diff.add_argument("--threshold", type=float, default=0.0, help="Only report differences > threshold")
    p_diff.add_argument("--json", action="store_true", help="Output as JSON")
    p_diff.set_defaults(func=cmd_diff)
    
    # --- identity (with nested subcommands) ---
    p_identity = subparsers.add_parser("identity", help="Manage signing keys")
    identity_subs = p_identity.add_subparsers(dest="identity_command", required=True)
    
    # identity generate
    p_id_gen = identity_subs.add_parser("generate", help="Generate new signing key")
    p_id_gen.add_argument("key_id", help="Unique identifier for this key")
    p_id_gen.add_argument("--name", help="Key owner name")
    p_id_gen.add_argument("--email", help="Key owner email")
    p_id_gen.add_argument("--org", help="Organization")
    passphrase_group = p_id_gen.add_mutually_exclusive_group()
    passphrase_group.add_argument(
        "--passphrase",
        dest="use_passphrase",
        action="store_true",
        help="Prompt for encryption passphrase (default)",
    )
    passphrase_group.add_argument(
        "--no-passphrase",
        dest="use_passphrase",
        action="store_false",
        help="Store private key without encryption",
    )
    p_id_gen.set_defaults(use_passphrase=True)
    p_id_gen.set_defaults(func=cmd_identity_generate)
    
    # identity list
    p_id_list = identity_subs.add_parser("list", help="List available keys")
    p_id_list.set_defaults(func=cmd_identity_list)
    
    # identity export
    p_id_export = identity_subs.add_parser("export", help="Export public key")
    p_id_export.add_argument("key_id", help="Key ID to export")
    p_id_export.set_defaults(func=cmd_identity_export)
    
    # identity import
    p_id_import = identity_subs.add_parser("import", help="Import public key")
    p_id_import.add_argument("file", help="Path to public key JSON file")
    p_id_import.set_defaults(func=cmd_identity_import)
    
    # Parse and dispatch
    args = parser.parse_args()
    
    # Setup logging based on flags
    setup_logging(verbose=not args.quiet, debug=args.debug)
    
    # Call the command's function (set via set_defaults)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
