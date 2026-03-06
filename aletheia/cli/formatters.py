"""CLI report formatting utilities."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

from ..store.repository import AletheiaRepository


def generate_forensic_report(
    repo: AletheiaRepository,
    stats: Dict[str, Any],
    duration: float,
    check_orphans: bool,
) -> Dict[str, Any]:
    """Generate structured forensic report from audit stats."""
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

    orphaned_bytes = 0
    for obj_id in stats.get("orphaned_files", []):
        obj_path = repo._object_path(obj_id)
        if obj_path.exists():
            try:
                orphaned_bytes += obj_path.stat().st_size
            except OSError:
                pass

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
            "description": "File hash does not match content-address (INTEGRITY FAILURE)",
            "severity": "CRITICAL",
            "count": len(stats.get("corrupted", [])),
            "objects": stats.get("corrupted", []),
        },
        "orphaned_objects": {
            "description": "Files on disk not referenced by any database row",
            "severity": "LOW",
            "count": len(stats.get("orphaned_files", [])) if check_orphans else "not_checked",
            "wasted_bytes": orphaned_bytes if check_orphans else "not_checked",
            "objects": stats.get("orphaned_files", []) if check_orphans else [],
        },
        "recommendations": [],
    }

    if has_data_loss:
        report["recommendations"].append(
            {
                "priority": "CRITICAL",
                "action": "RESTORE_FROM_BACKUP",
                "description": (
                    f"{len(stats.get('missing_files', []))} object(s) are missing from disk. "
                    "Restore from backup immediately or re-ingest original files."
                ),
            }
        )

    if has_corruption:
        report["recommendations"].append(
            {
                "priority": "CRITICAL",
                "action": "INVESTIGATE_CORRUPTION",
                "description": (
                    f"{len(stats.get('corrupted', []))} object(s) have hash mismatches. "
                    "This indicates bit rot, disk failure, or tampering."
                ),
            }
        )

    if has_orphans and orphaned_bytes > 0:
        report["recommendations"].append(
            {
                "priority": "LOW",
                "action": "CLEANUP_ORPHANS",
                "description": (
                    f"{len(stats.get('orphaned_files', []))} orphaned file(s) "
                    f"({format_bytes(orphaned_bytes)}) can be safely deleted."
                ),
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
    lines.append("")
    lines.append("=" * 70)
    lines.append("ALETHEIA FORENSIC INTEGRITY REPORT")
    lines.append("=" * 70)
    lines.append(f"Repository: {report['repository']}")
    lines.append(f"Generated:  {report['generated_at']}")
    lines.append(f"Duration:   {report['audit_duration_seconds']} seconds")
    lines.append("")
    lines.append(f"Status: {report['status']['code']} - {report['status']['message']}")
    lines.append("")

    summary = report["summary"]
    lines.append("Summary")
    lines.append("-" * 70)
    lines.append(f"Total Objects Indexed: {summary['total_objects']:,}")
    lines.append(f"Verified OK:           {summary['verified_ok']:,}")
    lines.append(f"Missing (Data Loss):   {summary['missing_count']:,}")
    lines.append(f"Corrupted (Bit Rot):   {summary['corrupted_count']:,}")
    orphan_count = summary["orphaned_count"]
    if orphan_count == "not_checked":
        lines.append("Orphaned (Junk):       [not checked]")
    else:
        lines.append(f"Orphaned (Junk):       {orphan_count:,}")
    lines.append("")

    missing = report["missing_objects"]
    if missing["count"] > 0:
        lines.append("Missing Objects (DATA LOSS)")
        lines.append("-" * 70)
        lines.append(f"Count: {missing['count']}")
        if verbose:
            for obj_id in missing["objects"][:20]:
                lines.append(f"  - {obj_id}")
            if len(missing["objects"]) > 20:
                lines.append(f"  ... and {len(missing['objects']) - 20} more")
        lines.append("")

    corrupted = report["corrupted_objects"]
    if corrupted["count"] > 0:
        lines.append("Corrupted Objects (INTEGRITY FAILURE)")
        lines.append("-" * 70)
        lines.append(f"Count: {corrupted['count']}")
        if verbose:
            for obj in corrupted["objects"][:20]:
                if isinstance(obj, dict):
                    lines.append(f"  - {obj.get('object_id', 'unknown')}")
                    lines.append(f"    reason: {obj.get('reason', 'unknown')}")
                else:
                    lines.append(f"  - {obj}")
            if len(corrupted["objects"]) > 20:
                lines.append(f"  ... and {len(corrupted['objects']) - 20} more")
        lines.append("")

    orphaned = report["orphaned_objects"]
    if orphaned["count"] != "not_checked" and orphaned["count"] > 0:
        lines.append("Orphaned Objects (JUNK DATA)")
        lines.append("-" * 70)
        lines.append(f"Count: {orphaned['count']}")
        wasted = orphaned.get("wasted_bytes", 0)
        if wasted and wasted != "not_checked":
            lines.append(f"Wasted Space: {format_bytes(wasted)}")
        if verbose:
            for obj_id in orphaned["objects"][:20]:
                lines.append(f"  - {obj_id}")
            if len(orphaned["objects"]) > 20:
                lines.append(f"  ... and {len(orphaned['objects']) - 20} more")
        lines.append("")

    lines.append("Recommendations")
    lines.append("-" * 70)
    for rec in report["recommendations"]:
        lines.append(f"[{rec['priority']}] {rec['action']}")
        lines.append(f"  {rec['description']}")
        lines.append("")

    return "\n".join(lines)


def format_bytes(byte_count: int) -> str:
    """Format byte count in human-readable form."""
    if byte_count < 1024:
        return f"{byte_count} bytes"
    if byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    if byte_count < 1024 * 1024 * 1024:
        return f"{byte_count / (1024 * 1024):.1f} MB"
    return f"{byte_count / (1024 * 1024 * 1024):.2f} GB"


def format_timestamp(unix_ms: int) -> str:
    """Format Unix milliseconds to readable timestamp."""
    if unix_ms == 0:
        return "N/A"
    try:
        dt = datetime.utcfromtimestamp(unix_ms / 1000)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "Invalid"
