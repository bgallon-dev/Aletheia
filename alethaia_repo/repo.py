#!/usr/bin/env python3
"""
Aletheia Repository CLI - Unified interface for all repository operations

Usage:
    repo ingest <file> [options]
    repo verify <artifact_id> --file <path> [options]
    repo show <artifact_id> [options]
    repo list [options]
    repo cleanup [options]
    repo rebuild [options]
    repo audit [options]
"""

import json
import sys
from datetime import datetime
from pathlib import Path

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
        if args[i] == '--repo' and i + 1 < len(args):
            repo_root = args[i + 1]
            i += 2
        elif args[i] == '--quiet':
            verbose = False
            i += 1
        else:
            remaining.append(args[i])
            i += 1
    
    return remaining, {'repo_root': repo_root, 'verbose': verbose}


def cmd_ingest(args: list) -> int:
    """Ingest command - now calls IngestPipeline directly."""
    if len(args) < 1:
        print("Usage: repo ingest <file> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print("  --window <bytes>     Window size (default: 65536)", file=sys.stderr)
        print("  --step <bytes>       Step size (default: 16384)", file=sys.stderr)
        print("  --m <1|2>            Block size (default: 1)", file=sys.stderr)
        print("  --threads <N>        Thread count (default: auto)", file=sys.stderr)
        print("  --repo <path>        Repository root (default: .)", file=sys.stderr)
        print("  --no-auto-init       Don't auto-initialize repository", file=sys.stderr)
        print("  --quiet              Suppress output", file=sys.stderr)
        print("  --keep-temp          Keep temporary .albc file", file=sys.stderr)
        return 2
    
    file_path = args[0]
    remaining, common = parse_common_args(args[1:])
    
    # Parse ingest-specific args
    kwargs = {
        'window_size': 65536,
        'step_size': 16384,
        'm': 1,
        'threads': 0,
        'verbose': common['verbose'],
        'keep_temp': False
    }
    auto_init = True
    
    i = 0
    while i < len(remaining):
        arg = remaining[i]
        if arg == '--window' and i + 1 < len(remaining):
            kwargs['window_size'] = int(remaining[i + 1])
            i += 2
        elif arg == '--step' and i + 1 < len(remaining):
            kwargs['step_size'] = int(remaining[i + 1])
            i += 2
        elif arg == '--m' and i + 1 < len(remaining):
            kwargs['m'] = int(remaining[i + 1])
            i += 2
        elif arg == '--threads' and i + 1 < len(remaining):
            kwargs['threads'] = int(remaining[i + 1])
            i += 2
        elif arg == '--no-auto-init':
            auto_init = False
            i += 1
        elif arg == '--keep-temp':
            kwargs['keep_temp'] = True
            i += 1
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            return 2
    
    try:
        pipeline = IngestPipeline(repo_root=common['repo_root'], auto_init=auto_init)
        artifact_id = pipeline.ingest(file_path, **kwargs)
        return 0
    except RepositoryNotInitializedError:
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common['verbose']:
            import traceback
            traceback.print_exc()
        return 1


def cmd_verify(args: list) -> int:
    """Verify command - now calls ArtifactVerifier directly."""
    if len(args) < 1:
        print("Usage: repo verify <artifact_id> --file <path> [options]", file=sys.stderr)
        print("\nOptions:", file=sys.stderr)
        print("  --repo <path>    Repository root (default: .)", file=sys.stderr)
        print("  --quiet          Suppress verbose output", file=sys.stderr)
        return 2
    
    artifact_id = args[0]
    remaining, common = parse_common_args(args[1:])
    
    file_path = None
    i = 0
    while i < len(remaining):
        if remaining[i] == '--file' and i + 1 < len(remaining):
            file_path = remaining[i + 1]
            i += 2
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2
    
    if not file_path:
        print("Error: --file <path> is required", file=sys.stderr)
        return 2
    
    try:
        verifier = ArtifactVerifier(repo_root=common['repo_root'])
        result = verifier.verify(artifact_id, file_path, verbose=common['verbose'])
        
        if common['verbose']:
            print()
        
        print(result.format_report(verbose=common['verbose']))
        
        return 0 if result.passed() else 1
        
    except RepositoryNotInitializedError:
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common['verbose']:
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
        repo = AletheiaRepository(common['repo_root'], auto_init=False)
        
        # Load artifact record
        record_path = repo.records_dir / f"{artifact_id}.json"
        if not record_path.exists():
            print(f"Error: Artifact not found: {artifact_id}", file=sys.stderr)
            return 1
        
        with open(record_path, 'r') as f:
            record = json.load(f)
        
        # Display record
        print(f"\n=== Artifact: {artifact_id} ===\n")
        
        print(f"Record Version: {record.get('record_version', 'unknown')}")
        print(f"Created At:     {format_timestamp(record.get('created_at_unix_ms', 0))}")
        print(f"Record Path:    {record_path.relative_to(repo.root)}")
        
        print(f"\nContent Object:  {record['content_object_id']}")
        print(f"Barcode Object:  {record.get('barcode_object_id', 'N/A')}")
        
        scan_params = record.get("scan_params", {})
        if scan_params:
            print(f"\nScan Parameters:")
            print(f"  Window Size:   {scan_params.get('window_size_bytes', 'N/A')} bytes")
            print(f"  Step Size:     {scan_params.get('step_size_bytes', 'N/A')} bytes")
            print(f"  Block Size:    m={scan_params.get('m_block_size', 'N/A')}")
            print(f"  Quantization:  {scan_params.get('quant_version', 'N/A')}")
            print(f"  Barcode Len:   {scan_params.get('barcode_len', 'N/A')} windows")
        
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
        if remaining[i] == '--limit' and i + 1 < len(remaining):
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
        repo = AletheiaRepository(common['repo_root'], auto_init=False)
        
        # Query artifacts ordered by creation time
        conn = repo._connect()
        conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT artifact_id, created_at_unix_ms, window_size_bytes, 
                   step_size_bytes, m_block_size, record_path
            FROM artifacts
            ORDER BY created_at_unix_ms DESC
            LIMIT ?
        """, (limit,))
        
        artifacts = cursor.fetchall()
        conn.close()
        
        if not artifacts:
            print("No artifacts found in repository.")
            return 0
        
        print(f"\n=== Recent Artifacts (showing {len(artifacts)}) ===\n")
        
        # Table header
        print(f"{'Artifact ID':<16}  {'Created':<19}  {'Scan Params':<20}  {'Record Path'}")
        print("-" * 100)
        
        for artifact in artifacts:
            artifact_id_short = artifact['artifact_id'][:14]
            created = format_timestamp(artifact['created_at_unix_ms'])
            
            ws = artifact.get('window_size_bytes')
            ss = artifact.get('step_size_bytes')
            m = artifact.get('m_block_size')
            
            if ws and ss and m:
                scan_params = f"WS={ws//1024}K SS={ss//1024}K m={m}"
            else:
                scan_params = "N/A"
            
            record_path = Path(artifact['record_path']).name if artifact['record_path'] else "N/A"
            
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
        if remaining[i] == '--max-age' and i + 1 < len(remaining):
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
        repo = AletheiaRepository(common['repo_root'], auto_init=False)
        deleted = repo.cleanup_tmp_directory(max_age_hours)
        
        print(f"Cleaned up {deleted} abandoned temp file(s) older than {max_age_hours}h")
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
        if remaining[i] == '--strict':
            continue_on_error = False
            i += 1
        elif remaining[i] == '--verify':
            verify_objects = True
            i += 1
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2
    
    try:
        repo = AletheiaRepository(common['repo_root'], auto_init=False)
        
        if common['verbose']:
            print("\n⚠️  WARNING: This will rebuild the entire index from scratch.")
            print("   This is a disaster recovery operation for when the database is lost.\n")
        
        stats = repo.rebuild_index(
            verbose=common['verbose'],
            continue_on_error=continue_on_error,
            verify_objects=verify_objects
        )
        
        # Return non-zero if there were broken artifacts
        if stats['broken'] > 0:
            return 1
        
        return 0
        
    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common['verbose']:
            import traceback
            traceback.print_exc()
        return 1


def cmd_audit(args: list) -> int:
    """Audit repository integrity (deep verification)."""
    remaining, common = parse_common_args(args)
    
    check_orphans = True
    i = 0
    while i < len(remaining):
        if remaining[i] == '--no-orphans':
            check_orphans = False
            i += 1
        else:
            print(f"Unknown argument: {remaining[i]}", file=sys.stderr)
            return 2
    
    try:
        repo = AletheiaRepository(common['repo_root'], auto_init=False)
        
        stats = repo.audit_objects(
            verbose=common['verbose'],
            check_orphans=check_orphans
        )
        
        # Return non-zero if there were integrity issues
        if len(stats['corrupted']) > 0 or len(stats['missing_files']) > 0:
            return 1
        
        return 0
        
    except RepositoryNotInitializedError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if common['verbose']:
            import traceback
            traceback.print_exc()
        return 1


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


def main():
    """Main CLI dispatcher."""
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(2)
    
    command = sys.argv[1]
    args = sys.argv[2:]
    
    commands = {
        'ingest': cmd_ingest,
        'verify': cmd_verify,
        'show': cmd_show,
        'list': cmd_list,
        'cleanup': cmd_cleanup,
        'rebuild': cmd_rebuild,
        'audit': cmd_audit,
        'help': lambda _: (print_usage(), 0)[1],
        '--help': lambda _: (print_usage(), 0)[1],
        '-h': lambda _: (print_usage(), 0)[1],
    }
    
    if command not in commands:
        print(f"Error: Unknown command: {command}", file=sys.stderr)
        print_usage()
        sys.exit(2)
    
    exit_code = commands[command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
