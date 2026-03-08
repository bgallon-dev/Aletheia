#!/usr/bin/env python3
"""
Aletheia Repository CLI - Unified interface for all repository operations.
"""

import argparse
import functools
import json
import logging
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

from ..domain import ArtifactRecord, SchemaValidationError
from ..ingest import ALBCParser, IngestPipeline, OdinScanner
from ..store.repository import (
    AletheiaRepository,
    BrokenArtifactError,
    ImmutabilityError,
    IntegrityError,
    ObjectNotFoundError,
    RepositoryError,
    RepositoryNotInitializedError,
)
from ..store.verify import ArtifactVerifier
from .formatters import (
    format_forensic_report,
    format_timestamp,
    generate_forensic_report,
)


EXIT_OK = 0  # success
EXIT_VERIFICATION_FAILED = 1  # tamper / corruption detected
EXIT_USER_ERROR = 2  # bad args, missing file, unknown key, not initialized
EXIT_SYSTEM_ERROR = 3  # disk I/O, permission denied
EXIT_INTERNAL_ERROR = 4  # unexpected / programming error


try:
    from ..store.identity import IdentityError, KeyNotFoundError, SignatureInvalidError

    _ID_TAMPER = (SignatureInvalidError,)  # exit 1
    _ID_USER = (IdentityError, KeyNotFoundError)  # exit 2
except ImportError:
    _ID_TAMPER = _ID_USER = ()  # type: ignore[assignment]


logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging level based on verbosity flags."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    fmt = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(level=level, format=fmt, datefmt=datefmt)


def command_handler(func):
    @functools.wraps(func)
    def wrapper(args: argparse.Namespace) -> int:
        try:
            return func(args)
        # --- exit 1: data integrity / tamper ---
        except (IntegrityError, BrokenArtifactError) as e:
            logger.error("%s", e)
            if getattr(args, "debug", False):
                traceback.print_exc()
            return EXIT_VERIFICATION_FAILED
        except _ID_TAMPER as e:  # type: ignore[misc]
            logger.error("Signature invalid: %s", e)
            return EXIT_VERIFICATION_FAILED
        # --- exit 2: user errors ---
        except RepositoryNotInitializedError as e:
            logger.error("Repository not initialized: %s", e)
            logger.error("Run 'aletheia init' to create a repository here.")
            return EXIT_USER_ERROR
        except (SchemaValidationError, ObjectNotFoundError, ImmutabilityError) as e:
            logger.error("%s", e)
            return EXIT_USER_ERROR
        except RepositoryError as e:
            logger.error("%s", e)
            return EXIT_USER_ERROR
        except (FileNotFoundError, ValueError) as e:
            logger.error("%s", e)
            return EXIT_USER_ERROR
        except _ID_USER as e:  # type: ignore[misc]
            logger.error("Identity error: %s", e)
            if getattr(args, "debug", False):
                traceback.print_exc()
            return EXIT_USER_ERROR
        # --- exit 3: system errors ---
        except PermissionError as e:
            logger.error("Permission denied: %s", e)
            return EXIT_SYSTEM_ERROR
        except OSError as e:
            logger.error("System I/O error: %s", e)
            if getattr(args, "debug", False):
                traceback.print_exc()
            return EXIT_SYSTEM_ERROR
        # --- exit 4: internal / unexpected ---
        except Exception as e:
            logger.error("Unexpected error: %s: %s", type(e).__name__, e)
            if getattr(args, "debug", False):
                traceback.print_exc()
            return EXIT_INTERNAL_ERROR

    return wrapper


@command_handler
def cmd_init(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).resolve()
    repo = AletheiaRepository(str(repo_path), auto_init=True)
    if args.verbose:
        print(f"Repository initialized at: {repo_path}")
        print(f"  Config:   {repo.config_path}")
        print(f"  Database: {repo.db_path}")
    else:
        print(f"Initialized: {repo_path}")
    return EXIT_OK


@command_handler
def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest a file into the repository."""
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
        verbose=args.verbose,
        keep_temp=args.keep_temp,
        sign_with=args.sign,
        passphrase=passphrase,
        output_format=args.format,
    )

    if args.verbose:
        print(f"\nIngested: {artifact_id}")
    return EXIT_OK


@command_handler
def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a file against its artifact record."""
    verifier = ArtifactVerifier(repo_root=args.repo)
    result = verifier.verify(
        args.baseline,
        args.path,
        verbose=args.verbose,
        enable_zoom=not args.no_zoom,
        require_signature=args.require_signature,
    )

    if args.verbose:
        print()
    report = result.format_report(verbose=args.verbose)
    try:
        print(report)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(
            report.encode(encoding, errors="replace").decode(encoding, errors="replace")
        )

    if result.error:
        lowered = result.error.lower()
        if (
            "not found" in lowered
            or "invalid artifact record schema" in lowered
            or "failed to load artifact record" in lowered
        ):
            return EXIT_USER_ERROR

    return EXIT_OK if result.passed() else EXIT_VERIFICATION_FAILED


@command_handler
def cmd_list(args: argparse.Namespace) -> int:
    """List recent artifacts."""
    repo = AletheiaRepository(args.repo, auto_init=False)
    artifacts = repo.get_recent_artifacts(limit=args.limit)

    if not artifacts:
        print("No artifacts found in repository.")
        return EXIT_OK

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

        record_path = (
            Path(artifact["record_path"]).name if artifact["record_path"] else "N/A"
        )
        print(f"{artifact_id_short}..  {created}  {scan_params:<20}  {record_path}")

    print()
    return EXIT_OK


@command_handler
def cmd_inspect(args: argparse.Namespace) -> int:
    repo = AletheiaRepository(args.repo, auto_init=False)
    record_path = repo.records_dir / f"{args.artifact_id}.json"
    if not record_path.exists():
        logger.error("Artifact not found: %s", args.artifact_id)
        return EXIT_USER_ERROR

    with open(record_path, "r") as f:
        raw = json.load(f)
    record = ArtifactRecord.from_dict(raw)
    ts = datetime.fromtimestamp(record.created_at_unix_ms / 1000).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    sp = record.scan_params
    print(f"\n=== Artifact: {args.artifact_id} ===\n")
    print(f"Record Version:  {record.record_version}")
    print(f"Created At:      {ts}")
    print(f"\nContent Object:  {record.content_object_id}")
    print(f"Barcode Object:  {record.barcode_object_id}")
    print(f"\nScan Parameters:")
    print(f"  Window Size:   {sp.window_size_bytes} bytes")
    print(f"  Step Size:     {sp.step_size_bytes} bytes")
    print(f"  Block Size:    m={sp.m_block_size}")
    print(f"  Quantization:  {sp.quant_version}")
    print(f"  Barcode Len:   {sp.barcode_len} windows")
    print(f"  Format:        ALBC v{sp.format_version}")
    print(f"  Algorithm:     {sp.algo_version}")

    meta = record.metadata or {}
    print(f"\nMetadata:")
    print(f"  Original File: {meta.get('original_filename', 'N/A')}")
    print(f"  Ingested From: {meta.get('ingested_from', 'N/A')}")

    print(f"\nIdentity Link:")
    if record.identity_link:
        sig = record.identity_link
        print(f"  Status:      SIGNED")
        print(f"  Key ID:      {sig.key_id}")
        print(f"  Fingerprint: {sig.fingerprint}")
        print(f"  Signed At:   {sig.signed_at}")
    else:
        print(f"  Status:      UNSIGNED")
    print()
    return EXIT_OK


@command_handler
def cmd_export(args: argparse.Namespace) -> int:
    repo = AletheiaRepository(args.repo, auto_init=False)
    record_path = repo.records_dir / f"{args.artifact_id}.json"
    if not record_path.exists():
        logger.error("Artifact not found: %s", args.artifact_id)
        return EXIT_USER_ERROR

    with open(record_path, "r") as f:
        raw = json.load(f)

    record = ArtifactRecord.from_dict(raw)
    output = json.dumps(record.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(output)
        if args.verbose:
            print(f"Exported to: {args.output}")
    else:
        print(output)
    return EXIT_OK


@command_handler
def cmd_sign(args: argparse.Namespace) -> int:
    from ..store.identity import CRYPTO_AVAILABLE, IdentityLink

    if not CRYPTO_AVAILABLE:
        logger.error(
            "cryptography package required. Install with: pip install cryptography"
        )
        return EXIT_USER_ERROR

    passphrase = None
    if args.passphrase:
        import getpass

        passphrase = getpass.getpass(f"Passphrase for key '{args.key_id}': ")

    repo = AletheiaRepository(args.repo, auto_init=False)
    identity = IdentityLink()

    record_path = repo.records_dir / f"{args.artifact_id}.json"
    if not record_path.exists():
        logger.error("Artifact not found: %s", args.artifact_id)
        return EXIT_USER_ERROR
    with open(record_path, "r") as f:
        raw = json.load(f)

    record = ArtifactRecord.from_dict(raw)
    if record.identity_link is not None and not args.force:
        logger.error(
            "Already signed by '%s'. Use --force to overwrite.",
            record.identity_link.key_id,
        )
        return EXIT_USER_ERROR

    sig_block = identity.sign_artifact_record(
        raw, key_id=args.key_id, passphrase=passphrase
    )
    _to_dict = getattr(sig_block, "to_dict", None)
    sig_dict = _to_dict() if _to_dict is not None else sig_block
    repo.update_artifact_identity_link(
        args.artifact_id,
        sig_dict,
        allow_overwrite=args.force,
    )

    if args.verbose:
        print(f"Signed: {args.artifact_id}")
        print(f"  Key:         {args.key_id}")
        print(f"  Fingerprint: {sig_dict.get('fingerprint', '?')}")
    else:
        print(f"Signed: {args.artifact_id}")
    return EXIT_OK


@command_handler
def cmd_cleanup(args: argparse.Namespace) -> int:
    """Clean up abandoned temp files."""
    repo = AletheiaRepository(args.repo, auto_init=False)
    deleted = repo.cleanup_tmp_directory(args.max_age)

    if args.verbose:
        print(f"Cleaned up {deleted} abandoned temp file(s) older than {args.max_age}h")
    return EXIT_OK


@command_handler
def cmd_rebuild(args: argparse.Namespace) -> int:
    """Rebuild index from filesystem (disaster recovery)."""
    repo = AletheiaRepository(args.repo, auto_init=False)

    if args.verbose:
        print("\nWARNING: This will rebuild the entire index from scratch.")
        print("This is a disaster recovery operation for when the database is lost.\n")

    stats = repo.rebuild_index(
        verbose=args.verbose,
        continue_on_error=not args.strict,
        verify_objects=args.verify,
    )

    if stats["broken"] > 0:
        return EXIT_VERIFICATION_FAILED
    return EXIT_OK


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

    check_orphans = not args.no_orphans
    start_time = time.time()
    stats = repo.audit_objects(verbose=args.verbose, check_orphans=check_orphans)
    end_time = time.time()

    report = generate_forensic_report(
        repo=repo,
        stats=stats,
        duration=end_time - start_time,
        check_orphans=check_orphans,
    )

    if args.json:
        report_text = json.dumps(report, indent=2)
    else:
        report_text = format_forensic_report(report, verbose=args.verbose)

    if args.output:
        Path(args.output).write_text(report_text)
        if args.verbose:
            print(f"\nReport written to: {args.output}")
    else:
        print(report_text)

    has_issues = (
        len(stats.get("corrupted", [])) > 0 or len(stats.get("missing_files", [])) > 0
    )
    return EXIT_VERIFICATION_FAILED if has_issues else EXIT_OK


@command_handler
def cmd_doctor(args: argparse.Namespace) -> int:
    issues = []

    def check(name, fn):
        try:
            msg = fn()
            print(f"  OK    {name}: {msg}")
        except Exception as e:
            issues.append((name, str(e)))
            print(f"  FAIL  {name}: {e}")

    def _binary():
        s = OdinScanner(require_binary=True)
        return f"found at '{s.odin_binary}'"

    check("Odin binary", _binary)

    repo = None

    def _repo():
        nonlocal repo
        repo = AletheiaRepository(args.repo, auto_init=False)
        return f"initialized at {repo.root.resolve()}"

    check("Repository", _repo)

    if repo is not None:
        _checked_repo: AletheiaRepository = repo

        def _db():
            conn = _checked_repo._connect()
            conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()
            conn.close()
            return f"SQLite OK ({_checked_repo.db_path.name})"

        check("Database", _db)

        def _write():
            import uuid as _uuid

            p = _checked_repo.tmp_dir / f".probe_{_uuid.uuid4().hex}"
            p.write_bytes(b"")
            p.unlink(missing_ok=True)
            return "tmp/ writable"

        check("Write permission", _write)

        def _disk():
            import shutil

            free = shutil.disk_usage(str(_checked_repo.root)).free / (1024**3)
            label = "OK" if free >= 1.0 else "LOW"
            return f"{free:.1f} GB free ({label})"

        check("Disk space", _disk)

    def _keys():
        from ..store.identity import CRYPTO_AVAILABLE, IdentityLink

        if not CRYPTO_AVAILABLE:
            return "cryptography not installed (signing unavailable)"
        keys = IdentityLink().list_keys()
        return f"{len(keys)} key(s) available"

    check("Signing keys", _keys)

    print()
    if issues:
        print(f"FAIL  {len(issues)} check(s) failed.")
        return EXIT_SYSTEM_ERROR
    print("OK  All checks passed.")
    return EXIT_OK


@command_handler
def cmd_diff(args: argparse.Namespace) -> int:
    repo = AletheiaRepository(args.repo, auto_init=False)

    def _load(artifact_id: str) -> ArtifactRecord:
        rp = repo.records_dir / f"{artifact_id}.json"
        if not rp.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_id}")
        with open(rp, "r") as f:
            return ArtifactRecord.from_dict(json.load(f))

    r1 = _load(args.artifact_id_1)
    r2 = _load(args.artifact_id_2)
    sp1, sp2 = r1.scan_params, r2.scan_params
    if (
        sp1.window_size_bytes != sp2.window_size_bytes
        or sp1.step_size_bytes != sp2.step_size_bytes
    ):
        logger.error(
            "Incompatible scan params: WS %d/%d, SS %d/%d",
            sp1.window_size_bytes,
            sp2.window_size_bytes,
            sp1.step_size_bytes,
            sp2.step_size_bytes,
        )
        return EXIT_USER_ERROR

    b1 = repo.get_object_bytes(r1.barcode_object_id, obj_type_hint="barcode")
    b2 = repo.get_object_bytes(r2.barcode_object_id, obj_type_hint="barcode")
    p1 = ALBCParser.parse_full(b1)
    p2 = ALBCParser.parse_full(b2)
    if not p1 or not p2:
        logger.error("Failed to parse one or both barcodes")
        return EXIT_USER_ERROR

    regions = ALBCParser.compare_barcodes(
        p1["barcode_payload"],
        p2["barcode_payload"],
        sp1.window_size_bytes,
        sp1.step_size_bytes,
    )

    if args.json:
        print(
            json.dumps(
                {
                    "artifact_id_1": args.artifact_id_1,
                    "artifact_id_2": args.artifact_id_2,
                    "identical": len(regions) == 0,
                    "differing_regions": [
                        {
                            "start_window": r[0],
                            "end_window": r[1],
                            "start_byte": r[2],
                            "end_byte": r[3],
                        }
                        for r in regions
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"\n=== Barcode Diff ===\n")
        print(f"Artifact 1: {args.artifact_id_1}")
        print(f"Artifact 2: {args.artifact_id_2}")
        if not regions:
            print("Identical.")
        else:
            print(f"{len(regions)} differing region(s):")
            for i, (sw, ew, sb, eb) in enumerate(regions, 1):
                print(f"  {i}. windows {sw}-{ew}, bytes {sb:,}-{eb:,}")
        print()
    return EXIT_OK


def _get_identity():
    """Helper to get IdentityLink instance with proper error handling."""
    from ..store.identity import CRYPTO_AVAILABLE, IdentityLink

    if not CRYPTO_AVAILABLE:
        raise ValueError(
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
            logger.error("Passphrases do not match")
            return EXIT_USER_ERROR

    result = identity.generate_key(
        args.key_id, passphrase=passphrase, metadata=metadata
    )

    print(f"\nGenerated new signing key: {args.key_id}")
    print(f"  Fingerprint:   {result['fingerprint']}")
    print(f"  Private key:   {result['private_key_path']}")
    print(f"  Public key:    {result['public_key_path']}")
    if not args.use_passphrase:
        print("\nKey stored without passphrase encryption (--no-passphrase).")
    print("\nKeep your private key secure and back it up safely.")
    print("Share the public key with verifiers.")
    return EXIT_OK


@command_handler
def cmd_identity_list(args: argparse.Namespace) -> int:
    """List available keys."""
    identity = _get_identity()
    keys = identity.list_keys()

    if not keys:
        print("No keys found.")
        print(f"\nKey directory: {identity.key_dir}")
        print("Generate a key with: aletheia identity generate <key_id>")
        return EXIT_OK

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
    return EXIT_OK


@command_handler
def cmd_identity_export(args: argparse.Namespace) -> int:
    """Export public key."""
    identity = _get_identity()
    key_json = identity.export_public_key(args.key_id)
    print(key_json)
    return EXIT_OK


@command_handler
def cmd_identity_import(args: argparse.Namespace) -> int:
    """Import public key."""
    identity = _get_identity()
    key_json = Path(args.file).read_text()
    key_id = identity.import_public_key(key_json)
    print(f"Imported public key: {key_id}")
    return EXIT_OK


def _auto_migrate_legacy(root: "Path", dest: "Path") -> None:
    """Run auto-migration of legacy root data; log if anything was moved."""
    from ..store.repository import migrate_legacy_root_data

    try:
        migrated = migrate_legacy_root_data(root, dest)
        if migrated:
            logger.info(
                "Auto-migrated legacy repository data from '%s' into '%s'. "
                "Use --repo . to keep using the project root directly.",
                root,
                dest,
            )
    except Exception as exc:
        logger.warning("Auto-migration failed (non-fatal): %s", exc)


def main() -> int:
    """Main CLI entry point using argparse subparsers."""
    parser = argparse.ArgumentParser(
        prog="aletheia",
        description=(
            "Aletheia Repository CLI - Content-addressed storage with forensic verification"
        ),
    )
    parser.add_argument(
        "--repo",
        default=None,
        help=(
            "Repository root directory (default: aletheia_repo). "
            "On first run without --repo, any existing runtime data found at the "
            "project root is automatically migrated into aletheia_repo. "
            "Pass --repo . to use the project root directly (legacy behavior)."
        ),
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("--quiet", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--debug", action="store_true", help="Show full tracebacks on error"
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    p_init = subparsers.add_parser("init", help="Initialize a new repository")
    p_init.set_defaults(func=cmd_init)

    p_ingest = subparsers.add_parser("ingest", help="Ingest a file into the repository")
    p_ingest.add_argument("file", help="File to ingest")
    p_ingest.add_argument(
        "--window", type=int, default=65536, help="Window size in bytes"
    )
    p_ingest.add_argument("--step", type=int, default=16384, help="Step size in bytes")
    p_ingest.add_argument(
        "--m", type=int, default=1, help="Block size for entropy calculation"
    )
    p_ingest.add_argument(
        "--threads", type=int, default=0, help="Thread count (0=auto)"
    )
    p_ingest.add_argument(
        "--format",
        type=int,
        choices=[1, 2],
        default=1,
        help="ALBC format version",
    )
    p_ingest.add_argument(
        "--keep-temp", action="store_true", help="Keep temporary .albc file"
    )
    p_ingest.add_argument(
        "--no-auto-init",
        action="store_true",
        help="Fail if repository is not initialized",
    )
    p_ingest.add_argument("--sign", metavar="KEY_ID", help="Sign with this key ID")
    p_ingest.add_argument(
        "--passphrase", action="store_true", help="Prompt for signing passphrase"
    )
    p_ingest.set_defaults(func=cmd_ingest)

    p_verify = subparsers.add_parser(
        "verify", help="Verify a file against its artifact record"
    )
    p_verify.add_argument("path", help="Path to the file to verify")
    p_verify.add_argument(
        "--baseline",
        required=True,
        metavar="ARTIFACT_ID",
        help="Artifact ID to verify against",
    )
    p_verify.add_argument("--no-zoom", action="store_true")
    p_verify.add_argument("--require-signature", action="store_true")
    p_verify.set_defaults(func=cmd_verify)

    p_list = subparsers.add_parser("list", help="List recent artifacts")
    p_list.add_argument("--limit", type=int, default=20, help="Max artifacts to show")
    p_list.set_defaults(func=cmd_list)

    p_inspect = subparsers.add_parser(
        "inspect", help="Show human-readable artifact summary"
    )
    p_inspect.add_argument("artifact_id")
    p_inspect.set_defaults(func=cmd_inspect)

    p_show = subparsers.add_parser("show", help=argparse.SUPPRESS)
    p_show.add_argument("artifact_id")
    p_show.set_defaults(func=cmd_inspect)

    p_export = subparsers.add_parser("export", help="Export artifact record as JSON")
    p_export.add_argument("artifact_id")
    p_export.add_argument("--format", choices=["json"], default="json")
    p_export.add_argument("--output", "-o", metavar="FILE")
    p_export.set_defaults(func=cmd_export)

    p_sign = subparsers.add_parser("sign", help="Sign an existing artifact record")
    p_sign.add_argument("artifact_id")
    p_sign.add_argument("--key", required=True, dest="key_id", metavar="KEY_ID")
    p_sign.add_argument("--passphrase", action="store_true")
    p_sign.add_argument(
        "--force", action="store_true", help="Overwrite existing signature"
    )
    p_sign.set_defaults(func=cmd_sign)

    p_doctor = subparsers.add_parser("doctor", help="Run system health checks")
    p_doctor.set_defaults(func=cmd_doctor)

    p_audit = subparsers.add_parser("audit", help="Run forensic integrity audit")
    p_audit.add_argument("--no-orphans", action="store_true", help="Skip orphan check")
    p_audit.add_argument("--json", action="store_true", help="Output as JSON")
    p_audit.add_argument("--output", metavar="FILE", help="Write report to file")
    p_audit.set_defaults(func=cmd_audit)

    p_cleanup = subparsers.add_parser("cleanup", help="Clean up abandoned temp files")
    p_cleanup.add_argument(
        "--max-age", type=int, default=24, help="Max age in hours (default: 24)"
    )
    p_cleanup.set_defaults(func=cmd_cleanup)

    p_rebuild = subparsers.add_parser(
        "rebuild",
        help="Rebuild index from filesystem (disaster recovery)",
    )
    p_rebuild.add_argument("--strict", action="store_true", help="Stop on first error")
    p_rebuild.add_argument("--verify", action="store_true", help="Verify object hashes")
    p_rebuild.set_defaults(func=cmd_rebuild)

    p_diff = subparsers.add_parser("diff", help="Compare two stored artifact barcodes")
    p_diff.add_argument("artifact_id_1", help="First artifact ID")
    p_diff.add_argument("artifact_id_2", help="Second artifact ID")
    p_diff.add_argument("--json", action="store_true")
    p_diff.set_defaults(func=cmd_diff)

    p_identity = subparsers.add_parser("identity", help="Manage signing keys")
    identity_subs = p_identity.add_subparsers(dest="identity_command", required=True)

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

    p_id_list = identity_subs.add_parser("list", help="List available keys")
    p_id_list.set_defaults(func=cmd_identity_list)

    p_id_export = identity_subs.add_parser("export", help="Export public key")
    p_id_export.add_argument("key_id", help="Key ID to export")
    p_id_export.set_defaults(func=cmd_identity_export)

    p_id_import = identity_subs.add_parser("import", help="Import public key")
    p_id_import.add_argument("file", help="Path to public key JSON file")
    p_id_import.set_defaults(func=cmd_identity_import)

    args = parser.parse_args()
    setup_logging(verbose=args.verbose, debug=args.debug)

    # Resolve implicit default repo path and trigger one-time auto-migration.
    _implicit_repo = args.repo is None
    if _implicit_repo:
        args.repo = "aletheia_repo"
        _auto_migrate_legacy(Path("."), Path(args.repo))

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
