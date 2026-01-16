from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, Iterator, BinaryIO, cast
import hashlib
import json
import os
import sqlite3
import shutil
import uuid
import time
import sys

from utils import compute_file_hash, hash_and_copy_file, hash_bytes


class RepositoryError(Exception):
    """Base exception for repository errors."""

    pass


class RepositoryNotInitializedError(RepositoryError):
    """Raised when repository structure is missing."""

    pass


class ObjectNotFoundError(RepositoryError):
    """Raised when an object is missing from both database and filesystem."""

    pass


class BrokenArtifactError(RepositoryError):
    """Raised when an artifact record references missing objects."""

    pass


class IntegrityError(RepositoryError):
    """Raised when object content doesn't match its content-address."""

    pass


class AletheiaRepository:
    """Content-addressed storage repository with SQLite indexing."""

    def __init__(self, repo_root: str = ".", auto_init: bool = True):
        """
        Initialize repository.

        Args:
            repo_root: Root directory for the repository
            auto_init: If True, automatically create directory structure and database.
                      If False, fail fast if structure doesn't exist.
        """
        self.root = Path(repo_root)
        self.objects_dir = self.root / "objects"
        self.records_dir = self.root / "records"
        self.tmp_dir = self.root / "tmp"
        self.config_path = self.root / "config.json"
        self.db_path = self.root / "index.sqlite3"

        # Check or initialize repository structure
        if auto_init:
            self._ensure_initialized()
        else:
            self._verify_initialized()

    def _ensure_initialized(self) -> None:
        """Ensure repository structure exists, creating it if necessary."""
        # Create directory structure
        for directory in [self.objects_dir, self.records_dir, self.tmp_dir]:
            directory.mkdir(parents=True, exist_ok=True)

        # Create config.json if it doesn't exist
        if not self.config_path.exists():
            config = {
                "version": "aletheia/repo/1",
                "storage": {"hash_algorithm": "sha256", "object_fanout": 2},
                "created_at": self._unix_ms(),
            }
            self.config_path.write_text(json.dumps(config, indent=2))

        # Initialize database if needed
        if not self.db_path.exists() or not self._check_schema():
            self._init_database()

    def _verify_initialized(self) -> None:
        """Verify repository structure exists, raise if not."""
        missing = []

        for name, path in [
            ("objects directory", self.objects_dir),
            ("records directory", self.records_dir),
            ("tmp directory", self.tmp_dir),
            ("config file", self.config_path),
            ("database", self.db_path),
        ]:
            if not path.exists():
                missing.append(name)

        if missing:
            raise RepositoryNotInitializedError(
                f"Repository not initialized. Missing: {', '.join(missing)}. "
                f"Initialize with: AletheiaRepository(auto_init=True)"
            )

        # Verify database schema
        if not self._check_schema():
            raise RepositoryNotInitializedError(
                "Database exists but schema is invalid. "
                "Re-initialize with: AletheiaRepository(auto_init=True)"
            )

    def _check_schema(self) -> bool:
        """Check if database has the required tables."""
        if not self.db_path.exists():
            return False

        try:
            conn = self._connect()
            cursor = conn.cursor()

            # Check for required tables
            cursor.execute(
                """
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name IN ('objects', 'artifacts')
            """
            )
            tables = {row[0] for row in cursor.fetchall()}

            conn.close()

            return tables == {"objects", "artifacts"}
        except sqlite3.Error:
            return False

    def _connect(self) -> sqlite3.Connection:
        """
        Create a database connection with proper settings.

        - WAL mode for better concurrency
        - Foreign key enforcement for data integrity
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_database(self) -> None:
        """Initialize the SQLite database schema."""
        conn = self._connect()
        cursor = conn.cursor()

        # Objects table: dedupe + metadata for all content-addressed objects
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS objects (
                object_id TEXT PRIMARY KEY,
                size_bytes INTEGER NOT NULL,
                type TEXT NOT NULL,
                created_at_unix_ms INTEGER NOT NULL
            )
        """
        )

        # Artifacts table: one row per Artifact Record
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                record_version TEXT NOT NULL,
                record_path TEXT NOT NULL,
                content_object_id TEXT NOT NULL,
                barcode_object_id TEXT,
                created_at_unix_ms INTEGER NOT NULL,
                window_size_bytes INTEGER,
                step_size_bytes INTEGER,
                m_block_size INTEGER,
                quant_version TEXT,
                barcode_len INTEGER,
                FOREIGN KEY (content_object_id) REFERENCES objects(object_id),
                FOREIGN KEY (barcode_object_id) REFERENCES objects(object_id)
            )
        """
        )

        # Create indexes for common queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_objects_type ON objects(type)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_objects_created ON objects(created_at_unix_ms)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_created ON artifacts(created_at_unix_ms)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_scan_params ON artifacts(window_size_bytes, step_size_bytes)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_record_version ON artifacts(record_version)"
        )

        conn.commit()
        conn.close()

    def _hash_content(self, data: bytes) -> str:
        """Content-address: SHA-256 hex."""
        return hash_bytes(data)

    def _object_path(self, object_id: str) -> Path:
        """Get storage path using 2-char fanout (ab/abcd...ef)."""
        return self.objects_dir / object_id[:2] / object_id

    def _unix_ms(self) -> int:
        """Current timestamp in Unix milliseconds."""
        return int(datetime.utcnow().timestamp() * 1000)

    def store_object(self, data: bytes, obj_type: str) -> str:
        """
        Store immutable object from bytes (for small data like barcodes).

        For large files, use store_object_from_file() instead.
        """
        object_id = self._hash_content(data)
        obj_path = self._object_path(object_id)

        obj_path.parent.mkdir(parents=True, exist_ok=True)

        if not obj_path.exists():
            tmp_path = self.tmp_dir / f"{object_id}.{uuid.uuid4().hex}.tmp"
            try:
                tmp_path.write_bytes(data)
                try:
                    os.replace(str(tmp_path), str(obj_path))
                except OSError:
                    if obj_path.exists():
                        tmp_path.unlink(missing_ok=True)
                    else:
                        raise
            except:
                tmp_path.unlink(missing_ok=True)
                raise

        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO objects (object_id, size_bytes, type, created_at_unix_ms) VALUES (?, ?, ?, ?)",
            (object_id, len(data), obj_type, self._unix_ms()),
        )
        conn.commit()
        conn.close()

        return object_id

    def store_object_from_file(self, file_path: str, obj_type: str) -> Tuple[str, int]:
        """
        Store object from file using single-pass hash-and-copy (memory-efficient).

        Computes hash WHILE copying - only reads file once.
        For a 50GB file, this saves 50GB of disk I/O compared to hash-then-copy.

        Returns:
            (object_id, file_size): The content-address hash and file size
        """
        file_path_obj = Path(file_path)
        obj_path = None
        tmp_path = None

        try:
            # Create unique temp file (for atomic move + concurrent safety)
            tmp_path = self.tmp_dir / f"ingest.{uuid.uuid4().hex}.tmp"

            # SINGLE-PASS: Hash and copy simultaneously
            object_id, file_size = hash_and_copy_file(file_path_obj, tmp_path)

            # Determine final object path
            obj_path = self._object_path(object_id)
            obj_path.parent.mkdir(parents=True, exist_ok=True)

            # Atomic move to final location
            if not obj_path.exists():
                try:
                    os.replace(str(tmp_path), str(obj_path))
                    tmp_path = None  # Successfully moved, don't delete in finally
                except OSError:
                    # Race condition: another process created the file first
                    if obj_path.exists():
                        pass  # That's fine, content is identical (content-addressed)
                    else:
                        raise

            # Index the object
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO objects (object_id, size_bytes, type, created_at_unix_ms) VALUES (?, ?, ?, ?)",
                (object_id, file_size, obj_type, self._unix_ms()),
            )
            conn.commit()
            conn.close()

            return object_id, file_size

        finally:
            # Cleanup tmp file if it still exists (failed before move)
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    def artifact_exists(self, artifact_id: str) -> bool:
        """Check if an artifact already exists in the repository."""
        record_path = self.records_dir / f"{artifact_id}.json"
        if record_path.exists():
            return True

        # Also check database index
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM artifacts WHERE artifact_id = ? LIMIT 1", (artifact_id,)
        )
        exists = cursor.fetchone() is not None
        conn.close()

        return exists

    def get_object_path(self, object_id: str) -> Optional[Path]:
        """
        Get the filesystem path for an object.

        Returns:
            Path if object exists, None otherwise
        """
        obj_path = self._object_path(object_id)
        return obj_path if obj_path.exists() else None

    def get_object_stream(
        self, object_id: str, chunk_size: int = 8 * 1024 * 1024
    ) -> Iterator[bytes]:
        """
        Stream object bytes without loading entire file into RAM.

        This is the memory-safe way to read large objects (50GB files, etc.)

        Args:
            object_id: Content-addressed object ID
            chunk_size: Bytes per chunk (default: 8MB)

        Yields:
            Chunks of object data

        Raises:
            ObjectNotFoundError: If object doesn't exist
        """
        obj_path = self._object_path(object_id)
        if not obj_path.exists():
            raise ObjectNotFoundError(f"Object not found: {object_id}")

        with open(obj_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

    def get_object_handle(self, object_id: str, mode: str = "rb") -> BinaryIO:
        """
        Open object as file handle (caller manages lifecycle).

        Use this for random access or when you need fine control over I/O.
        Caller MUST close the handle when done.

        Args:
            object_id: Content-addressed object ID
            mode: File mode (default: 'rb')

        Returns:
            Open file handle

        Raises:
            ObjectNotFoundError: If object doesn't exist

        Example:
            with repo.get_object_handle(content_id) as f:
                f.seek(50 * 1024 * 1024 * 1024)  # Jump to 50GB mark
                data = f.read(512)
        """
        obj_path = self._object_path(object_id)
        if not obj_path.exists():
            raise ObjectNotFoundError(f"Object not found: {object_id}")

        return cast(BinaryIO, open(obj_path, mode))

    def get_object_bytes(
        self,
        object_id: str,
        max_size: Optional[int] = None,
        obj_type_hint: Optional[str] = None,
    ) -> bytes:
        """
        Load entire object into memory as bytes.

        ⚠️ WARNING: Only use for small objects (barcodes, metadata, etc.)

        DYNAMIC SAFETY LIMITS (Issue #4 - Barcode Trap):
        - Default: 100 MB (safe for most barcodes)
        - type='barcode': 500 MB (large file barcodes can be big)
        - type='content': 100 MB (should use streaming)
        - Custom: Caller can override

        Args:
            object_id: Content-addressed object ID
            max_size: Override safety limit (bytes)
            obj_type_hint: Type hint for dynamic limits ('barcode', 'content', etc.)

        Returns:
            Object bytes

        Raises:
            ObjectNotFoundError: If object doesn't exist
            RepositoryError: If object exceeds max_size
        """
        obj_path = self._object_path(object_id)
        if not obj_path.exists():
            raise ObjectNotFoundError(f"Object not found: {object_id}")

        # Dynamic safety limits based on object type (Issue #4)
        if max_size is None:
            if obj_type_hint == "barcode":
                max_size = 500 * 1024 * 1024  # 500 MB for barcodes
            else:
                max_size = 100 * 1024 * 1024  # 100 MB default

        # Safety check: Don't accidentally load 50GB into RAM
        size = obj_path.stat().st_size
        if size > max_size:
            raise RepositoryError(
                f"Object {object_id} is {size:,} bytes, exceeds max_size={max_size:,}. "
                f"Use get_object_stream() or get_object_handle() instead."
            )

        return obj_path.read_bytes()

    def rebuild_index(
        self,
        verbose: bool = True,
        continue_on_error: bool = True,
        verify_objects: bool = False,
    ) -> Dict[str, Any]:
        """
        Rebuild entire SQLite index from JSON records and filesystem objects.

        SAFETY TRADE-OFF (Issue #2):
        Uses PRAGMA synchronous = OFF for massive speedup (50×).

        WHY THIS IS ACCEPTABLE:
        1. Rebuild is IDEMPOTENT - can be re-run if it fails
        2. Source of truth is filesystem (objects/ + records/), not DB
        3. If power fails mid-rebuild:
           - Corrupted DB → Delete it, re-run rebuild
           - Filesystem unchanged → No data loss
        4. This is a RECOVERY operation, not normal ingest

        WHY IT'S DANGEROUS FOR INGEST:
        - Ingest creates NEW objects/records on disk
        - If power fails, files might be on disk but not indexed
        - Corruption = data loss (objects exist but unreachable)

        For rebuild: Corruption = annoyance (just re-run)
        For ingest: Corruption = data loss (objects orphaned)

        Args:
            verbose: Print progress messages
            continue_on_error: Continue indexing even if some artifacts broken
            verify_objects: Re-hash objects to verify integrity (SLOW)

        Returns:
            Statistics dict with counts
        """
        if verbose:
            print("\n=== Rebuilding Repository Index ===")
            print("\n⚠️  SAFETY MODE: Using fast but unsafe writes")
            print("   Database corruption during rebuild is acceptable (just re-run)")
            print("   Source of truth (objects/ + records/) is unchanged\n")

            if verify_objects:
                print("⚠️  Forensic mode: Will re-hash all objects (SLOW)\n")

        # Collect all artifact records
        artifact_files = list(self.records_dir.glob("*.json"))
        total = len(artifact_files)

        if verbose:
            print(f"Found {total} artifact record(s) to index\n")

        stats = {
            "total": total,
            "indexed": 0,
            "broken": 0,
            "errors": [],
            "integrity_failures": [],
        }

        # Single transaction for entire rebuild (massive speedup)
        conn = self._connect()

        try:
            # CRITICAL: Disable synchronous writes (Issue #2)
            # This is the "sharp knife" - acceptable here because:
            # - Rebuild is idempotent (can re-run)
            # - Filesystem is source of truth (DB is just cache)
            # - Corruption = annoyance, not data loss
            conn.execute("PRAGMA synchronous = OFF")

            for i, record_path in enumerate(artifact_files, 1):
                artifact_id = record_path.stem

                if verbose and i % 100 == 0:
                    print(f"Progress: {i}/{total} ({100*i//total}%)")
                elif verbose and i % 10 == 0:
                    print(f"[{i}/{total}]", end=" ", flush=True)

                try:
                    success = self.ensure_artifact_indexed(
                        artifact_id,
                        conn=conn,
                        verify_objects=verify_objects,
                        raise_on_broken=(not continue_on_error),
                    )

                    if success:
                        stats["indexed"] += 1
                    else:
                        stats["broken"] += 1
                        stats["errors"].append(
                            f"{artifact_id}: Broken (missing objects)"
                        )

                except IntegrityError as e:
                    stats["integrity_failures"].append(str(e))
                    stats["broken"] += 1
                    if not continue_on_error:
                        raise

                except BrokenArtifactError as e:
                    stats["broken"] += 1
                    stats["errors"].append(f"{artifact_id}: {e}")
                    if not continue_on_error:
                        raise

                except Exception as e:
                    stats["broken"] += 1
                    stats["errors"].append(f"{artifact_id}: {e}")
                    if not continue_on_error:
                        raise

            # Commit entire transaction once at end
            conn.commit()

            # Re-enable synchronous writes for safety
            conn.execute("PRAGMA synchronous = NORMAL")

        except Exception as e:
            conn.rollback()
            conn.close()
            raise
        finally:
            conn.close()

        if verbose:
            print(f"\n\n=== Index Rebuild Complete ===")
            print(f"Total:              {stats['total']}")
            print(f"Indexed:            {stats['indexed']}")
            print(f"Broken:             {stats['broken']}")

            if verify_objects and stats["integrity_failures"]:
                print(f"\n⚠️  Integrity Failures: {len(stats['integrity_failures'])}")
                for failure in stats["integrity_failures"][:5]:
                    print(f"  - {failure}")
                if len(stats["integrity_failures"]) > 5:
                    print(f"  ... and {len(stats['integrity_failures']) - 5} more")

            if stats["errors"]:
                print(f"\nErrors/Broken Artifacts:")
                for error in stats["errors"][:10]:
                    print(f"  - {error}")
                if len(stats["errors"]) > 10:
                    print(f"  ... and {len(stats['errors']) - 10} more")

        return stats

    def audit_objects(
        self, verbose: bool = True, check_orphans: bool = True
    ) -> Dict[str, Any]:
        """
        Deep audit of repository integrity (forensic verification).

        PERFORMANCE OPTIMIZATIONS (Issues #1, #2, #3):
        1. STREAMING: Iterates cursor directly (no fetchall trap)
        2. SOFT RAM CEILING: Set of object IDs for orphan detection
           - For 50M objects: ~3.2 GB RAM (64 bytes per SHA-256 hex string)
           - Alternative: Stream filesystem + query DB (slower but constant RAM)
        3. INDEXED QUERIES: Uses object_id PRIMARY KEY for O(log N) lookups

        Args:
            verbose: Print progress
            check_orphans: Check for orphaned files (uses ~64 bytes RAM per object)

        Returns:
            Audit report with integrity failures
        """
        if verbose:
            print("\n=== Repository Integrity Audit ===\n")

        stats = {
            "total_objects": 0,
            "verified": 0,
            "corrupted": [],
            "missing_files": [],
            "orphaned_files": [],
        }

        # PHASE 1: Verify all indexed objects exist and have correct hash
        # FIX #1: Stream directly from cursor (no fetchall trap!)
        conn = self._connect()
        cursor = conn.cursor()
        cursor.execute("SELECT object_id, type, size_bytes FROM objects")

        # FIX #2: Build set for orphan detection (soft RAM ceiling acceptable for admin task)
        # Alternative approach at end of method for truly massive repos
        indexed_ids = set() if check_orphans else None

        if verbose:
            # Get count for progress reporting
            count_cursor = conn.cursor()
            count_cursor.execute("SELECT COUNT(*) FROM objects")
            stats["total_objects"] = count_cursor.fetchone()[0]
            count_cursor.close()
            print(f"Verifying {stats['total_objects']} indexed objects...\n")

        i = 0
        # CRITICAL: Iterate cursor directly (streaming, not fetchall)
        for row in cursor:
            object_id, obj_type, db_size = row
            i += 1

            if indexed_ids is not None:
                indexed_ids.add(object_id)

            if verbose and i % 10000 == 0:
                progress = (
                    f"{i:,}"
                    if stats["total_objects"] == 0
                    else f"{i}/{stats['total_objects']} ({100*i//stats['total_objects']}%)"
                )
                print(f"Progress: {progress}")

            obj_path = self._object_path(object_id)

            # Check if file exists
            if not obj_path.exists():
                stats["missing_files"].append(object_id)
                continue

            # Verify size matches
            try:
                actual_size = obj_path.stat().st_size
            except OSError:
                stats["missing_files"].append(object_id)
                continue

            if actual_size != db_size:
                stats["corrupted"].append(
                    {
                        "object_id": object_id,
                        "reason": f"Size mismatch: DB={db_size}, File={actual_size}",
                    }
                )
                continue

            # Re-hash to verify content-address
            try:
                actual_hash, _ = compute_file_hash(obj_path)
                if actual_hash != object_id:
                    stats["corrupted"].append(
                        {
                            "object_id": object_id,
                            "actual_hash": actual_hash,
                            "reason": "Content hash mismatch",
                        }
                    )
                    continue
            except Exception as e:
                stats["corrupted"].append(
                    {"object_id": object_id, "reason": f"Hash failed: {e}"}
                )
                continue

            stats["verified"] += 1

        cursor.close()

        # Update total if we didn't get it earlier
        if stats["total_objects"] == 0:
            stats["total_objects"] = i

        # PHASE 2: Check for orphaned files (Issue #3 - optimized approach)
        if check_orphans and indexed_ids is not None:
            if verbose:
                print("\nScanning for orphaned object files...")

            # Our fanout structure: objects/ab/abcd...
            # We need to traverse the directory tree
            orphan_count = 0

            for fanout_dir in self.objects_dir.iterdir():
                if not fanout_dir.is_dir():
                    continue

                for obj_file in fanout_dir.iterdir():
                    if obj_file.is_file():
                        object_id = obj_file.name

                        # Validate it looks like a SHA-256 hex
                        if len(object_id) == 64 and all(
                            c in "0123456789abcdef" for c in object_id
                        ):
                            # O(1) lookup in memory set (fast!)
                            if object_id not in indexed_ids:
                                stats["orphaned_files"].append(object_id)
                                orphan_count += 1

                                if verbose and orphan_count % 100 == 0:
                                    print(f"  Found {orphan_count} orphaned files...")

        # ALTERNATIVE APPROACH for truly massive repos (50M+ objects):
        # Comment out the indexed_ids approach above and use this instead:
        # This queries the DB for each file (slower but constant RAM)
        #
        # if check_orphans:
        #     if verbose:
        #         print("\nScanning for orphaned object files (streaming mode)...")
        #
        #     orphan_count = 0
        #     cursor = conn.cursor()
        #
        #     for fanout_dir in self.objects_dir.iterdir():
        #         if not fanout_dir.is_dir():
        #             continue
        #
        #         for obj_file in fanout_dir.iterdir():
        #             if obj_file.is_file():
        #                 object_id = obj_file.name
        #
        #                 if len(object_id) == 64:
        #                     cursor.execute("SELECT 1 FROM objects WHERE object_id = ? LIMIT 1", (object_id,))
        #                     if cursor.fetchone() is None:
        #                         stats['orphaned_files'].append(object_id)
        #                         orphan_count += 1
        #
        #     cursor.close()

        conn.close()

        if verbose:
            print(f"\n=== Audit Complete ===")
            print(f"Total objects:      {stats['total_objects']:,}")
            print(f"Verified:           {stats['verified']:,}")
            print(f"Corrupted:          {len(stats['corrupted']):,}")
            print(f"Missing files:      {len(stats['missing_files']):,}")
            if check_orphans:
                print(f"Orphaned files:     {len(stats['orphaned_files']):,}")

            if stats["corrupted"]:
                print(f"\n⚠️  Corrupted Objects:")
                for corruption in stats["corrupted"][:10]:
                    obj_id = corruption["object_id"][:16]
                    print(f"  - {obj_id}...: {corruption['reason']}")
                if len(stats["corrupted"]) > 10:
                    print(f"  ... and {len(stats['corrupted']) - 10} more")

        return stats

    def get_object(self, object_id: str) -> bytes:
        """
        Load entire object as bytes.

        This is a convenience alias for get_object_bytes with default parameters.
        """
        return self.get_object_bytes(object_id)

    def store_artifact(self, artifact_id: str, record: Dict[str, Any]) -> None:
        """
        Store an artifact record as JSON.

        Args:
            artifact_id: Unique artifact identifier (derived from content + barcode)
            record: Artifact record dict (from ArtifactRecordBuilder.build())

        Records stored as: records/{artifact_id}.json
        """
        record_path = self.records_dir / f"{artifact_id}.json"

        # Write record
        record_path.write_text(json.dumps(record, indent=2))

        # Index in database
        self.ensure_artifact_indexed(artifact_id)

    def ensure_artifact_indexed(
        self,
        artifact_id: str,
        conn: Optional[sqlite3.Connection] = None,
        verify_objects: bool = False,
        raise_on_broken: bool = False,
    ) -> bool:
        """
        Index an artifact in the database.

        Loads the artifact record from disk and inserts into SQLite index.
        Used after store_artifact() to index in DB.
        Also used in rebuild_index() to re-index all artifacts.

        Args:
            artifact_id: Artifact identifier
            conn: Optional database connection (reuses if provided, for batch operations)
            verify_objects: If True, verify referenced objects exist (forensic mode)
            raise_on_broken: If True, raise on missing objects; if False, log and continue

        Returns:
            True if indexed successfully, False if artifact is broken

        Raises:
            BrokenArtifactError: If referenced objects missing and raise_on_broken=True
            IntegrityError: If object content doesn't match content-address
        """
        record_path = self.records_dir / f"{artifact_id}.json"

        if not record_path.exists():
            raise FileNotFoundError(f"Artifact record not found: {record_path}")

        # Load record
        with open(record_path, "r") as f:
            record = json.load(f)

        # Verify referenced objects exist
        content_obj_id = record.get("content_object_id")
        barcode_obj_id = record.get("barcode_object_id")

        if not content_obj_id:
            raise BrokenArtifactError(f"{artifact_id}: Missing content_object_id")

        content_path = self._object_path(content_obj_id)
        barcode_path = self._object_path(barcode_obj_id) if barcode_obj_id else None

        if not content_path.exists():
            msg = f"{artifact_id}: Missing content object {content_obj_id}"
            if raise_on_broken:
                raise BrokenArtifactError(msg)
            return False

        if barcode_obj_id and barcode_path and not barcode_path.exists():
            msg = f"{artifact_id}: Missing barcode object {barcode_obj_id}"
            if raise_on_broken:
                raise BrokenArtifactError(msg)
            return False

        # Optional: Verify object integrity (forensic mode)
        if verify_objects:
            if content_path.exists():
                actual_hash = compute_file_hash(content_path)[0]
                if actual_hash != content_obj_id:
                    raise IntegrityError(
                        f"{artifact_id}: Content mismatch. "
                        f"Expected {content_obj_id}, got {actual_hash}"
                    )

            if barcode_obj_id and barcode_path and barcode_path.exists():
                actual_hash = hashlib.sha256(barcode_path.read_bytes()).hexdigest()
                if actual_hash != barcode_obj_id:
                    raise IntegrityError(
                        f"{artifact_id}: Barcode mismatch. "
                        f"Expected {barcode_obj_id}, got {actual_hash}"
                    )

        # Index in database
        close_conn = False
        if conn is None:
            conn = self._connect()
            close_conn = True

        try:
            cursor = conn.cursor()

            scan_params = record.get("scan_params", {})

            # Extract with legacy fallback (canonical keys use _bytes suffix)
            window_size_bytes = scan_params.get(
                "window_size_bytes", scan_params.get("window_size", 65536)
            )
            step_size_bytes = scan_params.get(
                "step_size_bytes", scan_params.get("step_size", 16384)
            )
            m_block_size = scan_params.get("m_block_size", 1)
            quant_version = scan_params.get("quant_version", "v0")
            barcode_len = scan_params.get("barcode_len", 0)

            cursor.execute(
                """
                INSERT OR REPLACE INTO artifacts (
                    artifact_id, record_version, record_path,
                    content_object_id, barcode_object_id,
                    created_at_unix_ms,
                    window_size_bytes, step_size_bytes, m_block_size,
                    quant_version, barcode_len
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    artifact_id,
                    record.get("record_version", "aletheia/ar/1"),
                    str(record_path.relative_to(self.root)),
                    content_obj_id,
                    barcode_obj_id,
                    record.get("created_at_unix_ms", self._unix_ms()),
                    window_size_bytes,
                    step_size_bytes,
                    m_block_size,
                    quant_version,
                    barcode_len,
                ),
            )

            if close_conn:
                conn.commit()

            return True

        finally:
            if close_conn:
                conn.close()

    def cleanup_tmp_directory(self, max_age_hours: int = 24) -> int:
        """
        Clean up abandoned temporary files older than max_age_hours.

        Temp files are created during ingest but should be cleaned up.
        If a process crashes mid-ingest, temp files may be left behind.

        Args:
            max_age_hours: Delete files older than this (default: 24 hours)

        Returns:
            Number of files deleted
        """
        if not self.tmp_dir.exists():
            return 0

        deleted = 0
        now = time.time()
        max_age_seconds = max_age_hours * 3600

        for tmp_file in self.tmp_dir.iterdir():
            if tmp_file.is_file():
                try:
                    file_age = now - tmp_file.stat().st_mtime
                    if file_age > max_age_seconds:
                        tmp_file.unlink()
                        deleted += 1
                except OSError:
                    # File may have been deleted by another process
                    pass

        return deleted
