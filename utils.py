#!/usr/bin/env python3
"""
Aletheia Utilities - Shared streaming I/O operations
"""

import hashlib
from pathlib import Path
from typing import Tuple, Optional, BinaryIO, Callable


DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8MB chunks


def compute_file_hash(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int], None]] = None
) -> Tuple[str, int]:
    """
    Compute SHA-256 hash of file using streaming (memory-efficient for large files).
    
    Args:
        file_path: Path to file to hash
        chunk_size: Size of chunks to read (default: 8MB)
        progress_callback: Optional callback called with bytes_read after each chunk
    
    Returns:
        (hash_hex, file_size): SHA-256 hash and file size in bytes
    """
    hasher = hashlib.sha256()
    file_size = 0
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            file_size += len(chunk)
            
            if progress_callback:
                progress_callback(file_size)
    
    return hasher.hexdigest(), file_size


def hash_and_copy_file(
    src_path: Path,
    dst_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int], None]] = None
) -> Tuple[str, int]:
    """
    Hash and copy file in a single pass (memory-efficient for large files).
    
    Reads source file once, computing hash while writing to destination.
    This cuts disk I/O in half compared to separate hash + copy operations.
    
    Args:
        src_path: Source file path
        dst_path: Destination file path
        chunk_size: Size of chunks to read/write (default: 8MB)
        progress_callback: Optional callback called with bytes_processed after each chunk
    
    Returns:
        (hash_hex, file_size): SHA-256 hash and total bytes copied
    """
    hasher = hashlib.sha256()
    file_size = 0
    
    with open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            
            # Update hash and write in single pass
            hasher.update(chunk)
            dst.write(chunk)
            file_size += len(chunk)
            
            if progress_callback:
                progress_callback(file_size)
    
    return hasher.hexdigest(), file_size


def hash_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file_handle(
    file_handle: BinaryIO,
    chunk_size: int = DEFAULT_CHUNK_SIZE
) -> Tuple[str, int]:
    """
    Hash data from an open file handle (doesn't seek, reads from current position).
    
    Useful for hashing portions of files or data from pipes/streams.
    
    Args:
        file_handle: Open binary file handle
        chunk_size: Size of chunks to read
    
    Returns:
        (hash_hex, bytes_read): SHA-256 hash and total bytes read
    """
    hasher = hashlib.sha256()
    bytes_read = 0
    
    while True:
        chunk = file_handle.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
        bytes_read += len(chunk)
    
    return hasher.hexdigest(), bytes_read