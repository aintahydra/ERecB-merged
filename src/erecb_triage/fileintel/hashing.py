"""Bounded, single-pass SHA-256 and MD5 for local file identification."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from erecb_triage.staging import fingerprint, regular_reader


class FileTooLarge(OSError):
    pass


class FileChanged(OSError):
    pass


@dataclass(frozen=True)
class FileHashes:
    sha256_hash: str
    md5_hash: str
    size_bytes: int


def stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _validate_limits(block_size: int, max_size: int | None) -> None:
    if type(block_size) is not int or block_size < 1:
        raise ValueError("block_size must be a positive integer")
    if max_size is not None and (type(max_size) is not int or max_size < 0):
        raise ValueError("max_size must be a nonnegative integer or null")


def read_header(reader: BinaryIO, sample_size: int, *, block_size: int,
                max_size: int | None = None) -> bytes:
    _validate_limits(block_size, max_size)
    if type(sample_size) is not int or sample_size < 0:
        raise ValueError("sample_size must be a nonnegative integer")
    parts = []
    size = 0
    while size < sample_size:
        amount = min(block_size, sample_size - size)
        if max_size is not None:
            amount = min(amount, max_size - size + 1)
        chunk = reader.read(amount)
        if not chunk:
            break
        size += len(chunk)
        if max_size is not None and size > max_size:
            raise FileTooLarge("file exceeds max_file_size_bytes")
        parts.append(chunk)
    return b"".join(parts)


def hash_stream(reader: BinaryIO, *, block_size: int = 1048576,
                max_size: int | None = None, prefix: bytes = b"") -> FileHashes:
    """Hash an already-read header and the remainder without rewinding the stream."""
    _validate_limits(block_size, max_size)
    size = len(prefix)
    if max_size is not None and size > max_size:
        raise FileTooLarge("file exceeds max_file_size_bytes")
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    sha256.update(prefix)
    md5.update(prefix)
    while True:
        amount = block_size if max_size is None else min(block_size, max_size - size + 1)
        chunk = reader.read(amount)
        if not chunk:
            break
        size += len(chunk)
        if max_size is not None and size > max_size:
            raise FileTooLarge("file exceeds max_file_size_bytes")
        sha256.update(chunk)
        md5.update(chunk)
    return FileHashes(sha256.hexdigest(), md5.hexdigest(), size)


def hash_file(path: Path, *, block_size: int = 1048576,
              max_size: int | None = None) -> FileHashes:
    _validate_limits(block_size, max_size)
    before = fingerprint(path)
    if max_size is not None and before[2] > max_size:
        raise FileTooLarge("file exceeds max_file_size_bytes")
    with regular_reader(path) as reader:
        if stat_signature(os.fstat(reader.fileno())) != before:
            raise FileChanged("file changed before hashing")
        result = hash_stream(reader, block_size=block_size, max_size=max_size)
        if (result.size_bytes != before[2] or stat_signature(os.fstat(reader.fileno())) != before
                or fingerprint(path) != before):
            raise FileChanged("file changed during hashing")
    return result
