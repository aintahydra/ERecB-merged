from __future__ import annotations

import bz2
import gzip
import os
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from erecb_triage.processors.base import Processor, ProcessorResult

ZIP_SUFFIXES = (".en_dec", ".enc", ".zip")
TAR_SUFFIXES = (".tar.bz2", ".tbz2", ".tbz", ".tar.gz", ".tgz", ".tar")
COMPRESSION_SUFFIXES = (".bzip2", ".bzip", ".bz2", ".bz", ".gz")


@dataclass(frozen=True)
class ArchiveEstimate:
    archive_format: str
    file_count: int
    extracted_bytes: int
    method: str


class ArchiveUnarchiver(Processor):
    """Extraction engine; all public pipeline entry points use indexed staging."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name, self.config = name, config
        self.filename_regex = re.compile(config["filename_regex"], re.I) if config.get("filename_regex") else None
        self.supported_formats = tuple(config.get("supported_formats", ZIP_SUFFIXES + (".tar.gz",)))
        self.max_depth = config.get("max_depth_from_event_root", 2)
        self.max_archive_size = config.get("max_archive_size_bytes") or 0
        self.max_total_bytes = config.get("max_total_extracted_bytes_per_archive") or 0
        self.max_files = config.get("max_extracted_files_per_archive") or 0
        self.overwrite = config.get("overwrite", False)

    def process(self, input_records: list[dict[str, Any]], context: Any) -> ProcessorResult:
        from erecb_triage.processors.input_stager import InputStager
        return InputStager(self.name, {
            "unarchiver": self.name, "copy_files": False, "copy_directories": True,
            "extract_nested_archives": True,
        }).process(input_records, context)

    def _archive_format(self, path: Path) -> str:
        for suffix in sorted(self.supported_formats, key=len, reverse=True):
            if path.name.lower().endswith(suffix):
                return suffix
        return ""

    def _is_candidate(self, path: Path, depth: int = 0) -> bool:
        return bool(self._archive_format(path)) and (
            self.max_depth is None or depth <= self.max_depth
        ) and (self.filename_regex is None or bool(self.filename_regex.match(path.name)))

    def _discover(self, root: Path):
        if root.is_symlink():
            return
        if root.is_file():
            if self._is_candidate(root):
                yield root, 0
            return
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink())
            depth = len(Path(directory).relative_to(root).parts)
            if self.max_depth is not None and depth >= self.max_depth:
                dirs[:] = []
            for name in sorted(files):
                path = Path(directory) / name
                if not path.is_symlink() and path.is_file() and self._is_candidate(path, depth):
                    yield path, depth

    def validate(self, path: Path) -> str:
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise OSError("archive must be a regular file")
        size = path.stat().st_size
        if self.max_archive_size and size > self.max_archive_size:
            raise OSError(
                f"archive size {size} bytes exceeds configured limit {self.max_archive_size} bytes"
            )
        kind = self._archive_format(path)
        if kind in ZIP_SUFFIXES:
            if not zipfile.is_zipfile(path):
                raise OSError("format_mismatch: file content is not a valid ZIP")
            with zipfile.ZipFile(path) as archive:
                if any(item.flag_bits & 1 for item in archive.infolist()):
                    raise OSError("encrypted ZIP entries are not supported")
        elif kind in TAR_SUFFIXES:
            # Opening in the selected mode checks compression as well as the tar header.
            with tarfile.open(path, self._tar_mode(kind)):
                pass
        elif kind not in COMPRESSION_SUFFIXES:
            raise OSError(f"unsupported archive format: {kind}")
        return kind

    def estimate_extraction(self, path: Path) -> ArchiveEstimate | None:
        """Estimate supported archive contents before the stager copies or extracts them."""
        kind = self._archive_format(path)
        if kind in ZIP_SUFFIXES:
            with zipfile.ZipFile(path) as archive:
                files = [item for item in archive.infolist() if not item.is_dir()]
                return ArchiveEstimate(kind, len(files), sum(item.file_size for item in files), "zip_central_directory")
        if kind in TAR_SUFFIXES:
            count = total = 0
            with tarfile.open(path, self._tar_mode(kind)) as archive:
                for member in archive:
                    if member.isfile():
                        count += 1
                        total += member.size
            return ArchiveEstimate(kind, count, total, "tar_header_scan")
        return None

    def estimated_extracted_bytes(self, path: Path) -> int | None:
        """Compatibility helper for callers needing only an estimated byte count."""
        estimate = self.estimate_extraction(path)
        return None if estimate is None else estimate.extracted_bytes

    def validate_estimate(self, estimate: ArchiveEstimate) -> None:
        if self.max_files and estimate.file_count > self.max_files:
            raise OSError(
                f"estimated extracted file count {estimate.file_count} exceeds configured limit {self.max_files}"
            )
        if self.max_total_bytes and estimate.extracted_bytes > self.max_total_bytes:
            raise OSError(
                f"estimated extracted byte count {estimate.extracted_bytes} exceeds configured limit {self.max_total_bytes}"
            )

    @staticmethod
    def _tar_mode(kind: str) -> str:
        if kind in (".tar.gz", ".tgz"):
            return "r:gz"
        if kind in (".tar.bz2", ".tbz2", ".tbz"):
            return "r:bz2"
        return "r:"

    def extract(self, path: Path, output: Path) -> tuple[str, int, int]:
        """Write only into an empty, private directory assigned by the stager."""
        kind = self.validate(path)
        count = total = 0

        def copy(source, target: Path, expected: int | None = None):
            nonlocal count, total
            count += 1
            self._check_limits(count, total)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            size = 0
            with target.open("xb") as dest:
                os.chmod(target, 0o600)
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    total += len(chunk)
                    self._check_limits(count, total)
                    dest.write(chunk)
                dest.flush()
                os.fsync(dest.fileno())
            if expected is not None and size != expected:
                raise OSError("archive member size disagrees with metadata")

        if kind in ZIP_SUFFIXES:
            with zipfile.ZipFile(path) as archive:
                for item in archive.infolist():
                    target = self._safe_member_path(output, item.filename)
                    mode = stat.S_IFMT(item.external_attr >> 16)
                    if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                        raise OSError(f"zip special member is not allowed: {item.filename}")
                    if item.flag_bits & 1:
                        raise OSError("encrypted ZIP entries are not supported")
                    if item.is_dir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    if mode == stat.S_IFDIR:
                        raise OSError("inconsistent ZIP directory metadata")
                    self._check_limits(count + 1, total + item.file_size)
                    with archive.open(item) as source:
                        copy(source, target, item.file_size)
        elif kind in TAR_SUFFIXES:
            with tarfile.open(path, self._tar_mode(kind)) as archive:
                for member in archive:
                    target = self._safe_member_path(output, member.name)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    elif member.isfile():
                        if member.issparse():
                            raise OSError(f"tar sparse member is not allowed: {member.name}")
                        self._check_limits(count + 1, total + member.size)
                        source = archive.extractfile(member)
                        if source is None:
                            raise OSError(f"unreadable member: {member.name}")
                        with source:
                            copy(source, target, member.size)
                    else:
                        raise OSError(f"tar special member is not allowed: {member.name}")
        else:
            opener = gzip.open if kind == ".gz" else bz2.open
            with opener(path, "rb") as source:
                copy(source, self._safe_member_path(output, path.name[:-len(kind)] or "decompressed"))
        return kind, count, total

    @staticmethod
    def _safe_member_path(output: Path, member: str) -> Path:
        pure = PurePosixPath(member)
        if (not member or "\x00" in member or "\\" in member or pure.is_absolute()
                or ".." in pure.parts):
            raise OSError(f"path_traversal: archive member escapes output directory: {member}")
        target = output.joinpath(*pure.parts)
        if not target.resolve().is_relative_to(output.resolve()):
            raise OSError(f"path_traversal: archive member escapes output directory: {member}")
        return target

    def _check_limits(self, count: int, total: int) -> None:
        if self.max_files and count > self.max_files:
            raise OSError("extracted file count exceeds configured limit")
        if self.max_total_bytes and total > self.max_total_bytes:
            raise OSError("extracted byte count exceeds configured limit")
