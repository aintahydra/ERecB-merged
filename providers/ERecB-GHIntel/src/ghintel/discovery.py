"""Filesystem-only Git repository discovery; it never invokes Git."""

from __future__ import annotations

import os
from pathlib import Path

from .gitconfig import parse_git_config
from .models import RepositoryLocation

_GIT_FILE_LIMIT = 8192


def discover_repositories(root: Path) -> list[RepositoryLocation]:
    """Return all qualifying boundaries below *root*, including nested repositories."""
    if not root.is_dir():
        raise FileNotFoundError(f"input directory does not exist: {root}")
    found: list[RepositoryLocation] = []
    _walk(root, found)
    return sorted(found, key=lambda item: os.fspath(item.path).casefold())


def _walk(directory: Path, found: list[RepositoryLocation]) -> None:
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    git_entry = next((entry for entry in entries if entry.name == ".git"), None)
    if git_entry is not None and not git_entry.is_symlink():
        location = _repository_location(directory, git_entry)
        if location is not None:
            found.append(location)
    for entry in entries:
        if entry.name == ".git" or entry.is_symlink():
            continue
        try:
            if entry.is_dir(follow_symlinks=False):
                _walk(Path(entry.path), found)
        except OSError:
            continue


def _repository_location(repository_path: Path, git_entry: os.DirEntry[str]) -> RepositoryLocation | None:
    try:
        if git_entry.is_dir(follow_symlinks=False):
            config_path = Path(git_entry.path) / "config"
            parsed = parse_git_config(config_path)
            return RepositoryLocation(repository_path, "directory", parsed.remotes, parsed.diagnostics)
        if not git_entry.is_file(follow_symlinks=False):
            return None
        content = Path(git_entry.path).read_bytes()
        if len(content) > _GIT_FILE_LIMIT:
            return RepositoryLocation(repository_path, "worktree", (), (".git file exceeds size limit",))
        first_line = content.decode("utf-8", errors="replace").splitlines()[0] if content else ""
        if not first_line.casefold().startswith("gitdir:"):
            return None
        target_text = first_line.split(":", 1)[1].strip()
        target = Path(target_text)
        if not target.is_absolute():
            target = repository_path / target
        target = Path(os.path.normpath(target))
        if target.is_symlink() or not target.is_dir():
            return RepositoryLocation(repository_path, "worktree", (), ("invalid or symlinked worktree gitdir",))
        config_path = _worktree_config(target)
        parsed = parse_git_config(config_path)
        return RepositoryLocation(repository_path, "worktree", parsed.remotes, parsed.diagnostics)
    except OSError as error:
        return RepositoryLocation(repository_path, "unknown", (), (f"could not inspect .git: {error}",))


def _worktree_config(git_dir: Path) -> Path:
    common_dir = git_dir / "commondir"
    try:
        value = common_dir.read_text(encoding="utf-8").strip()
    except OSError:
        return git_dir / "config"
    if not value:
        return git_dir / "config"
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = git_dir / candidate
    candidate = Path(os.path.normpath(candidate))
    if candidate.is_dir() and not candidate.is_symlink():
        return candidate / "config"
    return git_dir / "config"
