from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from yararuler.config import AppConfig, RuleSource
from yararuler.errors import RuleSyncError
from yararuler.models import SyncedSource

GIT_TIMEOUT_SECONDS = 180


def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.username is None:
        return value
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, parsed.path, parsed.query, parsed.fragment))


def source_name_from_url(url: str) -> str:
    cleaned = url.rstrip("/")
    name = cleaned.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    name = name.removesuffix(".git")
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-.")
    if not name or not name[0].isalnum():
        raise RuleSyncError(f"cannot derive a source name from {redact_url(url)}")
    return name


class GitRunner:
    def run(self, args: list[str], cwd: Path | None = None) -> str:
        env = os.environ.copy()
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"})
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=cwd,
                env=env,
                text=True,
                capture_output=True,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuleSyncError(f"git operation failed: {exc}") from exc
        if result.returncode:
            detail = redact_url(result.stderr.strip() or result.stdout.strip())
            operation = args[0] if args else "command"
            raise RuleSyncError(f"git {operation} failed: {detail[:2000]}")
        return result.stdout.strip()


def _canonical_url(url: str, base: Path) -> str:
    parsed = urlsplit(url)
    if not parsed.scheme and not re.match(r"^[^/@\s]+@[^:/\s]+:.+", url):
        return str((base / os.path.expanduser(os.path.expandvars(url))).resolve())
    return url.rstrip("/").removesuffix(".git")


def _checkout_fetched_ref(git: GitRunner, checkout: Path, ref: str | None) -> None:
    if ref:
        git.run(["fetch", "--prune", "origin", ref], cwd=checkout)
        git.run(["checkout", "--detach", "FETCH_HEAD"], cwd=checkout)
        return
    git.run(["fetch", "--prune", "origin"], cwd=checkout)
    try:
        remote_head = git.run(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=checkout)
    except RuleSyncError:
        remote_head = "origin/HEAD"
    git.run(["checkout", "--detach", remote_head], cwd=checkout)


def _sync_one(source: RuleSource, destination: Path, base: Path, git: GitRunner) -> SyncedSource:
    configured_url = _canonical_url(source.url, base)
    if destination.exists():
        if not (destination / ".git").is_dir():
            raise RuleSyncError(f"source destination is not a Git checkout: {destination}")
        status = git.run(["status", "--porcelain"], cwd=destination)
        if status:
            raise RuleSyncError(f"source checkout has local changes: {destination}")
        actual_url = git.run(["remote", "get-url", "origin"], cwd=destination)
        if _canonical_url(actual_url, base) != configured_url:
            raise RuleSyncError(
                f"origin URL mismatch for {source.name}: "
                f"{redact_url(actual_url)} != {redact_url(source.url)}"
            )
        _checkout_fetched_ref(git, destination, source.ref)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging_parent = Path(tempfile.mkdtemp(prefix=f".{source.name}-", dir=destination.parent))
        checkout = staging_parent / "checkout"
        try:
            git.run(["clone", "--no-checkout", configured_url, str(checkout)])
            _checkout_fetched_ref(git, checkout, source.ref)
            os.replace(checkout, destination)
        finally:
            shutil.rmtree(staging_parent, ignore_errors=True)
    commit = git.run(["rev-parse", "HEAD"], cwd=destination)
    return SyncedSource(
        name=source.name,
        url=redact_url(source.url),
        ref=source.ref,
        commit=commit,
        path=destination.resolve(),
    )


def synchronize_sources(
    config: AppConfig,
    sources: tuple[RuleSource, ...],
    git: GitRunner | None = None,
) -> list[SyncedSource]:
    runner = git or GitRunner()
    root = config.paths.rules_dir / "sources"
    root.mkdir(parents=True, exist_ok=True)
    synced: list[SyncedSource] = []
    for source in sources:
        if source.enabled:
            synced.append(_sync_one(source, root / source.name, config.config_path.parent, runner))
    return synced
