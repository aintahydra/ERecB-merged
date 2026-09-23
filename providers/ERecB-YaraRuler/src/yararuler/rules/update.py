from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from yararuler.config import AppConfig, RuleSource
from yararuler.errors import RuleBuildError, RuleSyncError
from yararuler.models import UpdateSummary
from yararuler.rules.aggregate import compile_with_isolation
from yararuler.rules.cache import atomic_write_pointer
from yararuler.rules.compiler import (
    redact_url,
    sha256_file,
    validate_sources,
    yara_runtime,
)
from yararuler.rules.quarantine import stage_quarantine
from yararuler.rules.sync import source_name_from_url, synchronize_sources


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@contextmanager
def update_lock(path: Path) -> Iterator[None]:
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - supported targets provide fcntl
        raise RuleSyncError("rule update locking is unsupported on this platform") from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.seek(0)
            owner = handle.read().strip() or "unknown"
            raise RuleSyncError(f"another rule update holds the lock (PID {owner})") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _extra_sources(urls: list[str], configured: tuple[RuleSource, ...]) -> tuple[RuleSource, ...]:
    sources = list(configured)
    names = {source.name for source in sources}
    for url in urls:
        name = source_name_from_url(url)
        if name in names:
            raise RuleSyncError(f"extra source name collides with configured source: {name}")
        source = RuleSource(name=name, url=url)
        sources.append(source)
        names.add(name)
    return tuple(sources)


def _verify_in_fresh_process(path: Path) -> None:
    script = "import sys,yara; yara.load(sys.argv[1])"
    try:
        result = subprocess.run(
            [sys.executable, "-c", script, str(path)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuleBuildError(f"cache verification failed: {exc}") from exc
    if result.returncode:
        raise RuleBuildError(f"cache verification failed: {result.stderr.strip()[:2000]}")


def _publish_quarantine(staged: Path, destination: Path, generation: str) -> None:
    backup = destination.parent / f".{destination.name}-old-{generation}"
    if destination.exists():
        os.replace(destination, backup)
    try:
        os.replace(staged, destination)
    except Exception:
        if backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    shutil.rmtree(backup, ignore_errors=True)


class RuleUpdateService:
    def update(
        self,
        config: AppConfig,
        extra_source_urls: list[str] | None = None,
        force_rebuild: bool = False,
    ) -> UpdateSummary:
        del force_rebuild  # updates always rebuild from the resolved source commits
        started = time.monotonic()
        generation = str(uuid.uuid4())
        timestamp = utc_now()
        sources = _extra_sources(extra_source_urls or [], config.rules.sources)
        enabled = tuple(source for source in sources if source.enabled)
        if not enabled:
            raise RuleSyncError("no enabled rule sources are configured")
        cache_dir = config.rules.cache_dir
        generations = cache_dir / "generations"
        cache_dir.mkdir(parents=True, exist_ok=True)
        generations.mkdir(parents=True, exist_ok=True)

        with update_lock(config.paths.rules_dir / ".update.lock"):
            synced = synchronize_sources(config, enabled)
            accepted, rejected = validate_sources(synced)
            staging = cache_dir / f".staging-{generation}"
            quarantine_staging = config.rules.quarantine_dir.parent / f".quarantine-{generation}"
            staging.mkdir(parents=True, exist_ok=False)
            try:
                rules_path = staging / "rules.yac"
                accepted, aggregate_rejected = compile_with_isolation(accepted, rules_path)
                rejected.extend(aggregate_rejected)
                _verify_in_fresh_process(rules_path)
                artifact_digest = sha256_file(rules_path)
                manifest = {
                    "schema_version": 1,
                    "generation_id": generation,
                    "timestamp": timestamp,
                    "python_version": sys.version.split()[0],
                    "runtime": yara_runtime(),
                    "platform": platform.system(),
                    "machine": platform.machine(),
                    "sources": [
                        {
                            "name": source.name,
                            "url": redact_url(source.url),
                            "ref": source.ref,
                            "commit": source.commit,
                        }
                        for source in synced
                    ],
                    "accepted_rules": [
                        {
                            "source": entry.source,
                            "url": redact_url(entry.source_url),
                            "commit": entry.commit,
                            "path": entry.path,
                            "sha256": entry.sha256,
                            "namespace": entry.namespace,
                        }
                        for entry in accepted
                    ],
                    "rejected": [
                        {
                            key: value
                            for key, value in asdict(item).items()
                            if key != "absolute_path"
                        }
                        for item in rejected
                    ],
                    "counts": {
                        "sources": len(synced),
                        "accepted": len(accepted),
                        "quarantined": len(rejected),
                    },
                    "artifact": {
                        "filename": "rules.yac",
                        "sha256": artifact_digest,
                        "size": rules_path.stat().st_size,
                    },
                    "build_duration_seconds": round(time.monotonic() - started, 6),
                }
                with (staging / "manifest.json").open("w", encoding="utf-8") as handle:
                    handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                stage_quarantine(rejected, quarantine_staging, timestamp)
                generation_dir = generations / generation
                os.replace(staging, generation_dir)
                _publish_quarantine(quarantine_staging, config.rules.quarantine_dir, generation)
                atomic_write_pointer(cache_dir, generation)
            except Exception:
                shutil.rmtree(staging, ignore_errors=True)
                shutil.rmtree(quarantine_staging, ignore_errors=True)
                raise

        return UpdateSummary(
            generation=generation,
            sources=len(synced),
            accepted=len(accepted),
            quarantined=len(rejected),
            cache_path=generations / generation / "rules.yac",
        )
