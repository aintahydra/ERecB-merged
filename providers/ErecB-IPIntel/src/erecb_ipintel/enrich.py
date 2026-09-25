from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import tempfile

from .config import AppConfig
from .db import Database
from .models import IPTuple, NormalizedIntelRecord
from .progress import ProgressCallback
from .providers.base import ProviderAdapter
from .providers.ctx_io import CtxIoProvider


def parse_extraction_file(path: Path) -> set[IPTuple]:
    tuples: set[IPTuple] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            row = _parse_extraction_line(line)
            if row:
                tuples.add(row)
    return tuples


def _parse_extraction_line(line: str) -> IPTuple | None:
    line = line.rstrip("\r\n")
    if not line.strip() or ";" not in line:
        return None
    ip_text, source = line.split(";", 1)
    try:
        ip = str(ipaddress.ip_address(ip_text.strip()))
    except ValueError:
        return None
    return IPTuple(ip=ip, path=source.removeprefix(" ").strip())


def enabled_providers(config: AppConfig) -> list[ProviderAdapter]:
    providers: list[ProviderAdapter] = []
    if config.providers.ctx_io.enabled:
        providers.append(CtxIoProvider(config.providers.ctx_io, config.root))
    return providers


def enrich_file(
    path: Path,
    config: AppConfig,
    db: Database,
    provider_names: set[str] | None = None,
    progress: ProgressCallback | None = None,
    max_ips: int | None = None,
    consume: bool = False,
) -> dict[str, int | bool]:
    if max_ips is not None and max_ips < 1:
        raise ValueError("max_ips must be 1 or greater")

    tuples = parse_extraction_file(path)
    for row in tuples:
        db.add_observation(row.ip, row.path, str(path))
    unique_ips = sorted({row.ip for row in tuples}, key=lambda ip: (":" in ip, ip))
    selected_ips = unique_ips[:max_ips] if max_ips is not None else unique_ips
    result, completed_ips = _enrich_ips(selected_ips, config, db, str(path), provider_names, progress)
    result.pop("not_found", None)  # Preserve the legacy extraction-file result contract.
    remaining_tuples = {row for row in tuples if row.ip not in completed_ips}
    if consume and completed_ips:
        _remove_completed_ips(path, completed_ips)
    return {
        "tuples": len(tuples),
        "ips": len(unique_ips),
        "selected_ips": len(selected_ips),
        "completed_ips": len(completed_ips),
        "remaining_tuples": len(remaining_tuples),
        "remaining_ips": len({row.ip for row in remaining_tuples}),
        "consumed": consume,
        **result,
    }


def enrich_ip(
    ip: str,
    config: AppConfig,
    db: Database,
    provider_names: set[str] | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, int | bool]:
    canonical = str(ipaddress.ip_address(ip))
    result, completed_ips = _enrich_ips([canonical], config, db, None, provider_names, progress)
    return {"ips": 1, "completed_ips": len(completed_ips), **result}


def _enrich_ips(
    ips: list[str],
    config: AppConfig,
    db: Database,
    input_file: str | None,
    provider_names: set[str] | None,
    progress: ProgressCallback | None,
) -> tuple[dict[str, int | bool], set[str]]:
    total_success = 0
    total_failure = 0
    total_not_found = 0
    rate_limited = False
    provider_completions: list[set[str]] = []
    providers = [
        provider
        for provider in enabled_providers(config)
        if not provider_names or provider.name in provider_names
    ]
    for provider in providers:
        run_id = db.create_provider_run(provider.name, input_file, len(ips))
        success_count = 0
        failure_count = 0
        completed_for_provider: set[str] = set()
        stage = f"enrich {provider.name} unique IPs"
        if progress:
            progress(stage, 0, len(ips))
        for completed, ip in enumerate(ips, start=1):
            try:
                raw = provider.fetch(ip)
                record = provider.normalize(ip, raw, config.database.store_raw_provider_json)
                db.merge_intel(record, run_id, raw.status, raw.error_summary)
                if raw.status == "success":
                    success_count += 1
                    completed_for_provider.add(ip)
                elif raw.status == "not_found":
                    failure_count += 1
                    total_not_found += 1
                    completed_for_provider.add(ip)
                else:
                    failure_count += 1
                if raw.status_code == 429:
                    rate_limited = True
                    break
            except Exception as exc:
                record = NormalizedIntelRecord(ip=ip, provider_name=provider.name)
                db.merge_intel(record, run_id, "failed", f"{exc.__class__.__name__}: {exc}")
                failure_count += 1
            finally:
                if progress:
                    progress(stage, completed, len(ips))
        status = "complete" if failure_count == 0 else "partial_failed"
        db.finish_provider_run(run_id, status, success_count, failure_count)
        total_success += success_count
        total_failure += failure_count
        provider_completions.append(completed_for_provider)

    completed_ips = set.intersection(*provider_completions) if provider_completions else set()
    return (
        {
            "success": total_success,
            "failed": total_failure,
            "not_found": total_not_found,
            "rate_limited": rate_limited,
        },
        completed_ips,
    )


def _remove_completed_ips(path: Path, completed_ips: set[str]) -> None:
    """Atomically remove valid tuple lines for completed IPs, preserving other text."""

    source_mode = path.stat().st_mode
    temporary_path: Path | None = None
    try:
        with path.open("r", encoding="utf-8", newline="") as source:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as destination:
                temporary_path = Path(destination.name)
                for line in source:
                    row = _parse_extraction_line(line)
                    if row is None or row.ip not in completed_ips:
                        destination.write(line)
                destination.flush()
                os.fsync(destination.fileno())
        os.chmod(temporary_path, source_mode)
        os.replace(temporary_path, path)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
