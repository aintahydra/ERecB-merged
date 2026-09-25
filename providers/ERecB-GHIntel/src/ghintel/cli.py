"""Typer command-line interface for the local Stage 1 workflow."""

from __future__ import annotations

import asyncio
import json
import math
import shlex
import sqlite3
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from . import __version__

from .config import ResolvedConfig, load_config, persist_input_dir
from .database import database, initialize, list_project_cards, lookup_project_card, search_project_cards, upsert_requested_repository
from .search import SearchQueryError
from .corrections import CorrectionError, append_correction
from .exports import ExportError, export_csv, export_json
from .roots import RootRemapError, list_roots, remap_root
from .snapshots import SnapshotError, create_snapshot, verify_snapshot
from .github_urls import normalize_github_url
from .migrations import MigrationError
from .merge import merge_databases as merge_intelligence_databases
from .pipeline import run_discovery
from .stage2 import FetchRateLimitExhausted, create_run, doctor_report, fetch_all, resume_run, verify_configured_model
from .enrichment import enrich_all

app = typer.Typer(help="Local-first GitHub repository intelligence.", no_args_is_help=True, invoke_without_command=True)
db_app = typer.Typer(help="Database maintenance commands.", no_args_is_help=True)
roots_app = typer.Typer(help="Scan-root portability commands.", no_args_is_help=True)
app.add_typer(db_app, name="db")
app.add_typer(roots_app, name="roots")
requests_app = typer.Typer(help="Import verified offline repository requests.")
homework_app = typer.Typer(help="Inspect or process unresolved repository requests.")
app.add_typer(requests_app, name="requests")
app.add_typer(homework_app, name="homework")


def _require_mode(mode: str, profile: Path | None) -> None:
    from erecb_triage.mode import ModeError, require_mode

    try:
        require_mode(mode, profile)
    except ModeError as error:
        error_console.print(f"[red]Mode profile error:[/red] {error}")
        raise typer.Exit(2) from error


@db_app.command("merge")
def db_merge(
    source: Annotated[Path, typer.Option("--source")],
    dest: Annotated[Path, typer.Option("--dest")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    backup: Annotated[bool, typer.Option("--backup")] = False,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Merge a verified connected-machine snapshot into the air-gap database."""
    _require_mode("airgap", mode_profile)
    try:
        console.print_json(json.dumps(merge_intelligence_databases(
            source, dest, dry_run=dry_run, backup=backup,
        )))
    except (OSError, sqlite3.Error, ValueError, SnapshotError) as exc:
        error_console.print(f"[red]Merge failed:[/red] {exc}")
        raise typer.Exit(6) from exc
console = Console()
error_console = Console(stderr=True)


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", is_eager=True, help="Show the installed ghintel version")] = False,
) -> None:
    """Local-first GitHub repository intelligence."""
    if version:
        console.print(f"ghintel {__version__}")
        raise typer.Exit()


def _config(path: Path, db_override: Path | None = None) -> ResolvedConfig:
    try:
        config = load_config(path)
    except (OSError, ValidationError, ValueError) as error:
        error_console.print(f"[red]Configuration error:[/red] {error}")
        raise typer.Exit(2) from error
    if db_override is not None:
        config.db_dir = db_override.parent.resolve()
        config._db_override = db_override.resolve()  # type: ignore[attr-defined]
    return config


def _db_path(config: ResolvedConfig) -> Path:
    return getattr(config, "_db_override", config.db_path)


def _fetch_progress(current: int, total: int, identity: str) -> None:
    error_console.print(f"Fetching {current}/{total}: {identity}", markup=False)


def _homework_path(config: ResolvedConfig, override: Path | None) -> Path:
    return override or _db_path(config).with_name("ghintel-homework.sqlite3")


@requests_app.command("import")
def requests_import(
    bundle: Path,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    state: Annotated[Path | None, typer.Option("--state")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Validate and queue URLs only; this command never queries GitHub."""
    _require_mode("connected", mode_profile)
    from erecb_triage.homework import HomeworkQueue
    from erecb_triage.exchange import read_bundle

    resolved = _config(config)
    parsed = read_bundle(bundle)
    for item in parsed["repositories"]:
        identity = normalize_github_url(item["canonical_url"])
        if identity.identity_key != item["identity_key"] or identity.canonical_url != item["canonical_url"]:
            raise typer.BadParameter("repository normalization differs from GHIntel")
    with HomeworkQueue(_homework_path(resolved, state), "repository") as queue:
        console.print_json(json.dumps(queue.import_bundle(bundle)))


@homework_app.command("list")
def homework_list(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    state: Annotated[Path | None, typer.Option("--state")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    from erecb_triage.homework import HomeworkQueue

    _require_mode("connected", mode_profile)
    resolved = _config(config)
    with HomeworkQueue(_homework_path(resolved, state), "repository") as queue:
        console.print_json(json.dumps({"pause_until": queue.pause_until(), "items": queue.list_items()}))


@homework_app.command("run")
def homework_run(
    limit: Annotated[int, typer.Option("--limit", min=1)] = 20,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    state: Annotated[Path | None, typer.Option("--state")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Fetch and enrich newest eligible URL-only requests first."""
    from erecb_triage.homework import HomeworkQueue

    _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    initialize(_db_path(resolved))
    completed = []
    configured_force_llm = resolved.config.scan.force_llm_on_unchanged
    with HomeworkQueue(_homework_path(resolved, state), "repository") as queue:
        with database(_db_path(resolved)) as connection:
            for item in queue.lease(limit=limit):
                payload = json.loads(item["payload"])
                retry_delay = None
                try:
                    detail = None
                    repository = normalize_github_url(payload["canonical_url"])
                    if repository.identity_key != item["identity"]:
                        raise ValueError("repository normalization differs from request bundle")
                    repository_id = upsert_requested_repository(connection, payload["canonical_url"])
                    run_id = create_run(connection, kind="fetch", config=resolved, repository_ids=[repository_id])
                    asyncio.run(fetch_all(connection, resolved, refresh=True, run_id=run_id))
                    fetch_item = connection.execute(
                        "SELECT state, error_message FROM run_items WHERE run_id=? AND repository_id=?",
                        (run_id, repository_id),
                    ).fetchone()
                    if fetch_item is None or fetch_item["state"] != "complete":
                        # An older snapshot must not turn a failed current fetch into a
                        # successful refresh or trigger costly enrichment.
                        outcome = "not_found" if fetch_item and "404" in (fetch_item["error_message"] or "") else "error"
                        detail = fetch_item["error_message"] if fetch_item else "fetch run did not produce an item"
                    elif connection.execute(
                        "SELECT 1 FROM github_snapshots WHERE repository_id = ? LIMIT 1", (repository_id,),
                    ).fetchone() is None:
                        outcome = "not_found"
                    else:
                        # A forced all-indicators request explicitly refreshes old
                        # enrichment even if its source-set fingerprint is unchanged.
                        force_llm = configured_force_llm or item["selection"] == "all"
                        resolved.config.scan.force_llm_on_unchanged = force_llm
                        _configure_enrichment_mode(resolved, refresh=True,
                                                   force_llm=force_llm)
                        enrich_run_id = asyncio.run(enrich_all(
                            connection, resolved, repository_refs=(payload["canonical_url"],),
                        ))
                        run_item = connection.execute(
                            "SELECT state FROM run_items WHERE run_id=? AND repository_id=?",
                            (enrich_run_id, repository_id),
                        ).fetchone()
                        card = lookup_project_card(connection, item["identity"])
                        outcome = ("success" if run_item and run_item["state"] in {"complete", "skipped_reuse"}
                                   and card and card.get("github_status") == "available" else "error")
                except FetchRateLimitExhausted as exc:
                    outcome = "rate_limited"
                    detail = str(exc)
                    retry_delay = max(1, math.ceil(exc.retry_after_seconds))
                except Exception as exc:
                    outcome = "error"
                    detail = f"{type(exc).__name__}: {exc}"
                queue.finish(item["identity"], lease_token=item["lease_token"], outcome=outcome,
                             detail=detail, retry_after_seconds=retry_delay)
                completed.append({"repository": item["identity"], "outcome": outcome})
                if outcome == "rate_limited":
                    break
    console.print_json(json.dumps(completed))


def _report_rate_limit(error: FetchRateLimitExhausted, config: ResolvedConfig) -> None:
    reset = error.reset_at.astimezone().isoformat(timespec="seconds")
    remaining = max(0, error.total - error.completed)
    command = " ".join(
        shlex.quote(part)
        for part in (
            "ghintel",
            "resume",
            str(error.run_id),
            "--config",
            str(config.config_path),
            "--db",
            str(_db_path(config)),
        )
    )
    error_console.print("[yellow]GitHub rate limit exhausted; the fetch run was safely interrupted.[/yellow]")
    error_console.print(f"Completed: {error.completed}/{error.total}; remaining: {remaining}", markup=False)
    error_console.print(f"Resume after: {reset}", markup=False)
    error_console.print(f"Run: {error.run_id}", markup=False)
    error_console.print(f"Command: {command}", markup=False)




@roots_app.command("list")
def roots_list(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List logical scan roots tracked by this database."""
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            roots = list_roots(connection)
    except (OSError, MigrationError) as error:
        error_console.print(f"[red]Roots failed:[/red] {error}")
        raise typer.Exit(6) from error
    if as_json:
        console.print_json(json.dumps(roots))
        return
    table = Table("Name", "Path", "Updated")
    for root in roots:
        table.add_row(str(root["name"]), str(root["absolute_path"]), str(root["updated_at"]))
    console.print(table)


@roots_app.command("remap")
def roots_remap(
    name: str,
    new_path: Path,
    reason: Annotated[str, typer.Option("--reason")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Remap one logical scan root without changing its local-copy identities."""
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            plan = remap_root(connection, name, new_path, reason=reason, dry_run=dry_run)
    except (OSError, MigrationError, RootRemapError) as error:
        error_console.print(f"[red]Root remap failed:[/red] {error}")
        raise typer.Exit(2) from error
    action = "Would remap" if dry_run else "Remapped"
    console.print(f"{action} {plan.name}: {plan.old_path} -> {plan.new_path}")


@app.command()
def init(
    config: Annotated[Path, typer.Option("--config", help="Configuration file to create")] = Path("config.toml"),
    force: Annotated[bool, typer.Option("--force", help="Replace an existing configuration file")] = False,
) -> None:
    """Create configuration, runtime directories, and a migrated database."""
    if config.exists() and not force:
        error_console.print(f"[red]Refusing to overwrite existing configuration:[/red] {config}")
        raise typer.Exit(2)
    template = files("ghintel").joinpath("config.example.toml")
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    resolved = _config(config)
    resolved.input_dir.mkdir(parents=True, exist_ok=True)
    resolved.db_dir.mkdir(parents=True, exist_ok=True)
    resolved.output_dir.mkdir(parents=True, exist_ok=True)
    applied = initialize(resolved.db_path)
    console.print(f"Initialized {resolved.db_path} ({len(applied)} migration(s) applied).")


@app.command()
def discover(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Discover local Git repositories and persist local source evidence."""
    resolved = _config(config, db)
    try:
        run_id, count = run_discovery(resolved)
    except (OSError, MigrationError) as error:
        error_console.print(f"[red]Discovery failed:[/red] {error}")
        raise typer.Exit(6) from error
    payload = {"run_id": run_id, "repositories_found": count}
    if as_json:
        console.print_json(json.dumps(payload))
    else:
        console.print(f"Discovery run {run_id}: found {count} Git repository boundar{'y' if count == 1 else 'ies'}.")


@app.command()
def lookup(
    github_url: str,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Look up one supported GitHub address in the local database only."""
    try:
        repository = normalize_github_url(github_url)
    except ValueError as error:
        error_console.print(f"[red]Invalid GitHub URL:[/red] {error}")
        raise typer.Exit(2) from error
    resolved = _config(config, db)
    if not _db_path(resolved).exists():
        error_console.print("[red]Database not found.[/red] Run 'ghintel init' and 'ghintel discover' first.")
        raise typer.Exit(1)
    with database(_db_path(resolved)) as connection:
        card = lookup_project_card(connection, repository.identity_key)
    if card is None:
        message = {"identity_key": repository.identity_key, "information_status": "not-found"}
        if as_json:
            console.print_json(json.dumps(message))
        else:
            console.print(f"Not in database: {repository.canonical_url}")
        raise typer.Exit(1)
    _render_card(card, as_json)


@app.command(name="list")
def list_repositories(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List known canonical GitHub repositories."""
    resolved = _config(config, db)
    if not _db_path(resolved).exists():
        error_console.print("[red]Database not found.[/red] Run 'ghintel init' first.")
        raise typer.Exit(1)
    with database(_db_path(resolved)) as connection:
        cards = list_project_cards(connection)
    if as_json:
        console.print_json(json.dumps(cards))
        return
    table = Table("Repository", "Purpose", "Status", "GitHub", "Copies")
    for card in cards:
        table.add_row(str(card["canonical_url"]), str(card["purpose"] or "—"), str(card["information_status"]), str(card["github_status"]), str(len(card["local_copies"])))
    console.print(table)








@app.command(name="export")
def export_data(
    export_format: Annotated[str, typer.Option("--format", help="json or csv")] = "json",
    output: Annotated[Path | None, typer.Option("--output")] = None,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Export current project intelligence without raw source/provider/cache data."""
    resolved = _config(config, db)
    if export_format not in {"json", "csv"}:
        error_console.print("[red]Export failed:[/red] --format must be json or csv")
        raise typer.Exit(2)
    destination = output or (resolved.output_dir / ("ghintel.json" if export_format == "json" else "ghintel-csv"))
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            written = export_json(connection, destination) if export_format == "json" else export_csv(connection, destination)
    except (OSError, MigrationError, ExportError) as error:
        error_console.print(f"[red]Export failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Wrote {written}.")


@app.command()
def correct(
    repository: str,
    field_path: str,
    replacement_json: str,
    rationale: Annotated[str, typer.Option("--rationale")],
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Append a typed correction that overlays future project-card refreshes."""
    target = repository if "://" in repository or "@" in repository else f"https://github.com/{repository.strip('/')}"
    try:
        normalized = normalize_github_url(target)
        replacement = json.loads(replacement_json)
        resolved = _config(config, db)
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            row = connection.execute("SELECT id FROM repositories WHERE identity_key=?", (normalized.identity_key,)).fetchone()
            if row is None:
                raise CorrectionError(f"repository is not in the database: {normalized.canonical_url}")
            correction_id = append_correction(connection, int(row["id"]), field_path, replacement, rationale)
    except (OSError, MigrationError, CorrectionError, ValueError, json.JSONDecodeError) as error:
        error_console.print(f"[red]Correction failed:[/red] {error}")
        raise typer.Exit(2) from error
    console.print(f"Recorded correction {correction_id}.")


@app.command()
def search(
    query: str,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=100)] = 20,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search current local project cards with SQLite FTS5."""
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            cards = search_project_cards(connection, query, limit)
    except (OSError, MigrationError, SearchQueryError) as error:
        error_console.print(f"[red]Search failed:[/red] {error}")
        raise typer.Exit(2) from error
    if as_json:
        console.print_json(json.dumps(cards))
        return
    table = Table("Repository", "Purpose", "Status")
    for card in cards:
        table.add_row(str(card["canonical_url"]), str(card["purpose"] or "—"), str(card["information_status"]))
    console.print(table)


@app.command()
def show(
    repository: str,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show the detailed project card for a canonical URL or owner/name."""
    target = repository if "://" in repository or "@" in repository else f"https://github.com/{repository.strip('/') }"
    lookup(target, config, db, as_json)


@app.command()
def fetch(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Use conditional GitHub requests even when cached")] = False,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Fetch GitHub metadata and README evidence into the local database."""
    _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            run_id = asyncio.run(fetch_all(connection, resolved, refresh=refresh, progress=_fetch_progress))
    except FetchRateLimitExhausted as error:
        _report_rate_limit(error, resolved)
        raise typer.Exit(7) from error
    except (OSError, MigrationError, RuntimeError) as error:
        error_console.print(f"[red]Fetch failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Fetch run {run_id} recorded.")


@app.command()
def enrich(
    repository: Annotated[list[str] | None, typer.Option("--repository", "-r", help="Canonical URL or owner/name; repeatable")] = None,
    limit: Annotated[int | None, typer.Option("--limit", min=1, help="Maximum repositories in this new run")] = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Bypass current-finding reuse; validated provider cache may still be reused")] = False,
    force_llm: Annotated[bool, typer.Option("--force-llm", help="Recontact the provider even if unchanged evidence has a validated cache entry")] = False,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Run budgeted enrichment with the configured provider after local readiness checks pass."""
    _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    _configure_enrichment_mode(resolved, refresh=refresh, force_llm=force_llm)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            run_id = asyncio.run(enrich_all(connection, resolved, repository_refs=tuple(repository or ()), limit=limit))
    except (OSError, MigrationError, RuntimeError) as error:
        error_console.print(f"[red]Enrichment failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Enrichment run {run_id} recorded.")




@app.command()
def scan(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    target_dir: Annotated[Path | None, typer.Option("--target-dir", help="Persist this directory as paths.input_dir before scanning")] = None,
    refresh: Annotated[bool, typer.Option("--refresh", help="Use conditional GitHub requests")] = False,
    with_enrich: Annotated[bool, typer.Option("--enrich", help="Also run configured-provider enrichment after fetch")] = False,
    enrich_repository: Annotated[list[str] | None, typer.Option("--enrich-repository", help="Canonical URL or owner/name to enrich; repeatable")] = None,
    enrich_limit: Annotated[int | None, typer.Option("--enrich-limit", min=1, help="Maximum repositories to enrich in this scan")] = None,
    enrich_refresh: Annotated[bool, typer.Option("--enrich-refresh", help="Bypass reuse for the enrichment sub-run")] = False,
    enrich_force_llm: Annotated[bool, typer.Option("--enrich-force-llm", help="Recontact the provider for unchanged evidence")] = False,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Discover, then fetch; optionally enrich when the explicit gate is ready."""
    if (enrich_repository or enrich_limit is not None or enrich_refresh or enrich_force_llm) and not with_enrich:
        error_console.print("[red]Scan failed:[/red] --enrich target and refresh options require --enrich")
        raise typer.Exit(2)
    resolved = _config(config, db)
    if not resolved.config.github.offline:
        _require_mode("connected", mode_profile)
    if target_dir is not None:
        try:
            saved = persist_input_dir(resolved.config_path, target_dir)
            resolved = _config(resolved.config_path, db)
        except (OSError, ValidationError, ValueError) as error:
            error_console.print(f"[red]Scan failed:[/red] could not save --target-dir: {error}")
            raise typer.Exit(2) from error
        error_console.print(f"Saved paths.input_dir = {saved}", markup=False)
    try:
        discovery_run, discovered = run_discovery(resolved)
        fetch_run: int | None = None
        enrich_run: int | None = None
        if not resolved.config.github.offline:
            with database(_db_path(resolved)) as connection:
                fetch_run = asyncio.run(fetch_all(connection, resolved, refresh=refresh, progress=_fetch_progress))
        if with_enrich and not resolved.config.github.offline:
            _configure_enrichment_mode(resolved, refresh=enrich_refresh, force_llm=enrich_force_llm)
            with database(_db_path(resolved)) as connection:
                enrich_run = asyncio.run(enrich_all(connection, resolved, repository_refs=tuple(enrich_repository or ()), limit=enrich_limit))
    except FetchRateLimitExhausted as error:
        _report_rate_limit(error, resolved)
        raise typer.Exit(7) from error
    except (OSError, MigrationError, RuntimeError) as error:
        error_console.print(f"[red]Scan failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Discovery run {discovery_run}: {discovered} repository boundaries; fetch={fetch_run or 'skipped'}; enrich={enrich_run or 'skipped'}.")


@app.command()
def resume(
    run_id: int,
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Resume an interrupted fetch or enrichment run without redoing completed items."""
    _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            resumed = asyncio.run(resume_run(connection, resolved, run_id, progress=_fetch_progress))
    except FetchRateLimitExhausted as error:
        _report_rate_limit(error, resolved)
        raise typer.Exit(7) from error
    except (OSError, MigrationError, RuntimeError) as error:
        error_console.print(f"[red]Resume failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Resumed run {resumed}.")


@app.command()
def doctor(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
    check_provider: Annotated[bool, typer.Option("--check-provider", "--check-gemini", help="Verify the configured enrichment model; sends no repository text")] = False,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Check readiness; --check-provider additionally verifies account model access."""
    if check_provider:
        _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    try:
        initialize(_db_path(resolved))
        with database(_db_path(resolved)) as connection:
            report = doctor_report(connection, resolved)
    except (OSError, MigrationError) as error:
        error_console.print(f"[red]Doctor failed:[/red] {error}")
        raise typer.Exit(6) from error
    if check_provider:
        report["provider_model_checked"] = True
        try:
            report["provider_model_resource"] = asyncio.run(verify_configured_model(resolved))
            report["provider_model_available"] = True
        except Exception as error:
            report["provider_model_available"] = False
            report["provider_ready"] = False
            report["issues"].append(f"configured provider model check failed: {type(error).__name__}")
    if as_json:
        console.print_json(json.dumps(report))
        return
    console.print("Database: " + ("ready" if report["database_ok"] else "migration mismatch"))
    console.print(str(report["enrichment_provider"]).title() + ": " + ("ready" if report["provider_ready"] else "not ready"))
    if report["provider_model_checked"]:
        console.print("Configured model: " + ("available" if report["provider_model_available"] else "unavailable"))
    for issue in report["issues"]:
        console.print(f"- {issue}")




@db_app.command("snapshot")
def db_snapshot(
    output: Annotated[Path, typer.Option("--output", help="New snapshot path; must not already exist")],
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
    mode_profile: Annotated[Path | None, typer.Option("--mode-profile")] = None,
) -> None:
    """Create an online SQLite backup and checksum manifest."""
    _require_mode("connected", mode_profile)
    resolved = _config(config, db)
    try:
        info = create_snapshot(_db_path(resolved), output)
    except (OSError, MigrationError, SnapshotError) as error:
        error_console.print(f"[red]Snapshot failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Created {info.snapshot}; integrity_check={info.integrity_check}; manifest={info.manifest}.")


@db_app.command("verify")
def db_verify(
    snapshot: Path,
    manifest: Annotated[Path | None, typer.Option("--manifest")] = None,
) -> None:
    """Verify a snapshot manifest checksum and SQLite integrity check."""
    try:
        info = verify_snapshot(snapshot, manifest)
    except (OSError, SnapshotError) as error:
        error_console.print(f"[red]Snapshot verification failed:[/red] {error}")
        raise typer.Exit(2) from error
    console.print(f"Verified {info.snapshot}; schema={info.schema_version}; integrity_check={info.integrity_check}.")


@db_app.command("migrate")
def db_migrate(
    config: Annotated[Path, typer.Option("--config")] = Path("config.toml"),
    db: Annotated[Path | None, typer.Option("--db")] = None,
) -> None:
    """Apply pending numbered SQLite migrations."""
    resolved = _config(config, db)
    try:
        applied = initialize(_db_path(resolved))
    except (OSError, MigrationError) as error:
        error_console.print(f"[red]Migration failed:[/red] {error}")
        raise typer.Exit(6) from error
    console.print(f"Applied {len(applied)} migration(s).")


def _render_card(card: dict[str, object], as_json: bool) -> None:
    if as_json:
        console.print_json(json.dumps(card))
        return
    table = Table(title=str(card["canonical_url"]), show_header=False)
    table.add_row("Purpose", str(card["purpose"] or "Not enriched"))
    table.add_row("Status", str(card["information_status"]))
    table.add_row("GitHub availability", str(card["github_status"]))
    if card["github_error"]:
        table.add_row("GitHub detail", str(card["github_error"]))
    table.add_row("GitHub owner", _owner(card))
    table.add_row("Stars", str(card["stars_count"]) if card["stars_count"] is not None else "—")
    table.add_row("License", str(card["license_spdx"] or "—"))
    table.add_row("Fork", ("yes" + (f"; parent: {card['parent_url']}" if card["parent_url"] else "")) if card["is_fork"] else "no")
    table.add_row("Documented people", _people(card))
    table.add_row("Capabilities", ", ".join(card["capabilities"]) or "—")
    table.add_row("Intended uses", ", ".join(card["intended_uses"]) or "—")
    table.add_row("Local copies", "\n".join(card["local_copies"]) or "—")
    table.add_row("Finding provenance", str(card["finding_provenance"] or "—"))
    console.print(table)


def _owner(card: dict[str, object]) -> str:
    login = card.get("owner_login")
    if not login:
        return "Unknown (not fetched)"
    return f"{card.get('owner_type') or 'account'}: {card.get('owner_display_name') or login} ({login})"


def _people(card: dict[str, object]) -> str:
    people = card["documented_people"]
    if not people:
        return "Unknown"
    return "\n".join(f"{person['role']}: {person['name']}" for person in people)


if __name__ == "__main__":
    app()


def _configure_enrichment_mode(config: ResolvedConfig, *, refresh: bool, force_llm: bool) -> None:
    """Apply one-run reuse overrides without rewriting the operator's TOML file."""
    if force_llm:
        refresh = True
        config.config.scan.force_llm_on_unchanged = True
    if refresh:
        config.config.scan.duplicate_policy = "refresh"
