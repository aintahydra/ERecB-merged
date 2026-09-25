from __future__ import annotations

import logging
from pathlib import Path

import typer

from yararuler.config import AppConfig, load_config
from yararuler.errors import ConfigurationError, YaraRulerError
from yararuler.logging import configure_logging
from yararuler.report.service import ReportService
from yararuler.rules.update import RuleUpdateService
from yararuler.rules.exchange import export_cache, import_cache
from yararuler.rules.update import update_lock
from yararuler.scan.service import ScanService
from erecb_triage.mode import ModeError

app = typer.Typer(
    name="yararuler",
    help="Synchronize YARA rules and passively scan threat artifacts.",
    no_args_is_help=True,
    add_completion=False,
)
LOGGER = logging.getLogger(__name__)


@app.callback()
def root(
    ctx: typer.Context,
    config: Path = typer.Option(Path("config.toml"), "--config", help="TOML configuration file."),
    log_level: str | None = typer.Option(
        None, "--log-level", help="Override the configured log level."
    ),
) -> None:
    ctx.obj = {"config_path": config, "log_level": log_level}


def _configuration(ctx: typer.Context) -> AppConfig:
    config = load_config(ctx.obj["config_path"])
    try:
        configure_logging(ctx.obj["log_level"] or config.logging.level)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    return config


def _fail(exc: BaseException) -> None:
    code = exc.exit_code if isinstance(exc, YaraRulerError) else 2 if isinstance(exc, ModeError) else 70
    if code == 70:
        LOGGER.exception("unexpected internal error", exc_info=exc)
    typer.echo(f"error: {exc}", err=True)
    raise typer.Exit(code=code)


@app.command("update-rules")
def update_rules(
    ctx: typer.Context,
    mode_profile: Path | None = typer.Option(None, "--mode-profile"),
    source: list[str] | None = typer.Option(
        None, "--source", help="Additional repository URL for this update."
    ),
    force_rebuild: bool = typer.Option(
        False, "--force-rebuild", help="Rebuild even when source commits are unchanged."
    ),
) -> None:
    """Clone or update configured repositories and publish a validated cache."""
    try:
        from erecb_triage.mode import require_mode
        require_mode("connected", mode_profile)
        config = _configuration(ctx)
        summary = RuleUpdateService().update(
            config, extra_source_urls=source or [], force_rebuild=force_rebuild
        )
        typer.echo(
            f"active generation {summary.generation}: "
            f"sources={summary.sources} accepted={summary.accepted} "
            f"quarantined={summary.quarantined} cache={summary.cache_path}",
            err=True,
        )
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(exc)


@app.command("cache-export")
def cache_export(ctx: typer.Context, output: Path = typer.Option(..., "--output"),
                 mode_profile: Path | None = typer.Option(None, "--mode-profile")) -> None:
    """Package the verified active compiled generation for manual transfer."""
    try:
        from erecb_triage.mode import require_mode
        require_mode("connected", mode_profile)
        config = _configuration(ctx)
        typer.echo(f"exported generation {export_cache(config.rules.cache_dir, output)} to {output}")
    except Exception as exc:
        _fail(exc)


@app.command("cache-import")
def cache_import(ctx: typer.Context, source: Path = typer.Option(..., "--source"),
                 mode_profile: Path | None = typer.Option(None, "--mode-profile")) -> None:
    """Verify compatibility and atomically activate a transferred generation."""
    try:
        from erecb_triage.mode import require_mode
        require_mode("airgap", mode_profile)
        config = _configuration(ctx)
        with update_lock(config.paths.rules_dir / ".update.lock"):
            generation = import_cache(source, config.rules.cache_dir)
        typer.echo(f"activated generation {generation}")
    except Exception as exc:
        _fail(exc)


def _positive(value: int, label: str) -> int:
    if value < 1:
        raise ConfigurationError(f"{label} must be a positive integer")
    return value


def _configured_output(config: AppConfig, override: str | None) -> str:
    if override is not None:
        return override if override == "-" else str(Path(override).resolve())
    if config.report.output == "-":
        return "-"
    configured = Path(config.report.output).expanduser()
    if not configured.is_absolute():
        configured = config.config_path.parent / configured
    return str(configured.resolve())


@app.command("scan")
def scan(
    ctx: typer.Context,
    target_dir: Path | None = typer.Option(None, "--target-dir", help="Directory to scan."),
    all_files: bool = typer.Option(False, "--all", help="Scan all readable regular files."),
    exec_only: bool = typer.Option(
        False, "--exec-only", help="Scan executable and script candidates only."
    ),
    glob: list[str] | None = typer.Option(None, "--glob", help="Repeatable basename glob."),
    regex: list[str] | None = typer.Option(None, "--regex", help="Repeatable path regex."),
    threads: int | None = typer.Option(None, "--threads", help="Worker process count."),
    timeout: int | None = typer.Option(None, "--timeout", help="Per-file YARA timeout."),
    include_strings: bool = typer.Option(
        False, "--include-strings", help="Include matched identifiers and offsets."
    ),
    report_format: str | None = typer.Option(None, "--format", help="Report format: json or csv."),
    output: str | None = typer.Option(None, "--output", help="Report path, or - for stdout."),
) -> None:
    """Discover candidate files, scan them with the active cache, and report matches."""
    try:
        config = _configuration(ctx)
        if all_files and exec_only:
            raise ConfigurationError("--all and --exec-only are mutually exclusive")
        selector = (
            "all" if all_files else "exec-only" if exec_only else config.scan.default_selector
        )
        selected_target = target_dir.resolve() if target_dir else config.paths.target_dir
        selected_threads = _positive(
            threads if threads is not None else config.scan.threads, "threads"
        )
        selected_timeout = _positive(
            timeout if timeout is not None else config.scan.timeout_seconds, "timeout"
        )
        selected_format = report_format or config.report.format
        if selected_format not in {"json", "csv"}:
            raise ConfigurationError("format must be json or csv")
        selected_output = _configured_output(config, output)
        excluded: set[Path] = set()
        if selected_output != "-":
            output_path = Path(selected_output)
            excluded.add(output_path)
            if selected_format == "csv":
                excluded.add(Path(f"{output_path}.metadata.json"))
        summary = ScanService().scan(
            config,
            target_dir=selected_target,
            selector=selector,
            globs=glob or [],
            regexes=regex or [],
            threads=selected_threads,
            timeout_seconds=selected_timeout,
            include_strings=include_strings or config.scan.include_strings,
            excluded_paths=excluded,
        )
        ReportService().write(
            summary,
            output=selected_output,
            format=selected_format,
            pretty_json=config.report.pretty_json,
        )
        LOGGER.info(
            "scan complete: discovered=%d selected=%d scanned=%d matched_files=%d "
            "matches=%d errors=%d",
            summary.metadata.total_files_discovered,
            summary.metadata.total_files_selected,
            summary.metadata.total_files_scanned,
            summary.metadata.total_files_matched,
            summary.metadata.total_matches,
            summary.metadata.total_errors,
        )
        if summary.errors:
            raise typer.Exit(code=5)
    except typer.Exit:
        raise
    except Exception as exc:
        _fail(exc)


def main() -> None:
    app()
