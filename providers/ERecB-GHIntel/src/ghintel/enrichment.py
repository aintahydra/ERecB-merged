"""Budgeted provider orchestration; every provider result is validated before promotion."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from .budgets import BudgetExceeded, BudgetLimiter, BudgetLimits, Reservation, maximum_cost_micro_usd
from .config import ResolvedConfig
from .evidence import PROMPT_VERSION, RESPONSE_SCHEMA_VERSION
from .findings import build_provider_request, persist_deterministic_inference, record_provider_result
from .github_urls import normalize_github_url
from .languages import LanguageDetector, LinguaDetector
from .providers.base import EnrichmentProvider
from .stage2 import _resume_existing_run, complete_run, create_run, transition_item


class EnrichmentPreflightError(RuntimeError):
    pass


class BudgetReconciliationError(RuntimeError):
    pass


class EnrichmentSelectionError(RuntimeError):
    pass


def _preflight(config: ResolvedConfig, provider_name: str) -> str:
    """Validate selected provider settings without contacting it or exposing a key."""
    selected_name, provider_config, pricing = config.selected_provider()
    if provider_name != selected_name:
        if provider_name == "gemini":
            provider_config, pricing = config.config.gemini, config.config.pricing.gemini
        elif provider_name == "anthropic":
            provider_config, pricing = config.config.anthropic, config.config.pricing.anthropic
        else:
            provider_config, pricing = config.config.ollama, config.config.pricing.ollama
    failures: list[str] = []
    if not provider_config.enabled:
        failures.append(f"{provider_name}.enabled=false")
    if not provider_config.allow_source_upload:
        failures.append(f"{provider_name}.allow_source_upload=false")
    key = config.provider_key(provider_name)  # type: ignore[arg-type]
    if provider_name != "ollama" and not key:
        failures.append(f"environment variable {provider_config.api_key_env} is not set")
    if provider_name != "ollama" and (pricing.input_usd_per_million_tokens <= 0 or pricing.output_usd_per_million_tokens <= 0):
        failures.append(f"operator {provider_name} input/output pricing must both be positive")
    if failures:
        raise EnrichmentPreflightError(f"{provider_name} enrichment is not ready: " + "; ".join(failures))
    return key or ""


def preflight_provider(config: ResolvedConfig) -> str:
    """Validate the configured enrichment provider without contacting it."""
    return _preflight(config, config.config.enrichment.provider)


def preflight_gemini(config: ResolvedConfig) -> str:
    """Compatibility check for an explicitly configured Gemini provider."""
    return _preflight(config, "gemini")


async def enrich_all(connection: sqlite3.Connection, config: ResolvedConfig, *, provider: EnrichmentProvider | None = None, run_id: int | None = None, detector: LanguageDetector | None = None, repository_refs: tuple[str, ...] = (), limit: int | None = None) -> int:
    """Enrich each canonical repository once, enforcing all configured hard ceilings."""
    provider_name, provider_config, _ = config.selected_provider()
    key = preflight_provider(config)
    if provider is None:
        if provider_name == "anthropic":
            from .providers.anthropic import AnthropicProvider

            provider = AnthropicProvider(api_key=key, model=provider_config.model, timeout_seconds=provider_config.timeout_seconds, max_retries=provider_config.max_retries)
        elif provider_name == "ollama":
            from .providers.ollama import OllamaProvider

            provider = OllamaProvider(endpoint=provider_config.endpoint, model=provider_config.model, timeout_seconds=provider_config.timeout_seconds, max_retries=provider_config.max_retries, thinking=provider_config.thinking)
        else:
            from .providers.gemini import GeminiProvider

            provider = GeminiProvider(api_key=key, model=provider_config.model, timeout_seconds=provider_config.timeout_seconds, max_retries=provider_config.max_retries)
    limits = BudgetLimits(
        requests=config.config.budgets.max_gemini_requests_per_run,
        repositories=config.config.budgets.max_repositories_enriched_per_run,
        input_tokens=config.config.budgets.max_input_tokens_per_run,
        output_tokens=config.config.budgets.max_output_tokens_per_run,
        cost_micro_usd=int(config.config.budgets.max_cost_usd_per_run * 1_000_000),
    )
    if run_id is None:
        repository_ids = _select_repository_ids(connection, repository_refs, limit)
        run_id = create_run(connection, kind="enrich", config=config, repository_ids=repository_ids)
    else:
        if repository_refs or limit is not None:
            raise EnrichmentSelectionError("--repository and --limit cannot be used when resuming a run")
        run_id = _resume_existing_run(connection, run_id, "enrich")
    try:
        if detector is None:
            detector = _load_offline_detector()
        limiter = BudgetLimiter(limits, initial_usage=reconcile_budget_usage(connection, run_id))
        rows = connection.execute(
            "SELECT r.id FROM repositories r JOIN run_items item ON item.repository_id=r.id "
            "WHERE item.run_id=? AND item.state NOT IN ('complete', 'skipped_reuse') ORDER BY r.identity_key",
            (run_id,),
        ).fetchall()
        for row in rows:
            repository_id = int(row["id"])
            if _should_reuse(connection, repository_id, config):
                transition_item(connection, run_id, repository_id, "skipped_reuse")
                continue
            try:
                request = build_provider_request(
                    connection, repository_id, config.config.scan.max_source_bytes_per_repo,
                    provider_config.max_output_tokens_per_request,
                )
                cached = _cached_finding(connection, repository_id, provider.provider_name, provider.model, request.source_set_hash)
                if cached is not None and not config.config.scan.force_llm_on_unchanged:
                    _promote_cached(connection, repository_id, cached)
                    transition_item(connection, run_id, repository_id, "complete")
                    continue
                estimated_input = await provider.count_tokens(request.prompt)
                if estimated_input < 0:
                    raise ValueError("provider returned a negative token count")
                reserved = _reservation(config, estimated_input)
                await limiter.reserve(reserved)
                _ledger(connection, run_id, repository_id, None, "reserve", reserved)
                try:
                    result = await provider.enrich(request)
                except Exception:
                    await limiter.release(reserved)
                    _ledger(connection, run_id, repository_id, None, "release", reserved)
                    raise
                actual = _actual_reservation(config, result.input_tokens, result.output_tokens)
                if result.input_tokens < 0 or result.output_tokens < 0:
                    raise ValueError("provider returned negative usage")
                finding_id = record_provider_result(
                    connection, repository_id, provider=provider.provider_name, model=provider.model,
                    result=result, maximum_source_bytes=config.config.scan.max_source_bytes_per_repo,
                )
                attempt_id = _latest_attempt(connection, repository_id, provider.provider_name, provider.model, request.source_set_hash)
                if finding_id is not None:
                    persist_deterministic_inference(
                        connection, repository_id, detector=detector,
                        minimum_letters=config.config.language.minimum_letters,
                        minimum_script_ratio=config.config.language.minimum_script_ratio,
                    )
                _ledger(connection, run_id, repository_id, attempt_id, "commit", actual)
                _record_actual_cost(connection, attempt_id, actual.cost_micro_usd)
                await limiter.settle(reserved, actual)
                transition_item(connection, run_id, repository_id, "complete" if finding_id is not None else "failed")
            except BudgetExceeded as error:
                transition_item(connection, run_id, repository_id, "blocked_budget", error=error)
            except Exception as error:
                transition_item(connection, run_id, repository_id, "failed", error=error)
        complete_run(connection, run_id)
        return run_id
    except Exception:
        complete_run(connection, run_id, failed=True)
        raise


def reconcile_budget_usage(connection: sqlite3.Connection, run_id: int) -> Reservation:
    """Rebuild actual charges plus unresolved conservative reservations for one run."""
    outstanding: dict[int, list[Reservation]] = {}
    used = Reservation(0, 0, 0, 0, 0)
    rows = connection.execute(
        """SELECT run_item_id, kind, request_count, repository_count, input_tokens, output_tokens, cost_micro_usd
           FROM budget_ledger WHERE run_id=? ORDER BY id""",
        (run_id,),
    ).fetchall()
    for row in rows:
        item_id = row["run_item_id"]
        if item_id is None:
            raise BudgetReconciliationError("budget ledger row is missing its run item")
        value = Reservation(
            int(row["request_count"]), int(row["repository_count"]), int(row["input_tokens"]),
            int(row["output_tokens"]), int(row["cost_micro_usd"]),
        )
        stack = outstanding.setdefault(int(item_id), [])
        if row["kind"] == "reserve":
            stack.append(value)
        elif row["kind"] == "release":
            _consume_reservation(stack, value, "release")
        elif row["kind"] == "commit":
            _consume_reservation(stack, value, "commit", require_same_value=False)
            used = _combine_reservations(used, value)
        else:
            raise BudgetReconciliationError(f"unsupported budget ledger kind: {row['kind']}")
    for stack in outstanding.values():
        for value in stack:
            used = _combine_reservations(used, value)
    return used


def _consume_reservation(stack: list[Reservation], value: Reservation, kind: str, *, require_same_value: bool = True) -> None:
    if not stack:
        raise BudgetReconciliationError(f"budget ledger {kind} has no prior reserve")
    reserved = stack.pop()
    if require_same_value and reserved != value:
        raise BudgetReconciliationError(f"budget ledger {kind} does not match its reserve")


def _combine_reservations(left: Reservation, right: Reservation) -> Reservation:
    return Reservation(
        left.requests + right.requests,
        left.repositories + right.repositories,
        left.input_tokens + right.input_tokens,
        left.output_tokens + right.output_tokens,
        left.cost_micro_usd + right.cost_micro_usd,
    )


def _load_offline_detector() -> LanguageDetector | None:
    try:
        return LinguaDetector()
    except ImportError:
        return None


def _should_reuse(connection: sqlite3.Connection, repository_id: int, config: ResolvedConfig) -> bool:
    if config.config.scan.duplicate_policy != "reuse":
        return False
    return connection.execute("SELECT 1 FROM repository_current_findings WHERE repository_id=?", (repository_id,)).fetchone() is not None


def _cached_finding(connection: sqlite3.Connection, repository_id: int, provider: str, model: str, source_hash: str) -> int | None:
    row = connection.execute(
        """SELECT f.id FROM provider_cache cache
           JOIN provider_attempts attempt ON attempt.id=cache.attempt_id
           JOIN findings f ON f.repository_id=attempt.repository_id AND f.input_fingerprint=attempt.source_set_hash AND f.provenance=attempt.provider
           WHERE attempt.repository_id=? AND cache.provider=? AND cache.model=? AND cache.prompt_version=?
             AND cache.schema_version=? AND cache.validation_version='1' AND cache.source_set_hash=?
           ORDER BY attempt.id DESC LIMIT 1""",
        (repository_id, provider, model, PROMPT_VERSION, RESPONSE_SCHEMA_VERSION, source_hash),
    ).fetchone()
    return int(row["id"]) if row else None


def _promote_cached(connection: sqlite3.Connection, repository_id: int, finding_id: int) -> None:
    connection.execute(
        "INSERT INTO repository_current_findings(repository_id, finding_id) VALUES (?, ?) ON CONFLICT(repository_id) DO UPDATE SET finding_id=excluded.finding_id",
        (repository_id, finding_id),
    )
    connection.commit()


def _reservation(config: ResolvedConfig, input_tokens: int) -> Reservation:
    _, provider_config, price = config.selected_provider()
    output = provider_config.max_output_tokens_per_request
    return Reservation(1, 1, input_tokens, output, maximum_cost_micro_usd(input_tokens, output, price.input_usd_per_million_tokens, price.output_usd_per_million_tokens))


def _actual_reservation(config: ResolvedConfig, input_tokens: int, output_tokens: int) -> Reservation:
    price = config.selected_provider()[2]
    return Reservation(1, 1, input_tokens, output_tokens, maximum_cost_micro_usd(input_tokens, output_tokens, price.input_usd_per_million_tokens, price.output_usd_per_million_tokens))


def _ledger(connection: sqlite3.Connection, run_id: int, repository_id: int, attempt_id: int | None, kind: str, value: Reservation) -> None:
    item = connection.execute("SELECT id FROM run_items WHERE run_id=? AND repository_id=?", (run_id, repository_id)).fetchone()
    connection.execute(
        """INSERT INTO budget_ledger(run_id, run_item_id, provider_attempt_id, kind, request_count, repository_count,
           input_tokens, output_tokens, cost_micro_usd, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (run_id, item["id"], attempt_id, kind, value.requests, value.repositories, value.input_tokens,
         value.output_tokens, value.cost_micro_usd, _now()),
    )
    connection.commit()


def _latest_attempt(connection: sqlite3.Connection, repository_id: int, provider: str, model: str, source_hash: str) -> int:
    row = connection.execute(
        "SELECT id FROM provider_attempts WHERE repository_id=? AND provider=? AND model=? AND source_set_hash=? ORDER BY id DESC LIMIT 1",
        (repository_id, provider, model, source_hash),
    ).fetchone()
    if row is None:
        raise RuntimeError("provider attempt was not recorded")
    return int(row["id"])


def _record_actual_cost(connection: sqlite3.Connection, attempt_id: int, cost: int) -> None:
    connection.execute("UPDATE provider_attempts SET cost_micro_usd=? WHERE id=?", (cost, attempt_id))
    connection.commit()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _select_repository_ids(connection: sqlite3.Connection, references: tuple[str, ...], limit: int | None) -> list[int]:
    if limit is not None and limit < 1:
        raise EnrichmentSelectionError("limit must be positive")
    requested: set[str] = set()
    for reference in references:
        target = reference if "://" in reference or "@" in reference else f"https://github.com/{reference.strip('/')}"
        try:
            requested.add(normalize_github_url(target).identity_key)
        except ValueError as error:
            raise EnrichmentSelectionError(f"invalid repository selection {reference!r}: {error}") from error
    if requested:
        placeholders = ", ".join("?" for _ in requested)
        rows = connection.execute(
            f"SELECT id, identity_key FROM repositories WHERE identity_key IN ({placeholders}) ORDER BY identity_key",
            tuple(sorted(requested)),
        ).fetchall()
        found = {row["identity_key"] for row in rows}
        missing = sorted(requested - found)
        if missing:
            raise EnrichmentSelectionError("selected repository is not in the local database: " + ", ".join(missing))
    else:
        rows = connection.execute("SELECT id, identity_key FROM repositories ORDER BY identity_key").fetchall()
    selected = [int(row["id"]) for row in rows]
    return selected if limit is None else selected[:limit]
