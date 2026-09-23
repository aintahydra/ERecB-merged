"""Persistent Stage 2 workflows for fetching and recording repository intelligence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from collections.abc import Callable, Sequence
from typing import Any

from .cache import SqliteCache
from .config import ResolvedConfig
from .github_client import GithubClient, GithubRateLimitExhausted, GithubRequestError, OfflineError


class WorkflowError(RuntimeError):
    pass


class FetchRateLimitExhausted(WorkflowError):
    """A fetch run stopped at a safe checkpoint until GitHub resets its quota."""

    def __init__(
        self,
        *,
        run_id: int,
        reset_at: datetime,
        retry_after_seconds: float,
        completed: int,
        total: int,
    ) -> None:
        self.run_id = run_id
        self.reset_at = reset_at
        self.retry_after_seconds = retry_after_seconds
        self.completed = completed
        self.total = total
        super().__init__(f"GitHub rate limit exhausted until {reset_at.isoformat()}")


FetchProgress = Callable[[int, int, str], None]


def create_run(connection: sqlite3.Connection, *, kind: str, config: ResolvedConfig, repository_ids: Sequence[int] | None = None) -> int:
    payload = config.config.model_dump(mode="json")
    config_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    run_id = connection.execute(
        "INSERT INTO runs(kind, config_hash, duplicate_policy, status, started_at) VALUES (?, ?, ?, 'running', ?)",
        (kind, config_hash, config.config.scan.duplicate_policy, _now()),
    ).lastrowid
    selected = [int(row["id"]) for row in connection.execute("SELECT id FROM repositories ORDER BY id")] if repository_ids is None else list(dict.fromkeys(repository_ids))
    connection.executemany(
        "INSERT INTO run_items(run_id, repository_id, state, updated_at) VALUES (?, ?, 'pending', ?)",
        [(run_id, repository_id, _now()) for repository_id in selected],
    )
    connection.commit()
    return int(run_id)


def complete_run(connection: sqlite3.Connection, run_id: int, *, failed: bool = False) -> None:
    incomplete = connection.execute(
        "SELECT 1 FROM run_items WHERE run_id=? AND state IN ('pending', 'discovered', 'sources_captured', 'fetched', 'deterministic', 'enriched', 'validated') LIMIT 1",
        (run_id,),
    ).fetchone()
    unsuccessful = connection.execute("SELECT 1 FROM run_items WHERE run_id=? AND state IN ('failed', 'blocked_budget') LIMIT 1", (run_id,)).fetchone()
    status = "failed" if failed or unsuccessful else "interrupted" if incomplete else "complete"
    connection.execute("UPDATE runs SET status=?, completed_at=? WHERE id=?", (status, _now(), run_id))
    connection.commit()


def transition_item(connection: sqlite3.Connection, run_id: int, repository_id: int, state: str, *, error: Exception | None = None) -> None:
    valid = {"pending", "discovered", "sources_captured", "fetched", "deterministic", "enriched", "validated", "promoted", "complete", "failed", "blocked_budget", "skipped_reuse"}
    if state not in valid:
        raise ValueError(f"unsupported run-item state: {state}")
    connection.execute(
        "UPDATE run_items SET state=?, attempt_count=attempt_count+1, error_code=?, error_message=?, updated_at=? WHERE run_id=? AND repository_id=?",
        (state, type(error).__name__ if error else None, str(error) if error else None, _now(), run_id, repository_id),
    )
    connection.commit()


async def fetch_all(
    connection: sqlite3.Connection,
    config: ResolvedConfig,
    *,
    refresh: bool = False,
    client: GithubClient | None = None,
    run_id: int | None = None,
    progress: FetchProgress | None = None,
) -> int:
    """Fetch GitHub metadata and preferred README once per canonical repository."""
    if config.config.github.offline:
        raise OfflineError("GitHub HTTP is disabled by github.offline")
    run_id = create_run(connection, kind="fetch", config=config) if run_id is None else _resume_existing_run(connection, run_id, "fetch")
    own_client = client is None
    if client is None:
        client = GithubClient(
            token=config.provider_key("github"), offline=False,
            timeout_seconds=config.config.github.timeout_seconds,
            max_retries=config.config.github.max_retries,
            cache_ttl_hours=config.config.github.cache_ttl_hours,
            cache=SqliteCache(connection),
        )
    try:
        if own_client:
            await client.__aenter__()
        rows = connection.execute(
            "SELECT r.id, r.owner, r.name, r.identity_key, item.state, item.error_code, item.error_message "
            "FROM repositories r JOIN run_items item ON item.repository_id=r.id "
            "WHERE item.run_id=? AND item.state NOT IN ('complete', 'skipped_reuse') ORDER BY r.identity_key",
            (run_id,),
        ).fetchall()
        total = len(rows)
        for index, row in enumerate(rows, start=1):
            repository_id = int(row["id"])
            if progress is not None:
                progress(index, total, str(row["identity_key"]))
            try:
                state = str(row["state"])
                payload: dict[str, Any] | None = None
                completion_error = GithubRequestError(str(row["error_message"])) if state == "sources_captured" and row["error_message"] else None
                if state not in {"fetched", "sources_captured"}:
                    metadata = await client.repository(row["owner"], row["name"], refresh=refresh)
                    payload = metadata.payload
                    _store_snapshot(connection, repository_id, payload)
                    transition_item(connection, run_id, repository_id, "fetched")
                    state = "fetched"
                if state == "fetched":
                    readme_error: GithubRequestError | None = None
                    try:
                        readme = await client.readme(row["owner"], row["name"], refresh=refresh)
                        _store_github_readme(connection, repository_id, readme.payload, config.config.scan.max_document_bytes)
                    except GithubRateLimitExhausted:
                        raise
                    except GithubRequestError as error:
                        # A missing README does not discard verified repository metadata.
                        readme_error = error
                    transition_item(connection, run_id, repository_id, "sources_captured", error=readme_error)
                    completion_error = readme_error
                    state = "sources_captured"
                if state == "sources_captured":
                    payload = payload or _latest_snapshot_payload(connection, repository_id)
                    if payload is None:
                        raise WorkflowError(f"fetch checkpoint for repository {repository_id} has no GitHub snapshot")
                    owner = payload.get("owner") if payload is not None and isinstance(payload.get("owner"), dict) else {}
                    login = owner.get("login") if isinstance(owner.get("login"), str) else None
                    if owner.get("type") == "User" and login:
                        try:
                            profile = await client.profile(login, refresh=refresh)
                            _store_owner_profile(connection, repository_id, login, profile.payload, config.config.scan.max_document_bytes)
                        except GithubRateLimitExhausted:
                            raise
                        except GithubRequestError:
                            pass
                    transition_item(connection, run_id, repository_id, "complete", error=completion_error)
            except GithubRateLimitExhausted as error:
                _pause_fetch_item(connection, run_id, repository_id, error)
                _interrupt_run(connection, run_id)
                completed, run_total = _fetch_counts(connection, run_id)
                raise FetchRateLimitExhausted(
                    run_id=run_id,
                    reset_at=error.reset_at,
                    retry_after_seconds=error.retry_after_seconds,
                    completed=completed,
                    total=run_total,
                ) from error
            except (GithubRequestError, OfflineError) as error:
                transition_item(connection, run_id, repository_id, "failed", error=error)
        complete_run(connection, run_id)
        return run_id
    except FetchRateLimitExhausted:
        raise
    except Exception:
        complete_run(connection, run_id, failed=True)
        raise
    finally:
        if own_client:
            await client.__aexit__(None, None, None)


def _provider_settings(config: ResolvedConfig, provider_name: str | None = None) -> tuple[str, Any, Any]:
    selected_name, selected_config, selected_pricing = config.selected_provider()
    if provider_name is None or provider_name == selected_name:
        return selected_name, selected_config, selected_pricing
    if provider_name == "gemini":
        return "gemini", config.config.gemini, config.config.pricing.gemini
    if provider_name == "anthropic":
        return "anthropic", config.config.anthropic, config.config.pricing.anthropic
    if provider_name == "ollama":
        return "ollama", config.config.ollama, config.config.pricing.ollama
    raise WorkflowError(f"unsupported enrichment provider: {provider_name}")


def doctor_report(connection: sqlite3.Connection, config: ResolvedConfig) -> dict[str, Any]:
    """Return credential-safe readiness checks; this deliberately never contacts providers."""
    migrations = [row["version"] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
    provider_name, provider_config, pricing = _provider_settings(config)
    issues: list[str] = []
    if provider_config.enabled and provider_name != "ollama" and not config.provider_key(provider_name):
        issues.append(f"environment variable {provider_config.api_key_env} is not set")
    if provider_config.enabled and not provider_config.allow_source_upload:
        issues.append(f"{provider_name}.allow_source_upload=false prevents repository-text enrichment")
    if provider_config.enabled and provider_name != "ollama" and (pricing.input_usd_per_million_tokens <= 0 or pricing.output_usd_per_million_tokens <= 0):
        issues.append(f"{provider_name} pricing must be supplied by the operator before enrichment")
    return {
        "database_ok": migrations == [1, 2, 3, 4, 5, 6],
        "applied_migrations": migrations,
        "github_offline": config.config.github.offline,
        "enrichment_provider": provider_name,
        "provider_enabled": provider_config.enabled,
        "provider_ready": provider_config.enabled and not issues,
        "issues": issues,
        "network_checked": False,
        "configured_model": provider_config.model,
        "provider_model_checked": False,
        "provider_model_available": None,
    }


async def verify_configured_model(config: ResolvedConfig, *, provider: Any | None = None) -> str:
    """Verify selected-account model access without sending repository text."""
    provider_name, provider_config, _ = _provider_settings(config)
    if not provider_config.enabled:
        raise WorkflowError(f"{provider_name} model check requires {provider_name}.enabled=true")
    key = config.provider_key(provider_name)
    if provider_name != "ollama" and not key:
        raise WorkflowError(f"{provider_name} model check requires environment variable {provider_config.api_key_env}")
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
    verifier = getattr(provider, "verify_model", None)
    if not callable(verifier):
        raise WorkflowError(f"{provider_name} provider does not support model verification")
    name = await verifier()
    if not isinstance(name, str) or not name:
        raise WorkflowError(f"{provider_name} model check returned no model name")
    return name


async def verify_configured_gemini_model(config: ResolvedConfig, *, provider: Any | None = None) -> str:
    """Compatibility entry point for callers intentionally checking Gemini."""
    if config.config.enrichment.provider == "gemini":
        return await verify_configured_model(config, provider=provider)
    original = config.config.enrichment.provider
    config.config.enrichment.provider = "gemini"
    try:
        return await verify_configured_model(config, provider=provider)
    finally:
        config.config.enrichment.provider = original


def _store_snapshot(connection: sqlite3.Connection, repository_id: int, payload: dict[str, Any]) -> None:
    metadata = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(metadata.encode()).hexdigest()
    owner = payload.get("owner") if isinstance(payload.get("owner"), dict) else {}
    license_info = payload.get("license") if isinstance(payload.get("license"), dict) else {}
    parent = payload.get("parent") if isinstance(payload.get("parent"), dict) else {}
    stars = payload.get("stargazers_count")
    stars = stars if isinstance(stars, int) and not isinstance(stars, bool) and stars >= 0 else None
    license_spdx = license_info.get("spdx_id") if isinstance(license_info.get("spdx_id"), str) else None
    parent_name = parent.get("full_name") if isinstance(parent.get("full_name"), str) else None
    connection.execute(
        """INSERT OR IGNORE INTO github_snapshots(repository_id, owner_login, owner_display_name, owner_type,
           metadata_json, metadata_hash, captured_at, stars_count, license_spdx, is_fork, parent_full_name)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (repository_id, owner.get("login"), owner.get("name") or owner.get("login"), owner.get("type"), metadata, digest, _now(),
         stars, license_spdx, int(bool(payload.get("fork"))), parent_name),
    )
    _store_deterministic_finding(connection, repository_id, payload, digest)
    connection.commit()


def _latest_snapshot_payload(connection: sqlite3.Connection, repository_id: int) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT metadata_json FROM github_snapshots WHERE repository_id=? ORDER BY id DESC LIMIT 1",
        (repository_id,),
    ).fetchone()
    if row is None:
        return None
    value = json.loads(row["metadata_json"])
    return value if isinstance(value, dict) else None


def _pause_fetch_item(connection: sqlite3.Connection, run_id: int, repository_id: int, error: Exception) -> None:
    connection.execute(
        "UPDATE run_items SET attempt_count=attempt_count+1, error_code=?, error_message=?, updated_at=? "
        "WHERE run_id=? AND repository_id=?",
        (type(error).__name__, str(error), _now(), run_id, repository_id),
    )
    connection.commit()


def _interrupt_run(connection: sqlite3.Connection, run_id: int) -> None:
    connection.execute("UPDATE runs SET status='interrupted', completed_at=? WHERE id=?", (_now(), run_id))
    connection.commit()


def _fetch_counts(connection: sqlite3.Connection, run_id: int) -> tuple[int, int]:
    row = connection.execute(
        "SELECT SUM(CASE WHEN state IN ('complete', 'skipped_reuse') THEN 1 ELSE 0 END), COUNT(*) "
        "FROM run_items WHERE run_id=?",
        (run_id,),
    ).fetchone()
    return int(row[0] or 0), int(row[1])


def _store_deterministic_finding(connection: sqlite3.Connection, repository_id: int, payload: dict[str, Any], fingerprint: str) -> None:
    """Promote only GitHub's own short description; no ownership claim is inferred."""
    summary = payload.get("description")
    if not isinstance(summary, str) or not summary.strip():
        return
    current = connection.execute(
        "SELECT f.provenance FROM repository_current_findings current JOIN findings f ON f.id=current.finding_id WHERE current.repository_id=?",
        (repository_id,),
    ).fetchone()
    if current is not None and current["provenance"] != "deterministic-github-description":
        return
    existing = connection.execute(
        "SELECT id FROM findings WHERE repository_id=? AND input_fingerprint=? AND provenance='deterministic-github-description'",
        (repository_id, fingerprint),
    ).fetchone()
    if existing is None:
        version = connection.execute("SELECT COALESCE(MAX(version), 0) + 1 FROM findings WHERE repository_id=?", (repository_id,)).fetchone()[0]
        finding_id = connection.execute(
            "INSERT INTO findings(repository_id, version, input_fingerprint, summary, tool_types_json, capabilities_json, intended_uses_json, provenance, created_at) VALUES (?, ?, ?, ?, '[]', '[]', ?, 'deterministic-github-description', ?)",
            (repository_id, version, fingerprint, summary.strip(), json.dumps(payload.get("topics") if isinstance(payload.get("topics"), list) else []), _now()),
        ).lastrowid
    else:
        finding_id = existing["id"]
    connection.execute(
        "INSERT INTO repository_current_findings(repository_id, finding_id) VALUES (?, ?) ON CONFLICT(repository_id) DO UPDATE SET finding_id=excluded.finding_id",
        (repository_id, finding_id),
    )
    from .search import refresh_repository_search

    refresh_repository_search(connection, repository_id)


def _store_github_readme(connection: sqlite3.Connection, repository_id: int, payload: dict[str, Any], maximum: int) -> None:
    encoded = payload.get("content")
    if not isinstance(encoded, str) or payload.get("encoding") != "base64":
        raise GithubRequestError("README response was not base64 content")
    try:
        raw = base64.b64decode(encoded, validate=False)
    except (ValueError, binascii.Error) as error:
        raise GithubRequestError("README content could not be decoded") from error
    truncated = len(raw) > maximum
    raw = raw[:maximum]
    text = raw.decode("utf-8", errors="replace")
    locator = str(payload.get("path") or "README")
    digest = hashlib.sha256(raw).hexdigest()
    document = connection.execute(
        "SELECT id FROM source_documents WHERE repository_id=? AND local_copy_id IS NULL AND origin='github' AND locator=?",
        (repository_id, locator),
    ).fetchone()
    if document is None:
        document_id = connection.execute(
            "INSERT INTO source_documents(repository_id, local_copy_id, origin, kind, locator, translation, priority) VALUES (?, NULL, 'github', 'readme', ?, 0, 10)",
            (repository_id, locator),
        ).lastrowid
    else:
        document_id = document["id"]
    connection.execute(
        "INSERT OR IGNORE INTO source_versions(document_id, content_hash, content, byte_count, encoding, truncated, captured_at) VALUES (?, ?, ?, ?, 'utf-8', ?, ?)",
        (document_id, digest, text, len(raw), int(truncated), _now()),
    )
    connection.commit()


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _resume_existing_run(connection: sqlite3.Connection, run_id: int, expected_kind: str) -> int:
    row = connection.execute("SELECT kind, status FROM runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        raise WorkflowError(f"run {run_id} does not exist")
    if row["kind"] != expected_kind:
        raise WorkflowError(f"run {run_id} is {row['kind']}, not {expected_kind}")
    if row["status"] == "complete":
        raise WorkflowError(f"run {run_id} is already complete")
    connection.execute("UPDATE runs SET status='running', completed_at=NULL WHERE id=?", (run_id,))
    connection.commit()
    return run_id


async def resume_run(connection: sqlite3.Connection, config: ResolvedConfig, run_id: int, *, progress: FetchProgress | None = None) -> int:
    """Resume only incomplete items from an interrupted fetch or enrichment run."""
    row = connection.execute("SELECT kind FROM runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        raise WorkflowError(f"run {run_id} does not exist")
    if row["kind"] == "fetch":
        return await fetch_all(connection, config, refresh=True, run_id=run_id, progress=progress)
    if row["kind"] == "enrich":
        from .enrichment import enrich_all

        return await enrich_all(connection, config, run_id=run_id)
    raise WorkflowError(f"run {run_id} cannot be resumed")


def _store_owner_profile(connection: sqlite3.Connection, repository_id: int, login: str, payload: dict[str, Any], maximum: int) -> None:
    """Store bounded user-profile context as attributable evidence, not authorship."""
    fields = ("name", "bio", "company", "location", "blog")
    lines = ["GitHub user profile context only; this does not establish repository authorship.", f"login: {login}"]
    for field in fields:
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            lines.append(f"{field}: {value.strip()}")
    raw = "\n".join(lines).encode("utf-8")
    truncated = len(raw) > maximum
    raw = raw[:maximum]
    content = raw.decode("utf-8", errors="ignore")
    digest = hashlib.sha256(raw).hexdigest()
    locator = f"profile:{login.casefold()}"
    row = connection.execute(
        "SELECT id FROM source_documents WHERE repository_id=? AND local_copy_id IS NULL AND origin='github' AND locator=?",
        (repository_id, locator),
    ).fetchone()
    if row is None:
        document_id = connection.execute(
            "INSERT INTO source_documents(repository_id, local_copy_id, origin, kind, locator, translation, priority) VALUES (?, NULL, 'github', 'profile', ?, 0, 5)",
            (repository_id, locator),
        ).lastrowid
    else:
        document_id = row["id"]
    connection.execute(
        "INSERT OR IGNORE INTO source_versions(document_id, content_hash, content, byte_count, encoding, truncated, captured_at) VALUES (?, ?, ?, ?, 'utf-8', ?, ?)",
        (document_id, digest, content, len(raw), int(truncated), _now()),
    )
    connection.commit()
