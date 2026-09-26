from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

from .errors import ConfigError


@dataclass(frozen=True)
class ScanConfig:
    follow_symlinks: bool
    max_file_size_bytes: int | None
    hash_block_size_bytes: int


@dataclass(frozen=True)
class EnrichmentConfig:
    enabled_providers: tuple[str, ...]
    provider_timeout_seconds: float
    provider_retry_count: int
    store_raw_responses: bool
    raw_response_dir: Path
    requery_success_after_days: int | None
    requery_failure_after_hours: int


@dataclass(frozen=True)
class CtxIoConfig:
    api_key_path: Path
    base_url: str


@dataclass(frozen=True)
class ProvidersConfig:
    ctx_io: CtxIoConfig


@dataclass(frozen=True)
class AppConfig:
    input_dir: Path
    watch_depth: int
    watch_interval_seconds: float
    database_path: Path
    log_level: str
    scan: ScanConfig
    enrichment: EnrichmentConfig
    providers: ProvidersConfig


DEFAULT_CONFIG: dict[str, Any] = {
    "input_dir": "in",
    "watch_depth": 1,
    "watch_interval_seconds": 10,
    "database_path": "dbs/fileintel.sqlite3",
    "log_level": "INFO",
    "scan": {
        "follow_symlinks": False,
        "max_file_size_bytes": None,
        "hash_block_size_bytes": 1024 * 1024,
    },
    "enrichment": {
        "enabled_providers": ["ctx_io"],
        "provider_timeout_seconds": 30,
        "provider_retry_count": 2,
        "store_raw_responses": False,
        "raw_response_dir": "data/provider_raw",
        "requery_success_after_days": None,
        "requery_failure_after_hours": 24,
    },
    "providers": {
        "ctx_io": {
            "api_key_path": "ctx_io_api_key.txt",
            "base_url": "https://api.ctx.io/v1",
        }
    },
}


def load_config(path: str | Path = "config.yaml") -> AppConfig:
    config_path = Path(path)
    data = _deep_merge(DEFAULT_CONFIG, _read_yaml(config_path))

    try:
        scan = data["scan"]
        enrichment = data["enrichment"]
        providers = data["providers"]
        ctx_io = providers["ctx_io"]

        cfg = AppConfig(
            input_dir=_resolve_path(data["input_dir"]),
            watch_depth=int(data["watch_depth"]),
            watch_interval_seconds=float(data["watch_interval_seconds"]),
            database_path=_resolve_path(data["database_path"]),
            log_level=str(data["log_level"]).upper(),
            scan=ScanConfig(
                follow_symlinks=bool(scan["follow_symlinks"]),
                max_file_size_bytes=_optional_int(scan["max_file_size_bytes"]),
                hash_block_size_bytes=int(scan["hash_block_size_bytes"]),
            ),
            enrichment=EnrichmentConfig(
                enabled_providers=tuple(enrichment["enabled_providers"]),
                provider_timeout_seconds=float(enrichment["provider_timeout_seconds"]),
                provider_retry_count=int(enrichment["provider_retry_count"]),
                store_raw_responses=bool(enrichment["store_raw_responses"]),
                raw_response_dir=_resolve_path(enrichment["raw_response_dir"]),
                requery_success_after_days=_optional_int(enrichment["requery_success_after_days"]),
                requery_failure_after_hours=int(enrichment["requery_failure_after_hours"]),
            ),
            providers=ProvidersConfig(
                ctx_io=CtxIoConfig(
                    api_key_path=_resolve_path(ctx_io["api_key_path"]),
                    base_url=str(ctx_io["base_url"]).rstrip("/"),
                )
            ),
        )
    except KeyError as exc:
        raise ConfigError(f"missing configuration key: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"invalid configuration value: {exc}") from exc

    validate_config(cfg)
    return cfg


def validate_config(config: AppConfig) -> None:
    if config.watch_depth < 1:
        raise ConfigError("watch_depth must be >= 1")
    if config.watch_interval_seconds <= 0:
        raise ConfigError("watch_interval_seconds must be > 0")
    if config.scan.hash_block_size_bytes <= 0:
        raise ConfigError("scan.hash_block_size_bytes must be > 0")
    if config.scan.max_file_size_bytes is not None and config.scan.max_file_size_bytes < 0:
        raise ConfigError("scan.max_file_size_bytes must be >= 0")
    if config.enrichment.provider_retry_count < 0:
        raise ConfigError("enrichment.provider_retry_count must be >= 0")

    known = {"ctx_io"}
    unknown = set(config.enrichment.enabled_providers) - known
    if unknown:
        raise ConfigError(f"unknown provider(s): {', '.join(sorted(unknown))}")
    config.database_path.parent.mkdir(parents=True, exist_ok=True)
    if config.enrichment.store_raw_responses:
        config.enrichment.raw_response_dir.mkdir(parents=True, exist_ok=True)


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        if path.name == "config.yaml":
            return {}
        raise ConfigError(f"configuration file does not exist: {path}")
    with path.open("r", encoding="utf-8") as fh:
        text = fh.read()
    if yaml is not None:
        data = yaml.safe_load(text) or {}
    else:
        data = _parse_simple_yaml(text)
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be a mapping")
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _resolve_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw_line = lines[index]
        line = raw_line.split("#", 1)[0].rstrip()
        index += 1
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            raise ConfigError("fallback YAML parser only supports key/value mappings")

        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        current = stack[-1][1]

        if raw_value:
            current[key] = _parse_scalar(raw_value)
            continue

        list_values, consumed = _parse_indented_list(lines, index, indent)
        if consumed:
            current[key] = list_values
            index += consumed
            continue

        nested: dict[str, Any] = {}
        current[key] = nested
        stack.append((indent, nested))
    return root


def _parse_indented_list(lines: list[str], start_index: int, parent_indent: int) -> tuple[list[Any], int]:
    values: list[Any] = []
    consumed = 0
    for raw_line in lines[start_index:]:
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            consumed += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent <= parent_indent:
            break
        if not stripped.startswith("- "):
            return [], 0
        values.append(_parse_scalar(stripped[2:].strip()))
        consumed += 1
    return values, consumed


def _parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "null":
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part.strip()) for part in inner.split(",")]
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value
