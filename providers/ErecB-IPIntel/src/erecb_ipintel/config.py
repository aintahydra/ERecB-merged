from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class PathsConfig:
    input_root: Path
    output_root: Path
    db_path: Path


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    recognition_depth: int = 1
    follow_symlinks: bool = False
    watch_interval_seconds: int = 60
    retry_failed_directories: bool = False


@dataclass(frozen=True, slots=True)
class ExtractionConfig:
    chunk_size_bytes: int = 1_048_576
    chunk_overlap_bytes: int = 256
    max_file_size_bytes: int | None = None
    include_hidden_files: bool = True
    include_hidden_directories: bool = True


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    store_raw_provider_json: bool = True


@dataclass(frozen=True, slots=True)
class CtxIoConfig:
    enabled: bool = True
    base_url: str = "https://api.ctx.io/v1"
    api_key: str | None = None
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_backoff_seconds: int = 2


@dataclass(frozen=True, slots=True)
class ProvidersConfig:
    ctx_io: CtxIoConfig


@dataclass(frozen=True, slots=True)
class AppConfig:
    root: Path
    paths: PathsConfig
    discovery: DiscoveryConfig
    extraction: ExtractionConfig
    database: DatabaseConfig
    providers: ProvidersConfig


DEFAULTS: dict[str, Any] = {
    "paths": {
        "input_root": "in",
        "output_root": "output",
        "db_path": "dbs/ipintel.sqlite3",
    },
    "discovery": {
        "recognition_depth": 1,
        "follow_symlinks": False,
        "watch_interval_seconds": 60,
        "retry_failed_directories": False,
    },
    "extraction": {
        "chunk_size_bytes": 1_048_576,
        "chunk_overlap_bytes": 256,
        "max_file_size_bytes": None,
        "include_hidden_files": True,
        "include_hidden_directories": True,
    },
    "database": {
        "store_raw_provider_json": True,
    },
    "providers": {
        "ctx_io": {
            "enabled": True,
            "base_url": "https://api.ctx.io/v1",
            "api_key": None,
            "timeout_seconds": 30,
            "retry_count": 3,
            "retry_backoff_seconds": 2,
        },
    },
}


def load_config(root: Path | None = None, config_path: Path | None = None) -> AppConfig:
    root = (root or Path.cwd()).resolve()
    data = _deep_copy(DEFAULTS)
    detected = config_path or _find_config(root)
    if detected:
        _deep_merge(data, _read_config_file(detected))

    if os.environ.get("ERECB_INPUT_ROOT"):
        data["paths"]["input_root"] = os.environ["ERECB_INPUT_ROOT"]
    if os.environ.get("ERECB_OUTPUT_ROOT"):
        data["paths"]["output_root"] = os.environ["ERECB_OUTPUT_ROOT"]
    if os.environ.get("ERECB_DB_PATH"):
        data["paths"]["db_path"] = os.environ["ERECB_DB_PATH"]
    if os.environ.get("CTX_IO_API_KEY"):
        data["providers"]["ctx_io"]["api_key"] = os.environ["CTX_IO_API_KEY"]

    paths = data["paths"]
    discovery = DiscoveryConfig(**data["discovery"])
    extraction = ExtractionConfig(**data["extraction"])
    database = DatabaseConfig(**data["database"])
    providers = ProvidersConfig(ctx_io=CtxIoConfig(**data["providers"]["ctx_io"]))

    if discovery.recognition_depth < 1:
        raise ValueError("discovery.recognition_depth must be 1 or greater")
    if extraction.chunk_overlap_bytes < 64:
        raise ValueError("extraction.chunk_overlap_bytes must be at least 64 bytes")
    if extraction.chunk_overlap_bytes >= extraction.chunk_size_bytes:
        raise ValueError("extraction.chunk_overlap_bytes must be smaller than chunk_size_bytes")

    return AppConfig(
        root=root,
        paths=PathsConfig(
            input_root=_resolve(root, paths["input_root"]),
            output_root=_resolve(root, paths["output_root"]),
            db_path=_resolve(root, paths["db_path"]),
        ),
        discovery=discovery,
        extraction=extraction,
        database=database,
        providers=providers,
    )


def _resolve(root: Path, value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _find_config(root: Path) -> Path | None:
    for name in ("config.yaml", "config.yml", "config.toml", "config.json"):
        path = root / name
        if path.exists():
            return path
    return None


def _read_config_file(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    if suffix == ".toml":
        return tomllib.loads(path.read_text(encoding="utf-8"))
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("YAML config requires PyYAML; use config.toml or config.json instead") from exc
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raise ValueError(f"unsupported config file type: {path}")


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _deep_copy(value: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value))
