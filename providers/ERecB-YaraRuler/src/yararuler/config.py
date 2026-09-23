from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from yararuler.errors import ConfigurationError

SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PathsConfig(StrictModel):
    rules_dir: Path = Path("rules")
    target_dir: Path = Path("in")


class RuleSource(StrictModel):
    name: str
    url: str
    ref: str | None = None
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not SOURCE_NAME.fullmatch(value):
            raise ValueError("must match [A-Za-z0-9][A-Za-z0-9._-]*")
        return value

    @field_validator("ref")
    @classmethod
    def valid_ref(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or value.startswith("-")
            or any(character.isspace() or ord(character) < 32 for character in value)
            or ".." in value
            or "//" in value
            or "@{" in value
            or value.endswith(("/", "."))
        ):
            raise ValueError("is not a safe Git ref")
        return value

    @field_validator("url")
    @classmethod
    def valid_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        parsed = urlsplit(value)
        is_scp_ssh = bool(re.match(r"^[^/@\s]+@[^:/\s]+:.+", value))
        is_local = parsed.scheme == "" and not is_scp_ssh
        if parsed.scheme not in {"", "https", "ssh", "file"} and not is_scp_ssh:
            raise ValueError("must use https, ssh, file, scp-style SSH, or a local path")
        if is_local and "\x00" in value:
            raise ValueError("contains a NUL byte")
        return value


class RulesConfig(StrictModel):
    cache_dir: Path = Path("rules/cache")
    quarantine_dir: Path = Path("rules/quarantine")
    sources: tuple[RuleSource, ...] = ()

    @model_validator(mode="after")
    def unique_sources(self) -> RulesConfig:
        names = [source.name for source in self.sources]
        if len(names) != len(set(names)):
            raise ValueError("rule source names must be unique")
        return self


class ScanConfig(StrictModel):
    threads: int = Field(default=1, ge=1)
    timeout_seconds: int = Field(default=30, ge=1)
    default_selector: Literal["all", "exec-only"] = "exec-only"
    follow_symlinks: bool = False
    include_strings: bool = False
    max_file_size_bytes: int = Field(default=0, ge=0)


class ReportConfig(StrictModel):
    format: Literal["json", "csv"] = "json"
    output: str = "report.json"
    pretty_json: bool = True


class LoggingConfig(StrictModel):
    level: str = "INFO"

    @field_validator("level")
    @classmethod
    def valid_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("must be CRITICAL, ERROR, WARNING, INFO, or DEBUG")
        return normalized


class AppConfig(StrictModel):
    paths: PathsConfig = PathsConfig()
    rules: RulesConfig = RulesConfig()
    scan: ScanConfig = ScanConfig()
    report: ReportConfig = ReportConfig()
    logging: LoggingConfig = LoggingConfig()
    config_path: Path = Field(exclude=True)

    @model_validator(mode="after")
    def non_overlapping_rule_paths(self) -> AppConfig:
        source_root = (self.paths.rules_dir / "sources").resolve()
        cache = self.rules.cache_dir.resolve()
        quarantine = self.rules.quarantine_dir.resolve()
        for left, right, label in (
            (source_root, cache, "source and cache directories"),
            (source_root, quarantine, "source and quarantine directories"),
            (cache, quarantine, "cache and quarantine directories"),
        ):
            if _contains(left, right) or _contains(right, left):
                raise ValueError(f"{label} must not overlap")
        return self


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _expand_path(value: Path, base: Path) -> Path:
    expanded = Path(os.path.expandvars(os.path.expanduser(str(value))))
    if not expanded.is_absolute():
        expanded = base / expanded
    return expanded.resolve()


def load_config(path: Path | str = Path("config.toml")) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"configuration file not found: {config_path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot read configuration {config_path}: {exc}") from exc

    base = config_path.parent
    try:
        parsed = AppConfig.model_validate({**raw, "config_path": config_path})
        resolved = parsed.model_copy(
            update={
                "paths": parsed.paths.model_copy(
                    update={
                        "rules_dir": _expand_path(parsed.paths.rules_dir, base),
                        "target_dir": _expand_path(parsed.paths.target_dir, base),
                    }
                ),
                "rules": parsed.rules.model_copy(
                    update={
                        "cache_dir": _expand_path(parsed.rules.cache_dir, base),
                        "quarantine_dir": _expand_path(parsed.rules.quarantine_dir, base),
                    }
                ),
            }
        )
        # Revalidate after path resolution so overlap checks use final paths.
        return AppConfig.model_validate(resolved.model_dump() | {"config_path": config_path})
    except ValidationError as exc:
        raise ConfigurationError(f"invalid configuration {config_path}: {exc}") from exc
