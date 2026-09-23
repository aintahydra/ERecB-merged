"""Configuration loading and validation."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
import tomllib
from pathlib import Path
from urllib.parse import urlparse
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .models import LanguageCategory


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PathsConfig(StrictModel):
    input_dir: Path = Path("in")
    db_dir: Path = Path("dbs")
    output_dir: Path = Path("output")


class ScanConfig(StrictModel):
    duplicate_policy: Literal["reuse", "refresh"] = "reuse"
    follow_symlinks: bool = False
    max_document_bytes: int = Field(default=1_048_576, gt=0)
    max_source_bytes_per_repo: int = Field(default=4_194_304, gt=0)
    force_llm_on_unchanged: bool = False

    @model_validator(mode="after")
    def reject_symlinks(self) -> "ScanConfig":
        if self.follow_symlinks:
            raise ValueError("scan.follow_symlinks=true is not supported in version 1")
        return self


class GithubConfig(StrictModel):
    token_env: str = "GITHUB_TOKEN"
    offline: bool = False
    concurrency: int = Field(default=4, gt=0)
    cache_ttl_hours: int = Field(default=24, gt=0)
    max_retries: int = Field(default=5, ge=0)
    timeout_seconds: int = Field(default=30, gt=0)


class GeminiConfig(StrictModel):
    enabled: bool = True
    api_key_env: str = "GEMINI_API_KEY"
    model: str = "gemini-3.8-flash"
    concurrency: int = Field(default=1, gt=0)
    timeout_seconds: int = Field(default=90, gt=0)
    max_retries: int = Field(default=3, ge=0)
    max_output_tokens_per_request: int = Field(default=4096, gt=0)
    allow_source_upload: bool = True


class AnthropicConfig(GeminiConfig):
    """Claude-specific connection and output limits."""

    api_key_env: str = "ANTHROPIC_API_KEY"
    model: str = "claude-sonnet-4-6"


class OllamaConfig(StrictModel):
    """Local Ollama endpoint settings; no credential is stored or required."""

    enabled: bool = False
    endpoint: str = "http://127.0.0.1:11434"
    model: str = "gpt-oss:120b"
    concurrency: int = Field(default=1, gt=0)
    timeout_seconds: int = Field(default=300, gt=0)
    max_retries: int = Field(default=1, ge=0)
    max_output_tokens_per_request: int = Field(default=4096, gt=0)
    allow_source_upload: bool = True
    thinking: Literal["low", "medium", "high"] = "low"

    @field_validator("endpoint")
    @classmethod
    def endpoint_is_safe_http_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("ollama.endpoint must be a plain http or https base URL")
        return value.rstrip("/")


class EnrichmentConfig(StrictModel):
    """Selects the one provider that may receive bounded repository evidence."""

    provider: Literal["anthropic", "gemini", "ollama"] = "anthropic"


class BudgetsConfig(StrictModel):
    max_gemini_requests_per_run: int = Field(default=100, ge=0)
    max_input_tokens_per_run: int = Field(default=500_000, ge=0)
    max_output_tokens_per_run: int = Field(default=100_000, ge=0)
    max_cost_usd_per_run: float = Field(default=10.0, ge=0)
    max_repositories_enriched_per_run: int = Field(default=100, ge=0)

    @field_validator("max_cost_usd_per_run")
    @classmethod
    def finite_cost(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("max_cost_usd_per_run must be finite")
        return value


class LanguageConfig(StrictModel):
    minimum_letters: int = Field(default=100, ge=0)
    minimum_script_ratio: float = Field(default=0.20, ge=0, le=1)
    gemini_fallback: bool = True
    allowed_categories: list[LanguageCategory] = list(LanguageCategory)

    @model_validator(mode="after")
    def exact_categories(self) -> "LanguageConfig":
        if set(self.allowed_categories) != set(LanguageCategory):
            raise ValueError("language.allowed_categories must contain every supported category")
        return self


class GeminiPricing(StrictModel):
    input_usd_per_million_tokens: float = Field(default=0.0, ge=0)
    output_usd_per_million_tokens: float = Field(default=0.0, ge=0)


class AnthropicPricing(GeminiPricing):
    """Operator-maintained token prices for the Claude provider."""


class OllamaPricing(GeminiPricing):
    """Local Ollama inference has no provider token charge by default."""


class PricingConfig(StrictModel):
    gemini: GeminiPricing = GeminiPricing()
    anthropic: AnthropicPricing = AnthropicPricing()
    ollama: OllamaPricing = OllamaPricing()


class Config(StrictModel):
    version: Literal[1]
    paths: PathsConfig = PathsConfig()
    scan: ScanConfig = ScanConfig()
    github: GithubConfig = GithubConfig()
    gemini: GeminiConfig = GeminiConfig()
    anthropic: AnthropicConfig = AnthropicConfig()
    ollama: OllamaConfig = OllamaConfig()
    enrichment: EnrichmentConfig = EnrichmentConfig()
    budgets: BudgetsConfig = BudgetsConfig()
    language: LanguageConfig = LanguageConfig()
    pricing: PricingConfig = PricingConfig()

    @field_validator("github", "gemini", "anthropic")
    @classmethod
    def environment_variable_names(cls, value: GithubConfig | GeminiConfig | AnthropicConfig):
        env_name = value.token_env if isinstance(value, GithubConfig) else value.api_key_env
        if not env_name or any(char.isspace() for char in env_name):
            raise ValueError("environment variable names must be non-empty and contain no whitespace")
        return value

    def resolved(self, config_path: Path) -> "ResolvedConfig":
        base = config_path.parent.resolve()
        return ResolvedConfig(
            config=self,
            config_path=config_path.resolve(),
            input_dir=_resolve_path(base, self.paths.input_dir),
            db_dir=_resolve_path(base, self.paths.db_dir),
            output_dir=_resolve_path(base, self.paths.output_dir),
        )


class ResolvedConfig:
    def __init__(self, *, config: Config, config_path: Path, input_dir: Path, db_dir: Path, output_dir: Path):
        self.config = config
        self.config_path = config_path
        self.input_dir = input_dir
        self.db_dir = db_dir
        self.output_dir = output_dir

    @property
    def db_path(self) -> Path:
        return getattr(self, "_db_override", self.db_dir / "ghintel.sqlite3")

    def provider_key(self, name: Literal["github", "gemini", "anthropic", "ollama"]) -> str | None:
        if name == "github":
            env_name = self.config.github.token_env
        elif name == "gemini":
            env_name = self.config.gemini.api_key_env
        elif name == "anthropic":
            env_name = self.config.anthropic.api_key_env
        else:
            return None
        return os.environ.get(env_name)

    def selected_provider(self) -> tuple[str, GeminiConfig | AnthropicConfig | OllamaConfig, GeminiPricing | AnthropicPricing | OllamaPricing]:
        """Return the enabled provider's identifier, limits, and operator pricing."""
        if self.config.enrichment.provider == "anthropic":
            return "anthropic", self.config.anthropic, self.config.pricing.anthropic
        if self.config.enrichment.provider == "ollama":
            return "ollama", self.config.ollama, self.config.pricing.ollama
        return "gemini", self.config.gemini, self.config.pricing.gemini


def _resolve_path(base: Path, value: Path) -> Path:
    return value if value.is_absolute() else (base / value).resolve()


def load_config(path: Path) -> ResolvedConfig:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    return Config.model_validate(raw).resolved(path)


def persist_input_dir(path: Path, input_dir: Path) -> Path:
    """Atomically replace paths.input_dir and return its absolute value."""
    target = input_dir.expanduser().resolve()
    if not target.is_dir():
        raise ValueError(f"target directory does not exist or is not a directory: {target}")
    original = path.read_text(encoding="utf-8")
    updated = _replace_input_dir(original, target)
    Config.model_validate(tomllib.loads(updated))

    mode = path.stat().st_mode
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, mode & 0o7777)
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
        raise
    return target


def _replace_input_dir(text: str, target: Path) -> str:
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    value = json.dumps(os.fspath(target), ensure_ascii=False)
    section_start: int | None = None
    section_end = len(lines)

    for index, line in enumerate(lines):
        content = line.rstrip("\r\n").split("#", 1)[0].strip()
        if not re.fullmatch(r"\[[^\[\]]+\]", content):
            continue
        if content == "[paths]":
            section_start = index
            continue
        if section_start is not None:
            section_end = index
            break

    if section_start is not None:
        for index in range(section_start + 1, section_end):
            if re.match(r"^\s*input_dir\s*=", lines[index]):
                indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
                ending = "\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
                lines[index] = f"{indent}input_dir = {value}{ending}"
                return "".join(lines)
        lines.insert(section_start + 1, f"input_dir = {value}{newline}")
        return "".join(lines)

    separator = "" if not text or text.endswith(("\n", "\r")) else newline
    return f"{text}{separator}[paths]{newline}input_dir = {value}{newline}"
