from __future__ import annotations

from pathlib import Path
from typing import Any

from erecb_triage.ipintel.spec import MIN_CHUNK_OVERLAP_BYTES


REPORT_SUFFIXES = {
    "ip_retriever": "-ipintel.md",
    "file_retriever": "-fileintel.md",
    "ghintel": "-ghintel.md",
    "yara_scan": "-yara.md",
}


DEFAULT_CONFIG: dict[str, Any] = {
    "watch": {
        "path": "./in", "recursive": False, "event_debounce_ms": 500,
        "stable_check": {"enabled": True, "interval_ms": 250, "unchanged_checks": 3},
    },
    "logging": {
        "level": "INFO", "file_path": "./logs/erecb-triage.log",
        "max_bytes": 10 * 1024 ** 2, "backup_count": 10,
    },
    "dispatcher": {
        "max_workers": 1, "duplicate_policy": "skip_if_output_exists",
        "staging_index_path": "./data/staging.sqlite3",
        "staging_root": "./middle-earth", "output_root": "./output",
        "publish_summary": False,
    },
    "pipelines": {"on_added": {
        "preprocessors": {"processors": ["stage_input"]},
        "analysis": {"processors": []},
    }},
    "processors": {
        "stage_input": {
            "type": "input_stager", "output_root": "./middle-earth",
            "unarchiver": "unarchive_all_supported", "copy_directories": True,
            "copy_files": True,
            "archive_output_naming": {
                "strip_final_suffixes": [".en_dec", ".enc"],
                "timestamp_format": "%y%m%d-%H%M%S", "timezone": "UTC",
                "collision_policy": "append_counter",
            },
        },
        "artifact_inventory": {"type": "artifact_inventory", "max_entries": 200000},
        "unarchive_all_supported": {
            "type": "archive_unarchiver", "output_root": "./middle-earth",
            "max_depth_from_event_root": 2,
            "filename_regex": r".*\.(en_dec|enc|zip|tar\.gz)$",
            "supported_formats": [".en_dec", ".enc", ".zip", ".tar.gz"],
            # The production capacity envelope admits an 80 GB-class archive and a
            # 150 GB-class extraction while retaining a bounded decompression guard.
            "max_archive_size_bytes": 100 * 1024 ** 3,
            "max_total_extracted_bytes_per_archive": 200 * 1024 ** 3,
            "max_extracted_files_per_archive": 200000, "overwrite": False,
        },
        "ip_retriever": {
            "type": "ip_retriever", "db_path": "./dbs/ipintel.sqlite3",
            "output_root": "./output", "chunk_size_bytes": 1048576,
            "chunk_overlap_bytes": 256, "max_file_size_bytes": None,
            "ip_singularity_threshold": 20,
            "max_observations_per_file": 1024, "max_observations_per_capture": 10000,
            "follow_symlinks": False, "include_hidden_files": True,
            "include_hidden_directories": True, "report_suffix": "-ipintel.md",
        },
        "file_retriever": {
            "type": "file_retriever", "db_path": "./dbs/fileintel.sqlite3",
            "output_root": "./output", "max_depth_from_staged_root": None,
            "max_file_size_bytes": None, "hash_block_size_bytes": 1048576,
            "follow_symlinks": False, "include_hidden_files": True,
            "include_hidden_directories": True,
            "classifier": {"use_magic": True, "extension_fallback": True},
            "report_suffix": "-fileintel.md",
        },
        "ghintel": {
            "type": "ghintel", "db_path": "./dbs/ghintel.sqlite3", "output_root": "./output",
            "chunk_size_bytes": 1048576, "max_candidate_bytes": 2048,
            "max_depth_from_staged_root": None, "max_file_size_bytes": None,
            "follow_symlinks": False, "include_hidden_files": True,
            "include_hidden_directories": True, "report_suffix": "-ghintel.md",
        },
        "yara_scan": {
            "type": "yara_scan", "cache_dir": "./rules/cache", "output_root": "./output",
            "selector": "exec-only", "max_depth_from_staged_root": None,
            "max_file_size_bytes": None, "follow_symlinks": False,
            "include_hidden_files": True, "include_hidden_directories": True,
            "threads": 1, "timeout_seconds": 30, "include_strings": False,
            "max_string_instances_per_rule": 32, "report_suffix": "-yara.md",
        },
    },
}

def load_config(path: str | Path | None = None) -> dict[str, Any]:
    if path is None:
        config = _deep_copy(DEFAULT_CONFIG)
        validate_config(config)
        return config

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(config_path)

    with config_path.open("r", encoding="utf-8") as handle:
        text = handle.read()

    try:
        import yaml  # type: ignore
    except ImportError:
        loaded = _parse_simple_yaml(text)
    else:
        loaded = yaml.safe_load(text) or {}

    if not isinstance(loaded, dict):
        raise ValueError("configuration must be a mapping")
    config = _merge_dicts(_deep_copy(DEFAULT_CONFIG), loaded)
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    import re

    if not isinstance(config, dict):
        raise ValueError("configuration must be a mapping")
    logging_settings = config.get("logging", {})
    if not isinstance(logging_settings, dict):
        raise ValueError("logging must be a mapping")
    if logging_settings.get("level", "INFO") not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ValueError("logging.level must be DEBUG, INFO, WARNING, or ERROR")
    log_path = logging_settings.get("file_path")
    if not isinstance(log_path, str) or not log_path.strip() or "\x00" in log_path:
        raise ValueError("logging.file_path must be a nonempty path string without NUL")
    for key, minimum in (("max_bytes", 1), ("backup_count", 0)):
        value = logging_settings.get(key)
        if type(value) is not int or value < minimum:
            raise ValueError(f"logging.{key} must be an integer >= {minimum}")
    processors = config.get("processors", {})
    if not isinstance(processors, dict):
        raise ValueError("processors must be a mapping")
    if any(not isinstance(settings, dict) for settings in processors.values()):
        raise ValueError("processor settings must be mappings")
    watch = config.get("watch", {})
    if watch.get("recursive", False):
        raise ValueError("only direct-child watch events are supported")
    stable = watch.get("stable_check", {})
    for key, value, minimum in (
        ("event_debounce_ms", watch.get("event_debounce_ms", 500), 0),
        ("interval_ms", stable.get("interval_ms", 250), 1),
        ("unchanged_checks", stable.get("unchanged_checks", 3), 1),
    ):
        if type(value) is not int or value < minimum:
            raise ValueError(f"{key} must be an integer >= {minimum}")
    dispatcher = config.get("dispatcher", {})
    if dispatcher.get("max_workers", 1) != 1:
        raise ValueError("the synchronous dispatcher requires max_workers: 1")
    if dispatcher.get("duplicate_policy", "skip_if_output_exists") != "skip_if_output_exists":
        raise ValueError("unsupported duplicate_policy")
    if type(dispatcher.get("publish_summary", False)) is not bool:
        raise ValueError("dispatcher.publish_summary must be a boolean")
    for pipeline in config.get("pipelines", {}).values():
        for phase in ("preprocessors", "analysis"):
            names = pipeline.get(phase, {}).get("processors", [])
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise ValueError(f"{phase}.processors must be a list")
            if len(names) != len(set(names)):
                raise ValueError(f"{phase}.processors contains duplicate names")
            for name in names:
                if name not in processors:
                    raise ValueError(f"configured processor not found: {name}")
                is_stager = processors[name].get("type") in {"input_stager", "archive_unarchiver", "artifact_inventory"}
                if is_stager != (phase == "preprocessors"):
                    raise ValueError(f"{name}: processor is in the wrong pipeline phase")
    # The production profile exposes only formats with Phase 2 hostile-fixture coverage.
    supported = {".en_dec", ".enc", ".zip", ".tar.gz"}
    for name, settings in processors.items():
        kind = settings.get("type")
        if kind not in {"archive_unarchiver", "input_stager", "artifact_inventory", "ip_retriever", "file_retriever", "ghintel", "yara_scan"}:
            raise ValueError(f"unsupported processor type for {name}: {kind}")
        if kind == "file_retriever":
            try:
                file_retriever_settings(settings)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            continue
        if kind == "ip_retriever":
            try:
                ip_retriever_settings(settings)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            continue
        if kind == "ghintel":
            try:
                ghintel_settings(settings)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            continue
        if kind == "yara_scan":
            try:
                yara_scan_settings(settings)
            except ValueError as exc:
                raise ValueError(f"{name}: {exc}") from exc
            continue
        if kind == "artifact_inventory":
            value = settings.get("max_entries")
            if type(value) is not int or value < 1:
                raise ValueError(f"{name}: max_entries must be a positive integer")
            continue
        if not settings.get("output_root"):
            raise ValueError(f"{name}: output_root is required")
        if kind == "input_stager":
            unarchiver = processors.get(settings.get("unarchiver"), {})
            if unarchiver.get("type") != "archive_unarchiver":
                raise ValueError(f"{name}: unarchiver must name an archive_unarchiver")
            naming = settings.get("archive_output_naming", {})
            for key, expected in (("timezone", "UTC"), ("timestamp_format", "%y%m%d-%H%M%S"),
                                  ("collision_policy", "append_counter")):
                if naming.get(key, expected) != expected:
                    raise ValueError(f"{name}: {key} must be {expected}")
            suffixes = naming.get("strip_final_suffixes", [".en_dec", ".enc"])
            if not isinstance(suffixes, list) or any(s not in {".en_dec", ".enc"} for s in suffixes):
                raise ValueError(f"{name}: invalid strip_final_suffixes")
        elif kind == "archive_unarchiver":
            formats = settings.get("supported_formats", [])
            if not isinstance(formats, list) or not formats or any(f not in supported for f in formats):
                raise ValueError(f"{name}: invalid supported_formats")
            if settings.get("filename_regex") is not None:
                re.compile(settings["filename_regex"])
            for key in ("max_depth_from_event_root", "max_archive_size_bytes",
                        "max_total_extracted_bytes_per_archive", "max_extracted_files_per_archive"):
                value = settings.get(key)
                if value is not None and (type(value) is not int or value < 0):
                    raise ValueError(f"{name}: {key} must be nonnegative or null")


def file_retriever_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate without I/O and return independent settings with optional defaults filled."""
    if not isinstance(settings, dict) or settings.get("type") != "file_retriever":
        raise ValueError("type must be file_retriever")
    for key in ("db_path", "output_root"):
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"{key} must be a nonempty path string without NUL")
    if "classifier" in settings and not isinstance(settings["classifier"], dict):
        raise ValueError("classifier must be a mapping")
    resolved = _merge_dicts(_deep_copy(DEFAULT_CONFIG["processors"]["file_retriever"]), _deep_copy(settings))
    for key in ("max_depth_from_staged_root", "max_file_size_bytes"):
        value = resolved[key]
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{key} must be a nonnegative integer or null")
    block = resolved["hash_block_size_bytes"]
    if type(block) is not int or block < 1:
        raise ValueError("hash_block_size_bytes must be a positive integer")
    for key in ("follow_symlinks", "include_hidden_files", "include_hidden_directories"):
        if type(resolved[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    for key in ("use_magic", "extension_fallback"):
        if type(resolved["classifier"][key]) is not bool:
            raise ValueError(f"classifier.{key} must be a boolean")
    if not any(resolved["classifier"][key] for key in ("use_magic", "extension_fallback")):
        raise ValueError("at least one classifier method must be enabled")
    if resolved["report_suffix"] != REPORT_SUFFIXES["file_retriever"]:
        raise ValueError("report_suffix must be -fileintel.md")
    return resolved


def ip_retriever_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate IP extraction settings without reading staged files or SQLite databases."""
    if not isinstance(settings, dict) or settings.get("type") != "ip_retriever":
        raise ValueError("type must be ip_retriever")
    for key in ("db_path", "output_root"):
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"{key} must be a nonempty path string without NUL")
    resolved = _merge_dicts(_deep_copy(DEFAULT_CONFIG["processors"]["ip_retriever"]), _deep_copy(settings))
    for key in ("chunk_size_bytes", "chunk_overlap_bytes"):
        value = resolved[key]
        minimum = 1 if key == "chunk_size_bytes" else MIN_CHUNK_OVERLAP_BYTES
        if type(value) is not int or value < minimum:
            raise ValueError(f"{key} must be an integer >= {minimum}")
    limit = resolved["max_file_size_bytes"]
    if limit is not None and (type(limit) is not int or limit < 0):
        raise ValueError("max_file_size_bytes must be a nonnegative integer or null")
    for key in ("ip_singularity_threshold", "max_observations_per_file", "max_observations_per_capture"):
        if type(resolved[key]) is not int or resolved[key] < 1:
            raise ValueError(f"{key} must be a positive integer")
    if resolved["ip_singularity_threshold"] > resolved["max_observations_per_file"]:
        raise ValueError("ip_singularity_threshold must not exceed max_observations_per_file")
    for key in ("follow_symlinks", "include_hidden_files", "include_hidden_directories"):
        if type(resolved[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    if resolved["report_suffix"] != REPORT_SUFFIXES["ip_retriever"]:
        raise ValueError("report_suffix must be -ipintel.md")
    return resolved


def ghintel_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate offline GHIntel settings without opening a producer database."""
    if not isinstance(settings, dict) or settings.get("type") != "ghintel":
        raise ValueError("type must be ghintel")
    for key in ("db_path", "output_root"):
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"{key} must be a nonempty path string without NUL")
    resolved = _merge_dicts(_deep_copy(DEFAULT_CONFIG["processors"]["ghintel"]), _deep_copy(settings))
    for key in ("chunk_size_bytes", "max_candidate_bytes"):
        value = resolved[key]
        if type(value) is not int or value < 1:
            raise ValueError(f"{key} must be a positive integer")
    for key in ("max_depth_from_staged_root", "max_file_size_bytes"):
        value = resolved[key]
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{key} must be a nonnegative integer or null")
    for key in ("follow_symlinks", "include_hidden_files", "include_hidden_directories"):
        if type(resolved[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    if resolved["report_suffix"] != REPORT_SUFFIXES["ghintel"]:
        raise ValueError("report_suffix must be -ghintel.md")
    return resolved


def yara_scan_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Validate YaraRuler-consumer settings without loading YARA or its cache."""
    if not isinstance(settings, dict) or settings.get("type") != "yara_scan":
        raise ValueError("type must be yara_scan")
    for key in ("cache_dir", "output_root"):
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(f"{key} must be a nonempty path string without NUL")
    resolved = _merge_dicts(_deep_copy(DEFAULT_CONFIG["processors"]["yara_scan"]), _deep_copy(settings))
    if resolved["selector"] != "exec-only":
        raise ValueError("selector must be exec-only")
    for key in ("max_depth_from_staged_root", "max_file_size_bytes"):
        value = resolved[key]
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"{key} must be a nonnegative integer or null")
    if resolved["follow_symlinks"] is not False:
        raise ValueError("follow_symlinks must be false in version 1")
    for key in ("include_hidden_files", "include_hidden_directories", "include_strings"):
        if type(resolved[key]) is not bool:
            raise ValueError(f"{key} must be a boolean")
    for key in ("threads", "timeout_seconds", "max_string_instances_per_rule"):
        if type(resolved[key]) is not int or resolved[key] < 1:
            raise ValueError(f"{key} must be a positive integer")
    if resolved["report_suffix"] != REPORT_SUFFIXES["yara_scan"]:
        raise ValueError("report_suffix must be -yara.md")
    return resolved


def resolve_path(base_dir: Path, value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _deep_copy(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_deep_copy(item) for item in value]
    return value


def _merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge_dicts(base[key], value)
        else:
            base[key] = value
    return base


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    lines = text.splitlines()

    for index, raw_line in enumerate(lines, start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"line {index}: list item has no list parent")
            parent.append(_parse_scalar(line[2:].strip()))
            continue

        if ":" not in line:
            raise ValueError(f"line {index}: expected key-value pair")

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            child = _next_container(lines, index, indent)
            if not isinstance(parent, dict):
                raise ValueError(f"line {index}: mapping entry has no mapping parent")
            parent[key] = child
            stack.append((indent, child))
            continue

        if not isinstance(parent, dict):
            raise ValueError(f"line {index}: mapping entry has no mapping parent")
        parent[key] = _parse_scalar(value)

    return root


def _next_container(lines: list[str], current_index: int, current_indent: int) -> Any:
    for raw_line in lines[current_index:]:
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent <= current_indent:
            return {}
        return [] if raw_line.strip().startswith("- ") else {}
    return {}


def _parse_scalar(value: str) -> Any:
    if value.startswith("[") or value.startswith("{"):
        import json
        return json.loads(value)
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "Null", "~"}:
        return None
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        value = value[1:-1]
        return value.replace(r"\\", "\\")
    try:
        return int(value)
    except ValueError:
        return value
