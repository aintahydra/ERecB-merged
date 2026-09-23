"""Offline YaraRuler adapter over a verified immutable compiled-rule cache."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from erecb_triage.config import resolve_path, yara_scan_settings
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult
from erecb_triage.yarascan.cache import CacheError, YaraDependencyError, default_rule_loader, pin_cache
from erecb_triage.yarascan.discovery import discover
from erecb_triage.yarascan.matcher import scan_file
from erecb_triage.yarascan.report import publish_report, render_report


class YaraScan(Processor):
    """Scan only authorized staged files; source-rule build/update is intentionally absent."""

    def __init__(self, name: str, config: dict, *, rule_loader: Callable[[Path], Any] | None = None, clock=None) -> None:
        self.name, self.config, self.clock = name, yara_scan_settings(config), clock
        # Fail startup only for a selected real adapter; injected loaders keep dependency-free tests possible.
        if rule_loader is None:
            try:
                default_rule_loader  # make the optional boundary explicit before dispatch begins
                import yara  # type: ignore # noqa: F401
            except ImportError as exc:
                raise YaraDependencyError("yara-python is required by the yara_scan profile; install erecb-triage[yara]") from exc
        self.rule_loader = rule_loader or default_rule_loader

    def accepts(self, records, context) -> bool:
        return any(record.get("type") == "staged_capture" for record in records)

    def process(self, input_records, context) -> ProcessorResult:
        records: list[dict] = []
        errors: list[ProcessorError] = []
        metrics = {"yara_files_discovered": 0, "yara_files_selected": 0, "yara_files_size_skipped": 0,
                   "yara_files_skipped": 0, "yara_files_scanned": 0, "yara_files_matched": 0, "yara_rule_matches": 0,
                   "yara_cache_unavailable": 0}
        for capture in input_records:
            if capture.get("type") != "staged_capture":
                continue
            try:
                context.authorize_capture(capture)
                expected = resolve_path(context.base_dir, self.config["output_root"]) / (capture["report_stem"] + self.config["report_suffix"])
                if context.report_path(capture, self.name) != expected:
                    raise ValueError("configured report disagrees with reservation")
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(context.event.path, str(exc), "yara_report_error")); continue
            capture_errors: list[ProcessorError] = []
            capture_records: list[dict] = []
            cache_generation = None
            try:
                cache = pin_cache(resolve_path(context.base_dir, self.config["cache_dir"]), loader=self.rule_loader)
                cache_generation = cache.generation
                discovery = discover(Path(capture["staged_path"]), self.config)
                capture_errors.extend(discovery.errors)
                for key, value in discovery.metrics.items(): metrics[key] += value
                for candidate in discovery.files:
                    matches, error = scan_file(candidate, cache, self.config, context.base_dir)
                    metrics["yara_files_scanned"] += 1
                    if error:
                        capture_errors.append(error); continue
                    if matches:
                        metrics["yara_files_matched"] += 1
                        metrics["yara_rule_matches"] += len(matches)
                        capture_records.extend(matches)
            except (CacheError, OSError, ValueError) as exc:
                metrics["yara_cache_unavailable"] += 1
                context.logger.warning("yara cache unavailable target=%r cache_dir=%s reason=%s",
                                       context.event.relative_path.as_posix(), self.config["cache_dir"], exc)
                capture_errors.append(ProcessorError(expected, str(exc), "yara_cache_unavailable"))
            try:
                content = render_report(capture, capture_records, metrics, capture_errors, cache_generation=cache_generation,
                                        report_path=expected, base_dir=context.base_dir, generated_at=(self.clock or context.clock)())
                publish_report(content, expected, lambda: context.report_path(capture, self.name))
            except (OSError, ValueError) as exc:
                capture_errors.append(ProcessorError(expected, str(exc), "yara_report_error"))
            records.extend(capture_records); errors.extend(capture_errors)
        return ProcessorResult(records=records, errors=errors, metrics=metrics)
