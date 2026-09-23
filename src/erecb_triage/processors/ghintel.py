"""Compose offline GitHub repository observations, local cards, and a report."""
from __future__ import annotations

from pathlib import Path

from erecb_triage.config import ghintel_settings, resolve_path
from erecb_triage.ghintel.extractor import ExtractionResult, scan_capture
from erecb_triage.ghintel.report import publish_report, render_report
from erecb_triage.ghintel.repository import GHIntelRepository
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult


class GHIntel(Processor):
    def __init__(self, name: str, config: dict, *, clock=None) -> None:
        self.name, self.config, self.clock = name, ghintel_settings(config), clock

    def accepts(self, records, context) -> bool:
        return any(record.get("type") == "staged_capture" for record in records)

    def process(self, input_records, context) -> ProcessorResult:
        records, errors = [], []
        metrics = {**ExtractionResult().metrics, "ghintel_lookup_hits": 0, "ghintel_lookup_misses": 0,
                   "ghintel_lookup_unavailable": 0, "ghintel_lookup_errors": 0}
        for capture in input_records:
            if capture.get("type") != "staged_capture": continue
            try: context.authorize_capture(capture)
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(context.event.path, str(exc), "invalid_staged_capture")); continue
            expected = resolve_path(context.base_dir, self.config["output_root"]) / (capture["report_stem"] + self.config["report_suffix"])
            try:
                if context.report_path(capture, self.name) != expected: raise ValueError("configured report disagrees with reservation")
                extraction = scan_capture(capture, self.config, context.base_dir)
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(expected, str(exc), "ghintel_report_error")); continue
            capture_records, capture_errors = list(extraction.observations), list(extraction.errors)
            groups = {}
            for observation in extraction.observations: groups.setdefault(observation["identity_key"], []).append(observation)
            database_path = resolve_path(context.base_dir, self.config["db_path"])
            with GHIntelRepository(database_path) as repository:
                availability = "available" if repository.available else "unavailable"
                if repository.initialization_error: capture_errors.append(repository.initialization_error)
                for key, observations in sorted(groups.items()):
                    outcome = repository.lookup(key)
                    metric_name = {
                        "hit": "ghintel_lookup_hits", "miss": "ghintel_lookup_misses",
                        "unavailable": "ghintel_lookup_unavailable", "error": "ghintel_lookup_errors",
                    }[outcome.status]
                    metrics[metric_name] += 1
                    evidence = observations[0]
                    capture_records.append({**evidence, "type": "github_intel_lookup", "status": outcome.status,
                                            "source_paths": sorted(item["source_path"] for item in observations),
                                            "error_code": outcome.error.code if outcome.error else None})
                    if outcome.error: capture_errors.append(outcome.error)
                    if outcome.status == "hit": capture_records.append({**evidence, "type": "github_intel_hit", **outcome.card})
            records.extend(capture_records)
            for key, value in extraction.metrics.items(): metrics[key] += value
            try:
                content = render_report(capture, capture_records, metrics, capture_errors, base_dir=context.base_dir,
                                        report_path=expected, database_path=database_path, database_availability=availability,
                                        generated_at=(self.clock or context.clock)())
                publish_report(content, expected, lambda: context.report_path(capture, self.name))
            except (OSError, ValueError) as exc: capture_errors.append(ProcessorError(expected, str(exc), "ghintel_report_error"))
            errors.extend(capture_errors)
        return ProcessorResult(records=records, errors=errors, metrics=metrics)
