"""Compose current IP evidence, local lookup outcomes, and an owned report."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from pathlib import Path

from erecb_triage.config import ip_retriever_settings, resolve_path
from erecb_triage.ipintel.contracts import IpEvidence
from erecb_triage.ipintel.extractor import ExtractionResult, scan_capture
from erecb_triage.ipintel.report import publish_report, render_report
from erecb_triage.ipintel.repository import IpIntelRepository
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult


_LOOKUP_COUNTERS = {
    "hit": "ipintel_lookup_hits", "miss": "ipintel_lookup_misses",
    "unavailable": "ipintel_lookup_unavailable", "error": "ipintel_lookup_errors",
}


class IPRetriever(Processor):
    def __init__(self, name: str, config: dict, *, clock=None) -> None:
        self.name = name
        self.config = ip_retriever_settings(config)
        self.clock = clock

    def accepts(self, input_records, context) -> bool:
        return any(record.get("type") == "staged_capture" for record in input_records)

    def _authorize(self, capture: dict, context) -> dict:
        row = context.staging_state.validate_record(capture, verify_manifest=True)
        if (capture.get("source_event_id") != context.event.id
                or capture.get("pipeline_run_id") != context.run_id):
            raise ValueError("staged capture has stale invocation provenance")
        if (capture.get("source_path") != str(context.event.path)
                or row["source_relative_path"] != context.event.relative_path.as_posix()
                or (row["source_sha256"] and capture.get("source_sha256") != row["source_sha256"])):
            raise ValueError("staged capture belongs to a different input identity")
        return {**capture, "staging_started_at": row["staging_started_at"]}

    def process(self, input_records, context) -> ProcessorResult:
        records: list[dict] = []
        errors: list[ProcessorError] = []
        metrics = {**ExtractionResult().metrics, **dict.fromkeys(_LOOKUP_COUNTERS.values(), 0)}
        seen: set[str] = set()
        for record in input_records:
            if record.get("type") != "staged_capture":
                continue
            try:
                capture = self._authorize(record, context)
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(ProcessorError(context.event.path, str(exc), "invalid_staged_capture"))
                continue
            identity = capture["staged_path"]
            if identity in seen:
                continue
            seen.add(identity)
            expected_path = resolve_path(context.base_dir, self.config["output_root"]) / (
                capture["report_stem"] + self.config["report_suffix"]
            )

            def authorize_report():
                path = context.report_path(capture, self.name)
                if path != expected_path:
                    raise ValueError("configured IPRetriever report disagrees with reservation")
                return path

            try:
                authorize_report()
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(ProcessorError(expected_path, str(exc), "ipintel_report_error"))
                continue
            try:
                context.logger.info(
                    "ipintel scan start target=%r ip_singularity_threshold=%d max_observations_per_file=%d max_observations_per_capture=%d",
                    context.event.relative_path.as_posix(), self.config["ip_singularity_threshold"],
                    self.config["max_observations_per_file"],
                    self.config["max_observations_per_capture"],
                )
                extraction = scan_capture(capture, self.config, context.base_dir)
                context.logger.info(
                    "ipintel scan complete target=%r observations=%d unique_ips=%d singularities=%d truncated=%d errors=%d",
                    context.event.relative_path.as_posix(), extraction.metrics["ipintel_observations"],
                    extraction.metrics["ipintel_unique_ips"], extraction.metrics["ipintel_singularities"],
                    extraction.metrics["ipintel_observations_truncated"],
                    len(extraction.errors),
                )
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(Path(identity), str(exc), "invalid_staged_capture"))
                continue
            observations = list({
                (item["ip"], item["source_path"]): item for item in extraction.observations
            }.values())
            observations.sort(key=lambda item: (item["ip_version"], item["ip"], item["source_path"]))
            grouped: dict[str, list[dict]] = {}
            for item in observations:
                grouped.setdefault(item["ip"], []).append(item)
            capture_records = [*observations, *extraction.singularities]
            capture_errors = list(extraction.errors)
            capture_metrics = {**extraction.metrics, **dict.fromkeys(_LOOKUP_COUNTERS.values(), 0)}
            capture_metrics["ipintel_observations"] = len(observations)
            capture_metrics["ipintel_unique_ips"] = len(grouped)
            database_path = resolve_path(context.base_dir, self.config["db_path"])
            with IpIntelRepository(database_path) as repository:
                database_availability = "available" if repository.available else "unavailable"
                if repository.initialization_error is not None:
                    capture_errors.append(repository.initialization_error)
                for ip, items in grouped.items():
                    evidence = {key: items[0][key] for key in IpEvidence.__annotations__}
                    evidence["source_paths"] = sorted({item["source_path"] for item in items})
                    outcome = repository.lookup(ip)
                    capture_metrics[_LOOKUP_COUNTERS[outcome.status]] += 1
                    capture_records.append({
                        **evidence, "type": "ip_intel_lookup", "status": outcome.status,
                        "error_code": outcome.error.code if outcome.error else None,
                    })
                    if outcome.status == "hit":
                        capture_records.append({
                            **evidence, "type": "ip_intel_hit", **asdict(outcome.intelligence),
                        })
                    elif outcome.status == "error":
                        capture_errors.append(outcome.error)
            records.extend(capture_records)
            for key, value in capture_metrics.items():
                metrics[key] += value
            try:
                content = render_report(
                    capture, capture_records, capture_metrics, capture_errors,
                    base_dir=context.base_dir, report_path=expected_path,
                    database_path=database_path,
                    database_availability=database_availability,
                    generated_at=(self.clock or context.clock)(),
                )
                publish_report(content, expected_path, authorize_report)
            except (OSError, ValueError, sqlite3.Error) as exc:
                capture_errors.append(ProcessorError(expected_path, str(exc), "ipintel_report_error"))
            errors.extend(capture_errors)
        return ProcessorResult(records=records, errors=errors, metrics=metrics)
