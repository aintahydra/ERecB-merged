"""Compose local executable evidence and intelligence for authorized captures."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict
from pathlib import Path

from erecb_triage.config import file_retriever_settings, resolve_path
from erecb_triage.fileintel.contracts import HashEvidence
from erecb_triage.fileintel.discovery import DiscoveryResult, scan_capture
from erecb_triage.fileintel.report import publish_report, render_report
from erecb_triage.fileintel.repository import FileIntelRepository
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult


_LOOKUP_COUNTERS = {
    "hit": "fileintel_lookup_hits", "miss": "fileintel_lookup_misses",
    "ambiguous": "fileintel_lookup_ambiguities", "unavailable": "fileintel_lookup_unavailable",
    "error": "fileintel_lookup_errors",
}


class FileRetriever(Processor):
    def __init__(self, name: str, config: dict, *, clock=None) -> None:
        self.name = name
        self.config = file_retriever_settings(config)
        self.clock = clock

    def accepts(self, input_records, context) -> bool:
        return any(record.get("type") == "staged_capture" for record in input_records)

    def _authorize(self, capture, context):
        row = context.staging_state.validate_record(capture, verify_manifest=True)
        if (capture.get("source_event_id") != context.event.id
                or capture.get("pipeline_run_id") != context.run_id):
            raise ValueError("staged capture has stale invocation provenance")
        if (capture.get("source_path") != str(context.event.path)
                or row["source_relative_path"] != context.event.relative_path.as_posix()
                or (row["source_sha256"] and capture.get("source_sha256") != row["source_sha256"])):
            raise ValueError("staged capture belongs to a different input identity")
        # The staging index, not an accumulated record, owns summary timestamps.
        return {**capture, "staging_started_at": row["staging_started_at"]}

    def process(self, input_records, context) -> ProcessorResult:
        records, errors = [], []
        metrics = {**DiscoveryResult().metrics, **dict.fromkeys(_LOOKUP_COUNTERS.values(), 0)}
        seen = set()
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
                    raise ValueError("configured FileRetriever report disagrees with reservation")
                return path

            try:
                authorize_report()
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(ProcessorError(expected_path, str(exc), "fileintel_report_error"))
                continue

            try:
                discovery = scan_capture(capture, self.config, context.base_dir)
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(Path(identity), str(exc), "invalid_staged_capture"))
                continue
            observations = list({
                (item["sha256_hash"], item["source_path"]): item
                for item in discovery.observations
            }.values())
            observations.sort(key=lambda item: (item["sha256_hash"], item["source_path"]))
            grouped = {}
            for item in observations:
                grouped.setdefault(item["sha256_hash"], []).append(item)
            capture_records = list(observations)
            capture_errors = list(discovery.errors)
            capture_metrics = {**discovery.metrics, **dict.fromkeys(_LOOKUP_COUNTERS.values(), 0)}
            capture_metrics["fileintel_observations"] = len(observations)
            capture_metrics["fileintel_unique_hashes"] = len(grouped)
            database_path = resolve_path(context.base_dir, self.config["db_path"])
            with FileIntelRepository(database_path) as repository:
                db_availability = "available" if repository.available else "unavailable"
                if repository.initialization_error is not None:
                    capture_errors.append(repository.initialization_error)
                for sha256, items in grouped.items():
                    evidence = {key: items[0][key] for key in HashEvidence.__annotations__}
                    evidence["source_paths"] = sorted({item["source_path"] for item in items})
                    outcome = repository.lookup(sha256, items[0]["md5_hash"])
                    capture_metrics[_LOOKUP_COUNTERS[outcome.status]] += 1
                    capture_records.append({
                        **evidence, "type": "file_intel_lookup", "status": outcome.status,
                        "error_code": outcome.error.code if outcome.error else None,
                    })
                    if outcome.status == "hit":
                        capture_records.append({
                            **evidence, "type": "file_intel_hit", **asdict(outcome.intelligence),
                        })
                    elif outcome.status == "ambiguous":
                        capture_records.append({
                            **evidence, "type": "file_intel_ambiguity", "reason": outcome.reason,
                            "candidate_file_entity_ids": list(outcome.candidate_file_entity_ids),
                        })
                    elif outcome.status == "error":
                        capture_errors.append(outcome.error)
            # Report failures must not discard completed evidence or lookup outcomes.
            records.extend(capture_records)
            for key, value in capture_metrics.items():
                metrics[key] += value
            try:
                content = render_report(
                    capture, capture_records, capture_metrics, capture_errors,
                    base_dir=context.base_dir, report_path=expected_path,
                    database_path=database_path,
                    classification_availability=discovery.classification_availability,
                    database_availability=db_availability,
                    generated_at=(self.clock or context.clock)(),
                )
                publish_report(content, expected_path, authorize_report)
            except (OSError, ValueError, sqlite3.Error) as exc:
                capture_errors.append(ProcessorError(expected_path, str(exc), "fileintel_report_error"))
            errors.extend(capture_errors)
        return ProcessorResult(records=records, errors=errors, metrics=metrics)
