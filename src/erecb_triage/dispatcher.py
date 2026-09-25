from __future__ import annotations

import logging
import hashlib
import json
import sqlite3
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from erecb_triage.config import resolve_path, validate_config
from erecb_triage.events import WatchEvent
from erecb_triage.processors import (
    ArchiveUnarchiver, ArtifactInventory, FileRetriever, GHIntel, IPRetriever, Processor, ProcessorError, ProcessorResult, YaraScan,
)
from erecb_triage.processors.input_stager import InputStager
from erecb_triage.staging import StagingState, hash_file
from erecb_triage.summary import publish_summary, render_summary


@dataclass(frozen=True)
class ProcessingContext:
    event: WatchEvent
    config: dict[str, Any]
    output_root: Path
    analysis_output_root: Path
    base_dir: Path
    run_id: str
    logger: logging.Logger
    staging_state: StagingState
    report_specs: dict[str, tuple[Path, str]]
    clock: Callable[[], datetime]

    def report_path(self, capture: dict, processor_name: str) -> Path:
        """Check ownership immediately before an analysis processor publishes a report."""
        row = self.authorize_capture(capture)
        directory, suffix = self.report_specs[processor_name]
        return self.staging_state.claim_report_slot(row, processor_name, directory, suffix)

    def authorize_capture(self, capture: dict):
        """Authorize a ready capture for this event/run, not just any indexed capture."""
        row = self.staging_state.validate_record(capture, verify_manifest=True)
        if (row["source_relative_path"] != self.event.relative_path.as_posix()
                or capture.get("source_path") != str(self.event.path)
                or (row["source_sha256"] and capture.get("source_sha256") != row["source_sha256"])):
            raise ValueError("staged capture belongs to a different input identity")
        if (capture.get("source_event_id") != self.event.id
                or capture.get("pipeline_run_id") != self.run_id):
            raise ValueError("staged capture has stale invocation provenance")
        return row


class Dispatcher:
    def __init__(
        self,
        config: dict[str, Any],
        base_dir: Path | None = None,
        logger: logging.Logger | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
        processor_factories: dict[str, Callable[[str, dict], Processor]] | None = None,
    ) -> None:
        validate_config(config)
        self.config = config
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.logger = logger or logging.getLogger("erecb_triage.dispatcher")
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._queue: deque[WatchEvent] = deque()
        self._draining = False
        self._closed = False
        self._factories = {
            "archive_unarchiver": ArchiveUnarchiver,
            "artifact_inventory": ArtifactInventory,
            "input_stager": InputStager,
            "ip_retriever": IPRetriever,
            "file_retriever": FileRetriever,
            "ghintel": GHIntel,
            "yara_scan": YaraScan,
        }
        self._factories.update(processor_factories or {})
        self._preprocessors = [(name, self._build_processor(name)) for name in self._names("preprocessors")]
        self._analysis = [(name, self._build_processor(name)) for name in self._names("analysis")]
        settings = config.get("dispatcher", {})
        self.watch_root = resolve_path(self.base_dir, config.get("watch", {}).get("path", "./in"))
        self.output_root = resolve_path(self.base_dir, settings.get("staging_root", "./middle-earth"))
        self.analysis_output_root = resolve_path(self.base_dir, settings.get("output_root", "./output"))
        self.report_specs = {}
        for name, _ in self._analysis:
            processor_config = config["processors"][name]
            directory = resolve_path(self.base_dir, processor_config["output_root"])
            default_suffixes = {
                "ip_retriever": "-ipintel.md", "file_retriever": "-fileintel.md", "ghintel": "-ghintel.md",
                "yara_scan": "-yara.md",
            }
            default_suffix = default_suffixes[processor_config["type"]]
            suffix = processor_config.get("report_suffix", default_suffix)
            if (directory, suffix) in self.report_specs.values():
                raise ValueError("analysis processors must have distinct report paths")
            self.report_specs[name] = (directory, suffix)
        for name, _ in self._preprocessors:
            if (config["processors"][name]["type"] in {"input_stager", "archive_unarchiver"}
                    and resolve_path(self.base_dir, config["processors"][name]["output_root"]) != self.output_root):
                raise ValueError(f"{name}: output_root must equal dispatcher.staging_root")
        directories = {self.analysis_output_root, *(directory for directory, _ in self.report_specs.values())}
        if self._overlap(self.watch_root, self.output_root):
            raise ValueError("watch and staging roots must be disjoint")
        for directory in directories:
            if self._overlap(directory, self.watch_root) or self._overlap(directory, self.output_root):
                raise ValueError("analysis output must be outside watch and staging roots")
        index_path = Path(settings.get("staging_index_path", "./data/staging.sqlite3"))
        index_path = index_path if index_path.is_absolute() else self.base_dir / index_path
        if index_path.is_symlink():
            raise ValueError("staging index must not be a symlink")
        index_path = index_path.resolve()
        if index_path.is_relative_to(self.watch_root) or index_path.is_relative_to(self.output_root):
            raise ValueError("staging index must be outside watch and staging roots")
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        self.staging_state = StagingState(index_path, self.watch_root, self.output_root, self.clock)
        for phase, processors in (("preprocessor", self._preprocessors), ("analysis", self._analysis)):
            for name, _ in processors:
                self.logger.info(
                    "processor ready phase=%s processor=%s type=%s",
                    phase, name, config["processors"][name]["type"],
                )

    @staticmethod
    def _overlap(first: Path, second: Path) -> bool:
        return first.is_relative_to(second) or second.is_relative_to(first)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        if not self._closed:
            try:
                self.drain()
            finally:
                self.staging_state.close()
                self._closed = True

    def enqueue(self, event: WatchEvent) -> None:
        if self._closed:
            raise RuntimeError("dispatcher is closed")
        self._queue.append(event)
        self.logger.info("target queued target=%r", event.relative_path.as_posix())

    def list_captures(self) -> list[dict[str, Any]]:
        """List indexed capture generations for explicit operator selection."""
        rows = self.staging_state.connection.execute(
            "SELECT id, source_relative_path, capture_name, status, staging_started_at "
            "FROM captures ORDER BY id DESC"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            report = self.staging_state.connection.execute(
                "SELECT generated_at, policy_sha256, database_sha256, yara_generation, statuses "
                "FROM analysis_runs WHERE capture_id=? ORDER BY id DESC LIMIT 1", (row["id"],)
            ).fetchone()
            if report is not None:
                item["last_analysis"] = {
                    "generated_at": report["generated_at"], "policy_sha256": report["policy_sha256"],
                    "database_sha256": json.loads(report["database_sha256"]),
                    "yara_generation": report["yara_generation"],
                    "statuses": json.loads(report["statuses"]),
                }
            result.append(item)
        return result

    def capture_for_replay(self, capture_id: int) -> tuple[dict, ProcessingContext]:
        """Construct a fresh invocation for one manifest-verified staged generation."""
        if self._closed or type(capture_id) is not int or capture_id < 1:
            raise ValueError("a positive capture ID is required")
        row = self.staging_state.get(capture_id)
        if row is None or row["status"] != "ready" or not self.staging_state.usable(row):
            raise ValueError("capture is not a ready, verified staging generation")
        relative = Path(row["source_relative_path"])
        if len(relative.parts) != 1 or relative.name != row["report_stem"]:
            raise ValueError("capture source identity is invalid")
        event = WatchEvent(
            id=f"evt-{uuid4()}", kind="added", root_path=self.watch_root,
            path=self.watch_root / relative, relative_path=relative,
            is_directory=False, observed_at=self.clock(),
        )
        context = self._context(event)
        capture = {
            "type": "staged_capture", "capture_name": row["capture_name"],
            "source_name": event.source_name, "source_path": str(event.path),
            "source_relative_path": relative.as_posix(), "report_stem": row["report_stem"],
            "staged_path": row["staged_path"], "staging_method": "replay",
            "source_event_id": event.id, "pipeline_run_id": context.run_id,
        }
        if row["source_sha256"]:
            capture["source_sha256"] = row["source_sha256"]
            capture["staging_started_at"] = row["staging_started_at"]
        context.authorize_capture(capture)
        return capture, context

    def replay(self, capture_id: int) -> ProcessorResult:
        """Run analysis again against one ready, manifest-verified staged capture."""
        capture, context = self.capture_for_replay(capture_id)
        return self.dispatch(context.event, replay_capture_id=capture_id)

    def drain(self) -> list[ProcessorResult]:
        if self._draining:
            return []
        self._draining = True
        results = []
        try:
            while self._queue:
                event = self._queue.popleft()
                try:
                    results.append(self.dispatch(event))
                except Exception as exc:
                    self.logger.exception("event failed: %s", event.path)
                    results.append(ProcessorResult(errors=[ProcessorError(
                        event.path, str(exc), "dispatch_exception"
                    )]))
            return results
        finally:
            self._draining = False

    def dispatch(self, event: WatchEvent, *, replay_capture_id: int | None = None) -> ProcessorResult:
        if self._closed:
            raise RuntimeError("dispatcher is closed")
        if event.kind != "added":
            return ProcessorResult(metrics={"events_ignored": 1})
        if (event.root_path != self.watch_root or len(event.relative_path.parts) != 1
                or event.relative_path.name in {".", ".."}
                or event.path != self.watch_root / event.relative_path):
            return ProcessorResult(errors=[ProcessorError(
                event.path, "not a direct-child watch event", "invalid_event"
            )])
        target = event.relative_path.as_posix()
        self.logger.info("target start target=%r", target)
        records: list[dict[str, Any]] = []
        errors: list[ProcessorError] = []
        metrics: dict[str, int] = {"processors_run": 0}
        context = self._context(event)

        if replay_capture_id is not None:
            capture, replay_context = self.capture_for_replay(replay_capture_id)
            if replay_context.event.relative_path.as_posix() != target:
                raise ValueError("replay capture does not belong to this input")
            capture["source_event_id"] = event.id
            capture["pipeline_run_id"] = context.run_id
            context.authorize_capture(capture)
            records.append(capture)

        def run(name, processor, phase: str):
            try:
                if not processor.accepts(list(records), context):
                    self.logger.info(
                        "processor skipped target=%r phase=%s processor=%s reason=no_applicable_records",
                        target, phase, name,
                    )
                    return True, ProcessorResult()
                metrics["processors_run"] += 1
                started = time.monotonic()
                self.logger.info("processor start target=%r phase=%s processor=%s", target, phase, name)
                result = processor.process(list(records), context)
                elapsed_ms = int((time.monotonic() - started) * 1000)
                records.extend(result.records)
                errors.extend(result.errors)
                for key, value in result.metrics.items():
                    if key != "processors_run":
                        metrics[key] = metrics.get(key, 0) + value
                for error in result.errors:
                    self.logger.warning("%s: %s", error.code, error.message)
                self.logger.info(
                    "processor complete target=%r phase=%s processor=%s elapsed_ms=%d errors=%d",
                    target, phase, name, elapsed_ms, len(result.errors),
                )
                return True, result
            except Exception as exc:
                self.logger.exception("processor failed target=%r phase=%s processor=%s", target, phase, name)
                errors.append(ProcessorError(event.path, str(exc), "processor_exception"))
                return False, None

        for name, processor in self._preprocessors:
            if replay_capture_id is not None and self.config["processors"][name]["type"] != "artifact_inventory":
                continue
            succeeded, _ = run(name, processor, "preprocessor")
            if not succeeded:
                # A failed preprocessing boundary cannot safely yield analysis input.
                self.logger.info("target complete target=%r processors_run=%d errors=%d", target, metrics["processors_run"], len(errors))
                return ProcessorResult(records=records, errors=errors, metrics=metrics)

        eligible = []
        for record in records:
            if record.get("type") != "staged_capture":
                continue
            try:
                row = context.authorize_capture(record)
                record["capture_id"] = row["id"]
                eligible.append(record)
            except (OSError, ValueError) as exc:
                errors.append(ProcessorError(event.path, str(exc), "invalid_staged_capture"))
        records[:] = [
            record for record in records
            if record.get("type") != "staged_capture" or record in eligible
        ]
        statuses: list[dict[str, Any]] = []
        if eligible:
            provenance = self._analysis_provenance()
            for capture in eligible:
                capture["analysis_provenance"] = provenance
            for name, processor in self._analysis:
                report_path = None
                started_at = self.clock()
                try:
                    for record in eligible:
                        report_path = context.report_path(record, name)
                except (OSError, ValueError, sqlite3.Error) as exc:
                    errors.append(ProcessorError(event.path, str(exc), "report_collision"))
                    # Report ownership is adapter-scoped; a collision for one output must
                    # not suppress an independent later analysis processor.
                    statuses.append(self._adapter_status(name, "failed", report_path, [], False, started_at=started_at,
                                                         completed_at=self.clock()))
                    continue
                error_start = len(errors)
                succeeded, adapter_result = run(name, processor, "analysis")
                adapter_errors = errors[error_start:]
                codes = [issue.code for issue in adapter_errors]
                if not succeeded:
                    state, current = "failed", False
                elif any(code.endswith("report_error") for code in codes):
                    state, current = "failed", False
                elif codes:
                    state, current = "degraded", bool(report_path and report_path.exists())
                else:
                    state, current = "success", bool(report_path and report_path.exists())
                statuses.append(self._adapter_status(name, state, report_path, codes, current,
                                                     adapter_result.metrics if adapter_result else {}, started_at, self.clock()))
            if self.config.get("dispatcher", {}).get("publish_summary", False):
                for capture in eligible:
                    self._publish_capture_summary(context, capture, statuses, records, errors)
            for capture in eligible:
                try:
                    self.staging_state.record_analysis(capture["capture_id"], provenance, statuses)
                except (OSError, ValueError) as exc:
                    errors.append(ProcessorError(event.path, str(exc), "analysis_history_error"))
        self.logger.info("target complete target=%r processors_run=%d errors=%d", target, metrics["processors_run"], len(errors))
        return ProcessorResult(records=records, errors=errors, metrics=metrics, statuses=statuses)

    def _analysis_provenance(self) -> dict[str, Any]:
        names = ("ip_retriever", "file_retriever", "ghintel", "yara_scan")
        policy = {name: self.config["processors"][name] for name in names if name in self.config["processors"]}
        fingerprint = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        database_hashes = {}
        for name in ("ip_retriever", "file_retriever", "ghintel"):
            settings = policy.get(name)
            if settings is None:
                continue
            path = resolve_path(self.base_dir, settings["db_path"])
            try:
                database_hashes[name] = hash_file(path)
            except OSError:
                database_hashes[name] = None
        generation = None
        yara_settings = policy.get("yara_scan")
        if yara_settings is not None:
            pointer = resolve_path(self.base_dir, yara_settings["cache_dir"]) / "active"
            if pointer.is_file() and not pointer.is_symlink():
                try:
                    generation = pointer.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError):
                    pass
        return {"policy_sha256": fingerprint, "database_sha256": database_hashes,
                "yara_generation": generation}

    def _adapter_status(self, name: str, state: str, report_path: Path | None, codes: list[str], current: bool,
                        metrics: dict[str, int] | None = None, started_at: datetime | None = None,
                        completed_at: datetime | None = None) -> dict[str, Any]:
        started = started_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if started_at else None
        completed = completed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if completed_at else None
        duration_ms = None if not started_at or not completed_at else max(0, int((completed_at - started_at).total_seconds() * 1000))
        return {"name": name, "state": state, "report_path": report_path, "report_current": current,
                "error_codes": sorted(set(codes))[:32], "metrics": dict(metrics or {}), "started_at": started,
                "completed_at": completed, "duration_ms": duration_ms}

    def _publish_capture_summary(self, context: ProcessingContext, capture: dict, statuses: list[dict[str, Any]],
                                 records: list[dict[str, Any]], errors: list[ProcessorError]) -> None:
        try:
            row = context.authorize_capture(capture)
            directory = self.analysis_output_root
            path = self.staging_state.claim_report_slot(row, "triage_summary", directory, "-summary.md")
            rendered_statuses = [dict(status, summary_path=path) for status in statuses]
            enabled = {status["name"] for status in rendered_statuses}
            for name in ("ip_retriever", "file_retriever", "ghintel", "yara_scan"):
                if name not in enabled:
                    disabled = self._adapter_status(name, "not_enabled", None, [], False)
                    disabled["summary_path"] = path
                    rendered_statuses.append(disabled)
            order = ("ip_retriever", "file_retriever", "ghintel", "yara_scan")
            rendered_statuses.sort(key=lambda status: order.index(status["name"]))
            content = render_summary(capture, rendered_statuses, records, base_dir=self.base_dir, generated_at=self.clock())
            publish_summary(content, path, lambda: self.staging_state.claim_report_slot(row, "triage_summary", directory, "-summary.md"))
            records.append({"type": "triage_summary", "report_path": str(path), "capture_name": capture["capture_name"]})
        except (OSError, ValueError) as exc:
            errors.append(ProcessorError(context.event.path, str(exc), "summary_report_error"))

    def _context(self, event: WatchEvent) -> ProcessingContext:
        return ProcessingContext(
            event=event, config=self.config, output_root=self.output_root,
            analysis_output_root=self.analysis_output_root, base_dir=self.base_dir,
            run_id=f"run-{uuid4()}", logger=self.logger, staging_state=self.staging_state,
            report_specs=self.report_specs, clock=self.clock,
        )

    def _names(self, phase: str) -> list[str]:
        return list(self.config.get("pipelines", {}).get("on_added", {}).get(phase, {}).get("processors", []))

    def _build_processor(self, name: str) -> Processor:
        processor_config = self.config["processors"][name]
        kind = processor_config["type"]
        if kind not in self._factories:
            raise ValueError(f"configured processor is not implemented: {name} ({kind})")
        if kind in {"input_stager", "archive_unarchiver"}:
            engine = (processor_config if kind == "archive_unarchiver"
                      else self.config["processors"][processor_config["unarchiver"]])
            if engine.get("overwrite", False):
                raise ValueError("indexed staging currently requires overwrite: false")
        return self._factories[kind](name, processor_config)
