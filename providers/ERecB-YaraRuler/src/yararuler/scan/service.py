from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from datetime import UTC, datetime
from pathlib import Path

from yararuler.config import AppConfig
from yararuler.models import (
    Candidate,
    FileResult,
    ScanErrorRecord,
    ScanMetadata,
    ScanSummary,
)
from yararuler.rules.cache import load_active_cache
from yararuler.rules.compiler import require_yara
from yararuler.scan.discovery import FileDiscoverer
from yararuler.scan.filters import CandidateFilter
from yararuler.scan.matcher import (
    MatchOutcome,
    initialize_worker,
    match_candidate,
    worker_scan,
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ScanService:
    def _record_outcome(
        self,
        outcome: MatchOutcome,
        results: list[FileResult],
        errors: list[ScanErrorRecord],
    ) -> None:
        if outcome.result is not None:
            results.append(outcome.result)
        if outcome.error is not None:
            errors.append(outcome.error)

    def scan(
        self,
        config: AppConfig,
        *,
        target_dir: Path,
        selector: str,
        globs: list[str],
        regexes: list[str],
        threads: int,
        timeout_seconds: int,
        include_strings: bool,
        excluded_paths: set[Path] | None = None,
    ) -> ScanSummary:
        started_at = utc_now()
        active = load_active_cache(config.rules.cache_dir)
        discoverer = FileDiscoverer(
            target_dir,
            follow_symlinks=config.scan.follow_symlinks,
            excluded_paths=excluded_paths,
        )
        candidate_filter = CandidateFilter(
            selector=selector,
            globs=globs,
            regexes=regexes,
            max_file_size_bytes=config.scan.max_file_size_bytes,
        )
        discovered = 0
        selected = 0
        scanned = 0
        results: list[FileResult] = []
        errors: list[ScanErrorRecord] = []

        def selected_candidates() -> Iterator[Candidate]:
            nonlocal discovered, selected
            for candidate in discoverer.iter_files():
                discovered += 1
                try:
                    accepted = candidate_filter.accepts(candidate)
                except OSError as exc:
                    errors.append(
                        ScanErrorRecord(
                            candidate.file_path,
                            "filter",
                            type(exc).__name__,
                            str(exc).replace("\x00", "")[:1000],
                        )
                    )
                    continue
                if accepted:
                    selected += 1
                    yield candidate

        if threads == 1:
            rules = require_yara().load(str(active.rules_path))
            for candidate in selected_candidates():
                self._record_outcome(
                    match_candidate(rules, candidate, timeout_seconds, include_strings),
                    results,
                    errors,
                )
                scanned += 1
        else:
            pending: dict[Future[MatchOutcome], Candidate] = {}
            queue_limit = max(threads * 2, 1)
            with ProcessPoolExecutor(
                max_workers=threads,
                initializer=initialize_worker,
                initargs=(str(active.rules_path),),
            ) as executor:
                for candidate in selected_candidates():
                    while len(pending) >= queue_limit:
                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        for future in done:
                            original = pending.pop(future)
                            scanned += 1
                            try:
                                outcome = future.result()
                            except Exception as exc:
                                outcome = MatchOutcome(
                                    original.sequence,
                                    error=ScanErrorRecord(
                                        original.file_path,
                                        "scan",
                                        "worker_failure",
                                        str(exc).replace("\x00", "")[:1000],
                                    ),
                                )
                            self._record_outcome(outcome, results, errors)
                    future = executor.submit(
                        worker_scan, (candidate, timeout_seconds, include_strings)
                    )
                    pending[future] = candidate
                for future, original in list(pending.items()):
                    scanned += 1
                    try:
                        outcome = future.result()
                    except Exception as exc:
                        outcome = MatchOutcome(
                            original.sequence,
                            error=ScanErrorRecord(
                                original.file_path,
                                "scan",
                                "worker_failure",
                                str(exc).replace("\x00", "")[:1000],
                            ),
                        )
                    self._record_outcome(outcome, results, errors)

        errors.extend(discoverer.errors)
        results.sort(key=lambda result: (result.file_path, result.sequence))
        errors.sort(key=lambda error: (error.path, error.operation, error.category))
        metadata = ScanMetadata(
            timestamp=started_at,
            completed_at=utc_now(),
            target_directory=str(Path(target_dir).resolve()),
            cache_generation=active.generation,
            total_files_discovered=discovered,
            total_files_selected=selected,
            total_files_scanned=scanned,
            total_files_matched=len(results),
            total_matches=sum(len(result.matches) for result in results),
            total_errors=len(errors),
            filters={"selector": selector, "globs": globs, "regexes": regexes},
        )
        return ScanSummary(metadata, results, errors)
