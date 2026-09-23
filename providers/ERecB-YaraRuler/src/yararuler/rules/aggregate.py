from __future__ import annotations

from pathlib import Path

from yararuler.errors import RuleBuildError
from yararuler.models import RejectedRule, RuleEntry
from yararuler.rules.compiler import compile_aggregate


def compile_with_isolation(
    entries: list[RuleEntry], output: Path
) -> tuple[list[RuleEntry], list[RejectedRule]]:
    """Compile all entries, isolating deterministic cross-unit failures if necessary."""
    initial_error: RuleBuildError | None = None
    try:
        compile_aggregate(entries, output)
        return entries, []
    except RuleBuildError as exc:
        initial_error = exc
        if len(entries) < 2:
            raise

    accepted: list[RuleEntry] = []
    rejected: list[RejectedRule] = []
    probe = output.with_name(f".{output.name}.probe")
    for entry in entries:
        try:
            compile_aggregate([*accepted, entry], probe)
        except RuleBuildError as exc:
            rejected.append(
                RejectedRule(
                    source=entry.source,
                    source_url=entry.source_url,
                    commit=entry.commit,
                    path=entry.path,
                    absolute_path=entry.absolute_path,
                    sha256=entry.sha256,
                    phase="aggregate_compile",
                    error_class=type(exc).__name__,
                    diagnostic=str(exc)[:4000],
                )
            )
        else:
            accepted.append(entry)
        finally:
            probe.unlink(missing_ok=True)

    if not rejected:
        assert initial_error is not None
        raise initial_error
    compile_aggregate(accepted, output)
    return accepted, rejected
