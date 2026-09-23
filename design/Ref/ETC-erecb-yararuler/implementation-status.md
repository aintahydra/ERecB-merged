# YaraRuler 0.1.0 implementation status

This document records the system as implemented on 2026-09-18. It supplements
`implementation-plan.md` and takes precedence where the original plan describes a
different mechanism or a future hardening step.

## Delivered scope

The 0.1.0 implementation delivers both planned commands:

- `yararuler update-rules` synchronizes managed Git repositories, validates rule
  compilation units individually, quarantines rejected units, compiles a combined
  `.yac` artifact, verifies it in a fresh Python process, and atomically publishes an
  immutable cache generation.
- `yararuler scan` safely traverses a target directory, applies selector/glob/regex
  filters, scans with one process or a bounded process pool, applies a per-file YARA
  timeout, hashes matched files, and atomically writes JSON or CSV reports.

The package includes strict TOML configuration, stable exit codes, deterministic
result ordering, recoverable per-file errors, optional matched-string locations, and
passive-analysis safeguards. Rule comparison and semantic optimization remain outside
the 0.1.0 scope.

## As-built structure

The planned layout was implemented with these additions:

```text
.
├── docs/installation-and-usage.md
├── design/implementation-status.md
├── ruff.toml
├── src/yararuler/rules/aggregate.py
└── dist/
    ├── yararuler-0.1.0-py3-none-any.whl
    ├── yararuler-0.1.0.tar.gz
    └── SHA256SUMS
```

`rules/aggregate.py` owns recovery from interactions that appear only during combined
rule compilation. The documentation describes deployment from the generated wheel and
source distribution, including offline dependency preparation.

## Design reconciliations

### Distribution model

The YaraRuler wheel is `py3-none-any`, rather than one wheel per operating system and
architecture. YaraRuler itself is pure Python; the native/platform-specific component
is the separately resolved `yara-python` dependency. This keeps the application wheel
portable while still requiring a compatible `yara-python` wheel or local build on the
destination system.

The supported release artifacts are produced with Hatchling from `pyproject.toml`:

```text
dist/yararuler-0.1.0-py3-none-any.whl
dist/yararuler-0.1.0.tar.gz
```

The source distribution contains the example configuration, tests, design documents,
and operational documentation. `askings.md`, `gh-token.txt`, prior distributions, and generated tool caches are
explicitly excluded.

### Aggregate compilation recovery

The plan proposed bisecting a failed accepted set. The implementation uses a
deterministic incremental reconstruction instead:

1. attempt to compile the complete accepted set;
2. only if that fails, rebuild the set in deterministic order;
3. test each next compilation unit together with the units accepted so far;
4. quarantine a unit with phase `aggregate_compile` if adding it breaks the aggregate;
5. compile and publish the remaining non-empty set.

This finds deterministic cross-unit incompatibilities while keeping the normal
successful path to a single aggregate compile. If no valid aggregate can be produced,
the update fails and the prior active cache remains selected.

### Cache generations and retention

The implementation uses the planned immutable generation directories and an atomically
replaced `active` pointer. The pointer is restricted to canonical UUID values before it
is used as a path, and the scanner verifies the artifact digest, platform, YARA version,
manifest generation, and loadability.

Automatic generation pruning and scan leases are not implemented in 0.1.0. Therefore,
all successfully published generations are retained and no active generation can be
removed by YaraRuler while a scan is using it. Operators may archive old generations
only while no scans or updates are running. Automated lease-aware pruning remains a
future hardening item.

The active pointer file is flushed and fsynced before atomic replacement. The compiled
artifact and manifest are verified before publication, but full directory fsync across
all filesystems is not currently guaranteed.

### Update rebuild behavior

Every successful `update-rules` invocation currently rebuilds and verifies a new cache
from the resolved repository commits. `--force-rebuild` is accepted for CLI stability
but produces the same behavior because unchanged-commit incremental cache reuse is not
implemented. Incremental reuse remains an optimization, not a correctness requirement.

### Rule and path hardening

Beyond the original validation rules, configured Git refs reject option-like values,
whitespace/control characters, and unsafe ref constructs. Git error messages report
only the operation name and redact credentials from URLs. Active cache pointers cannot
escape `cache/generations/`.

Symlinks are disabled by default. When explicitly enabled, directory identities prevent
cycles and report-path normalization safely handles targets outside the initial target
root. The report output and CSV metadata sidecar are excluded from candidate discovery.

### Matched string bounds

When `--include-strings` is enabled, JSON and CSV contain identifiers, offsets, and
lengths but never matched byte content. The implementation bounds normalized string
instances to 10,000 per matched rule to prevent unbounded report growth. A dedicated
truncation-count field is not present in schema 1.0; adding one requires a schema-version
decision and remains a follow-up item.

### Worker failure behavior

Normal YARA timeouts and file I/O failures are converted to per-file error records and
do not stop other candidates. Worker future failures are also converted to records when
the process pool remains usable. Version 0.1.0 does not recreate a process pool after a
pool-wide failure; such a failure aborts the scan as an internal error.

## Verification baseline

The implementation was verified with:

- 29 passing unit and integration tests;
- real `yara-python` 4.5.4 compilation, quarantine, include, cache, and scan tests;
- equivalent single-process and two-process match results;
- Ruff static checks and formatting;
- successful wheel and source-distribution builds;
- isolated installation and CLI startup from both distribution formats;
- successful SHA-256 checksum verification of both release artifacts.

The integration suite uses local temporary Git repositories and does not require a
network connection.

## Deferred work

- rule comparison, semantic deduplication, and collision reporting;
- cache reuse when source commits and build inputs are unchanged;
- scan leases and automatic old-generation pruning;
- explicit matched-string truncation counters in a future report schema;
- process-pool recreation after catastrophic worker failure;
- recorded cross-platform performance benchmarks and release CI artifacts.
