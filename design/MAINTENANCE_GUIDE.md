# Maintenance Guide

## Configuration and state locations

YAML profiles live in `config/`:

| Profile | Intended use |
| --- | --- |
| `watcher_unarchiver.yaml` | staging/extraction only |
| `watcher_ipintel.yaml`, `watcher_fileintel.yaml`, `watcher_ghintel.yaml`, `watcher_yara.yaml` | focused adapter diagnostics |
| `watcher_localintel.yaml` | IPIntel and FileIntel |
| `watcher_all.yaml` | supported four-adapter sequential profile |

All relative paths are resolved from the directory in which `erecb-triage` is run. The main
operational paths are configured in `watch.path` and `dispatcher`:

```text
in/                  source archive input
middle-earth/        dispatcher-owned trusted staging
middle-earth/.partial/ private incomplete staging work
output/              Markdown reports
data/staging.sqlite3 dispatcher-owned identity, recovery, and report-slot state
logs/                rotating operational logs (default: logs/erecb-triage.log)
dbs/*.sqlite3        producer-owned, read-only intelligence databases
rules/cache/         producer-owned, immutable YARA generations
```

Do not manually edit `data/staging.sqlite3`, report slots, staging manifests, or a capture that
is being scanned. Use `erecb-triage --check` for read-only configuration/dependency diagnostics.

The top-level `logging` configuration controls durable run logs. Its default is an INFO-level,
10 MiB rotating file with ten retained backups. Point `logging.file_path` at an operator-owned
filesystem with enough retention capacity; do not place it under `in/`, `middle-earth/`, or a
producer-owned directory. The unarchiver logs its preflight space estimate and rejection reason
there before it copies a supported archive.

For large captures, IPIntel treats a file with more than 20 distinct valid IPs as an IP-list
singularity. `ip_singularity_threshold` defaults to 20: reading stops at the twenty-first IP, no
IP from that file is enriched, and the file path appears in the IP report and capture summary.
`max_observations_per_file` defaults to 1,024 and `max_observations_per_capture` to 10,000.
The singularity threshold must not exceed the per-file bound. These settings cap retained report
evidence, not the archive's staging file count. Do not raise them without sizing VM memory; an OS
`SIGKILL`/`killed` message requires reviewing the kernel OOM log, because a killed process cannot
emit a final application error.

YARA scan consumes only a compiled immutable cache at `processors.yara_scan.cache_dir` (default
`rules/cache`). If it is absent, configure and run the YaraRuler producer under `providers/`
to build its cache, then point this setting to the resulting directory. A raw rules repository
clone is not consumable by Triage. Keep the consumer read-only and use `erecb-triage --check` to
validate the `active` pointer and generation before a production run.

## Large-capture limits and capacity

`unarchive_all_supported` has a bounded production envelope of 100 GiB per archive
(`107374182400` bytes), 200 GiB total extracted data (`214748364800` bytes), and 200,000
extracted files. `watcher_all.yaml` repeats these values explicitly so a copied profile preserves
the envelope. For an 80 GB archive that expands to 150 GB, use the standard profile unchanged.

The source remains in `in/` while `InputStager` copies it into `middle-earth/.partial/` and
extracts it there. On a shared filesystem, a maximum-size capture can therefore require about
400 GiB before filesystem overhead; reserve at least 450 GiB free, plus retention capacity.
Do not set these limits to unlimited: they are decompression-bomb and disk-exhaustion controls.

## Credentials and API keys

The ERecB Triage runtime is deliberately offline and does **not** consume API keys. None belong
in the YAML profiles, SQLite producer databases, reports, test fixtures, logs, or release
artifacts.

The repository root currently contains `.env` and `gh-token.txt`; this guide does not inspect
their contents. They are not referenced by the triage runtime and must be treated as sensitive
legacy/operator files: exclude them from distribution, remove them from deployment directories
unless a producer explicitly needs them, and rotate any exposed
credential through its provider. The producer design documents under `providers/` may describe keys
for their own update/enrichment applications; those settings do not authorize network behavior
in ERecB Triage.

## Add an analysis processor

1. Define the processor contract and report suffix in a new `DESIGN_...` document. Specify input
   `staged_capture`, data boundaries, read/write authority, failure states, resource limits,
   provenance, and exact report semantics.
2. Add a dedicated module under `src/erecb_triage/<processor>/` for parsing/repository/report
   logic. Keep producer adapters read-only and do not import/execute captured data.
3. Add an adapter in `src/erecb_triage/processors/<processor>.py` implementing `Processor`.
   It must call `context.authorize_capture()` and publish only through `context.report_path()`.
4. Register the lazy export in `processors/__init__.py`, the type factory in `dispatcher.py`,
   a fixed suffix/default in `config.py`, and strict no-I/O settings validation.
5. Add a focused YAML profile under `config/`; add it to `MANIFEST.in` by relying on the existing
   `config/*.yaml` rule. Add it to `watcher_all.yaml` only after isolated tests pass.
6. Add fixtures and unit/integration tests proving hostile path behavior, missing producer
   dependencies, deterministic output, report ownership, and unrelated-adapter isolation.
7. Update `REPRODUCTION_GUIDE.md`, `DISTRIBUTION_UBUNTU.md`, the operator runbook, and the
   relevant implementation phase status before releasing.

Preprocessors are reserved for trusted staging-related work. An analysis processor must not
modify a capture, producer database, rule source/cache, or another adapter's report.

## Add a preprocessor

Preprocessors run in declared order before analysis. Register their type in
`config.validate_config()` as a preprocessor type and ensure any staging writer uses the
existing `StagingState` lifecycle. `artifact_inventory` is an example of a safe non-writing
post-staging preprocessor: it copies verified manifest facts but does not make eligibility or
security decisions.

## Dependency and release maintenance

Keep optional dependencies in `pyproject.toml` extras. A base install must import and run the
staging-only profile without optional native libraries. Rebuild both distribution artifacts after
changes and verify them in a clean environment. See `DISTRIBUTION_UBUNTU.md` for commands.

Before replacing a producer DB or active YARA generation, stop/finish current captures. Database
sessions and YARA generations are pinned per capture, so a safe replacement affects later
captures. Do not prune YARA generations while scanners or producer updates might be active.
