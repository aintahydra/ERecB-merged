# ERecB Triage

ERecB Triage is a Python directory watcher and controlled archive unarchiver.

This checkout also contains the FileIntel, GHIntel, IPIntel, and YaraRuler producers under
`providers/`. They share one Git repository with triage; see
[`design/REPOSITORY_LAYOUT.md`](design/REPOSITORY_LAYOUT.md) for ownership and artifact paths.

It watches `in/` for newly dropped archive files or capture directories and extracts supported
archives into `middle-earth/` without executing any captured content.

Supported archive candidates include:

- `.zip`
- `.enc` and `.en_dec` files containing ZIP data
- `.tar.gz`

Additional tar and compression-stream formats are deliberately disabled until they have the
same hostile-fixture coverage as the production formats above.

## Quick Start

From the project root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
erecb-triage --once --config config/watcher_unarchiver.yaml
```

Continuous watcher mode:

```bash
erecb-triage --config config/watcher_unarchiver.yaml
```

One-shot mode scans existing direct children already present in `in/`, drains queued work,
and exits with status 1 if any processing errors occurred (0 otherwise):

```bash
erecb-triage --once --config config/watcher_unarchiver.yaml
```

## Fixture Check

```bash
cp testdata/212.212.212.212.tar.gz in/
cp testdata/213.213.213.213_99.zip in/
erecb-triage --once --config config/watcher_unarchiver.yaml
```

Expected output files:

```text
middle-earth/212.212.212.212.tar.gz-<YYMMDD-HHMMSS>/malicious/malware.exe
middle-earth/213.213.213.213_99.zip-<YYMMDD-HHMMSS>/a/b/c/iplist.txt
```

The suffix is the UTC staging-start time; collisions receive a counter. Identical archive
bytes at the same input path reuse their saved name across restarts. Staging identity and
report ownership are stored in `data/staging.sqlite3`. Retain that index with the captures.

Indexed staging currently requires `overwrite: false` and one dispatcher per staging root.
It publishes complete snapshots from `middle-earth/.partial/` and verifies saved manifests
before reusing output. InputStager also supports directly dropped files and directories.
The dispatcher supports ordered analysis and reserves stable report paths. The canonical
`config/watcher_all.yaml` profile runs IPIntel, FileIntel, GHIntel, and YaraRuler against the
same trusted staged capture, then publishes `output/<archive>-summary.md`. The summary is an
operational status report, never a malware or benign verdict. Install the optional YARA binding
before selecting that profile:

```bash
python -m pip install -e '.[yara]'
erecb-triage --config config/watcher_all.yaml --check
erecb-triage --once --config config/watcher_all.yaml
```

`--check` is read-only: it validates configuration, paths, staging-state schema, selected
adapter construction, producer DB schemas, optional classifier state, free space, and the active
YARA cache generation. A missing or invalid replaceable DB/cache is reported as degraded; a
missing selected optional dependency or unsafe configuration is fatal. Update YARA rules only
through the YaraRuler producer, outside capture processing.

## FileIntel Discovery Dependency

Standalone executable discovery and hashing are implemented. For magic-based detection,
install the system `libmagic` library using your operating system's package manager, then
install the optional Python dependency:

```bash
python -m pip install -e '.[fileintel]'
```

Without magic support, discovery uses configured extension fallback and returns a degraded
classification status with a warning. If fallback is disabled too, classification is
unavailable. Explicitly configuring both methods off is invalid. Standalone read-only
FileIntel database lookup is also implemented, with SHA-256 matching, constrained MD5
fallback, and explicit unavailable/error outcomes. FileRetriever now composes discovery and
lookup into structured records and evidence-linked Markdown reports, with atomic,
ownership-checked publication. Run the FileRetriever-only pipeline with:

```bash
erecb-triage --once --config config/watcher_fileintel.yaml
```

This configuration uses extension-only classification so it runs without optional magic
support. Reports are written to `output/<original-archive-name>-fileintel.md`; staged evidence
stays under `middle-earth/`. Missing or incompatible intelligence databases still produce reports
and make one-shot mode return status 1 because the degraded lookup is reported as a warning.
The no-config defaults and `watcher_unarchiver.yaml` remain staging/unarchiving-only.

## IP Intelligence

IPRetriever recursively reads staged regular files as bounded byte streams, extracts canonical
IPv4/IPv6 literals, excludes the documented non-actionable IPv4 ranges, looks up the remaining
addresses in the existing read-only `dbs/ipintel.sqlite3`, and writes
`output/<original-archive-name>-ipintel.md`:

```bash
erecb-triage --once --config config/watcher_ipintel.yaml
```

The IP profile has no external-provider dependency. It scans file bytes rather than names,
does not expand nested content, and does not treat a database miss, nullable verdict, or failed
historical provider result as a benign result. Missing or incompatible databases still produce
an evidence-linked report with local observations and incomplete lookup warnings; one-shot mode
therefore exits with status 1 in that degraded case. The local database is producer-owned:
IPRetriever opens it only with SQLite read-only mode and never creates, migrates, or enriches it.

## Documentation

- Merged repository layout and data ownership: `design/REPOSITORY_LAYOUT.md`
- Packaging, redistribution, and run instructions: `docs/PACKAGING_AND_RUNNING.md`
- Implementation design: `design/DESIGN_02_WATCHER_UNARCHIVER.md`
- Shared staging/dispatcher verification: `docs/FILEINTEL_PHASE2_VERIFICATION.md`
- Executable discovery verification: `docs/FILEINTEL_PHASE3_VERIFICATION.md`
- Read-only intelligence lookup verification: `docs/FILEINTEL_PHASE4_VERIFICATION.md`
- FileRetriever adapter and report verification: `docs/FILEINTEL_PHASE5_VERIFICATION.md`
- FileRetriever runtime verification: `docs/FILEINTEL_PHASE6_VERIFICATION.md`
- IPIntel implementation design: `design/DESIGN_03_PROCESSOR_IPINTEL.md`
- IPIntel runtime verification: `docs/IPINTEL_PHASE6_VERIFICATION.md`
- Unified-profile operation and recovery: [`docs/OPERATOR_RUNBOOK.md`](docs/OPERATOR_RUNBOOK.md)
