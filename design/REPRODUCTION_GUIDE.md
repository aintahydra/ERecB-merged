# Reproduction Guide

## Purpose and scope

This guide reproduces the current ERecB Triage baseline from source or a release artifact.
It complements, rather than replaces, the normative design documents:

- `DESIGN_01_SKELETON.md` — pipeline contracts and patterns;
- `DESIGN_02_WATCHER_UNARCHIVER.md` — trusted ingestion and recovery;
- `DESIGN_03_PROCESSOR_IPINTEL.md` through `DESIGN_06_PROCESSOR_YARARULER.md` — adapter contracts; and
- `IMPLEMENTATION_01_...` through `IMPLEMENTATION_07_...` — implemented phase records and known limits.

The supported baseline is sequential and offline:

The shared repository and producer output paths are described in
[`REPOSITORY_LAYOUT.md`](REPOSITORY_LAYOUT.md).

```text
in/<archive>
  -> watcher stabilization
  -> private extraction and manifest verification
  -> middle-earth/<capture-generation>
  -> IPIntel | FileIntel | GHIntel | YaraScan
  -> output/<archive>-<adapter>.md and optional -summary.md
```

## Architecture and patterns

| Concern | Pattern | Primary implementation |
| --- | --- | --- |
| Input lifecycle | Watcher + dispatcher queue | `watcher.py`, `dispatcher.py` |
| Hostile archive boundary | Private staging, validate-then-publish | `processors/input_stager.py`, `staging.py` |
| Analysis extension point | Strategy/adapter through `Processor` | `processors/base.py`, `processors/` |
| Stable published output | Logical report-slot ownership + atomic replacement | `staging.py`, adapter `report.py` modules |
| Local intelligence | Read-only repository adapter | `ipintel/`, `fileintel/`, `ghintel/` |
| Rule matching | Immutable cache snapshot consumer | `yarascan/` |
| Optional scale metadata | Manifest-bound inventory | `inventory.py`, `processors/artifact_inventory.py` |

Captured data is never executed, imported, mounted, or sent to a network service. The consumer
never writes producer databases, rules, rule caches, or source archives.

## Reproduce from source

Use Python 3.10 or newer. In a clean virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m compileall -q src
PYTHONPATH=src python -m unittest discover -s tests -t . -v
```

For the optional native integrations:

```bash
python -m pip install -e '.[fileintel,yara]'
```

`python-magic` also needs a host `libmagic` library. `yara-python` needs a compatible native
libyara/wheel. Core import and non-YARA profiles do not depend on either optional package.

## Reproduce the unified workflow

Prepare these operator-owned inputs outside the package:

```text
in/                         # archive drop directory
dbs/ipintel.sqlite3         # producer-owned, read-only
dbs/fileintel.sqlite3       # producer-owned, read-only
dbs/ghintel.sqlite3         # producer-owned, read-only
rules/cache/active          # UUID active pointer
rules/cache/generations/... # immutable rules.yac + manifest.json
```

Run the non-mutating readiness check before dispatching:

```bash
erecb-triage --config config/watcher_all.yaml --check
erecb-triage --config config/watcher_all.yaml --once
```

The YARA cache can be degraded while the remaining adapters run. A selected but unavailable
`yara-python` dependency is fatal at startup. A missing/incompatible producer database creates a
report with explicit unavailable evidence rather than a negative finding.

## Deterministic verification boundaries

Tests use inert, temporary fixtures and standard-library `unittest`. They verify report naming,
trusted extraction/recovery, producer read-only access, YARA cache identity, status summaries,
and manifest-bound inventory. Generated timestamps, capture generation names, and temporary
directories are expected to vary; normalized evidence and fixed archive-basename report slots do
not.

Rebuilding artifacts is described in `DISTRIBUTION_UBUNTU.md`. Runtime operation and recovery is
described in `../docs/OPERATOR_RUNBOOK.md`.
