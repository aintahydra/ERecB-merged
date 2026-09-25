# ERecB Intelligent Triage — Implementation Roadmap

## 1. Purpose

This document is the roadmap and index for implementing DESIGN 01-06. Detailed work is split
into the numbered `IMPLEMENTATION_01_...` through `IMPLEMENTATION_08_...` phase documents.

Supporting references: [reproduction](REPRODUCTION_GUIDE.md), [maintenance](MAINTENANCE_GUIDE.md),
and [Ubuntu distribution](DISTRIBUTION_UBUNTU.md).

The target workflow is:

```text
in/<archive_file_name>
  -> stable direct-child event
  -> safe, complete extraction under middle-earth/<unique_capture_name>/
  -> IPIntel -> FileIntel -> GHIntel -> YaraRuler
  -> output/<archive_file_name>-<processor>.md
```

Analysis order is deterministic, but the four adapters are independent and consume the same
ready `staged_capture`. A future correlation processor is separate.

## 2. Non-negotiable boundaries

1. Captured files are hostile data and are never executed, imported, sourced, or mounted.
2. Capture analysis performs no provider, GitHub, LLM, Git, or rule-repository network work.
3. Capture analysis opens IPIntel, FileIntel, and GHIntel databases strictly read-only. Explicit
   maintenance commands outside the capture pipeline invoke producer-owned merges.
4. YaraScan consumes one verified immutable YaraRuler cache generation and never compiles
   source rules in the event path.
5. YARA matches file content; hashes identify the exact matched file bytes.
6. Misses, null verdicts, provider failures, unavailable lookups, and zero YARA matches are not
   proof of benignness.
7. Only a manifest-verified `ready` staging generation reaches analysis.
8. Canonical reports use the exact original archive basename plus one fixed suffix:
   `-ipintel.md`, `-fileintel.md`, `-ghintel.md`, or `-yara.md`.
9. Report ownership is keyed by source-relative input path and processor. A successful newer
   generation at the same filename may atomically refresh that logical report slot.

## 3. Baseline audit (2026-09-20)

| Capability | Status | Main gap |
| --- | --- | --- |
| Watcher, dispatcher, stager, unarchiver | Implemented / verified baseline | Required-format and recovery corpus can grow over time |
| IPIntel adapter | Present / baseline verified | Broader producer-compatibility corpus remains Phase 03 work |
| FileIntel adapter | Present / baseline verified | Broader producer-compatibility corpus remains Phase 03 work |
| Archive-filename report naming | Implemented / verified | Stable slots refresh canonical hyphenated report paths |
| GHIntel adapter | Implemented / baseline verified | Broader producer-compatibility corpus remains Phase 04 work |
| YaraRuler pipeline adapter | Implemented / single-worker baseline verified | Process-worker equivalence awaits a compatible native-YARA corpus |
| Unified four-adapter profile | Implemented baseline | Full release verification remains Phase 06 work |

The local producer databases match the documented schema families, but consumers must
validate required tables/columns at runtime. A schema version alone is insufficient.

## 4. Phase index

Complete phases in dependency order. Independent processor phases 03-05 may proceed in
parallel only after phase 02 and their phase-01 contracts/fixtures are accepted.

| Order | Phase | Detailed plan | Depends on |
| --- | --- | --- | --- |
| 01 | Contracts and test foundation | [`IMPLEMENTATION_01_CONTRACTS_TEST_FOUNDATION.md`](IMPLEMENTATION_01_CONTRACTS_TEST_FOUNDATION.md) | Revised DESIGN 01-06 |
| 02 | Trusted ingestion and dispatcher | [`IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md`](IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md) | 01 |
| 03 | IPIntel and FileIntel | [`IMPLEMENTATION_03_IPINTEL_FILEINTEL.md`](IMPLEMENTATION_03_IPINTEL_FILEINTEL.md) | 02 |
| 04 | GHIntel | [`IMPLEMENTATION_04_GHINTEL.md`](IMPLEMENTATION_04_GHINTEL.md) | 02; phase-01 fixtures |
| 05 | YaraRuler | [`IMPLEMENTATION_05_YARARULER.md`](IMPLEMENTATION_05_YARARULER.md) | 02; phase-01 fixtures |
| 06 | Unified triage release | [`IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md`](IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md) | 03, 04, 05 |
| 07 | Scale and optional correlation | [`IMPLEMENTATION_07_SCALE_CORRELATION.md`](IMPLEMENTATION_07_SCALE_CORRELATION.md) | 06 and measured baseline |
| 08 | Two-machine intelligence exchange | [`IMPLEMENTATION_08_TWO_MACHINE_EXCHANGE.md`](IMPLEMENTATION_08_TWO_MACHINE_EXCHANGE.md) | Offline triage baseline and provider contracts |

Each phase document specifies objective, code surfaces, work packages, tests, verification
artifacts, and exit gate. Its presence does not indicate completion.

## 5. Phase outcomes

| Phase | Required outcome |
| --- | --- |
| 01 | Executable contracts, temporary producer fixtures, offline guards, and staging migration design |
| 02 | Hostile-safe archive-to-ready-staging boundary, dispatcher isolation, and canonical report slots |
| 03 | Verified read-only IPIntel and FileIntel reports from real staged captures |
| 04 | Producer-compatible offline GitHub address/project-card intelligence |
| 05 | Verified-cache YARA matching with target/rule provenance and no matched-byte leakage |
| 06 | Supported all-processors configuration, packaging, runbook, corpus, recovery, and soak proof |
| 07 | Measured optional optimizations/correlation that preserve phases 01-06 invariants |
| 08 | On-demand air-gap reports and request export, provider-owned LIFO enrichment, verified DB/cache return and merge |

## 6. Release-wide verification matrix

Every enabled adapter and integration path must prove:

| Area | Required proof |
| --- | --- |
| Input identity | duplicate reuse, changed-content separation, staging collision handling |
| Filesystem safety | traversal, link, special-file, disappearance, mutation, permission cases |
| Resource safety | byte/file/depth/time/worker/record/report bounds |
| Producer compatibility | every queried field exists; compatible newer inputs allowed |
| Read-only behavior | no DB/cache creation, migration, mutation, or fallback writable open |
| Outcome semantics | hit/miss/unavailable/error distinct; ambiguity and null preserved |
| Provenance | source archive, unique staging generation, current path, DB/cache/rule identity |
| Determinism | stable traversal, normalized records, metrics, report sections/order |
| Publication | exact archive-based name, logical ownership, private temp, atomic replacement |
| Isolation | per-file, per-adapter, and per-event failures preserve unrelated work |
| Offline operation | attempted network, Git/helper, provider, or source compilation fails tests |

## 7. Completion and status rules

A phase is complete only when code, tests, configuration, operator documentation, migration or
rollback notes, and a reproducible verification record land together. A prose “complete” label
or configuration entry is not evidence.

The unified release is done when:

- DESIGN 01-06 match implemented records, configuration, naming, and failure behavior;
- all four adapters run only on authorized ready staged captures;
- producer schemas/cache formats are validated and remain unmodified;
- all reports retain current evidence, exact staging and producer/cache provenance, and
  explicit uncertainty;
- clean-install, offline acceptance, interruption recovery, and sustained-run suites pass; and
- no critical issue permits path escape, captured-code execution, writable intelligence,
  unbounded hostile output, stale-report ambiguity, or report ownership violation.
