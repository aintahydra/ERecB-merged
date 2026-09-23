# IMPLEMENTATION 01: Contracts and Test Foundation

## 1. Objective and status

Build the executable contract and verification foundation required by every later phase.
This document expands roadmap Phase 0 from `IMPLEMENTATION_PLAN.md`.

Status: **implemented (baseline)**. The standard-library offline suite, synthetic producer
fixtures, version-2 staging migration, strict IP/File report suffix contracts, and canonical
incremental profile are present. GHIntel/Yara-specific compatibility fixtures and guards remain
work for their implementation phases.

## 2. Dependencies and design inputs

- `DESIGN_01_SKELETON.md`: shared pipeline and record model.
- `DESIGN_02_WATCHER_UNARCHIVER.md`: staging identity, readiness, and report ownership.
- DESIGN 03-06: processor-specific records, metrics, reports, and producer boundaries.
- `providers/*/design/`: producer-owned schema/cache contracts.
- Checked-in `dbs/*.sqlite3`: compatibility examples, never test targets.

No later implementation phase may weaken the contracts frozen here without updating its
design, fixtures, migrations, and compatibility tests in the same change.

## 3. Deliverables

```text
tests/
  conftest.py
  fixtures/
    ipintel_schema.sql
    fileintel_schema.sql
    ghintel_schema.sql
    ipintel_extraction_vectors.json
    ghintel_url_vectors.json
    yararuler_cache/
  unit/
  integration/
docs/
  verification.md
config/
  watcher_all.yaml
```

Add development/test dependencies without making optional runtime integrations mandatory.
Define one documented local verification command that runs formatting/static checks, unit
tests, integration tests that need no optional native dependency, and import/package checks.

## 4. Work package A — shared vocabulary and records

Freeze these product-to-adapter mappings:

| Product name | Class compatibility name | Configuration type |
| --- | --- | --- |
| IPIntel | `IPRetriever` | `ip_retriever` |
| FileIntel | `FileRetriever` | `file_retriever` |
| GHIntel | `GHIntel` | `ghintel` |
| YaraRuler | `YaraScan` | `yara_scan` |

Define runtime validators or dataclasses for:

- `WatchEvent` with a normalized direct-child `relative_path`;
- `ProcessingContext` with one application base directory;
- `ProcessorError` and `ProcessorResult`;
- `staged_capture`, including:
  - unique timestamped `capture_name`;
  - exact original archive basename `report_stem`;
  - source-relative/absolute paths and source SHA-256;
  - staging method, ready-state identity, event ID, and run ID;
- normalized display paths confined to the staged root; and
- processor metrics with documented integer counting units.

Validation requirements:

- `report_stem == source_name == source_relative_path.name`;
- it is one component, not `.` or `..`, and contains no NUL/control/line-separator character;
- `capture_name == staged_path.name`;
- archive source digests are 64 lowercase hexadecimal characters;
- event/run provenance belongs to the current dispatch; and
- processors never reconstruct identity from `context.event.path`.

## 5. Work package B — staging-state schema migration design

The current state schema owns report paths through `reports(report_path, capture_id)`. The new
canonical report name is stable across capture generations, so ownership must instead be a
logical source/processor slot.

Introduce an explicit staging schema version and a table equivalent to:

```sql
CREATE TABLE report_slots (
  source_relative_path TEXT NOT NULL,
  processor_name TEXT NOT NULL,
  report_path TEXT NOT NULL UNIQUE,
  PRIMARY KEY (source_relative_path, processor_name)
);
```

Migration rules:

1. Back up or transactionally migrate only the staging-state database; never touch an
   intelligence database.
2. Preserve the existing `captures` identities and manifests.
3. Preserve legacy timestamp/underscore report rows and files without adopting, renaming,
   overwriting, or deleting them.
4. Create new logical slots lazily or from configured processors using the exact archive
   basename and fixed hyphenated suffix.
5. Reject a new computed path if it is an existing unowned filesystem entry.
6. Make migration idempotent and fail startup on an unknown newer staging schema.
7. Document optional legacy cleanup as a separate operator action after verification.

Add migration tests for empty, populated, partially migrated, corrupt, and newer-version state.

## 6. Work package C — configuration contract

Centralize defaults and strict type validation. The standard report suffixes are exact:

- `-ipintel.md`
- `-fileintel.md`
- `-ghintel.md`
- `-yara.md`

Reject duplicate enabled processors that would publish the same report path. Validate paths
without opening databases, traversing captures, loading YARA, importing optional libmagic, or
creating output directories.

All relative paths use the dispatcher's single application base directory. Add tests proving
that a processor cannot reinterpret a DB/cache/output path relative to a capture.

Create `config/watcher_all.yaml` as the target profile. Until GHIntel and YaraScan are
registered, either omit them from its selected analysis list or mark the profile explicitly
non-runnable; configuration must never pretend an unavailable type is active.

Reconcile `watcher_unarchiver.yaml` with the `input_stager` boundary. If direct unarchiver use
is retained for development, give it an explicit development name and state that it does not
provide the complete analysis trust contract.

## 7. Work package D — producer fixtures

Generate minimal test-only schema fixtures from documented required capabilities:

- IPIntel: entities, reverse DNS, related IOC/actor, provider run/result, and supporting
  observation/migration surfaces.
- FileIntel: files, names, tags, observations, provider lookups, scan jobs, constraints, and
  SHA-256/MD5 indexes needed to exercise ambiguity.
- GHIntel: migrations 1-6 surfaces used by the consumer, including project-card view,
  findings/current pointer, corrections, snapshots, people, and language inference.
- YaraRuler: one minimal valid immutable cache generation and isolated malformed pointer,
  manifest, digest, namespace, compatibility, and artifact fixtures.

Fixtures must contain inert synthetic content only. Tests must copy/build them in temporary
directories and must never open checked-in operational databases with a writable connection.

Add a compatibility inspection test that reads each checked-in DB with `mode=ro` and compares
only required tables/columns. Do not make test success depend on operational row contents.

## 8. Work package E — offline and immutability guards

Test-time guards must fail immediately on:

- socket/network client creation by a capture processor;
- subprocess Git or credential-helper invocation;
- writable SQLite opens against producer databases;
- schema creation/migration by a consumer;
- YARA source compilation or repository synchronization in the event path; and
- writes outside temporary input, staging, state, and output roots.

Record SHA-256 hashes of copied producer fixtures before and after each integration scenario.
For local producer databases, perform read-only metadata inspection only.

## 9. Test matrix

| Area | Required cases |
| --- | --- |
| Records | missing/extra fields, wrong types, unsafe names, stale run IDs, path mismatch |
| Configuration | defaults, unknown keys/types, bool-as-int, missing processor, duplicate report target |
| Migration | fresh DB, legacy DB, retry after interruption, unknown newer version, corrupt state |
| Schemas | exact required surface, missing table, missing column, allowed extra column/version |
| Offline guard | attempted socket, HTTP client, Git, provider SDK, writable SQLite |
| Paths | project base, capture-relative attack, symlinked state/output, filename length limit |

## 10. Verification artifacts

Check in:

- tests and all inert fixtures;
- the exact verification command and tool versions in `docs/verification.md`;
- a concise baseline result with passed/skipped tests and optional-dependency reason; and
- a generated list of checked design links and missing-link failure behavior.

Do not check in operational DB copies, capture data, provider responses, credentials, or
compiled caches from real rule repositories.

## 11. Exit gate

Implementation 01 is complete only when:

- the baseline suite passes from a clean checkout with network denied;
- staging migration tests are idempotent and preserve legacy state/files;
- all shared records and exact report suffixes are executable contracts;
- required producer capabilities are tested without writable operational DB access;
- invalid configuration and malformed staged records fail before analysis; and
- the verification record is present and reproducible.

Next: [`IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md`](IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md).
