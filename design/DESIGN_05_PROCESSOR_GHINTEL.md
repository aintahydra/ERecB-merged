# DESIGN 05: GHIntel Processor

> Revision baseline: 2026-09-20. Producer architecture, data, normalization, and project-card
> semantics are defined under
> [`providers/ERecB-GHIntel/design/`](../providers/ERecB-GHIntel/design/). This processor is a read-only,
> offline consumer. Delivery status is centralized in
> [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
> Detailed delivery tasks are in [`IMPLEMENTATION_04_GHINTEL.md`](IMPLEMENTATION_04_GHINTEL.md).

## 1. Scope

This document defines the `GHIntel` analysis processor for the staged-capture pipeline in
`DESIGN_02_WATCHER_UNARCHIVER.md`.

`GHIntel`:

- Recursively scans a completed staged capture directory under `middle-earth/`.
- Extracts supported GitHub repository addresses from regular-file bytes.
- Normalizes each address to the same canonical repository identity used by the independent
  `ERecB-GHIntel` database producer.
- Looks up the repository's current project card in `dbs/ghintel.sqlite3`.
- Writes an evidence-linked Markdown report under `output/`.

The processor is an offline consumer. It does not invoke Git, inspect credential helpers,
clone repositories, call GitHub, or invoke any LLM provider. The independent ERecB-GHIntel
application owns discovery, enrichment, corrections, migrations, and all mutation of
`ghintel.sqlite3`. Its current design documents and actual database schema define the
producer contract; triage does not invoke that application's runtime.

The first implementation searches file contents only. Directory names and filenames are not
repository-address evidence. It does not infer a GitHub repository merely because a staged
tree contains a `.git` directory.

## 2. Pipeline Position and Failure Policy

`GHIntel` runs after the dispatcher has emitted a completed, usable `staged_capture`. A
recommended full pipeline is:

```text
in/capture.zip.en_dec appears
  -> watcher stabilizes and enqueues the input
  -> dispatcher stages it under middle-earth/<capture_name>/
  -> IPRetriever analyzes the staged capture
  -> FileRetriever analyzes the staged capture
  -> GHIntel analyzes the same staged capture
  -> YaraScan analyzes the same staged capture
  -> output/<archive_file_name>-ghintel.md
```

`GHIntel` consumes the `staged_capture` record directly. It must not require IP or file
intelligence records, and it ignores unrelated accumulated record types. A prior processor's
empty result, returned non-fatal errors, or unexpected exception does not suppress GHIntel.
If GHIntel itself raises unexpectedly, the dispatcher records an adapter-scoped error and
continues with YaraRuler and later events.

Errors while reading one captured file are non-fatal and do not discard observations from
other files. A missing, unreadable, or incompatible intelligence database is also non-fatal:
the processor still reports locally observed repository addresses and marks their lookups as
incomplete. Invalid processor configuration and inability to construct the processor are
startup failures.

## 3. Configuration

The combined pipeline adds the following processor definition and ordered processor name:

```yaml
pipelines:
  on_added:
    preprocessors:
      processors:
        - "stage_input"
    analysis:
      processors:
        - "ip_retriever"
        - "file_retriever"
        - "ghintel"

processors:
  ghintel:
    type: "ghintel"
    db_path: "./dbs/ghintel.sqlite3"
    output_root: "./output"
    chunk_size_bytes: 1048576
    max_candidate_bytes: 512
    max_file_size_bytes: null
    max_depth_from_staged_root: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    report_suffix: "-ghintel.md"
```

`chunk_size_bytes` controls bounded reads. Candidate recognition keeps a bounded carry state,
so results must not depend on chunk boundaries and `chunk_size_bytes` need not exceed
`max_candidate_bytes`.

`max_candidate_bytes` bounds an address-like ASCII run. An overlong run is discarded through
its next delimiter instead of being split into a false candidate.

`max_file_size_bytes: null` permits files of any size to be streamed. A non-null limit skips
files larger than the limit; the limit is checked before and during reading. A partial read
never contributes observations.

`max_depth_from_staged_root: null` scans the complete staged tree. Zero scans only regular
files directly below the staged root. Hidden settings apply to path components below the
staged root. Symlinks are not followed by default.

### 3.1 Validation Contract

Validation operates on resolved settings after defaults have been applied. It must not open
the intelligence database, traverse captures, or create report directories.

| Setting | Default | Rule |
| --- | --- | --- |
| `type` | none | Required literal `ghintel`. |
| `db_path` | `./dbs/ghintel.sqlite3` | Required nonempty string without NUL; existence is checked during processing. |
| `output_root` | `./output` | Required nonempty string without NUL. |
| `chunk_size_bytes` | `1048576` | Exact integer >= 1. |
| `max_candidate_bytes` | `512` | Exact integer in `64..4096`. |
| `max_file_size_bytes` | `null` | `null` or exact integer >= 0. |
| `max_depth_from_staged_root` | `null` | `null` or exact integer >= 0. |
| `follow_symlinks` | `false` | Boolean. |
| `include_hidden_files` | `true` | Boolean. |
| `include_hidden_directories` | `true` | Boolean. |
| `report_suffix` | `-ghintel.md` | Required literal `-ghintel.md`. |

Booleans, floats, and numeric strings are invalid for integer settings. Boolean settings
accept only booleans. Relative paths resolve against the configuration base directory, never
against a capture. Validation returns an independent settings mapping and does not silently
trim or rewrite configured paths.

## 4. Record Contract

### 4.1 Input

The processor accepts records of this form:

```json
{
  "type": "staged_capture",
  "capture_name": "capture.zip-260918-120000",
  "report_stem": "capture.zip.en_dec",
  "source_name": "capture.zip.en_dec",
  "source_path": "/abs/path/in/capture.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staged_path": "/abs/path/middle-earth/capture.zip-260918-120000",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

The adapter verifies the record against the dispatcher's ready staging index and trusted
manifest before reading it. A synthetic record may be used in isolated unit tests, but
production code must not derive capture identity from `context.event.path`.

### 4.2 Repository Observation

Emit one observation for each unique `(identity_key, source_path)` in a capture:

```json
{
  "type": "github_repository_observation",
  "identity_key": "github.com/owner/repository",
  "canonical_url": "https://github.com/Owner/Repository",
  "observed_address": "git@github.com:Owner/Repository.git",
  "occurrence_count": 2,
  "first_byte_offset": 128,
  "source_path": "/abs/path/middle-earth/capture/config.txt",
  "display_path": "middle-earth/capture/config.txt",
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

`identity_key` is the Unicode-case-folded `github.com/owner/repository` key. Display casing
comes from the first deterministically ordered observation until a database hit supplies the
producer's canonical URL. `observed_address` is bounded, control-free evidence from the first
occurrence on that path. Reports escape it as untrusted text.

### 4.3 Lookup Outcome and Intelligence Hit

Emit exactly one lookup record per unique identity in each capture:

```json
{
  "type": "github_intel_lookup",
  "identity_key": "github.com/owner/repository",
  "canonical_url": "https://github.com/Owner/Repository",
  "source_paths": ["middle-earth/capture/config.txt"],
  "status": "hit",
  "error_code": null,
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Statuses are:

| Status | Meaning |
| --- | --- |
| `hit` | The identity exists and the complete effective card was read. |
| `miss` | The read-only query completed and the identity does not exist. |
| `unavailable` | The DB could not be opened or required schema is incompatible. |
| `error` | The DB opened and validated, but this query failed. |

`error_code` is null for `hit` and `miss`. Use `ghintel_db_unavailable`,
`ghintel_schema_incompatible`, or `ghintel_lookup_error` otherwise. A database-wide problem
adds one capture-level `ProcessorError`; each affected identity still receives its own
outcome. Zero observed identities produce no invented lookup records, but the report states
whether database validation succeeded.

A hit additionally emits `github_intel_hit`:

```json
{
  "type": "github_intel_hit",
  "identity_key": "github.com/owner/repository",
  "repository_id": 7,
  "canonical_url": "https://github.com/Owner/Repository",
  "owner": "Owner",
  "name": "Repository",
  "information_status": "ready",
  "purpose": "Repository purpose",
  "tool_types": ["remote administration"],
  "capabilities": ["command execution"],
  "intended_uses": ["security testing"],
  "finding_version": 3,
  "finding_provenance": "deterministic-github-description",
  "finding_created_at": "2026-09-17T10:00:00+00:00",
  "github_owner": {
    "login": "Owner",
    "display_name": "Owner Name",
    "type": "Organization"
  },
  "github_captured_at": "2026-09-17T09:00:00+00:00",
  "stars_count": 10,
  "license_spdx": "MIT",
  "is_fork": false,
  "parent_url": null,
  "documented_people": [],
  "language_inference": null,
  "corrections_applied": ["summary"],
  "source_paths": ["middle-earth/capture/config.txt"],
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Nullable producer fields stay null. Empty relationships are empty lists. A database hit does
not imply that enrichment is complete: preserve `information_status` (`ready`,
`deterministic-only`, or `not-enriched`) and show missing fields as `Unknown` in the report.
The GitHub owner/account relationship is not presented as proof of authorship. Documented
people retain their producer role, quote, login, and confidence.

### 4.4 Metrics

| Metric | Counting unit |
| --- | --- |
| `ghintel_files_scanned` | Regular-file paths read to confirmed EOF. |
| `ghintel_files_skipped` | Paths excluded by policy or incompletely read. |
| `ghintel_observations` | Unique `(identity_key, source_path)` observations. |
| `ghintel_unique_repositories` | Unique identities in the capture. |
| `ghintel_lookup_hits` | Identities with `hit`. |
| `ghintel_lookup_misses` | Identities with `miss`. |
| `ghintel_lookup_unavailable` | Identities with `unavailable`. |
| `ghintel_lookup_errors` | Identities with `error`. |

The four lookup counters sum to `ghintel_unique_repositories`. Captures never share lookup
records or evidence, even when they contain the same identity.

## 5. Address Extraction and Normalization

Read captured files as bytes. Do not import, execute, source, decode wholesale, or invoke Git
on captured content. Traverse deterministically and do not follow symlinks by default.

Version 1 recognizes a conservative subset of the complete ASCII repository-root addresses
accepted by the producer's `normalize_github_url()`:

```text
https://github.com/owner/repository[.git][/]
http://github.com/owner/repository[.git][/]
git://github.com/owner/repository[.git][/]
ssh://[git@]github.com[:port]/owner/repository[.git][/]
git@github.com:owner/repository[.git]
github.com/owner/repository[.git][/]
```

The bare `github.com/...` form is an extraction convenience and is converted to HTTPS before
normalization. Host and scheme matching are ASCII case-insensitive. The canonical URL is
always `https://github.com/<owner>/<repository>` and the terminal `.git` and slash are
removed. The identity key case-folds the complete host/owner/name identity exactly as the
producer does.

An explicit SSH port must be decimal in `1..65535`; it does not participate in identity,
matching the producer normalizer. Version 1 deliberately rejects:

- non-GitHub hosts and lookalike suffixes such as `github.com.example`;
- HTTP credentials, query strings, fragments, controls, whitespace, backslashes, dot
  segments, missing segments, and more than two repository path segments;
- unsupported SSH users and malformed or out-of-range ports;
- GitHub subresource links such as `/owner/repo/blob/main/file`; and
- an address embedded in a larger ASCII word or path token.

Subresource URLs may be added later behind separate test vectors; they must map only a
validated repository prefix and must not weaken the exact-root grammar silently.

The streaming tokenizer retains enough bounded carry state to decide both candidate
boundaries. A candidate ending at a chunk boundary is held until a right delimiter or true
EOF. An interrupted read, size-limit transition, or changed file is not EOF. Deduplicate
repeated addresses after normalization while retaining occurrence counts by source path.

Use shared JSON extraction vectors across all supported split points. Vectors cover every
accepted transport, mixed casing, `.git`, punctuation, repeated observations, binary
delimiters, chunk boundaries, overlong tokens, lookalike hosts, credentials, queries,
fragments, subresource paths, malformed percent escapes, and Unicode adjacent bytes.

## 6. Read-Only SQLite Lookup

Open `dbs/ghintel.sqlite3` with SQLite URI `mode=ro`, set `PRAGMA query_only = ON`, use
parameterized queries, and never fall back to a writable connection. The processor does not
run migrations or create a missing database.

Validate the required schema surface before lookup. The local database currently records
producer migrations 1-6, but compatibility is capability-based rather than a hard-coded
version equality check. Require the tables/view and every selected/filter/order column used by
this consumer:

- `schema_migrations`, `repositories`, and `repository_project_cards`;
- `repository_current_findings`, `findings`, and `corrections`;
- `github_snapshots`, `people`, `repository_people`, and `language_inferences`.

Newer producer migrations are allowed when these required columns and semantics remain
available. Missing required columns are an incompatible schema, not a miss.

Lookup starts with the indexed identity:

```sql
SELECT *
FROM repository_project_cards
WHERE identity_key = ?;
```

Within one read transaction, load the newest GitHub snapshot, current finding's language
inference, current local-copy metadata if included in the report, and the latest
non-superseded correction for each supported field. Map `parent_full_name` to a canonical
GitHub parent URL only after validating its exact owner/repository shape. Apply correction
fields exactly as the producer does:
`summary` replaces `purpose`; `tool_types`, `capabilities`, and `intended_uses` replace their
corresponding arrays. Do not mutate the producer view or write a derived cache into this DB.

JSON array/object columns must decode to the expected shapes. Invalid JSON or a failed child
query makes that identity an `error`; do not emit a partially populated hit. A valid row with
null purpose or no finding is still a hit with its original `information_status`.

Database `local_copies` and source documents are historical producer provenance. They are not
evidence that the current capture contains a repository address. Current source paths always
come from this processor's byte scan.

## 7. Markdown Report

Write:

```text
output/<archive_file_name>-ghintel.md
```

Use `staged_capture.report_stem`, equal to the exact original archive basename including all
suffixes, after validating it against `source_name` and the source-relative basename. Validate
the timestamped `capture_name` against `staged_path` and include it as report provenance.
Reserve report ownership by source-relative path and processor through the dispatcher. Publish
through a private temporary sibling, flush/fsync, recheck ownership, and atomically replace
only that logical input filename's GHIntel report.

The report contains:

```text
# GitHub Intelligence Report: <archive_file_name>

## Summary

- Original input: ...
- Staged path: ...
- Files scanned: N
- Files skipped: N
- Unique repositories found: N
- Repositories with local intelligence: N
- Repositories without local DB records: N
- Repositories with incomplete lookups: N
- Database status: available | unavailable | incompatible
- Generated at: ...

## Repositories With Local Intelligence

| Repository | Status | Purpose | Tool Types | Sources |
| --- | --- | --- | --- | --- |

## Repositories Without Local Intelligence

| Repository | Sources |
| --- | --- |

## Intelligence Lookup Incomplete

| Repository | Lookup Status | Error Code | Sources |
| --- | --- | --- | --- |

## Warnings

## Details

### https://github.com/Owner/Repository

- Information status: ready
- Purpose: ...
- Tool types: ...
- Capabilities: ...
- Intended uses: ...
- GitHub owner: Owner (Organization)
- Documented people: ...
- Language inference: ...
- Finding version/provenance: ...
- Source paths:
  - middle-earth/<capture_name>/config.txt
```

Sort identities by `identity_key` and paths lexically. Escape Markdown, HTML, controls, and
Unicode formatting/line-separator characters in all untrusted database and capture values.
Repository links use validated canonical HTTPS URLs only. Source links target authorized
staged paths and percent-encode filesystem bytes. A miss is labeled `No local DB record`, not
`benign`. An unavailable lookup is never grouped with misses.

## 8. Implementation Layout

```text
src/erecb_triage/
  processors/
    ghintel.py
  ghintel/
    __init__.py
    contracts.py
    extractor.py
    normalization.py
    repository.py
    report.py
```

- `extractor.py` performs confined traversal and bounded streaming extraction.
- `normalization.py` implements the producer-compatible URL identity contract without
  importing the independent application's runtime.
- `repository.py` validates and reads the producer DB in read-only transactions.
- `report.py` renders and atomically publishes evidence-linked Markdown.
- `processors/ghintel.py` validates staged records and composes the services.

The processor registry maps type `ghintel` to `GHIntel`.

## 9. Security and Resource Boundaries

- Treat every captured path and byte as hostile.
- Never execute target content or use a captured `.git/config` through Git.
- Do not follow symlinks by default. If enabled later, constrain resolved targets to the
  staged root, track directory device/inode identities, and reject escapes.
- Stream files and bound carry state, diagnostics, observations, and rendered field lengths.
- Stat before and after reading. Discard every observation from a file whose identity, size,
  or nanosecond mtime changes.
- Never log file content, provider payloads, API keys, or unrelated database source text.
- Keep producer database values as descriptive intelligence. They do not prove that the
  repository caused the captured host's activity.

## 10. Testing Plan

Unit tests cover:

- every accepted and rejected address form and parity with ERecB-GHIntel normalization;
- candidates at every chunk split point and true-EOF handling;
- overlong tokens, binary delimiters, duplicate counts, and stable ordering;
- depth, hidden, size, symlink, special-file, mutation, and read-error behavior;
- read-only schema validation, hits, misses, null fields, malformed JSON, corrections,
  documented people, latest snapshots, and language inference;
- unavailable/incompatible DB outcomes without database creation;
- report escaping, safe canonical links, source links, ownership checks, and atomic refresh.

Dispatcher and integration tests cover:

- ordered execution after staging and independence from prior processor records;
- suppression for pending, failed, corrupt, or encrypted staging output;
- duplicate capture reuse, distinct changed/colliding staging names, and atomic refresh of the
  canonical archive-filename-based report;
- one capture containing multiple forms of the same identity across several files;
- a temporary producer-schema DB containing one ready, one deterministic-only, and one
  corrected project card; and
- a missing DB still producing observations and a report.

Tests use temporary schema fixtures and inert byte files. They never modify the checked-in
`dbs/ghintel.sqlite3` or access the network.

## 11. Acceptance Criteria

- GHIntel scans only authorized completed staged captures.
- It finds supported repository-root addresses in arbitrary regular-file bytes with results
  invariant to chunk boundaries.
- It produces the same canonical URL and identity key as the database producer.
- It opens `ghintel.sqlite3` strictly read-only and applies current-card corrections.
- Hits, misses, unavailable lookups, and query errors remain distinct in records and reports.
- Every reported identity links to at least one current staged source path.
- Missing enrichment fields remain unknown and GitHub ownership is not mislabeled as
  authorship.
- Read errors and an unavailable DB do not discard successful local observations.
- The report uses the original archive filename and the dispatcher's ownership and
  atomic-publication contract; the unique staging name remains visible as provenance.
- The processor performs no Git, GitHub, or LLM operation.

## 12. Phased Implementation Plan

Status as of 2026-09-20: design revised against the producer references and checked-in schema;
implementation has not started. See `IMPLEMENTATION_PLAN.md` for dependencies and gates.

### Phase 1: Contracts and Producer-Schema Fixture

Add typed records, frozen extraction vectors, a minimal migrations-1-through-6 schema fixture,
and tests that document correction and project-card semantics. Exit when record fields,
metrics, lookup statuses, and producer compatibility are executable specifications.

### Phase 2: Streaming Discovery and Normalization

Implement confined deterministic traversal, the bounded tokenizer, exact address grammar,
normalization, deduplication, and configuration validation. Exit when all vectors pass across
all chunk splits and filesystem boundary tests pass without a database.

### Phase 3: Read-Only Repository

Implement schema validation, read transactions, effective-card assembly, and explicit
hit/miss/unavailable/error results. Exit when temporary producer-schema fixtures cover full,
partial, corrected, malformed, missing, and incompatible database cases without mutation.

### Phase 4: Processor and Report

Compose extraction and lookup behind the Processor interface. Add trusted-capture checks,
records, metrics, error aggregation, report rendering, ownership authorization, and atomic
publication. Exit when a valid staged capture produces an evidence-linked report even with
an unavailable DB.

### Phase 5: Runtime Integration

Register `ghintel`, add a runnable configuration, packaging notes, watcher/dispatcher tests,
and an end-to-end inert archive fixture. Run the full existing regression suite. Exit when all
section 11 criteria have passing tests and the documented full pipeline can invoke GHIntel in
the configured order.
