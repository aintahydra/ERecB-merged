# DESIGN 04: FileIntel Processor (`FileRetriever` Compatibility Adapter)

> Revision baseline: 2026-09-20. The FileIntel producer contracts are under
> [`providers/ERecB-FileIntel/design/`](../providers/ERecB-FileIntel/design/). This document defines only
> the offline consumer. Phase annotations are a work breakdown; status and release proof are
> centralized in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). Source files exist for
> this adapter, but this workspace contains no automated tests or verification reports.
> Detailed verification and integration tasks are in
> [`IMPLEMENTATION_03_IPINTEL_FILEINTEL.md`](IMPLEMENTATION_03_IPINTEL_FILEINTEL.md).

## 1. Scope

This document defines the `FileRetriever` analysis processor for the staged-capture pipeline
from `DESIGN_02_WATCHER_UNARCHIVER.md`.

`FileRetriever` is the existing compatibility name for the FileIntel pipeline adapter. It:

- Recursively scans a completed staged capture directory under `middle-earth/`.
- Identifies executable and script-like executable files.
- Calculates SHA-256 and MD5 for each executable using bounded streaming reads.
- Looks up local file intelligence in `dbs/fileintel.sqlite3`.
- Writes an evidence-linked Markdown report under `output/`.

The processor is offline. It does not call CTX.IO, VirusTotal, MalwareBazaar, or any other
external provider. The `erecb-fileintel` application under `providers/ERecB-FileIntel/` owns
enrichment collection, schema migration, and mutation of `dbs/fileintel.sqlite3`; its design
lives in its `design/` directory.

Section 12 defines the phased implementation plan, including unfinished staging and
dispatcher prerequisites. The behavior specified here is the target design, not a statement
that those prerequisites or the processor are already implemented.

## 2. Pipeline Position

`FileRetriever` runs after the dispatcher has staged the newly added input into
`middle-earth/`. In the standard full local-intelligence pipeline, it runs after
`IPRetriever`, but it must not depend on IP records existing.

Expected flow:

```text
in/2023-08-13_09-02-04.zip.en_dec appears
  -> watcher stabilizes the direct child and enqueues WatchEvent(kind=added)
  -> dispatcher stages input into middle-earth/2023-08-13_09-02-04.zip-260907-123456/
  -> dispatcher emits one completed staged_capture record
  -> dispatcher runs IPRetriever when configured
  -> dispatcher runs FileRetriever against the same staged_capture
  -> output/2023-08-13_09-02-04.zip.en_dec-fileintel.md
```

The watcher remains content-agnostic. The dispatcher owns processor ordering. `FileRetriever`
scans `staged_capture.staged_path`, not the original path under `in/`.

If `IPRetriever` returns no IP records, no DB hits, non-fatal errors, or an unexpected
adapter exception, `FileRetriever` still runs as long as there is a completed, usable
`staged_capture`. Analysis adapters are independent; only preprocessing failure suppresses
analysis for that event.

## 3. Configuration

The following is the planned combined local-intelligence configuration. Both adapters exist,
but the combined profile remains unaccepted until Phase 2 verification. The present
FileRetriever-only configuration is
`config/watcher_fileintel.yaml`; it keeps the same staging and FileRetriever settings while
using `analysis.processors: ["file_retriever"]`.

```yaml
watch:
  path: "./in"
  recursive: false
  event_debounce_ms: 500
  stable_check:
    enabled: true
    interval_ms: 250
    unchanged_checks: 3

dispatcher:
  max_workers: 1
  duplicate_policy: "skip_if_output_exists"
  staging_index_path: "./data/staging.sqlite3"
  staging_root: "./middle-earth"
  output_root: "./output"

pipelines:
  on_added:
    preprocessors:
      processors:
        - "stage_input"
    analysis:
      processors:
        - "ip_retriever"
        - "file_retriever"

processors:
  stage_input:
    type: "input_stager"
    output_root: "./middle-earth"
    unarchiver: "unarchive_all_supported"
    copy_directories: true
    copy_files: true
    archive_output_naming:
      strip_final_suffixes: [".en_dec", ".enc"]
      timestamp_format: "%y%m%d-%H%M%S"
      timezone: "UTC"
      collision_policy: "append_counter"

  unarchive_all_supported:
    type: "archive_unarchiver"
    output_root: "./middle-earth"
    max_depth_from_event_root: 2
    filename_regex: ".*\\.(en_dec|enc|zip|tar\\.gz)$"
    supported_formats:
      - ".en_dec"
      - ".enc"
      - ".zip"
      - ".tar.gz"
    max_archive_size_bytes: 107374182400
    max_total_extracted_bytes_per_archive: 214748364800
    max_extracted_files_per_archive: 200000
    overwrite: false

  ip_retriever:
    type: "ip_retriever"
    db_path: "./dbs/ipintel.sqlite3"
    output_root: "./output"
    chunk_size_bytes: 1048576
    chunk_overlap_bytes: 256
    max_file_size_bytes: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    report_suffix: "-ipintel.md"

  file_retriever:
    type: "file_retriever"
    db_path: "./dbs/fileintel.sqlite3"
    output_root: "./output"
    max_depth_from_staged_root: null
    max_file_size_bytes: null
    hash_block_size_bytes: 1048576
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    classifier:
      use_magic: true
      extension_fallback: true
    report_suffix: "-fileintel.md"
```

Configuration borrowed from `erecb-fileintel`:

- `db_path`
- `max_file_size_bytes`
- `hash_block_size_bytes`
- `follow_symlinks`
- executable classification rules based on magic strings and extension fallback

Configuration adapted for this staged-capture pipeline:

- `max_depth_from_staged_root` limits recursive scanning depth below one staged capture.
  `null` means scan the full staged tree. This is the closest equivalent to
  `erecb-fileintel` watcher depth, but it is applied inside a dispatcher-defined capture
  root rather than to decide what directory is a watch target.
- `include_hidden_files` and `include_hidden_directories` follow the same convention as
  `IPRetriever`.
- `report_suffix` is the required literal `-fileintel.md` for the standard processor.

`watch_depth` from `erecb-fileintel` is not used. This tool's watcher recognizes stable
direct children under `in/`; the dispatcher and stager define the scan root.

### 3.1 Validation Contract

Validation operates on resolved settings after defaults have been applied. Phase 3 implements
these rules in `config.py` through `file_retriever_settings()`. Configuration must not import `magic`, access
the intelligence DB, or create output directories as a side effect of validation.

| Setting | Default | Rule |
| --- | --- | --- |
| `type` | none | Required literal `file_retriever`. |
| `db_path` | `./dbs/fileintel.sqlite3` in default definition | Required nonempty string, no NUL or whitespace-only value; existence is checked at lookup time. |
| `output_root` | `./output` in default definition | Required nonempty string, no NUL or whitespace-only value. |
| `max_depth_from_staged_root` | `null` | `null` or integer >= 0; zero scans root-level files only. |
| `max_file_size_bytes` | `null` | `null` or integer >= 0; zero permits only empty files. |
| `hash_block_size_bytes` | `1048576` | Integer >= 1; never `null`. |
| `follow_symlinks` | `false` | Boolean. |
| `include_hidden_files` | `true` | Boolean. |
| `include_hidden_directories` | `true` | Boolean. |
| `classifier` | mapping below | Must be a mapping; omitted mapping/keys receive defaults. |
| `classifier.use_magic` | `true` | Boolean. |
| `classifier.extension_fallback` | `true` | Boolean. |
| `report_suffix` | `-fileintel.md` | Required literal `-fileintel.md`. |

For integer settings use exact integer types: booleans, numeric strings, and floats are
invalid. Boolean settings accept only booleans, not `0`, `1`, strings, or `null`. Reject
configurations with both classifier methods disabled. Missing required paths after default
resolution are configuration errors; an absent database file is a recoverable lookup issue.
Resolve relative paths with `resolve_path(dispatcher.base_dir, value)`, never against the
capture directory. Do not silently trim or rewrite configured paths.

Phase 3 boundary tests must include `null`, `0`, `1`, `-1`, `true`, `1.0`, and `"1"` for
integer settings; omitted and invalid classifier mappings; both methods disabled; missing,
empty, and NUL-containing paths; and the accepted suffix `-fileintel.md` plus rejected
alternatives `_fileintel.md`, `fileintel.md`, `../x`, `x/y`, `x\\y`, `.`, and `..`. Test
base-directory resolution with a working directory different from that base.

`file_retriever_settings(settings)` returns an independent dictionary with optional defaults
filled in, preserving path strings. Required `type`, `db_path`, and `output_root` must already
exist; `load_config()` fills these for the named default `file_retriever` definition. Custom
processor definitions provide their own required values. Use the existing `resolve_path()`
with the dispatcher's base directory when accessing configured DB/report paths. Phase 5
implements that resolution in the adapter. The default analysis processor list remains
empty; Phase 6 registers FileRetriever and supplies `config/watcher_fileintel.yaml` as the
explicit runnable pipeline.

## 4. Event and Record Model

### 4.1 Input Records

`FileRetriever` consumes `staged_capture` records:

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_path": "/abs/path/in/2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staged_path": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Production dispatch must pass a staged record. Manual unit tests may instantiate the processor
with a synthetic `staged_capture`, but the processor should not infer report identity from
`context.event.path`.

### 4.2 Output Records

Executable observation:

```json
{
  "type": "file_observation",
  "sha256_hash": "<64 lowercase hex characters>",
  "md5_hash": "<32 lowercase hex characters>",
  "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
  "classification_reason": "magic: pe32",
  "size_bytes": 34816,
  "source_path": "/abs/path/middle-earth/capture/tool.exe",
  "display_path": "middle-earth/capture/tool.exe",
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

File intelligence hit:

```json
{
  "type": "file_intel_hit",
  "sha256_hash": "<64 lowercase hex characters>",
  "md5_hash": "<32 lowercase hex characters>",
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-...",
  "match_type": "sha256",
  "file_entity_id": 1,
  "db_sha256_hash": "<64 lowercase hex characters>",
  "db_md5_hash": "<32 lowercase hex characters>",
  "source_paths": [
    "middle-earth/capture/tool.exe"
  ],
  "magic": "PE32 executable ...",
  "malicious": "yes",
  "created_at": "2026-09-04T01:00:00Z",
  "updated_at": "2026-09-04T01:30:00Z",
  "file_names": [
    {"file_name": "tool.exe", "source": "local", "first_seen_at": "2026-09-04T01:00:00Z"}
  ],
  "tags": [
    {"tag": "ransomware", "source": "ctx_io", "first_seen_at": "2026-09-04T01:30:00Z"}
  ],
  "provider_lookups": [
    {
      "provider": "ctx_io",
      "status": "success",
      "query_hash": "<64 lowercase hex characters>",
      "query_hash_type": "sha256",
      "http_status": 200,
      "requested_at": "2026-09-04T01:29:00Z",
      "completed_at": "2026-09-04T01:30:00Z",
      "raw_response_path": null,
      "error_message": null
    }
  ],
  "historical_observations": []
}
```

No DB row is still meaningful. The report must list the executable under "Executables Without
Local Intelligence" so analysts can distinguish local discovery from enrichment coverage.

### 4.3 Lookup Outcomes and Ambiguities

Emit exactly one `file_intel_lookup` for each unique successfully hashed SHA-256 in each
capture/run. It has the common hash/provenance fields from the hit above plus:

```json
{
  "type": "file_intel_lookup",
  "source_paths": ["middle-earth/capture/tool.exe"],
  "status": "miss",
  "error_code": null
}
```

This fragment must be combined with `sha256_hash`, `md5_hash`, `capture_name`,
`staged_capture`, `source_event_id`, and `pipeline_run_id`; these are required on all four
record types. `FileIntelLookup` and the other TypedDicts in
`src/erecb_triage/fileintel/contracts.py` define the complete Python shapes. They are type
contracts, not runtime validators. Phase 5 constructs these records from authorized captures,
discovery observations, and repository outcomes.

| `status` | Meaning | Additional record and report treatment |
| --- | --- | --- |
| `hit` | Complete canonical row and child queries succeeded. | One `file_intel_hit`; show `match_type` explicitly, including weak MD5 matches. |
| `miss` | Both hash queries completed successfully with no candidates. | No hit; show under Executables Without Local Intelligence. |
| `ambiguous` | No SHA-256 hit; MD5 candidates fail the fallback rules. | One `file_intel_ambiguity`; separate ambiguity section, never count as a miss or hit. |
| `unavailable` | DB could not be opened or its schema is incompatible. | Preserve local hashes under Intelligence Lookup Incomplete and emit a warning. |
| `error` | A query failed after the database was opened and validated. | Same incomplete section; never turn query failure into a miss or partial hit. |

`error_code` is null for `hit`, `miss`, and `ambiguous`. For `unavailable`, use
`fileintel_db_unavailable` or `fileintel_schema_incompatible`; for `error`, use
`fileintel_lookup_error`. Add a `ProcessorError` with that code and a useful message. Emit
one capture-level warning for an unavailable database rather than one warning per hash;
every affected hash still gets its own outcome. With zero hashes, report the database
availability check and any warning without inventing lookup records. Previously completed
lookups stay valid if a later query fails; a hash whose child query fails gets `error` and
no partially populated hit.

An ambiguity adds the following fields to the same common hash/provenance fields:

```json
{
  "type": "file_intel_ambiguity",
  "source_paths": ["middle-earth/capture/tool.exe"],
  "candidate_file_entity_ids": [4, 7],
  "reason": "multiple_md5_rows"
}
```

Sort candidate IDs ascending and deduplicate them. `reason` is `multiple_md5_rows` when
more than one row matches MD5, otherwise `conflicting_sha256` for a single row with a
different non-null SHA-256. Never emit an intelligence hit alongside an ambiguity.

### 4.4 Field Semantics and Provenance

- All fields in the TypedDicts are required. Nullable fields use `null`; absent child rows
  use empty lists. Current hashes are lowercase hexadecimal strings of length 64 and 32.
  Hashing failures produce errors, never observations with incomplete hashes.
- `sha256_hash` and `md5_hash` always describe current bytes, including on weak hits.
  `db_sha256_hash` and `db_md5_hash` preserve the canonical DB values, which may be null.
  `match_type` is required on every hit and is exactly `sha256` or `md5`.
- Observation `magic` is the local description or null; hit `magic` is the database's
  description or null. `classification_reason` is `magic: <matched indicator>` or
  `extension fallback: <lowercase extension>`.
- `source_path` and `staged_capture` are absolute paths. `display_path` and grouped
  `source_paths` are repository-relative when possible, otherwise absolute. Grouped paths
  are sorted, unique, nonempty, and must come from current observations in that capture.
- Deduplicate observations by `(staged_capture, sha256_hash, source_path)` within a run.
  Group outcomes and hits by `(staged_capture, sha256_hash)`. The same bytes in two captures
  yield independent records, metrics, and reports, even when they share a DB entity ID.
- `malicious` preserves the DB's `yes`, `no`, or `unknown`. Neither a miss, an unavailable
  DB, nor a provider failure implies `no`. Historical observations and provider metadata
  retain their source attribution and are never substituted for current source paths.
- Child record fields and nullability follow the selected columns in section 6. Timestamps
  are preserved as stored. Raw-response paths are metadata and must not be opened.

### 4.5 Metric Contract

Use these integer keys in `ProcessorResult.metrics` to avoid collisions with IPRetriever.
All counters start at zero per capture/run and are summed across captures by the adapter.

| Metric | Counting unit |
| --- | --- |
| `fileintel_files_scanned` | Distinct current regular-file paths whose classification completed, including non-executables and candidates whose later hashing failed. |
| `fileintel_files_skipped` | Distinct encountered file entries excluded by policy, unreadable, or failing classification/hashing; successful non-executables are not skipped. |
| `fileintel_executables_found` | Distinct paths classified as executable, even if subsequent hashing fails. |
| `fileintel_observations` | Successfully hashed executable paths after observation deduplication. |
| `fileintel_unique_hashes` | Unique observed SHA-256 values per capture. |
| `fileintel_lookup_hits` | Unique hashes with outcome `hit`. |
| `fileintel_lookup_misses` | Unique hashes with outcome `miss`. |
| `fileintel_lookup_ambiguities` | Unique hashes with outcome `ambiguous`. |
| `fileintel_lookup_unavailable` | Unique hashes with outcome `unavailable`. |
| `fileintel_lookup_errors` | Unique hashes with outcome `error`. |

Pruned directories and their unvisited descendants are not counted as skipped files. A
classified executable whose hashing fails counts as scanned, found, and skipped, but not as
an observation. Thus scanned and skipped are not disjoint; do not sum them as a total.
Each encountered path contributes at most once to any one counter.

Unfollowed symlink entries and special-file entries count as skipped without inspecting a
symlink target's type. When following links is enabled, cyclic directory links are pruned
with a warning and are not counted as skipped files. Hidden-entry rules apply to the names
encountered along the traversal path, including aliases.

The five lookup counters sum to `fileintel_unique_hashes`. For example, two executable
paths with identical bytes and one SHA-256 hit produce two scanned/found/observation counts,
one unique hash, one hit, and zero skips. With no DB, the same capture produces one
unavailable outcome and zero misses. Repeating those bytes in another capture increments
the aggregated unique-hash and lookup counters again.

## 5. Executable Discovery and Hashing

Use the scanning design from `providers/ERecB-FileIntel/design/DESIGN_02.md`, adapted to a read-only
analysis processor.

### 5.1 Dependency and Classification Contract

Use optional `python-magic` backed by the system `libmagic`. Phase 3 adds an optional
dependency extra and installation notes; Phase 1 requires no new runtime dependencies.
Inject a magic-description callable into classifier tests, so test outcomes do not depend
on the host's magic database or platform-specific descriptions.

If magic is explicitly disabled, do not import or call it and do not warn. If enabled but
the Python module or native library is unavailable, emit `fileintel_magic_unavailable` once
per capture and use extension fallback when enabled. Without fallback, preserve a report
warning that classification was unavailable, skip affected file entries, and do not present
the zero-executable count as a completed negative scan. Both methods explicitly disabled is
a configuration error, distinct from a missing optional dependency at runtime.

Match magic indicators case-insensitively, using the order below for deterministic reasons.
If no executable indicator matches, only an empty description or generic description
`data`, `ASCII text`, or `Unicode text` (case-insensitive, allowing comma-delimited detail)
is ambiguous and eligible for extension fallback. Other nonmatching descriptions are
definitive negatives. A positively identified ZIP container is also eligible for `.apk`
fallback, because APK is an executable package. A per-file detection/read error produces
`fileintel_classification_error` and skips that file; it is not a reason to invent a hit.

### 5.2 Discovery Rules

Required behavior:

- Walk recursively under each completed staged capture directory.
- Process regular files only.
- Do not execute, import, source, mount, or decode captured files as trusted code.
- Do not follow symlinks by default.
- Continue when a file disappears, is unreadable, or exceeds configured size limits.
- Sort traversal paths for deterministic tests and reports.
- Apply `max_depth_from_staged_root` to directories below `staged_path`; depth `0` means files
  directly inside the staged root.
- Use magic detection when available. Prefer local magic over extension-only hints.
- Use extension fallback only when configured and magic is missing, ambiguous, or unavailable.
- Compute SHA-256 and MD5 in a single streaming pass using `hash_block_size_bytes`.
- Normalize hashes to lowercase hex.
- Deduplicate observations by `(sha256_hash, source_path)`.

Initial executable indicators from `erecb-fileintel`:

```text
pe32
pe32+
msi installer
windows installer
elf 32-bit
elf 64-bit
elf
shared object
mach-o
dex
dalvik
posix shell script
bourne-again shell script
powershell
```

Initial extension fallback indicators:

```text
.exe
.dll
.sys
.ocx
.msi
.so
.dylib
.app
.dex
.apk
.ps1
.sh
.bash
```

APK files should be treated as executable candidates only when magic detection or extension
fallback identifies them. `FileRetriever` does not recursively unpack APK/ZIP contents; the
unarchiver controls archive expansion.

### 5.3 Implemented Discovery Service

Phase 3 exposes `scan_capture(capture, settings, base_dir, *, describe=None)` in
`fileintel/discovery.py`. The caller supplies a staged record with a canonical absolute
`staged_path`, matching safe `capture_name`, and current event/run IDs. The service validates
this shape; dispatcher readiness/ownership authorization remains the adapter's responsibility
in Phase 5. It never infers a root from a watch event or opens an intelligence database.

The returned `DiscoveryResult` contains `observations`, `errors`, discovery `metrics`, and
`classification_availability` (`available`, `degraded`, or `unavailable`). Metrics cover the
five discovery counters in section 4.5; lookup counters and their sum invariant apply after
Phase 4/5 lookup processing, not to a discovery-only result.

`ExecutableClassifier` receives at most 8192 bytes from a file header. When magic is disabled
or unavailable, extension fallback needs no header read. When magic is active, the header is
read in bounded blocks and passed as a prefix to `hash_stream()` along with the same open
reader. No rewind or second content pass is required. Both digests cover the entire file;
MD5 uses `usedforsecurity=False` for identification. Reads respect `hash_block_size_bytes`,
including when it is smaller than the header sample. Size checks during reading may consume
one byte beyond the limit to detect growth; oversized files never yield observations.

Traversal anchors file opens to a directory descriptor for the capture. Each physical path
component is opened without following symlinks; opt-in links are resolved to targets inside
the root before that traversal. Directory ancestor identities detect cycles, while distinct
in-root alias paths remain distinct observations. File descriptor/path identity, size, and
timestamps are checked across classification and hashing; unstable files yield no hashes.

Expected depth/hidden/initial-size/special-file exclusions increment skip counts without
warning spam. Failures use `ProcessorError` with these codes:

- `fileintel_magic_unavailable`: one dependency warning per capture.
- `fileintel_classification_error`: per-file detector failure or invalid description.
- `fileintel_read_error` / `fileintel_hash_error`: file read or hashing failure.
- `fileintel_size_limit`: a file crosses its limit during reading.
- `fileintel_source_changed`: file or source-path mutation detected during processing.
- `fileintel_path_outside_capture` / `fileintel_symlink_cycle`: rejected opt-in link targets.
- `fileintel_scan_error`: directory enumeration/open failure or changed capture root.

Per-file failures preserve successful observations from other files. A missing/replaced
capture root invalidates the scan's observations. Invalid settings or malformed capture
identity raise `ValueError` before scanning.

## 6. SQLite Lookup

Open `dbs/fileintel.sqlite3` with SQLite URI `mode=ro`; never fall back to a writable
connection. Do not create schema, run migrations,
insert scan jobs, insert observations, or mutate provider data from this processor.

The local database and `providers/ERecB-FileIntel/design/DESIGN_02.md` define these
lookup tables:

- `files`
- `file_names`
- `tags`
- `file_observations`
- `provider_lookups`

Lookup per unique SHA-256:

```sql
SELECT
  id,
  sha256_hash,
  md5_hash,
  magic,
  malicious,
  created_at,
  updated_at
FROM files
WHERE sha256_hash = ?;
```

If no SHA-256 row exists, perform constrained MD5 fallback as secondary intelligence.
This is part of the initial implementation, with no separate enable/disable setting:

```sql
SELECT
  id,
  sha256_hash,
  md5_hash,
  magic,
  malicious,
  created_at,
  updated_at
FROM files
WHERE md5_hash = ?
ORDER BY id;
```

MD5 fallback rules:

- Use SHA-256 matches as authoritative.
- If an MD5 lookup returns one row whose SHA-256 is null or equal to the observed SHA-256,
  treat it as a weak match and mark `match_type: md5`.
- If an MD5 lookup returns multiple rows or a row with a conflicting SHA-256, do not merge it
  as a hit. Emit a non-fatal ambiguity record and show the ambiguity in the report.

For a matched `files.id`, load child rows:

```sql
SELECT file_name, source, first_seen_at
FROM file_names
WHERE file_id = ?
ORDER BY source, file_name, id;

SELECT tag, source, first_seen_at
FROM tags
WHERE file_id = ?
ORDER BY source, tag, id;

SELECT
  provider,
  query_hash,
  query_hash_type,
  status,
  http_status,
  requested_at,
  completed_at,
  raw_response_path,
  error_message
FROM provider_lookups
WHERE file_id = ?
ORDER BY completed_at DESC, requested_at DESC, id DESC;

SELECT file_path, file_name, magic, observed_at
FROM file_observations
WHERE file_id = ?
ORDER BY observed_at DESC, file_path, id;
```

Use `file_observations` only as historical context from `erecb-fileintel`; do not treat those
paths as evidence for the current staged capture.

The historical Phase 1 reported verification of the local database's table/column definitions,
indexes, constraints, and foreign keys against the producer design. Phase 0 of the centralized
plan must recreate `tests/fixtures/fileintel_schema.sql` and a `fileintel_db_factory` in
`tests/conftest.py` to create independent temporary databases. The fixture includes `scan_jobs` to satisfy observation
foreign keys and retains the remaining producer tables for faithful schema fixtures.
The snapshot is test-only DDL, never a FileRetriever migration. Tests must not read or
modify the operational database. SHA-256 uniqueness is a partial unique index; MD5 is
nonunique, and multiple rows with null SHA-256 are legal. Compatibility checks must verify
the required lookup columns, not assume a schema version number alone proves compatibility.

### 6.1 Implemented Repository API

Phase 4 exposes `FileIntelRepository(db_path: Path)` in `fileintel/repository.py`. The caller
resolves `db_path` against the configuration base directory and supplies an absolute path.
Use one single-use context manager per capture, even when discovery found zero hashes:

```python
with FileIntelRepository(db_path) as repository:
    warning = repository.initialization_error  # Emit once per capture, if present.
    result = repository.lookup(sha256_hash, md5_hash)
```

Entering opens the URI with `mode=ro`, enables `query_only`, disables trusted schema, and
checks the five lookup tables and all selected/filter/order columns. Producer-only tables,
schema-version rows, and extra columns do not determine lookup compatibility. Initialization
failures close any opened connection and set `initialization_error` to a `ProcessorError`:
`fileintel_db_unavailable` for opening/reading failures or `fileintel_schema_incompatible`
for missing tables/columns. `available` indicates a currently usable initialized connection.

`lookup()` accepts lowercase hexadecimal SHA-256/MD5 digests from discovery and returns a
`LookupResult` with `status`, optional `intelligence`, sorted unique candidate IDs and reason
for ambiguities, and optional `error`. `FileIntelligence` contains only database-side hit
fields; it never supplies current source paths or capture/event/run identity. Child lists
preserve provider attribution, nullable fields, and historical metadata verbatim. A final
`id` ordering tie-breaker makes equal observation timestamps/paths deterministic.

Every uncached lookup uses a short read transaction so parent and child rows share one
snapshot. It releases the transaction before returning, including after a query failure.
A failed query yields `fileintel_lookup_error` and no partial intelligence. Unexpected
duplicate SHA-256 entities also yield an error rather than arbitrarily selecting one.
Queries bind hash values and parent IDs as parameters. Stored paths are never opened.

All outcomes, including misses and failures, are cached by observed SHA-256 for the session.
Conflicting MD5 values for a cached SHA-256 are invalid caller input and raise `ValueError`.
Returned data is copied so consumer mutation cannot contaminate later results. Each new
capture must create a new repository; close clears the cache and closes the connection.
Lookup outside the context and reopening a used repository raise `RuntimeError`.

Phase 5 attaches current evidence/provenance, deduplicates unavailable warnings, constructs
the section 4 records/counters, and renders reports. This repository does not modify local
observations or implement those adapter responsibilities.

## 7. Markdown Report

Output path for archive `in/<archive_file_name>`:

```text
output/<archive_file_name>-fileintel.md
```

Use `staged_capture.report_stem`, which equals the exact original archive basename including
all suffixes. Validate it against `source_name` and the source-relative basename. Keep
`capture_name` as staging provenance and validate that it agrees with `staged_path`; reject an
invalid record instead of silently deriving either identity.

Report identity and repeat processing:

- The dispatcher reserves/checks report ownership in its staging state before writing.
- If analysis runs again for the same input filename, `FileRetriever` may refresh that
  filename's existing canonical report after analysis succeeds.
- Write to a temporary file under `output/` and atomically replace only the report owned by
  the same source-relative path and processor.
- `Generated at` is report-generation UTC time and may change on refresh.

Report structure:

```text
# File Intelligence Report: 2023-08-13_09-02-04.zip.en_dec

## Summary

- Original input: in/2023-08-13_09-02-04.zip.en_dec
- Staging started at: 2026-09-07T12:34:56Z
- Staged path: middle-earth/2023-08-13_09-02-04.zip-260907-123456
- Files scanned: N
- Files skipped: N
- Executables found: N
- Executables with local intelligence: N
- Executables without local intelligence: N
- Unique executable hashes: N
- Lookup hits / misses / ambiguities / unavailable / errors: N / N / N / N / N
- Classification availability: available / degraded / unavailable
- Database availability: available / unavailable
- Generated at: UTC timestamp

## Executables With Local Intelligence

| SHA-256 | MD5 | Malicious | Tags | Names | Sources |
| --- | --- | --- | --- | --- | --- |

## Executables Without Local Intelligence

| SHA-256 | MD5 | Magic | Sources |
| --- | --- | --- | --- |

## Ambiguous MD5 Matches

| MD5 | Observed SHA-256 | Candidate DB Rows | Sources |
| --- | --- | --- | --- |

## Intelligence Lookup Incomplete

| SHA-256 | MD5 | Lookup Status | Error Code | Sources |
| --- | --- | --- | --- | --- |

## Warnings

Capture-level and per-file issues, including unavailable classification or intelligence.

## Details

### <sha256>

- MD5: <md5>
- Malicious: yes
- Magic: PE32 executable ...
- Classification reason: magic: pe32
- Tags: ransomware (ctx_io)
- Known names: tool.exe (local)
- Current source paths:
  - middle-earth/2023-08-13_09-02-04.zip-260907-123456/tool.exe
- Historical observations:
  - /older/path/tool.exe observed_at=...
- Provider lookups:
  - ctx_io success query=sha256 completed_at=...
```

Report requirements:

- Summary executable counts use paths; label unique-hash and lookup counts separately as
  in section 4.5. "Executables without local intelligence" counts only paths with confirmed
  `miss` outcomes; show ambiguity, unavailable, and error counts separately.
- Every listed executable must link back to at least one current staged source path.
- Keep current source paths relative to the repository root when possible.
- Escape Markdown table characters in values such as paths, tags, and file names.
- Sort by `malicious` severity, SHA-256, then source path for deterministic output.
- If the DB is missing or unreadable, still write a report with local executable hashes and a
  clear warning section.

### 7.1 Implemented Adapter and Report APIs

Phase 5 implements `FileRetriever(name, config, *, clock=None)` in
`processors/file_retriever.py`. `accepts()` checks for staged records; `process()` verifies
each capture against the ready staging index and trusted manifest before scanning. It also
checks source identity and current event/run provenance. Invalid captures return
`invalid_staged_capture` without scanning or publishing and do not suppress other valid
captures. Unrelated accumulated records are ignored; input records are not mutated.

Duplicate staged records are processed once per capture. Observations are deduplicated by
SHA-256 and source path within that capture, and each unique SHA-256 gets one lookup outcome.
The adapter opens a separate repository context for each capture, even when no hashes were
found. Capture-level database unavailability emits one warning; query errors retain their
per-hash outcome. All ten counters are summed across captures, with observation and
unique-hash counts recomputed after deduplication.

`render_report()` receives one capture's records, metrics, errors, availability values,
resolved base/report paths, and a timezone-aware generation timestamp. It labels path and
hash counts separately and sorts by verdict (`yes`, `unknown`, `no`), SHA-256, and path.
The staged name is preserved verbatim; the staging timestamp comes from the trusted index.
For directly copied inputs whose index timestamp is null, the report says `not recorded`.
Every executable has a current-source link. Labels are relative to the configuration base
where possible; URL targets are relative to the report directory and percent-encode the
actual filesystem bytes. HTML, Markdown delimiters, controls, and Unicode formatting/line
separators are escaped in untrusted metadata. Historical/provider paths remain plain text.

`publish_report(content, path, authorize)` requires the ownership-check callback to return
the expected reserved path before creating a temporary file and immediately before replacing
the report. The adapter supplies `ProcessingContext.report_path` with an additional check
against configured output root/suffix. Publication uses an exclusive, private temporary file
in the output directory, flushes and fsyncs it, then atomically replaces the owned target.
An open directory descriptor anchors temporary creation, replacement, and cleanup; a changed
directory identity or symlinked parent is rejected. The output directory remains operator-owned
and the existing single-dispatcher lock/ownership model applies.

Expected report I/O, reservation, or rendering-validation failures return
`fileintel_report_error` while preserving completed records and counters. Failed writes remove
temporary files and leave the previous report intact. Unexpected programming errors still
propagate to the dispatcher's analysis exception policy. Reports and processor records are
implemented. Phase 6 registers the processor and verifies watcher/CLI acceptance.

## 8. Implementation Layout

Add modules under the existing package:

```text
src/erecb_triage/
  processors/
    file_retriever.py
  fileintel/
    __init__.py
    contracts.py
    classifier.py
    discovery.py
    hashing.py
    repository.py
    report.py
```

Responsibilities:

- `fileintel/contracts.py`: shared typed dictionary shapes for observations and lookup results.
- `processors/file_retriever.py`: processor adapter, config resolution, record production.
- `fileintel/classifier.py`: magic and extension-based executable classification.
- `fileintel/discovery.py`: confined traversal, classification/hash composition, observations,
  discovery metrics, and per-file errors.
- `fileintel/hashing.py`: streaming SHA-256 and MD5 calculation.
- `fileintel/repository.py`: read-only SQLite access and mapping to internal objects.
- `fileintel/report.py`: Markdown rendering and atomic report publication.

The processor registry must map `file_retriever` to `FileRetriever`, and config validation
must accept `type: "file_retriever"` with a required `db_path`, `output_root`, positive
`hash_block_size_bytes`, optional nonnegative `max_file_size_bytes`, and safe `report_suffix`.

## 9. Dispatcher Changes Required

The dispatcher must support ordered analysis processors, not only preprocessors.

Pseudo-code:

```text
dispatch(event):
  context = create_context(event)
  records = []

  for processor in configured preprocessors:
    result = processor.process(records, context)
    records.extend(result.records)

  if not has_completed_staged_capture(records):
    return combined ProcessorResult

  for processor in configured analysis processors:
    if not processor.accepts(records, context):
      continue
    result = processor.process(records, context)
    records.extend(result.records)

  return combined ProcessorResult
```

With the standard local-intelligence pipeline:

```text
analysis.processors = ["ip_retriever", "file_retriever"]
```

Both processors consume the same `staged_capture`. `FileRetriever` must ignore IP record
types unless future correlation logic explicitly uses them.

## 10. Testing Plan

Phase 0 must recreate fixtures and schema-assumption tests in `tests/conftest.py`,
`tests/fixtures/fileintel_schema.sql`, and `tests/test_fileintel_schema.py`. They validate the
producer schema's hash uniqueness, MD5 ambiguity, verdict constraints, source attribution,
historical-observation foreign keys, nullable provider metadata, and read-only SQLite
behavior. They do not claim coverage of the future processor or runtime config validator.
Sections 3.1, 4.3-4.5, and 5.1 specify their boundary cases for the later behavior tests below.

Unit tests:

- Classifies executables from representative magic strings.
- Uses extension fallback only when configured.
- Computes SHA-256 and MD5 in one streaming pass.
- Skips files above `max_file_size_bytes`.
- Does not follow symlinks by default.
- Honors `max_depth_from_staged_root`.
- Deduplicates repeated `(sha256_hash, source_path)` observations.
- Reads `files`, `file_names`, `tags`, `file_observations`, and `provider_lookups`.
- Handles SHA-256 hits, missing rows, single weak MD5 fallback hits, and ambiguous MD5 rows.
- Handles missing or unreadable DB by still producing a report.
- Escapes Markdown table values.
- Uses the archive `report_stem` plus `-fileintel.md` for report paths and records the
  timestamped `capture_name` inside the report.
- Rejects invalid source/report identity or capture names inconsistent with `staged_path`.

Dispatcher tests:

- Runs `file_retriever` after `ip_retriever` when both are configured.
- Passes the original `staged_capture` record to `FileRetriever` after `IPRetriever` appends
  records.
- Runs `FileRetriever` when `IPRetriever` has no observations or no DB hits.
- Produces distinct staging identities for changed archive bytes and same-second collisions,
  then atomically refreshes the archive-filename-based report.
- Does not run `FileRetriever` on pending, failed, corrupt, or encrypted archive extraction
  output.
- Reserves report ownership before first write and rejects unrelated existing report paths.

Integration test:

```text
copy testdata/2023-08-13_09-02-04.zip.en_dec in/
run python -m erecb_triage --once --config config/watcher_localintel.yaml
expect middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/
expect output/2023-08-13_09-02-04.zip.en_dec-ipintel.md
expect output/2023-08-13_09-02-04.zip.en_dec-fileintel.md
expect file-intel report lists executable hashes and matching DB intelligence when present
```

## 11. Acceptance Criteria

- `FileRetriever` scans completed staged directories under `middle-earth/`, not original
  inputs under `in/`.
- It identifies executable and script-like executable files using magic-first classification
  with configurable extension fallback.
- It computes lowercase SHA-256 and MD5 with bounded streaming reads.
- It opens `dbs/fileintel.sqlite3` read-only and never mutates the DB.
- It queries canonical file intelligence by SHA-256, with constrained MD5 fallback.
- It writes `output/<archive_file_name>-fileintel.md` using the original archive basename.
- Missing DB rows are shown as executables without local intelligence, not as errors.
- Missing or unreadable DB still yields a local executable-hash report with a warning.
- Lookup failures and ambiguities are distinct from confirmed misses in records and reports.
- Dispatcher configuration can run `ip_retriever` followed by `file_retriever` for each
  completed staged capture.
- Duplicate captures retain stable report paths; changed inputs and staging-name collisions
  receive distinct staging identities and refresh the canonical filename-based report only
  after successful analysis.

### 11.1 Acceptance Status

Current source contains and registers both `ip_retriever` and `file_retriever`, but no checked-in
combined profile or executable test evidence exists in this workspace. The combined milestone
is therefore not release-accepted. Phase 1 of `IMPLEMENTATION_PLAN.md` adds the profile and
proves ordering, independent failure isolation, report ownership, and end-to-end behavior.

## 12. Phased Implementation Plan

Each phase produces a reviewable implementation and focused tests. Historical notes reported
Phases 1-5 and the FileRetriever-only portion of Phase 6 complete on 2026-09-09. The referenced
verification documents and test suite are absent from this workspace as of 2026-09-20, so the
current classification is **implemented, verification evidence missing**. Use the centralized
plan for authoritative status and restore the listed evidence before release acceptance.

### 12.1 Current Baseline and Dependencies

Source inspection at planning time shows:

- `dispatcher.py` runs only configured preprocessors, constructs only `ArchiveUnarchiver`,
  and has no enqueue boundary or separate analysis output root.
- `config.py` recognizes `input_stager` and `ip_retriever`, but neither processor module is
  present. Configuration acceptance therefore does not establish runtime availability.
- `staging.py` already contains capture identity, manifest verification, and report ownership
  helpers. Integrate these helpers according to DESIGN 02 rather than duplicate that state
  inside FileRetriever.
- `watcher.py` invokes its supplied dispatch callback directly. Watcher and CLI integration
  must expose the enqueue-and-drain contract described in DESIGN 02.
- FileRetriever modules, configuration validation, and tests remain to be added.

Phase 1 adds `fileintel/contracts.py`, a test-only schema snapshot, and isolated database
fixtures/tests. Phase 2 completes the shared staging/dispatcher prerequisites listed above
and fixes the legacy fixture failures. Phase 3 adds standalone discovery/hashing and full
setting validation. Phase 4 adds the standalone read-only intelligence repository.
Phase 5 composes the processor adapter and publishes reports. Phase 6 registers FileRetriever
and verifies its watcher/CLI path; real combined IP/FileIntel acceptance remains dependent on
DESIGN 03.

Implementation order:

```text
Phase 1: contracts and test baseline
  -> Phase 2: completed staging and ordered dispatcher
  -> Phase 3: executable discovery and hashing
  -> Phase 4: local database lookup
  -> Phase 5: processor records and report publication
  -> Phase 6: runtime integration and acceptance
```

After Phase 1, discovery and repository work can proceed independently of the staging work.
Phase 5 requires Phases 2-4. Phase 6 verifies the assembled application. Implementing
IPRetriever itself remains work defined by DESIGN 03: it is a prerequisite for the combined
pipeline acceptance test, but not for a usable FileRetriever-only pipeline.

### 12.2 Phase 1: Fix Contracts and Establish the Test Baseline

Historical status: reported complete on 2026-09-08. Contracts are finalized in sections 3-6 and
`fileintel/contracts.py`; schema fixtures and their 10 tests pass. The baseline report records
the 9 existing failures and the Phase 2 prerequisites. Runtime configuration validation,
classification, and record production remain assigned to their later phases.

Deliverables:

- Run the existing test suite and record existing failures before implementation. Review
  fixtures against the partially updated default configuration; do not assume the current
  checkout is a passing baseline.
- Confirm the required tables and columns against the local database using read-only schema
  inspection. Build temporary SQLite fixtures from that schema for automated tests; tests
  must not modify or depend on the contents of `dbs/fileintel.sqlite3`.
- Finalize the section 4 record contracts, including `match_type` on every intelligence hit
  (`sha256` or `md5`) and a defined ambiguity record containing observed hashes, current
  source paths, and candidate database row identifiers.
- Distinguish a successful lookup with no row from an unavailable or failed lookup in
  records, metrics, and report warnings. Missing intelligence is not a benign verdict.
- Define metric counting units: scanned/skipped files count paths, executable observations
  count paths, and database lookup outcomes count unique hashes per capture. Preserve all
  current paths when several files share a hash; do not merge capture provenance.
- Specify configuration validation for nullable nonnegative depth/size limits, positive
  block size, boolean scan/classifier settings, required paths, and safe report suffixes.
  Reject booleans where integers are required. Resolve paths relative to the dispatcher's
  configured base directory.
- Settle dependency behavior: use optional `python-magic` with system `libmagic`; report
  unavailable magic detection once per capture and apply extension fallback only when
  enabled. With both methods disabled, reject configuration. Keep classifier tests
  independent of host-installed magic data.
- Include the constrained MD5 fallback from section 6 in the initial implementation so the
  acceptance criteria do not depend on an unspecified optional feature.

Exit criteria: record fields, metric units, classification degradation, and validation rules
are documented alongside their tests; baseline failures and prerequisite work are identified.

### 12.3 Phase 2: Complete Staging and Dispatcher Prerequisites

Historical status: reported complete on 2026-09-08. `InputStager`, indexed publication/recovery, queue draining,
ordered analysis, report reservations, and startup runtime-availability checks are implemented.
The referenced Phase 2 verification document is absent and must be recreated.
This also completes the shared DESIGN 03 Phase 2 prerequisite; it does not implement either
intelligence processor. Indexed staging requires `overwrite: false`; replacement of existing
capture directories with `overwrite: true` remains unsupported and is rejected at startup.

Primary files: `staging.py`, `processors/input_stager.py`, `processors/base.py`,
`dispatcher.py`, `watcher.py`, and `__main__.py`.

Deliverables:

- Complete InputStager integration with the existing unarchiver and `StagingState`. Emit
  `staged_capture` only after successful publication or verified reuse of completed output.
  Pending or failed extraction must not authorize analysis. Preserve the stager-assigned
  capture name and the current event/run provenance.
- Add `enqueue(event)` and deterministic queue draining with `max_workers: 1`. Both normal
  watching and `--once` use this boundary; `--once` drains all accepted work before returning.
  A synchronous drain is sufficient for this phase, as allowed by DESIGN 02.
- Extend context with separate staging and analysis output roots and access to the existing
  capture/report ownership mechanism. Reserve paths for every configured analysis report,
  including FileRetriever, before publication.
- Run preprocessors once, then analysis processors in configured order against accumulated
  records. Preserve returned errors and metrics and check processor eligibility.
- Implement the section 2 failure policy explicitly: returned non-fatal errors and unexpected
  analysis exceptions are adapter-scoped and permit the next independent analysis processor.
  A preprocessing exception prevents analysis for that event. Continue handling subsequent
  queued events.
- Keep the preprocessor-only configuration usable. Reject configured processor types that
  cannot be constructed, while allowing unused definitions for future processors.

Verification: extend dispatcher/staging tests using small analysis test doubles. Assert
ordering, accumulated records, exception behavior, queue draining, report reservations,
duplicate reuse, changed-content naming, and suppression of analysis for incomplete output.

Exit criteria: a real staged capture reaches an analysis test double through the watcher/CLI
path, with trusted identity and reserved report ownership; no FileRetriever or IPRetriever
implementation is needed to prove this prerequisite.

### 12.4 Phase 3: Executable Discovery, Hashing, and Configuration

Historical status: reported complete on 2026-09-08. Standalone discovery, magic-first classification, streaming
hashes, configuration validation, and the optional dependency extra are implemented.
The historical record reported 206 passing tests. That suite and its Phase 3 verification
document are absent; recreate and rerun them before acceptance. The
native libmagic execution was not verified because the test interpreter lacks `python-magic`.

Primary files: `fileintel/classifier.py`, `fileintel/discovery.py`, `fileintel/hashing.py`, `config.py`, and
`pyproject.toml` where optional dependency metadata is needed.

Deliverables:

- Implement deterministic traversal and the classifier from section 5. Apply depth, hidden
  file/directory, and size settings consistently; depth zero includes root-level files only.
- Restrict reads to regular files and skip symlinks by default. If following symlinks is
  enabled, constrain resolved targets to the staged root and detect directory cycles.
  Reuse existing regular-file reading helpers where their semantics fit.
- Stream SHA-256 and MD5 together. Enforce size limits during reads as well as at initial
  stat, detect files changing during hashing, and discard incomplete hashes on failure.
  Return per-file errors without losing successful observations from the capture.
- Add FileRetriever defaults and validation without enabling an unavailable processor in the
  default runtime pipeline. Keep IP-specific validation separate from FileRetriever settings.

Verification: use inert binary headers, script text, and temporary files. Cover magic-first
classification, fallback enabled/disabled, missing magic support, hidden/depth boundaries,
size boundaries, empty files, known hashes, bounded reads, symlinks, special files, mutation,
and unreadable/disappearing files. Use controlled failures where OS permissions are unreliable.

Exit criteria: discovery returns deterministic local observations with correct hashes and
source paths, independently of any database or dispatcher.

### 12.5 Phase 4: Read-Only Intelligence Repository

Historical status: reported complete on 2026-09-09. Read-only schema validation, SHA-256/MD5 lookup, deterministic
child metadata, capture-scoped caching, and explicit failure outcomes are implemented.
The referenced Phase 4 verification document is absent and must be recreated.

Primary file: `fileintel/repository.py`.

Deliverables:

- Open an existing SQLite database strictly read-only, use parameterized queries, and close
  connections after processing. Check required schema compatibility without migration.
- Implement SHA-256 lookup, constrained MD5 fallback, child-row loading, and deterministic
  mapping according to section 6. Cache lookup results per unique hash within a capture.
- Keep historical database paths separate from current evidence. Treat provider fields,
  including `raw_response_path`, as stored metadata; do not fetch providers or open referenced
  files during lookup.
- Represent misses, weak hits, ambiguities, and database failures distinctly. Missing,
  unreadable, malformed, or incompatible databases must allow local hash reporting to
  continue with a warning and must never cause database creation.

Verification: temporary schema fixtures cover all queried tables, SHA-256 precedence, single
MD5-only rows, conflicting/multiple MD5 rows, missing child rows, repeated hashes, and database
failure cases. Check that lookup leaves fixture schema and contents unchanged and that opening
a nonexistent path creates no database.

Exit criteria: repository results preserve source attribution and match strength, and all
database failure cases leave local observations usable.

### 12.6 Phase 5: Processor Adapter and Markdown Reports

Historical status: reported complete on 2026-09-09. Capture authorization, observation/lookup records and counters,
escaped evidence-linked reports, and ownership-checked atomic publication are implemented.
The referenced Phase 5 verification document is absent and must be recreated.

Primary files: `processors/file_retriever.py` and `fileintel/report.py`.

Deliverables:

- Compose discovery and repository services behind the existing Processor interface. Accept
  only completed, usable staged captures; ignore unrelated accumulated records. Process each
  capture independently and preserve event/run identifiers.
- Produce observations, intelligence hits, ambiguity records, errors, and metrics according
  to the Phase 1 contracts. Deduplicate repeated observations without dropping distinct paths.
- Render the section 7 report, including zero-executable captures, misses, weak matches,
  ambiguities, partial scan failures, and unavailable intelligence. Show lookup availability
  explicitly so a failed lookup is not presented as a confirmed database miss.
- Escape untrusted text and encode source links correctly. Validate capture identity and
  report ownership before writing; publish through a temporary file in the output directory
  and atomic replacement. Clean up temporary files after failure and preserve any previous
  owned report if publication fails.

Verification: processor tests use synthetic staged records with real temporary files and
database fixtures. Report assertions cover all result categories, hostile Markdown/path
characters, stable ordering, name/counter preservation, invalid identity, publication failure,
and repeated report refresh. Assert successful records survive non-fatal per-file errors.

Exit criteria: invoking FileRetriever on a valid staged capture produces an evidence-linked
report and structured results, including when the database is unavailable.

### 12.7 Phase 6: Runtime Integration and Acceptance

Historical status: FileRetriever-only milestone reported complete on 2026-09-09. FileRetriever
is exported and registered, and `config/watcher_fileintel.yaml` is present. The referenced
Phase 6 verification document is absent. Both real adapters are now present, but their combined
profile and end-to-end test remain Phase 2 work in `IMPLEMENTATION_PLAN.md`.

Primary files: `processors/__init__.py`, `dispatcher.py`, configuration examples, CLI usage
documentation, and integration tests.

Deliverables:

- Export/register `FileRetriever` and support a runnable FileRetriever-only configuration
  with `analysis.processors: ["file_retriever"]`.
- Provide the full `config/watcher_localintel.yaml` example from section 3 and verify the real
  `ip_retriever` followed by `file_retriever` sequence. Test doubles verify ordering earlier
  but do not satisfy this combined integration requirement.
- Exercise watcher -> queue -> staging -> FileRetriever -> report using a generated inert
  executable fixture in an archive and a temporary intelligence database. Use a controlled
  clock for timestamp assertions; avoid depending on a live database hit or wall-clock date.
- Verify missing DB, no executables, no hits, duplicate input, changed archive bytes,
  same-second naming collisions, and failed/encrypted/corrupt extraction. Confirm the combined
  pipeline still produces file intelligence when IPRetriever returns no observations or
  non-fatal lookup errors.
- Document installation with and without magic support, configuration, report locations,
  and warning behavior. Run the existing watcher/unarchiver regression suite together with
  the new tests; resolve regressions introduced by this work and report remaining baseline
  failures separately.

Exit criteria: every section 11 acceptance criterion has passing verification. Both adapters
exist in current source, but the combined pipeline criterion remains open until tested with
both real processors. Record current proof in the centralized implementation plan rather than
adding another historical status claim here.
