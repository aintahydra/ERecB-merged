# ERecB-FileIntel Detailed Design

## 1. Scope

This document expands `DESIGN_01-Top_Level.md` into an implementation-ready design. It keeps the first implementation small enough to build quickly while preserving extension points for more intelligence providers and future processing modes.

The implementation target is a Python command line tool under `src/`.

Primary features covered here:

- Manual recursive directory scan.
- Watcher mode with configurable directory detection depth.
- Executable file detection using `python-magic`.
- SHA-256 and MD5 collection.
- CTX.IO intelligence lookup.
- Provider-neutral enrichment architecture.
- SQLite persistence and merge behavior.

## 2. Runtime Model

The tool has two entry points that share the same processing pipeline.

```text
Manual scan:
  CLI -> AppContext -> ScanService -> Repository -> EnrichmentService -> Repository

Watcher:
  CLI -> AppContext -> WatchService -> ScanService -> Repository -> EnrichmentService -> Repository
```

`AppContext` owns process-wide dependencies:

- Loaded configuration.
- Logger.
- Database connection factory.
- Repository object.
- Provider registry.
- Enrichment service.
- Scan service.

The scanner and providers should not create their own database connections directly. They receive dependencies from the application layer.

## 3. Proposed Source Layout

```text
src/
  erecb_fileintel/
    __init__.py
    __main__.py
    cli.py
    app.py
    config.py
    logging_setup.py
    models.py
    errors.py
    db/
      __init__.py
      connection.py
      schema.py
      repository.py
      migrations.py
    scan/
      __init__.py
      service.py
      walker.py
      classifier.py
      hashing.py
      executable_rules.py
    enrichment/
      __init__.py
      service.py
      merge.py
      providers/
        __init__.py
        base.py
        ctx_io.py
    watcher/
      __init__.py
      service.py
      detector.py
```

Responsibility split:

| Module | Responsibility |
| --- | --- |
| `cli.py` | Parse commands and options. |
| `app.py` | Build dependencies and expose command handlers. |
| `config.py` | Load and validate configuration. |
| `models.py` | Shared dataclasses and enums. |
| `db/repository.py` | All database reads/writes used by services. |
| `scan/service.py` | Coordinate one recursive scan job. |
| `scan/walker.py` | Directory traversal. |
| `scan/classifier.py` | Magic detection and executable decision. |
| `scan/hashing.py` | Streaming hash calculation. |
| `enrichment/service.py` | Coordinate provider lookups for hashes. |
| `enrichment/merge.py` | Canonical merge rules. |
| `providers/base.py` | Provider interface and normalized result model. |
| `providers/ctx_io.py` | CTX.IO API adapter. |
| `watcher/service.py` | Continuous watcher loop. |
| `watcher/detector.py` | Find new directories at configured watch depth. |

## 4. Configuration Design

Use YAML for the initial configuration because it is readable for operators and can express provider-specific settings cleanly.

Default file:

```text
config.yaml
```

Example:

```yaml
input_dir: in
watch_depth: 1
watch_interval_seconds: 10
database_path: dbs/fileintel.sqlite3
log_level: INFO

scan:
  follow_symlinks: false
  max_file_size_bytes: null
  hash_block_size_bytes: 1048576

enrichment:
  enabled_providers:
    - ctx_io
  provider_timeout_seconds: 30
  provider_retry_count: 2
  store_raw_responses: false
  raw_response_dir: data/provider_raw
  requery_success_after_days: null
  requery_failure_after_hours: 24

providers:
  ctx_io:
    api_key_path: ctx_io_api_key.txt
    base_url: https://api.ctx.io/v1
```

Validation rules:

- `watch_depth` must be an integer greater than or equal to `1`.
- `watch_interval_seconds` must be greater than `0`.
- `database_path` parent directory should be created if missing.
- `ctx_io.api_key_path` must exist if `ctx_io` is enabled.
- `hash_block_size_bytes` must be positive.
- `raw_response_dir` is required only when `store_raw_responses` is true.

Path handling:

- Relative paths are resolved against the current working directory where the CLI is run.
- Internal database records should store normalized absolute paths for scanned roots and file observations.

## 5. Domain Models

Use dataclasses for internal service boundaries. These are conceptual definitions; exact import paths can be adjusted during implementation.

```python
@dataclass(frozen=True)
class FileCandidate:
    path: Path
    name: str
    size_bytes: int

@dataclass(frozen=True)
class ClassificationResult:
    path: Path
    magic: str
    is_executable: bool
    reason: str

@dataclass(frozen=True)
class HashResult:
    sha256_hash: str
    md5_hash: str

@dataclass(frozen=True)
class FileObservation:
    scan_job_id: int
    file_path: Path
    file_name: str
    magic: str
    sha256_hash: str
    md5_hash: str

@dataclass(frozen=True)
class NormalizedIntel:
    provider_name: str
    provider_status: str
    sha256_hash: str | None
    md5_hash: str | None
    magic: str | None
    malicious: str | None
    tags: tuple[str, ...]
    file_names: tuple[str, ...]
    raw_response_path: str | None
    error_message: str | None
```

`malicious` should use canonical string values:

- `yes`
- `no`
- `unknown`

Provider lookup statuses:

- `success`
- `not_found`
- `auth_error`
- `rate_limited`
- `timeout`
- `network_error`
- `parse_error`
- `provider_error`
- `skipped`

Scan job statuses:

- `running`
- `succeeded`
- `partial`
- `failed`

Watch directory statuses:

- `new`
- `scanning`
- `scanned`
- `failed`

## 6. Database Schema

SQLite is the initial database. The schema should be created by `init-db` and also checked on normal startup.

### 6.1 DDL

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256_hash TEXT,
  md5_hash TEXT,
  magic TEXT,
  malicious TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (malicious IN ('yes', 'no', 'unknown'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_files_sha256
  ON files(sha256_hash)
  WHERE sha256_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_files_md5
  ON files(md5_hash);

CREATE TABLE IF NOT EXISTS file_names (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  file_name TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  UNIQUE (file_id, file_name, source)
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL,
  tag TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
  UNIQUE (file_id, tag, source)
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mode TEXT NOT NULL,
  root_path TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  files_seen INTEGER NOT NULL DEFAULT 0,
  executables_found INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0,
  CHECK (mode IN ('watcher', 'manual')),
  CHECK (status IN ('running', 'succeeded', 'partial', 'failed'))
);

CREATE TABLE IF NOT EXISTS scan_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_job_id INTEGER NOT NULL,
  file_path TEXT,
  phase TEXT NOT NULL,
  error_type TEXT NOT NULL,
  error_message TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_job_id INTEGER NOT NULL,
  file_id INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  file_name TEXT NOT NULL,
  magic TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  md5_hash TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY (scan_job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_observations_scan_job
  ON file_observations(scan_job_id);

CREATE INDEX IF NOT EXISTS idx_file_observations_sha256
  ON file_observations(sha256_hash);

CREATE TABLE IF NOT EXISTS provider_lookups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER,
  provider TEXT NOT NULL,
  query_hash TEXT NOT NULL,
  query_hash_type TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  requested_at TEXT NOT NULL,
  completed_at TEXT,
  raw_response_path TEXT,
  error_message TEXT,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_provider_lookups_file_provider
  ON provider_lookups(file_id, provider);

CREATE INDEX IF NOT EXISTS idx_provider_lookups_query_hash
  ON provider_lookups(query_hash);

CREATE TABLE IF NOT EXISTS watch_directories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  input_dir TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  absolute_path TEXT NOT NULL,
  watch_depth INTEGER NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_scan_job_id INTEGER,
  status TEXT NOT NULL,
  FOREIGN KEY (last_scan_job_id) REFERENCES scan_jobs(id) ON DELETE SET NULL,
  UNIQUE (input_dir, relative_path, watch_depth)
);
```

### 6.2 Repository API

All persistence should go through a repository object. Initial methods:

```text
initialize_schema()

create_scan_job(mode, root_path) -> scan_job_id
finish_scan_job(scan_job_id, status, files_seen, executables_found, error_count)
record_scan_error(scan_job_id, file_path, phase, error_type, error_message)

upsert_local_observation(observation) -> file_id
get_files_for_enrichment(scan_job_id) -> list[FileForEnrichment]

create_provider_lookup(file_id, provider, query_hash, query_hash_type) -> lookup_id
finish_provider_lookup(lookup_id, status, http_status, raw_response_path, error_message)

merge_intelligence(file_id, normalized_intel)

list_known_watch_directories(input_dir, watch_depth) -> set[str]
insert_watch_directory(input_dir, relative_path, absolute_path, watch_depth) -> watch_directory_id
update_watch_directory_status(watch_directory_id, status, last_scan_job_id)
```

The repository owns transactions. Service modules should not assemble multi-statement SQL directly.

## 7. Canonical Upsert and Merge

### 7.1 Local Observation Upsert

When the scanner finds an executable:

1. Compute lowercase `sha256_hash` and `md5_hash`.
2. Look up `files` by `sha256_hash`.
3. If not found, create `files` row with:
   - `sha256_hash`
   - `md5_hash`
   - local `magic`
   - `malicious = unknown`
4. If found, update only allowed fields:
   - Set `md5_hash` if missing.
   - Set `magic` if missing.
   - Do not change `malicious`.
5. Insert local basename into `file_names` with `source = local`.
6. Insert `file_observations` row.

MD5 must not be used as the only identity when SHA-256 exists. It is an auxiliary lookup and enrichment value.

### 7.2 Provider Intelligence Merge

For each `NormalizedIntel`:

1. Resolve the target `file_id`.
2. If provider returns a SHA-256 that conflicts with the local SHA-256, record lookup as `provider_error` or add a scan error-style warning. Do not overwrite.
3. If canonical `sha256_hash` is missing and provider SHA-256 exists, set it.
4. If canonical `md5_hash` is missing and provider MD5 exists, set it.
5. If canonical `magic` is missing and provider magic exists, set it.
6. Merge `malicious` using severity ordering:
   - `yes` outranks `no`
   - `yes` outranks `unknown`
   - `no` outranks `unknown`
   - `no` never overwrites `yes`
7. Insert unique tags with provider as source.
8. Insert unique file names with provider as source.
9. Update `files.updated_at`.

The top-level user requirement says `malicious` starts as `no` and only changes from `no` to `yes`. This design uses `unknown` for local-only records because no provider has yet stated that the file is normal. In reports, `unknown` can be displayed separately from `no`.

## 8. Scan Algorithm

### 8.1 Manual Scan

```text
function run_manual_scan(target_dir):
  config = load_config()
  root = normalize_and_validate_directory(target_dir)
  scan_job_id = repository.create_scan_job("manual", root)

  counters = ScanCounters()
  try:
    for candidate in walk_files(root):
      counters.files_seen += 1
      try:
        classification = classifier.classify(candidate.path)
        if not classification.is_executable:
          continue

        hash_result = hash_file(candidate.path)
        observation = build_file_observation(scan_job_id, candidate, classification, hash_result)
        repository.upsert_local_observation(observation)
        counters.executables_found += 1
      except RecoverableScanError as err:
        counters.error_count += 1
        repository.record_scan_error(scan_job_id, candidate.path, err.phase, err.type, err.message)

    enrichment.enrich_scan_job(scan_job_id)
    status = "partial" if counters.error_count > 0 else "succeeded"
    repository.finish_scan_job(scan_job_id, status, counters)
  except FatalScanError:
    repository.finish_scan_job(scan_job_id, "failed", counters)
    raise
```

The scan service should treat unreadable files as recoverable. A missing target directory is fatal.

### 8.2 Directory Walk

Rules:

- Use `os.scandir()` or `Path.iterdir()` recursively.
- Process regular files only.
- Default: do not follow symlinks.
- If `max_file_size_bytes` is configured, skip larger files and record a scan error with phase `scan`.
- Continue when a file disappears between listing and reading.

Traversal order does not need to be stable for correctness. Sorting paths may make tests deterministic, so it is recommended for initial implementation.

### 8.3 Magic and Executable Detection

`python-magic` returns variable strings depending on libmagic version. Rules should use case-insensitive substring matching.

Initial positive indicators:

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

Detection result should include a reason, such as `magic: PE32 executable` or `extension fallback: .ps1`, to simplify debugging.

## 9. Watcher Design

### 9.1 Directory Depth

Depth is relative to `input_dir`.

Example tree:

```text
in/
  a/
    b/
      c/
```

Depth values:

| Path | Relative path | Depth |
| --- | --- | --- |
| `in/a` | `a` | 1 |
| `in/a/b` | `a/b` | 2 |
| `in/a/b/c` | `a/b/c` | 3 |

With `watch_depth = 1`, only `a` is considered a watch target. Once `a` is seen and scanned, later creation of `a/b` does not trigger a separate watcher scan. It may still be scanned if it exists while `a` is being recursively scanned.

### 9.2 Polling Detector

Initial watcher implementation uses polling:

```text
function detect_watch_targets(input_dir, watch_depth):
  targets = set()
  recursively visit directories from input_dir until watch_depth
  for each directory where relative depth == watch_depth:
    targets.add(relative_path)
  return targets
```

The watcher loop:

```text
function watch():
  known = repository.list_known_watch_directories(input_dir, watch_depth)
  while true:
    current = detector.detect_watch_targets(input_dir, watch_depth)
    new_targets = current - known
    for relative_path in sorted(new_targets):
      absolute_path = input_dir / relative_path
      watch_id = repository.insert_watch_directory(...)
      repository.update_watch_directory_status(watch_id, "scanning", null)
      scan_job_id = scan_service.run_watcher_scan(absolute_path)
      repository.update_watch_directory_status(watch_id, final_status, scan_job_id)
      known.add(relative_path)
    sleep(watch_interval_seconds)
```

On startup, the watcher reads known targets from the database. This means previously processed directories are not automatically scanned again after restart.

### 9.3 Rescan Policy

The first version does not automatically rescan changed files inside an already known watch target. Watcher mode is directory-arrival based, not continuous file modification monitoring.

Later rescan options:

- Manual `scan` command.
- `watch --rescan-known`.
- Time-based reprocessing.
- File event monitoring.

## 10. Enrichment Design

### 10.1 Provider Registry

The provider registry maps names from config to provider instances.

```text
ctx_io -> CtxIoProvider
```

If an enabled provider is unknown, configuration validation should fail before scanning starts.

### 10.2 Enrichment Flow

```text
function enrich_scan_job(scan_job_id):
  files = repository.get_files_for_enrichment(scan_job_id)
  for file in files:
    for provider in enabled_providers:
      query_hash, query_hash_type = choose_query_hash(file, provider)
      if should_skip_recent_lookup(file, provider):
        continue

      lookup_id = repository.create_provider_lookup(...)
      try:
        raw = provider.lookup(query_hash, query_hash_type)
        intel = provider.normalize(raw)
        repository.finish_provider_lookup(lookup_id, intel.provider_status, ...)
        if intel.provider_status == "success":
          repository.merge_intelligence(file.id, intel)
      except ProviderAuthError:
        repository.finish_provider_lookup(lookup_id, "auth_error", ...)
        disable provider for remainder of current run
      except ProviderRateLimitError:
        repository.finish_provider_lookup(lookup_id, "rate_limited", ...)
        stop using provider until next run or configured backoff expires
      except ProviderError as err:
        repository.finish_provider_lookup(lookup_id, err.status, ...)
```

### 10.3 Lookup Repetition

Initial policy:

- Query each enabled provider for each executable found during a scan.
- If a prior successful lookup exists and `requery_success_after_days` is null, skip duplicate successful lookups.
- If a prior failed lookup exists, requery only after `requery_failure_after_hours`.

This avoids repeatedly consuming provider quota for known hashes.

## 11. CTX.IO Provider Details

### 11.1 Request

```text
GET {base_url}/file/report/{hash}
x-api-key: <api key>
```

Use SHA-256 as the query hash when available.

### 11.2 Response Handling

Successful response requirements:

- JSON response body can be parsed.
- `ctx_result.result_code == 200`.
- `ctx_data` exists.

Status mapping:

| Condition | Provider status |
| --- | --- |
| HTTP 200 and CTX result 200 with `ctx_data` | `success` |
| HTTP 401 or 403 | `auth_error` |
| HTTP 404 | `not_found` |
| HTTP 429 | `rate_limited` |
| Timeout | `timeout` |
| Network exception | `network_error` |
| Invalid JSON | `parse_error` |
| Other HTTP or CTX error code | `provider_error` |

### 11.3 Normalization

Hash normalization:

- Convert CTX.IO `sha256` and `md5` values to lowercase.
- Ignore empty strings.
- Validate expected hex length if practical:
  - MD5: 32 hex characters.
  - SHA-256: 64 hex characters.

Malicious normalization:

```text
if detect is missing:
  malicious = unknown
elif detect lowercased == "normal":
  malicious = no
else:
  malicious = yes
```

Tags:

- Combine `ctx_data.tags` and `ctx_data.threat_types`.
- Strip whitespace.
- Ignore empty values.
- Deduplicate case-sensitively for storage unless a later reporting layer wants case-insensitive display.

File names:

- Use `ctx_data.file_names`.
- Add local file names separately through local observation upsert.

## 12. CLI Design

Use `argparse` for the first implementation. It is enough for the expected command set and avoids extra dependencies.

Commands:

```text
python -m erecb_fileintel init-db --config config.yaml
python -m erecb_fileintel scan /path/to/target --config config.yaml
python -m erecb_fileintel watch --config config.yaml
python -m erecb_fileintel show-summary --config config.yaml
```

Future package command:

```text
erecb-fileintel scan /path/to/target --config config.yaml
```

Command behavior:

| Command | Behavior |
| --- | --- |
| `init-db` | Create or migrate database schema and exit. |
| `scan` | Run one recursive manual scan and exit with status summary. |
| `watch` | Run watcher loop until interrupted. |
| `show-summary` | Print counts of files, malicious files, tags, and recent scans. |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Completed with partial scan errors. |
| `2` | Configuration error. |
| `3` | Fatal scan error. |
| `4` | Database error. |
| `5` | Provider authentication error when provider use was required. |

## 13. Logging

Use Python `logging`.

Default log output:

- Console logs at configured level.
- Optional file logging can be added later.

Recommended log events:

- Application start and mode.
- Loaded config path.
- Database initialization.
- Scan job start and finish.
- Count of files seen and executables found.
- Recoverable scan errors.
- Provider lookup status.
- Provider authentication and rate limit events.
- Watcher detected directory.

Never log:

- API key value.
- Full raw provider response unless debug logging explicitly enables it and the user accepts the risk.

## 14. Testing Design

Unit tests should cover:

- Config validation.
- Watch depth target detection.
- Executable classification rules from sample magic strings.
- Hash calculation using known test files.
- Local DB upsert behavior.
- Merge rules for `malicious`, tags, file names, and missing hashes.
- CTX.IO response normalization.
- Provider status mapping.

Integration tests should cover:

- Manual scan against a temporary directory.
- Database schema creation.
- End-to-end scan with a mocked CTX.IO provider.
- Watcher detection without waiting on real long intervals.

Do not call the real CTX.IO API in automated tests by default. Use fixture JSON and mocked HTTP responses.

## 15. Implementation Sequence

Recommended detailed sequence:

1. Create package skeleton under `src/`.
2. Implement config loading and validation.
3. Implement SQLite connection and schema creation.
4. Implement repository methods for scan jobs, files, names, tags, and observations.
5. Implement hash calculation.
6. Implement magic classification and executable rules.
7. Implement manual scan mode.
8. Implement CTX.IO provider with mocked tests.
9. Implement enrichment service and merge rules.
10. Implement watcher directory detector.
11. Implement watcher service.
12. Add summary command.
13. Add integration tests.

Manual scan should be implemented before watcher mode because it proves the core processing pipeline with simpler control flow.

## 16. Deferred Features

The following features are intentionally outside the first implementation:

- Uploading files to external services.
- Scanning inside compressed archives.
- Distributed workers.
- Web UI.
- Real-time file modification monitoring.
- Advanced STIX/TAXII export.
- Multiple database backends.
- Automatic deletion or aging of old intelligence.

The design leaves room for these features through provider adapters, repository boundaries, and a scan job model.
