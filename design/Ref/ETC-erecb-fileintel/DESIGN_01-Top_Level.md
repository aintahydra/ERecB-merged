# ERecB-FileIntel Top-Level Design

## 1. Purpose

ERecB-FileIntel collects hashes of executable files, enriches those hashes with intelligence from external services, and stores the merged result in a local database.

The initial implementation should support:

- Watcher mode: monitor a configured input directory and process newly discovered directories.
- Manual scan mode: recursively process a user-specified directory.
- Phase 1 collection: identify executable files and compute `sha256` and `md5`.
- Phase 2 enrichment: query intelligence providers, initially CTX.IO.
- Persistent storage: merge newly collected values into existing records without losing previous intelligence.

Future implementations should be able to add more intelligence providers, such as VirusTotal or MalwareBazaar, without redesigning the scanner or database merge rules.

## 2. High-Level Architecture

The system is organized as a pipeline with independent components.

```text
             +----------------+
             | Configuration  |
             +-------+--------+
                     |
   +-----------------+-----------------+
   |                                   |
+--v-----------+              +--------v------+
| Watcher Mode |              | Manual Mode   |
+------+-------+              +-------+-------+
       |                              |
       +---------------+--------------+
                       |
                +------v------+
                | Scan Engine |
                +------+------+
                       |
                +------v------+
                | File Type   |
                | Classifier  |
                +------+------+
                       |
                +------v------+
                | Hash Engine |
                +------+------+
                       |
                +------v------+
                | DB Upsert   |
                +------+------+
                       |
                +------v------+
                | Enrichment  |
                | Orchestrator|
                +------+------+
                       |
       +---------------+---------------+
       |                               |
+------v------+                 +------v------+
| CTX.IO      |                 | Future      |
| Provider    |                 | Providers   |
+------+------+                 +------+------+
       |                               |
       +---------------+---------------+
                       |
                +------v------+
                | DB Merge    |
                +-------------+
```

## 3. Component Responsibilities

### 3.1 Configuration

The configuration layer provides runtime settings to all components. The initial configuration should support:

| Setting | Purpose | Example |
| --- | --- | --- |
| `input_dir` | Base directory watched in watcher mode | `in/` |
| `watch_depth` | Directory depth used to decide what counts as a new directory | `1` |
| `watch_interval_seconds` | Polling interval if filesystem events are not used | `10` |
| `database_path` | Local database file path | `dbs/fileintel.sqlite3` |
| `ctx_io_api_key_path` | CTX.IO API key file | `ctx_io_api_key.txt` |
| `enabled_providers` | Ordered provider list | `["ctx_io"]` |
| `provider_timeout_seconds` | HTTP timeout per provider request | `30` |
| `provider_retry_count` | Retry count for temporary failures | `2` |
| `max_file_size_bytes` | Optional maximum scanned file size | unset |
| `follow_symlinks` | Whether recursive scans follow symbolic links | `false` |

Recommended initial format: YAML or TOML. Environment variable overrides can be added later for deployment use.

### 3.2 Watcher Mode

Watcher mode monitors `input_dir` and starts a scan when a new directory is detected at the configured watch depth.

Depth behavior:

- Depth is measured relative to `input_dir`.
- `watch_depth = 1` means only immediate children of `input_dir` are recognized as watch targets.
- If `in/a` is detected and scanned, later creation of `in/a/b` is not independently detected when `watch_depth = 1`.
- `watch_depth = 2` would recognize `in/a/b` as a separate watch target.

Watcher state should be persistent, not only in memory. This prevents a restarted tool from reprocessing every known directory unless explicitly requested.

Recommended watcher state:

- Normalized absolute directory path.
- Relative path from `input_dir`.
- Watch depth.
- First seen time.
- Last scan start and finish time.
- Scan status.

Initial implementation can use polling for portability. A later implementation can replace the polling detector with OS filesystem events while keeping the same watcher state model.

### 3.3 Manual Scan Mode

Manual scan mode accepts a specific directory path and recursively processes it immediately.

Manual scans should:

- Not depend on `input_dir`.
- Reuse the same scan engine as watcher mode.
- Record a scan job in the database.
- Optionally update watcher state only if the scanned directory is also under the configured watched tree. This should not be required for correctness.

### 3.4 Scan Engine

The scan engine recursively walks a target directory and evaluates files one by one.

Responsibilities:

- Normalize the target directory path.
- Traverse recursively.
- Avoid infinite loops caused by symbolic links unless `follow_symlinks = true`.
- Skip unreadable files and record scan errors.
- Send each regular file to the file type classifier.
- Send executable files to the hash engine.
- Produce file observations with:
  - `sha256_hash`
  - `md5_hash`
  - `magic`
  - `file_name`
  - `file_path`
  - `scan_job_id`

The scanner should not call intelligence providers directly. It should only produce observations and store them, then hand hash values to the enrichment orchestrator.

### 3.5 File Type Classifier

The classifier uses `python-magic` to obtain the file magic string. It then determines whether the file should be treated as executable or script-like executable content.

Initial executable categories:

- Windows PE executables: PE32, PE32+, `.exe`, `.dll`, `.sys`, `.ocx`.
- Windows installers: MSI.
- Linux and Unix binaries: ELF32, ELF64, shared objects `.so`.
- macOS binaries: Mach-O.
- Android executable content: DEX, APK if detected as archive with Android contents.
- Scripts commonly used for execution: PowerShell, bash shell scripts.

The classifier should prefer magic detection over file extension. Extension-based hints can be used only as a fallback when magic output is ambiguous.

The executable detection rules should be isolated in one module or configuration file so the accepted file types can be tuned later.

### 3.6 Hash Engine

The hash engine computes:

- SHA-256
- MD5

Both hashes should be computed in a single streaming pass over the file to avoid loading large files into memory.

Hash values should be normalized to lowercase hex before storage. If an external provider returns uppercase hashes, those should also be normalized before merge.

### 3.7 Enrichment Orchestrator

The enrichment orchestrator receives hash records and calls enabled intelligence providers.

Responsibilities:

- Select the best available hash for each provider request. CTX.IO supports MD5, SHA-1, or SHA-256; the initial system should use SHA-256 when available.
- Call each enabled provider through a provider interface.
- Normalize provider-specific responses into a common intelligence result.
- Store provider raw response metadata where useful for troubleshooting.
- Merge normalized intelligence into the canonical file intelligence record.
- Record provider request success, not found, rate limit, timeout, and error states.

The orchestrator should be provider-agnostic. Adding VirusTotal or MalwareBazaar should require adding a provider adapter, not modifying scan logic.

### 3.8 Intelligence Provider Interface

Each provider adapter should expose the same conceptual interface:

```text
provider_name
lookup(hash_value, hash_type) -> ProviderLookupResult
normalize(raw_response) -> NormalizedIntel
```

`NormalizedIntel` should contain:

| Field | Meaning |
| --- | --- |
| `sha256_hash` | SHA-256 if known |
| `md5_hash` | MD5 if known |
| `magic` | Provider file type if known |
| `malicious` | Boolean or unknown |
| `tags` | List of normalized tags |
| `file_names` | List of known file names |
| `provider_name` | Source provider |
| `provider_status` | Success, not found, error, rate limited, etc. |
| `raw_reference` | Optional pointer to stored raw response |

Provider adapters should not write directly to the canonical intelligence table. They return normalized data to the orchestrator.

## 4. CTX.IO Provider Design

The initial provider is CTX.IO.

Request:

```text
GET https://api.ctx.io/v1/file/report/{hash}
Header: x-api-key: <api key>
```

API key source:

```text
ctx_io_api_key.txt
```

Initial normalization rules:

| Canonical field | CTX.IO source |
| --- | --- |
| `sha256_hash` | `ctx_data.hash.sha256` |
| `md5_hash` | `ctx_data.hash.md5` |
| `magic` | `ctx_data.file_type` |
| `malicious` | `ctx_data.detect != "normal"` |
| `tags` | `ctx_data.tags + ctx_data.threat_types` |
| `file_names` | `ctx_data.file_names` |

If CTX.IO returns no successful record, the system should keep the Phase 1 observation in the database and record the provider lookup status. Lack of provider data must not delete or downgrade local data.

## 5. Database Design

The initial database can be SQLite because the tool is local and pipeline-oriented. The design should avoid SQLite-specific assumptions in business logic so PostgreSQL can be introduced later if concurrent or centralized deployment is needed.

### 5.1 Main Tables

#### `files`

Canonical merged intelligence per executable hash.

| Column | Purpose |
| --- | --- |
| `id` | Internal primary key |
| `sha256_hash` | SHA-256, unique when present |
| `md5_hash` | MD5, indexed |
| `magic` | Best known file type or magic value |
| `malicious` | `yes`, `no`, or `unknown` |
| `created_at` | First record creation time |
| `updated_at` | Last merge time |

Recommended uniqueness:

- Prefer `sha256_hash` as the canonical identity.
- Use `md5_hash` as a secondary lookup key.
- If two partial records are later found to refer to the same executable, merge them into one canonical record.

#### `file_names`

Many-to-one names observed for a file.

| Column | Purpose |
| --- | --- |
| `file_id` | Reference to `files.id` |
| `file_name` | Observed or provider-reported file name |
| `source` | `local`, `ctx_io`, or future provider |
| `first_seen_at` | First seen time |

Unique key: `file_id`, `file_name`, `source`.

#### `tags`

Many-to-one tags observed for a file.

| Column | Purpose |
| --- | --- |
| `file_id` | Reference to `files.id` |
| `tag` | Tag or threat type |
| `source` | Provider name |
| `first_seen_at` | First seen time |

Unique key: `file_id`, `tag`, `source`.

#### `scan_jobs`

One row per manual or watcher-triggered scan.

| Column | Purpose |
| --- | --- |
| `id` | Internal primary key |
| `mode` | `watcher` or `manual` |
| `root_path` | Directory scanned |
| `status` | Running, succeeded, failed, partial |
| `started_at` | Start time |
| `finished_at` | Finish time |
| `files_seen` | Number of regular files inspected |
| `executables_found` | Number of executable files hashed |
| `error_count` | Number of scan errors |

#### `file_observations`

Local observations from actual filesystem scans.

| Column | Purpose |
| --- | --- |
| `id` | Internal primary key |
| `scan_job_id` | Reference to `scan_jobs.id` |
| `file_id` | Reference to canonical `files.id` |
| `file_path` | Full path at scan time |
| `file_name` | Basename at scan time |
| `magic` | Local magic result |
| `sha256_hash` | Local SHA-256 |
| `md5_hash` | Local MD5 |
| `observed_at` | Observation time |

#### `provider_lookups`

Records each provider lookup attempt.

| Column | Purpose |
| --- | --- |
| `id` | Internal primary key |
| `file_id` | Reference to `files.id` when known |
| `provider` | Provider name |
| `query_hash` | Hash submitted to provider |
| `query_hash_type` | `sha256`, `md5`, etc. |
| `status` | Success, not found, error, timeout, rate limited |
| `http_status` | HTTP status when available |
| `requested_at` | Request start time |
| `completed_at` | Request finish time |
| `raw_response_path` | Optional path to stored raw JSON |
| `error_message` | Error details when applicable |

#### `watch_directories`

Persistent watcher state.

| Column | Purpose |
| --- | --- |
| `id` | Internal primary key |
| `input_dir` | Configured watch root |
| `relative_path` | Directory relative to watch root |
| `absolute_path` | Normalized absolute path |
| `watch_depth` | Depth setting used when detected |
| `first_seen_at` | Detection time |
| `last_scan_job_id` | Last scan job for this directory |
| `status` | New, scanning, scanned, failed |

## 6. Merge Rules

Canonical file intelligence must only become more complete or more severe.

Field-level merge behavior:

| Field | Rule |
| --- | --- |
| `sha256_hash` | If empty or `none`, replace with a real hash value. Do not overwrite a different existing real value without conflict handling. |
| `md5_hash` | If empty or `none`, replace with a real hash value. Do not overwrite a different existing real value without conflict handling. |
| `magic` | If empty or `none`, replace with a new value. Prefer provider `file_type` only when local magic is missing, unless a later rule assigns source priority. |
| `malicious` | `yes` wins over `no` and `unknown`. `no` must not overwrite `yes`. |
| `tags` | Add new unique values. Do not remove old values during normal enrichment. |
| `file_names` | Add new unique values from local scan and providers. Do not remove old values during normal enrichment. |

Conflict handling:

- If an existing `sha256_hash` conflicts with a provider-returned `sha256_hash`, record a provider lookup warning and do not overwrite automatically.
- If a duplicate MD5 maps to multiple SHA-256 values, keep separate canonical file rows because MD5 is not collision-safe.
- If a provider reports suspicious or inconsistent data, preserve the local hash observation and store provider details separately for auditability.

## 7. Processing Flow

### 7.1 Watcher Flow

```text
1. Load configuration.
2. Ensure database schema exists.
3. Read known watch directories from DB.
4. List directories under input_dir to configured watch_depth.
5. For each newly detected directory:
   a. Insert watch_directories row.
   b. Create scan_jobs row with mode = watcher.
   c. Run recursive scan engine on that directory.
   d. Upsert local file hash observations.
   e. Enrich discovered hashes through enabled providers.
   f. Merge provider intelligence.
   g. Mark scan and watch directory status.
6. Sleep or wait for next filesystem event.
```

### 7.2 Manual Scan Flow

```text
1. Load configuration.
2. Ensure database schema exists.
3. Validate user-supplied target directory.
4. Create scan_jobs row with mode = manual.
5. Run recursive scan engine on target directory.
6. Upsert local file hash observations.
7. Enrich discovered hashes through enabled providers.
8. Merge provider intelligence.
9. Mark scan status and print summary.
```

## 8. Error Handling

The tool should continue processing other files and hashes when individual files or providers fail.

Expected error categories:

- Unreadable file.
- File removed during scan.
- Permission denied.
- Magic detection failure.
- Hash calculation failure.
- Provider timeout.
- Provider authentication failure.
- Provider rate limit.
- Provider malformed response.
- Database write failure.

File-level and provider-level errors should be recorded in the database and logs. A scan job should be marked `partial` if some files or provider lookups failed but the scan still completed.

Authentication failure against CTX.IO should disable further CTX.IO requests for the current run to avoid repeated failed API calls.

## 9. Security and Privacy Considerations

- Do not store API keys in the database.
- Read `ctx_io_api_key.txt` at runtime and keep it out of logs.
- Do not upload file contents to providers in the initial design; only hashes are submitted.
- Normalize and validate paths before scanning.
- Default `follow_symlinks` to `false` to avoid scanning outside expected trees.
- Store raw provider responses only if configured, because they may contain sensitive metadata.
- Logs should include hashes and statuses, but not API keys.

## 10. Initial Source Layout

Source code will later be placed under `src/`. A likely implementation layout is:

```text
src/
  erecb_fileintel/
    __init__.py
    cli.py
    config.py
    db.py
    watcher.py
    scanner.py
    classifier.py
    hashing.py
    enrichment/
      __init__.py
      orchestrator.py
      providers/
        __init__.py
        base.py
        ctx_io.py
```

This layout keeps scanning, provider integrations, and storage separated.

## 11. Initial CLI Shape

The exact CLI can be finalized during implementation, but the top-level commands should be:

```text
erecb-fileintel watch --config config.yaml
erecb-fileintel scan /path/to/target --config config.yaml
erecb-fileintel init-db --config config.yaml
erecb-fileintel show-summary --config config.yaml
```

`watch` runs continuously. `scan` runs one manual recursive scan and exits.

## 12. Design Decisions

| Topic | Decision |
| --- | --- |
| Primary language | Python |
| File type detection | `python-magic` |
| Initial DB | SQLite |
| Primary file identity | SHA-256 |
| Initial provider | CTX.IO |
| Provider architecture | Adapter interface returning normalized intelligence |
| Watcher implementation | Start with portable polling; allow later filesystem-event backend |
| API key storage | Read from `ctx_io_api_key.txt`, not DB |

## 13. Open Questions for Later Design

- Should provider lookups be performed synchronously during scan, or queued for background workers?
- Should the tool support re-enrichment of old hashes after a configured TTL?
- Should raw provider JSON be stored in DB, filesystem, or not at all by default?
- Should local file paths be retained permanently, or should only basenames be kept for privacy?
- Should archive inspection be supported for executable files inside ZIP, RAR, ISO, or APK containers?
- Should the database expose export formats such as CSV, JSONL, or STIX later?

## 14. Implementation Priorities

Recommended first implementation sequence:

1. Configuration loader.
2. SQLite schema and migration bootstrap.
3. Manual scan mode with classifier and hash engine.
4. Canonical DB upsert and merge rules.
5. CTX.IO provider adapter.
6. Enrichment orchestrator.
7. Watcher mode with persistent directory state.
8. Summary/reporting commands.

This sequence proves the core scan and enrichment path before adding continuous watching behavior.
