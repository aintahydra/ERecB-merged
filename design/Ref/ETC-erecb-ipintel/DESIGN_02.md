# ERecB-IPIntel Detailed Top-Level Design

## 1. Scope

This document expands the top-level design into an implementation-ready plan. It defines the main modules, command flows, database responsibilities, provider boundaries, state handling, and validation strategy for the first implementation.

This document does not define final source code APIs line by line. Those details belong in implementation design or code-level documents under `design/` before work starts in `src/`.

## 2. Design Goals

Primary goals:

- Extract IPv4 and IPv6 addresses from files under configured directories.
- Support automatic discovery of new input directories using configurable recognition depth.
- Support manual recursive scans of a specified directory.
- Write deduplicated `IP; PATH` tuples to timestamped files under `output/`.
- Enrich unique IP addresses using CTX.IO first.
- Store accumulated intelligence in a portable SQLite database under `dbs/`.
- Keep provider integration replaceable and extensible.
- Avoid leaking credentials in logs, exceptions, test data, or generated artifacts.

Non-goals for the first implementation:

- Archive-aware extraction.
- GUI.
- Distributed execution.
- Real-time filesystem event processing as a hard requirement.
- Full threat-intelligence correlation across providers.
- Deletion or expiry policy for stale intelligence.

## 3. Runtime Model

The tool should be a local command-line application. Every command loads configuration, initializes the database if needed, performs one bounded task, and exits unless explicitly run in a polling or watch mode.

Recommended command model:

```text
erecb-ipintel init-db
erecb-ipintel discover
erecb-ipintel watch
erecb-ipintel scan DIR
erecb-ipintel enrich FILE [--provider ctx_io]
erecb-ipintel enrich-ip IP [--provider ctx_io]
erecb-ipintel status
```

Command responsibilities:

- `init-db`: create or migrate schema, then exit.
- `discover`: perform one automatic discovery pass under configured `input_root`.
- `watch`: repeatedly run discovery with a configured sleep interval.
- `scan DIR`: recursively scan a manually supplied directory and write one output file.
- `enrich FILE`: parse an extraction output file and enrich unique IPs.
- `enrich-ip IP`: enrich one validated IP.
- `status`: summarize DB path, enabled providers, visit-state counts, and recent provider failures.

The first implementation can ship only the commands required for immediate workflows, but internal services should be structured so the rest can be added without rewriting the architecture.

## 4. Configuration Plan

### 4.1 Configuration Sources

Configuration should be loaded in this order:

1. Built-in defaults.
2. Optional repository-local configuration file.
3. Environment variables for selected operational settings.
4. Explicit command-line options.

Later sources override earlier sources.

Recommended initial config file:

```text
config.yaml
```

YAML is readable and suitable for nested provider configuration. If minimizing dependencies is preferred, TOML is also acceptable through Python's standard `tomllib` for reading, but YAML is more familiar for operational config.

### 4.2 Configuration Fields

```yaml
paths:
  input_root: in
  output_root: output
  db_path: dbs/ipintel.sqlite3

discovery:
  recognition_depth: 1
  follow_symlinks: false
  watch_interval_seconds: 60
  retry_failed_directories: false

extraction:
  chunk_size_bytes: 1048576
  chunk_overlap_bytes: 256
  max_file_size_bytes: null
  include_hidden_files: true
  include_hidden_directories: true

database:
  store_raw_provider_json: true

providers:
  ctx_io:
    enabled: true
    base_url: https://api.ctx.io/v1
    api_key: null
    timeout_seconds: 30
    retry_count: 3
    retry_backoff_seconds: 2
```

### 4.3 Path Handling

All configured paths should be resolved relative to the repository root or current working directory selected by the application. Once resolved, modules should use normalized absolute paths internally.

For display and output files:

- Prefer paths relative to the repository root when possible.
- Preserve enough path information to locate the original file.
- Do not collapse distinct files into identical display paths.

## 5. Module Breakdown

Future source code under `src/` should be divided by responsibility.

Recommended package layout:

```text
src/erecb_ipintel/
  __init__.py
  cli.py
  config.py
  logging.py
  paths.py
  discovery.py
  scanner.py
  ip_extract.py
  output_writer.py
  enrich.py
  models.py
  db.py
  migrations.py
  providers/
    __init__.py
    base.py
    ctx_io.py
  tests/
```

Responsibilities:

- `cli.py`: command parsing and user-facing command orchestration.
- `config.py`: load, merge, validate, and expose configuration.
- `logging.py`: create safe logging helpers that avoid credential leakage.
- `paths.py`: path normalization, repository-root handling, filename sanitization.
- `discovery.py`: automatic directory discovery and visit-state transitions.
- `scanner.py`: recursive file traversal.
- `ip_extract.py`: chunked IP candidate extraction and validation.
- `output_writer.py`: deduplicated tuple file writing.
- `enrich.py`: parse output files, deduplicate IPs, call providers, merge results.
- `models.py`: typed internal data objects.
- `db.py`: repository operations and transactions.
- `migrations.py`: schema creation and future migration entry point.
- `providers/base.py`: provider adapter interface and common result types.
- `providers/ctx_io.py`: CTX.IO credential resolution, HTTP calls, and mapping.

## 6. Data Flow

### 6.1 Automatic IP Collection Flow

```text
discover command
  -> load config
  -> initialize DB
  -> enumerate recognized directory units at configured depth
  -> compare units with visited_directories
  -> mark new units pending
  -> for each pending unit:
       mark processing
       recursively scan regular files under that unit
       extract and validate IP candidates
       deduplicate (ip, path) tuples
       write output/ips_DIRNAME_YYMMDD-HHMMSS.txt
       mark done with output filename
       on failure, mark failed with safe error summary
```

The automatic flow records recognized directory units, not every descendant directory.

### 6.2 Manual Scan Flow

```text
scan DIR command
  -> load config
  -> validate DIR exists and is a directory
  -> recursively scan regular files under DIR
  -> extract and validate IP candidates
  -> deduplicate (ip, path) tuples
  -> write output/ips_DIRNAME_YYMMDD-HHMMSS.txt
  -> optionally record scan metadata in DB
```

Manual scans must not require or mutate automatic discovery state, except for optional scan-run metadata. This keeps manual processing predictable.

### 6.3 Enrichment Flow

```text
enrich FILE command
  -> load config
  -> initialize DB
  -> parse FILE as IP/path tuples
  -> validate and canonicalize IPs
  -> insert or update source observations
  -> create provider_run record
  -> for each unique IP:
       for each enabled provider:
         call provider.fetch(ip)
         call provider.normalize(ip, raw_result)
         merge normalized values into DB
         record provider_ip_results
  -> mark provider_run complete or partial failure
```

Provider failures should not abort the entire enrichment run unless initialization fails, credentials are unavailable, or the database cannot be updated.

## 7. Directory Discovery Details

### 7.1 Recognition Depth

Recognition depth is the number of path components below `input_root` that define a new work unit.

Examples:

```text
input_root = in
recognition_depth = 1

Recognized:
  in/a
  in/b

Not independently recognized:
  in/a/x
  in/a/x/y
```

```text
input_root = in
recognition_depth = 2

Recognized:
  in/a/x
  in/a/y
  in/b/z

Not independently recognized:
  in/a
  in/a/x/deeper
```

If `recognition_depth` is `0`, the design should reject it as invalid for automatic discovery. Manual scan covers root-level recursive processing.

### 7.2 Discovery Algorithm

Algorithm:

1. Resolve `input_root`.
2. If it does not exist, create it or return a clear configuration error. Creating it is convenient for first use.
3. Walk directory components until the configured depth is reached.
4. Collect directories exactly at that depth.
5. Normalize each recognized path relative to `input_root`.
6. Query `visited_directories` for matching `(input_root, relative_path, recognition_depth)`.
7. Insert unseen paths as `pending`.
8. Process pending paths in deterministic sorted order.

Symlink handling:

- Do not follow symlinked directories by default.
- Do not scan symlinked files by default unless explicitly enabled later.
- Record skipped symlinks at debug level.

### 7.3 State Transitions

```text
unseen -> pending -> processing -> done
                         |
                         v
                       failed
```

State rules:

- `pending`: discovered but not scanned.
- `processing`: currently being scanned.
- `done`: scan completed and output file was written.
- `failed`: scan failed for the unit.

Startup recovery:

- A previous `processing` row older than a configured threshold can be changed to `failed` or `pending`.
- First implementation may mark stale `processing` rows as `failed` with an explanatory message.

## 8. IP Extraction Details

### 8.1 Chunking

The extractor reads files as bytes.

Default:

```text
chunk_size_bytes = 1 MiB
chunk_overlap_bytes = 256 bytes
```

The overlap reduces the chance of missing an IP token split across chunk boundaries. The overlap must be larger than the maximum IP token length accepted by the tokenizer.

Processing logic:

1. Read a chunk.
2. Prefix it with the previous chunk tail.
3. Extract ASCII candidate spans.
4. Validate candidates.
5. Store canonical non-whitelisted IP/path tuples.
6. Save the last `chunk_overlap_bytes` bytes as the next tail.

Duplicate tuples across overlapped chunks are removed by the deduplication set.

### 8.2 Candidate Extraction

Candidate extraction should identify ASCII tokens that may contain IPv4 or IPv6 addresses without decoding whole files.

Candidate characters:

- digits
- ASCII letters
- `.`
- `:`
- `%`
- `-`
- `_`

The tokenizer should split on other bytes. After token extraction, cleanup rules may remove surrounding punctuation that often appears around URLs and structured text:

- `(`
- `)`
- `[`
- `]`
- `{`
- `}`
- `<`
- `>`
- comma
- semicolon
- single quote
- double quote

Boundary rule:

- Reject a candidate if the IP portion is embedded in a larger alphanumeric or hexadecimal token.
- Accept candidates surrounded by separators such as whitespace, slash, bracket, comma, or quote.

### 8.3 Validation and Canonicalization

Use Python's `ipaddress.ip_address()` for final validation.

Rules:

- Valid IPv4 is emitted in canonical dotted-decimal form.
- Valid IPv6 is emitted in compressed canonical form.
- Invalid IPv4 such as `999.1.1.1` is rejected.
- IPv4-like version strings such as `1.2.3.999` are rejected.
- IPv6 zone identifiers may be stripped before validation only when the candidate matches the documented zone-id form.

Special cases to define in extractor tests:

- `http://8.8.8.8/path`
- `[2001:db8::1]:443`
- `fe80::1%eth0`
- `abc8.8.8.8def`
- `192.0.2.1` validates syntactically but is discarded by the extraction whitelist
- `2001:db8::1deadbeef` when embedded in a larger hex token
- IP split across a chunk boundary
- duplicate IP in the same file
- same IP in multiple files

### 8.4 Ignored IPv4 Extraction Whitelist

After validation and canonicalization, the extractor applies a built-in IPv4 whitelist of ranges that are intentionally ignored. Matching addresses are suppressed from extraction output, but the validation helper may still canonicalize them for internal checks.

| Address block | Explanation |
| --- | --- |
| `0.0.0.0/8` | Current network |
| `10.0.0.0/8` | Private network |
| `100.64.0.0/10` | Private network. Shared address space between a service provider and its subscribers |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `172.16.0.0/12` | Private network |
| `192.0.0.0/24` | Reserved (IANA) |
| `192.0.2.0/24` | TEST-NET-1, Documentation and example code |
| `192.88.99.0/24` | IPv6 to IPv4 relay |
| `192.168.0.0/16` | Private network |
| `198.18.0.0/15` | Network benchmark tests |
| `198.51.100.0/24` | TEST-NET-2, Documentation and examples |
| `203.0.113.0/24` | TEST-NET-3, Documentation and examples |
| `224.0.0.0/4` | Multicasts (former Class D network) |
| `233.252.0.0/24` | MCAST-TEST-NET |
| `240.0.0.0/4` | Reserved (former Class E network) |
| `255.255.255.255/32` | Broadcast |

## 9. Output File Details

### 9.1 File Format

Each output line:

```text
IP_ADDRESS; PATH
```

No header in the first implementation. A header would make manual reading easier, but it would require every parser to skip it. Keeping plain tuple lines is simpler.

### 9.2 Path Format

Use a path that is useful to the user and stable across local runs:

- If the source file is under the repository root, write a repository-relative path.
- Otherwise, write an absolute path.

The parser must split only on the first semicolon so paths containing semicolons can still be represented:

```text
ip, path = line.split(";", 1)
```

Trim whitespace around the IP field. Preserve the path after removing one optional leading space.

### 9.3 Naming

Automatic scan example:

```text
in/sample_batch/*
output/ips_sample_batch_260904-013000.txt
```

Manual scan example:

```text
erecb-ipintel scan /cases/case-001/evidence
output/ips_evidence_260904-013000.txt
```

Collision handling:

- Timestamp to seconds should normally prevent collisions.
- If the target filename exists, append `_1`, `_2`, and so on.

## 10. Intelligence Provider Details

### 10.1 Provider Adapter Contract

Provider adapters should expose a narrow contract:

```text
name: stable provider identifier, for example ctx_io
configure(config): load non-secret config
validate_credentials(): fail early with safe errors
fetch(ip): return raw provider result
normalize(ip, raw): return normalized intelligence
```

The collection engine should not know provider-specific JSON paths.

### 10.2 Normalized Intelligence Object

Normalized provider output:

```text
NormalizedIntelRecord
  ip: canonical IP queried
  ipv4: nullable string
  ipv6: nullable string
  country_code: nullable string
  whois: nullable string
  reverse_dns: list[string]
  malicious: nullable "Yes" | "No"
  related_iocs: list[string]
  related_actors: list[string]
  provider_name: string
  provider_result_code: nullable string
  provider_transaction_id: nullable string
  raw_response_json: nullable string
```

All list fields should be deduplicated while preserving first-seen order before database insertion.

### 10.3 CTX.IO Mapping Rules

CTX.IO uses `ctx_data` as the source for intelligence fields.

Direct fields:

- `ipv4 = ctx_data.ipv4`
- `ipv6 = ctx_data.ipv6` or null
- `country_code = ctx_data.country_code`
- `whois = ctx_data.whois`
- `reverse_dns = ctx_data.reverse_dns` or empty list

Malicious:

```text
if ctx_data.detect exists and ctx_data.detect != "normal":
    malicious = "Yes"
else:
    malicious = "No"
```

Related IOCs:

- Read `ctx_data.apt_ioc_indicator`.
- Traverse dictionaries and arrays below it.
- Collect scalar leaf values.
- Convert leaf values to strings.
- Omit nulls and empty strings.
- Deduplicate.

Related actors:

- Read `ctx_data.apt_threat_actors`.
- For each actor object, collect:
  - `country_code`, uppercased when present
  - `name`
  - `aliases`
- Format as `(CC)Name/Alias1/Alias2`.
- If country code is missing, use `()Name/Alias1`.
- If aliases are missing, use `(CC)Name`.
- Omit actors with no name and no aliases.

### 10.4 HTTP Behavior

CTX.IO requests:

- Method: `GET`
- URL: `{base_url}/ip/report/{ip}`
- Header: `x-api-key`
- Timeout: configured timeout

Retry candidates:

- connection timeout
- read timeout
- HTTP 429
- HTTP 500, 502, 503, 504

Do not retry:

- HTTP 400
- HTTP 401
- HTTP 403
- syntactically invalid provider response

The request URL can be logged because it includes only the IP. Headers must not be logged.

## 11. Database Detailed Plan

### 11.1 SQLite File

Default:

```text
dbs/ipintel.sqlite3
```

The application should create `dbs/` automatically if missing.

Recommended SQLite settings:

```text
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
```

WAL creates sidecar files while the DB is active. For backup, stop the tool first or use SQLite backup APIs. If strict single-file backup is preferred at all times, use default rollback journal instead of WAL. This is an implementation decision to confirm later.

### 11.2 Tables

Schema version:

```sql
CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);
```

IP entities:

```sql
CREATE TABLE ip_entities (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  ip_version INTEGER NOT NULL CHECK (ip_version IN (4, 6)),
  ipv4 TEXT NULL,
  ipv6 TEXT NULL,
  country_code TEXT NULL,
  whois TEXT NULL,
  malicious TEXT NULL CHECK (malicious IN ('Yes', 'No')),
  first_seen_local TEXT NOT NULL,
  last_updated_local TEXT NOT NULL
);
```

Observations:

```sql
CREATE TABLE ip_observations (
  id INTEGER PRIMARY KEY,
  ip_entity_id INTEGER NOT NULL,
  source_path TEXT NOT NULL,
  extraction_file TEXT NULL,
  observed_at TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, source_path)
);
```

Reverse DNS:

```sql
CREATE TABLE ip_reverse_dns (
  ip_entity_id INTEGER NOT NULL,
  domain TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, domain)
);
```

Related IOCs:

```sql
CREATE TABLE ip_related_iocs (
  ip_entity_id INTEGER NOT NULL,
  ioc TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, ioc)
);
```

Related actors:

```sql
CREATE TABLE ip_related_actors (
  ip_entity_id INTEGER NOT NULL,
  actor TEXT NOT NULL,
  first_seen_local TEXT NOT NULL,
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id),
  UNIQUE (ip_entity_id, actor)
);
```

Provider runs:

```sql
CREATE TABLE provider_runs (
  id INTEGER PRIMARY KEY,
  provider_name TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'partial_failed', 'failed')),
  input_file TEXT NULL,
  ip_count INTEGER NOT NULL DEFAULT 0,
  success_count INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0
);
```

Provider results:

```sql
CREATE TABLE provider_ip_results (
  id INTEGER PRIMARY KEY,
  provider_run_id INTEGER NOT NULL,
  ip_entity_id INTEGER NOT NULL,
  provider_name TEXT NOT NULL,
  provider_status TEXT NOT NULL CHECK (provider_status IN ('success', 'not_found', 'failed')),
  provider_result_code TEXT NULL,
  provider_transaction_id TEXT NULL,
  fetched_at TEXT NOT NULL,
  error_summary TEXT NULL,
  raw_response_json TEXT NULL,
  FOREIGN KEY (provider_run_id) REFERENCES provider_runs(id),
  FOREIGN KEY (ip_entity_id) REFERENCES ip_entities(id)
);
```

Visited directories:

```sql
CREATE TABLE visited_directories (
  id INTEGER PRIMARY KEY,
  input_root TEXT NOT NULL,
  relative_path TEXT NOT NULL,
  absolute_path TEXT NOT NULL,
  recognition_depth INTEGER NOT NULL,
  first_detected_at TEXT NOT NULL,
  processed_at TEXT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'done', 'failed')),
  output_file TEXT NULL,
  last_error TEXT NULL,
  UNIQUE (input_root, relative_path, recognition_depth)
);
```

Recommended indexes:

```sql
CREATE INDEX idx_ip_entities_ip_version ON ip_entities(ip_version);
CREATE INDEX idx_ip_observations_path ON ip_observations(source_path);
CREATE INDEX idx_provider_ip_results_ip ON provider_ip_results(ip_entity_id);
CREATE INDEX idx_visited_directories_status ON visited_directories(status);
```

### 11.3 DB Merge Rules

When storing an enriched IP:

1. Ensure a row exists in `ip_entities`.
2. Apply scalar-field merge.
3. Insert reverse DNS values.
4. Insert related IOC values.
5. Insert related actor values.
6. Insert provider result audit row.
7. Commit the transaction.

Scalar-field merge:

- Prefer non-null new values over null old values.
- Replace old non-null values with new non-null values when the provider is the latest source.
- Preserve all provider result details in audit rows so overwritten scalar values remain explainable.

Malicious merge:

- `Yes` wins over `No`.
- `No` does not overwrite existing `Yes`.
- Null does not overwrite either value.

## 12. Logging and Error Messages

Log levels:

- `ERROR`: command failed or provider unavailable.
- `WARNING`: skipped file, failed provider call, malformed output line.
- `INFO`: command start/end, output file written, enrichment summary.
- `DEBUG`: individual file scan details and skipped symlinks.

Safe error requirements:

- Do not include API keys.
- Do not dump request headers.
- Do not dump full raw provider responses by default.
- Include enough context to debug: provider name, IP, status code, exception class, and safe short message.

## 13. Security Controls

File processing:

- Treat all input files as untrusted bytes.
- Do not execute input files.
- Do not import or parse input as active content.
- Do not follow symlinks by default.
- Limit memory by chunked reading.

Credential handling:

- Resolve CTX.IO key from explicit config, `CTX_IO_API_KEY`, then `ctx_io_api_key.txt`.
- Strip whitespace.
- Keep key in memory only.
- Avoid including key in config dumps.
- Add tests that verify safe exception messages do not expose a fake key.

Version-control exclusions:

```text
ctx_io_api_key.txt
dbs/
output/
*.sqlite3
*.sqlite3-shm
*.sqlite3-wal
```

## 14. Test Plan

### 14.1 Unit Tests

Configuration:

- defaults load correctly
- config overrides defaults
- environment variable overrides provider key
- local key file fallback works
- missing required provider key produces safe error

IP extraction:

- valid IPv4
- invalid IPv4
- valid compressed IPv6
- bracketed IPv6
- URL-contained IP
- zone identifier stripping
- embedded-token rejection
- chunk-boundary extraction
- binary-file extraction
- duplicate tuple removal

Directory discovery:

- depth `1` recognition
- depth `2` recognition
- descendant created after parent is done is not recognized at depth `1`
- failed state is recorded
- manual scan does not mutate visit state

CTX.IO normalization:

- direct field mapping
- missing `ipv6`
- missing `ctx_data`
- malicious mapping from `detect`
- flattened `apt_ioc_indicator`
- flattened threat actor with alias
- threat actor without alias

Database:

- schema creation
- insert IP entity
- insert observations
- merge scalar fields
- `Yes` malicious wins
- array tables deduplicate
- provider audit row inserted on success and failure

### 14.2 Integration Tests

Local filesystem workflow:

1. Create temporary `in/` tree.
2. Add files with valid and invalid IP candidates.
3. Run discovery.
4. Verify output file name and contents.
5. Verify `visited_directories` state.

Enrichment workflow with mocked CTX.IO:

1. Create extraction output file.
2. Use a fake CTX.IO HTTP response.
3. Run enrichment.
4. Verify normalized DB contents.
5. Verify no API key appears in logs or exceptions.

### 14.3 Manual Smoke Tests

Before first release:

```text
erecb-ipintel init-db
erecb-ipintel scan in/sample
erecb-ipintel enrich output/ips_sample_*.txt
erecb-ipintel status
```

## 15. Implementation Sequence

Recommended order:

1. Create project packaging and `src/erecb_ipintel/` package.
2. Implement configuration loading and path utilities.
3. Implement SQLite schema creation and repository helpers.
4. Implement chunked IP extraction with unit tests.
5. Implement recursive scanner and output writer.
6. Implement manual `scan DIR`.
7. Implement discovery state and `discover`.
8. Implement provider interface.
9. Implement CTX.IO adapter with mocked tests.
10. Implement enrichment DB merge.
11. Add `status` command.
12. Update `.gitignore` for generated artifacts.
13. Run end-to-end smoke tests.

This order reduces risk because extraction and storage can be verified locally before making external API calls.

## 16. Operational Notes

Backup:

- Stop the tool before copying `dbs/ipintel.sqlite3`.
- If WAL mode is enabled, copy the SQLite database using the SQLite backup API or include WAL sidecar files.

Recovery:

- If a run is interrupted during extraction, the affected directory may remain `processing`.
- A later `discover` command should identify stale `processing` rows and mark them failed or retry them according to configuration.
- If enrichment is interrupted, completed IPs remain committed. The provider run may show `running` until recovery logic marks it failed.

Performance:

- File scanning is I/O-bound.
- Provider enrichment is network-bound and rate-limit-sensitive.
- Initial implementation can process provider requests sequentially.
- Later implementation can add bounded concurrency per provider.

Portability:

- The SQLite file is the unit of intelligence portability.
- The output text files are portable scan artifacts.
- Configuration may need path adjustment when copied to another system.

## 17. Later Design Documents

Suggested follow-up documents:

- `DESIGN_03-IP_Extraction.md`: tokenizer, boundary rules, chunk handling, and test vectors.
- `DESIGN_04-Database.md`: final SQLite schema and migration strategy.
- `DESIGN_05-Providers.md`: provider interface, CTX.IO adapter, rate limits, and provider merge policy.
- `DESIGN_06-CLI_Operations.md`: final commands, config file format, logs, and operator workflows.

