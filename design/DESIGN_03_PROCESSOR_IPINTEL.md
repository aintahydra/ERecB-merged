# DESIGN 03: IPIntel Processor (`IPRetriever` Compatibility Adapter)

> Revision baseline: 2026-09-20. The IP database producer contracts are under
> [`providers/ErecB-IPIntel/design/`](../providers/ErecB-IPIntel/design/). This document defines only the
> offline consumer. Phase annotations below are a work breakdown; current status and proof are
> centralized in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). Source files exist for
> this adapter, but this workspace contains no automated test suite, so prior “complete” labels
> are not release verification.
> Detailed verification and integration tasks are in
> [`IMPLEMENTATION_03_IPINTEL_FILEINTEL.md`](IMPLEMENTATION_03_IPINTEL_FILEINTEL.md).

## 1. Scope

This document defines the next implementation slice after
`DESIGN_02_WATCHER_UNARCHIVER.md`.

The implementation adds an `IPRetriever` processor that:

- Recursively scans a staged capture directory under `middle-earth/`.
- Extracts IPv4 and IPv6 addresses from regular files using bounded chunked reads.
- Filters out non-actionable built-in IPv4 ranges.
- Looks up matching intelligence in the local SQLite database `dbs/ipintel.sqlite3`.
- Writes an evidence-linked Markdown report under `output/`.

`IPRetriever` is the existing compatibility name for the IPIntel pipeline adapter. It is
offline. It does not call CTX.IO or any external provider. The database is
produced by the `erecb-ipintel` application under `providers/ErecB-IPIntel/`, whose design lives
in its `design/` directory.

`DESIGN_04_PROCESSOR_FILEINTEL.md` adds `FileRetriever` as a later analysis processor in the
same staged-capture pipeline.

Section 12 defines the phased implementation plan. This document specifies target behavior;
configuration entries alone do not mean the processor or its staging prerequisites exist.

## 2. Pipeline Position

`IPRetriever` runs after the dispatcher has staged the newly added input into
`middle-earth/`.

Expected flow (staging starts at `2026-09-07T12:34:56Z` in this example):

```text
in/2023-08-13_09-02-04.zip.en_dec appears
  -> watcher stabilizes the direct child and enqueues WatchEvent(kind=added)
  -> dispatcher stages input into middle-earth/2023-08-13_09-02-04.zip-260907-123456/
       normal archive input: run Unarchiver
       exceptional directory/file input: copy into a same-named staging directory
       extracted member tree: 185.17.40.153:85/<files>
  -> dispatcher emits a staged_capture record
  -> dispatcher runs IPRetriever against middle-earth/2023-08-13_09-02-04.zip-260907-123456/
  -> dispatcher may then run FileRetriever against the same staged_capture
  -> output/2023-08-13_09-02-04.zip.en_dec-ipintel.md
```

The stager treats `.en_dec` as a ZIP alias and removes only that final suffix from the
wrapper label, retaining `.zip`. It preserves the inner `IP:PORT` directory. The capture name
includes the assigned UTC staging-start timestamp and any collision counter from DESIGN 02.

The watcher remains content-agnostic. It only reports stable filesystem additions under
`in/`. The dispatcher owns routing, staging, and processor ordering.

An empty IP result, a confirmed database miss, returned non-fatal errors, or an unexpected
IPIntel exception must not prevent other independent analysis adapters from consuming the
same completed capture. The dispatcher records an adapter-scoped exception and continues;
subsequent queued events also run.

## 3. Configuration

Extend `config/watcher_unarchiver.yaml` or create a successor such as
`config/watcher_ipintel.yaml` with an analysis stage.

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
        # Full local-intelligence pipelines append "file_retriever" here; see DESIGN 04.

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
    ip_singularity_threshold: 20
    max_observations_per_file: 1024
    max_observations_per_capture: 10000
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    report_suffix: "-ipintel.md"
```

For the standard IPIntel processor, `report_suffix` is the required literal `-ipintel.md`.

Staging and archive settings follow DESIGN 02, sections 5.1 and 6.3. The dispatcher-owned
`data/staging.sqlite3` maps archive identity to its persistent staging name; it is not an
intelligence DB and is not accessed by `IPRetriever`. Duplicate lookup precedes timestamp
allocation. `.en_dec` and `.enc` must validate as ZIP content; no decryption or direct-file
fallback is attempted for invalid archives.

Configuration borrowed from `erecb-ipintel`:

- `chunk_size_bytes`
- `chunk_overlap_bytes`
- `max_file_size_bytes`
- `follow_symlinks`
- `include_hidden_files`
- `include_hidden_directories`
- `db_path`
- `output_root`

`visit_recognition_depth` / `recognition_depth` is not used by `IPRetriever` in this
pipeline. The Step2 watcher already defines the work unit as one stable direct child under
`in/`, normally an archive file and only exceptionally a directory. The dispatcher defines the
scan root as the corresponding staged directory under `middle-earth/`.

## 4. Event and Record Model

### 4.1 Staged Capture Record

The staging preprocessor emits one record per staged work unit.

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staging_started_at": "2026-09-07T12:34:56Z",
  "source_path": "/abs/path/in/2023-08-13_09-02-04.zip.en_dec",
  "staged_path": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

`capture_name` is the final staging directory basename assigned by the stager, including the
UTC timestamp and any collision counter for archives. `source_name` retains the full original
filename. `source_sha256` and `staging_started_at` are required for archive captures and may be
omitted for exceptional directory/file captures.

A reused archive retains these saved identity and naming fields. `source_event_id` and
`pipeline_run_id` refer to the current invocation. Only completed, usable staged directories
are passed to analysis; pending or failed extraction must not trigger a scan or report.

Allowed `staging_method` values:

- `archive_extracted`
- `directory_copied`
- `file_copied`
- `skipped_existing_output`

### 4.2 IPRetriever Input

`IPRetriever` consumes completed, usable `staged_capture` records. Tests supply synthetic
staged records using the same contract. With no eligible staged record, skip analysis; do not
infer an input root or report identity from `context.event.path`.

### 4.3 IPRetriever Output Records

IP observation:

```json
{
  "type": "ip_observation",
  "ip": "8.8.8.8",
  "ip_version": 4,
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "source_path": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/config.txt",
  "display_path": "middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/config.txt",
  "staged_capture": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

IP intelligence hit:

```json
{
  "type": "ip_intel_hit",
  "ip": "8.8.8.8",
  "ip_version": 4,
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "staged_capture": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-...",
  "ip_entity_id": 1,
  "source_paths": [
    "middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/config.txt"
  ],
  "country_code": "US",
  "whois": "...",
  "reverse_dns": ["dns.google"],
  "malicious": "No",
  "related_iocs": [],
  "related_actors": [],
  "provider_results": [
    {
      "provider_name": "ctx_io",
      "provider_status": "success",
      "fetched_at": "2026-09-04T01:30:00Z"
    }
  ]
}
```

Lookup outcome records use the same six common identity fields as `ip_observation`, plus
`type: "ip_intel_lookup"`, `source_paths`, `status`, and nullable `error_code`. Status is one
of `hit`, `miss`, `unavailable`, or `error`. `hit` means the canonical entity and every
requested child query completed. `miss` means the canonical query completed with no entity.
`unavailable` means opening or validating the DB failed; `error` means a query failed after
successful initialization. `error_code` is null for hits and misses, `ipintel_db_unavailable`
or `ipintel_schema_incompatible` for unavailable results, and `ipintel_lookup_error` for an
error result. A hit is emitted only alongside its `hit` lookup outcome.

`ip_intel_hit.malicious` preserves the producer's `Yes`, `No`, or null exactly. Null is not
`No`; `not_found` and `failed` provider statuses are historical provider metadata, not entity
misses. `reverse_dns`, `related_iocs`, `related_actors`, and `provider_results` are always
lists, using empty lists when the DB has no child rows. Current `source_paths` come only from
this scan. Producer `ip_observations.source_path` remains historical metadata and must never
be substituted as current evidence.

### 4.4 Metric Contract

All keys are integers and are reset per capture/run before the adapter aggregates captures:

| Metric | Counting unit |
| --- | --- |
| `ipintel_files_scanned` | Current regular-file paths read to EOF or intentionally stopped as a singularity. |
| `ipintel_files_skipped` | Current file entries excluded by policy or that fail reading/size stability checks. |
| `ipintel_singularities` | Files that exceeded `ip_singularity_threshold`; no IP evidence is emitted from them. |
| `ipintel_observations` | Unique `(canonical_ip, source_path)` current observations. |
| `ipintel_unique_ips` | Unique canonical IPs per staged capture. |
| `ipintel_lookup_hits` | Unique IPs whose lookup outcome is `hit`. |
| `ipintel_lookup_misses` | Unique IPs whose lookup outcome is `miss`. |
| `ipintel_lookup_unavailable` | Unique IPs whose lookup outcome is `unavailable`. |
| `ipintel_lookup_errors` | Unique IPs whose lookup outcome is `error`. |

The four lookup counters sum to `ipintel_unique_ips`. A partial read creates no observations
from the incomplete file and increments `ipintel_files_skipped`; complete observations from
other files remain valid. The future extractor deduplicates per
`(staged_capture, canonical_ip, source_path)` and the adapter groups lookups per
`(staged_capture, canonical_ip)`. Separate captures never share evidence or a lookup cache.

## 5. IP Extraction Rules

Use the extraction design from `providers/ErecB-IPIntel/design/DESIGN_02.md`.

Required behavior:

- Read files as bytes.
- Do not execute, import, source, or decode captured files wholesale.
- Walk recursively under the staged capture directory, including preserved `IP:PORT` member
  directories. Extract IP observations from file bytes, not from wrapper or member names.
- Do not follow symlinks by default.
- Use bounded chunked reads with carry state sufficient for the configured overlap contract.
- Extract ASCII candidate tokens from chunks.
- Validate candidates with Python `ipaddress.ip_address()`.
- Canonicalize all emitted IP strings.
- Reject candidates embedded in larger alphanumeric or hexadecimal tokens.
- Strip IPv6 zone identifiers only for documented zone-id syntax.
- Deduplicate `(ip, source_path)` observations.
- Sort observations by IP version, canonical IP, then source path.
- If more than `ip_singularity_threshold` (default 20) distinct valid IPs occur in one file,
  stop reading it at the next valid IP boundary, emit one `ip_singularity` record with its path,
  and do not emit or enrich any IP observation from that file. The IP and capture summaries list
  the singularity path. The threshold must not exceed `max_observations_per_file`.

The built-in ignored IPv4 ranges are the same as `erecb-ipintel`:

| Address block | Explanation |
| --- | --- |
| `0.0.0.0/8` | Current network |
| `10.0.0.0/8` | Private network |
| `100.64.0.0/10` | Shared address space |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `172.16.0.0/12` | Private network |
| `192.0.0.0/24` | Reserved |
| `192.0.2.0/24` | TEST-NET-1 |
| `192.88.99.0/24` | IPv6 to IPv4 relay |
| `192.168.0.0/16` | Private network |
| `198.18.0.0/15` | Benchmark testing |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `224.0.0.0/4` | Multicast |
| `233.252.0.0/24` | MCAST-TEST-NET |
| `240.0.0.0/4` | Reserved |
| `255.255.255.255/32` | Broadcast |

### 5.1 Frozen Phase 1 Grammar

Phase 1 fixes the initial extraction scope to ASCII literals found in file bytes. Phase 3 does
not scan filenames, decode UTF-16, resolve hostnames, or expand nested/compressed content.
Candidate bytes may be a bare IPv4/IPv6 literal, IPv4 followed by a decimal port, or bracketed
IPv6 optionally followed by a decimal port. A port must be in `1..65535`; bare IPv6 with a
trailing `:port` is intentionally unsupported because the form is ambiguous. Enclosing `[` and
`]`, URL punctuation, quotes, commas, slashes, and whitespace are boundary punctuation, not
part of an address.

An IPv6 zone is stripped only from an IPv6 literal ending in `%` followed by 1 to 63 ASCII
characters from `[A-Za-z0-9_.-]`. Other `%` forms are rejected. `ipaddress.ip_address()` then
validates and canonicalizes the literal. IPv4 emits dotted decimal; IPv6 emits its compressed
string. IPv4-mapped IPv6 remains a version-6 key such as `::ffff:192.0.2.128`; the IPv4 ignore
list applies only to values whose parsed version is 4.

The accepted candidate, including bracket/port or zone decoration, is at most 110 bytes:
39-byte IPv6, `%` plus 63-byte zone, and seven bytes of bracket/port syntax. The required
128-byte minimum overlap leaves a boundary byte beyond that maximum. `chunk_size_bytes` may be
smaller than overlap; Phase 3 must retain bounded carry state and produce the same result for
all supported chunk sizes. Candidates adjacent to ASCII letters or digits are embedded and
rejected. Overlong candidate runs are discarded through their next delimiter, and a candidate
at a chunk end is held until its right boundary or EOF; an interrupted or size-limited read is
not an EOF boundary.

Reusable vectors must live in `tests/fixtures/ipintel_extraction_vectors.json`. They cover IPv4,
ports, compressed/expanded/bracketed/scoped/mapped IPv6, punctuation, ignored ranges, malformed
tokens, embedded tokens, binary delimiters, and expected canonical keys. Phase 3 must run every
vector across every split point; Phase 1 intentionally stores vectors without implementing a
scanner.

## 6. SQLite Lookup

The processor opens `dbs/ipintel.sqlite3` with SQLite URI `mode=ro` and never falls back to a
writable connection. It must not create or mutate the DB;
`erecb-ipintel` remains the owner of enrichment collection and schema migration.

Use the schema defined in `providers/ErecB-IPIntel/design/DESIGN_02.md` and present in the local
database:

- `ip_entities`
- `ip_observations`
- `ip_reverse_dns`
- `ip_related_iocs`
- `ip_related_actors`
- `provider_runs`
- `provider_ip_results`

Lookup per unique canonical IP:

```sql
SELECT
  id,
  ip,
  ip_version,
  ipv4,
  ipv6,
  country_code,
  whois,
  malicious,
  first_seen_local,
  last_updated_local
FROM ip_entities
WHERE ip = ?;
```

If an entity exists, load child rows:

```sql
SELECT domain FROM ip_reverse_dns WHERE ip_entity_id = ? ORDER BY domain;
SELECT ioc FROM ip_related_iocs WHERE ip_entity_id = ? ORDER BY ioc;
SELECT actor FROM ip_related_actors WHERE ip_entity_id = ? ORDER BY actor;
SELECT
  provider_name,
  provider_status,
  provider_result_code,
  provider_transaction_id,
  fetched_at,
  error_summary
FROM provider_ip_results
WHERE ip_entity_id = ?
ORDER BY fetched_at DESC, id DESC;
```

No DB row is still a useful finding: the report must list the observed IP with `No local DB
record` so analysts can distinguish extraction from enrichment coverage.

A failed or unavailable lookup is not a confirmed miss. Preserve extracted observations and
report incomplete lookups separately, with a warning. Preserve database `malicious` values
as `Yes`, `No`, or null; null, a missing entity, and failed provider metadata do not imply
`No`. The local database uses different verdict values from the FileIntel database.

Database `ip_observations` are historical metadata, not evidence that the current capture
contains an address. The initial report's source paths must come from this scan. Provider
history comes from `provider_ip_results`; its `provider_run_id` references `provider_runs`,
which must be present in schema fixtures even when the report does not select run metadata.

## 7. Markdown Report

Output path for archive `in/<archive_file_name>`:

```text
output/<archive_file_name>-ipintel.md
```

Use `staged_capture.report_stem`, which equals the exact original direct-child archive
basename (`source_name`) including all suffixes. Do not use the timestamped `capture_name` in
the report filename. Example:

```text
in/2023-08-13_09-02-04.zip.en_dec
middle-earth/2023-08-13_09-02-04.zip-260907-123456/
output/2023-08-13_09-02-04.zip.en_dec-ipintel.md
```

Validate that `report_stem` is the unchanged safe single component accepted by DESIGN 02 and
agrees with `source_name` and the source-relative basename. Also validate that
`capture_name` agrees with the basename of `staged_path`; reject an invalid record instead of
silently deriving either identity.

Report identity and repeat processing:

- Distinct archive identities have distinct timestamped staging names. If they arrive through
  the same input filename, they intentionally target the same canonical report path; the latest
  successfully completed analysis replaces it and identifies its staging generation in the
  report body.
- Duplicate events and identical archive re-copies at the same input path reuse the saved
  `capture_name`, `staged_path`, and canonical report path across restarts. Changed bytes get a
  new staging identity before analysis but retain the filename-based report path.
- If analysis runs again for a reused or replacement capture, it may refresh that logical
  input filename's existing report.
  Write to a temporary file under `output/` and atomically replace only the report owned by
  that source-relative path and processor. Reserve/check ownership before writing; unrelated pre-existing reports are
  collisions, not replacement targets. Persist report ownership in the dispatcher's staging
  state before the first write, including for exceptional inputs.
- The dispatcher validates output ownership and serializes report writes in the first version.
  `IPRetriever` does not invent identities or mutate the staging index.
- `Generated at` is the report-generation UTC time and may change on refresh; it never changes
  the capture name or its saved `staging_started_at`.
- Later analysis processors receive the accumulated record set, including `ip_observation`
  and `ip_intel_hit` records. They must treat these as optional context; the existence or
  absence of IP records must not decide whether the staged capture is eligible for later
  processors.

Report structure:

```text
# IP Intelligence Report: 2023-08-13_09-02-04.zip.en_dec

## Summary

- Original input: in/2023-08-13_09-02-04.zip.en_dec
- Staging started at: 2026-09-07T12:34:56Z
- Staged path: middle-earth/2023-08-13_09-02-04.zip-260907-123456
- Files scanned: N
- Files skipped: N
- Unique IPs found: N
- IPs with local intelligence: N
- IPs without local DB records: N
- IPs with incomplete lookups: N
- Generated at: UTC timestamp

## IPs With Local Intelligence

| IP | Malicious | Country | Reverse DNS | Sources |
| --- | --- | --- | --- | --- |

## IPs Without Local Intelligence

| IP | Sources |
| --- | --- |

## Intelligence Lookup Incomplete

| IP | Lookup Status | Error Code | Sources |
| --- | --- | --- | --- |

## Warnings

Capture-level and per-file issues, including unavailable local intelligence.

## Details

### 8.8.8.8

- Version: IPv4
- Malicious: No
- Country: US
- Reverse DNS: dns.google
- Related IOCs: none
- Related actors: none
- Last updated local: 2026-09-04T01:30:00Z
- Source paths:
  - middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/config.txt
- Provider results:
  - ctx_io success fetched_at=2026-09-04T01:30:00Z result_code=...
```

Report requirements:

- Every listed IP must link back to at least one source path.
- Keep paths relative to the repository root when possible.
- Escape Markdown table characters in values such as paths, domains, and actor names.
- Use stable sorting for deterministic tests.
- If the DB is missing or unreadable, still write a report with extracted IPs and a clear
  warning section.

## 8. Implementation Layout

Add modules under the existing package:

```text
src/erecb_triage/
  processors/
    ip_retriever.py
  ipintel/
    __init__.py
    contracts.py
    extractor.py
    repository.py
    report.py
```

Responsibilities:

- `ipintel/contracts.py`: observation, lookup outcome, and intelligence record shapes.
- `processors/ip_retriever.py`: processor adapter, config resolution, record production.
- `ipintel/extractor.py`: chunked IP extraction and ignored-range filtering.
- `ipintel/repository.py`: read-only SQLite access and mapping to internal objects.
- `ipintel/report.py`: Markdown rendering, capture-name validation, and atomic publication
  under the dispatcher's report ownership contract.

The split keeps the processor thin and makes extraction, DB lookup, and report generation
testable without a dispatcher.

## 9. Dispatcher Changes Required

The dispatcher must support both preprocessing and analysis processors.

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

The processor registry must map:

- `archive_unarchiver` -> `ArchiveUnarchiver`
- `input_stager` -> staging processor that either invokes the unarchiver or copies input
- `ip_retriever` -> `IPRetriever`
- `file_retriever` -> `FileRetriever` when DESIGN 04 is implemented

Unknown processor types should fail during configuration validation.

The pseudo-code omits error/metric aggregation and exception handling; implement those using
the section 2 failure policy. Reject selected processors that cannot be constructed before
accepting work. Known but unused processor definitions may remain in configuration while
their implementation is pending. The enqueue/drain boundary and ordered execution are shared
with DESIGN 04 Phase 2, not separate IP-specific dispatcher implementations.

## 10. Testing Plan

Unit tests:

- Extracts IPv4 and IPv6 from text and binary files.
- Finds IPs split across chunk boundaries.
- Rejects invalid and embedded candidates.
- Applies the explicit ignored IPv4 ranges.
- Does not follow symlinks by default.
- Deduplicates repeated `(ip, path)` observations.
- Reads DB rows from `ip_entities` and child tables.
- Handles missing DB rows.
- Handles missing or unreadable DB by still producing a report.
- Escapes Markdown table values.
- Uses the provided archive `report_stem` plus `-ipintel.md` for its report and includes the
  timestamped `capture_name` as provenance inside the report.
- Rejects invalid capture names or names inconsistent with `staged_path`.
- Scans files below the preserved `185.17.40.153:85/` member directory without treating its
  name alone as an IP observation.
- Atomically refreshes the same source-relative archive's report without replacing a report
  owned by another logical input path.

Dispatcher tests:

- Runs preprocessors before analysis processors.
- Passes staged records from the staging processor into `IPRetriever`.
- Passes the accumulated records from `IPRetriever` to later processors without dropping the
  original `staged_capture` record.
- Continues processing when one processor returns non-fatal errors.
- Reuses a duplicate archive's report path after restart without creating another timestamp.
- Produces distinct staging identities for changed archive bytes and same-second collisions,
  while refreshing the same archive-filename-based report after successful analysis.
- Runs no analysis on pending, failed, corrupt, or encrypted archive extraction output.
- Reserves report ownership before first write and rejects unrelated existing report paths.

Integration test (inject UTC staging time `2026-09-07T12:34:56Z`; live runs use actual UTC):

```text
copy testdata/2023-08-13_09-02-04.zip.en_dec in/
run python -m erecb_triage --once --config config/watcher_ipintel.yaml
expect middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/
expect output/2023-08-13_09-02-04.zip.en_dec-ipintel.md
expect report contains each extracted IP surviving section 5 filtering and any local hits
```

## 11. Acceptance Criteria

- A `.en_dec` ZIP copied into `in/` is extracted as normal ZIP data. At the example staging
  time, `2023-08-13_09-02-04.zip.en_dec` creates
  `middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/`.
- A `.enc` ZIP uses the same timestamp naming policy, removing only its final `.enc`.
- Ordinary `.zip` and `.tar.gz` captures retain their full filenames before the staging
  timestamp; all archive-name collisions follow DESIGN 02's counter policy.
- A directory copied into `in/` is treated as an exceptional uncompressed capture and staged
  under `middle-earth/<sanitized-directory-name>/`.
- A regular non-archive file copied into `in/` is treated as an exceptional direct-file
  capture and staged under `middle-earth/<sanitized-file-basename>/`.
- `IPRetriever` scans the staged directory, not the original `in/` input.
- `IPRetriever` reads `dbs/ipintel.sqlite3` without modifying it.
- `output/<archive_file_name>-ipintel.md` uses the original archive basename.
- Duplicate archives retain their staging/report paths across restarts; changed bytes receive
  distinct staging names and atomically refresh the same filename-based report after success.
- Only the same source-relative archive filename's report slot may be atomically refreshed;
  unrelated reports are preserved.
- The report includes source paths for every IP.
- The watcher and dispatcher continue after corrupt archives, unreadable files, or missing DB
  records.
- IPv4/IPv6 extraction is canonical, deterministic, and invariant to supported chunk sizes,
  including tokens and their delimiters split across reads.
- A missing/unreadable database still produces an observation report; failed lookups are
  distinct from successful lookups with no row.
- IPRetriever runs independently of FileRetriever. When both are available and configured,
  the dispatcher runs IP analysis first and preserves the staged capture for file analysis.

## 12. Phased Implementation Plan

Historical delivery note: IPIntel Phases 1-6 were reported complete on 2026-09-09, including
the ordered IPRetriever -> FileRetriever runtime path. A 2026-09-20 workspace audit found the
implementation modules but not the referenced `tests/` or `docs/*VERIFICATION.md` artifacts.
The current classification is therefore **implemented, verification evidence missing**.
Each phase below is retained as a work breakdown; authoritative status and release gates are
in `IMPLEMENTATION_PLAN.md`.

### 12.1 Current Baseline and Dependencies

The following records the historical planning baseline. Shared Phase 2 was reported to have
resolved the dispatcher/stager gaps and legacy failures, but the referenced verification
document is absent from this workspace. Phase 0-2 of the centralized plan must recreate and
run that evidence.

- `config.py` already defines `ip_retriever` settings and accepts its type, but validation is
  partial and the dispatcher cannot construct IPRetriever. Phase 1 subsequently added the
  `ipintel/` contracts/specification package; `processors/ip_retriever.py` remains absent.
- `dispatcher.py` runs only preprocessors and constructs only ArchiveUnarchiver. It has no
  enqueue boundary or separate analysis output root. Its current exception-and-continue
  behavior differs from the required analysis exception policy.
- `staging.py` contains identity, manifest verification, and report reservation helpers, but
  InputStager integration and completed-capture routing remain unfinished.
- FileIntel Phase 1 added typed contracts and temporary SQLite fixtures for its own schema.
  Reuse that testing pattern, while retaining the IP database's own schema and verdict types.
- The last recorded suite result is 11 passing tests and 9 failures; see
  `docs/FILEINTEL_PHASE1_BASELINE.md`. The failing legacy fixtures select `stage_input` after
  removing its processor definition. IPIntel Phase 1 must recheck the baseline at execution
  time, not treat this historical result as a new test run.

Suggested implementation order:

```text
Phase 1: contracts, extraction test vectors, and schema baseline
  -> Phase 2: shared staging and ordered dispatcher
  -> Phase 3: streaming extraction, filtering, and configuration
  -> Phase 4: local intelligence repository
  -> Phase 5: processor records and report publication
  -> Phase 6: runtime integration and acceptance
```

Phases 3 and 4 can proceed independently after Phase 1. Phase 5 requires Phases 2-4; Phase 6
assembles the runtime workflow. Phase 2 is the same shared work as DESIGN 04 Phase 2: implement
it once, reuse its tests, and record the shared completion in both designs. Neither processor
requires the other's extraction or repository implementation. Combined-pipeline verification
waits until both real processors exist, without blocking either standalone pipeline.

### 12.2 Phase 1: Finalize Contracts and Establish the Baseline

Historical status: reported complete on 2026-09-09. Typed contracts, producer-schema fixtures,
frozen grammar vectors, strict settings validation, and baseline documentation were reported
implemented. The referenced Phase 1 baseline document is absent.

Primary source artifact: `ipintel/contracts.py`. The schema fixture, shared fixtures,
extraction vectors, and baseline report named by the historical plan must be recreated under
Phase 0 of `IMPLEMENTATION_PLAN.md`.

Deliverables:

- Run the current suite before edits and record failures, interpreter/test-runner versions,
  and commands. Review legacy configuration fixtures and identify prerequisites without
  hiding baseline failures behind skips or expected-failure markers.
- Inspect `dbs/ipintel.sqlite3` read-only and compare it with the producer DDL. Build isolated
  temporary databases from a committed test-only schema snapshot. Include nullable fields,
  unique IPs, child uniqueness/foreign keys, provider runs, and provider results. Tests must
  not depend on operational database contents or modify that database.
- Finalize typed `ip_observation`, `ip_intel_lookup`, and `ip_intel_hit` shapes. Require
  canonical IP/version, capture identity, current event/run provenance, and current paths.
  Define lookup outcomes `hit`, `miss`, `unavailable`, and `error`, with stable error codes.
  Specify nullability and empty child lists, preserving `Yes`/`No`/null verdict semantics.
- Specify deduplication per `(staged_capture, canonical_ip, source_path)` within a run and
  grouping per `(staged_capture, canonical_ip)`. Repeated bytes or addresses in separate
  captures must not combine evidence. Define `ipintel_` metric names and units for file paths,
  observations, unique IPs, and lookup outcomes, including partial-file scans.
- Freeze extraction grammar with explicit input/expected-output vectors: IPv4, compressed
  and expanded IPv6, bracketed IPv6 with ports, IPv4 with ports, mixed IPv6/IPv4 notation,
  zone IDs, punctuation, malformed addresses, and larger embedded tokens. Decide scoped
  address syntax and maximum accepted token length, including zone IDs, before writing the
  chunk algorithm. Specify whether mapped IPv6 remains IPv6 and how the IPv4 ignore list
  applies; test the resulting canonical lookup key against producer conventions.
- Specify configuration defaults and strict types: positive integer chunk size, overlap at
  least 128 bytes and large enough for the accepted token plus boundary context, nullable
  nonnegative size limit, boolean scan settings, required nonempty paths, and the literal
  `-ipintel.md` report suffix. Reject booleans as integer values and reject alternate suffixes. Resolve paths
  against the dispatcher's base directory. Decide and test support for chunks smaller than
  overlap rather than assuming they cannot occur.
- Confirm the initial extraction scope is ASCII IP literals in file bytes. Filenames,
  UTF-16 decoding, hostname resolution, and compressed-content expansion are not additional
  extraction sources. Use standard-library `ipaddress` for address validation; no external
  service or new parsing framework is required.

Verification: schema fixtures exercise nullable verdicts, address uniqueness, attributed
child rows, provider foreign keys, and read-only behavior. Record grammar examples and
configuration boundary cases as reusable test vectors for Phase 3.

Exit criterion: a documented baseline, verified schema fixtures, explicit record/metric
contracts, and unambiguous parser/configuration test vectors exist. This was historically
reported complete on 2026-09-09; the missing fixtures must be restored before acceptance.

### 12.3 Phase 2: Complete Shared Staging and Dispatcher Support

Historical status: reported complete on 2026-09-08 through DESIGN 04 Phase 2. Reuse the
present InputStager, dispatcher queue/lifecycle, and report ownership APIs; recreate the
absent staging-pipeline tests before accepting the phase.
IPIntel Phase 1 is complete with its own schema, contracts, and extraction test vectors.
No real IPRetriever/FileRetriever is constructed in these shared analysis tests.

Primary files: `staging.py`, `processors/input_stager.py`, `processors/base.py`,
`dispatcher.py`, `watcher.py`, and `__main__.py`.

Deliverables:

- Complete the shared DESIGN 02 / DESIGN 04 Phase 2 work, or verify and reuse it if already
  implemented. Integrate InputStager with the existing unarchiver and StagingState; only
  successful publication or verified reuse emits an eligible staged capture.
- Provide `enqueue(event)` and deterministic draining with `max_workers: 1`, including
  draining accepted work before `--once` returns. A synchronous drain is sufficient for
  this phase. Preserve direct-child watcher semantics.
- Separate staging and analysis output roots in context. Reserve/check report paths for all
  configured analysis processors, including `-ipintel.md`, using the shared ownership state.
  IPRetriever receives the resulting identity and does not maintain another staging index.
- Run preprocessors once and analysis in configured order against accumulated records;
  preserve errors and metrics. Check eligibility and continue later independent adapters
  after returned non-fatal errors or unexpected analysis exceptions.
- Update legacy test configuration fixtures to explicitly select their intended processors
  and assess any newly exposed failures. Keep preprocessor-only configurations usable and
  reject selected processors that cannot be constructed before processing inputs.

Verification: shared dispatcher tests use analysis test doubles to prove queue draining,
ordering, accumulated records, error handling, identity reuse, ownership reservations, and
suppression of analysis for failed or incomplete extraction. Test both watcher and `--once`
entry paths without requiring either intelligence processor to exist.

Exit criterion: a completed capture reaches an analysis test double with stable identity,
separate output roots, and reserved report ownership. The shared work is recorded once and
referenced from both implementation plans.

### 12.4 Phase 3: Streaming Extraction, Filtering, and Configuration

Historical status: reported complete on 2026-09-09. `ipintel/extractor.py` implements deterministic, descriptor-
anchored traversal and bounded byte-stream extraction. `config.ip_retriever_settings()` was
completed in Phase 1 and is now exercised by the extraction service. See
`docs/IPINTEL_PHASE3_VERIFICATION.md`.

Primary files: `ipintel/extractor.py`, `config.py`, and focused extractor/configuration tests.

Deliverables:

- Traverse regular files deterministically, honoring hidden-file/directory and size settings.
  Skip symlinks by default; when following is enabled, restrict resolved targets to the staged
  root and prevent directory cycles. Reuse compatible existing filesystem helpers.
- Implement bounded byte reads, candidate extraction, `ipaddress` validation, canonicalization,
  and the fixed ignored IPv4 ranges in section 5. Do not substitute `is_private` or
  `is_global` heuristics for that explicit list or silently add IPv6 exclusions.
- Preserve both token and delimiter context across reads. Defer a trailing candidate until
  its right boundary or actual EOF is known; do not emit valid-looking prefixes of a longer
  invalid token. Bound carry state, discard overlong candidates through their delimiter, and
  deduplicate discoveries from overlapping chunks.
- Apply the Phase 1 decisions for zones, mapped forms, ports, and canonical keys. Enforce
  size limits during reads as well as initial stat. Document and implement partial results
  for unreadable, disappearing, or changing files and ensure a size-limit stop is not mistaken
  for a true token boundary.
- Complete the existing IP configuration validator using Phase 1 rules, without changing
  unrelated FileIntel settings or enabling a runtime processor that is not registered yet.

Verification: run each grammar vector at every possible split point, including splits in
surrounding delimiters. Cover one-byte/tiny reads, overlap duplication, EOF, long invalid
tokens, binary noise, zone/mapped forms, and ignored-range boundaries. Compare accepted
observations across supported chunk sizes. Cover file limits, hidden entries, symlinks,
special files, and read failures with controlled fixtures.

Exit criterion: extraction produces canonical, deterministic observations from inert temporary
files, independently of the dispatcher and database. Chunk size affects performance only,
not accepted observations for unchanged complete files. This criterion was historically
reported complete on 2026-09-09 and requires renewed test evidence.

### 12.5 Phase 4: Read-Only Intelligence Repository

Historical status: reported complete on 2026-09-09. `ipintel/repository.py` provides a single-use, capture-scoped
read-only session with canonical-IP caching, strict required-column checks, complete lookup
outcomes, and deterministic producer metadata. The referenced Phase 4 verification document
is absent and must be recreated.

Primary file: `ipintel/repository.py`, with repository tests using the Phase 1 schema fixtures.

Deliverables:

- Open only existing databases using SQLite URI `mode=ro`, check required schema columns,
  use parameterized queries, and close connections deterministically. Never create schema,
  migrate data, insert observations, or fetch enrichment.
- Query `ip_entities` by canonical IP and load reverse DNS, related IOCs/actors, and provider
  results in deterministic order. Preserve nullable values and provider statuses, including
  `not_found` and `failed`, without turning them into local entity misses.
- Cache complete lookup outcomes per unique canonical IP within a capture. Keep current
  source-path grouping in the processor; any historical DB paths remain separate metadata.
- Distinguish complete hits, successful misses, database unavailability/incompatibility, and
  query failures. A failed child query must not publish a partial entity as a complete hit.
  Previously completed lookups and local observations remain usable after a later failure.

Verification: fixtures cover IPv4 and canonical IPv6 keys, null verdicts, empty child sets,
multiple provider results/statuses, duplicate lookup inputs, schema mismatch, malformed or
missing DBs, and query failures. Confirm no DB is created on a missing path and fixture
schema/data remain unchanged after read-only retrieval.

Exit criterion: repository outcomes preserve canonical identity and attribution, distinguish
coverage from failures, and allow observation reporting when intelligence is unavailable. This
criterion was historically reported complete on 2026-09-09 and requires renewed test evidence.

### 12.6 Phase 5: Processor Adapter and Evidence Reports

Historical status: reported complete on 2026-09-09. `processors/ip_retriever.py` composes extraction, read-only
lookup, record production, and reserved-report publication. `ipintel/report.py` renders
escaped evidence-linked Markdown and atomically replaces only reports owned by the staged
capture. The adapter is not yet exported or registered by the dispatcher; see
`docs/IPINTEL_PHASE5_VERIFICATION.md`.

Primary files: `processors/ip_retriever.py`, `ipintel/report.py`, and processor/report tests.

Deliverables:

- Compose extraction and repository services behind the existing Processor interface. Consume
  eligible staged captures, ignore unrelated records, and preserve the Phase 1 provenance and
  deduplication contracts for each capture independently.
- Emit observations, per-IP lookup outcomes, hits, errors, and metrics. Keep addresses with
  no row visible and retain local evidence when DB access fails. No observations, no hits,
  or recoverable errors must not suppress a later eligible processor.
- Render section 7 reports for empty captures, all-filtered results, misses, nullable verdicts,
  complete intelligence, and incomplete scans/lookups. Escape untrusted values and encode
  source links. Preserve the archive-derived `report_stem`; include the stager-assigned
  timestamped name and collision counter as report provenance.
- Validate capture identity and report ownership, write a temporary file in the output
  directory, then replace only the report owned by that capture. On publication failure,
  preserve any previous report and clean up temporary files.

Verification: use synthetic staged records, temporary captured files, and real fixture DBs.
Assert repeated addresses retain every distinct current path, separate captures do not merge,
historical observations never substitute for current evidence, and missing DBs still produce
reports. Test invalid identity, unsafe report targets, hostile Markdown, deterministic sorting,
reused reports, partial failures, and atomic publication failure.

Exit criterion: directly invoking IPRetriever on an eligible capture yields correct records
and an evidence-linked report, including when no intelligence database is available. This
criterion was historically reported complete on 2026-09-09 and requires renewed test evidence.

### 12.7 Phase 6: Runtime Integration and Acceptance

Historical status: reported complete on 2026-09-09. IPRetriever is exported and registered by
the dispatcher, and `config/watcher_ipintel.yaml` is present. The historically reported
watcher-to-report and combined acceptance tests and Phase 6 verification document are absent;
recreate and rerun them.

Primary files: `processors/__init__.py`, `dispatcher.py`, `config/watcher_ipintel.yaml`,
CLI usage documentation, and integration tests.

Deliverables:

- Export/register IPRetriever and provide a runnable configuration selecting
  `analysis.processors: ["ip_retriever"]`. Verify all processor paths use the dispatcher's
  single application base directory and never the capture as a base.
- Exercise watcher -> queue -> staging -> IPRetriever -> report with generated inert ZIP
  fixtures containing IP-bearing text/binary files and a temporary intelligence DB. Include
  an `IP:PORT` member directory whose name alone produces no observation. Use a controlled
  clock for naming assertions; do not rely on current live DB hits or wall-clock timestamps.
- Verify `.en_dec`/`.enc` aliases, directory/direct-file staging, duplicate reuse across
  restart, changed bytes, same-second collisions, missing DB, all-filtered/empty scans, and
  failed/encrypted/corrupt extraction. Assert incomplete extraction never reaches analysis.
- When FileRetriever is available, run the real ordered
  `["ip_retriever", "file_retriever"]` pipeline and verify both reports. Empty IP results,
  misses, and returned non-fatal IP errors must still permit file analysis. Test doubles prove
  ordering earlier but do not satisfy this combined integration check.
- Document installation, configuration, filtering scope, reports, and warning behavior. Run
  the full watcher/unarchiver and intelligence test suites, resolve regressions introduced by
  this work, and report any remaining baseline failures separately.

Exit criterion: section 11's standalone IPRetriever criteria have passing verification through
the real application, including the real combined IPRetriever -> FileRetriever pipeline. This
was historically reported complete on 2026-09-09 but requires renewed evidence under Phase 2
of `IMPLEMENTATION_PLAN.md`.
