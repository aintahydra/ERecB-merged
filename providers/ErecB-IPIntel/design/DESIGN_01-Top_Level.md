# ERecB-IPIntel Top-Level Design

## 1. Purpose

ERecB-IPIntel is a local tool for:

1. Collecting IP addresses from files under configured input directories.
2. Writing deduplicated IP/path tuples to text output files.
3. Enriching collected IP addresses with intelligence from external providers.
4. Accumulating normalized intelligence records in a portable local database.

The first implementation targets CTX.IO as the intelligence provider. The design keeps provider integration replaceable so later providers such as VirusTotal or Censys can be added without redesigning the extraction or storage layers.

## 2. Repository Layout

Expected top-level directories and files:

```text
ERecB-IPIntel/
  design/                  Design documents.
  src/                     Future program source code.
  in/                      Default watched input root.
  output/                  Extracted IP tuple files.
  dbs/                     Portable database files.
  ctx_io_api_key.txt       Local compatibility credential file; not committed.
  config.*                 Future runtime configuration file.
```

Generated and secret files must be excluded from version control:

- `ctx_io_api_key.txt`
- any local runtime state files that record visited directories

## 3. Top-Level Architecture

The tool is organized into five major subsystems:

```text
CLI / Scheduler
      |
      v
Configuration Loader
      |
      +--> Directory Discovery / Visit State
      |         |
      |         v
      |   IP Extraction Engine
      |         |
      |         v
      |   Extraction Output Writer
      |
      +--> Intelligence Collection Engine
                |
                v
          Provider Adapters
                |
                v
          Intelligence Repository
                |
                v
             SQLite DB
```

### 3.1 CLI / Scheduler

The first implementation should expose command-line commands. A long-running scheduler can be implemented either as a CLI mode or as a thin wrapper over the same services.

Proposed commands:

- `watch`: inspect the configured input root, detect new directories at the configured recognition depth, extract IPs, and write output files.
- `scan DIR`: manually scan a specific directory recursively, independent of new-directory recognition state.
- `enrich FILE [--provider NAME] [--max-ips N] [--consume]`: read an extracted IP tuple file, reduce it to unique canonical IPs, and collect intelligence. Optional queue mode limits work and removes completed IP tuples atomically.
- `enrich-ip IP`: collect intelligence for a single IP, useful for testing and operations.
- `init-db`: explicitly create or migrate the local database. Normal commands may also create it automatically when missing.
- `status`: print a JSON summary of database and recent provider state.

Long-running scan and enrichment commands report bounded percentage progress to standard error. Normal command results, output paths, and JSON summaries remain on standard output so scripts can consume them independently from progress messages. Progress is grouped into approximately ten-percent buckets rather than one line per file or API call.

### 3.2 Configuration Loader

Configuration should be loaded once at process startup and passed into subsystems explicitly.

Initial configuration fields:

```yaml
input_root: in
output_root: output
db_path: dbs/ipintel.sqlite3
visit_recognition_depth: 1
chunk_size_bytes: 1048576
chunk_overlap_bytes: 256
providers:
  ctx_io:
    enabled: true
    api_key: null
    base_url: https://api.ctx.io/v1
    timeout_seconds: 30
    retry_count: 3
```

Credential resolution for CTX.IO:

1. Explicit client configuration.
2. `CTX_IO_API_KEY` environment variable.
3. Repository-local `ctx_io_api_key.txt`.

The resolved key is stripped of surrounding whitespace. It must never be logged, persisted to DB, included in exceptions, or stored in test fixtures.

## 4. Mode 1: IP Collection

### 4.1 Directory Discovery

In automatic mode, the tool watches or periodically inspects `input_root`. It recognizes new directories at `visit_recognition_depth`.

Definition:

- Depth `1` means immediate subdirectories of `input_root`, such as `in/a`.
- Depth `2` means directories such as `in/a/b`.
- A directory below the configured recognition depth is scanned only when its nearest recognized ancestor is processed.

Example with `visit_recognition_depth: 1`:

1. `in/a` appears.
2. The tool recognizes `in/a` as new and recursively scans everything under `in/a`.
3. Later, `in/a/b` is created.
4. The tool does not recognize `in/a/b` as a new automatic unit because `in/a` was already visited.
5. The user can still run `scan in/a/b` manually.

### 4.2 Visit State

The tool needs durable state for automatic discovery. The state records recognized directory units, not every scanned subdirectory.

Recommended state location:

```text
dbs/ipintel.sqlite3
```

The same SQLite database can store both intelligence records and visit state. This keeps backup and migration simple: copying `dbs/ipintel.sqlite3` preserves accumulated intelligence and automatic discovery state.

Minimum visit-state fields:

- recognized path, normalized relative to `input_root` when possible
- absolute path snapshot
- recognition depth
- first detected timestamp
- processed timestamp
- status: `pending`, `processing`, `done`, `failed`
- last error summary

### 4.3 File Scanning Rules

The extractor recursively scans regular files under the selected scan root.

Rules:

- Include binary files.
- Do not execute files.
- Do not decode complete files as text.
- Read bounded byte chunks with overlap.
- Extract ASCII candidate tokens from chunks.
- Validate every candidate with Python's `ipaddress` module.
- Canonicalize output through `ipaddress`.
- Reject candidates embedded in larger alphanumeric or hexadecimal tokens.
- Strip common surrounding URL/bracket punctuation according to documented extractor rules.
- Strip IPv6 zone identifiers only when they follow documented syntax, for example `fe80::1%eth0` becomes `fe80::1` before validation.
- Do not scan inside archives in the initial version.

Compressed or encrypted bytes may produce incidental candidate strings. Only syntactically valid, non-whitelisted IP addresses are emitted.

### 4.3.1 Extraction Whitelist

After a candidate is validated and canonicalized, extraction discards IPv4 addresses in the built-in whitelist below. Whitelisted addresses are not written to extraction output files and therefore are not sent to enrichment through the normal scan workflow.

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

### 4.4 Extracted IP Output

The output writer receives `(ip_address, source_path)` tuples and removes duplicate tuples.

Format:

```text
IP_ADDRESS; PATH
```

Output file naming:

```text
output/ips_DIRNAME_YYMMDD-HHMMSS.txt
```

Where `DIRNAME` is the basename of the scanned recognition unit. For manual scans, use the basename of the requested scan directory. If a name is unsafe for a filename, replace unsafe characters with `_`.

The output file should use UTF-8 text and stable sorted order:

1. IP version.
2. Canonical IP address.
3. Source path.

Sorting is not required for correctness, but it makes output diffs and manual review easier.

## 5. Mode 2: Intelligence Collection

### 5.1 Input

The enrichment mode reads one extraction output file per command invocation. It parses the first field before `;` as the IP address and validates it again with `ipaddress`.

Intelligence collection operates on unique canonical IP addresses. Multiple source paths for the same IP are retained in the database as observations.

Within one provider run, each provider is called at most once for each selected canonical IP. Tuple count and API-call count are therefore intentionally different: three source-path tuples for one IP produce three observations but one provider lookup.

### 5.2 Provider Model

Each intelligence provider implements a common adapter interface:

```text
ProviderAdapter
  name
  supports(ip) -> bool
  fetch(ip) -> ProviderRawResult
  normalize(ip, raw_result) -> NormalizedIntelRecord
```

Provider adapters are responsible for:

- Credential loading.
- API request construction.
- HTTP timeouts.
- Retry and backoff policy.
- Provider-specific response validation.
- Mapping provider fields into the normalized model.
- Returning raw provider response metadata for audit/debug storage.

The collection engine is responsible for:

- Deduplicating input IPs.
- Applying an optional per-run unique-IP limit before provider calls.
- Calling enabled providers.
- Handling provider failures without losing other providers' results.
- Merging normalized records into the database.
- Recording collection attempts and errors.
- Tracking which IPs completed across every selected provider.
- Stopping further calls to a provider after a final HTTP 429 response.
- Optionally consuming completed IP tuples from the input file with an atomic rewrite.

### 5.3 Resumable Quota Processing

The enrichment file can be used as a resumable queue through explicit CLI options:

```text
erecb-ipintel enrich FILE --max-ips N --consume
```

`--max-ips N` selects at most `N` unique canonical IPs for each enabled provider during that invocation. It is a per-run limit, not an automatic model of a provider's account-wide daily usage. Calls made by other tools are not visible to ERecB-IPIntel, and provider retry attempts may count separately under provider billing rules.

`--consume` is opt-in because it modifies the input file. After provider processing:

- An IP is complete only when every selected provider returns `success` or definitive `not_found`.
- Every tuple for a completed IP is removed, because one lookup covers all of that IP's source paths.
- Unselected IPs, failed IPs, and an IP receiving a final HTTP 429 remain.
- Unrecognized, malformed, blank, and comment lines are preserved.
- The rewritten content is flushed to a temporary file in the same directory and atomically replaces the original.

Without `--consume`, the input file is never modified. The final JSON summary reports original tuple/IP counts, selected and completed IP counts, remaining tuple/IP counts, success/failure counts, and whether rate limiting occurred.

### 5.4 CTX.IO Provider

Endpoint:

```text
GET https://api.ctx.io/v1/ip/report/{ip}
Header: x-api-key: <resolved key>
```

CTX.IO field mapping:

| Normalized field | CTX.IO source |
| --- | --- |
| `ipv4` | `ctx_data.ipv4` |
| `ipv6` | `ctx_data.ipv6`, or null when missing |
| `country_code` | `ctx_data.country_code` |
| `whois` | `ctx_data.whois` |
| `reverse_dns` | `ctx_data.reverse_dns` |
| `malicious` | `Yes` when `ctx_data.detect != "normal"`, otherwise `No` |
| `related_iocs` | Flattened leaf values under `ctx_data.apt_ioc_indicator` |
| `related_actors` | Flattened actor names from `ctx_data.apt_threat_actors` |

Actor flattening:

```text
(COUNTRY_CODE_UPPERCASE)Name/Alias1/Alias2
```

Example:

```text
(CN)Barium/Wicked Spider
```

Provider response handling:

- Treat missing `ctx_data` as a provider result with no usable intelligence, not as a parser crash.
- Preserve provider result code and transaction ID when available.
- Do not persist the API key.
- Store enough provider metadata to identify when each provider was queried and whether it succeeded.

## 6. Database Design

Use SQLite for the first implementation.

Reasons:

- Single portable database file.
- Easy backup by copying `dbs/ipintel.sqlite3`.
- No server process required.
- Good support from Python standard and third-party tooling.
- Supports transactional updates and schema migrations.

### 6.1 Normalized Data Model

The user-facing intelligence record has these fields:

- `ipv4`: string, nullable
- `ipv6`: string, nullable
- `country_code`: string, nullable
- `whois`: string, nullable
- `reverse_dns`: array of strings
- `malicious`: string, `Yes` or `No`
- `related_iocs`: array of strings
- `related_actors`: array of strings

SQLite does not have a native array type. Store array values in child tables instead of JSON-only columns so records can be queried and deduplicated reliably.

### 6.2 Proposed Tables

Core IP table:

```text
ip_entities
  id INTEGER PRIMARY KEY
  ip TEXT NOT NULL UNIQUE
  ip_version INTEGER NOT NULL
  ipv4 TEXT NULL
  ipv6 TEXT NULL
  country_code TEXT NULL
  whois TEXT NULL
  malicious TEXT NULL CHECK malicious IN ('Yes', 'No')
  first_seen_local TEXT NOT NULL
  last_updated_local TEXT NOT NULL
```

Observation table:

```text
ip_observations
  id INTEGER PRIMARY KEY
  ip_entity_id INTEGER NOT NULL
  source_path TEXT NOT NULL
  extraction_file TEXT NULL
  observed_at TEXT NOT NULL
  UNIQUE(ip_entity_id, source_path)
```

Array-value tables:

```text
ip_reverse_dns
  ip_entity_id INTEGER NOT NULL
  domain TEXT NOT NULL
  UNIQUE(ip_entity_id, domain)

ip_related_iocs
  ip_entity_id INTEGER NOT NULL
  ioc TEXT NOT NULL
  UNIQUE(ip_entity_id, ioc)

ip_related_actors
  ip_entity_id INTEGER NOT NULL
  actor TEXT NOT NULL
  UNIQUE(ip_entity_id, actor)
```

Provider audit tables:

```text
provider_runs
  id INTEGER PRIMARY KEY
  provider_name TEXT NOT NULL
  started_at TEXT NOT NULL
  finished_at TEXT NULL
  status TEXT NOT NULL

provider_ip_results
  id INTEGER PRIMARY KEY
  provider_run_id INTEGER NOT NULL
  ip_entity_id INTEGER NOT NULL
  provider_name TEXT NOT NULL
  provider_status TEXT NOT NULL
  provider_result_code TEXT NULL
  provider_transaction_id TEXT NULL
  fetched_at TEXT NOT NULL
  error_summary TEXT NULL
  raw_response_json TEXT NULL
```

Automatic discovery state:

```text
visited_directories
  id INTEGER PRIMARY KEY
  input_root TEXT NOT NULL
  relative_path TEXT NOT NULL
  absolute_path TEXT NOT NULL
  recognition_depth INTEGER NOT NULL
  first_detected_at TEXT NOT NULL
  processed_at TEXT NULL
  status TEXT NOT NULL
  last_error TEXT NULL
  UNIQUE(input_root, relative_path, recognition_depth)
```

### 6.3 Merge Semantics

The database accumulates intelligence.

For scalar fields:

- If the existing value is null and the new value is non-null, store the new value.
- If the new value is non-null and differs from the existing value, update the field and preserve the new provider result in `provider_ip_results`.
- `last_updated_local` is updated whenever a normalized record changes.

For array fields:

- Insert new values with uniqueness constraints.
- Do not remove old values unless a future pruning policy is designed.

For `malicious`:

- If any provider reports malicious, store `Yes`.
- Store `No` only when there is no existing `Yes` and the provider reports normal.

## 7. Error Handling and Reliability

Extraction errors:

- Skip unreadable files.
- Record per-file errors in logs.
- Continue scanning other files.
- Mark an automatic directory scan as `failed` only when the scan cannot meaningfully proceed for the directory.

Provider errors:

- Use bounded timeouts.
- Retry transient HTTP/network failures with backoff.
- Do not retry permanent authentication failures in a tight loop.
- Store failed attempts in provider audit tables.
- Continue other IPs and providers when one request fails.
- Treat a final HTTP 429 as a provider stop signal for the current run instead of continuing through the remaining selected IPs.
- Leave rate-limited and otherwise incomplete tuples in a consumed queue file.

Database errors:

- Use transactions around each logical batch.
- Create schema automatically when the DB file does not exist.
- Use migrations for future schema changes.

## 8. Security and Privacy

- Never log API keys.
- Never include API keys in exceptions, fixtures, or raw response storage.
- Treat scanned files as untrusted input.
- Do not execute scanned files.
- Do not follow symlinks by default unless explicitly enabled in configuration.
- Use bounded memory for scanning large files.
- Keep generated DB and output artifacts out of version control.

## 9. Initial Implementation Boundaries

In scope for the first implementation:

- CLI commands for automatic discovery, manual scan, and CTX.IO enrichment.
- Recursive regular-file scanner with chunked IP extraction.
- Deduplicated `IP; PATH` output files.
- SQLite database under `dbs/`.
- CTX.IO provider adapter.
- Provider abstraction sufficient for adding more providers later.
- Basic schema migration mechanism.
- Bounded scan and enrichment progress on standard error.
- Per-run unique-IP limits and opt-in atomic queue consumption for resumable enrichment.

Out of scope for the first implementation:

- Scanning inside archive formats.
- GUI.
- Real-time filesystem event watcher, unless added as a thin enhancement over periodic discovery.
- Distributed workers.
- Advanced confidence scoring across providers.
- Deleting stale intelligence.

## 10. Open Design Decisions for Later Documents

These items should be decided in lower-level design documents before implementation:

- Exact configuration file format and filename.
- Detailed IP candidate tokenizer rules and test vectors.
- Whether raw provider JSON should be stored forever, compressed, or disabled by configuration.
- Automated provider quota accounting across processes, accounts, and provider reset windows.
- Whether automatic discovery should run once, poll continuously, or support both.
- Log format and log destination.
- Schema migration tooling.
