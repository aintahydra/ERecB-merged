# Usage Guide

ERecB-IPIntel provides one command-line entry point:

```bash
erecb-ipintel COMMAND [OPTIONS]
```

Run commands from the runtime working directory that contains `in/`, `output/`, `dbs/`, and optionally `ctx_io_api_key.txt` or a config file.

Progress messages are written to standard error. Generated paths, summaries, and JSON results are written to standard output, so shell scripts can redirect them independently.

## Commands

### Initialize the Database

```bash
erecb-ipintel init-db
```

Creates or migrates the SQLite database at the configured `db_path`. The default is `dbs/ipintel.sqlite3`. Other commands also initialize the database automatically.

### Manual Scan

```bash
erecb-ipintel scan DIR
```

Recursively scans regular files under `DIR`, extracts valid non-whitelisted IP addresses, deduplicates `(IP, path)` tuples, and writes an output file under `output/`.

Scan progress is written to standard error in bounded percentage updates. The command reports recursive directories completed rather than printing every filename.

Example:

```bash
erecb-ipintel scan in/sample
```

Output file format:

```text
IP_ADDRESS; PATH
```

Output filename format:

```text
output/ips_DIRNAME_YYMMDD-HHMMSS.txt
```

### Automatic Discovery Pass

```bash
erecb-ipintel discover
```

Looks under the configured `input_root`, recognizes new directory units at the configured recognition depth, scans each unvisited unit, writes output files, and records visit state in SQLite.

Discovery reports bounded percentage progress based on pending recognized directory units.

With the default recognition depth of `1`, `in/a` and `in/b` are recognized as work units. A later-created `in/a/child` is not recognized separately after `in/a` has already been processed.

### Watch Mode

```bash
erecb-ipintel watch
```

Repeatedly runs discovery and sleeps for `discovery.watch_interval_seconds` between passes. Stop it with `Ctrl-C`.

### Enrich an Extraction File

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt
```

Parses the extraction file, validates unique IP addresses, stores source observations, calls enabled providers, and merges normalized intelligence into the database.

Before provider calls, tuples are reduced to unique canonical IP addresses. Multiple source paths for the same IP are all stored as observations, but each enabled provider is called only once for that IP. Enrichment progress is written to standard error in bounded percentage updates and is based on selected unique IPs for each provider.

Limit enrichment to a provider:

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt --provider ctx_io
```

For a provider plan with a daily quota, process the extraction file as a resumable queue:

```bash
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt --max-ips 1000 --consume
```

`--max-ips` limits the number of unique canonical IPs queried by each enabled provider during that invocation. It is a per-run limit and does not track calls made by other programs or the provider's account-wide reset window. Provider retry attempts may also count separately, so leave suitable headroom when the provider enforces a strict raw-request quota.

`--consume` atomically rewrites the input file after the run. An IP is removed only after every selected provider returns `success` or a definitive `not_found` response for it. Unselected IPs, failed IPs, and an IP that receives a final HTTP 429 remain in the file. A final 429 also stops later calls to that provider during the run. Repeat the same command after the provider quota resets.

Because one IP may have several source-path tuples, completing one unique IP removes every tuple for that IP. Unrecognized or malformed lines are preserved. Input mutation is opt-in; without `--consume`, the extraction file is unchanged.

Example final JSON shape:

```json
{
  "completed_ips": 1000,
  "consumed": true,
  "failed": 0,
  "ips": 2500,
  "rate_limited": false,
  "remaining_ips": 1500,
  "remaining_tuples": 1500,
  "selected_ips": 1000,
  "success": 1000,
  "tuples": 2500
}
```

`tuples` and `remaining_tuples` count deduplicated `(IP, source path)` pairs, while `ips` and `remaining_ips` count unique canonical IPs. The two counts can differ when one IP appears in several source files.

### Enrich One IP

```bash
erecb-ipintel enrich-ip 8.8.8.8
```

Useful for provider testing and operational checks.

### Status

```bash
erecb-ipintel status
```

Prints a JSON summary with the DB path, stored IP entity count, visit-state counts, and recent provider failures.

## Extraction Behavior

The scanner reads files as bytes in bounded chunks with overlap. It extracts ASCII candidate tokens, validates them with Python's `ipaddress` module, canonicalizes valid addresses, and rejects candidates embedded in larger alphanumeric tokens.

The extractor discards the following IPv4 ranges before writing output:

| Address block | Explanation |
| --- | --- |
| `0.0.0.0/8` | Current network |
| `10.0.0.0/8` | Private network |
| `100.64.0.0/10` | Shared address space |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `172.16.0.0/12` | Private network |
| `192.0.0.0/24` | Reserved (IANA) |
| `192.0.2.0/24` | TEST-NET-1 |
| `192.88.99.0/24` | IPv6 to IPv4 relay |
| `192.168.0.0/16` | Private network |
| `198.18.0.0/15` | Network benchmark tests |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `224.0.0.0/4` | Multicast |
| `233.252.0.0/24` | MCAST-TEST-NET |
| `240.0.0.0/4` | Reserved |
| `255.255.255.255/32` | Broadcast |

## Database and Backup

The default SQLite database is `dbs/ipintel.sqlite3`. To move accumulated state to another machine, stop any running `watch` process and copy the database file. If SQLite WAL sidecar files are present, copy those too or use SQLite backup tooling.

## Common Workflows

Manual collection and enrichment:

```bash
erecb-ipintel scan /path/to/evidence
erecb-ipintel enrich output/ips_evidence_YYMMDD-HHMMSS.txt
erecb-ipintel status
```

Quota-limited, resumable enrichment:

```bash
erecb-ipintel scan /path/to/evidence
erecb-ipintel enrich output/ips_evidence_YYMMDD-HHMMSS.txt --max-ips 1000 --consume
# Repeat the same enrich command after the provider quota resets.
```

Automatic collection:

```bash
mkdir -p in/batch-001
cp /path/to/files/* in/batch-001/
erecb-ipintel discover
```

Provider smoke test:

```bash
export CTX_IO_API_KEY='YOUR_CTX_IO_API_KEY'
erecb-ipintel enrich-ip 8.8.8.8 --provider ctx_io
```

## Troubleshooting

`ModuleNotFoundError: erecb_ipintel` means the package is not installed in the active Python environment. Activate the intended virtual environment and reinstall the wheel or source tree.

`CredentialError: CTX.IO API key is not configured` means no key was found in config, `CTX_IO_API_KEY`, or `ctx_io_api_key.txt`. `homework run` checks the key before leasing work; `requests import` remains offline and key-free.

A scan that writes zero tuples may still be correct if all detected addresses are invalid, embedded in larger tokens, or part of the extraction whitelist.

`rate_limited: true` or a stored `HTTP 429` failure means the provider stopped accepting requests for the current quota window. With `--consume`, completed IPs have been removed and unfinished IPs remain in the file. Wait for the provider quota to reset, then rerun the same command.

If enrichment is interrupted abruptly, DB rows committed before the interruption remain, but the input queue may not yet have been rewritten. Review the provider run and input file before restarting if duplicate paid lookups must be avoided.
