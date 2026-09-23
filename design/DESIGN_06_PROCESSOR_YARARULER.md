# DESIGN 06: YaraScan Processor

> Revision baseline: 2026-09-20. The cache producer contract is defined by
> [`implementation-plan.md`](../providers/ERecB-YaraRuler/design/implementation-plan.md) as reconciled by
> [`implementation-status.md`](../providers/ERecB-YaraRuler/design/implementation-status.md); the status
> document takes precedence for delivered 0.1.0 behavior. Pipeline delivery status is
> centralized in [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).
> Detailed delivery tasks are in [`IMPLEMENTATION_05_YARARULER.md`](IMPLEMENTATION_05_YARARULER.md).

## 1. Scope

This document defines the `YaraScan` analysis processor for the staged-capture pipeline in
`DESIGN_02_WATCHER_UNARCHIVER.md`.

`YaraScan`:

- Recursively discovers executable and script-like files in a completed staged capture.
- Loads one verified, immutable YARA rule-cache generation built from configured cloned rule
  sets.
- Matches selected files without executing or importing them.
- Emits structured file/rule match records with rule provenance.
- Writes an evidence-linked Markdown report under `output/`.

The implementation adapts the offline scanning architecture described in the checked-in
ERecB-YaraRuler design under `providers/ERecB-YaraRuler/design/`.
Capture processing never clones, fetches, checks out, edits, or compiles rule repositories.
Rule synchronization, validation, quarantine, aggregate compilation, and transactional cache
publication are administrative preparation performed before captures are dispatched.

The processor reports rule matches as evidence for analyst review. A match alone is not a
malware verdict and must not automatically classify the capture as a C2 server, ORB, victim,
or attack-tool host. YARA evaluates file content. Hashes are computed only after a match to
identify the exact captured bytes; hashes themselves are never matched against YARA rules.

## 2. Rule Preparation Boundary

The provided cloned rule sets are prepared using the ERecB-YaraRuler cache contract:

```text
configured cloned/source repositories
  -> individual .yar/.yara validation
  -> unsafe/invalid rule quarantine
  -> unique namespace assignment
  -> aggregate compilation
  -> immutable cache generation:
       rules/cache/generations/<uuid>/rules.yac
       rules/cache/generations/<uuid>/manifest.json
  -> atomic rules/cache/active pointer
```

`YaraScan` reads the active pointer once per capture, validates the selected generation, and
keeps that generation for the entire scan. An administrative update published concurrently
affects only later captures. The processor never silently compiles source rules when the
cache is absent, stale, incompatible, corrupt, or empty.

The manifest supplies rule provenance: source name, source URL, configured ref, resolved
commit, accepted rule path, rule SHA-256, and assigned namespace. Treat the URL as untrusted;
strip user information and redact credentials before placing it in a record, report, error,
or log. Cache generation, artifact digest, YARA version, platform, and architecture must
match the loaded artifact.

If the project later embeds rule preparation, it must preserve the YaraRuler controls for
safe includes, quarantine, locks, non-interactive Git, clean managed checkouts, aggregate
isolation, and atomic cache publication. That work is outside this processor.

## 3. Pipeline Position and Failure Policy

A recommended analysis order is:

```text
ip_retriever -> file_retriever -> ghintel -> yara_scan
```

`YaraScan` consumes the completed `staged_capture` directly and independently discovers its
own candidates. It does not depend on FileRetriever observations because YaraScan has a
separate, frozen executable-selection contract. It may use earlier records only in a future
explicit correlation layer.

A cache setup failure (`missing`, `incompatible`, `corrupt`, or no accepted rules) is a
capture-level non-fatal processor failure: emit `yarascan_cache_unavailable`, write a report
that clearly states no files were scanned, and allow the watcher to process later events.
Per-file discovery, filtering, timeout, read, or mutation failures are isolated and do not
discard other matches. Invalid configuration or a missing `yara-python` dependency for a
configured YaraScan is a startup failure.

## 4. Configuration

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
        - "yara_scan"

processors:
  yara_scan:
    type: "yara_scan"
    cache_dir: "./rules/cache"
    output_root: "./output"
    selector: "exec-only"
    max_depth_from_staged_root: null
    max_file_size_bytes: null
    follow_symlinks: false
    include_hidden_files: true
    include_hidden_directories: true
    threads: 1
    timeout_seconds: 30
    include_strings: false
    max_string_instances_per_rule: 10000
    report_suffix: "-yara.md"
```

`selector` is fixed to `exec-only` in the first pipeline implementation because this
processor's stated role is scanning executables. The standalone YaraRuler application's
`all`, glob, and regex modes remain useful for analyst-driven scans but are not part of this
automatic processor contract.

`max_file_size_bytes: null` means unlimited size subject to the YARA timeout and operating
system limits. A configured zero permits only empty files. This differs deliberately from
the standalone application's `0 means unlimited` CLI convention and matches the nullable
size-limit convention used by this pipeline.

### 4.1 Validation Contract

| Setting | Default | Rule |
| --- | --- | --- |
| `type` | none | Required literal `yara_scan`. |
| `cache_dir` | `./rules/cache` | Required nonempty string without NUL. |
| `output_root` | `./output` | Required nonempty string without NUL. |
| `selector` | `exec-only` | Required literal `exec-only` in version 1. |
| `max_depth_from_staged_root` | `null` | `null` or exact integer >= 0. |
| `max_file_size_bytes` | `null` | `null` or exact integer >= 0. |
| `follow_symlinks` | `false` | Boolean; version 1 rejects `true`. |
| `include_hidden_files` | `true` | Boolean. |
| `include_hidden_directories` | `true` | Boolean. |
| `threads` | `1` | Exact integer >= 1. |
| `timeout_seconds` | `30` | Exact integer >= 1. |
| `include_strings` | `false` | Boolean. |
| `max_string_instances_per_rule` | `10000` | Exact integer in `0..10000`; zero records no instances. |
| `report_suffix` | `-yara.md` | Required literal `-yara.md`. |

Booleans, floats, and numeric strings are invalid for integer fields. Resolve paths against
the configuration base directory. Validation must not load YARA, access the cache, traverse a
capture, or create directories. Runtime construction verifies that `yara-python` is present.
Cache compatibility is checked per capture so a later administrative publication can repair
an unavailable cache without restarting the watcher.

## 5. Input and Output Records

### 5.1 Input

YaraScan accepts the standard completed `staged_capture` record described in DESIGN 03-05.
It verifies capture readiness, manifest identity, event/run provenance, safe timestamped
capture name, archive-derived `report_stem`, and confinement of `staged_path` before scanning.

### 5.2 Match Record

Emit one `yara_match` record per `(file, namespace, rule)`:

```json
{
  "type": "yara_match",
  "file_path": "/abs/path/middle-earth/capture/tool.exe",
  "display_path": "middle-earth/capture/tool.exe",
  "sha256_hash": "<64 lowercase hex characters>",
  "md5_hash": "<32 lowercase hex characters>",
  "rule": "SUSP_Recon_Commands",
  "namespace": "ns_community__recon_yar__abc123",
  "tags": ["apt", "recon"],
  "meta": {
    "author": "Security Research",
    "description": "Detects system discovery routines"
  },
  "strings": null,
  "strings_truncated": false,
  "rule_source": {
    "name": "community-rules",
    "url": "https://github.com/Yara-Rules/rules.git",
    "ref": null,
    "commit": "<40 hex characters>",
    "path": "recon.yar",
    "sha256": "<64 lowercase hex characters>"
  },
  "cache_generation": "<uuid>",
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Hashes describe the current captured bytes and are computed only for files with at least one
match. MD5 is an artifact identifier only and never drives a verdict. All matches for one
file share its hashes and provenance.

Rule metadata values are normalized to JSON scalars. Bytes decode with UTF-8 replacement;
unsupported objects become bounded strings. Sort tags, metadata keys, and matches by
`(namespace, rule)`. A namespace missing from the validated manifest is a cache-integrity
error; do not emit an unprovenanced match.

When `include_strings` is true, `strings` contains only identifier, offset, and length:

```json
[
  {"identifier": "$cmd", "offset": 128, "length": 7}
]
```

Never emit matched bytes. Sort instances by `(offset, identifier)` and cap them per rule.
Include `strings_truncated: true` when more instances existed than were retained. With
`include_strings: false`, use null in processor records and omit the section from reports.
Cap normalized metadata at 256 entries per rule, keys at 256 characters, and rendered scalar
values at 4096 characters. Record a capture warning when serialization truncates metadata;
never allow rule-controlled metadata to grow a processor result without bound.

### 5.3 Scan Error Record

Recoverable file failures emit:

```json
{
  "type": "yara_scan_error",
  "operation": "scan",
  "category": "scan_timeout",
  "message": "bounded sanitized diagnostic",
  "source_path": "middle-earth/capture/tool.exe",
  "capture_name": "capture",
  "staged_capture": "/abs/path/middle-earth/capture",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Categories include `stat_error`, `read_error`, `filter_error`, `scan_timeout`,
`file_changed_during_scan`, `worker_failure`, and `cache_integrity_error`. Diagnostics are
control-free and capped at 1000 characters. They never contain target bytes or matched data.

### 5.4 Metrics

| Metric | Counting unit |
| --- | --- |
| `yarascan_files_discovered` | Eligible regular-file paths encountered before filtering. |
| `yarascan_files_selected` | Paths accepted by the executable selector and size/depth policy. |
| `yarascan_files_scanned` | Selected paths for which YARA returned a result, including no match. |
| `yarascan_files_matched` | Unique paths with at least one retained rule match. |
| `yarascan_rule_matches` | Retained `(path, namespace, rule)` matches. |
| `yarascan_scan_errors` | Recoverable path-level errors. |
| `yarascan_files_skipped_size` | Executable candidates excluded by size. |

`files_scanned` excludes timeouts and errors. A no-match result is successful and increments
it. `files_matched` counts files, while `rule_matches` counts rules.

## 6. Candidate Discovery and Executable Selection

Walk the staged tree deterministically with `os.scandir()`. Include readable regular files
only; skip sockets, devices, FIFOs, and symlinks. Apply hidden/depth policy consistently and
record per-path errors. Version 1 rejects symlink following even if requested.

Read at most 8192 bytes for classification. A regular file is selected when any check
succeeds:

1. It starts with PE `MZ`, ELF `7f 45 4c 46`, a 32/64-bit Mach-O magic in either endian
   order, or a universal/fat Mach-O magic.
2. Its first line begins with `#!` and contains a nonempty lexically parsed interpreter token.
3. Its lowercase suffix is `.ps1`, `.bat`, `.cmd`, `.sh`, `.py`, `.pl`, `.php`, `.rb`, `.js`,
   or `.vbs`.
4. Its lowercase suffix is `.exe`, `.dll`, `.sys`, `.bin`, `.elf`, `.so`, or `.dylib`.
5. When optional libmagic support is installed, its MIME description contains one of the
   configured executable/script fragments used by ERecB-YaraRuler.

These are selection hints, not claims that a file is safe or malicious. Never import a
script, execute a binary, or trust an extension. Libmagic failure degrades to the other checks
and produces at most one warning per capture.

Apply the maximum size after classification so `yarascan_files_skipped_size` means an
executable candidate was skipped. Recheck size when the file is opened for YARA scanning.

## 7. Cache Validation and Scanning

Read `<cache_dir>/active` and require a canonical lowercase UUID. Resolve only
`<cache_dir>/generations/<uuid>/`; the pointer cannot contain a path. Load and validate
`manifest.json` before `rules.yac`:

- manifest schema version and generation match;
- platform, machine, and YARA/yara-python compatibility match;
- the artifact filename is `rules.yac`;
- artifact size and SHA-256 match the manifest;
- accepted entries are nonempty and have unique namespaces;
- every accepted namespace maps to a source and relative rule path; and
- `yara.load()` succeeds.

For one thread, load the rules once in the dispatcher process. For `threads > 1`, use a
bounded `ProcessPoolExecutor`; each worker loads the pinned artifact once in its initializer.
Limit queued futures to twice the worker count. Workers return serializable outcomes and
never write reports or logs. Sort parent-process results for deterministic output.

Per selected file:

1. Open/stat and retain device, inode, size, and nanosecond mtime.
2. Call `Rules.match(filepath=..., timeout=timeout_seconds)`.
3. If no rules match, return a successful no-match outcome without hashing.
4. If rules match, stream the file once to calculate SHA-256 and MD5.
5. Re-stat and compare the complete identity tuple.
6. Discard every match and hash if the file changed.
7. Normalize and provenance-check matches before returning them.

The YARA timeout is the per-file guard. A timeout or dynamic yara-python exception becomes a
recoverable error. Repeated process-pool breakage may abort this processor for the capture,
but must not terminate the watcher.

## 8. Markdown Report

Write:

```text
output/<archive_file_name>-yara.md
```

Use the same archive-derived `report_stem`, source-relative ownership, staging-provenance
validation, and ownership-checked atomic publication contract as the intelligence reports.

Report structure:

```text
# YARA Scan Report: <archive_file_name>

## Summary

- Original input: ...
- Staged path: ...
- Cache generation: ...
- Rule sources: N
- Accepted rules: N
- Files discovered: N
- Executable candidates selected: N
- Files scanned successfully: N
- Files with matches: N
- Rule matches: N
- Scan errors: N
- Generated at: ...

## Matched Files

| File | SHA-256 | Rules | Tags |
| --- | --- | --- | --- |

## Warnings and Scan Errors

| Path | Operation | Category | Message |
| --- | --- | --- | --- |

## Details

### middle-earth/<capture_name>/tool.exe

- SHA-256: ...
- MD5 (identifier only): ...
- Rule: community-rules/recon.yar :: SUSP_Recon_Commands
- Namespace: ...
- Tags: apt, recon
- Metadata: ...
- Rule source commit: ...
- String locations: `$cmd` at offset 128, length 7
```

If the cache is unavailable, the report contains no matched-file table rows, states that no
files were scanned, and explains the cache error. If the scan succeeds with zero matches,
that is a successful result and the report says `No YARA matches`; it does not say the capture
is clean.

Escape Markdown, HTML, controls, and Unicode formatting/line separators in paths, rule names,
tags, metadata, and diagnostics. Link only to authorized staged files. Never render matched
bytes. Sort file details by display path and matches by namespace/rule.

## 9. Implementation Layout and Dependencies

```text
src/erecb_triage/
  processors/
    yara_scan.py
  yarascan/
    __init__.py
    contracts.py
    cache.py
    discovery.py
    filters.py
    hashing.py
    matcher.py
    report.py
```

The processor registry maps `yara_scan` to `YaraScan`. Package `yara-python` in a dedicated
optional extra, for example:

```toml
[project.optional-dependencies]
yara = ["yara-python"]
```

Optional libmagic integration may reuse the project's existing FileRetriever dependency and
adapter. Core header, shebang, and extension behavior must work without libmagic.

Code may be adapted from the independent YaraRuler application, but the pipeline-specific adapter must use
trusted staged records, nullable size semantics, dispatcher report ownership, and processor
records defined here. Do not shell out to the standalone CLI for each capture.

## 10. Security and Operational Controls

- Captured files and cloned rules are both untrusted input. YARA scanning is not a strong
  sandbox boundary; deploy under a low-privilege OS account or external sandbox appropriate
  to the environment.
- Never use `shell=True`, invoke a target file, or load Python modules by captured filename.
- Never compile unvalidated source rules during event processing.
- Constrain cache paths by UUID generation and verified manifest/artifact hashes.
- Do not follow captured symlinks in version 1.
- Bound worker queues, diagnostics, metadata text, tags, rule matches, and string instances.
- Exclude the report temporary/final path if an operator misconfigures output beneath the
  staged tree, though output-root validation should normally keep it separate.
- Preserve the previous owned report when serialization or publication fails.
- Treat rule metadata and source URLs as untrusted display data and redact URL credentials.

## 11. Testing Plan

Unit tests cover:

- every executable header, shebang, suffix, optional MIME behavior, and false cases;
- depth, hidden, size, special-file, symlink, permission, disappearance, and mutation cases;
- strict configuration boundaries including `null`, zero, negative, booleans, floats, and
  strings for numeric fields;
- active-pointer traversal attempts, malformed manifests, platform/YARA mismatch, artifact
  digest mismatch, empty accepted rules, duplicate namespaces, and corrupt `.yac` files;
- no-match success, one/multiple matches, timeout, dynamic YARA error, and worker failure;
- hash-on-match behavior and deterministic single/multiple-worker normalization;
- namespace-to-rule-source provenance, scalar metadata normalization, string omission/caps,
  and no matched-byte leakage; and
- report escaping, ordering, links, ownership checks, and atomic replacement.

Integration tests use a local cloned Git fixture and the YaraRuler preparation service to
build a cache containing one harmless fixed-string rule plus one quarantined invalid rule.
They then stage an inert archive containing header/extension candidates and verify:

- only executable candidates are scanned;
- single and multiple workers produce equivalent normalized records;
- a matching file produces hashes, rule provenance, records, and the owned report;
- a no-match capture succeeds;
- cache failure still produces a clear report and later events continue; and
- corrupt/failed staging never reaches YaraScan.

Tests never clone over the network and never execute fixture artifacts.

## 12. Acceptance Criteria

- YaraScan runs only on completed, authorized staged captures.
- It deterministically finds executable/script candidates using the frozen version-1
  heuristic and does not follow symlinks.
- It pins and verifies one immutable cache generation per capture.
- It never updates repositories or compiles source rules during capture processing.
- It applies a per-file YARA timeout and isolates recoverable file failures.
- Every match identifies current file bytes, namespace/rule, tags, metadata, cache generation,
  and rule source/path/commit provenance.
- It emits no matched byte content; optional string evidence contains offsets and lengths
  only and is capped.
- File and rule counts are distinct and deterministic.
- Zero matches is success but is not reported as proof that the capture is clean.
- Missing/incompatible/corrupt cache state is distinguishable from a successful no-match
  scan and does not terminate the watcher.
- The report uses the original archive filename, includes the unique staging name as
  provenance, and uses ownership-checked atomic publication.

## 13. Phased Implementation Plan

Status as of 2026-09-20: design revised against the YaraRuler 0.1.0 as-built status;
pipeline-adapter implementation has not started. See `IMPLEMENTATION_PLAN.md`.

### Phase 1: Contracts, Configuration, and Cache Fixtures

Add typed records, metric definitions, YaraScan settings, a minimal valid manifest fixture,
and strict validation tests. Add the optional `yara-python` packaging extra. Exit when invalid
runtime configuration fails before work and cache outcomes have executable contracts.

### Phase 2: Cache Consumer and Executable Discovery

Adapt verified active-generation loading, manifest provenance mapping, confined traversal,
and the executable selector. Keep rule preparation outside the processor. Exit when discovery
and all cache-integrity failures are tested independently of the dispatcher.

### Phase 3: Matching Engine

Implement one-worker matching first, including timeouts, hash-on-match, mutation checks,
metadata/string normalization, and rule provenance. Then add bounded process workers with
deterministic aggregation. Exit when one and multiple workers produce equivalent normalized
results for the harmless fixture corpus.

### Phase 4: Processor Adapter and Report

Add staged-capture authorization, records, metrics, error aggregation, Markdown rendering,
and ownership-checked atomic publication. Exit when valid, no-match, partial-error, and
cache-unavailable captures all produce the specified report without losing valid results.

### Phase 5: Runtime Integration and Acceptance

Register `yara_scan`, add a runnable configuration and rule-preparation documentation, and
exercise watcher -> staging -> YaraScan -> report end to end. Run the full regression suite
with and without the optional YARA/libmagic dependencies where supported. Exit when every
section 12 criterion has passing verification.
