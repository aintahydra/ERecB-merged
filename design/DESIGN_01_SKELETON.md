# DESIGN 01: Cybersecurity Triage Pipeline Architecture

> Revision baseline: 2026-09-20. This document is the system-level contract. Component
> details live in DESIGN 02-06, and delivery sequencing/status lives in
> [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). The applications under
> [`providers/`](../providers/) are authoritative for their producer-owned database and YARA-cache
> formats; see [`REPOSITORY_LAYOUT.md`](REPOSITORY_LAYOUT.md). When a producer schema changes, its consumer adapter must fail closed as
> `incompatible`; this pipeline must never migrate producer-owned state.

### Terminology and compatibility

The product-facing processor names are **IPIntel**, **FileIntel**, **GHIntel**, and
**YaraRuler**. Existing source uses the compatibility names `IPRetriever`, `FileRetriever`,
and `YaraScan`, with configuration types `ip_retriever`, `file_retriever`, and the planned
`yara_scan`. These are adapter names, not separate products. New documentation and user-facing
output should use the product-facing names; renaming public configuration keys is deferred so
existing profiles remain valid.

| Product capability | Pipeline adapter | Producer-owned input | Network during capture analysis |
| --- | --- | --- | --- |
| IPIntel | `IPRetriever` / `ip_retriever` | `dbs/ipintel.sqlite3` | Never |
| FileIntel | `FileRetriever` / `file_retriever` | `dbs/fileintel.sqlite3` | Never |
| GHIntel | `GHIntel` / `ghintel` | `dbs/ghintel.sqlite3` | Never |
| YaraRuler | `YaraScan` / `yara_scan` | verified active YARA cache generation | Never |

YARA rules match file content, not precomputed hashes. SHA-256 and MD5 are calculated for a
matched file to identify the exact bytes that produced the match.

## 1. Goal

Build a directory watcher that monitors a configured input directory and launches configurable
processing pipelines when capture archives or, exceptionally, capture directories/files are
added.

The required archive workflow is strictly ordered:

```text
stable new archive in in/
  -> fully and safely unarchive into a unique directory under middle-earth/
  -> run each configured processor over that unarchived directory
  -> atomically publish Markdown reports under output/
```

No analysis processor reads the archive directly from `in/` or runs before staging is ready.

The system should support:

- A configuration file that defines the watched directory, expected to be `./in/` by default.
- Detection of newly added capture archive files under `./in/`, primarily `.en_dec` files
  containing normal ZIP data, with `.enc`, `.zip`, and `.tar.gz` also supported.
- Exceptional support for a newly added uncompressed capture directory under `./in/`.
- A processor interface for independent processing steps.
- A dispatcher that runs processors in pipelines.
- A dispatcher-owned staging boundary that turns every accepted input into a work directory
  under `./middle-earth/`.
- Processors that can emit findings and pass augmented records to later processors.
- Initial processor families for:
  - Controlled archive extraction from added captures.
  - IP address extraction from added content.
  - Local IP intelligence retrieval from `dbs/ipintel.sqlite3`.
  - Executable file discovery and local file intelligence retrieval from
    `dbs/fileintel.sqlite3`.
  - GitHub repository-address discovery and local project-card retrieval from
    `dbs/ghintel.sqlite3`.
  - YARA matching with a prebuilt, verified cache generation produced by the independent
    YaraRuler application.

An expected added archive may look like:

```text
in/2023-08-13_09-02-04.zip.en_dec
  -> middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/
```

The example assumes staging starts at `2026-09-07T12:34:56Z`. Strip only the final `.en_dec`
from this filename, preserve `.zip`, and append the UTC staging-start time as `-YYMMDD-HHMMSS`.
Preserve archive member directories, including `IP:PORT` names on Linux, beneath that wrapper.

The archive or directory name may contain an IP address and port separated by `_` or `:`, but this
convention is not guaranteed and must not be trusted as evidence by itself. It can be stored
as weak metadata for triage, but all security findings must come from inspected content or
local intelligence records.

Captured archives may expand to tens of GB and contain thousands of files, including nested
archives, executables, linkable libraries, scripts, logs, configuration files, credentials,
documents, firmware, packet captures, and disk images. Occasionally the same material may be
provided as an uncompressed directory. Treat all captured content as hostile.

## 2. Non-Goals for the First Implementation

- Real-time guarantees for every filesystem edge case.
- Distributed processing.
- A full database schema optimized for analytics.
- Automatic remediation or deletion of observed files.
- Recursive extraction without explicit limits.
- Executing, importing, sourcing, mounting, or otherwise trusting captured files.
- Calling intelligence providers, cloning Git repositories, compiling YARA rules, or updating
  any producer-owned database while processing a capture.
- Treating a database miss, nullable verdict, failed lookup, or zero YARA matches as proof that
  an artifact is benign.

## 3. Configuration

Use a structured configuration file, for example `config/watcher_localintel.yaml`.

Example:

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
        - "ghintel"
        - "yara_scan"

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

This is the target combined profile. A processor may appear in configuration only after its
type is registered and its dependencies pass startup validation. The current implementation
baseline and the order in which this profile becomes runnable are recorded in
`IMPLEMENTATION_PLAN.md`.

Configuration responsibilities:

- All relative paths resolve against one explicit application base directory. The current CLI
  uses its startup working directory as that base, so operators launch from the project root;
  a future `--base-dir` may make it explicit. Normalize paths once before overlap checks and
  never resolve a processor path relative to captured content.
- `watch.path` selects the directory to monitor.
- `watch.stable_check` controls when a copied file or exceptional directory is considered
  complete enough to dispatch.
- `dispatcher.staging_root` selects where captured input is extracted or copied before
  analysis.
- `dispatcher.output_root` selects where analysis reports are written.
- `dispatcher.staging_index_path` stores this tool's persistent archive identity-to-staging
  mapping, separate from the externally produced intelligence DBs under `dbs/`.
- `duplicate_policy: skip_if_output_exists` reuses a completed archive staging entry matched
  by input-relative path and SHA-256 of archive bytes before allocating a timestamped name.
  A changed archive at the same path receives a new staging name. See DESIGN 02, section 5.1.
- `archive_output_naming` applies to archive work units: remove at most one configured final
  suffix, keep `.zip` and `.tar.gz`, then append UTC staging-start time once. Same-second name
  collisions receive `-2`, `-3`, etc. Exceptional directory/file staging remains same-named.
- Report identity is intentionally different from staging identity. For an archive,
  `report_stem` is its exact direct-child filename (`source_name`), including archive and
  transport suffixes. For example, `sample.zip.en_dec` publishes
  `sample.zip.en_dec-ipintel.md`, not a timestamped report name.
- New captures are expected to be direct child archive files of `watch.path`, for example
  `./in/2023-08-13_09-02-04.zip.en_dec`. Direct child directories are accepted as an exception.
- `pipelines.on_added.preprocessors` defines processors that run once before analysis
  processors. The normal first preprocessor is the input stager.
- `pipelines.on_added.analysis.processors` lists analysis processors that consume the same
  immutable `staged_capture`. Configuration order controls deterministic execution and report
  publication, but it does not create a data dependency among the four analysis processors.
- Analysis processors receive the accumulated record set, select `staged_capture` records,
  and ignore unrelated records. A future correlation processor may consume outputs from all
  four adapters; the adapters themselves do not depend on one another.
- `processors` contains processor-specific settings.
- The standard processor suffixes are fixed as `-ipintel.md`, `-fileintel.md`,
  `-ghintel.md`, and `-yara.md` so every report follows
  `<archive_file_name>-<processor>.md`.
- Version 1 permits at most one enabled standard instance of each report-producing processor
  per pipeline; reject configurations that would target the same canonical report path.

For `in/sample.zip.en_dec`, the standard report set is:

| Processor | Markdown report |
| --- | --- |
| IPIntel | `output/sample.zip.en_dec-ipintel.md` |
| FileIntel | `output/sample.zip.en_dec-fileintel.md` |
| GHIntel | `output/sample.zip.en_dec-ghintel.md` |
| YaraRuler | `output/sample.zip.en_dec-yara.md` |

## 4. Core Concepts

### 4.1 Watch Event

The watcher converts raw filesystem events into a stable internal event.

```text
WatchEvent
  id: unique event id
  kind: added | modified | removed
  root_path: configured watched directory
  path: added archive file, file, or directory path
  relative_path: path relative to the watch root
  is_directory: boolean
  capture_root: direct child under ./in that defines the capture unit
  source_name: original input basename, including all suffixes
  observed_at: timestamp
```

The first version only dispatches `added` events. The model keeps `modified` and `removed` available for future expansion.

The watcher should dispatch direct children added under `./in/`. The primary workflow is one
directly added archive file per captured case. A directly added directory is supported as an
exception for uncompressed captures.

### 4.2 Processing Context

Each pipeline execution receives a context object.

```text
ProcessingContext
  event: WatchEvent
  config: resolved application config
  logger: structured logger
  output_root: resolved middle-earth staging path
  analysis_output_root: resolved report output path
  run_id: unique pipeline run id
```

The context gives processors access to shared services without coupling them to the watcher or dispatcher.

### 4.3 Processor Result

Processors should not mutate global state directly except through explicit outputs defined by
their contract, such as staged files or reports. They return a result that can be passed to
the next processor.

```text
ProcessorResult
  records: list of records produced or augmented by the processor
  metrics:
    files_seen: integer
    records_emitted: integer
    errors_seen: integer
  errors: non-fatal processor errors
```

Records are typed dictionaries or dataclasses. They should include enough provenance to trace every finding to a path and pipeline run.

Records should distinguish:

- Original capture paths.
- Extracted artifact paths.
- The archive path that produced an extracted artifact.
- The unique timestamped `capture_name` used for staging from the stable `report_stem` used
  for canonical report filenames.

## 5. Processor Interface

All processors implement the same interface.

```text
Processor
  name: string
  accepts(input_records, context) -> boolean
  process(input_records, context) -> ProcessorResult
```

Expected behavior:

- `name` is stable and used in configuration.
- `accepts` allows a processor to skip incompatible input.
- `process` performs work and returns records for downstream processors.
- A processor may accept an empty input list.
- Preprocessing processors such as input staging and archive extraction may accept an empty
  input list and return `staged_capture` and artifact records.
- Analysis processors such as `IPRetriever` consume staged records from previous processors.
- Non-fatal errors are captured in the result. Fatal setup/configuration failures should fail pipeline startup.

Recommended base interface in implementation:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

@dataclass(frozen=True)
class ProcessorResult:
    records: list[Mapping[str, Any]]
    metrics: Mapping[str, int]
    errors: list[str]

class Processor(ABC):
    name: str

    def accepts(
        self,
        input_records: Sequence[Mapping[str, Any]],
        context: "ProcessingContext",
    ) -> bool:
        return True

    @abstractmethod
    def process(
        self,
        input_records: Sequence[Mapping[str, Any]],
        context: "ProcessingContext",
    ) -> ProcessorResult:
        ...
```

## 6. Dispatcher and Pipeline Execution

The dispatcher receives normalized watch events and runs the configured processor sequence.

High-level event-driven flow:

```text
Filesystem watcher
  -> Event normalizer/debouncer
  -> Dispatcher event queue
  -> Processor runner
  -> Input staging / archive unarchiver processors
  -> IPRetriever
  -> FileRetriever
  -> GHIntel
  -> YaraScan
  -> optional future correlation processor
  -> Reports / processor outputs
```

Dispatcher responsibilities:

- Select preprocessor and analysis processor lists for the event kind.
- Create a `ProcessingContext`.
- Run shared preprocessors once for the event.
- Run processors in configured order.
- Route newly added archives, and exceptional directories/files, into `middle-earth/` before
  analysis.
- Pass records from one processor to the next.
- Keep staged capture records available to analysis processors.
- Preserve all analysis records for later processors; downstream processors must ignore record
  types they do not consume instead of requiring a single-record-type stream.
- Run analysis only for completed, usable staged captures. Reserve and validate report
  ownership in staging state before writing; serialize writes under the staging-root lock.
- Preserve emitted records in the dispatcher result.
- Log processor metrics and errors.
- Isolate analysis adapters so a failure in IPIntel, FileIntel, GHIntel, or YaraRuler does not
  suppress the other independent adapters or later events. A failed preprocessor still blocks
  analysis because no trusted staged capture exists.

Execution policy:

- Processors run sequentially in the first implementation for deterministic resource use and
  report publication. The four analysis adapters are logically independent even though each
  receives accumulated records. A future correlation processor may explicitly depend on
  their outputs.
- The first implementation drains an in-process queue synchronously; bounded capture-level
  concurrency may be added only after staging locks, SQLite snapshots, memory limits, and
  report ownership are tested under contention.

Pseudo-code:

```text
dispatch(event):
  context = create_context(event)
  records = run_preprocessors(context, config.pipelines[event.kind].preprocessors)

  if not has_completed_staged_capture(records):
    return records

  run_analysis(context, config.pipelines[event.kind].analysis.processors, records)

run_preprocessors(context, preprocessors):
  records = []

  for processor in preprocessors:
    if not processor.accepts(records, context):
      continue

    result = processor.process(records, context)
    records.extend(result.records)

  return records

run_analysis(context, processor_names, records):
  for processor in processor_names:
    if not processor.accepts(records, context):
      continue

    try:
      result = processor.process(records, context)
      records.extend(result.records)
      log metrics and errors
    except Exception as error:
      append a processor-scoped error
      continue with the next independent analysis processor
```

Processor ordering:

- Input staging should normally be configured as the first preprocessor.
- Archive extraction processors should normally be invoked by staging or configured as
  `preprocessors`.
- Preprocessors run once for a capture before analysis processors start.
- The same unarchiver implementation may be reused by the input stager or configured under
  different processor names in future workflows.
- Analysis processors should normally scan staged capture directories under `middle-earth/`.
  Original input paths remain provenance, not the primary analysis root.
- If an unarchiver fails on one archive, processing should continue with other archives when
  present and preserve the original input path as provenance.

## 7. Watcher Design

The first implementation should use a polling watcher so tests and local runs do not depend
on OS-specific filesystem notification behavior. Keep the watcher behind a small interface so
a future notification-based implementation can be added without changing the dispatcher.

Responsibilities:

- Load and validate configuration.
- Ensure the watched path exists and is a directory. The default watched path is `./in/`.
- Detect newly added direct children under the watched path.
- Normalize raw events into `WatchEvent`.
- Debounce related events so partially copied archive files or exceptional directory trees are
  not processed repeatedly.
- Dispatch only after a short quiet period.

Important behavior:

- If an archive file is added, the dispatcher should extract it into one staged capture
  directory before analysis.
- If a directory is added, treat it as one exceptional uncompressed capture and stage it under
  `middle-earth/`.
- If a non-archive file is added, stage it for analysis only when configuration allows direct
  files.
- If the added path is a direct child of `./in/`, treat it as one captured case and set it as
  `capture_root`.
- Do not trust the input name as evidence even when it appears to contain an IP address and port.
- The watcher itself should not know how to extract archives, copy captures, extract IPs, or
  read the intelligence database.

Debounce strategy:

- Maintain a map of path to latest create event.
- Reset a timer when the same file changes or another event appears under the same added
  directory.
- Dispatch after `event_debounce_ms` without related create events.
- Prefer dispatching the direct child under `./in/` instead of every child when an exceptional
  directory tree is copied in.

## 8. Processor 0: Input Stager and Archive Unarchiver

Purpose:

- Convert a direct archive addition under `./in/` into a staged work directory under
  `./middle-earth/`.
- If the addition is an archive, extract it safely.
- If the addition is an exceptional directory or regular non-archive file, copy it safely.
- Emit a `staged_capture` record for downstream analysis processors.

The stager, not the watcher or analysis processor, assigns `capture_name`. For archives it is
the final unique staging directory basename, including timestamp and any collision counter.
The persisted assignment survives duplicate events, re-copies of identical bytes at the same
input path, retries, and restarts. Only completed extraction output may be reused; a directory
existing by itself is insufficient. DESIGN 02, sections 5.1 and 6.3, defines this contract.
Exceptional directory/file basenames are sanitized once by the stager using DESIGN 02's
filename rules, so the staging directory and report use the same name.

Staged capture output record:

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_path": "/watched/in/2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staging_started_at": "2026-09-07T12:34:56Z",
  "staged_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

## 9. Processor 0b: Archive Unarchiver

Purpose:

- Search the added capture for configured archive files.
- Extract matching archives into a controlled output location.
- Emit records describing extracted files and extraction errors.
- Run as a dispatcher preprocessor before content-analysis processors so extracted content is
  available for IP scanning.

Input:

- Empty input records, or artifact records from a previous unarchiver run.
- Uses `context.event.capture_root` as the scan root. In the common case this is a direct
  archive file. In the exceptional directory case it is the copied directory.

Output record:

```json
{
  "type": "archive_extracted",
  "archive_path": "/watched/in/case-001.tar.gz",
  "output_dir": "/repo/middle-earth/case-001.tar.gz-260907-123456",
  "archive_format": ".tar.gz",
  "files_extracted": 42,
  "bytes_extracted": 12345,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Selection configuration:

- `max_depth_from_event_root` limits archive discovery by directory depth from the added
  event path. It matters mainly for exceptional directory inputs that may contain nested
  archives.
- `filename_regex` limits extraction to archive file paths whose names match a regular
  expression, for example `.*\.(en_dec|enc|zip|tar\.gz)$`.
- If both depth and regular expression are configured, both conditions must match.
- If depth is `null`, no depth filter is applied.
- If regular expression is `null`, no name filter is applied.

Hostile-content controls:

- Never execute extracted files.
- Extract into a dedicated staging directory under `middle-earth/`.
- Prevent path traversal by rejecting archive entries that would escape the extraction directory.
- Reject or safely handle absolute paths, symlinks, hard links, device nodes, FIFOs, and special files.
- Enforce configured limits for archive size, extracted file count, total extracted bytes, and nesting depth.
- Preserve original files and avoid overwriting unless explicitly configured.
- Log encrypted, corrupt, unsupported, or oversized archives as non-fatal processor errors.

Implementation notes:

- Use standard library support for `zipfile` and `tarfile`.
- Treat `.en_dec` and `.enc` as ZIP content after validating with `zipfile.is_zipfile`.
  These suffixes do not request decryption. An invalid or encrypted ZIP produces an archive
  error and must not fall back to direct-file copying.
- Leave other archive formats, such as `.7z`, `.xz`, `.bz2`, or single-file `.gz`, as future
  extensions unless operational requirements change.
- Treat archive metadata as untrusted.
- Resolve the persisted staging assignment before extraction; never generate a fresh timestamp
  for a duplicate input. New archive identities receive timestamped output paths.
- Emit extraction manifest records so later processors and analysts can trace findings back to source archives.

## 10. Processor 1: IPIntel (`IPRetriever` adapter)

Purpose:

- Search recursively through staged capture directories.
- Extract IPv4 and IPv6 addresses.
- Retrieve matching local intelligence from `dbs/ipintel.sqlite3`.
- Write an evidence-linked Markdown report under `output/`.

Input:

- `staged_capture` records from the input stager.
- Scans `record.staged_path`, not the original input under `in/`.

Output record:

```json
{
  "type": "ip_observation",
  "ip": "8.8.8.8",
  "ip_version": 4,
  "source_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/file.txt",
  "display_path": "middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/file.txt",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Report output:

```text
output/<report_stem>-ipintel.md
```

Use `staged_capture.report_stem`, which is the original archive basename. A newly completed
analysis of the same watched filename atomically refreshes that filename's canonical report.
The report body records `capture_name`, source SHA-256, staged path, and run ID so analysts can
identify the exact timestamped staging generation that produced it.

Implementation notes:

- Recursively walk staged directories.
- Include binary files using bounded byte chunks.
- Respect max file size, symlink, hidden-file, chunk-size, and chunk-overlap config.
- Use robust IP parsing instead of accepting any regex-like number sequence.
- A pragmatic approach is:
  - Use broad candidate regexes for IPv4/IPv6.
  - Validate candidates with a standard IP address parser.
  - Normalize output using the parser's canonical representation.
- Include line number for text files when available.
- Use `dbs/ipintel.sqlite3` read-only; the separate `erecb-ipintel` application owns
  enrichment collection and DB mutation.
- Continue and write a report if the DB is missing, unreadable, or lacks a row for an
  observed IP.

## 11. Processor 2: FileIntel (`FileRetriever` adapter)

Purpose:

- Search recursively through staged capture directories.
- Identify executable or script-like executable files without executing captured content.
- Calculate SHA-256 and MD5 in one streaming pass for each executable.
- Retrieve matching local intelligence from `dbs/fileintel.sqlite3`.
- Write an evidence-linked Markdown report under `output/`.

Input:

- `staged_capture` records from the input stager.
- May receive `ip_observation` and `ip_intel_hit` records from `IPRetriever`; these are
  preserved as upstream context but are not required for hash lookup.
- Scans `record.staged_path`, not the original input under `in/`.

Output record:

```json
{
  "type": "file_observation",
  "sha256_hash": "<64 lowercase hex characters>",
  "md5_hash": "<32 lowercase hex characters>",
  "magic": "PE32 executable ...",
  "classification_reason": "magic: PE32 executable",
  "source_path": "/repo/middle-earth/2023-08-13_09-02-04.zip-260907-123456/tool.exe",
  "display_path": "middle-earth/2023-08-13_09-02-04.zip-260907-123456/tool.exe",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Report output:

```text
output/<report_stem>-fileintel.md
```

Use the same archive-derived `report_stem` as every other analysis adapter.
The separate `erecb-fileintel` application owns provider enrichment and DB mutation;
`FileRetriever` opens `dbs/fileintel.sqlite3` read-only and treats missing rows as coverage
gaps, not processor errors. See `DESIGN_04_PROCESSOR_FILEINTEL.md`.

## 12. Processor 3: GHIntel

Purpose:

- Extract supported GitHub repository-root addresses from staged regular-file bytes.
- Normalize addresses to the producer's case-folded `github.com/owner/repository` identity.
- Read the effective project card from `dbs/ghintel.sqlite3` without invoking Git, GitHub, or
  an LLM provider.
- Write `output/<report_stem>-ghintel.md` with current-capture evidence kept separate from
  producer history.

GHIntel is a content scanner, not a Git repository scanner. It does not trust a captured
`.git` directory, evaluate Git configuration, follow includes, or run credential helpers.
Database hits, misses, unavailable lookups, and query errors remain distinct. See
`DESIGN_05_PROCESSOR_GHINTEL.md`.

## 13. Processor 4: YaraRuler (`YaraScan` adapter)

Purpose:

- Select executable and script-like candidates from the completed staged capture.
- Pin and validate one immutable YARA cache generation prepared by the independent YaraRuler
  application.
- Match file content with per-file timeouts and without executing target content.
- Emit rule/source/cache provenance and hashes of matched bytes, then write
  `output/<report_stem>-yara.md`.

Capture processing never clones rule repositories or compiles source rules. A missing or
invalid cache is distinguishable from a successful scan with no matches. See
`DESIGN_06_PROCESSOR_YARARULER.md`.

## 14. Error Handling

Use three levels of failure:

- Configuration errors:
  - Invalid watched path.
  - Unknown processor name in pipeline.
  - Missing required processor configuration, such as DB path or output root.
  - These should fail startup.

- Processor record errors:
  - Unreadable file.
  - File deleted before processing.
  - Corrupt, encrypted, unsupported, oversized, or path-traversing archive.
  - These should be captured in `ProcessorResult.errors` and logged.

An observed IP that has no local DB row is not an error. It should be represented in the
IPRetriever report as an IP without local intelligence.

An executable hash that has no local DB row is not an error. It should be represented in the
FileRetriever report as an executable without local file intelligence.

A GitHub identity that has no local DB row is not an error. A YARA scan with zero matches is
also not an error and must not be described as a clean verdict. Missing/incompatible databases
or rule caches are degraded-analysis errors: preserve local observations, publish an explicit
incomplete report when possible, and continue with independent processors and later captures.

- Runtime errors:
  - Unexpected exception in a processor.
  - A preprocessing exception stops analysis for that event. An analysis exception is scoped
    to that adapter; log it, continue the remaining independent adapters, and allow later
    events to continue.

## 15. Suggested Project Layout

```text
config/
  watcher_ipintel.yaml
  watcher_localintel.yaml
src/
  erecb_triage/
    __init__.py
    config.py
    events.py
    watcher.py
    dispatcher.py
    processors/
      __init__.py
      archive_unarchiver.py
      base.py
      input_stager.py
      ip_retriever.py
      file_retriever.py
      ghintel.py
      yara_scan.py
    ipintel/
      __init__.py
      extractor.py
      repository.py
      report.py
    fileintel/
      __init__.py
      classifier.py
      hashing.py
      repository.py
      report.py
    ghintel/
      __init__.py
      extractor.py
      normalization.py
      repository.py
      report.py
    yarascan/
      __init__.py
      cache.py
      discovery.py
      matcher.py
      report.py
tests/
  test_archive_unarchiver.py
  test_ip_retriever.py
  test_file_retriever.py
  test_dispatcher.py
```

## 16. Delivery Plan

The authoritative phased delivery plan is
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). Component-local phase sections in DESIGN
03-06 define useful exit criteria but do not independently assert implementation status.

The former outline is retained below only as a capability decomposition:

### Phase 1: Core Contracts

- Add config loader and validator.
- Add `WatchEvent`, `ProcessingContext`, `Processor`, and `ProcessorResult`.
- Add processor registry.

### Phase 2: Dispatcher

- Implement processor loading from config.
- Implement shared preprocessor execution before analysis processors.
- Implement sequential processor execution.
- Add unit tests for processor ordering, skip behavior, and failure isolation.

### Phase 3: Watcher

- Add polling filesystem watcher.
- Normalize create events.
- Add debounce behavior for large copied archive files and exceptional directory captures.
- Dispatch direct child archive files under `./in/`; also dispatch direct child directories as
  exceptional uncompressed capture units.

### Phase 4: Archive Preprocessing

- Implement input staging for archive files first, with exceptional directory and regular-file
  staging.
- Implement archive unarchiver processor.
- Add depth-based archive discovery.
- Add filename regular-expression filtering.
- Add hostile archive safety checks.
- Add fixtures and unit tests for traversal attempts, oversized archives, nested archives, and repeated unarchiver runs.
- Cover `.en_dec` ZIP extraction, retained `.zip` in timestamped names, preserved `IP:PORT`
  members, same-second collisions, and persistent duplicate/retry handling.

### Phase 5: Local Analysis Processors

- Implement IPRetriever extraction, local SQLite lookup, and Markdown report writing.
- Add fixtures and unit tests.
- Verify report names use the original archive filename and hyphenated processor suffix; the
  report body identifies the unique timestamped staging capture.
- Implement FileRetriever executable classification, streaming hash calculation, local SQLite
  lookup, and Markdown report writing.
- Verify FileRetriever runs after IPRetriever when both are configured and still produces a
  report when the IP processor emits no records or no DB hits.

### Phase 6: GitHub Intelligence

- Implement bounded repository-address extraction and producer-compatible normalization.
- Implement the read-only GHIntel schema adapter and effective project-card report.
- Prove that capture processing performs no Git, network, credential-helper, or LLM action.

### Phase 7: YARA Analysis

- Implement the verified YaraRuler-cache consumer and executable selector.
- Add timed matching, match-only hashing, provenance normalization, and bounded reporting.
- Prove cache failure is distinct from a successful scan with zero matches.

## 17. Remaining Design Decisions

- Retention periods and deletion authority for input archives, staged captures, staging-index
  rows, reports, and old YARA generations.
- Whether the accumulated in-memory record list should become a versioned on-disk/streaming
  result store for very large captures.
- When capture-level parallelism is safe; version 1 uses an in-process queue and deterministic
  sequential draining.
- Whether deep formats such as disk images, firmware images, and packet captures should be handled by separate processors instead of the archive unarchiver.
- Whether a shared artifact inventory can reduce repeated walks without coupling the distinct
  eligibility and evidence rules of FileIntel, GHIntel, and YaraRuler.

Resolved decisions: Python is the implementation language; version 1 passes accumulated record
lists; continuous mode watches only new additions while explicit `--once` scans existing direct
children; and `python-magic` is optional with documented deterministic fallbacks.
