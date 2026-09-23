# DESIGN 02: Watcher, Dispatcher, and Unarchiver

> Revision baseline: 2026-09-20. This document defines the trust boundary that every
> analysis adapter relies on. Delivery status and verification evidence are tracked only in
> [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md); historical phase notes in processor
> documents are not substitutes for executable tests.
> Detailed delivery tasks are in
> [`IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md`](IMPLEMENTATION_02_TRUSTED_INGESTION_DISPATCHER.md).

## 1. Scope

This document refines the first implementation slice from `DESIGN_01_SKELETON.md` and
defines the staging behavior used by later analysis processors.

The implementation provides:

- A directory watcher that monitors `in/` for newly dropped archive files, with exceptional
  support for dropped directories or non-archive files.
- A dispatcher that receives normalized filesystem events and launches configured processors.
- A watcher-to-dispatcher enqueue boundary, even when the first implementation drains the
  queue synchronously.
- An unarchiver processor that extracts configured archive files into `middle-earth/`.
- A dispatcher-owned staging step that ensures every accepted input has a corresponding work
  directory under `middle-earth/`.

`DESIGN_03_PROCESSOR_IPINTEL.md` through `DESIGN_06_PROCESSOR_YARARULER.md` build on this by
running independent analysis processors against staged directories in `middle-earth/`.

## 2. First Implementation Behavior

Default local workflow (examples use staging-start time `2026-09-07T12:34:56Z`):

```text
copy testdata/2023-08-13_09-02-04.zip.en_dec in/
  -> middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/<extracted contents>

copy testdata/212.212.212.212_8080.enc in/
  -> middle-earth/212.212.212.212_8080-260907-123456/<extracted contents>

copy testdata/213.213.213.213_99.zip in/
  -> middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt

copy testdata/214.214.214.214.tar.gz in/
  -> middle-earth/214.214.214.214.tar.gz-260907-123456/<extracted contents>
```

Exceptional staging workflow:

```text
copy testdata/case-directory in/
  -> middle-earth/case-directory/<copied contents>

copy testdata/single-log.txt in/
  -> middle-earth/single-log.txt/single-log.txt
```

Rules:

- `in/` is the watched input directory.
- `middle-earth/` is the extraction output root.
- Directly dropped archive files in `in/` are the normal capture input.
- `.en_dec`, `.enc`, `.zip`, and `.tar.gz` are the enabled production archive formats. Other
  tar and compression-stream aliases remain disabled until each has containment, size-limit,
  atomic-publication, and hostile-fixture coverage.
- `.en_dec` is the primary capture suffix; `.en_dec` and `.enc` are validated and extracted
  as normal ZIP content, without decryption.
- Directly dropped directories in `in/` are exceptional uncompressed captures. They should be
  copied into `middle-earth/` and may also be scanned for nested matching archives.
- Directly dropped non-archive files are exceptional inputs for development or analyst-driven
  cases and should be copied into a same-named staging directory when enabled.
- Each direct archive gets a timestamped wrapper directory under `middle-earth/`. Remove
  only the final `.en_dec` or `.enc` when present; retain `.zip` and `.tar.gz`. Append
  `-YYMMDD-HHMMSS` from the UTC staging-start time assigned once to this archive identity.
- Preserve archive member paths under the wrapper, including a top-level `IP:PORT` directory
  such as `185.17.40.153:85` on Linux. Do not flatten it or use it to name the wrapper.
- Resolve duplicates before assigning names; distinct identities that collide receive a
  counter after the timestamp (`-2`, `-3`, ...). Sections 5.1 and 6.3 define the exact rules.
- If an archive is found inside a dropped directory, preserve the relative source path under
  `middle-earth/` to avoid collisions.
- The unarchiver must never execute, import, source, mount, or otherwise trust extracted
  content.

## 3. Configuration

Add a focused configuration file at `config/watcher_unarchiver.yaml`.

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
      processors: []

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
```

Notes:

- Resolve every relative path against one application base directory and carry it into the
  dispatcher. The current CLI defines that base as its startup working directory; production
  runs therefore start at the project root. Do not resolve paths independently inside
  processors or relative to captured content.
- `watch.recursive: false` means only direct additions to `in/` generate top-level events.
  If the exceptional event is a directory, processors may recursively inspect inside it.
- `max_depth_from_event_root` limits how deep the unarchiver searches under the added
  directory. It does not limit extraction path depth inside a valid archive.
- `filename_regex` is a regular expression, not a shell glob.
- `duplicate_policy: skip_if_output_exists` uses the persistent staging index for archives.
  Match the original input-relative path and SHA-256 of the archive bytes before generating
  a new name. Reuse only a completed, usable extraction, including its original timestamp.
- `dispatcher.staging_index_path` is owned by this tool and is separate from `dbs/`, whose
  intelligence databases are produced by other tools.
- `archive_output_naming` replaces `strip_archive_suffix_for_output`; there is no recursive
  suffix stripping. A `.zip.en_dec` filename becomes `.zip-YYMMDD-HHMMSS`, not
  `-YYMMDD-HHMMSS` and not `.zip.en_dec-YYMMDD-HHMMSS`.
- `.en_dec` and `.enc` select ZIP validation and extraction. Neither requests decryption.
- `input_stager` is a dispatcher preprocessor that routes direct archive files to the
  unarchiver and copies exceptional direct non-archive files/directories into `middle-earth/`.
- `pipelines.on_added.analysis` is empty in this document but is the extension point used by
  DESIGN 03-06. The canonical combined order is `ip_retriever`, `file_retriever`, `ghintel`,
  then `yara_scan`; each consumes the same trusted staged capture and ignores unrelated
  accumulated records.

The checked-in `config/watcher_unarchiver.yaml` is currently an unarchiver-only compatibility
profile and uses `archive_unarchiver` directly. Before the unified pipeline is released it
must be reconciled with this document's `input_stager` profile, because only the stager owns
persistent capture identity, ready-state validation, and report reservations.

## 4. Runtime Components

### 4.1 Watcher

Responsibilities:

- Load configuration.
- Ensure `in/` exists.
- Watch only immediate children added to `in/`.
- Convert raw filesystem notifications into `WatchEvent` objects.
- Wait until the added archive file, file, or directory appears stable before dispatching.
- Ignore files created by the system outside the watched input directory.

`WatchEvent`:

```text
WatchEvent
  id: unique event id
  kind: added
  root_path: absolute path to ./in
  path: absolute path to added file or directory
  relative_path: path relative to ./in
  source_name: original input basename, including all suffixes
  is_directory: boolean
  observed_at: UTC timestamp
```

Stability check:

- For a file, consider it stable after size and modification time are unchanged for
  `unchanged_checks` checks.
- For an exceptional directory, consider it stable after recursive file count, total size, and
  latest modification time are unchanged for `unchanged_checks` checks.
- If the path disappears before stabilization, drop the event and log it.

Implementation library:

- Use a polling watcher for the first implementation so tests do not rely on OS-specific
  notification behavior.
- Keep the watcher behind a small interface so a future `watchdog` implementation can be
  added without changing the dispatcher.

### 4.2 Dispatcher

Responsibilities:

- Receive `WatchEvent` objects from the watcher through `dispatcher.enqueue(event)`.
- Select processors configured under `pipelines.on_added.preprocessors` and
  `pipelines.on_added.analysis`.
- Create a `ProcessingContext`.
- Run preprocessors in order, then run analysis processors in order.
- Stage every accepted input into `middle-earth/` before analysis processors run.
- Run analysis only when staging emits a completed, usable `staged_capture`; preserve archive
  errors without analyzing partial output or the original failed archive.
- Record processor results and errors.
- Prevent one bad event from terminating the watcher process. Continue later independent
  analysis adapters after an analysis exception; stop analysis only when preprocessing fails
  to produce a trusted staged capture.
- Keep the watcher content-agnostic: all decisions about staging, unarchiving, IP scanning,
  executable scanning, and intelligence DB lookup belong to dispatcher-selected processors.

`ProcessingContext`:

```text
ProcessingContext
  event: WatchEvent
  config: resolved config
  output_root: absolute path to ./middle-earth
  analysis_output_root: absolute path to ./output
  base_dir: absolute configuration base directory
  staging_state: dispatcher-owned StagingState used by InputStager
  report_specs: configured processor names mapped to (output directory, hyphenated suffix)
  report_path(capture, processor_name): validate source/report identity and return reserved path
  run_id: unique run id
  logger: logger
```

First version execution model:

- Use one worker by default.
- Process events sequentially.
- Keep execution deterministic for tests.
- Add a queue boundary between watcher and dispatcher so future versions can increase worker
  count without changing processor contracts.
- Preserve ordered execution across future worker changes: preprocessors run once, and
  analysis processors run in the exact configured order against the accumulated record set.

Target lifecycle (present in the current source but requiring the verification gates in the
repository-wide plan): `enqueue(event)` queues without processing;
`drain()` processes queued events in order and returns their ProcessorResults. `dispatch(event)`
remains available for synchronous callers. Use Dispatcher as a context manager or call
`close()` to drain pending work and release the staging-root lock and SQLite connection.
The CLI uses the queue in both watcher and `--once` modes; one-shot mode returns nonzero
after draining if any event produced errors. Continuous mode schedules unstable sources for
another watcher stability check. Unexpected preprocessing exceptions suppress analysis for
that event. Unexpected analysis exceptions are adapter-scoped and do not suppress the next
independent analysis processor.

Pseudo-code:

```text
watcher observes new direct child under ./in
  -> watcher waits for path stability
  -> watcher creates WatchEvent
  -> dispatcher.enqueue(event)
  -> dispatcher creates ProcessingContext
  -> dispatcher resolves stage_input
  -> stage_input extracts the archive or copies exceptional non-archive inputs into middle-earth/
  -> dispatcher passes staged_capture records to analysis processors in configured order
  -> dispatcher logs records and errors
```

### 4.3 Processor Interface

Use a small synchronous processor contract for this slice.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass(frozen=True)
class ProcessorError:
    path: Path
    message: str
    code: str

@dataclass(frozen=True)
class ProcessorResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=dict)

class Processor(ABC):
    name: str

    @abstractmethod
    def process(
        self,
        input_records: list[dict[str, Any]],
        context: ProcessingContext,
    ) -> ProcessorResult:
        ...
```

The unarchiver is a source/preprocessor, so it can ignore `input_records` for the initial
implementation.

## 5. Input Stager Processor

Purpose:

- Convert every stable direct archive addition under `in/` into one staged capture directory
  under `middle-earth/`.
- Keep routing decisions out of the watcher.
- Emit `staged_capture` records for downstream analysis processors.

Behavior:

- If `event.path` has a supported archive suffix and matches the configured regex, route it
  to archive validation and extraction. An invalid or encrypted archive emits an error;
  it must not fall back to non-archive copying, even when `copy_files` is true.
- Resolve archive identity and reserve or reuse its staging name as specified in section 5.1.
  Pass that exact output path to the unarchiver; it must not generate another timestamp.
- If `event.path` is a directory, treat it as an exceptional uncompressed capture and
  recursively copy it into `middle-earth/<sanitized-directory-name>/`.
- If `event.path` is a non-archive file, treat it as an exceptional direct-file capture,
  create `middle-earth/<sanitized-file-basename>/`, and copy the file inside it.
- For archives, emit `staging_method: skipped_existing_output` only for a completed, usable
  entry for the same archive identity. A coincidentally existing directory is not a duplicate.
- Exceptional directory/file inputs keep their same-named staging behavior: reuse a usable
  existing staging directory when overwrite is disabled. Reject a name owned by another
  source or an indexed archive instead of adopting its output.
- Sanitize exceptional staging names once in the stager using the filename rules in section
  6.3. Separately set `report_stem` to the exact original direct-child basename for canonical
  report generation.
- Do not follow symlinks while copying unless future configuration explicitly allows it.

Staged capture record:

```json
{
  "type": "staged_capture",
  "capture_name": "2023-08-13_09-02-04.zip-260907-123456",
  "report_stem": "2023-08-13_09-02-04.zip.en_dec",
  "source_name": "2023-08-13_09-02-04.zip.en_dec",
  "source_path": "/abs/path/in/2023-08-13_09-02-04.zip.en_dec",
  "source_sha256": "<64 lowercase hex characters>",
  "staging_started_at": "2026-09-07T12:34:56Z",
  "staged_path": "/abs/path/middle-earth/2023-08-13_09-02-04.zip-260907-123456",
  "staging_method": "archive_extracted",
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

### 5.1 Archive Identity and Persistent Staging Assignment

Use a local SQLite staging index at `dispatcher.staging_index_path`. Bind each index to one
resolved watch root and staging root; fail startup if those roots disagree with its saved
metadata. This operational state is not part of the intelligence DB schema.

The same index stores unique `staged_path` ownership by archive identity and canonical
`report_path` ownership by `source_relative_path` plus processor. Report paths use the exact
direct-child basename as `report_stem`, followed by the processor's hyphenated suffix. Record
exceptional directory/file ownership too, before copying or reporting. A later archive identity
at the same source-relative path intentionally refreshes that logical input's reports only
after its staging and analysis succeed. A different source-relative path may not claim the
same report path. An existing unowned path is a collision, never proof of ownership. Analysis
adapters receive the assignment from the dispatcher and do not update staging state. The
staging-root process lock also covers report publication.

Each archive entry stores:

- `source_relative_path`: original path relative to the watch root, including all suffixes.
- `source_sha256`: SHA-256 of the complete archive bytes, computed with bounded reads.
- `capture_name`, `staged_path`, and `staging_started_at`: the reserved output assignment.
- `status`: `pending`, `ready`, or `failed`, plus extraction manifest and error details.

The trusted manifest records each extracted relative path, entry type, file size, and content
SHA-256. Keep it in staging state outside captured content so recovery can verify a published
directory. Source hashing and manifest hashing use bounded reads.

Enforce uniqueness for `(source_relative_path, source_sha256)`, `capture_name`, and
`staged_path`. The event ID, modification time, and filename timestamp are not archive
identity. Identical bytes re-copied at the same input path reuse one entry even after restart.
Changed bytes at that path, or identical bytes at a different input path, define a new entry.

Assignment and recovery:

1. After stabilization, hash the archive and validate the selected format. Detect source
   changes during hashing/extraction; do not publish output under a stale digest. Requeue an
   unstable source for stabilization.
2. Look up its identity before reading the clock. With `skip_if_output_exists` and
   `overwrite: false`, a `ready` entry with usable output returns the saved staged record.
   Preserve its name and staging-start time; record the current event/run IDs as invocation
   provenance. Analysis may run again against that same capture.
3. For a new identity, sample UTC once when reserving staging work, after validation and
   hashing. Persist this time and the name from section 6.3 in one transaction before
   extraction. Reserve staging names uniquely. Report paths do not participate in staging-name
   collision selection because they are keyed by source-relative filename, not capture name.
4. Extract into a private temporary directory beneath `middle-earth/.partial/`, outside all
   analysis roots. Persist the validated extraction manifest, publish the complete directory
   by an atomic rename on the same filesystem, then mark the entry `ready`. Emit a staged
   record only after completion. Captured files must not be able to write the staging index.
5. A failed attempt, missing completed output, or abandoned pending attempt retries the same
   saved assignment and timestamp. Clean only temporary output owned by that entry.
   A directory left by a crash between publication and the `ready` update must be verified
   against the saved manifest before recovery marks it ready. If ownership or completeness
   cannot be established, report a recovery error; do not adopt or overwrite unknown output.
6. Serialize staging ownership with a process lock for the staging root in the first version.
   A second process must fail startup rather than recover another live process's pending work.

Keep index entries for as long as their captures or reports are retained. An unavailable or
corrupt index is a staging error, not a reason to generate fresh names. Do not reconstruct
archive identity by guessing from timestamped directory names.

## 6. Unarchiver Processor

### 6.1 Target Discovery

The processor receives one `WatchEvent`.

If `event.path` is a file:

- Check whether the file has a configured archive extension.
- Check whether its basename matches `filename_regex`.
- Validate that the file content matches the selected archive type.
- If all checks pass, extract it.

If `event.path` is a directory:

- Walk recursively under the directory.
- For each file, calculate depth relative to `event.path`.
- Extract files that match supported format, regex, and depth limit.

Depth example:

```text
in/case/archive.zip                 depth 0
in/case/level1/archive.zip          depth 1
in/case/level1/level2/archive.zip   depth 2
```

### 6.2 Archive Type Detection

Prefer content-aware detection over filename-only trust:

- `.zip`: validate with `zipfile.is_zipfile`.
- `.en_dec` and `.enc`: validate with `zipfile.is_zipfile` and extract exactly as ZIP content.
  A filename ending in `.zip.en_dec` selects the `.en_dec` ZIP alias, not an encryption step.
- `.tar.gz`: validate as tar content and open with gzip compression.
- Use filename extensions only to select candidates quickly.
- If extension and content disagree, do not extract and emit an error record. ZIP aliases
  with corrupt data or password-protected entries also fail as archives; never copy them as
  exceptional non-archive captures. Apply the same extraction safety and size limits to aliases.

Format policy:

- The checked-in unarchiver profile enables only the four production formats above. Add another
  format only after its hostile-fixture coverage is accepted and it is enabled in configuration.
- Formats such as `.xz` and `.7z` remain unsupported. Add a format only by extending candidate
  selection, content validation, safe extraction, limits, and tests together.

### 6.3 Output Layout

For each new direct archive identity:

```text
middle-earth/<archive-label>-<YYMMDD-HHMMSS>[-<counter>]/<archive-contents>
```

Naming is owned by the stager and shared by all archive entry points:

- Start with the original filename. Remove at most one final suffix from
  `strip_final_suffixes` (default: `.en_dec`, `.enc`). Never strip the remaining `.zip`;
  ordinary `.zip` and `.tar.gz` filenames retain their complete archive extensions.
- Sanitize only the wrapper label: retain ASCII letters, digits, `.`, `_`, and `-`;
  replace other characters with `_`. Replace an empty label, `.`, or `..` with `capture`.
  Validate the final filename against filesystem length limits and fail with a naming error
  if it is too long. Do not sanitize or flatten archive members using this wrapper rule.
- Reserve `middle-earth/.partial/` for internal temporary output. Reject an exceptional input
  whose sanitized staging name is `.partial`; it must never become an analysis capture.
- Append UTC `staging_started_at` formatted as `%y%m%d-%H%M%S`. This is processing time,
  not the date embedded in the source filename, source mtime, or report-generation time.
- First try the name without a counter. If another identity has reserved it or its target
  already exists, try `-2`, `-3`, and so on.
  Reserve the first available name transactionally. This also handles label-sanitization
  collisions and clocks moving backwards without altering the assigned timestamp.
- `capture_name` is the final reserved directory basename, including any collision counter.
  Downstream processors use it as staging provenance, not as the report filename.
- `report_stem` is the original direct-child basename including all suffixes. Require a single
  filesystem component other than `.` or `..`; reject NUL, ASCII controls, and Unicode
  line/paragraph separators; and verify it equals `source_name` and
  `source_relative_path.name`. Do not sanitize or strip it. The report path is
  `output/<report_stem><processor-report-suffix>`.

Examples with staging-start time `2026-09-07T12:34:56Z`:

| Input filename | Assigned directory basename |
| --- | --- |
| `2023-08-13_09-02-04.zip.en_dec` | `2023-08-13_09-02-04.zip-260907-123456` |
| `sample.en_dec` | `sample-260907-123456` |
| `sample.enc` | `sample-260907-123456-2` if the preceding name is reserved |
| `sample.zip` | `sample.zip-260907-123456` |
| `sample.tar.gz` | `sample.tar.gz-260907-123456` |

Staging names and report names deliberately differ:

| Input archive | Staging directory | Canonical reports |
| --- | --- | --- |
| `sample.zip.en_dec` | `sample.zip-260907-123456/` | `sample.zip.en_dec-ipintel.md`, `sample.zip.en_dec-fileintel.md`, `sample.zip.en_dec-ghintel.md`, `sample.zip.en_dec-yara.md` |

If appending a processor suffix would exceed the filesystem filename limit, emit a report
naming error; do not truncate or hash the archive basename because that would violate the
operator-visible naming contract.

The expected primary layout is:

```text
in/2023-08-13_09-02-04.zip.en_dec
middle-earth/2023-08-13_09-02-04.zip-260907-123456/
  185.17.40.153:85/
    <archive-contents>
```

Keep the colon in a relative `IP:PORT` member directory on Linux. All path validation in
section 6.4 still applies. The member directory does not become a separate capture.

If an archive is found inside an exceptional dropped directory, retain its relative source
parent and apply the same naming and identity rules to its archive output:

```text
in/case/subdir/toolkit.zip
middle-earth/case/subdir/toolkit.zip-260907-123456/<archive-contents>
```

Its output remains within the parent staged capture and is scanned through that parent's
record; nested extraction does not create an additional analysis capture/report by default.

Duplicate and overwrite behavior:

- Resolve duplicates by the index in section 5.1, not by generating a name and checking whether
  it exists. With `overwrite: false`, reuse only the same identity's completed extraction and
  emit `skipped_existing_output`.
- A name collision with another identity always allocates a counter; it never skips the new
  archive or replaces the other capture.
- If `overwrite: true` is explicitly configured, re-extract the same identity at its saved
  path and timestamp. Validate ownership and containment before replacing that entry's output,
  and publish only fully validated replacement contents. Other identities remain untouched.
- Directory existence alone, including a partial extraction, never proves completion.

The current source supports indexed staging with `overwrite: false`; acceptance remains
unverified until the repository contains and passes the tests listed in section 7.
`overwrite: true` remains a future extension and is rejected at startup until atomic
replacement/recovery for populated capture directories is implemented.

### 6.4 Safe Extraction

All captured content is hostile. The unarchiver must implement these checks before writing any
archive member:

- Resolve the candidate destination path and ensure it stays under the intended archive output
  directory.
- Reject absolute paths.
- Reject `..` traversal.
- Reject symlinks and hard links in tar archives.
- Reject special files such as devices and FIFOs.
- Create directories with controlled permissions.
- Write regular files only.
- Enforce file count and total extracted byte limits.
- Never execute extracted files.

For zip files:

- Iterate `ZipInfo` entries.
- Reject entries whose normalized path escapes the output directory.
- Reject entries that look like symlinks based on external attributes.

For tar files:

- Iterate `TarInfo` entries.
- Permit only directories and regular files.
- Reject symlink, hardlink, device, FIFO, and other special entry types.
- Check destination paths before extraction.
- Avoid `tar.extractall`; extract members one by one after validation.

For single-file bzip/gzip content:

- Stream decompression in chunks.
- Enforce total extracted byte limits while writing.
- Emit one `extracted_artifact` record for the decompressed output file.
- Enable this path only when the exact suffix is present in `supported_formats`.

### 6.5 Records

Successful extraction record:

```json
{
  "type": "archive_extracted",
  "archive_path": "/abs/path/in/212.212.212.212.tar.gz",
  "output_dir": "/abs/path/middle-earth/212.212.212.212.tar.gz-260907-123456",
  "archive_format": ".tar.gz",
  "files_extracted": 1,
  "bytes_extracted": 12345,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Extracted artifact record:

```json
{
  "type": "extracted_artifact",
  "archive_path": "/abs/path/in/213.213.213.213_99.zip",
  "path": "/abs/path/middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt",
  "relative_path": "a/b/c/iplist.txt",
  "size_bytes": 67,
  "source_event_id": "evt-...",
  "pipeline_run_id": "run-..."
}
```

Error record:

```json
{
  "type": "archive_error",
  "archive_path": "/abs/path/in/bad.zip",
  "code": "path_traversal",
  "message": "archive member escapes output directory",
  "source_event_id": "evt-..."
}
```

## 7. Testing Plan

### 7.1 Unit Tests

Watcher:

- Creates an `added` event for a new direct child file under `in/`.
- Creates an `added` event for a new direct child directory under `in/`.
- Ignores nested child events when only direct children are watched.
- Drops events for paths that disappear before stabilization.

Dispatcher:

- Runs configured preprocessors in order.
- Runs analysis processors after preprocessors.
- Passes `staged_capture` records from preprocessors to analysis processors.
- Passes the accumulated record set from each analysis processor to later analysis processors.
- Passes a valid `ProcessingContext` to processors.
- Logs processor errors without stopping the dispatcher.
- Fails fast on unknown processor names during configuration or dispatch.

Input stager:

- Routes `.en_dec`, `.enc`, `.zip`, and `.tar.gz` content to the unarchiver.
- Copies exceptional dropped directories into `middle-earth/`.
- Copies exceptional dropped non-archive files into a same-named staging directory.
- Emits one `staged_capture` record for each accepted input.
- Reuses completed indexed archive output when overwrite is false; retains same-named
  exceptional directory/file behavior.
- Does not follow symlinks by default.

Unarchiver:

- Extracts `testdata/212.212.212.212.tar.gz` to
  `middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe`.
- Extracts `testdata/213.213.213.213_99.zip` to
  `middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt`.
- Treats `.en_dec` and `.enc` as ZIP content, including `.zip.en_dec` filenames.
- Supports `.en_dec`, `.enc`, `.zip`, and `.tar.gz` candidates in the default configuration.
- Skips extraction only for a ready, usable entry for the same archive identity when
  `overwrite` is false.
- Rejects path traversal archives.
- Rejects tar symlink and hardlink members.
- Enforces file count and byte limits.
- Honors `filename_regex`.
- Honors `max_depth_from_event_root` for archives inside dropped directories.

Archive identity and naming:

- With an injected UTC clock at `2026-09-07T12:34:56Z`, extracts the primary `.zip.en_dec`
  fixture to `middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/`.
- Removes only the final `.en_dec` or `.enc`; preserves ordinary `.zip` and `.tar.gz`.
- Rejects corrupt, encrypted, and path-traversing `.en_dec` archives without copying them.
- Reuses the same name and timestamp for duplicate events and identical re-copies at the same
  path, including after process restart.
- Assigns a distinct name to changed bytes at the same path or identical bytes at another path.
- Appends staging counters for same-second, sanitized-label, and existing staging-path
  collisions. Report-path collisions are handled independently: the same source-relative path
  may refresh its slot, while an unowned path or different logical owner is rejected.
- Retries failed extraction with the saved assignment; never scans partial output.
- Recovers a publication interrupted before the ready update only after manifest verification.
- Rejects an unavailable index or a second process claiming the same staging root.
- Preserves existing output belonging to another identity even when overwrite is enabled.

### 7.2 Integration Test

Test setup:

```text
in/
middle-earth/
testdata/
  2023-08-13_09-02-04.zip.en_dec
  212.212.212.212.tar.gz
  213.213.213.213_99.zip
```

Use an injected UTC clock fixed at `2026-09-07T12:34:56Z` for deterministic tests. Live CLI
runs use actual UTC staging-start time instead of the literal suffix shown here.

Test steps:

```bash
cp testdata/2023-08-13_09-02-04.zip.en_dec in/
cp testdata/212.212.212.212.tar.gz in/
cp testdata/213.213.213.213_99.zip in/
python -m erecb_triage --once --config config/watcher_unarchiver.yaml
```

Expected files:

```text
middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/<fixture files>
middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe
middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt
```

The integration test should use the dispatcher directly with synthetic `WatchEvent` objects if
filesystem notification timing is flaky. A separate smoke test can run the polling watcher.

## 8. Implementation Layout

```text
config/
  watcher_unarchiver.yaml
src/
  erecb_triage/
    __init__.py
    __main__.py
    config.py
    dispatcher.py
    events.py
    watcher.py
    processors/
      __init__.py
      archive_unarchiver.py
      base.py
      input_stager.py
      ip_retriever.py
      file_retriever.py
tests/
  test_dispatcher.py
  test_unarchiver.py
  test_watcher.py
  test_watcher_unarchiver_integration.py
```

## 9. Component Work Breakdown

This sequence describes the component, not current completion status. The authoritative
status, dependencies, and release gates are in `IMPLEMENTATION_PLAN.md`.

1. Add dataclasses for `WatchEvent`, `ProcessingContext`, `ProcessorResult`, and
   `ProcessorError`.
2. Add a YAML config loader and validator.
3. Add a processor registry mapping `archive_unarchiver` to the unarchiver class.
4. Add `input_stager` and update the processor registry.
5. Implement the dispatcher with synchronous preprocessor and analysis execution.
6. Implement safe archive candidate discovery.
7. Implement safe ZIP, `.en_dec`, and `.enc` extraction.
8. Implement safe tar-gzip extraction.
9. Implement persistent staging identity, UTC name reservation, collision counters, and recovery.
10. Implement the polling watcher with stability checks.
11. Add unit tests for dispatcher, watcher, input stager, and unarchiver.
12. Add integration tests using fixture archives in `testdata/`.
13. Add a command-line entry point:

```bash
python -m erecb_triage --config config/watcher_unarchiver.yaml
python -m erecb_triage --once --config config/watcher_unarchiver.yaml
```

## 10. Initial Acceptance Criteria

- Running the watcher monitors `in/`.
- One-shot mode scans existing direct children of `in/`.
- Copying `testdata/212.212.212.212.tar.gz` into `in/` creates:

```text
middle-earth/212.212.212.212.tar.gz-260907-123456/malicious/malware.exe
```

- Copying `testdata/213.213.213.213_99.zip` into `in/` creates:

```text
middle-earth/213.213.213.213_99.zip-260907-123456/a/b/c/iplist.txt
```

- A `.en_dec` or `.enc` file containing ZIP data extracts like a normal ZIP, without decryption.
- At the example UTC staging time, `2023-08-13_09-02-04.zip.en_dec` creates
  `middle-earth/2023-08-13_09-02-04.zip-260907-123456/185.17.40.153:85/` with its member tree intact.
- Direct non-archive files and directories are staged under `middle-earth/`.
- The dispatcher can run analysis processors after staging, including `ip_retriever` and
  `file_retriever` when configured by later design slices.
- `.en_dec`, `.enc`, `.zip`, and `.tar.gz` files are considered supported archive candidates by the
  default configuration.
- Re-copying identical archive bytes to the same input path reuses its completed indexed
  output and timestamp across restarts when `overwrite` is false.
- Changed content gets a separate capture; same-second collisions append a counter.
- Staged records carry both the unique `capture_name` for staging provenance and the original
  archive `report_stem` for consistent canonical report naming.
- With all processors enabled, `sample.zip.en_dec` owns exactly
  `sample.zip.en_dec-ipintel.md`, `sample.zip.en_dec-fileintel.md`,
  `sample.zip.en_dec-ghintel.md`, and `sample.zip.en_dec-yara.md` under `output/`.
- A successful replacement at the same input filename atomically refreshes those reports; a
  failed staging or analysis attempt leaves the prior successful report for that processor
  intact and records the failure separately.
- Failed or incomplete output is never treated as a completed duplicate.
- Malicious archive paths cannot write outside `middle-earth/`.
- The watcher process continues after a corrupt or unsupported archive.
