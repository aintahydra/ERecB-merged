# IMPLEMENTATION 02: Trusted Ingestion and Dispatcher

## 1. Objective and status

Prove the complete boundary from a stable archive in `in/` to an authorized, immutable
`staged_capture` under `middle-earth/`, then run independent analysis adapters with owned
Markdown report paths.

Status: **implemented (baseline)**. The trusted archive boundary, logical report slots,
recovery checks, single-process staging lock, and adapter-scoped analysis isolation are covered
by the offline integration suite. Production configuration enables only ZIP aliases and
`.tar.gz`; additional archive handlers remain intentionally unavailable pending their own
hostile-fixture coverage.

## 2. Required behavior

```text
in/sample.zip.en_dec becomes stable
  -> WatchEvent(kind=added)
  -> hash and validate source archive
  -> reserve unique staging identity
  -> extract into middle-earth/.partial/<private>/
  -> validate manifest and source stability
  -> atomic publish to middle-earth/sample.zip-YYMMDD-HHMMSS[-N]/
  -> mark staging row ready
  -> emit staged_capture(report_stem=sample.zip.en_dec)
  -> run configured analysis adapters
  -> publish output/sample.zip.en_dec-<processor>.md
```

No adapter may read the original archive or a `.partial` directory.

## 3. Files in scope

Primary implementation surfaces:

- `src/erecb_triage/watcher.py`
- `src/erecb_triage/events.py`
- `src/erecb_triage/staging.py`
- `src/erecb_triage/dispatcher.py`
- `src/erecb_triage/processors/input_stager.py`
- `src/erecb_triage/processors/archive_unarchiver.py`
- `src/erecb_triage/processors/base.py`
- `src/erecb_triage/config.py`
- `src/erecb_triage/__main__.py`
- `config/watcher_unarchiver.yaml`

## 4. Work package A — watcher and stabilization

Implement and verify:

- immediate-child discovery under the configured watch root;
- continuous mode dispatches only additions observed after startup;
- explicit `--once` enumerates existing immediate children deterministically;
- file stability uses unchanged size and nanosecond mtime for the configured number of checks;
- exceptional directory stability uses recursive count, total size, and latest mtime without
  following symlinks;
- a disappearing or changing source is dropped/requeued rather than dispatched as complete;
- debounce state is bounded and cleared after terminal processing; and
- events carry normalized absolute/root-relative paths and UTC observation time.

Tests use an injected clock/poller. They must not rely on filesystem timing sleeps except for a
small end-to-end smoke test.

## 5. Work package B — archive identity and reservation

For archive input, compute identity as `(source_relative_path, source_sha256)` with bounded
reads after stabilization. Detect source changes during hashing and extraction.

Reservation behavior:

- reuse a `ready` entry for identical bytes at the same input path;
- retry `pending`/`failed` work with its saved staging name and timestamp;
- allocate a new identity for changed bytes or a different input path;
- construct staging label by removing at most final `.en_dec` or `.enc`, retaining `.zip` or
  other archive suffixes;
- append UTC `-YYMMDD-HHMMSS`, then `-2`, `-3`, etc. for staging collisions;
- set `report_stem` to the unchanged direct-child source basename, including all suffixes; and
- reserve canonical report slots by `(source_relative_path, processor_name)`, independently of
  staging-name counters.

The report slot for a source filename may be reused by a later archive generation at that same
path. Another source-relative path and any unowned filesystem entry are collisions.

## 6. Work package C — safe extraction and publication

For every enabled archive format:

1. Select by configured suffix/regex, then verify content/type.
2. Enforce maximum source size before and during processing.
3. Extract only into an empty private directory below `.partial`.
4. Reject absolute paths, `..` escapes, symlinks, hardlinks, devices, FIFOs, sockets, and
   unsupported member types.
5. Enforce cumulative regular-file count and extracted-byte limits while writing.
6. Use controlled permissions and never preserve privileged mode/ownership metadata.
7. Hash each published regular file into a trusted manifest stored outside capture content.
8. Recheck source identity/stability before publication.
9. Fsync required files/state as supported, atomically rename on the same filesystem, and mark
   the entry `ready` only after successful publication.

ZIP aliases `.en_dec` and `.enc` request ZIP validation only; they do not request decryption.
Encrypted/corrupt aliases fail and never fall back to direct-file copying.

Freeze the production set after fixtures exist. Required: `.en_dec`, `.enc`, `.zip`, and
`.tar.gz`. Enable `.tar`, `.tgz`, tar-bzip, or single gzip/bzip streams only when every safety
case below passes for that handler.

## 7. Work package D — recovery

Handle process interruption at each durable boundary:

- reserved row before private directory creation;
- partial extraction;
- manifest stored before rename;
- published directory before `ready` update; and
- ready state with missing/modified output.

Recovery may mark published output ready only after complete manifest verification. It may
delete only a private partial directory proven to belong to the recovering row. Unknown output
is never adopted, overwritten, or recursively removed.

Retain an exclusive staging-root process lock. A second live dispatcher fails startup with an
actionable error.

## 8. Work package E — dispatcher isolation

The dispatcher must:

- validate every selected processor is constructible before watching;
- enqueue without executing and drain in deterministic event order;
- run preprocessors once, require at least one valid ready staged record, then run analysis;
- pass the accumulated record set while requiring adapters to select compatible records;
- aggregate namespaced metrics and bounded structured errors;
- treat preprocessing exceptions as event-level blockers;
- treat analysis exceptions as adapter-scoped and continue later independent adapters; and
- continue all later queued events.

Keep `max_workers: 1` in this phase. Do not add concurrency before the scale phase.

## 9. Work package F — report slots and atomic publication

Update the context API so `report_path(staged_capture, processor_name)`:

- revalidates staging readiness and current event/run provenance;
- validates `report_stem` against source identity;
- combines it with the processor's fixed hyphenated suffix;
- checks component and filesystem length limits without truncation;
- claims/validates the logical report slot; and
- rejects symlink, directory, or unowned existing targets.

Adapters write a private temporary sibling, flush/fsync, recheck the slot, and atomically
replace the canonical file. A failed render/publication leaves the prior successful report
intact. Reports include archive filename, source digest, unique staging name/path, run ID,
generation time, processor status, and warnings so retained reports identify their provenance.

## 10. Test matrix

| Area | Cases |
| --- | --- |
| Watcher | add, startup/once, nested event ignored, debounce, disappear, unstable file/directory |
| Identity | duplicate event, restart reuse, changed bytes, same bytes/different name, fixed-clock counter |
| ZIP | normal, `.en_dec`, `.enc`, encrypted, corrupt, traversal, absolute, symlink attributes |
| Tar | normal, traversal, absolute, symlink, hardlink, device, FIFO, sparse/unsupported metadata |
| Limits | source bytes, extracted bytes, file count, filename/path length, zero boundary |
| Recovery | interruption at every boundary, manifest mismatch, unknown directory, second process |
| Reports | exact four filenames, same-name refresh, other-owner collision, unowned file, symlink target |
| Isolation | preprocessor exception, returned error, each analysis exception, later event continuation |

Use generated inert fixtures. Never execute extracted members.

## 11. Verification scenarios

Minimum end-to-end scenario with an injected UTC clock:

```text
in/sample.zip.en_dec
middle-earth/sample.zip-260920-120000/<members>
output/sample.zip.en_dec-ipintel.md
output/sample.zip.en_dec-fileintel.md
```

Use analysis test doubles until Implementation 03. Repeat with changed archive bytes at the
same filename and verify a new staging directory plus atomic canonical-report refresh. Inject a
failed analysis and verify the previous report remains intact and the error is observable.

## 12. Exit gate

Implementation 02 is complete only when:

- no hostile fixture escapes its private staging directory;
- partial/failed extraction never reaches analysis;
- every ready staged record passes manifest and invocation validation;
- report naming and ownership exactly match the archive-filename contract;
- independent analysis failures do not suppress other adapters or later events;
- restart/recovery tests pass at every durable boundary; and
- the verification record includes commands, results, and enabled archive formats.

Next: [`IMPLEMENTATION_03_IPINTEL_FILEINTEL.md`](IMPLEMENTATION_03_IPINTEL_FILEINTEL.md).
