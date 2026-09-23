# YaraRuler implementation plan

> Implementation note: this is the original architectural plan. See
> [`implementation-status.md`](implementation-status.md) for the 0.1.1 as-built status
> and the few implementation details that supersede this plan.

## 1. Purpose and scope

YaraRuler is a passive-analysis CLI that synchronizes configured YARA repositories,
validates and compiles usable rules into a binary cache, discovers candidate files,
scans them concurrently, and writes deterministic JSON or CSV reports.

The first release contains two commands:

```text
yararuler update-rules [--source URL]
yararuler scan [OPTIONS]
```

Rule comparison, deduplication, semantic optimization, and collision analysis are
explicitly deferred. Target files are data only: no target is executed, imported,
loaded as a library, or passed to a shell.

## 2. Recommended technology

- Python 3.11 or newer.
- `yara-python` for validation, cache compilation, cache loading, and scanning.
- `typer` for the command-line interface and generated help.
- `pydantic` plus the standard-library `tomllib` for typed configuration.
- `python-magic` for MIME hints, treated as an optional enhancement because it also
  requires the platform `libmagic` package.
- The `git` executable, invoked with an argument vector and never through a shell.
- Standard-library `concurrent.futures.ProcessPoolExecutor` for scan parallelism.
- `pytest` for unit, integration, and CLI tests.

Pin direct dependencies and test against the oldest and newest supported Python and
YARA versions. Build Linux x86_64, Linux arm64, and macOS arm64 wheels where dependency
availability permits; otherwise document the required system packages.

## 3. Proposed repository layout

```text
.
├── config.toml
├── pyproject.toml
├── src/yararuler/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── config.py
│   ├── errors.py
│   ├── logging.py
│   ├── models.py
│   ├── rules/
│   │   ├── cache.py
│   │   ├── compiler.py
│   │   ├── quarantine.py
│   │   ├── sync.py
│   │   └── update.py
│   ├── scan/
│   │   ├── discovery.py
│   │   ├── filters.py
│   │   ├── hashing.py
│   │   ├── matcher.py
│   │   └── service.py
│   └── report/
│       ├── csv_writer.py
│       ├── json_writer.py
│       └── service.py
├── rules/
│   ├── sources/                 # managed Git checkouts
│   ├── quarantine/              # rejected-rule snapshots and diagnostics
│   ├── cache/
│   │   ├── active               # generation ID of the active cache
│   │   └── generations/
│   │       └── <generation-id>/
│   │           ├── rules.yac
│   │           └── manifest.json
│   └── .update.lock
├── in/
├── design/
└── tests/
    ├── fixtures/
    ├── unit/
    └── integration/
```

Generated directories should be ignored by Git except for optional `.gitkeep` files.
Source checkouts are managed state and must not be modified to quarantine a rule.

## 4. Configuration contract

Load `./config.toml` by default. A future global `--config PATH` option should be
implemented in the first release because it makes tests and automation predictable.

Precedence, from highest to lowest, is:

1. command-line option explicitly supplied by the user;
2. value in `config.toml`;
3. application default.

Unknown keys are configuration errors, paths expand environment variables and `~`,
and relative paths resolve against the directory containing the configuration file.
Secrets are not expected in this file.

Recommended schema:

```toml
[paths]
rules_dir = "rules"
target_dir = "in"

[rules]
cache_dir = "rules/cache"
quarantine_dir = "rules/quarantine"

[[rules.sources]]
name = "community-rules"
url = "https://github.com/Yara-Rules/rules.git"
ref = "main"                 # branch, tag, or commit; optional
enabled = true

[scan]
threads = 1
timeout_seconds = 30
default_selector = "exec-only" # "all" or "exec-only"
follow_symlinks = false
include_strings = false
max_file_size_bytes = 0       # 0 means unlimited

[report]
format = "json"
output = "report.json"
pretty_json = true

[logging]
level = "INFO"
```

Validation rules:

- source names must be unique and match `[A-Za-z0-9][A-Za-z0-9._-]*`;
- URLs must use an explicitly supported Git transport (`https`, `ssh`, or a local
  path when local sources are intentionally enabled);
- thread count and timeout must be positive integers;
- format must be `json` or `csv`;
- configured source, cache, and quarantine locations must not overlap in a way that
  lets a checkout overwrite the cache;
- duplicate resolved checkout paths are rejected.

The `--source URL` option adds one source for that update invocation. Its stable name
is derived from the repository basename and rejected on collision unless a future
`--source-name` option is added. It does not rewrite `config.toml`.

## 5. CLI behavior

### 5.1 Global behavior

```text
yararuler [--config PATH] [--log-level LEVEL] COMMAND
```

Human-readable progress and diagnostics go to stderr. Reports go only to the selected
output file, or to stdout when `--output -` is used. This separation keeps stdout safe
for pipelines.

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | command completed; zero matches is still success |
| 2 | CLI usage or configuration error |
| 3 | rule synchronization or cache-build failure |
| 4 | cache missing, stale, incompatible, or unreadable |
| 5 | scan completed but one or more files had recoverable errors |
| 6 | report could not be written |
| 70 | unexpected internal error |

Recoverable file errors still produce a report and use exit code 5. A future
`--ignore-file-errors` can opt automation into exit code 0 without changing report
contents.

### 5.2 `update-rules`

```text
yararuler update-rules [--source URL] [--force-rebuild]
```

The command prints a summary of repositories synchronized, files accepted, files
quarantined, and the cache generation published. It must retain the previous working
cache if synchronization or compilation fails.

### 5.3 `scan`

```text
yararuler scan \
  [--target-dir PATH] \
  [--all | --exec-only] \
  [--glob PATTERN ...] \
  [--regex PATTERN ...] \
  [--threads N] \
  [--timeout SECONDS] \
  [--include-strings] \
  [--format json|csv] \
  [--output PATH]
```

`--all` and `--exec-only` are selector modes and are mutually exclusive. If neither
is present, `scan.default_selector` applies. Glob and regex filters may be combined
with either selector. Repeated globs are ORed with one another, repeated regexes are
ORed with one another, and different filter families are ANDed:

```text
selected = selector(file)
           AND (no_globs OR any_glob_matches)
           AND (no_regexes OR any_regex_matches)
```

This makes `--all --glob '*.bin'` select readable `.bin` files, while
`--exec-only --glob 'sample_*' --regex '^in/release/'` selects executable/script
candidates satisfying both name and path restrictions.

Invalid regular expressions fail before traversal. A glob matches the basename using
case-sensitive shell-style matching. A regex searches the normalized report-relative
path, using `/` separators on every platform. If the target lies below the current
working directory, this is such as `in/release/a.exe`; otherwise it is relative to the
target's parent. The exact string used for matching is also emitted as `file_path`.

## 6. Rule update architecture

### 6.1 Safe repository synchronization

1. Acquire `rules/.update.lock` using an OS-level exclusive lock. If already locked,
   report the owning PID when available and exit rather than running two updates.
2. Validate all source definitions before changing local state.
3. For a missing source directory, clone into a sibling temporary directory with
   `git clone --no-tags` (unless a tag is requested), check out the configured ref,
   then atomically rename it to `rules/sources/<name>`.
4. For an existing checkout, verify that its origin URL matches configuration and
   that it contains no unexpected local changes. Fetch the configured origin and
   update with fast-forward-only semantics. Never merge, rebase, or discard local
   changes automatically.
5. Record the resolved commit SHA for every source. A pinned commit remains pinned;
   a branch resolves to the newly fetched branch head.
6. Network or Git failure for any required source aborts publication, logs the source
   failure, and leaves the active cache untouched.

Pass Git arguments as a list with `shell=False`. Set non-interactive Git environment
options so updates cannot hang on credential prompts. Redact credentials embedded in
URLs from logs and manifests.

### 6.2 Discovery and individual validation

Walk each source deterministically (sorted directories and filenames) and consider
regular files ending in `.yar` or `.yara`, case-insensitively. Do not follow symlinks
outside the checkout. For each candidate:

1. compute SHA-256;
2. compile it alone with `yara.compile(filepath=...)` and includes enabled;
3. resolve includes only beneath the same source root; reject absolute includes,
   traversal outside the root, include cycles, and missing include files;
4. capture compiler warnings and errors with source name and relative path;
5. classify it as accepted or quarantined.

“Individually” means one top-level file is a compilation unit; its explicit include
tree belongs to that unit. A file relying on undeclared cross-file rule identifiers
will fail individual validation and be quarantined. This deliberately makes the cache
reproducible and avoids implicit repository-wide coupling.

YARA module imports are allowed only when the installed YARA build supports them.
Unsupported modules (commonly environment-specific modules), syntax errors, obsolete
constructs, unsafe include paths, and encoding/read failures are quarantine reasons,
not whole-update failures.

### 6.3 Quarantine representation

Do not move or edit files inside a Git checkout. For each rejected top-level rule,
write:

```text
rules/quarantine/<source>/<relative/path>.yar
rules/quarantine/<source>/<relative/path>.yar.error.json
```

The copied rule is for diagnosis; the JSON sidecar contains source URL (redacted),
commit, original path, SHA-256, YARA version, phase, error class, sanitized diagnostic,
and timestamp. Rebuild quarantine data in a staging directory and publish it after
validation so removed/fixed rules do not leave misleading current diagnostics.

The cache manifest remains the authoritative accepted/rejected inventory. Limit
individual diagnostics and total copied bytes to prevent a hostile repository from
causing unbounded disk use; note truncation in the manifest.

### 6.4 Namespace and central compilation

Every accepted top-level file receives a stable, unique namespace:

```text
<sanitized-source-name>__<sanitized-relative-path>__<short-path-hash>
```

The path hash prevents normalization collisions. Store the human source name and
relative rule path in the manifest so consumers do not have to decode namespaces.

Compile all accepted units in one `yara.compile(filepaths={namespace: path, ...})`
call using the same constrained include resolver, then save the resulting `Rules`
object as a `.yac` artifact. Unique per-file namespaces prevent duplicate rule names
in unrelated files from colliding while preserving YARA's reported namespace.

If aggregate compilation fails after individual validation, bisect the accepted set
to identify problematic interaction(s), quarantine those units with phase
`aggregate_compile`, and retry once. If the remaining set still cannot compile, fail
the update and retain the prior active cache. Publishing an empty cache is forbidden
unless an explicit future `--allow-empty` option is introduced.

### 6.5 Transactional cache publication

Build under `rules/cache/.staging-<uuid>/`, then verify the saved artifact by loading
it with `yara.load()` in a fresh process. Generate a manifest containing:

- schema and cache generation versions;
- timestamp, Python/YARA/yara-python versions, platform, and architecture;
- source names, redacted URLs, configured refs, and resolved commit SHAs;
- accepted namespace/path/SHA-256 entries;
- rejected entries and normalized error categories;
- `.yac` SHA-256 and size;
- counts and build duration.

Fsync staged files where supported, atomically rename the complete staging directory
to `cache/generations/<generation-id>/`, then atomically replace the small `active`
pointer file with that generation ID. The scanner reads the pointer once, opens both
files from that immutable generation directory, and verifies the artifact hash. This
single-file commit point prevents a manifest/artifact mismatch after a crash. The
update lock prevents concurrent publishers, and at least the current and previous
verified generations are retained. Old generations may be pruned only after the new
pointer is durable and no scan holds a shared generation lease.

#### ERecB Triage consumer manifest contract

The Triage `yara_scan` adapter consumes this immutable cache directly. It does not
clone repositories or compile source rules, so every published manifest must use this
shared schema, rather than producer-local aliases such as `generation` or `accepted`:

```json
{
  "schema_version": 1,
  "generation_id": "<the UUID written to cache/active>",
  "platform": "Linux",
  "machine": "x86_64",
  "runtime": {
    "yara_version": "<libyara version>",
    "yara_python_version": "<yara-python version>"
  },
  "artifact": {
    "filename": "rules.yac",
    "size": 12345,
    "sha256": "<lowercase SHA-256>"
  },
  "accepted_rules": [
    {
      "namespace": "<unique namespace>",
      "source": "<source name>",
      "url": "<credential-redacted source URL>",
      "path": "<relative rule path>",
      "commit": "<resolved commit SHA>",
      "sha256": "<lowercase rule SHA-256>"
    }
  ]
}
```

`generation_id`, the generation-directory name, and `cache/active` must be the same
canonical lowercase UUID. The runtime and platform fields describe the process that
compiled `rules.yac`. Fsync the manifest before publishing its containing generation;
never repair a published generation in place. Consumers reject an absent, incomplete,
or mismatched manifest as degraded rather than treating it as a no-match scan.

## 7. File discovery and filtering

### 7.1 Traversal safety

- Resolve and validate the target directory before scanning.
- Traverse with `os.scandir()` to avoid unnecessary stat calls.
- By default, do not follow file or directory symlinks. Log broken links at debug or
  warning level and continue.
- If `follow_symlinks=true`, track visited directories by `(device, inode)` and skip
  repeats to prevent cycles. Also enforce a conservative maximum traversal depth.
- Yield readable regular files only; skip sockets, devices, FIFOs, and directories.
- Catch `PermissionError`, disappearing-file errors, and per-entry `OSError`; record a
  structured scan error and continue.
- Sort entries for deterministic single-threaded discovery and reports.
- Do not walk the report output path if it is inside the target tree; compare resolved
  paths and exclude the temporary and final report files.

Discovery streams candidates instead of retaining an unbounded directory listing.
A bounded queue applies backpressure between discovery and workers.

### 7.2 Executable and script heuristic

Read at most a small fixed prefix (for example 8 KiB). A file passes `--exec-only` if
any of these checks succeeds:

1. recognized magic bytes:
   - PE: `4d 5a`;
   - ELF: `7f 45 4c 46`;
   - Mach-O 32/64-bit, both endian forms: `fe ed fa ce`, `ce fa ed fe`,
     `fe ed fa cf`, `cf fa ed fe`;
   - optionally include universal/fat Mach-O: `ca fe ba be`, `be ba fe ca`;
2. a first line beginning `#!` names an interpreter after safe lexical parsing;
3. lowercase suffix is one of `.ps1`, `.bat`, `.cmd`, `.sh`, `.py`, `.pl`, `.php`,
   `.rb`, `.js`, or `.vbs`;
4. lowercase suffix is one of `.exe`, `.dll`, `.sys`, `.bin`, `.elf`, `.so`, or
   `.dylib`;
5. when available, libmagic reports a configured executable/script MIME family.

Do not trust extension or MIME as proof of safety; these are selection hints only.
Do not import a script to classify it. Libmagic failure degrades to the other checks
and emits at most one run-level warning to avoid log floods.

## 8. Scanning engine

### 8.1 Cache loading

Before traversal, load and validate the cache manifest, verify the `.yac` digest, and
load it with `yara.load()`. A cache built by an incompatible YARA version or platform
must fail with an actionable instruction to run `update-rules`; scanning must not
silently compile source repositories.

For one thread, scan in the main process. For `--threads N` where `N > 1`, start a
bounded `ProcessPoolExecutor`. Each worker loads the cache once in its initializer.
This avoids assumptions about shared `Rules` thread safety, gives real CPU parallelism,
and works with macOS's spawn process model. Preserve deterministic output by assigning
a discovery sequence number and sorting completed records before report serialization.

### 8.2 Per-file operation

For each selected path:

1. stat the file and retain device, inode, size, and nanosecond mtime;
2. call `Rules.match(filepath=..., timeout=timeout_seconds)`;
3. if there are no matches, return only counters;
4. for matched files, stream the file once to compute SHA-256 and MD5;
5. stat again; if identity, size, or mtime changed, discard the match as inconsistent,
   record `file_changed_during_scan`, and continue;
6. normalize matches into serializable model objects and return them to the parent.

The YARA timeout is the authoritative per-file guard. Classify its timeout exception
separately from I/O and internal errors. A worker crash should fail only its in-flight
file when the pool can be recreated; repeated pool failure becomes a scan-level error.
Set a bounded number of queued futures so millions of paths do not consume unbounded
memory.

Hash only matched files because hashes are only reported for results. MD5 is included
solely as an artifact identifier, never as a security decision. The report and logs
must make this purpose clear.

### 8.3 Match normalization

For every YARA match, retain:

- rule identifier;
- YARA namespace;
- ordered tags;
- all rule metadata, normalized to JSON scalar values;
- when requested, string identifier plus every matched instance's offset and length.

Do not emit matched byte content by default: it can contain secrets and makes reports
unbounded. Sort rule matches by namespace/rule and string instances by offset for
stable output.

## 9. Reporting contract

### 9.1 JSON

Use a versioned superset of the requested schema:

```json
{
  "schema_version": "1.0",
  "scan_metadata": {
    "timestamp": "2026-09-17T12:34:56.000Z",
    "completed_at": "2026-09-17T12:35:01.000Z",
    "target_directory": "/absolute/path/in",
    "cache_generation": "uuid",
    "total_files_discovered": 12,
    "total_files_selected": 8,
    "total_files_scanned": 8,
    "total_files_matched": 1,
    "total_matches": 2,
    "total_errors": 0,
    "filters": {
      "selector": "exec-only",
      "globs": [],
      "regexes": []
    }
  },
  "results": [
    {
      "file_path": "in/suspicious_payload.bin",
      "absolute_path": "/absolute/path/in/suspicious_payload.bin",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "matches": [
        {
          "rule": "SUSP_Recon_Commands",
          "namespace": "signature_base",
          "tags": ["apt", "recon"],
          "meta": {
            "author": "Security Research",
            "description": "Detects anomalous system discovery routines",
            "date": "2025-10-12"
          },
          "strings": [
            {"identifier": "$cmd", "offset": 128, "length": 7}
          ]
        }
      ]
    }
  ],
  "errors": []
}
```

`total_matches` counts matched rules, not files or string occurrences. `strings` is
omitted unless `--include-strings` is active. `errors` contains sanitized path,
operation, category, and message records for recoverable discovery/scan failures; it
must never contain file content. Use UTC RFC 3339 timestamps.

### 9.2 CSV

Emit one row per `(file, matched rule)` pair with columns:

```text
file_path,absolute_path,sha256,md5,rule,namespace,tags,meta,strings
```

Encode `tags`, `meta`, and optional `strings` as compact JSON inside correctly quoted
CSV cells. Write a header even for zero matches. Because CSV cannot naturally carry
scan metadata and errors, also write `<output>.metadata.json` when output is a file;
for stdout CSV, send summary/errors to stderr and document that machine consumers
should prefer JSON when error detail matters.

### 9.3 Output integrity

Write file reports to a temporary sibling, flush and fsync where supported, and use
`os.replace()` only after serialization succeeds. Refuse to overwrite an input target
unless the path was explicitly selected as output before discovery and excluded from
the candidate set. JSON must use UTF-8 and replace invalid path byte sequences safely.

## 10. Error handling and logging

Define domain exceptions for configuration, Git synchronization, rule validation,
cache compatibility, traversal, scan timeout, scan I/O, and reporting. Catch them at
command boundaries and map them to exit codes. Never use a blanket exception handler
inside a worker without returning the exception category and a sanitized message.

Default logs should include timestamp, level, operation, and relevant source/path.
Support structured JSON logs later without coupling report models to logging models.
Avoid logging source credentials, target contents, matched bytes, or full tracebacks at
normal verbosity. `--log-level DEBUG` may include tracebacks but still redacts URLs.

## 11. Security and portability controls

- Never use `shell=True`; never execute files discovered below the target directory.
- Treat repository names, rule metadata, filenames, include paths, and Git output as
  untrusted data.
- Constrain include resolution and quarantine destinations with resolved-path checks.
- Avoid Python module loading based on target suffix or MIME.
- Apply timeouts to Git subprocesses as well as YARA scans.
- Cap diagnostic size, included string instance count per rule, and report string-list
  size; report truncation counts.
- Use POSIX advisory locks where available and a tested cross-platform locking helper
  for macOS. Avoid Linux-only `/proc` behavior.
- Keep libmagic optional and test identical header/extension behavior without it.
- Document that scanning untrusted rules is not a strong sandbox boundary; run rule
  update/scan in an OS sandbox or low-privilege account for hostile repositories.

## 12. Internal interfaces

Keep orchestration thin and make side effects injectable for tests:

```python
class RuleUpdateService:
    def update(self, config: AppConfig, extra_sources: list[RuleSource]) -> UpdateSummary: ...

class FileDiscoverer:
    def iter_files(self, target: Path, options: DiscoveryOptions) -> Iterator[Candidate]: ...

class CandidateFilter:
    def accepts(self, candidate: Candidate) -> FilterDecision: ...

class ScanService:
    def scan(self, candidates: Iterable[Candidate], options: ScanOptions) -> ScanSummary: ...

class ReportWriter(Protocol):
    def write(self, summary: ScanSummary, destination: TextIO) -> None: ...
```

Use typed, immutable dataclasses or Pydantic models between layers. Workers return
plain serializable models and never write reports or logs directly. The parent process
owns aggregation, deterministic ordering, logging, and atomic report publication.

## 13. Test strategy

### 13.1 Unit tests

- configuration precedence, path resolution, unknown keys, and invalid values;
- source-name and namespace normalization collisions;
- Git URL redaction;
- include containment and cycle detection;
- quarantine classification and bounded diagnostics;
- all magic bytes, shebangs, case-normalized extensions, and MIME fallback;
- selector/glob/regex truth table, including repeated filters;
- symlink, broken-link, permission-error, and cycle behavior;
- match normalization for supported yara-python string APIs;
- JSON/CSV escaping, deterministic ordering, counters, and atomic replacement;
- cache manifest digest and compatibility validation.

### 13.2 Integration tests

Create local temporary Git repositories; tests must not depend on the network.

- clone, fast-forward update, pinned ref, URL mismatch, dirty checkout, and failed
  update retaining the previous cache;
- repository containing valid rules, syntax errors, unsupported imports, traversal
  includes, duplicate rule names, and fixed quarantined rules;
- saved `.yac` loads in a fresh spawned process and detects a known fixture;
- scans with 1 and multiple workers yield byte-for-byte equivalent normalized reports;
- timeouts, unreadable/disappearing/changing files, worker failure, and zero matches;
- JSON and CSV CLI golden tests using Typer's test runner.

Use a harmless fixture rule matching fixed text. Never execute fixture artifacts.
Permission tests may need platform guards when run as root.

### 13.3 Performance and acceptance tests

- cache load and command startup target: under one second on a documented reference
  machine for the representative cache;
- scan throughput benchmark across small and large files at 1, 2, 4, and 8 workers;
- bounded-memory test with at least 100,000 discovered paths;
- timeout enforcement test with a deliberately expensive rule;
- update benchmark with unchanged repositories and optional future incremental reuse.

Performance claims must state hardware, OS, YARA version, rule count, and corpus size.

## 14. Delivery phases

### Phase 1: project and contracts

- scaffold package, dependency groups, CLI, typed configuration, domain models, logging,
  and documented example config;
- implement global options and exit-code mapping;
- add unit tests for configuration and CLI validation.

Acceptance: both commands expose stable help, load config with documented precedence,
and fail cleanly before doing work when configuration is invalid.

### Phase 2: rule synchronization and cache

- implement locked Git synchronization, deterministic discovery, safe include resolver,
  individual validation, quarantine staging, namespaces, aggregate compilation,
  manifests, and transactional publication;
- test entirely with local Git fixtures.

Acceptance: one broken rule does not block valid rules; a failed update does not damage
the prior cache; the new cache loads and matches a known sample in a fresh process.

### Phase 3: discovery and filters

- implement safe traversal, symlink policy, primary selectors, magic/shebang/extension
  heuristics, optional libmagic, glob and regex filters, counters, and backpressure.

Acceptance: filter truth-table and filesystem edge-case tests pass on Linux and macOS,
and no candidate is invoked or imported.

### Phase 4: scan engine

- implement cache verification/loading, single-process path, process-pool workers,
  YARA timeouts, matched-file hashing, change detection, and normalized matches.

Acceptance: single- and multi-worker results are equivalent; timeout and per-file I/O
failures do not terminate the overall scan.

### Phase 5: reports and hardening

- implement versioned JSON and flattened CSV, metadata sidecar, atomic writes, stable
  ordering, structured error records, caps, packaging, CI matrix, and benchmarks.

Acceptance: golden reports validate against the documented schema, partial reports are
never published, supported platform CI passes, and performance results are recorded.

## 15. Definition of done

The first release is complete when:

- configured repositories can be cloned and updated reproducibly under `rules/sources`;
- invalid rules are diagnosed and excluded without modifying their checkouts;
- a verified, versioned, last-known-good `.yac` cache is published transactionally;
- target traversal and every filter combination have defined, tested behavior;
- per-file timeout and errors are isolated while scanning continues;
- requested match metadata, both hashes, and optional string offsets are exported;
- JSON and CSV outputs are deterministic and atomically written;
- the tool passes tests on Linux x86_64/arm64 and macOS arm64;
- documentation explicitly confirms passive analysis and no target execution.

## 16. Requirements traceability

| Requirement | Design location |
|---|---|
| Configured repository clone/pull | Sections 4 and 6.1 |
| Individual validation and quarantine | Sections 6.2 and 6.3 |
| Binary `.yac` cache | Sections 6.4 and 6.5 |
| Recursive, safe discovery | Section 7.1 |
| All/exec/glob/regex filtering | Sections 5.3 and 7.2 |
| Concurrent match evaluation | Section 8.1 |
| Per-file timeout and fault isolation | Sections 8.2 and 10 |
| Paths, hashes, rules, tags, metadata | Sections 8.3 and 9 |
| Optional string offsets | Sections 8.3 and 9.1 |
| JSON and CSV | Section 9 |
| Linux/macOS portability | Sections 2, 11, and 13 |
| Passive analysis | Sections 1 and 11 |
| Rule comparison deferred | Section 1 |
