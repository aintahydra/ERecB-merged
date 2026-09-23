# Phased implementation plan

## 1. Delivery principles

Each increment ends in runnable tests and a usable CLI slice. Build deterministic/local behavior before credentials or network access. Provider adapters arrive only after immutable audit storage, run checkpoints, validation, and budget reservations exist.

Testing layers:

- Unit: pure parsers, normalization, script analysis, config, evidence, budget arithmetic.
- Integration: temporary filesystem + real SQLite + fake HTTP/provider transports.
- CLI: Typer runner with stable stdout/stderr/exit codes.
- Credentialed smoke tests: opt-in and excluded from the default suite.

No test executes code from `tests/fixtures` or the supplied `in/` corpus.

## 2. Stage 1 — discovery and storage

Stage 1 needs no API credentials.

### 1.1 Foundation and contracts

Deliver:

- `pyproject.toml` with `src` layout, `ghintel` console entry point, supported Python range, runtime dependencies, and test/lint/type-check extras.
- Package/command scaffold matching the requested structure.
- Pydantic configuration models, version/unknown-key rejection, config-relative paths, and `config.example.toml`.
- Domain enums/DTOs for repository identity, remote role, source kind, run state, language category/method/confidence, and a project card that separates the GitHub owner/account from documented people while representing `not-enriched`/`Unknown` explicitly.
- Rich error boundary and stable exit-code mapping.

Tests:

- minimal/full/unknown/version-invalid TOML;
- missing environment variables are tolerated by Stage 1 and reported only when a provider is invoked;
- example config parses and paths resolve independently of process CWD.

### 1.2 Database and migrations

Deliver:

- connection factory with foreign keys, WAL, busy timeout, row mapping, and transaction helpers;
- checksum-enforced migration runner and packaged `001_initial.sql`;
- repositories for roots, canonical repositories, local copies, remotes, source versions, runs/items, and queries needed by `list`/`show`;
- indexed project-card query keyed by normalized canonical GitHub identity, with no source-blob hydration on the normal path;
- idempotent upserts that update observation timestamps without rewriting immutable history.

Tests:

- empty database bootstrap and repeated migration;
- rollback on migration failure and checksum mismatch rejection;
- foreign-key and uniqueness constraints;
- same observation twice produces no duplicate repository/copy/remote/source version.

### 1.3 Safe discovery and Git config

Deliver:

- `os.scandir` boundary walker with cycle-safe non-following behavior;
- `.git` directory and worktree-file resolution, including `commondir`;
- safe Git-config remote parser with diagnostics and ignored include behavior;
- complete-boundary-first source attribution API.

Fixtures/tests:

- ordinary repo, worktree `.git` file, extracted directory without `.git`, inaccessible/vanishing entry;
- symlink to a repo, symlink cycle, nested repos, `.git` symlink (reject), malformed/oversized `.git` file;
- config comments, quoting, multiple URLs/push URLs, malformed remote, include directive that must not be read;
- parent capture excludes every nested repository document.

### 1.4 URL normalization and deduplication

Deliver:

- parsers for supported HTTP/HTTPS/Git/SSH/SCP-like forms;
- canonical display URL and case-folded identity;
- remote edges, primary-target selection, and per-run canonical dedupe.

Tests:

- SSH and HTTPS forms collapse;
- `.git`, slash, host casing, and owner/repo casing normalize;
- ports, credentials, query/fragment, traversal, non-GitHub hosts, too many segments, malformed SCP forms are handled per contract;
- origin/upstream remain distinct and ambiguous primary selection is diagnosed.

### 1.5 Local sources and Stage 1 CLI

Deliver:

- bounded candidate selection, deterministic ranking, decoding/hashing, translation labels, binary rejection, and nested-boundary pruning;
- `init`, `discover`, database-only `lookup`, `list`, `show`, and `db migrate` commands;
- JSON output contracts and human tables;
- corpus acceptance test that may run against the checked-in `in/` path without modifying it.

Stage 1 gate:

- a discovered URL in HTTP(S), SSH, Git, and SCP-like form resolves to the same project card with no HTTP/provider transport invocation;
- exactly seven current Git repositories are found in the supplied corpus;
- a repeated discovery is idempotent apart from observation timestamps/run rows;
- an added fixture with SSH/HTTPS duplicate copies yields one canonical identity and two local copies;
- the nested-boundary fixture never attributes child documents to the parent;
- extracted archives without Git metadata are absent;
- process-spawn/import audit proves no project code was executed.

## 3. Stage 2 — GitHub, deterministic inference, and Gemini

Do not start credentialed Gemini work until the previously exposed key has been revoked and a replacement is installed only as `GEMINI_API_KEY`. Do not migrate the root token-like file or `.env` contents into config/database/logs.

### 2.1 Run state machine and duplicate policy

Deliver first:

- run/item state tables and compare-and-swap checkpoint transitions;
- target resolution and one item per canonical repository;
- reuse/refresh decision engine and versioned input fingerprints;
- interruption handling and `resume` skeleton using fake stages.

Tests:

- duplicate clones produce one item;
- interrupted step resumes once without duplicate rows;
- changed inputs invalidate only dependent checkpoints;
- reuse with a current finding cannot enter a network/provider adapter.

### 2.2 GitHub client, cache, and rate limits

Deliver:

- shared async `httpx` client and fakeable transport;
- repository metadata, preferred README, and conditional owner-profile retrieval;
- ETag/Last-Modified cache with stable representation keys;
- response-header-driven limiter/retry coordinator;
- `fetch` and GitHub portion of `doctor`.

Tests with scripted transports:

- `200 -> 304` retains body and updates validation metadata;
- redirects, transient 5xx, `retry-after`, primary reset, secondary-limit fallback, exhausted retries;
- authenticated/private-style 404 diagnostic;
- tokens/authorization never appear in cache/errors;
- offline fetch/scan invokes the HTTP transport zero times.

### 2.2.1 Implemented increment (2026-09-16)

Implemented and tested: persistent SQLite HTTP cache (including ETag revalidation), per-canonical-repository fetch runs/items, GitHub repository snapshot plus bounded README capture, offline-safe doctor, and fetch. A GitHub-controlled repository description is promoted as a deterministic project-card purpose only when no richer current finding exists; it never identifies the owner as the developer. The scan and resume commands are implemented. `scan --target-dir` validates and atomically persists a normalized absolute input path before discovery. Scan discovers then conditionally fetches, and only enriches when explicitly requested and not offline; resume retains completed endpoint checkpoints and processes only incomplete work. The enrich command implements its readiness gate and refuses before any provider request until Gemini credential replacement and operator pricing are configured.

Implemented and tested: bounded original-source selection, untrusted evidence delimiters, strict provider-output audit records, exact quote and source membership enforcement, documented-person attribution, atomic finding promotion, and cautious persisted language inference. Invalid output remains audit-only and cannot change the current project card.

Implemented and tested: Gemini preflight refusal, fake-provider enrichment orchestration, conservative request/token/output/cost reservations, budget ledger audit rows, actual-usage settlement, and validated-response cache reuse.

Implemented and tested: GitHub quota detection driven by retry and reset headers. Primary/secondary exhaustion commits the last successful endpoint, interrupts the run, exits `7`, and reports an exact resume command without sleeping until reset. Transient `5xx` responses retain bounded retries, and repository progress is visible on stderr.

### 2.3 Deterministic metadata, text cleanup, and language inference

Deliver:

- safe extraction of GitHub-owned identity/stars/license/fork fields;
- source analysis text and raw-offset/noise map;
- Unicode script counter and threshold policy;
- internal detector protocol plus a short dependency spike selecting an offline implementation using fixture accuracy, wheel/platform support, model size, and maintenance as criteria;
- explicit language mapping, subject gate, confidence/rationale, and persisted `language_inferences`.

Required fixtures:

- Chinese Han-only; Japanese Kana+Han; Korean Hangul; Arabic; Hebrew; Hindi; Russian;
- Ukrainian/Bulgarian Cyrillic and Polish/Czech Latin -> `Slavic-other`;
- Persian/Urdu Arabic script, Spanish/French, and all other unsupported detections -> `Unknown`;
- genuine English -> `English`;
- mixed/translated README sets and Korean translation of an English-origin project;
- language only inside code blocks; below-minimum text;
- organization owner; unrelated conflicting authors.

Assertions cover script counts, detector code, method, confidence, subject, rationale, and exclusion/down-weighting—not only the final enum.

### 2.4 Evidence model and deterministic finding versions

Deliver:
- validated documented author/maintainer extraction and project-card population, preserving the distinction between a GitHub owner account and a documented developer;

- immutable people/attribution, findings, language inference, and evidence persistence;
- exact quote/source-membership validator;
- deterministic findings when Gemini is disabled/unnecessary;
- promotion transaction/current pointer.

Tests:
- an organization-owned project without attributable people displays its organization owner and “documented developer: Unknown”; a user-owned project does not claim its owner is the developer without evidence;

- fabricated, normalized-but-not-exact, wrong-source, code-only, and overlong quotes fail/downgrade;
- invalid candidates leave the old current pointer untouched;
- repeated identical deterministic inputs do not create duplicate findings.

### 2.5 Provider abstraction, budgets, and cache

Deliver before real Gemini calls:

- provider protocol and fake provider;
- source-set hashing and validated-response cache;
- exact budget arithmetic, worst-case reservation, actual-use commit/release, repository cap;
- preflight refusal for zero/missing rates, source upload disabled, missing key, or exhausted limits;
- concurrency race tests proving the last allowed reservation wins and no ceiling is crossed.

Tests:

- every individual limit blocks before dispatch;
- retries consume request reservations;
- cached responses consume no provider request/tokens/cost but still count the repository outcome consistently;
- crash between reservation and response is reconciled on resume without permitting overspend (stale reservations remain conservatively charged until explicitly reconciled).

### 2.6 Gemini adapter and post-validation

Deliver:

- versioned system instruction and Pydantic response schema;
- bounded, delimited one-repository request with tools/function calling absent;
- `google-genai` async adapter, token count, configured timeout/retry/output cap, raw response and usage capture;
- full validation/downgrade/promotion pipeline;
- `enrich`, complete `scan`, `resume`, and Gemini `doctor`.

Tests use the fake provider for:

- valid structured result with exact evidence;
- invalid JSON/category/schema, refusal/truncation, unknown source ID, missing/fabricated quote, conflicting deterministic language;
- prompt-injection text asking for tools/files/network has no effect on request configuration;
- identical cache key reuses a validated response; prompt/schema/source changes miss cache;
- raw invalid output is retained for audit but never current.

Optional credentialed smoke test lists the configured model, counts a fixed prompt, and enriches a tiny synthetic repository under a very small explicit budget. It must be opt-in.

Stage 2 gate:

- offline runs make zero HTTP/provider calls;
- reuse with current findings makes zero GitHub/Gemini calls;
- refresh sends conditional requests and creates a version only for changed inputs/provenance;
- invalid Gemini output never changes current findings;
- Ctrl-C followed by resume finishes without duplicated source, provider, evidence, or finding rows;
- concurrent workers cannot exceed request, repository, token, or USD ceilings;
- `doctor` fails clearly for an unavailable configured model or unpriced Gemini setup.

## 4. Stage 3 — querying and portability

### 3.0 Implemented increment (2026-09-16)

Implemented and tested: `003_search.sql` FTS5 index, deterministic rebuild/per-card refresh, current-card FTS query validation, and the local `search` CLI. The index intentionally excludes captured source-document blobs. Also implemented: typed append-only corrections, effective-card and FTS overlays, and the local `correct` CLI. Also implemented: versioned JSON, relational CSV plus checksum manifest exports, and the local `export` CLI; source, provider, and HTTP cache blobs are excluded. Also implemented: logical root listing, validated dry-run remapping with append-only events, and the `roots list`/`roots remap` CLI. Also implemented: online SQLite backup snapshots with integrity and checksum-manifest verification, and `db snapshot`/`db verify`. Stage 2 metadata now also stores deterministic stars, SPDX license, fork status, and parent URL for project cards.


### 3.1 Search

Deliver `003_search.sql`, FTS synchronization/rebuild, `search`, filters, snippets, and deterministic tie-breaking. Test Unicode queries, corrected values, deleted/missing local copies, rebuild equivalence, and environments lacking FTS5.

### 3.2 Corrections

Deliver allowlisted typed field corrections, supersession, effective-view overlay, and correction display. Test that refresh/new findings retain effective corrections, audit order is stable, invalid field/type changes fail, and raw history is unchanged.

### 3.3 Exports

Deliver versioned JSON and relational CSV/manifest exports from a consistent read transaction. Test round-trippable IDs, Unicode/newlines, nulls, stable ordering, formula escaping, no secrets/raw auth headers, and deterministic output except declared export timestamps.

### 3.4 Root remapping

Deliver root list/remap with dry-run collision/path validation and append-only events. Integration test copies the fixture tree to a new absolute location, remaps the logical root, rediscovers, and proves existing local-copy identities/source history continue rather than duplicate.

### 3.5 Online snapshots

Deliver SQLite backup-based snapshot, integrity check, manifest/schema/app version, SHA-256 verification, and atomic publication. Test while another connection writes, destination collision behavior, injected backup/check failure, tampered checksum, and restore/open/read.

Stage 3 gate:

- search returns current effective values;
- manual corrections survive refresh and remain auditable;
- JSON/CSV exports preserve relationships and omit secrets;
- a relocated database remaps its root and continues scanning without duplicate copies;
- a snapshot made from a live database passes `PRAGMA integrity_check` and manifest verification.

## 5. Cross-cutting quality gates

Run on every stage:

- formatting, linting, static type checking, unit/integration/CLI tests;
- migration-from-empty and repeated-command idempotence tests;
- deterministic tests with frozen clocks/random jitter and no real network by default;
- dependency vulnerability/license review and pinned lock/constraints strategy appropriate to the chosen build workflow;
- Windows path-normalization unit coverage even if the supplied acceptance corpus is Linux;
- property/fuzz tests for remote URLs, Git-config text, Markdown cleanup, JSON response validation, and budget arithmetic;
- performance benchmark on the supplied corpus: bounded memory, no whole-tree file list retained, and per-document/per-repository caps enforced.

## 6. Recommended implementation order and review points

The shortest safe critical path is:

1. Config/domain contracts.
2. Migration/persistence core.
3. Discovery -> Git config -> URL identity.
4. Source capture and Stage 1 commands/gate.
5. Run/checkpoint engine.
6. GitHub cache/rate handling.
7. Language detector spike and deterministic evidence.
8. Findings/evidence promotion.
9. Budget reservation and fake provider.
10. Gemini adapter and Stage 2 commands/gate.
11. FTS, corrections, exports, remap, snapshots and Stage 3 gate.

Review points that should block dependent work:

- approve `001_initial.sql` and effective-view semantics before writing provider persistence;
- approve the offline detector from fixture results before locking dependencies;
- revoke/replace the exposed Gemini credential before any credentialed test;
- confirm operator prices and model availability through `doctor` before the first enrichment;
- freeze prompt/schema/validation version 1 together so cache semantics are reproducible.
