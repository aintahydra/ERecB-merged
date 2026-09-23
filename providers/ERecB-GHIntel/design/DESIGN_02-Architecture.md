# Architecture

## 1. Scope and invariants

`ghintel` inventories only directories that contain a real `.git` directory or a worktree-style `.git` file. Extracted source trees without Git metadata are out of scope. The system reads repository metadata and selected documentation; it never imports, builds, shells into, hooks, or otherwise executes project code.

Hard invariants:

- Never follow a filesystem symlink during discovery or source capture. Version 1 rejects `scan.follow_symlinks = true`; retaining the setting in the schema makes the security decision explicit and leaves room for a later, separately reviewed feature.
- Never read through a Git config `include`/`includeIf`, run credential helpers, expand remote helpers, or invoke `git`. Such directives produce diagnostics rather than filesystem or process activity.
- Never use an `upstream` or arbitrary remote as an alias for `origin`.
- Never make HTTP calls in offline mode.
- Never promote unvalidated provider output.
- Never store API keys or authorization headers.
- Never overwrite evidence or corrections in place.

Non-goals for the initial three stages include cloning repositories, analyzing source code semantics, identifying a person's nationality, crawling arbitrary URLs found in documents, or supporting non-GitHub forges.

## 2. Component boundaries

The requested package layout maps to these responsibilities:

| Module | Responsibility |
| --- | --- |
| `cli.py`, `commands/*` | Typer wiring, Rich presentation, command orchestration, stable exit codes. No business rules. |
| `config.py` | TOML load, Pydantic validation, path resolution, environment-secret lookup, version compatibility. |
| `discovery.py` | Non-following tree walk, repository-boundary detection, local-copy observations. |
| `gitconfig.py` | Safe parser for the subset of Git config needed for remotes and worktree common-dir resolution. |
| `github_urls.py` | Parse supported remote forms and produce normalized identities/canonical URLs. |
| `sources.py` | Candidate selection, bounded reads, decoding, translation labeling, noise-reduced analysis text, hashes. |
| `languages.py` | Script counts, detector adapter, evidence combination, category/confidence policy. |
| `models.py` | Domain enums and Pydantic DTO/provider response models. It must not contain SQL persistence logic. |
| `database.py`, `migrations.py` | Connections, transactions, repositories, current-view queries, ordered migration runner. |
| `github_client.py` | Async read-only REST calls, stable headers, response parsing; delegates caching and throttling. |
| `cache.py`, `rate_limits.py` | HTTP cache/validators and shared response-header-driven retry coordination. |
| `providers/base.py` | Enrichment request/response protocol independent of Gemini. |
| `providers/gemini.py` | `google-genai` adapter, schema-constrained request, timeout/retry, usage capture. |
| `evidence.py` | Prompt-source assembly and post-response category, ownership, and exact-quote validation. |
| `pipeline.py` | Run/item state machine, duplicate policy, idempotence, budgets, checkpoints, promotion transaction. |

Dependencies point inward: commands -> pipeline/services -> domain models and persistence ports -> external adapters. `languages.py`, URL parsing, discovery, and evidence validation remain testable without a database or network.

`lookup` uses a read-only query service over the effective current view. It is deliberately outside the pipeline: URL normalization and the database lookup are sufficient, so a lookup cannot accidentally spend a GitHub request or Gemini budget.

## 2.1 Investigator project card

The user-facing database record is a compact **project card**, not an unqualified aggregation of model output. A card contains:

- canonical repository URL and identity, plus known local-copy locations;
- a concise purpose, tool types, main capabilities, and intended uses;
- **GitHub owner/account**: login, display name, and account type from GitHub metadata;
- **documented people**: each attributable author/maintainer name, role, and supporting source quote;
- freshness/provenance: current finding version, capture time, source count, and whether the purpose is deterministic-only, validated Gemini enrichment, corrected, or not yet available;
- an explicit `Unknown`, `not enriched`, or `not in database` value rather than invented developer identities or summaries.

The owner is an account relationship, not proof of who developed the project. For an organization-owned repository, the card says “GitHub owner: organization …” and lists a developer only when an author/maintainer is documented. A user-owned repository still labels that person as the owner unless the evidence independently supports an author/maintainer role.

`lookup URL` parses every supported remote address through the same normalizer used at discovery, then performs one indexed lookup by `identity_key`. It accepts no fuzzy matching and never initiates HTTP/Gemini work. A separate `search` command serves ambiguous name/topic queries; `show` is the detailed version once an identity is known.

## 3. End-to-end data flow

```text
configured root
  -> boundary discovery
  -> safe Git-config parse
  -> remote normalization
  -> canonical repository + local-copy observations
  -> bounded local source versions
  -> one run item per canonical primary repository
       -> duplicate-policy decision
       -> GitHub metadata/README snapshot (optional, conditional)
       -> deterministic metadata and language evidence
       -> Gemini request (optional, budgeted, cached)
       -> evidence and schema validation
       -> immutable finding version
       -> transactional current-finding promotion
  -> effective view = current finding overlaid by latest corrections
```

The pipeline is repository-scoped: a failure commits its audit trail and item checkpoint without rolling back completed repositories. A repository's promotion, however, is atomic.

## 4. Discovery and identity

### 4.1 Boundary walk

Use `os.scandir()` and `DirEntry` metadata with `follow_symlinks=False`. Do not use a broad glob that resolves symlinks.

1. Start at the resolved configured input root and record its logical root ID.
2. For each directory entry, skip symlinks and the `.git` administrative entry itself.
3. A directory is a repository boundary when its immediate child `.git` is either a directory or a regular file whose bounded first line is `gitdir: <path>`.
4. Validate a worktree target lexically, resolve it without following arbitrary content, and locate shared configuration via its bounded `commondir` file when present. Only Git administrative config files required for that worktree are read.
5. Record the boundary, then continue below it to find nested repositories. Discovery and attribution are intentionally separate.
6. Mark formerly observed local copies as missing only after a complete successful walk; an interrupted walk must not create false removals.

Source capture happens after the complete boundary set is known. For repository `R`, descend from `R` without symlinks and prune `.git` plus every descendant repository root. This guarantees that nested documents belong only to the nested repository.

Filesystem errors are per-path diagnostics. A vanished path can be skipped; inability to inspect the configured root fails the run.

### 4.2 Git configuration

The parser supports sections, quoted subsection names, comments, line continuations, case-insensitive keys, multiple values, and `[remote "name"] url`/`pushurl`. It retains every raw remote occurrence for audit, with fetch URL preferred for identity. Malformed entries are diagnosed and skipped independently.

`include.path`, `includeIf`, URL rewrite rules, credential sections, hooks, filters, and remote helpers are not evaluated. The scanner is an inventory reader, not a complete Git behavior emulator.

### 4.3 Supported GitHub URLs

Accept:

- `https://github.com/owner/repository[.git]`
- `http://github.com/owner/repository[.git]`
- `git://github.com/owner/repository[.git]`
- `ssh://[git@]github.com[:port]/owner/repository[.git]` (default/explicit SSH port is not part of identity)
- SCP-like `git@github.com:owner/repository[.git]`

Reject non-GitHub hosts, credentials in HTTP URLs, query/fragment components, missing/extra path segments, dot segments, control characters, empty owner/name, and ambiguous local paths. Normalize the host to `github.com`, remove a terminal `.git` and slash, retain a display owner/name, and derive the unique identity key by Unicode case-folding `github.com/owner/repository`. The stable canonical URL is `https://github.com/<owner>/<repository>`.

GitHub owner/repository names are treated as URL identifiers, not filesystem paths. Database uniqueness uses the case-folded key; a later GitHub response may update display casing without changing identity.

### 4.4 Remote roles and primary targets

Every valid GitHub remote gets its own canonical repository record and a remote edge from the local copy:

- remote name exactly `origin` (case-insensitive) -> role `origin`;
- name `upstream` -> role `upstream`;
- all others -> role `other` while preserving their actual name.

The local copy's primary repository is its single valid GitHub `origin`. If there is no origin and exactly one GitHub remote exists, that identity may be selected with reason `sole-remote`. Multiple origins or multiple non-origin choices remain unresolved and are shown as diagnostics; they are not guessed.

Only primary identities become scan work items by default. An upstream identity is related data, not an alias, and is processed only if it is primary for another copy or explicitly targeted by a future command. Duplicate local copies converge on one canonical work item while all copy and remote observations remain distinct.

## 5. Duplicate policies and fingerprints

Discovery and local-copy persistence always run first.

### `reuse`

- Recapture bounded local documents so inventory and source history stay current.
- If the canonical repository already has a current valid finding, reuse it and make no GitHub or Gemini call.
- If it has no finding, proceed through available deterministic stages and allowed providers.

### `refresh`

- Recapture local sources.
- Request GitHub endpoint representations with saved `ETag`/`Last-Modified` validators even when the TTL is fresh when the operator explicitly asks for refresh.
- Build an input fingerprint from canonical repository identity, deterministic extractor version, ordered selected source content hashes and roles, normalized GitHub metadata hash, language-policy version, prompt version, and schema version.
- If the fingerprint is unchanged, retain the current finding. `force_llm_on_unchanged` may perform/reuse an LLM enrichment and create a new finding only when the resulting validated payload or audit provenance differs; it must not manufacture an identical version.
- If inputs changed, run deterministic extraction, optionally enrich, validate, and create a new finding.

In both modes, a run has a unique `(run_id, repository_id)` item, preventing duplicate clones from multiplying network/model work.

## 6. Sources and evidence

### 6.1 Candidate selection

Use a narrow allowlist rather than indexing arbitrary files:

1. Root preferred README: exact `README`/`README.*` candidates, with the GitHub API's preferred README and common Markdown/plain-text forms ranked first.
2. Root `AUTHORS*`, `MAINTAINERS*`, `CONTRIBUTORS*`.
3. Bounded package descriptions from declarative manifests such as `pyproject.toml`, `setup.cfg`, `package.json`, or language package metadata. Parse as data; never import `setup.py` or execute a package manager.
4. GitHub repository description, preferred README, and attributable owner profile text.

`README-xx`, `README_xx`, locale directories, and GitHub translation directories are labeled `translation`. They may describe translation availability and help summarize a tool, but are excluded from original-language dominance unless separate attributable evidence establishes authorship.

Apply `max_document_bytes` to each source and `max_source_bytes_per_repo` to the deterministic priority order. Read bytes once, hash the complete captured bytes, decode with BOM/UTF-8 detection and replacement diagnostics, and store the exact decoded text used for quote checking. Binary/NUL-heavy files are rejected. Truncation is recorded and never hidden.

### 6.2 Noise reduction

Generate a derived analysis view without changing the stored raw text. Remove/down-weight fenced and indented code, inline code, HTML tags, badges/images, URLs, dependency/version tables, generated markers, copied quotations, and repeated boilerplate. Preserve source IDs and enough mapping to locate evidence in the raw source. Summaries may use cleaned text; evidence quotes must match raw stored text exactly.

### 6.3 Evidence records

Each claim records field path, immutable source-version ID, exact quote, offsets when uniquely locatable, and validation status. A quote must:

- reference a source included in that exact request;
- occur byte-for-byte in its stored decoded text;
- be non-empty and within a configured length;
- not rely solely on a code/noise span for a biographical language claim.

Multiple occurrences are allowed but reported as non-unique; store the first deterministic offset plus occurrence count. Fabricated or cross-request evidence invalidates the affected inference; structural/provider failures invalidate the entire enrichment candidate.

Developer-role claims follow the same evidence discipline. A Gemini-produced person/name is stored only when it cites a request source containing the exact attribution. The application records the role as `author`, `maintainer`, `contributor`, or `other-documented-role`; it does not turn a repository-owner profile, a commit-looking string, or a model guess into a developer identity.

## 7. Mother-tongue inference

The exact output enum is `Chinese`, `Russian`, `Slavic-other`, `Korean`, `Japanese`, `Arabic`, `Hebrew`, `Hindi`, `English`, or `Unknown`. The field name is always `inferred_mother_tongue`.

### 7.1 Subject gate

Resolve a subject before classifying language. A documented individual maintainer/author may be a subject. An organization owner produces `Unknown`. Apparently unrelated multiple authors produce `Unknown` unless evidence explicitly attributes a statement to one named person; the inference then references that person rather than the repository as a whole.

### 7.2 Deterministic pass

On cleaned original-source text, count Unicode letters by script with `unicodedata` and retain per-source and aggregate counts. Apply both `minimum_letters` and `minimum_script_ratio`; a threshold failure is inconclusive, not English.

| Signal | Candidate/policy |
| --- | --- |
| Hangul | Korean |
| Hiragana or Katakana | Japanese; Kana disambiguates accompanying Han |
| Hebrew | Hebrew |
| Arabic | candidate only; detector must distinguish `ar` from Persian/Urdu/other |
| Devanagari | candidate only; detector must confirm `hi` |
| Cyrillic | candidate only; detector must distinguish `ru`, mapped Slavic codes, and unsupported languages |
| Han without Kana | Chinese candidate; confirm with consistent sources/detector |
| Predominantly Latin | detector required; Latin script alone is never English |

The offline detector sits behind a `LanguageDetector` protocol returning ranked BCP-47/ISO codes and scores. Select the concrete dependency in a Stage 2 spike against all fixtures, favoring deterministic offline operation and maintainable wheels. Mapping is explicit: `zh`, `ru`, `ko`, `ja`, `ar`, `he`, `hi`, and `en` map directly; `uk`, `be`, `bg`, `mk`, `sr`, `pl`, `cs`, `sk`, `sl`, `hr`, and `bs` map to `Slavic-other`; everything else maps to `Unknown`. Never map an unsupported detector result to English.

Strong, consistent evidence across at least two original source blocks can yield Medium confidence. An explicit attributable statement yields High. Limited deterministic text or Gemini-only support is Low. Organizational, conflicting, unsupported, or insufficient evidence is `Unknown` with Unknown confidence. Store the method as exactly `explicit-statement`, `unicode-script`, `language-detector`, `gemini`, or `combined`.

Gemini is a fallback for unresolved ambiguity, not a way to override an organization/multi-author hard stop. A Gemini claim without valid evidence remains `Unknown`.

## 8. GitHub integration

Use one shared `httpx.AsyncClient` with a descriptive `User-Agent`, GitHub API version header, stable `Accept` values, bounded timeouts, redirects, and a concurrency limiter. Only read repository metadata, preferred README content, and an owner profile when required for attribution. License identifiers, stars, fork relationships, canonical URLs, and owner type come only from deterministic GitHub fields.

Cache keys include method, normalized endpoint URL/query, API version, and representation headers; never include the token value. Store response body, status, `ETag`, `Last-Modified`, fetch/expiry times, and non-secret relevant headers. On refresh send `If-None-Match` (preferred) or `If-Modified-Since`; a `304` reuses the body and updates validation time.

The rate coordinator observes `retry-after` first, then `x-ratelimit-remaining`/`x-ratelimit-reset`. Primary or secondary quota exhaustion never causes an unannounced sleep until the next quota window: the final successful endpoint response is committed, the next network request is withheld, the run is marked interrupted, and the CLI exits `7` with the reset time and exact resume command. Transient `5xx` failures retain bounded exponential backoff. Authentication-sensitive `404` is preserved as a diagnostic rather than treated as proof that a private repository does not exist.

Offline mode constructs a transport that rejects all outbound calls and uses only stored cache/snapshots. Tests assert zero transport invocations.

## 9. Gemini enrichment

### 9.1 Request construction

One repository per request. The provider receives only bounded selected source blocks and deterministic metadata. It uses:

- a fixed, versioned system instruction;
- explicit delimiters and source IDs marking repository text as untrusted evidence;
- no tools, function declarations, browsing, URL context, file search, or automatic function calling;
- low temperature when the selected model supports it;
- a Pydantic-generated JSON Schema with `extra='forbid'` and literal enums;
- a configured maximum output-token value;
- async timeout and bounded retry behavior.

The schema contains summary, tool types, capabilities, intended uses, searchable categories, documented people/statements, and the language object described in the requirements. The prompt must state that source content cannot alter instructions or request actions.

As of the design date, the official SDK supports async clients, model listing, token counting, Pydantic/JSON Schema structured output, and response usage metadata. Keep those calls inside `providers/gemini.py` so SDK/API evolution affects one adapter. `doctor` lists models with the configured credential, matches the normalized configured ID and generation capability, and runs a fixed `count_tokens` probe; it does not make a paid generation merely to diagnose availability.

### 9.2 Validation and promotion

Persist the raw response and usage metadata before interpreting it. Then:

1. Parse and validate with Pydantic.
2. Reject unknown keys/categories and invalid cardinalities/lengths.
3. Verify every evidence source belonged to the request.
4. Verify every quote against that immutable source.
5. Reconcile language claims with subject gates and deterministic evidence.
6. Downgrade an unsupported/conflicting language claim to `Unknown`, recording the reason.
7. Materialize a candidate finding and its evidence in one transaction.
8. Move the repository's current pointer only when every required validation passes.

Provider errors, refusal, truncation, invalid JSON, schema failure, or fabricated evidence remain visible failed attempts. Model output never supplies a URL to fetch, a filename to open, or an action to execute.

### 9.3 Cache and budgets

The validated-response cache key is the canonical hash of:

`provider + model + prompt_version + response_schema_version + source_set_hash`

`source_set_hash` is over ordered source role, immutable content hash, and deterministic metadata supplied to the request. Cache entries retain validation version; changing validation policy can revalidate raw output without a paid call, but only currently valid entries are reusable.

Before dispatch, count tokens through Gemini when available or use a deliberately conservative local upper bound. In a database transaction, reserve one request, counted input tokens, configured maximum output tokens, maximum enriched-repository count, and the resulting worst-case cost. Cost uses operator-supplied per-model input/output rates; zero/missing rates are a sentinel that blocks Gemini. A concurrency-safe reservation prevents workers from collectively crossing a limit. After response, replace the reservation with actual usage and cost; failed calls still consume their actual request/usage. Retries require their own request reservation.

No request begins unless all hard limits remain satisfied. Budget exhaustion is a clean resumable stop, not an error that discards completed work.

## 10. Resumability and consistency

Run items move through durable stage checkpoints, with `failed`, `blocked_budget`, and `skipped_reuse` terminal/resumable states. During GitHub fetch, `pending -> fetched` commits repository metadata, `fetched -> sources_captured` records the README phase, and the owner-profile phase finishes the item as `complete`. A quota interruption retains the latest state so resume does not repeat completed endpoints. Enrichment continues through its deterministic, enriched, validated, and promoted checkpoints. Each step records its input hash and output IDs; a step is reused only while its inputs still match.

Use WAL mode, foreign keys, a busy timeout, short write transactions, and UTC timestamps. Network/model calls happen outside write transactions. Claiming an item and reserving budget are compare-and-swap transactions so concurrent resumes cannot duplicate work.

## 11. Security and privacy

- Secrets are read only from configured environment-variable names and are redacted in errors. Config values may name variables but may not contain literal keys.
- Candidate source selection excludes hidden root files, Git internals, arbitrary credential files, binaries, and the workspace's `.env`/token-like files.
- Provider upload is opt-in through `allow_source_upload`; the CLI prints the number of repositories/bytes selected and supports a dry run. Inline text remains a source upload in the privacy sense and is subject to the flag.
- SQL is parameterized; correction field paths come from an allowlist.
- Export and Rich output escape control characters and spreadsheet-dangerous CSV cells.
- Database/snapshot creation requests user-only permissions where the platform supports them.
- Logs contain IDs, hashes, counts, and sanitized errors, not credentials or full raw source/model payloads by default.

## 12. Portability and snapshots

Store one absolute path per logical root and all local-copy/source locators relative to it. `roots remap` validates the new directory and records an append-only mapping event; source history is unchanged. Reject relative paths that escape the root after normalization.

Create online snapshots with `sqlite3.Connection.backup()` into a temporary file in the destination directory. Run `PRAGMA integrity_check` on the completed copy, record schema/application versions and a SHA-256 sidecar/manifest, then atomically rename. A failed check leaves the current database untouched and removes or quarantines only the temporary snapshot.
