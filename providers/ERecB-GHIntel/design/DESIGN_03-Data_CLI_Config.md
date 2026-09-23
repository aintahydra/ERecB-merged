# Data, CLI, and configuration contracts

## 1. Persistence model

The database is an audit log with small mutable pointers. Content-bearing rows are immutable. Foreign keys are enabled on every connection; timestamps are UTC ISO-8601 strings; JSON text is emitted in canonical key order before hashing.

### 1.1 Discovery and identity

| Table | Essential columns and constraints |
| --- | --- |
| `schema_migrations` | `version PK`, `name`, `checksum`, `applied_at`; an applied checksum mismatch is fatal. |
| `scan_roots` | `id PK`, `name UNIQUE`, `absolute_path`, `path_key`, created/updated timestamps. Only the mapping is mutable. |
| `root_mapping_events` | append-only old/new path, timestamp, reason. |
| `repositories` | `id PK`, `host`, display `owner`, `name`, `identity_key UNIQUE`, `canonical_url`, optional GitHub node ID, timestamps. `identity_key` has a unique index used directly by offline URL lookup. |
| `local_copies` | `id PK`, `root_id FK`, normalized `relative_path`, `path_key`, Git kind, `primary_repository_id FK NULL`, selection reason, first/last seen, missing timestamp; unique `(root_id, path_key)`. |
| `remotes` | `id PK`, `local_copy_id FK`, remote name, role enum, direction (`fetch`/`push`), raw URL, normalized `repository_id FK NULL`, parse status/error; preserve repeated values with an ordinal. |
| `discovery_runs` | run metadata, root, status, counters, diagnostic summary. |
| `discovery_observations` | unique `(discovery_run_id, local_copy_id)`, config hash and observed metadata. |

`path_key` is platform-aware normalization used only for uniqueness; preserve original relative spelling for display. The canonical repository is never inferred from the directory name.

### 1.2 Sources and GitHub

| Table | Essential columns and constraints |
| --- | --- |
| `source_documents` | stable logical source: repository, optional local copy, origin (`local`/`github`), kind, locator, translation flag/language hint, priority; unique logical locator. |
| `source_versions` | immutable `id` used as external `source_id`, document FK, content SHA-256, exact decoded text, bytes, encoding, truncation/noise metadata JSON, capture timestamp; dedupe identical document/hash. |
| `github_snapshots` | repository FK, deterministic metadata fields plus raw JSON, normalized hash, captured timestamp; immutable. Extract and retain owner login/display name/type separately for the project card. |
| `http_cache_entries` | request key UNIQUE, status/body, `etag`, `last_modified`, fetched/validated/expires timestamps, safe headers JSON. |

Raw source text remains available for evidence audit. If database size later becomes material, compression belongs behind the persistence layer without changing source IDs or hashes.

### 1.3 Runs, provider calls, and budgets

| Table | Essential columns and constraints |
| --- | --- |
| `runs` | `id`, kind, configuration hash/snapshot with secret values absent, duplicate policy, status, start/end timestamps. |
| `run_items` | `(run_id, repository_id) UNIQUE`, state, attempt count, input hash, checkpoint/output IDs, error code/message, lease owner/expiry. |
| `budget_ledger` | append-only reservation/commit/release entries keyed to run/item/provider attempt; requests, repositories, input/output tokens, USD as decimal text. |
| `provider_attempts` | provider/model/versions/source-set hash, request hash, state, raw response, parsed JSON, validation errors, token fields, cost, timestamps. |
| `provider_cache` | composite cache dimensions UNIQUE, valid attempt FK, validation-policy version. Only validated attempts qualify. |

Use integer micro-dollars internally (or exact `Decimal` serialized as text), never binary floating point, for hard budget comparisons.

### 1.4 Findings, people, language, and evidence

| Table | Essential columns and constraints |
| --- | --- |
| `people` | stable attributable subject with normalized display name and optional GitHub login; do not invent identity merges. |
| `repository_people` | repository/person/role (`author`, `maintainer`, `contributor`, `other-documented-role`), source evidence, attribution confidence. A row proves only its documented role, never ownership by implication. |
| `findings` | repository FK, monotonic version, input fingerprint, optional GitHub snapshot/provider attempt, summary and structured JSON fields, provenance/status, created timestamp; unique repository/version and repository/fingerprint/provenance key. |
| `repository_current_findings` | `repository_id PK -> finding_id UNIQUE`; updated only by promotion transaction. |
| `language_inferences` | exactly the required fields: `finding_id`, `subject_person_id NULL`, category, method, confidence, detector language, `script_counts_json`, rationale, created timestamp. Category/method/confidence have checks. |
| `finding_evidence` | finding, field path, immutable source-version ID, exact quote, offsets, occurrence count, validation state; unique deterministic tuple. |
| `corrections` | append-only repository/finding scope, allowlisted field path, replacement JSON, rationale, created timestamp, optional supersedes correction. |

Only one language inference is attached to a finding in version 1. `Unknown` may have no subject. Confidence uses `High`, `Medium`, `Low`, or `Unknown`; it is not a free-form probability.

The effective view selects the current finding and overlays the latest non-superseded correction for each field. Refresh creates findings but never deletes corrections, so corrections survive refresh by design. `show --raw` can display the underlying finding alongside the effective value and correction provenance.

Define a read-only `repository_project_cards` SQL view (or equivalent parameterized query) joining the canonical repository, latest relevant GitHub snapshot, current effective finding, documented people, and source/evidence counts. It returns at most one card per repository without reading source blobs: `identity_key`, canonical URL, purpose, tool types, capabilities, intended uses, owner login/name/type, documented people JSON, finding ID/version/provenance, timestamps, correction flag, and `information_status` (`ready`, `deterministic-only`, `not-enriched`, `not-found`). Index joins by repository/finding/person IDs. `lookup` queries this view by normalized `identity_key`, making the common URL-to-answer path one indexed SQLite read.

### 1.5 Search and exports

Migration `002_search.sql` creates an external-content FTS5 index over effective repository name/URL, summary, tool types, capabilities, intended uses, searchable categories, GitHub owner display/login, and documented people names. Triggers or an explicit rebuild routine keep the index consistent; migration tests cover SQLite builds without FTS5 and report an actionable capability error.

JSON export is a versioned document with repositories, copies, remotes, current/effective findings, language inference, and evidence. Relational CSV export emits separate UTF-8 files with stable names/headers and foreign-key IDs plus a manifest. Formula-leading cells (`=`, `+`, `-`, `@`) are escaped for spreadsheet safety while the manifest records that transformation.

## 2. Migration strategy

- `001_initial.sql` creates the Stage 1 core schema and current-finding view.
- `002_stage2.sql` adds resumable-run, cache, provider, budget, language-inference, and evidence tables without rewriting applied history.
- `003_search.sql` adds Stage 3 FTS objects.
- Every SQL file is packaged as data, read in numeric order, hashed, and applied once in `BEGIN IMMEDIATE` using `sqlite3.executescript` semantics carefully enough that rollback remains controlled.
- Refuse a database newer than the running application. Refuse a changed checksum for an applied migration.
- A new database is migrated automatically by `init`; other commands never silently migrate an existing database unless explicitly documented. `db migrate` is the deliberate upgrade path.
- Migration integration tests start from empty, each historical fixture, and an interrupted/corrupt migration simulation.

## 3. Command surface

Global options: `--config PATH`, optional `--db PATH` override, `--verbose`, `--quiet`, `--no-color`, and `--json` where the command has a machine-readable result. Human output goes to stdout; diagnostics/progress go to stderr. JSON mode emits one valid document and disables decorative Rich output.

### Stage 1

| Command | Contract |
| --- | --- |
| `ghintel init [--force]` | Create missing configured directories, example-derived config, and a migrated DB. Refuse to overwrite existing config/DB without explicit force and never overwrite a non-empty DB. |
| `ghintel lookup GITHUB_URL` | Normalize a supported GitHub project URL/address and query the local DB only. Print the compact project card; never fetch, enrich, or search fuzzily. Exit `1` when the link is valid but is not indexed. |
| `ghintel discover [--root NAME]` | Local discovery, remote parse, dedupe, local source capture; no network. Print repositories/copies/diagnostics and run ID. |
| `ghintel list [filters]` | Tabular or JSON effective repository list; stable ordering defaults to identity key. |
| `ghintel show REPOSITORY` | Resolve numeric ID, canonical URL, or unambiguous owner/name; show the project card plus copies, remotes, current finding, inference/evidence, and correction provenance. |
| `ghintel db migrate [--dry-run]` | Show/apply pending numbered migrations with backup guidance and checksums. |

### Stage 2

| Command | Contract |
| --- | --- |
| `ghintel fetch [targets]` | Fetch/revalidate deterministic GitHub metadata/README only. Honors offline mode and never invokes Gemini. |
| `ghintel enrich [targets] [--dry-run]` | Deterministic classification then optional Gemini for eligible unresolved/enrichment work. Dry-run prints sources and worst-case budget without uploading. |
| `ghintel scan [targets]` | Compose discover -> capture -> fetch -> deterministic -> enrich according to duplicate policy. `--target-dir PATH` atomically persists a validated absolute `paths.input_dir` before the scan. |
| `ghintel resume RUN_ID` | Resume incomplete/failed-budget items after validating config/input compatibility; never clone a new run silently. |
| `ghintel doctor [--online]` | Validate config, directories, SQLite/FTS capability, migrations, env-var presence, price configuration, GitHub auth/rate headers, Gemini account model visibility/schema capability, and offline invariants. Online checks require the flag and respect provider enablement. |

### Stage 3

| Command | Contract |
| --- | --- |
| `ghintel search QUERY` | FTS search with filters and deterministic rank tie-breaking. |
| `ghintel correct REPOSITORY FIELD VALUE --reason TEXT` | Validate an allowlisted field/type and append a correction. Provide a distinct supersede operation rather than mutation/deletion. |
| `ghintel export --format json|csv --output PATH` | Produce versioned JSON or a relational CSV directory/manifest from a read transaction. |
| `ghintel roots list` / `roots remap NAME PATH` | Inspect or append a validated root mapping change. Dry-run shows resolved copy paths and collisions. |
| `ghintel db snapshot OUTPUT` | Online SQLite backup, integrity check, manifest/hash, atomic publish. Refuse to overwrite unless explicitly requested. |

Mutating commands print their run/change ID. Target expansion is resolved to canonical repository IDs before work starts and is recorded on the run.

## 4. Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Complete success, including an intentional cache/reuse result. |
| `1` | A syntactically valid `lookup` URL has no indexed repository. This is an investigation result, not a network failure. |
| `2` | CLI usage or configuration validation error. |
| `3` | Missing/invalid credentials or configured provider/model unavailable. |
| `4` | Hard budget prevented remaining work; run is resumable. |
| `5` | Partial run: at least one repository failed while others may have completed. |
| `6` | Database/migration/integrity failure. |
| `7` | Network/rate limit exhausted after policy; run is resumable. |

GitHub rate exhaustion never causes an unannounced sleep until the next quota window. The command persists its last safe endpoint checkpoint, marks the run interrupted, prints the reset time and exact `resume` command, and exits `7`. Short bounded retries remain appropriate for transient server failures.

Ctrl-C marks the run interrupted and returns conventional code `130` after the in-flight repository reaches a safe checkpoint.

## 5. Configuration contract

Load exactly one TOML file, defaulting to `./config.toml`. Resolve configured relative paths against the config file, not the current working directory. Reject unknown keys and unsupported `version`. `scan --target-dir PATH` is deliberately persistent rather than an ephemeral override: resolve the CLI path from the current working directory, require an existing directory, atomically store the normalized absolute path as `[paths].input_dir`, reload, and only then start the scan. Other CLI overrides are explicit and included (without secrets) in the run configuration snapshot.

The provided example is retained with these clarifications/additions:

```toml
version = 1

[paths]
# Replaced atomically with an absolute path by `scan --target-dir PATH`.
input_dir = "in"
db_dir = "dbs"
output_dir = "output"

[scan]
duplicate_policy = "reuse" # reuse | refresh
follow_symlinks = false     # true is rejected in v1
max_document_bytes = 1048576
max_source_bytes_per_repo = 4194304
force_llm_on_unchanged = false

[github]
token_env = "GITHUB_TOKEN"
offline = false
concurrency = 4
cache_ttl_hours = 24
max_retries = 5
timeout_seconds = 30

[gemini]
enabled = true
api_key_env = "GEMINI_API_KEY"
model = "gemini-3.8-flash"
concurrency = 1
timeout_seconds = 90
max_retries = 3
max_output_tokens_per_request = 4096
allow_source_upload = true

[budgets]
max_gemini_requests_per_run = 100
max_input_tokens_per_run = 500000
max_output_tokens_per_run = 100000
max_cost_usd_per_run = 10.0
max_repositories_enriched_per_run = 100

[language]
minimum_letters = 100
minimum_script_ratio = 0.20
gemini_fallback = true
allowed_categories = [
  "Chinese", "Russian", "Slavic-other", "Korean", "Japanese",
  "Arabic", "Hebrew", "Hindi", "English", "Unknown",
]

[pricing.gemini]
input_usd_per_million_tokens = 0.0
output_usd_per_million_tokens = 0.0
```

Validation rules:

- The allowed language list must equal the application enum in version 1; subsets would make persisted behavior dependent on accidental config.
- Positive finite timeouts, retry bounds, byte limits, concurrency, token limits, and cost limits are required.
- `gemini.enabled = true` plus zero/missing price values permits discovery/fetch but blocks any generation at preflight with an actionable error. Pricing is always operator-supplied.
- `allow_source_upload = false` disables Gemini enrichment even if enabled, because inline repository text is still disclosure to the provider.
- Offline mode is a hard GitHub network prohibition. Gemini should also be considered unavailable during an offline `scan`; `enrich` requires an explicit non-offline configuration.
- Environment variable names are validated; their values are read lazily only by the adapter that needs them.

## 6. Effective-record examples

For two clones whose origin URLs are SSH and HTTPS forms of the same owner/repository:

- one `repositories` row;
- two `local_copies` rows;
- at least two raw `remotes` rows;
- one run item and at most one GitHub/Gemini attempt per pipeline step;
- one current finding shared by both displays.

For a fork with `origin=A/fork` and `upstream=B/original`:

- two canonical repository rows and two remote edges;
- the local copy's primary identity is `A/fork`;
- local documents attach to `A/fork` only;
- `B/original` is not merged, and is not automatically enriched unless separately selected/primary.
