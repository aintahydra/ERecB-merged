# Phase 08: Two-machine intelligence exchange

Status: **implementation in progress**. The air-gap request/replay path, provider queues,
provider-owned merge commands, verified snapshots, YARA cache transfer, maintenance import,
and connected/air-gap role guards are implemented with focused tests. The provider-network
rehearsal and full release gate in section 7 remain open. The root triage CLI and provider
CLIs now check the selected role before commands that enrich, snapshot, merge, or activate a
cache. This phase follows the offline triage baseline in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). It covers an air-gapped capture machine and
an Internet-connected enrichment machine running the same merged source tree. The two roles are
explicit operating modes; capture analysis stays offline on either machine.

Current verification: the snapshot/mode regression tests pass (8), FileIntel tests pass (12),
IPIntel tests pass (16), and the GHIntel snapshot tests pass. The broader root suite has 61
passing tests; 7 tests that require repository-local `dbs/*.sqlite3` fail because those files
are on the remote test host, not this checkout. A database-independent selection passes (59).
All changed sources compile and `git diff --check` passes. The original capture was staged and
analyzed; both request selections exported; report
replay succeeded for IPIntel/FileIntel/GHIntel. On `192.168.56.110`, all three supplied DBs
passed SQLite quick-check and the read-only triage readiness check passed. The real request
bundles imported into isolated provider homework queues (143 files, 26 IPs, 132 repositories),
duplicate imports were no-ops, and the all-indicators bundle added 40 IPs and 1 repository.
Snapshots for all three databases were created and verified, including the 1.03 GB IPIntel
database. A compatible existing YARA cache was exported/imported and readiness then reported
the cache active. Live provider enrichment and physical transfer between separate machines
have not yet been run. The initial GHIntel snapshot smoke test initialized its supplied test
DB; the snapshot command is now strictly read-only, verified on a separate DB copy by matching
its SHA-256 before and after.

## 1. Confirmed operating contract

1. The air-gapped machine accepts archives under `in/`, stages them safely, and extracts file
   hashes, IPs, and GitHub repository identities. By default, inspect executable candidates;
   depth, file scope, byte limits, and existing adapter-specific limits remain configurable.
2. The four existing reports use only local `dbs/*.sqlite3` and a verified local YARA cache.
   An operator can regenerate reports on demand while the manifest-verified staged capture
   remains available. Regeneration does not require a permanent indicator inventory.
3. An air-gap request export contains canonical indicators and request metadata only. It never
   contains captured file bytes, paths, archive names, source excerpts, provider credentials,
   or raw reports. Default selection is **no matching DB record**; `--include all` requests a
   refresh of every observed indicator. A DB error or incompatible DB is not a miss.
4. The connected machine imports request bundles without automatically contacting providers.
   IPIntel, FileIntel, and GHIntel own their own enrichment and separate homework queues.
   A provider no-result remains homework for later retry. Eligible homework is processed newest
   request first, with rate-limit and retry delays respected.
5. Connected-side producer databases are exported as consistent SQLite snapshots. On the
   air-gapped machine, each producer validates and merges its own database into the existing
   one. YaraRuler exports/imports a verified cache generation separately.

Only copied files cross the machines. There is no network connection, shared mount, or direct
database access between them. Database merges and cache activation are maintenance operations,
never part of an archive's analysis pipeline.

Ship explicit `airgap` and `connected` profiles. The air-gap profile uses `in/`, `dbs/`,
`rules/cache/`, and `output/` by default and permits capture, report, request export, and
verified import/merge commands. The connected profile permits explicit provider enrichment,
snapshot export, and rule updates. Triage remains offline in both profiles. Provider queue
import and database verification do not need network access; `homework run` and rule-source
synchronization require the connected profile. Queue import belongs to the connected profile
but must itself remain offline. Reject a command/profile mismatch before I/O.

## 2. Current-state audit and inconsistencies to resolve

| Component | Reusable capability | Gap for this workflow |
| --- | --- | --- |
| Triage | Safe staging; read-only IP/File/GH lookups; verified YARA cache; four reports and stable report slots | Only watcher/`--once` and `--check` commands; no explicit report replay or request export. `skip_if_output_exists` must not suppress an operator-requested refresh. |
| Triage file scope | FileIntel and YARA default to executable candidates; FileIntel/GH/YARA have depth settings | IPIntel and GHIntel currently inspect all regular files; IPIntel has no staged-root depth setting; YARA consumer accepts only `exec-only`. Align defaults and expose deliberate per-adapter overrides. |
| IPIntel producer | Canonical IP enrichment, single-IP lookup, provider audit, resumable text-file consumption | No request-bundle import, homework, or implemented `merge-db` command, although `design/DESIGN_03-DB_update_merge.md` specifies one. Current `--consume` treats `not_found` as completed, contrary to the new homework rule. |
| FileIntel producer | Hash provider lookup and `merge-db --dry-run/--backup` | Enrichment is tied to a file scan job; hash-only import and homework are missing. The current merge copies scan/audit rows on every import and needs replay-safe exchange behavior. |
| GHIntel producer | Canonical URL lookup, targeted enrichment, resumable runs, and verified SQLite snapshots | New URLs enter mainly through local Git discovery; fetch has no URL target; no request import, homework, or database merge. Existing snapshots are whole DBs, not merge commands. |
| YaraRuler | `update-rules` builds an immutable generation; triage verifies version, platform, digest, and loadability | `force_rebuild` is currently ignored and every update rebuilds. No cache exchange command. A compiled cache can be activated only on a compatible platform/YARA runtime. |

The existing producer design folders remain the owners of database/cache contracts. The
`design/Ref/` copies are historical. Phase 08 must update producer designs alongside schema
changes and update consumer compatibility tests in the same change.

## 3. Shared exchange contract

Define a versioned, bounded request bundle, for example `erecb-requests-v1.json`, with a
sidecar SHA-256 manifest. Its fields are `schema_version`, random `bundle_id`, opaque
`source_instance_id`, monotonic source request sequence, UTC `created_at`, `selection`
(`missing` or `all`), extraction policy
fingerprint, item counts, and three sorted lists: files (`sha256`, optional `md5`), canonical
IPs, and normalized GitHub repository identity plus canonical URL. An opaque capture/run ID
may be included for deduplication, but no source path or archive name is exported. Reject
unknown versions, noncanonical values, excessive item counts/bytes, duplicate conflicting
hash pairs, and mismatched checksums before any queue mutation.

Each item has a stable identity: SHA-256 for files, `ipaddress` canonical text for IPs, and
GHIntel's canonical repository identity for GitHub URLs. Keep FileIntel's MD5 only as a
secondary lookup aid; never merge two distinct SHA-256 identities because MD5 matches. Use
shared test vectors between triage and producers so normalization cannot drift. Reimporting
the same `bundle_id` is a no-op; a new bundle mentioning an existing indicator records one new
request event. The source sequence orders requests from the one air-gapped machine even if its
clock changes or bundles are copied out of order; UTC remains useful for operators.

Default export includes only consumer lookup status `miss`. `hit` is excluded even if its
verdict or project card has unknown fields; resolving incomplete intelligence is the connected
producer's homework. FileIntel `ambiguous`, and all `unavailable`/`error` outcomes are reported
as export problems rather than silently treated as misses. `--include all` includes every
valid observation even if lookup is a hit, and can work without a usable DB while clearly
reporting that comparison was unavailable. Every export reports extraction truncation and
skipped-file counts so a short list is not mistaken for complete coverage.

## 4. Air-gapped capture and report work

Add explicit air-gap commands to the triage CLI, while preserving `--once`, watcher mode, and
`--check`:

| Proposed command | Behavior |
| --- | --- |
| `erecb-triage report --capture ID --config ...` | Reauthorize a `ready` staging generation against its manifest; re-read selected files, pin current DB/cache inputs, and atomically refresh the four owned reports and summary. No network or producer imports. |
| `erecb-triage requests export --capture ID --output PATH [--include all]` | Reauthorize and extract observations, compare against read-only local DBs unless forced, and publish one complete request bundle atomically. |
| `erecb-triage captures list` | Show stable capture IDs, source identity, ready/degraded state, and the most recent report/input versions for operator selection. |

Define a common capture-file selection policy with `selector: exec-only | all`, staged-root
depth, hidden-file rules, symlink policy, and per-file/capture byte limits. Default to
`exec-only` for hashes, IPs, GitHub URLs, and YARA; allow documented per-adapter overrides for
workflows that need IPs or URLs in text logs. Preserve each extractor's own parsing bounds and
IP singularity rule. Distinguish staged-root search depth from `watch.recursive`, which controls
only how input events are found. Reuse the current safe file-opening and manifest checks;
do not let report replay read an unverified path.

Refactor extraction, read-only lookup, and report rendering into callable steps so on-demand
commands and watcher dispatch use the same code. Replaying a report must bypass the normal
duplicate-skip decision only for its explicitly selected capture. Hold a coherent input set
for the full report run: maintenance cannot replace databases or the active cache until it
finishes. The report records capture generation, extraction policy, DB import-set identity
(or precomputed checksum), YARA generation, and generation time. A missing DB/cache yields
the existing explicit degraded status, not a negative finding.

## 5. Connected-side provider work

Implement `requests import`, `homework list`, and `homework run --limit N` within each producer
CLI. A thin merged-repository command may validate one bundle and invoke the three provider
imports, but it must not duplicate provider normalization, SQL, or network logic.

Each producer keeps its homework in a separate local state store, outside the intelligence DB
snapshots copied back to the air gap. Use one row per canonical indicator plus an append-only
request-event/attempt history. Track first/last requested UTC, count of distinct request
events, last outcome, next eligible time, and an in-progress lease for crash recovery. Import
does not query providers. Run selects eligible rows by newest source request sequence (and UTC
time for any future additional source), then a stable event ID; a new request moves an
existing item to the front without losing its history.
`not_found`, provider error, and rate limit remain unresolved with a bounded retry schedule;
success closes homework only when usable intelligence was stored. Invalid indicators are
rejected at import and do not become endlessly retrying homework. Expose counts and reasons.

- **IPIntel:** add bulk canonical-IP import and queue processing on top of `enrich_ip`/provider
  normalization. A hashless text extraction path is unnecessary. Retain provider attempts but
  do not remove `not_found` from homework; keep the old `--consume` semantics for existing
  extraction-file users or revise it explicitly with migration notes.
- **FileIntel:** add hash-only entity upsert and targeted enrichment without fabricating a
  `scan_job` or `file_observation`. Reuse current provider lookup, hash preference, and audit
  logic. A provider result with no file intelligence remains homework. Query by SHA-256 when
  available; keep optional MD5 for reconciliation and report ambiguous/conflicting hashes.
- **GHIntel:** add URL-only repository upsert, targeted fetch, and targeted enrichment for
  imported identities without a local Git checkout. Reuse `normalize_github_url`, HTTP cache,
  rate-limit checkpointing, and targeted enrichment. A non-enriched/not-found project card
  remains homework; local paths and source documents are never required in request bundles.

Forced `all` requests bypass normal success-age reuse once for that request event; provider
rate limits, budgets, and backoff still apply. Record the request ID on attempts so retries and
refresh results are auditable.

## 6. Database and YARA return path

Each producer adds or reuses `db snapshot`/`db verify` using SQLite's backup API and a
checksummed manifest. GHIntel already has these commands; FileIntel and IPIntel need them.
Do not copy a live SQLite file or depend on a `-wal` sidecar. The air-gap maintenance workflow
first verifies all files, supported schema versions, source/destination distinction, free
space, and a dry run. It pauses triage/report replay, makes recoverable destination backups,
then calls the producer-owned merge commands. It runs `erecb-triage --check` before resuming.
If any merge fails, restore the pre-import set; do not leave a mixture of new and old DBs
active. Record one import-set ID for audit and duplicate-copy detection.

| Producer | Merge work |
| --- | --- |
| FileIntel | Extend existing `merge-db` with a replay-safe import ledger and an `intelligence-only` exchange profile. Import file entities, tags/names, and provider evidence; avoid connected-machine scan paths, watch state, and unusable raw-response paths. Preserve local observations and existing scalar conflict rules. Ensure `--dry-run` never initializes or alters an existing destination. |
| IPIntel | Implement its existing `DESIGN_03-DB_update_merge.md` plan, including validation, backup, dry-run, canonical IP identity, child records, and audit history. Add replay-safe import tracking; never import connected-machine `visited_directories`. |
| GHIntel | Add a provider-owned relational merge keyed by canonical repository identity, remapping foreign keys for snapshots/findings/evidence/people. Preserve destination local copies and corrections; import newer intelligence without overwriting local corrections. Include dry-run, backup, validation, and replay-safe provenance. |

The YaraRuler producer should avoid rebuilding when source commits, enabled rule set,
compiler/runtime identity, and relevant config are unchanged; `--force-rebuild` must actually
override that check. Add cache export/import commands that package the active generation,
verify manifest/artifact checksums and loadability on the destination, then atomically switch
`active`. Never activate a cache built for a different OS/architecture/YARA version. Keep the
previous generation for rollback. A changed runtime is a legitimate rebuild trigger even when
source rules did not change.

## 7. Delivery sequence and acceptance gates

1. **Contract and baseline:** freeze request/manifest schemas, normalization vectors,
   no-result semantics, mode boundaries, and test fixtures; update stale baseline status in
   the roadmap and provider design documents.
2. **Air-gap side:** common selection policy, authorized report replay, missing/all request
   export, reproducible report provenance, and strict no-network tests.
3. **Connected providers:** implement three independent imports and LIFO homework queues,
   then hash-only FileIntel and URL-only GHIntel enrichment. Test duplicate/out-of-order
   bundles, no-result retry, forced refresh, rate-limit pause, and crash recovery.
4. **Return path:** complete IP/GH merges, harden FileIntel merge, add snapshots/verification,
   and orchestrate verified multi-DB backup/apply/restore. Test repeated and out-of-order
   snapshots, schema mismatch, local corrections, WAL, and interrupted imports.
5. **YARA and release:** conditional cache generation, portable cache transfer checks,
   compatible-runtime acceptance, operator profiles/runbook, and a two-machine rehearsal.
   Document offline software upgrades for both machines, bundle schema compatibility, and
   producer schema migrations before consumer deployment.

The rehearsal uses one capture with known and missing hashes/IPs/repos: export missing-only,
import twice (no duplicate request count), add a newer repeat request (moves to LIFO front),
resolve some indicators while retaining no-results, snapshot and manually transfer DBs,
merge twice (second pass is a no-op), regenerate all reports from the retained capture, then
force-export all. Assert that capture bytes never leave the air gap, triage never performs
network I/O, and old DB/cache versions remain restorable.

## 8. Deployment assumption

The two machines currently use the same OS, CPU architecture, and YARA/yara-python versions,
so a compiled-cache transfer is supported by the current cache contract. Validate those
properties again on every cache import because future upgrades can make them differ. Reject
an incompatible `rules.yac` without switching the active generation; a different-runtime
deployment would need a compatible build environment or an offline source-rule build path.
