# IMPLEMENTATION 04: GHIntel Processor

## 1. Objective and status

Implement the offline GHIntel pipeline adapter: discover GitHub repository-root addresses in
unarchived file bytes, normalize them exactly like the producer, retrieve effective local
project cards from `dbs/ghintel.sqlite3`, and publish Markdown evidence.

Status: **implemented (baseline)**. The adapter performs bounded, offline GitHub repository-root
extraction from authorized staged bytes, producer-compatible normalization, read-only
project-card lookup, and canonical Markdown publication. It performs no Git, network, or
provider operation.

## 2. Files to add or update

```text
src/erecb_triage/ghintel/
  __init__.py
  contracts.py
  extractor.py
  normalization.py
  repository.py
  report.py
src/erecb_triage/processors/ghintel.py
src/erecb_triage/processors/__init__.py
src/erecb_triage/config.py
src/erecb_triage/dispatcher.py
config/watcher_ghintel.yaml
```

The adapter must not depend on the independent producer's runtime package. Shared behavior is
enforced through vectors and schema contracts, not cross-application imports.

## 3. Input, outputs, and metrics

Input: one ready `staged_capture` with archive-derived `report_stem`.

Emit:

- one `github_repository_observation` per `(identity_key, source_path)`;
- one `github_intel_lookup` per unique identity with `hit`, `miss`, `unavailable`, or `error`;
- one `github_intel_hit` only beside a complete hit; and
- namespaced scan/observation/unique/lookup metrics from DESIGN 05.

Publish `output/<archive_file_name>-ghintel.md`. Keep the unique staging identity, source
digest, DB path/schema state, event ID, and run ID as provenance.

## 4. Work package A — strict settings and registration

Add `ghintel` configuration validation with exact types and defaults:

- read-only DB path and output root;
- positive chunk size;
- bounded candidate bytes;
- nullable nonnegative file size/depth;
- exact booleans for symlink/hidden settings; and
- required literal report suffix `-ghintel.md`.

Validation performs no traversal, DB open, output creation, Git operation, or network access.
Register `ghintel` only after construction and dependency tests pass.

## 5. Work package B — confined deterministic traversal

Use sorted `os.scandir()` traversal rooted at the authorized staging descriptor/path.

- Regular files only.
- No symlink following in version 1.
- Apply hidden/depth policies to every encountered component.
- Apply initial and during-read size checks.
- Stat before/after; discard all observations from a changed file.
- Bound per-file diagnostics and total captured observations.
- Exclude output paths if misconfiguration would place them beneath staging.

Count only confirmed-EOF reads as scanned. Policy exclusions and incomplete reads are skipped.

## 6. Work package C — streaming address extraction

Recognize the DESIGN 05 repository-root forms:

- HTTP/HTTPS/Git URLs;
- SSH URLs with optional valid explicit port;
- SCP-like `git@github.com:owner/repository.git`;
- bare `github.com/owner/repository` extraction convenience.

Tokenizer requirements:

- byte-oriented ASCII scanning; no whole-file decode;
- left/right token boundaries across chunks;
- bounded carry state independent of chunk size;
- discard overlong address-like runs through the next delimiter;
- hold a chunk-terminal candidate until delimiter or true EOF; and
- retain occurrence count and first byte offset without retaining surrounding content.

Reject credentials, query/fragment, controls/whitespace, backslash, dot segments, missing or
extra repository segments, lookalike hosts, unsupported SSH users, malformed ports,
subresource links, and candidates embedded in larger tokens.

## 7. Work package D — producer-compatible normalization

Normalize host to `github.com`, remove terminal `.git` and slash, preserve validated display
casing, produce `https://github.com/<owner>/<repository>`, and derive the Unicode-case-folded
identity key `github.com/owner/repository`.

Maintain a shared JSON vector set derived from the producer references. Run every accepted and
rejected vector directly against both the pipeline normalizer and a captured producer-expected
result. Any normalization drift blocks release because DB lookup identity would diverge.

Deduplicate after normalization by `(identity_key, source_path)` and aggregate unique lookups by
identity. Never infer a repository from filenames, directories, or captured `.git` metadata.

## 8. Work package E — read-only project-card repository

Open `ghintel.sqlite3` with URI `mode=ro`, `query_only=ON`, trusted schema disabled where
supported, and parameterized queries. Never create or migrate the DB.

Validate the required capability surface rather than exact migration equality:

- repositories and `repository_project_cards`;
- current findings/findings;
- corrections and supersession;
- latest GitHub snapshots;
- people/repository people; and
- language inferences.

Within one short read transaction:

1. Query the exact indexed `identity_key`.
2. Load/validate JSON arrays and documented-people shape.
3. Load latest snapshot metadata including stars, SPDX license, fork flag, and validated
   parent identity/URL.
4. Load current finding's language inference.
5. Resolve latest non-superseded correction for each allowlisted field.
6. Overlay `summary`, tool types, capabilities, and intended uses exactly as the producer.
7. Return a hit only if every required query/parse succeeds.

A valid repository with no finding remains a hit with `deterministic-only` or `not-enriched`.
A missing identity is a miss. Malformed JSON/child query failure is an error, never partial hit.

Producer local copies/source documents are history, not current-capture evidence. GitHub owner
is an account relationship, not proof of author/developer identity.

## 9. Work package F — records and Markdown

Construct records with current source paths, canonical URL, producer IDs/status, project-card
fields, correction provenance, snapshot provenance, documented people roles/quotes, and
language inference. Bound all rendered producer/capture strings.

Report sections:

- summary and archive/staging/DB provenance;
- repositories with local intelligence;
- repositories with no local DB record;
- incomplete lookups;
- warnings; and
- per-repository effective card and current evidence paths.

Escape Markdown, HTML, controls, and Unicode formatting separators. Create clickable links only
from validated canonical HTTPS URLs. Never make captured arbitrary text into a link target.

## 10. Prohibited operations

Tests must fail if GHIntel:

- invokes `git` or parses captured Git config through Git;
- evaluates includes, credential helpers, URL rewrites, hooks, or remote helpers;
- opens sockets or calls GitHub/provider/LLM SDKs;
- reads producer source blobs to manufacture current evidence;
- follows capture symlinks; or
- writes to `ghintel.sqlite3`.

## 11. Test matrix

| Area | Cases |
| --- | --- |
| Tokenizer | every chunk split, EOF, binary delimiters, punctuation, repeated/overlong tokens |
| Normalizer | transports, mixed case, `.git`, slash, SSH ports, malformed/lookalike/subresource |
| Traversal | depth, hidden, symlink, special file, size, permission, disappear, mutation |
| Repository | ready, deterministic-only, not-enriched, corrected, documented people, inference |
| Failures | missing/incompatible DB, malformed JSON, failed child query, null optional fields |
| Reporting | exact filename, escaping, safe links, ordering, atomic refresh, ownership collision |
| Offline | blocked Git/subprocess/socket/provider attempts and unchanged DB hash |

## 12. Integration scenario

Stage an inert archive containing several textual/binary files with multiple transport forms of
one identity plus one unknown identity. Use a temporary producer-schema DB containing a
corrected card.

Verify:

- one unique lookup for the equivalent forms;
- every current file path retained;
- corrected effective values and raw provenance distinguished;
- unknown identity reported as no local record;
- `output/<archive_file_name>-ghintel.md` published atomically; and
- zero network/Git operations.

## 13. Exit gate

Implementation 04 is complete only when:

- normalization matches all producer vectors;
- traversal/tokenization is chunk-invariant and mutation-safe;
- complete project-card semantics and corrections match the producer contract;
- hit/miss/unavailable/error remain distinct in records and report;
- the exact archive-filename report is evidence-linked and atomically owned; and
- offline/read-only guards and the full GHIntel suite pass.

Next release integration: [`IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md`](IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md).
