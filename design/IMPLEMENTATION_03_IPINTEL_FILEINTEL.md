# IMPLEMENTATION 03: IPIntel and FileIntel

## 1. Objective and status

Verify, harden, and integrate the existing IPIntel and FileIntel adapters against trusted
staged captures and producer-owned read-only databases.

Status: **implemented (baseline)**. Both adapters use manifest-authorized staged captures and
producer-owned read-only SQLite sessions. The offline suite verifies producer capability
surfaces, hit/miss/ambiguity/unavailable semantics, report provenance, and fixture immutability;
no provider calls or database mutation are added.

## 2. Files in scope

```text
src/erecb_triage/ipintel/
src/erecb_triage/fileintel/
src/erecb_triage/processors/ip_retriever.py
src/erecb_triage/processors/file_retriever.py
src/erecb_triage/config.py
src/erecb_triage/dispatcher.py
config/watcher_ipintel.yaml
config/watcher_fileintel.yaml
config/watcher_localintel.yaml
```

Target reports for `sample.zip.en_dec`:

- `output/sample.zip.en_dec-ipintel.md`
- `output/sample.zip.en_dec-fileintel.md`

## 3. Shared adapter requirements

Both adapters must:

- accept only current, ready, manifest-authorized `staged_capture` records;
- scan `staged_path`, never the archive under `in/`;
- traverse deterministically without following symlinks by default;
- process regular files only and isolate per-file failures;
- detect mutation with descriptor/path identity, size, and nanosecond mtime checks;
- use bounded reads and bounded error/report values;
- open one producer database session per capture with SQLite URI `mode=ro` and
  `PRAGMA query_only=ON`;
- validate required schema capabilities, allowing compatible newer schemas/extra columns;
- distinguish `hit`, `miss`, `unavailable`, and `error` (`ambiguous` additionally for files);
- use current staged paths as current evidence and producer observations only as history; and
- publish Markdown through the logical report slot with exact capture provenance.

No DB result may change local observation facts. No miss/failure/null value becomes benign.

## 4. Work package A — IP extraction

Implement/verify the DESIGN 03 byte grammar:

- ASCII IPv4 and IPv6 literals;
- IPv4 with valid decimal port;
- bracketed IPv6 with optional valid decimal port;
- documented IPv6 zone syntax and canonical zone removal;
- rejection of bare-IPv6-plus-port ambiguity;
- rejection inside larger alphanumeric/hex tokens;
- correct punctuation and binary-byte boundaries;
- maximum token/carry length and discard-through-delimiter behavior; and
- identical results at every relevant chunk split, including chunks smaller than overlap.

Validate with `ipaddress.ip_address()` and emit canonical text. Keep IPv4-mapped IPv6 as
version 6. Apply the exact ignored IPv4 blocks from DESIGN 03 only to version-4 results.

Deduplicate by `(canonical_ip, source_path)` while retaining every current source path for a
unique IP. An interrupted, oversized, or changing file contributes no partial observations.

## 5. Work package B — IPIntel repository

Validate/query:

- `ip_entities` by canonical `ip`;
- reverse DNS, related IOC, and related actor child rows;
- provider result history and its supporting run/foreign-key surface.

One entity is a `hit` only when every required child query completes. A child-query failure is
`error`, with no partial hit. Preserve `malicious` exactly as `Yes`, `No`, or null. Preserve
provider statuses/codes as historical metadata; a failed/not-found provider result is not a DB
entity miss.

Cache complete outcomes per canonical IP for that capture only. Close and clear the cache at
the end of the capture.

## 6. Work package C — IPIntel report and metrics

Produce observations, lookup outcomes, hits, namespaced metrics, and
`<archive_file_name>-ipintel.md`.

Report sections:

- summary and exact archive/staging/DB provenance;
- IPs with local intelligence;
- IPs with no local DB record;
- incomplete lookups;
- warnings; and
- per-IP details with current source paths.

Escape captured/database values for Markdown/HTML/control characters. Sort by IP version,
numeric IP value, then path. A missing DB still produces local observations and a report.

## 7. Work package D — executable discovery and hashing

Verify magic-first classification from bounded header bytes. When configured:

- optional `python-magic`/libmagic positive indicators take precedence;
- a definitive non-executable magic result prevents extension fallback;
- missing/ambiguous magic may use deterministic extension fallback;
- `.apk` fallback is allowed only under the DESIGN 04 rules;
- magic unavailability produces one capture warning, not warning spam; and
- both classification methods disabled is a startup configuration error.

For candidates, compute SHA-256 and MD5 in one complete streaming pass. MD5 is identification
only. Detect growth/replacement/change and discard incomplete hashes. Deduplicate current
observations by `(sha256, source_path)` and group lookups by SHA-256 within the capture.

## 8. Work package E — FileIntel repository

Lookup order:

1. Query exact SHA-256.
2. Only on SHA-256 miss, query MD5 candidates.
3. Accept one MD5 row only when its SHA-256 is null or equals the observed SHA-256.
4. Multiple MD5 rows are `multiple_md5_rows` ambiguity.
5. One row with conflicting SHA-256 is `conflicting_sha256` ambiguity.

For a hit, load names, tags, provider lookups, and historical observations in one short
consistent read transaction. Preserve DB `malicious` as `yes`, `no`, or `unknown`; keep DB
hashes separate from current hashes; never open stored raw-response or historical paths.

Cache outcomes by observed SHA-256 for the capture. Treat conflicting MD5 supplied for a
cached SHA-256 as invalid caller input.

## 9. Work package F — FileIntel report and metrics

Produce observations, lookup outcomes, hits/ambiguities, namespaced metrics, and
`<archive_file_name>-fileintel.md`.

Report sections:

- summary and exact archive/staging/DB provenance;
- executables with local intelligence;
- executables with no local DB record;
- ambiguous MD5 matches;
- incomplete lookups;
- warnings; and
- per-hash details with every current source path.

Display `match_type` explicitly. A weak MD5 hit must never look like a SHA-256 hit. Missing DB,
classification degradation, and zero executables are separate states.

## 10. Configuration and integration

Update defaults and profiles to exact suffixes. Add `watcher_localintel.yaml` with:

```yaml
analysis:
  processors:
    - ip_retriever
    - file_retriever
```

The order is deterministic but the adapters are independent. Empty results, misses, returned
errors, or unexpected IPIntel failure must not suppress FileIntel.

Validate integer boundaries (`null`, zero, positive, negative, bool, float, numeric string),
boolean exact types, hidden/depth behavior, path settings, classifier combinations, and fixed
report suffixes without runtime I/O during config validation.

## 11. Test matrix

### IPIntel

- every extraction vector across every split point;
- ignored-range boundaries and public neighbors;
- binary files, empty files, max-size crossing, disappearing/changing files;
- depth/hidden/symlink/special-file behavior;
- IPv4/IPv6 hit, miss, null verdict, empty/multiple child rows;
- missing/incompatible DB and parent/child query failures; and
- deterministic record/report escaping and ordering.

### FileIntel

- every magic/header/extension positive and definitive negative;
- optional magic available/unavailable/error modes;
- known SHA-256/MD5 vectors and bounded block sizes;
- size boundary, mutation, unreadable/disappearing/symlink/special files;
- SHA-256 hit, miss, valid weak MD5 hit, multiple/conflicting MD5 ambiguity;
- null fields, all child tables, malformed/missing/incompatible DB; and
- deterministic record/report escaping and ordering.

### Combined

- real archive -> ready staging -> both real adapters -> both exact reports;
- no IPs plus executable; IP lookup warning plus valid file hit;
- duplicate archive reuse and changed bytes at same filename;
- same-second staging collision with unchanged canonical report names;
- report publication failure isolated by processor; and
- before/after fixture and operational DB hashes unchanged.

## 12. Verification artifacts

Record:

- test command, Python/SQLite/libmagic versions, and optional-dependency state;
- counts of unit/integration cases and skips;
- hashes proving producer fixtures/operational DBs were not modified;
- sample redacted reports for hit/miss/unavailable/ambiguity; and
- any accepted classifier platform variance.

## 13. Exit gate

Implementation 03 is complete only when:

- both adapters pass standalone and combined offline tests;
- all extraction/hashing results are complete, deterministic, and mutation-safe;
- lookup outcome and verdict semantics match producer contracts;
- missing/incompatible DBs still produce explicit incomplete reports;
- exact archive-filename report names and atomic refresh pass end to end; and
- no test or runtime path mutates a producer database.

Next independent additions: [`IMPLEMENTATION_04_GHINTEL.md`](IMPLEMENTATION_04_GHINTEL.md)
and [`IMPLEMENTATION_05_YARARULER.md`](IMPLEMENTATION_05_YARARULER.md).
