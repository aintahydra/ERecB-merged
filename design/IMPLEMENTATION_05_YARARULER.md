# IMPLEMENTATION 05: YaraRuler Cache Consumer

## 1. Objective and status

Implement `YaraScan`, an offline consumer of one immutable cache generation produced by the
independent YaraRuler application. Scan selected unarchived files, retain rule provenance,
hash matched bytes, and publish Markdown without compiling rules in the capture path.

Status: **implemented (single-worker baseline)**. Depends on Implementation 02 and the cache
fixtures from Implementation 01. The adapter validates an immutable UUID-addressed cache,
loads only its verified `rules.yac` artifact, scans deterministic executable candidates, and
publishes an owned `-yara.md` report. It has no source-rule, Git, cache-update, or network
path. Process-worker parallelism (work package F) remains deliberately deferred until a real
`yara-python` multi-worker compatibility corpus is available.

## 2. Files to add or update

```text
src/erecb_triage/yarascan/
  __init__.py
  contracts.py
  cache.py
  discovery.py
  filters.py
  hashing.py
  matcher.py
  report.py
src/erecb_triage/processors/yara_scan.py
src/erecb_triage/processors/__init__.py
src/erecb_triage/config.py
src/erecb_triage/dispatcher.py
config/watcher_yara.yaml
pyproject.toml
```

Add `yara-python` as an explicit optional dependency group. Core package import and non-YARA
profiles must continue working without it.

Implemented baseline note: the shipped profile uses `threads: 1`; configurations may validate a
positive thread budget for the future worker implementation, but this baseline executes one
matcher serially and does not claim process-worker equivalence.

## 3. Input and outputs

Input: one ready `staged_capture` plus configured cache directory.

Emit:

- one `yara_match` per `(file, namespace, rule)`;
- recoverable `yara_scan_error` records;
- cache-unavailable capture warning/error; and
- the DESIGN 06 namespaced discovery/selection/scan/match/error metrics.

Publish `output/<archive_file_name>-yara.md`. A zero-match scan is successful but is never
described as clean. A missing/corrupt cache is not a zero-match scan.

## 4. Work package A — configuration and dependency boundary

Validate without loading YARA/cache or traversing captures:

- cache/output paths;
- selector literal `exec-only` for version 1;
- nullable nonnegative depth/file size;
- symlink setting (`false` only in version 1);
- hidden settings;
- positive threads and timeout;
- include-strings boolean and bounded per-rule instance cap; and
- required literal suffix `-yara.md`.

If selected and `yara-python` is unavailable/incompatible, fail startup with an actionable
dependency error. If installed but a cache later becomes unavailable, treat it as a per-capture
degraded processor result so a newly published cache can repair later captures without restart.

## 5. Work package B — pin and validate cache generation

Once per capture:

1. Read `<cache_dir>/active` exactly once.
2. Require one canonical lowercase UUID, not a path.
3. Resolve only `<cache_dir>/generations/<uuid>/` beneath the configured cache.
4. Open/validate `manifest.json` before loading `rules.yac`.
5. Verify manifest schema/generation, artifact filename, size, SHA-256, platform, machine,
   YARA/yara-python compatibility, nonempty accepted set, and unique namespaces.
6. Build a complete namespace -> source/rule-path/commit/digest provenance map.
7. Load the compiled artifact; never fall back to source compilation.
8. Pin the selected generation/provenance for the complete capture.

Redact credentials/userinfo from source URLs before records/logs/reports. Do not prune cache
generations: producer 0.1.0 has no scan leases or automatic pruning. Operational documentation
must require updates/cleanup outside active scans.

## 6. Work package C — candidate discovery

Walk the authorized staged tree deterministically with no symlink following. Consider readable
regular files only. Apply hidden/depth policy before classification.

Read at most the configured bounded header sample and select when any frozen version-1 rule
succeeds:

- PE, ELF, Mach-O, or universal/fat Mach-O signature;
- valid nonempty shebang interpreter token;
- configured script suffix;
- configured executable/library suffix; or
- optional libmagic executable/script indicator.

These are selection hints, not verdicts. Apply maximum file size after classification so the
size-skip metric specifically counts executable candidates. Recheck after open.

Optional libmagic failure degrades to deterministic signatures/shebang/suffixes and produces at
most one warning per capture.

## 7. Work package D — single-worker matcher

Implement single-worker correctness first:

1. Open/stat selected file and retain device, inode, size, and nanosecond mtime.
2. Call `Rules.match(filepath=..., timeout=...)` without reading target bytes into logs.
3. On no match, record successful scan and do not hash.
4. On match, stream once for SHA-256 and MD5.
5. Re-stat and compare the complete identity tuple.
6. If changed, discard all matches/hashes for the file.
7. Normalize each match and verify its namespace exists in the pinned provenance map.

Convert YARA timeout/dynamic exceptions to bounded recoverable errors. One file must not discard
matches from other files.

## 8. Work package E — match normalization

For each `(path, namespace, rule)`:

- sort/deduplicate tags;
- normalize metadata to bounded JSON scalar values;
- cap metadata entries, key length, and scalar rendered length;
- attach cache generation and complete rule source/ref/commit/path/digest provenance;
- attach current file SHA-256 and identification-only MD5; and
- sort deterministically by display path, namespace, and rule.

When strings are enabled, retain identifier, offset, and length only. Never retain or render
matched bytes. Sort instances and cap them per rule, with explicit truncation state/count in the
pipeline record schema even though standalone producer report schema 1.0 lacks that field.

A manifest/provenance mismatch is a cache-integrity error; never emit an unprovenanced match.

## 9. Work package F — bounded process workers

Add process workers only after all single-worker cases pass.

- Use `ProcessPoolExecutor`, not threads, for configured workers > 1.
- Load the pinned artifact once per worker initializer.
- Pass only serializable bounded work/outcomes.
- Limit outstanding futures to at most twice worker count.
- Normalize/sort in the parent; workers never write reports/logs/state.
- Convert individual future failure when the pool remains usable.
- Abort only this processor/capture on pool-wide breakage; later adapters/events continue.

Prove one-worker and multi-worker normalized records/metrics/reports are equivalent apart from
declared timing fields.

## 10. Work package G — Markdown report

Publish `<archive_file_name>-yara.md` through the logical report slot. Include:

- archive/source/staging/cache/YARA provenance;
- discovered, selected, scanned, matched-file, rule-match, and error counts;
- matched-file table with hashes, rule count, and tags;
- bounded warning/error table; and
- per-file rule/source/commit/metadata detail.

Optional string evidence shows location only. Escape all rule-controlled/capture values.

States must be explicit:

- cache unavailable: no files scanned;
- partial scan: some file errors;
- successful no-match: files scanned and no matches;
- successful match: evidence present, not automatic malware verdict.

## 11. Prohibited operations

Capture processing must never:

- invoke Git or synchronize rule repositories;
- compile `.yar`/`.yara` source;
- modify cache/quarantine/source directories;
- follow captured symlinks;
- execute/import target files;
- use `shell=True`;
- emit matched byte content; or
- treat YARA as a sandbox or verdict engine.

## 12. Test matrix

| Area | Cases |
| --- | --- |
| Config/dependency | every boundary/type, optional package absent/incompatible |
| Cache pointer | missing, whitespace, traversal, non-UUID, missing generation |
| Manifest/artifact | malformed JSON, mismatch, digest/size/platform/YARA, empty set, duplicate namespace, corrupt `.yac` |
| Discovery | every header/shebang/suffix, false cases, libmagic modes, hidden/depth/size/symlink/special |
| Matcher | no match, one/many matches, timeout, exception, disappear/change, hash-on-match only |
| Normalization | metadata scalars/bounds, tags, namespaces, URL redaction, string omission/cap/no bytes |
| Workers | one vs many equivalence, individual future failure, broken pool, bounded queue |
| Report | exact filename, all four states, escaping/order, atomic refresh/ownership |

Integration builds a harmless cache from a local temporary Git fixture through the independent
producer preparation service where available. It performs no network clone and never executes
the inert target corpus.

## 13. Verification artifacts

Record Python, `yara-python`, libyara, platform/machine, optional libmagic, and cache manifest
versions. Include normalized one/multi-worker comparison and proof that source/cache files and
matched target bytes were not modified or leaked.

## 14. Exit gate

Implementation 05 is complete only when:

- one verified cache generation is pinned per capture;
- every retained match has exact target and rule provenance;
- timeout/mutation/worker failures preserve unrelated results;
- no source compilation, Git/network activity, or matched-byte output occurs;
- one/multi-worker normalized results are equivalent; and
- the exact archive-filename YARA report passes all state and ownership tests.

Next release integration: [`IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md`](IMPLEMENTATION_06_UNIFIED_TRIAGE_RELEASE.md).
