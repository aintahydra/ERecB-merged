# IMPLEMENTATION 06: Unified Triage Release

## 1. Objective and status

Ship the complete offline workflow as one supported operational profile:

```text
archive -> trusted staging -> IPIntel -> FileIntel -> GHIntel -> YaraRuler -> Markdown reports
```

Status: **implemented (operational baseline)**. The canonical profile now dispatches all four
adapters from one trusted staging generation, emits an owned capture summary, and exposes a
read-only `--check` readiness command. It retains all Implementation 02 security/recovery gates.
The long-duration soak corpus, measured resource-performance baseline, automated retention
command, and release-install matrix remain release-hardening work rather than silently claimed
as complete.

## 2. Release scope

The release includes:

- watcher, stabilization, staging, recovery, and report ownership;
- all four registered analysis adapters;
- a canonical all-processors configuration;
- startup/runtime readiness diagnostics;
- consistent logging, status, packaging, and operator documentation;
- offline acceptance and sustained-run verification; and
- explicit retention administration.

It does not include automated remediation, online enrichment, automatic rule update during
capture processing, distributed scheduling, or composite malicious/benign scoring.

## 3. Work package A — canonical configuration

Make `config/watcher_all.yaml` runnable with:

```yaml
pipelines:
  on_added:
    preprocessors:
      processors: [stage_input]
    analysis:
      processors:
        - ip_retriever
        - file_retriever
        - ghintel
        - yara_scan
```

Include complete safe defaults and exact suffixes. Validate:

- one application base directory;
- disjoint watch, staging, partial/state, DB/cache, and output roots;
- one dispatcher per staging root;
- distinct processor report targets;
- optional dependency requirements only for enabled processors; and
- startup construction of every selected processor.

Keep single-processor profiles as diagnostic/minimal deployments, but ensure their settings are
derived from the same defaults and contract tests.

Implemented baseline: `watcher_all.yaml` enables `publish_summary: true`; its per-adapter
settings merge with the same strict defaults used by dedicated profiles. Missing YARA bindings are
fatal only when `yara_scan` is selected. A missing/replaced cache is runtime-degraded and is
reported without suppressing the other adapters.

## 4. Work package B — readiness and health reporting

Add a read-only startup diagnostic path or command that checks:

- watch/staging/output/state path existence, containment, permissions, free space, and locks;
- staging schema version/migration readiness;
- selected processor construction and report-slot mapping;
- required producer DB capability surfaces via `mode=ro`;
- optional libmagic availability/degradation;
- `yara-python` compatibility and current cache pointer/generation; and
- offline invariant configuration.

Do not create/migrate producer databases, update rules, or perform network calls. Clearly
separate fatal startup errors from runtime-recheckable degraded dependencies.

Implemented baseline: `erecb-triage --config config/watcher_all.yaml --check` emits sorted JSON
checks. It does not create directories, state, reports, cache artifacts, or producer databases.
It verifies configured path containment, existing staging schema when present, selected adapter
construction, read-only producer-schema capability surfaces, classifier availability, free space,
and the active YARA cache when available.

Runtime rechecks are required per capture for replaceable DB files and active YARA generation.
Pin each dependency session/generation so replacement affects later captures, not the one in
progress.

## 5. Work package C — unified status and summary

Create a capture-level result model that records for each adapter:

- `success`, `degraded`, `failed`, or `not_enabled`;
- start/finish time and duration;
- input/staging/report identity;
- DB schema/cache generation identity where applicable;
- namespaced counters; and
- bounded error/warning codes.

Optionally publish `<archive_file_name>-summary.md` after all enabled adapters finish. It links
the four canonical reports and explains missing/stale reports. It must not combine evidence
into a malware verdict or label absence as benign.

If an adapter fails before it can replace its canonical report, the summary/status must state
that the existing report, if any, belongs to an earlier staging generation. Never silently
present an old report as current.

Implemented baseline: when `dispatcher.publish_summary` is true, the dispatcher reserves a
stable `triage_summary` slot and publishes `<archive>-summary.md`. Each enabled adapter is
labelled `success`, `degraded`, or `failed`; the four known adapters not enabled by the profile
are labelled `not_enabled`. A link is emitted only when that adapter refreshed its report in the
current capture invocation; otherwise the summary explicitly warns about possible stale output.

## 6. Work package D — resource budgets

Define and enforce configuration limits for:

- accepted archive bytes;
- extracted files and cumulative extracted bytes;
- available-disk preflight/headroom;
- per-processor file size/depth;
- bounded observations, matches, metadata, warnings, and report bytes;
- YARA timeout/workers/queued futures; and
- event queue size/backpressure.

Budget exhaustion is explicit and scoped. Preserve completed results and report which analysis
was not performed. Never partially claim a successful negative scan.

Measure sequential baseline on representative small/medium/large inert corpora before adding
concurrency. Record wall time, CPU, peak RSS, disk growth, files/bytes, and per-processor time.

## 7. Work package E — logs and audit trail

Emit structured logs with:

- event/run/capture identifiers;
- source-relative path and digest (not captured contents);
- processor and lifecycle operation;
- DB/cache identity;
- duration and namespaced counters;
- stable sanitized error code; and
- publication/reuse/recovery decision.

Do not log captured content, matched bytes, credentials, authorization headers, full provider
payloads, or unsanitized control characters. Define log rotation/retention separately from
capture retention.

Persist enough staging/status state to answer which staging generation produced each current
report without parsing filenames.

## 8. Work package F — retention administration

Define distinct policies for:

- source archives in `in/`;
- private partial work;
- published staged captures/manifests;
- staging-index capture/history/report slots;
- Markdown reports;
- operational logs; and
- YARA generations (subject to producer 0.1.0 no-lease limitation).

Retention is never implicit in event handling. Provide a dry-run administrative command or
documented procedure that resolves exact owned targets, refuses active/pending captures, and
preserves referential/audit consistency. Use recoverable archival/trash behavior where
practical. Do not remove YARA generations while scans/updates may be running.

## 9. Work package G — packaging and deployment

Test installation variants:

- base watcher + IPIntel;
- FileIntel extension fallback only;
- FileIntel with python-magic/libmagic;
- YARA extra with compatible native library; and
- full bundle.

Produce reproducible wheel/source-distribution checks, import smoke tests, CLI help/startup,
and offline dependency guidance. Document low-privilege service execution, filesystem
permissions, resource limits, and optional external sandboxing for YARA.

Do not bundle operational DBs, rule caches, captures, reports, staging state, or secrets into
release artifacts.

## 10. Work package H — operator runbook

Document:

- initial directory/state creation and configuration;
- starting continuous mode and running explicit `--once`;
- expected staging and exact report filenames;
- interpreting hit/miss/unavailable/error/ambiguity/no-match;
- safely replacing producer DBs between captures;
- updating YARA rules outside capture processing;
- diagnosing locks, corrupt archives, incompatible schemas/caches, optional dependencies, and
  report collisions;
- retry/recovery after interruption;
- identifying report provenance/staleness; and
- retention/backup/restore.

Examples use inert data and redact machine-specific absolute paths.

## 11. Acceptance corpus

Create an offline corpus covering:

- ZIP aliases and tar archive with preserved nested/IP:PORT paths;
- public/ignored/malformed IPs across byte boundaries;
- executable/script candidates with file DB hit/miss/ambiguity;
- several equivalent/invalid GitHub address forms and corrected card;
- harmless YARA match and successful no-match;
- unavailable/incompatible DB/cache states;
- hostile archive paths/special entries;
- read/mutation/timeouts and one unexpected adapter exception; and
- duplicate/replacement archive at the same filename.

Expected reports for `sample.zip.en_dec`:

```text
output/sample.zip.en_dec-ipintel.md
output/sample.zip.en_dec-fileintel.md
output/sample.zip.en_dec-ghintel.md
output/sample.zip.en_dec-yara.md
```

Assertions cover deterministic normalized content excluding declared generated timestamps,
exact staging/report provenance, and unchanged producer DB/cache hashes.

## 12. Reliability and soak verification

Run:

- clean install/startup;
- continuous and one-shot modes;
- restart with ready/pending/failed entries;
- injected interruption at staging/report durable boundaries;
- sequential multi-capture queue including failures;
- producer DB/cache replacement between captures;
- disk-space and configured budget exhaustion; and
- representative sustained workload within documented limits.

Network must be denied throughout. Confirm no descriptor/process leak and stable memory after
many captures.

## 13. Release artifacts

Require:

- passing verification suite and recorded environment/tool versions;
- supported config examples and runbook;
- package artifacts with checksums and content audit;
- baseline performance/resource report;
- known limitations and deferred items;
- migration/rollback notes for staging state and report naming; and
- confirmation that designs and implementation status agree.

## 14. Exit gate

Implementation 06 is complete only when:

- one archive produces all enabled exact canonical reports from one trusted staging generation;
- failure/unavailability of one adapter leaves others intact and status unambiguous;
- the full corpus and recovery/soak suite pass with network denied;
- producer DBs and cache generations remain unchanged;
- clean installation and operator procedures are reproducible; and
- no critical issue permits path escape, captured-code execution, writable intelligence,
  unbounded hostile output, stale-report ambiguity, or report ownership violation.

Next optional work: [`IMPLEMENTATION_07_SCALE_CORRELATION.md`](IMPLEMENTATION_07_SCALE_CORRELATION.md).
