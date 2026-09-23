# IMPLEMENTATION 07: Scale and Optional Correlation

## 1. Objective and status

Optimize and extend only after the sequential four-processor release is correct, secure, and
measured. This phase is optional and must preserve every Implementation 01-06 invariant.

Status: **implemented (Track A inventory foundation only)**. The dispatcher can optionally emit a
versioned, bounded `artifact_inventory` record after trusted staging. It is derived only from the
verified manifest and is not yet used to shortcut any processor traversal or read. Sequential
dispatch remains the supported path; concurrency, JSON result publication, correlation, and new
artifact analyzers remain deferred until their own decision gates are met.

## 2. Decision gates

Before selecting work, capture:

- corpus size, file count/type distribution, and archive expansion;
- per-processor directory walks, bytes read, CPU time, wall time, and peak RSS;
- SQLite/cache/report timing;
- disk capacity/throughput and staging growth;
- queue wait and capture throughput; and
- deterministic output hashes excluding declared timestamps.

Approve a proposal only when it states the bottleneck, expected improvement, security impact,
compatibility impact, rollback, and benchmark acceptance threshold.

## 3. Track A — shared immutable artifact inventory

Potential goal: avoid repeated tree walks without forcing processors to share eligibility
semantics.

Define a versioned inventory generated from the trusted staged manifest containing only stable
filesystem facts such as relative path, regular-file type, size, and trusted manifest digest.
Processors still own:

- hidden/depth policy;
- content reads and mutation verification;
- executable classification;
- IP/GitHub tokenization;
- YARA selection/matching; and
- evidence/metric semantics.

The inventory must not mark a file executable, benign, malicious, or readable for a processor.
If staged content changes or inventory/manifest identity differs, reject it rather than falling
back silently.

Tests compare every processor record/metric/report with and without inventory acceleration.

Implemented foundation: `ArtifactInventory` runs only when explicitly included after
`stage_input` (the unified profile enables it). It copies sorted file/directory path, type, size,
and file digest facts from the trusted manifest and includes a canonical manifest SHA-256 plus
capture/run identity. It rejects malformed manifests, excess entries, duplicate facts, altered
manifest identities, or mixed-capture inventory. It never reads captured bytes, classifies a
file, or persists new state. No adapter currently consumes the inventory; this is intentional
until a benchmark identifies a traversal bottleneck and equivalence tests can cover the selected
consumer.

## 4. Track B — capture-level concurrency

Potential goal: process independent captures concurrently while keeping one capture's staging
and reports coherent.

Prerequisites:

- replace the single global staging-root lock with reviewed capture/report-slot locks or retain
  serialized staging and parallelize only analysis;
- preserve atomic staging reservation and recovery;
- serialize canonical report refreshes for the same source-relative filename;
- use one SQLite read session/snapshot per processor/capture;
- pin one YARA generation per capture;
- bound global plus per-capture worker/process/file-descriptor/memory/disk usage; and
- define deterministic per-capture results even when completion order changes.

Backpressure must reject/defer work explicitly rather than allowing an unbounded event/future
queue. Shutdown drains or checkpoints safely.

Race tests include same filename changed rapidly, different captures sharing DB/cache, report
slot contention, DB/cache replacement, cancellation, worker death, and restart recovery.

## 5. Track C — machine-readable results

Add versioned JSON alongside Markdown only if an integration consumer requires it.

Schema requirements:

- top-level schema version, capture/source/staging identity, run time, adapter status;
- typed observations/lookups/hits/errors with current evidence and producer provenance;
- explicit null versus absent semantics;
- bounded fields and deterministic ordering;
- no matched bytes, secrets, raw provider payloads, or unrestricted captured content; and
- atomic report-slot publication with a suffix such as `-triage.json` defined in a separate
  compatibility decision.

Golden round-trip/forward-compatibility tests are required. Markdown remains human-facing and
must be derived from the same normalized result, not independently divergent logic.

## 6. Track D — correlation processor

Correlation is a new downstream processor, not hidden behavior in the four evidence adapters.
It consumes normalized records after all enabled adapters finish.

Candidate correlations:

- IP and file intelligence observed in the same current source path;
- file hash with YARA match provenance;
- GitHub project address near a matched executable/script path; and
- repeated indicators across captures, only through an explicitly designed historical store.

Required output for every correlation:

- claim type and bounded confidence/category;
- exact contributing record IDs/current evidence paths;
- source DB/cache/version provenance;
- deterministic rule/version that produced the correlation;
- assumptions and conflicts; and
- no automatic benign/malicious or infrastructure-role claim unsupported by evidence.

Absence of a hit, absence of a rule match, or adapter failure cannot contribute positive
evidence of benignness. Keep inference distinct from observations and producer facts.

Any historical cross-capture store needs its own privacy, retention, migration, deduplication,
and backup design; do not overload producer databases or staging state.

## 7. Track E — additional container/artifact analyzers

Nested archives, disk images, firmware, packet captures, office documents, and APK/container
internals require separate processors and threat models. For each proposed analyzer specify:

- exact supported formats/content detection;
- recursion, expansion, file-count, byte, time, and nesting limits;
- path/link/special-file behavior;
- sandbox/native-library risk;
- provenance from container/member to current evidence;
- partial/failure semantics; and
- independent test corpus and optional dependency boundary.

Do not broaden the base unarchiver implicitly or mount captured images on the host.

## 8. Benchmark protocol

Use reproducible inert corpora with declared hashes and profiles:

- many small files;
- few large files;
- mixed executable/text/binary;
- high indicator/match density;
- zero findings; and
- configured limit boundaries.

For each change record median/tail wall time, CPU, peak RSS, read bytes, filesystem operations,
report size, and throughput over repeated runs. Compare normalized record/report hashes.

An optimization is accepted only when it materially improves its declared metric without
regressing security gates, determinism, error isolation, or representative worst-case resource
usage beyond an approved bound.

## 9. Regression matrix

Every selected track reruns:

- hostile archive/path/recovery suite;
- staged-record/report-slot ownership suite;
- all processor unit/integration fixtures;
- offline/network/Git/provider prohibition guards;
- producer DB/cache immutability hashes;
- dependency replacement between captures;
- one/multi-worker deterministic equivalence where applicable; and
- complete unified acceptance corpus.

Concurrency work adds race/fault injection and sanitizer/resource-leak runs appropriate to the
platform.

## 10. Rollout and rollback

Ship optimization features behind explicit versioned configuration with the sequential path as
a supported fallback until equivalence and soak evidence is sufficient. A rollback must not
require downgrading or discarding producer databases, staged captures, manifests, or reports.

For persistent new state:

- version schema/formats;
- migrate transactionally with backup/compatibility checks;
- reject unknown newer versions;
- document downgrade/read compatibility; and
- separate cleanup from migration.

## 11. Exit gate

An Implementation 07 track is complete only when:

- a measured baseline and explicit target justified the work;
- normalized evidence/report behavior remains equivalent or has an approved versioned change;
- all Implementation 01-06 invariants and regression suites pass;
- resource use remains bounded under adversarial and representative corpora;
- rollout, observability, and rollback are documented/tested; and
- benchmark evidence shows the promised material benefit.

Completion of one track does not imply completion of all deferred tracks.
