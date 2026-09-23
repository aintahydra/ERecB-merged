# ERecB Triage Operator Runbook

## Start and verify

Install the base package, then add optional integrations selected by the profile:

```bash
python -m pip install -e '.[fileintel,yara]'
erecb-triage --config config/watcher_all.yaml --check
erecb-triage --once --config config/watcher_all.yaml
```

`--check` is read-only. It does not create the staging index, directories, databases, reports,
or cache generations. Fatal checks block startup; degraded producer databases or a cache mean a
capture can still stage and other adapters can run, but their report/summary records the gap.

Continuous mode uses the same profile without `--once`. Run it as a low-privilege account with
read access to `in/`, producer databases, and the rule cache, plus write access only to
`middle-earth/`, `output/`, and `data/`. Do not grant the service write access to producer DBs,
rule source/cache trees, or capture archives.

## Progress output

The command writes operational progress to standard error at `INFO` level. In one-shot mode it
first announces every direct child being checked, then reports the ready-target count and queues
each stable target. At startup it also lists every configured processor that was constructed and
is ready to run. During a capture, `processor start` and `processor complete` lines identify the
target, phase, processor, elapsed time, and processor error count. For example:

```text
INFO target queued target='sample.zip.en_dec'
INFO target start target='sample.zip.en_dec'
INFO processor start target='sample.zip.en_dec' phase=preprocessor processor=input_stager
INFO processor complete target='sample.zip.en_dec' phase=preprocessor processor=input_stager elapsed_ms=842 errors=0
INFO processor start target='sample.zip.en_dec' phase=analysis processor=ip_retriever
```

Large captures can spend substantial time in `input_stager` while the archive is copied,
validated, and extracted. The start line is therefore the live indication of the current active
processor; the current release does not estimate a byte-completion percentage.

## Persistent operational logs and archive preflight

Normal watcher and one-shot runs write the same operational events to
`logs/erecb-triage.log` by default, relative to the application base directory. The file rotates
at 10 MiB and retains ten older files (`.1` through `.10`) so normal operation cannot consume
unbounded disk space. Configure `logging.file_path`, `logging.max_bytes`, and
`logging.backup_count` in the selected YAML profile for an operator-owned log location. `--check`
remains read-only and does not create a log file.

Before a supported ZIP or TAR archive is copied into private staging, `InputStager` logs an
`archive preflight` record with the archive size, estimated file count, estimated extracted
bytes, safety overhead, required staging bytes, and currently available bytes. A ZIP estimate
uses its central directory; a TAR estimate scans headers. If the estimated file/byte limit is
exceeded or the private staging filesystem cannot hold the archive copy and extraction together,
the target is rejected before copying or extracting. The log records `outcome=rejected` and the
reason, while the target's processor result records a `staging_error`.

## Large-capture memory bounds and reuse

An IP-list singularity is a file with more than 20 distinct valid IPs. IPIntel stops reading that
file at the twenty-first IP, does not submit any IP from it to the local database, and records its
path in both the IPIntel report and capture summary. This avoids treating an IP list as twenty or
thousands of independent enrichment targets. Set
`processors.ip_retriever.ip_singularity_threshold` only when the operational definition of an
IP-list changes.

IPIntel also bounds retained evidence to 1,024 distinct IP observations per file and 10,000 per
capture by default. The singularity threshold must not exceed the per-file bound. Set
`processors.ip_retriever.max_observations_per_file` and
`processors.ip_retriever.max_observations_per_capture` only after accounting for the VM's memory
budget. A capture bound writes an explicit truncation warning into its report and operational log
instead of accumulating unbounded evidence in memory. The other processors continue independently.

## YaraRuler cache setup

`yara_scan` is a read-only consumer. Its default `processors.yara_scan.cache_dir` is
`rules/cache`, which must contain a compiled, immutable cache produced by the separate ERecB
YaraRuler application. A raw clone of a rule repository alone is not sufficient: clone/configure
and run YaraRuler to build or update the cache, then point `cache_dir` to that cache directory and
run `erecb-triage --check` before processing a capture. The Triage service account needs read
access only; it must not write the rule source or cache.

If a shell prints only `killed` while a processor is running, the process received SIGKILL and
cannot write its own final error record. On Ubuntu, check the kernel log for an OOM-killer event:

```bash
sudo journalctl -k -b | grep -Ei 'out of memory|killed process'
```

Increase VM memory or swap as appropriate, retain the processor evidence bounds, and rerun the
same profile. A completed indexed staging capture is reused after its source hash is verified;
the stager no longer applies a new-space preflight before that reuse. Thus an analysis-only rerun
does not require room for another archive copy and extraction.

## Expected outputs

For `in/sample.zip.en_dec`, a successful unified run writes these stable report slots:

```text
output/sample.zip.en_dec-ipintel.md
output/sample.zip.en_dec-fileintel.md
output/sample.zip.en_dec-ghintel.md
output/sample.zip.en_dec-yara.md
output/sample.zip.en_dec-summary.md
```

The report basename is the original archive filename; the timestamped `middle-earth/` directory
is the particular staging generation. The summary links only reports refreshed by that generation.
If an adapter failed before refresh, it explicitly says that an existing report can belong to an
earlier capture.

## Large-capture capacity

The shipped defaults and `watcher_all.yaml` admit archives up to **100 GiB**, extracted content
up to **200 GiB**, and up to **200,000 extracted files** per archive. This covers the stated
80 GB archive / 150 GB extraction / 20,000-item workload and the supplied 134,077-item sample
while retaining bounded archive-bomb
protection. These are binary GiB limits: `107374182400` and `214748364800` bytes respectively.

Before accepting a capture near those limits, plan free storage for the staging algorithm, not
only the final extracted tree. It keeps the original in `in/`, privately copies an archive under
`middle-earth/.partial/`, then extracts it before atomically publishing the result. If `in/` and
`middle-earth/` share a filesystem, reserve at least **450 GiB free** for a capture at the
configured maximum, plus retention and report space. If they are separate filesystems, reserve
the archive size in `in/` and approximately the archive plus extraction limits in
`middle-earth/`. Keep the limits bounded; raising them also raises the maximum disk-consumption
impact of a hostile archive.

## Interpret and recover

Hits are local evidence, not automated remediation. A miss, null verdict, no YARA match,
unavailable lookup, ambiguity, or degraded state is not proof that a capture is benign.

After an interruption, restart the same profile. The dispatcher verifies pending/ready staging
manifests before reuse. Resolve an active staging lock by stopping the other dispatcher rather
than deleting state files. Treat corrupt archives, report-slot collisions, incompatible producer
schemas, and incompatible cache artifacts as operational errors; retain the source archive and
inspect its report/status provenance before retrying.

Replace producer databases or the active YARA cache only between captures. The adapters open a
read-only database session or pin one cache generation per capture, so a replacement affects a
later capture. YaraRuler producer version 0.1.0 has no scan leases: do not prune generations
while any scanner or producer update may be active.

## Retention and backup

Retention is an administrative policy, not watcher behavior. Keep source archives, staged
captures/manifests, `data/staging.sqlite3`, and reports together for the required audit window.
Back up producer DBs and cache generations through their owning applications. Before removing any
ERecB-owned material, stop dispatchers, identify exact completed capture/report paths, make a
recoverable archive or backup, and never recursively delete a broad root based on an unresolved
glob.
