# Offline verification

Run the Phase 1 baseline from the repository root with network access disabled:

```bash
PYTHONPATH=src python -m compileall -q src
PYTHONPATH=src python -m unittest discover -s tests -t . -v
PYTHONPATH=src python -c 'from erecb_triage.config import load_config; [load_config(path) for path in ("config/watcher_unarchiver.yaml", "config/watcher_ipintel.yaml", "config/watcher_fileintel.yaml", "config/watcher_localintel.yaml", "config/watcher_ghintel.yaml", "config/watcher_yara.yaml", "config/watcher_all.yaml")]'
```

The suite uses only Python's standard-library test runner.  It does not import optional
`python-magic`, contact a network service, run Git, or open checked-in producer databases
writable.  Producer schema fixtures are synthetic and are only suitable for temporary test
databases.

Phase 2 baseline result: 21 tests passed with Python's standard-library runner. Enabled
production archive formats are `.en_dec`, `.enc`, `.zip`, and `.tar.gz`. The suite includes
ZIP traversal and Windows-separator rejection, tar-link rejection, extraction limits, pending
publication recovery, corrupted-state rejection, exclusive staging-root locking, deterministic
watcher stabilization, and independent-analysis isolation.

Phase 3 baseline result: 28 tests passed. The suite exercises IP chunk-boundary canonicalization,
IP/File producer schema compatibility against the checked-in databases, synthetic hit and MD5
ambiguity outcomes, fixture SHA-256 immutability, full archive-to-two-report provenance, and
unavailable producer-database reports. `python-magic` remains optional; tests use deterministic
extension fallback where native libmagic is unavailable.

Phase 4 baseline result: 33 tests passed. The GHIntel suite covers strict transport-form
normalization, split-invariant byte extraction, synthetic corrected project cards, unknown
repository misses, checked-in DB capability inspection, and an archive-to-`-ghintel.md`
integration path without Git or network access.

Phase 5 single-worker baseline result: 37 tests passed. The YaraRuler suite validates the
canonical UUID cache pointer, manifest/artifact digest verification, source-URL credential
redaction, YARA/yara-python runtime compatibility, strict profile settings, and an
archive-to-`-yara.md` report through a harmless injected compiled-rule loader. It proves target
bytes are not rendered. The core package and non-YARA profiles remain importable without the
optional package; the dedicated `watcher_yara.yaml` profile fails startup with an actionable
dependency error until `.[yara]` is installed.

Phase 6 operational baseline result: 40 tests passed. The unified acceptance test stages one
archive and verifies all four exact adapter reports plus `-summary.md`; the summary does not make
a malware/benign verdict and contains only current-generation report links. The readiness test
proves `--check`-equivalent diagnostics do not create an absent staging index. A missing YARA
cache produces an explicit degraded YARA report/summary state without suppressing the other
reports. The CLI readiness check and a no-build-isolation wheel build both succeed.

Phase 7 Track A foundation result: 42 tests passed. The inventory integration test verifies that
the optional post-staging record contains only bounded manifest facts, is deterministically
ordered, never contains captured bytes, and rejects altered-manifest or mixed-invocation use.
It does not claim a traversal optimization or enable concurrency; all adapters continue using
their established, independently verified scan paths.
