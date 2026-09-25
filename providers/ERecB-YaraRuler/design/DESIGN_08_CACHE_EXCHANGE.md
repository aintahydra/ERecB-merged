# YaraRuler compiled-cache exchange extension

`update-rules` fingerprints enabled rule files and their transitive includes together with
compiler runtime/platform identity. If the active generation is verified and inputs are
unchanged, it is reused; `--force-rebuild` always compiles again. Unrelated documentation
changes do not rebuild the cache.

`cache-export --output DIR` publishes one active generation as `manifest.json`, `rules.yac`,
and `transfer.json` with checksums. `cache-import --source DIR` validates the transfer,
copies it to a private staging directory, loads it with the destination's YARA runtime to
check OS/architecture/version compatibility and artifact integrity, and only then switches
the active pointer. Older generations remain for rollback. The source-rule repositories
and quarantine directory are not transferred. The cache manifest version remains 1; the
optional build fingerprint is additional provenance.
