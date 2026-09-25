# FileIntel air-gap exchange extension

`erecb-fileintel requests import` validates the shared indicator-only bundle and updates a
separate `fileintel-homework.sqlite3`. Imported SHA-256 hashes have optional MD5 companions;
the SHA-256 is the canonical identity. `homework run --limit` processes eligible requests in
newest-request-first order. The targeted enrichment path upserts a hash-only file entity
without a fabricated scan job, observation, filename, or captured path. Explicit requests
bypass the ordinary success-age reuse policy. If no provider stores intelligence, an unused
hash-only placeholder is removed; the queue and lookup audit retain the unresolved attempt.

`db snapshot` uses SQLite online backup and a checksum manifest. The existing `merge-db`
gains `--intelligence-only`, which omits source scan/watch paths and raw-response paths and
records a source snapshot digest to make repeated imports no-ops. Existing scan-history merge
behavior remains available without that option. Dry-run now operates on an in-memory backup
of an existing destination and never initializes or edits it.

No FileIntel base schema migration is required; the import ledger is an additional
destination-only table. The air-gap maintenance command calls this producer-owned merge.
