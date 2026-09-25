# GHIntel air-gap exchange extension

`ghintel requests import` verifies the shared bundle and rechecks canonical URL identities
against GHIntel's own normalizer before queue mutation. The separate
`ghintel-homework.sqlite3` tracks distinct requests and LIFO priority. `homework run --limit`
upserts URL-only repositories without local Git copies, creates targeted fetch runs, and
uses targeted enrichment. A missing GitHub snapshot or failed enrichment stays homework.

The existing `ghintel db snapshot/verify` is the transfer format. `ghintel db merge` verifies
the snapshot manifest, checks schema/integrity, supports dry-run and backup, and imports
repository identities, GitHub snapshots, GitHub source documents/versions, findings,
evidence, documented people, and language inference with remapped foreign keys. Source
scan roots, local copies, remotes, and corrections are not imported. A finding that depends
on local-only evidence is not activated without that evidence. Existing air-gap corrections
remain local. A destination import ledger makes a repeated snapshot a no-op.

The base GHIntel schema is unchanged; the import ledger is an additional destination-only
table. Connected-side provider caches and HTTP cache are not part of the report-facing merge.
