# IPIntel air-gap exchange extension

The merged request contract is defined by `erecb_triage.exchange` and transported as JSON
plus a SHA-256 sidecar. `erecb-ipintel requests import` validates it before adding canonical
IP identities to a separate `ipintel-homework.sqlite3`. Repeated bundle IDs are no-ops;
distinct requests increment counts and update LIFO priority. `homework run --limit` calls the
existing single-IP provider workflow and keeps no-result/error/rate-limit items eligible for
later retry. Queue state is never copied to the air-gapped machine.

`db snapshot` uses SQLite backup and a checksum manifest. `merge-db` validates schema v1,
supports dry-run/backup, remaps entity and provider-run IDs, uses canonical IP identity,
merges newer non-null scalars and child intelligence, and records the source snapshot digest
for replay safety. It excludes `visited_directories`, connected-machine observations, and
provider-run input paths. The consumer treats rows containing only failed/not-found provider
attempts with no intelligence fields as misses so they can be requested again.

The older `enrich FILE --consume` command retains its extraction-file semantics; use the
homework commands for manually transferred requests. The base v1 intelligence schema is
unchanged; the import ledger is an additional destination-only table.
