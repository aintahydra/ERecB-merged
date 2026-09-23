# Database Reuse and Merge Design

## 1. Purpose

This document defines two related changes for ERecB-IPIntel:

1. Make reuse of an existing SQLite database an explicit, validated behavior.
2. Add a command that merges one compatible IP Intel SQLite database into another.

The default database remains:

```text
dbs/ipintel.sqlite3
```

Example:

```text
erecb-ipintel merge-db --source dbs/ipintel2.sqlite3 --dest dbs/ipintel.sqlite3
```

The source is never modified. The destination receives the combined intelligence, observations, and provider audit history.

## 2. Current State

The current implementation has schema version `1`. Schema versioning is represented by the `schema_migrations` table, with a row whose `version` is `1`; there is no separate `schema_version` table.

The implemented schema contains:

- `schema_migrations`
- `ip_entities`
- `ip_observations`
- `ip_reverse_dns`
- `ip_related_iocs`
- `ip_related_actors`
- `provider_runs`
- `provider_ip_results`
- `visited_directories`

`Database.initialize()` currently uses `CREATE TABLE IF NOT EXISTS`. This correctly reuses a valid v1 database, but it does not distinguish a valid database from an unrelated or incomplete SQLite file. The update must add explicit validation before normal reuse and before a merge.

## 3. Decisions

The following policies are decided for the first merge implementation.

| Topic | Decision |
| --- | --- |
| Destination backup | Create one only when `--backup` is supplied. |
| Scalar conflicts | The value from the entity with the more recent `last_updated_local` wins. On an equal timestamp, retain the destination value and report the conflict. |
| Discovery state | Do not merge `visited_directories`. Merging it could incorrectly suppress discovery in the destination environment. |
| Provider audit history | Preserve all `provider_runs` and `provider_ip_results`, including duplicate historical lookups. |

The merge is deliberately additive for intelligence arrays and audit records. It does not delete rows from the destination.

## 4. Required Behavior

### 4.1 Existing Database Reuse

When a configured database path already exists, the application must:

1. Verify that it is a readable SQLite database.
2. Read and validate its migration versions and required v1 tables and columns.
3. Reject an incompatible, partial, or newer unsupported database with a clear error.
4. Run supported migrations, if any are needed, before using it.
5. Preserve all existing rows.

When the configured path does not exist, the application must create its parent directory, create the SQLite file, and initialize the current schema.

An empty existing SQLite file is treated as a new database and initialized. A non-empty database without the expected schema is rejected; it must never be silently populated with IP Intel tables.

### 4.2 Database Merge

The command merges one source database into one destination database:

```text
erecb-ipintel merge-db --source SOURCE_DB --dest DEST_DB [--backup] [--dry-run]
```

- `SOURCE_DB` must exist, be readable, and be a compatible supported schema.
- `DEST_DB` may be an existing compatible database or a missing path. A missing destination is initialized to the current schema before importing source data.
- Source and destination must resolve to different files. The command rejects identical resolved paths and identical underlying files.
- The source is opened SQLite read-only, using a read-only connection URI.
- The destination is modified only after validation succeeds.
- `--dry-run` performs all validation and calculates the same summary without creating a backup or changing the destination.
- `--backup` creates a timestamped SQLite backup of the destination immediately before its merge transaction. It must use SQLite's backup API rather than a raw file copy, so it remains correct if WAL mode is enabled later.

The command must not modify the source under any option.

## 5. Schema Compatibility and Validation

Implement a single schema-inspection routine used by normal database opening and merge:

1. Open the database and run a simple SQLite query.
2. Inspect `schema_migrations`.
3. Require exactly the supported migration range for v1 (version `1`, with no version greater than the application supports).
4. Inspect `sqlite_master` and `PRAGMA table_info` to ensure every required v1 table and column exists.
5. Enable foreign keys and run `PRAGMA foreign_key_check`.

Validation errors must name the database path and safe structural reason, such as `missing table ip_entities` or `unsupported schema version 2`. They must not attempt a partial repair.

The required v1 tables are the nine tables in section 2. Required columns and constraints are defined by the v1 schema in `src/erecb_ipintel/db.py`; the validator should keep an explicit table-to-required-column mapping rather than comparing raw DDL text.

## 6. Merge Semantics

### 6.1 IP Entity Identity and Scalar Fields

`ip_entities.ip` is the canonical cross-database identity. Source IDs are local identifiers and must never be copied as destination IDs.

For each source entity:

1. Canonicalize and validate its `ip` defensively.
2. Insert it when absent, retaining the source's `first_seen_local` and `last_updated_local`.
3. When it already exists, retain the earliest non-null `first_seen_local`.
4. Compare `last_updated_local` timestamps to choose scalar values (`ipv4`, `ipv6`, `country_code`, and `whois`). The newer entity's non-null scalar values win. A null source value never erases a non-null destination value.
5. If the timestamps are equal and conflicting non-null values exist, retain the destination scalar value and increment a scalar-conflict warning counter.
6. Set `malicious` to `Yes` if either record is `Yes`; otherwise retain `No` when either record is `No`, and null only when neither record has a value.
7. Set `last_updated_local` to the later of the source and destination timestamps, not the wall-clock merge time.

The current schema has no field-level provenance. Provider-result audit records preserve the underlying lookup history but cannot identify which lookup set each individual scalar. This is an accepted v1 limitation.

### 6.2 Observations and Intelligence Collections

For each IP mapped to its destination entity ID:

- Merge `ip_observations` by `(ip_entity_id, source_path)`. When a duplicate observation exists, retain the earliest `observed_at` and retain the destination `extraction_file`. The current schema cannot distinguish same-text paths from different machines; that limitation is documented rather than guessed around.
- Merge reverse DNS, related IOCs, and related actors by their existing unique keys. Preserve the earliest `first_seen_local` when a value already exists.
- Never remove intelligence values from the destination.

### 6.3 Provider Audit History

Every source `provider_runs` row is appended to the destination and receives a new destination run ID. Its status, timestamps, input file, and counts are preserved.

Every source `provider_ip_results` row is appended with:

- the remapped destination provider-run ID;
- the destination `ip_entity_id` found from the source result's source IP; and
- all provider metadata, result status, response code, transaction ID, timestamps, safe error summary, and raw response JSON unchanged.

No audit deduplication occurs. This preserves a complete record of collection attempts from both databases.

### 6.4 Discovery State

`visited_directories` is excluded from the merge. Its paths and processing state are local to a particular input-root environment and must not alter automatic discovery in the destination.

An `--include-visit-state` option is out of scope for the first implementation. It can be added later only with explicit path-identity and status-conflict rules.

## 7. Merge Workflow

```text
1. Parse and resolve CLI paths.
2. Reject same-file source and destination arguments.
3. Open and validate the source read-only.
4. Inspect and validate the destination if it exists; otherwise record that a new v1 destination is planned.
5. If --dry-run, calculate and print the merge summary, then exit without creating a destination or backup.
6. If --backup and the destination exists, create a timestamped SQLite backup of it.
7. Create a missing destination schema, then begin one destination transaction with foreign keys enabled.
8. Read source data in dependency order and merge entities, child values, observations,
   provider runs, and provider results, maintaining ID maps.
9. Run foreign-key verification on the uncommitted destination data.
10. Commit once and print the summary.
```

If any fatal error occurs after the transaction starts, roll it back. The source remains unchanged; the destination remains unchanged except for an optional backup created before the transaction.

Foreign-key dependency order is:

```text
ip_entities
  -> ip_observations, ip_reverse_dns, ip_related_iocs, ip_related_actors
provider_runs
  -> provider_ip_results (also mapped to ip_entities)
```

The implementation should iterate source rows in bounded batches rather than load raw provider-response JSON for the whole source database into memory.

## 8. CLI Design

Add this subcommand to `erecb-ipintel`:

```text
erecb-ipintel merge-db --source SOURCE_DB --dest DEST_DB [--backup] [--dry-run]
```

| Option | Required | Meaning |
| --- | --- | --- |
| `--source PATH` | Yes | Compatible source DB; it is opened read-only. |
| `--dest PATH` | Yes | Compatible destination DB to update, or a new path to initialize. |
| `--backup` | No | Create a timestamped backup of an existing destination before merge. |
| `--dry-run` | No | Validate and calculate the summary without modifying either DB. |

The command returns zero only after a successful commit (or successful dry run). Invalid arguments, invalid schemas, I/O failures, backup failures, and transaction failures return non-zero.

The JSON summary should include at least:

- source and destination paths;
- whether the operation was a dry run and whether a backup was created;
- IP entities inserted and merged;
- observations and collection values inserted or already present;
- provider runs and provider results appended;
- scalar conflicts resolved by destination timestamp tie-breaking; and
- `visited_directories` skipped.

## 9. Implementation Plan

1. Refactor `db.py` so opening an existing DB validates its schema rather than relying only on `CREATE TABLE IF NOT EXISTS`. Keep new-database creation separate from validation.
2. Add a schema metadata definition shared by initializer and validator, including the current supported migration version.
3. Add a read-only source connection helper and a SQLite backup helper based on `Connection.backup`.
4. Implement `Database.merge_from(source, dry_run=False)` (or a dedicated merge service) with transaction control, ID mapping, timestamp comparison, and summary counters.
5. Add `merge-db` argument parsing and command dispatch in `cli.py` without loading the configured default DB before explicit source/destination validation.
6. Add merge-focused tests using two temporary SQLite databases with overlapping entities and distinct IDs.
7. Update `docs/USAGE.md` and `README.md` with the command, its source/destination behavior, `--dry-run`, and optional backup guidance.

## 10. Test Plan

Unit and integration coverage must include:

- initialize a missing database and reuse a valid v1 database without data loss;
- reject a non-SQLite file, unrelated SQLite file, partial schema, unsupported newer schema, and foreign-key violation;
- reject source and destination that refer to the same file;
- merge an entity present only in source;
- merge an overlapping IP while newest `last_updated_local` scalar values win;
- retain destination values and report a conflict when timestamps are equal;
- verify `Yes` always wins for `malicious`;
- deduplicate collection values and preserve earliest timestamps;
- preserve the full source provider-run/result history while remapping both foreign keys;
- confirm source DB hashes/content are unchanged after merge;
- confirm `visited_directories` are absent from the destination import;
- verify rollback leaves destination unchanged after an injected failure;
- verify `--dry-run` writes neither a destination update nor a backup; and
- verify `--backup` produces a restorable snapshot of the pre-merge destination.

## 11. Non-goals

The first implementation does not provide multi-source merge, output-to-a-third-file mode, visit-state merging, schema downgrades, conflict-interactive prompts, or field-level provenance. These can be designed later without changing the chosen safety and data-preservation rules.
