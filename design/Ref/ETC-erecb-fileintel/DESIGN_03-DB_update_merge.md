# Database Update and Merge Design

## 1. Purpose

This document plans two related improvements for ERecB-FileIntel:

1. Make existing database reuse an explicit supported behavior.
2. Add a tool to merge two File Intel SQLite databases into one database.

The default database path is:

```text
dbs/fileintel.sqlite3
```

Example merge case:

```text
dbs/fileintel.sqlite3
dbs/fileintel2.sqlite3
```

Expected result: one database containing the combined intelligence and scan history from both inputs, without weakening existing file intelligence.

## 2. Current State

The current implementation already behaves mostly like an extendable database:

- `connect(database_path)` opens the configured SQLite file.
- SQLite creates the physical database file if it does not exist.
- `initialize_schema()` runs `CREATE TABLE IF NOT EXISTS` statements.
- Normal scan processing upserts canonical file records by SHA-256.
- Local file names, tags, observations, provider lookups, scan jobs, errors, and watcher state are appended or inserted with uniqueness checks where defined.

This means the database is not intentionally recreated on each run.

Current limitations:

- The design documents do not explicitly state the "reuse existing DB" contract.
- There is no explicit startup validation that an existing database is compatible.
- `schema_version` is present, but migration behavior is minimal.
- There is no CLI command for merging two File Intel databases.
- Existing row IDs cannot be copied directly from one database into another because primary keys may collide.

## 3. Required Behavior

### 3.1 Existing Database Reuse

When `database_path` points to an existing SQLite database:

- The tool must open the existing database.
- The tool must preserve all existing records.
- The tool must create the schema for a new or empty SQLite database only.
- The tool must reject incompatible databases with a clear error.
- A scan must extend the database by adding new observations, names, tags, provider lookups, and merged intelligence.

When `database_path` does not exist:

- The parent directory should be created.
- A new SQLite database should be created.
- The current schema should be initialized.

### 3.2 Database Merge

The tool should merge one source database into one destination database.

Baseline command:

```text
erecb-fileintel merge-db --source dbs/fileintel2.sqlite3 --dest dbs/fileintel.sqlite3
```

The destination database is modified. The source database is read-only.

Optional safer command:

```text
erecb-fileintel merge-db --source dbs/fileintel2.sqlite3 --dest dbs/fileintel.sqlite3 --backup
```

With `--backup`, the tool creates a timestamped copy of the destination before modifying it.

Alternative explicit output mode:

```text
erecb-fileintel merge-db --source dbs/fileintel.sqlite3 --source dbs/fileintel2.sqlite3 --output dbs/fileintel_merged.sqlite3
```

This mode creates a new merged database and leaves both source databases unchanged. It is safer but slightly more complex to implement.

Recommended first implementation:

```text
erecb-fileintel merge-db --source SOURCE_DB --dest DEST_DB [--backup]
```

## 4. Schema Compatibility

Before normal startup or database merge, the tool should validate:

- The database file is a readable SQLite database.
- Required tables exist.
- Required columns exist.
- `schema_version` exists and contains a supported version.
- Foreign key checks pass.

Required tables for current version:

- `schema_version`
- `files`
- `file_names`
- `tags`
- `scan_jobs`
- `scan_errors`
- `file_observations`
- `provider_lookups`
- `watch_directories`

Compatibility policy:

| Case | Behavior |
| --- | --- |
| DB does not exist | Create new DB and schema. |
| DB exists and schema is current | Use as-is. |
| DB exists and schema is older but migratable | Run migrations, then use. |
| DB exists and schema is newer | Refuse to open unless `--allow-newer-schema` is explicitly added later. |
| DB exists but is empty | Initialize the current File Intel schema. |
| DB exists but is not File Intel DB | Refuse with clear error. |
| DB file is corrupt | Refuse and do not modify. |

## 5. Merge Semantics

The merge must preserve canonical intelligence quality. It should never downgrade a destination value.

### 5.1 File Identity

Canonical identity order:

1. SHA-256.
2. MD5 only when SHA-256 is missing.

Rules:

- If source and destination have the same SHA-256, they represent the same file.
- If source has SHA-256 and destination only has matching MD5, merge into the destination record and fill SHA-256.
- If source only has MD5 and destination has matching MD5, merge into the destination record.
- If MD5 matches but SHA-256 conflicts, keep separate file records and record a merge warning.
- Never overwrite a real SHA-256 with a different real SHA-256.
- Never overwrite a real MD5 with a different real MD5 unless it belongs to a confirmed same SHA-256 record and the conflict is explicitly handled.

### 5.2 Canonical `files` Merge

Field rules:

| Field | Merge rule |
| --- | --- |
| `sha256_hash` | Fill missing value only. Conflicting real values are errors/warnings. |
| `md5_hash` | Fill missing value only. Conflicting real values are warnings unless SHA-256 proves same file. |
| `magic` | Fill a missing value. When both values differ, use the value from the record with the newer valid `updated_at`; otherwise keep the destination value and emit a warning. |
| `malicious` | Use severity order: `yes` > `no` > `unknown`. |
| `created_at` | Keep earliest timestamp. |
| `updated_at` | Keep latest timestamp or set merge time after changes. |

### 5.3 Set-Like Tables

Tables that behave like sets should be merged by natural keys.

`file_names`:

- Natural key: destination `file_id`, `file_name`, `source`.
- Insert missing names.
- Preserve `first_seen_at`; use earliest timestamp when the same name/source exists in both.

`tags`:

- Natural key: destination `file_id`, `tag`, `source`.
- Insert missing tags.
- Preserve `first_seen_at`; use earliest timestamp when the same tag/source exists in both.

### 5.4 Scan History Tables

Scan history should be copied with new destination IDs.

`scan_jobs`:

- Always insert source scan jobs as new destination scan jobs.
- Preserve mode, root path, status, timestamps, and counters.
- Maintain a source-to-destination scan job ID map.

`scan_errors`:

- Copy errors and remap `scan_job_id`.

`file_observations`:

- Copy observations and remap:
  - `scan_job_id`
  - `file_id`
- Preserve observed path, name, magic, hashes, and timestamp.

Rationale: scan jobs are historical events. Even if two databases scanned the same directory, both histories may be useful.

### 5.5 Provider Lookup History

`provider_lookups` should be copied with new destination IDs.

Rules:

- Remap `file_id` to the merged destination file ID.
- Preserve provider, query hash, query hash type, status, HTTP status, timestamps, raw response path, and error message.
- If the exact same provider lookup already exists in destination, duplicate handling is configurable.

Recommended first implementation:

- Insert all source provider lookup rows as history.
- Do not deduplicate provider lookup rows initially.

Reason: provider lookups are audit events. Duplicate events are acceptable and simpler than accidentally dropping useful history.

### 5.6 Watcher State

`watch_directories` should be merged carefully because watcher state controls future scans.

Natural key:

```text
input_dir, relative_path, watch_depth
```

Rules:

- Insert missing watcher rows.
- If destination already has the same watcher key:
  - Keep the earliest `first_seen_at`.
  - Keep the latest or most useful status by precedence.
  - Remap `last_scan_job_id` if copied from source and no better destination value exists.

Status precedence:

```text
scanned > scanning > new > failed
```

This intentionally lets a completed scan state win over a `failed` state while retaining the source scan job and error history. A user can still manually scan the directory again after the merge.

## 6. Merge Workflow

Recommended internal workflow:

```text
1. Parse CLI options.
2. Resolve source and destination paths.
3. Refuse if source and destination are the same file.
4. Open source read-only.
5. Open destination read/write.
6. Validate both schemas.
7. Create destination backup if --backup is set.
8. Begin transaction on destination.
9. Build source file_id -> destination file_id map:
   a. For each source file, find matching destination file.
   b. Merge canonical fields or insert new file.
10. Merge file_names and tags.
11. Copy scan_jobs and build source scan_job_id -> destination scan_job_id map.
12. Copy scan_errors.
13. Copy file_observations with remapped file_id and scan_job_id.
14. Copy provider_lookups with remapped file_id.
15. Merge watch_directories with remapped last_scan_job_id.
16. Run `PRAGMA foreign_key_check`.
17. Commit transaction.
18. Print summary.
```

If any fatal error occurs before commit:

- Roll back the transaction.
- Leave the source unchanged.
- Leave the destination unchanged except for an optional backup file.

## 7. CLI Design

Add command:

```text
erecb-fileintel merge-db --source SOURCE_DB --dest DEST_DB [--backup]
```

Arguments:

| Option | Required | Meaning |
| --- | --- | --- |
| `--source` | Yes | Source File Intel DB to read from. |
| `--dest` | Yes | Destination File Intel DB to modify. |
| `--backup` | No | Create destination backup before merge. |
| `--dry-run` | No | Validate and calculate merge summary without modifying destination. |
| `--conflict-policy` | No | Conflict behavior. Initial value: `warn`. |

Recommended first command set:

```text
erecb-fileintel merge-db --source dbs/fileintel2.sqlite3 --dest dbs/fileintel.sqlite3 --backup
erecb-fileintel merge-db --source dbs/fileintel2.sqlite3 --dest dbs/fileintel.sqlite3 --dry-run
```

Possible summary output:

```text
source=dbs/fileintel2.sqlite3
dest=dbs/fileintel.sqlite3
files_inserted=10
files_merged=3
tags_inserted=18
file_names_inserted=12
scan_jobs_copied=2
observations_copied=40
provider_lookups_copied=13
watch_directories_inserted=1
warnings=0
status=succeeded
```

## 8. Implementation Plan

### 8.1 Existing DB Reuse Hardening

Files to update:

- `src/erecb_fileintel/db/migrations.py`
- `src/erecb_fileintel/db/repository.py`
- `src/erecb_fileintel/db/connection.py`
- `src/erecb_fileintel/app.py`
- `docs/USAGE.md`
- tests

Tasks:

1. Add a schema validation function.
2. Confirm `initialize_schema()` remains non-destructive.
3. Add tests showing records remain after repeated `init-db`.
4. Add tests showing a second scan extends an existing database.
5. Add user-facing documentation that existing DB files are reused and extended.

### 8.2 Merge Tool

New source files:

```text
src/erecb_fileintel/db/merge.py
```

CLI updates:

```text
src/erecb_fileintel/cli.py
src/erecb_fileintel/app.py
```

Suggested internal functions:

```text
validate_fileintel_db(conn) -> SchemaValidationResult
merge_databases(source_path, dest_path, backup=False, dry_run=False) -> MergeSummary
find_or_create_dest_file(source_file_row) -> dest_file_id
merge_file_names(source_file_id, dest_file_id)
merge_tags(source_file_id, dest_file_id)
copy_scan_jobs() -> dict[source_scan_job_id, dest_scan_job_id]
copy_scan_errors(scan_job_id_map)
copy_file_observations(file_id_map, scan_job_id_map)
copy_provider_lookups(file_id_map)
merge_watch_directories(scan_job_id_map)
```

Tests:

- Merging into an empty destination DB.
- Merging into a destination DB with the same SHA-256.
- `malicious=yes` wins over `no` and `unknown`.
- Tags and file names are unioned.
- Scan job IDs and file IDs are remapped correctly.
- Source DB is unchanged after merge.
- Dry run does not modify destination.
- Conflicting SHA-256/MD5 cases produce warnings and do not corrupt records.

## 9. Safety Requirements

- Source DB must be opened read-only.
- Destination merge must run in one transaction.
- `PRAGMA foreign_keys = ON` must be enabled.
- `PRAGMA foreign_key_check` must pass before commit.
- Destination backup is recommended by default in documentation.
- Merge should refuse same-file source/destination paths.
- Merge should print a summary and warning count.
- Merge should not delete rows from destination.

## 10. Documentation Updates

Update:

- `docs/USAGE.md`
- `README.md`

Add:

- Explanation that existing databases are extended, not recreated.
- `merge-db` examples.
- Backup recommendation.
- Conflict behavior explanation.

## 11. Finalized Merge Policy

The merge policy is finalized as follows:

1. `merge-db` updates the destination database in place. The source database is always opened read-only.
2. Provider lookup rows are copied exactly as audit history. Duplicate lookup events are allowed.
3. Watcher state is merged conservatively: `scanned > scanning > new > failed`. When statuses differ, the command warns and preserves both underlying scan histories.
4. When identical files have different non-empty `magic` values, the value on the fresher record wins. Freshness is the latest valid `files.updated_at`. If freshness is equal or invalid, the existing destination value is retained and a warning is emitted.
5. Database rows only are merged. `raw_response_path` is retained as text and the command warns when the referenced file is unavailable locally. Copying raw response files is a future optional feature.
6. Scan jobs, errors, observations, and provider lookups from both databases are preserved. Foreign-key IDs are remapped while copying source history.
7. `--backup` is optional. Documentation recommends it for every in-place production merge; `--dry-run` previews results without changing the destination.

## 12. Acceptance Criteria

The implementation is complete when:

- Running `init-db` against an existing DB preserves current records.
- Running scan/watch against an existing DB extends it.
- `merge-db --dry-run` reports expected merge counts without modifying destination.
- `merge-db --source dbs/fileintel2.sqlite3 --dest dbs/fileintel.sqlite3 --backup` merges records correctly.
- Source DB remains unchanged after merge.
- Destination passes `PRAGMA foreign_key_check`.
- Unit tests cover file identity merge, set union fields, scan history remapping, provider lookup copying, and watcher state merge.
- Documentation explains installation, existing DB reuse, and merge usage.
