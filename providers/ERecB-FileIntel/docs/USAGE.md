# Usage

ERecB-FileIntel scans files, hashes executable content, enriches hashes through intelligence providers, and stores results in SQLite.

## Configuration

Start from the example configuration:

```bash
cp config.example.yaml config.yaml
```

Important settings:

| Setting | Description |
| --- | --- |
| `input_dir` | Directory monitored by watcher mode. |
| `watch_depth` | Relative directory depth that counts as a new watch target. |
| `database_path` | SQLite database location. Default is `dbs/fileintel.sqlite3`. |
| `scan.follow_symlinks` | Whether recursive scans follow symlinks. Default is `false`. |
| `enrichment.enabled_providers` | Provider list. Initial supported value is `ctx_io`. |
| `providers.ctx_io.api_key_path` | File containing the CTX.IO API key. |

The default API key path is:

```text
ctx_io_api_key.txt
```

The API key file should contain only the key value. Request imports do not query CTX.IO and do
not require this file. `homework run` checks the key before leasing any requests; alternatively
set `CTX_IO_API_KEY` in the connected machine's environment.

## Initialize Database

```bash
erecb-fileintel --config config.yaml init-db
```

This creates the SQLite schema at `database_path`.

`init-db` is non-destructive. If a compatible File Intel database already exists at that path, its records remain intact and later scans extend it. The command rejects an unrelated, corrupt, or unsupported newer database rather than overwriting it.

## Manual Scan Mode

Run a recursive scan against a specific directory:

```bash
erecb-fileintel --config config.yaml scan /path/to/target
```

The scanner:

1. Walks the target directory recursively.
2. Uses `python-magic` to classify files.
3. Selects executable files and executable scripts.
4. Computes SHA-256 and MD5.
5. Stores local observations in SQLite.
6. Calls enabled intelligence providers.
7. Merges provider data into canonical records.

The command prints a compact summary:

```text
scan_job_id=1 status=succeeded files_seen=10 executables_found=2 errors=0
```

## Watcher Mode

Run continuous watcher mode:

```bash
erecb-fileintel --config config.yaml watch
```

Watcher mode monitors `input_dir` and scans newly detected directories at `watch_depth`.

Example:

```yaml
input_dir: in
watch_depth: 1
```

With this setting, `in/a` is detected and scanned. If `in/a/b` is created later, it is not treated as a separate new watch target because the configured depth is only `1`.

To detect second-level directories such as `in/a/b`, use:

```yaml
watch_depth: 2
```

Watcher state is stored in the database, so already detected directories are not rescanned automatically after restart.

## Merge Databases

Merge a database copied from another machine into the local database:

```bash
erecb-fileintel merge-db \
  --source dbs/fileintel2.sqlite3 \
  --dest dbs/fileintel.sqlite3 \
  --backup
```

The destination is updated in place; the source is opened read-only. `--backup` creates a timestamped SQLite backup beside the destination before the merge. Stop watcher processes that use the destination database before merging.

Preview the result first without modifying the destination:

```bash
erecb-fileintel merge-db \
  --source dbs/fileintel2.sqlite3 \
  --dest dbs/fileintel.sqlite3 \
  --dry-run
```

The merge keeps scan history from both databases and remaps internal IDs. File names and tags are unioned; `malicious=yes` cannot be downgraded. When the same file has different `magic` values, the value from the record with the newer `updated_at` is used. Provider lookup events are preserved as history, including duplicates. Raw provider-response files are not copied; a missing path is reported as a warning.

## Summary

Print database counts:

```bash
erecb-fileintel --config config.yaml show-summary
```

Example output:

```text
files=4 malicious=1 tags=3 scans=2
```

## Executable Detection

The initial detector recognizes common executable formats and executable scripts, including:

- PE32 and PE32+.
- DLL, SYS, OCX, and MSI.
- ELF and shared objects.
- Mach-O.
- DEX and APK extension fallback.
- PowerShell and shell scripts.

Magic detection is preferred. Extension matching is used as a fallback.

## CTX.IO Enrichment

CTX.IO is queried with SHA-256 when available.

Collected fields include:

| Stored field | CTX.IO source |
| --- | --- |
| `sha256_hash` | `ctx_data.hash.sha256` |
| `md5_hash` | `ctx_data.hash.md5` |
| `magic` | `ctx_data.file_type` |
| `malicious` | `ctx_data.detect` |
| `tags` | `ctx_data.tags` and `ctx_data.threat_types` |
| `file_names` | `ctx_data.file_names` plus local observed names |

`malicious` is set to `yes` when `ctx_data.detect` is anything other than `normal`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Scan completed with recoverable errors. |
| `2` | Configuration error. |
| `3` | Fatal scan error. |
| `4` | Database error. |
| `5` | Provider authentication error. |
| `130` | Interrupted by user. |
