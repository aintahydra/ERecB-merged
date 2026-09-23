# ghintel operations guide

This guide is organized by what you need to do. All examples use the installed `ghintel` command and a local `config.toml` created with `ghintel init`.

## 1. Understand what ghintel does

ghintel is an inventory and evidence tool, not a Git executor or code scanner. It only treats directories with a `.git` directory or worktree-style `.git` file as repositories. It reads Git configuration directly, does not invoke Git, does not follow symlinks, and never executes discovered project code.

It records each local checkout separately but deduplicates canonical GitHub identities such as SSH and HTTPS forms of `github.com/owner/repository`. `origin`, `upstream`, and other remotes remain distinct.

For a concise view of the installed command surface:

```bash
ghintel --help
ghintel doctor --config config.toml
```

Read the project [README](../README.md) for capabilities and safety boundaries.

## 2. Produce an inventory database

1. Put real Git working trees below the configured `paths.input_dir` (default: `in/`). Extracted archives without Git metadata are ignored.
2. Capture local identities and project documents without using any network:

   ```bash
   ghintel discover --config config.toml
   ghintel list --config config.toml
   ```

3. To fetch GitHub metadata and a preferred README, configure GitHub access and run:

   ```bash
   ghintel fetch --config config.toml
   ```

   `ghintel scan --config config.toml` combines discovery and fetch. Use `--refresh` for conditional HTTP requests instead of relying on a fresh cache. Set `github.offline = true` to ensure `scan` performs local discovery only.

   To scan a different corpus and make it the new configured input directory, use an explicit target. ghintel validates the directory, atomically stores its normalized absolute path in `config.toml`, reloads the configuration, and uses it for the same scan:

   ```bash
   ghintel scan --target-dir /media/sf_VMShared/in/20231003 --config config.toml
   ```

   This is a persistent configuration change, not a one-command override. A relative `--target-dir` is resolved from the current shell directory and saved as an absolute path. The target must already exist, `config.toml` must be writable, and a validation/write failure leaves the old value unchanged. Later `discover` and `scan` commands use the saved target. `fetch` does not walk the input directory; it operates on repositories already recorded in the database.

   When the same database has previously scanned another location, the new target is recorded as another logical scan root. Use `ghintel roots list` to inspect those mappings; use `roots remap` instead when an existing corpus was merely relocated.

   A token is optional for public repositories. Anonymous GitHub API access has a much smaller shared quota, so a large fetch may span more than one quota window. When GitHub reports that the quota is exhausted, ghintel saves the completed checkpoints, exits with code `7`, prints the reset time, and provides an exact command such as:

   ```bash
   ghintel resume 13 --config /absolute/path/config.toml --db /absolute/path/dbs/ghintel.sqlite3
   ```

   Run that command after the displayed reset time. Completed repository metadata, READMEs, and profiles are not requested again. Progress such as `Fetching 3/25: github.com/owner/repository` is written to stderr. `github.timeout_seconds` limits individual HTTP operations; it does not shorten GitHub's quota window, and transient `5xx` failures still use bounded retries.

4. To opt into model enrichment after reviewing the provider configuration, prices, source-upload setting, and budgets:

   ```bash
   ghintel doctor --config config.toml --check-provider
   ghintel enrich --config config.toml
   ```

   Target an individual known record with `ghintel enrich -r owner/repository`. `--refresh` bypasses current-finding reuse; `--force-llm` also bypasses a validated response cache. Both remain subject to the configured hard limits.

5. Publish a portable database snapshot only after reviewing its contents:

   ```bash
   ghintel db snapshot --config config.toml --output output/inventory.sqlite3
   ghintel db verify output/inventory.sqlite3
   ```

Snapshots preserve raw investigation data. For a broadly shareable summary, prefer a JSON/CSV export:

```bash
ghintel export --config config.toml --format json --output output/projects.json
ghintel export --config config.toml --format csv --output output/projects-csv
```

## 3. Use a database supplied by someone else

Ask the producer for the SQLite snapshot and, if available, its manifest file. Verify the snapshot before trusting it:

```bash
ghintel db verify /path/to/inventory.sqlite3
```

Create a separate local configuration if you do not already have one:

```bash
ghintel init --config consumer-config.toml
```

Point read commands at the supplied database with `--db`. This leaves your default local database alone:

```bash
ghintel lookup https://github.com/owner/repository \
  --config consumer-config.toml --db /path/to/inventory.sqlite3
ghintel show owner/repository \
  --config consumer-config.toml --db /path/to/inventory.sqlite3
ghintel search "database migration" \
  --config consumer-config.toml --db /path/to/inventory.sqlite3
ghintel list --config consumer-config.toml --db /path/to/inventory.sqlite3
```

`lookup` accepts supported GitHub SSH/HTTP/HTTPS addresses and only reads the local database. `show` additionally accepts `owner/repository` shorthand. `information_status`, `GitHub availability`, documented people, and finding provenance make the limits of the available evidence visible.

Do not run `discover`, `fetch`, `scan`, `enrich`, `correct`, `roots remap`, or `db migrate` against a supplied database unless you are authorized to modify it. Use `export` with a separate output path when you need a derived copy.

If you have also received the original repository corpus at a new path, remap a logical root rather than rediscovering as a separate corpus:

```bash
ghintel roots list --config consumer-config.toml --db /path/to/inventory.sqlite3
ghintel roots remap ROOT_NAME /new/corpus/path --reason "relocated corpus" \
  --config consumer-config.toml --db /path/to/inventory.sqlite3
```

Root remapping changes the supplied database and therefore needs producer authorization.
