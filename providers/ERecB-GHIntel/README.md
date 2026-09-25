# ghintel

`ghintel` is a local-first command-line inventory for GitHub repositories found inside local directories. It identifies real Git working trees, normalizes their GitHub remotes, captures bounded project documentation, and stores an auditable SQLite inventory. It never executes code from a discovered repository.

The primary read workflow is deliberately simple: given a GitHub URL, an investigator can use the local database to see the repository's purpose, known project people, local copies, GitHub availability, and finding provenance.

## Start here

- [Installation](docs/INSTALL.md) covers wheel/source installation, verification, configuration, and optional enrichment-provider setup.
- [Operations guide](docs/USAGE.md) has separate workflows for understanding the tool, producing an inventory database, and using a database shared by someone else.

After installation, initialize a local configuration and scan a repository corpus with:

```bash
export ERECB_MODE_PROFILE=/path/to/config/connected.yaml
ghintel init --config config.toml
ghintel scan --target-dir /media/sf_VMShared/in/20231003 --config config.toml
```

Commands that fetch GitHub data, enrich through a model, snapshot databases, or process
exchange homework require the connected profile. Use `--mode-profile PATH` for a one-command
override. Offline local inventory and read-only queries do not require a connected profile.

`--target-dir` is persistent: ghintel validates the directory, writes its normalized absolute path to `[paths].input_dir` in `config.toml`, and uses it immediately. Subsequent `discover` and `scan` commands use the saved directory.

## Capabilities

- Discover Git repositories without running their code or following symlinks.
- Normalize SSH and HTTPS GitHub addresses to one canonical identity while retaining every local copy and remote role.
- Query a local SQLite database by GitHub URL, list records, search current project cards, and export JSON or relational CSV.
- Optionally retrieve GitHub metadata and README evidence with HTTP caching. Anonymous fetching is supported; quota exhaustion saves a resumable checkpoint and exits instead of silently sleeping until the next GitHub quota window.
- Optionally enrich records through configured Anthropic or local Ollama models, subject to evidence validation and hard token/cost budgets.
- Preserve append-only evidence, provider attempts, findings, and corrections; create verifiable SQLite snapshots for sharing.

## Safety and privacy

The database can contain captured local documents and provider audit responses. Treat it as investigation data. Do not distribute it, provider credentials, or the local `config.toml` without review. Generated JSON/CSV exports omit raw source, HTTP-cache, and provider-response blobs.

Gemini configuration remains available for compatibility with the original design, but it is not a validated deployment path in this release.
