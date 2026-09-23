# Install ghintel

## Prerequisites

- Python 3.11 or newer.
- A wheel or source archive from the publisher's `dist/` directory.
- Optional: a GitHub token for online metadata retrieval, and an Anthropic or reachable Ollama service for enrichment. Discovery and local database queries need neither.

Use a virtual environment on a new machine:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ghintel-0.1.2-py3-none-any.whl
ghintel --version
ghintel --help
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

To install from the source distribution instead, use:

```bash
python -m pip install ghintel-0.1.2.tar.gz
```

The package resolves its declared runtime dependencies during installation. For offline deployment, obtain those dependency wheels from a trusted source first and install with pip's `--no-index --find-links` options.

## Create local runtime configuration

Run the following in an empty working directory (not inside the unpacked source archive):

```bash
ghintel init --config config.toml
```

It writes `config.toml` and creates the configured `in/`, `dbs/`, and `output/` directories. The generated database is migrated automatically.

`config.toml` is machine-local. Do not copy API keys into it; select environment variable names there and set the corresponding variables in the shell or a secret manager.

To choose an existing corpus from the command line and retain it for later commands:

```bash
ghintel scan --target-dir /media/sf_VMShared/in/20231003 --config config.toml
```

The target must already be a directory, and the configuration file must be writable. ghintel atomically replaces `[paths].input_dir` with the normalized absolute path before scanning. If validation or the configuration write fails, the previous configuration remains in place.

## Verify an installation

These commands make no network request:

```bash
ghintel --version
ghintel doctor --config config.toml
ghintel db migrate --config config.toml
```

`doctor --check-provider` intentionally contacts the configured provider only to verify model availability. Run it only after configuring that provider.

## Optional online capabilities

Set `github.offline = false` only when GitHub retrieval is wanted. A GitHub token in the configured environment variable is recommended for rate limits and private-repository access, but is not required for public repositories. When anonymous quota is exhausted, ghintel exits with code `7` after saving a resumable checkpoint; wait until the printed reset time and run the supplied `ghintel resume` command. Repository-level progress is written to stderr, while completed metadata, README, and profile phases are retained across resume. A GitHub `404` is reported as private or unavailable; ghintel does not infer which of those explanations is true.

For enrichment, select one supported, reviewed deployment path:

- Anthropic: set `[enrichment] provider = "anthropic"`, export the configured `ANTHROPIC_API_KEY`, and supply positive operator-controlled Anthropic prices.
- Ollama: set `[enrichment] provider = "ollama"`, enable `[ollama]`, and set the endpoint/model. No API key or provider price is required for local Ollama.

Both `allow_source_upload` and provider budgets are deliberate safeguards. Read [the operations guide](USAGE.md) before enabling either provider.
