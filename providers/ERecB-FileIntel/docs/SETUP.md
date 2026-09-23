# Setup

This guide installs ERecB-FileIntel on a new machine and prepares it to scan files, reuse a database, and merge a database copied from another machine.

## Requirements

- Python 3.10 or newer.
- `libmagic`, required by `python-magic`.
- A CTX.IO API key only when CTX.IO enrichment is enabled.

Install the required system packages.

Debian or Ubuntu:

```bash
sudo apt-get install python3 python3-venv libmagic1
```

Red Hat, Rocky Linux, AlmaLinux, or Fedora:

```bash
sudo dnf install python3 file-libs
```

macOS with Homebrew:

```bash
brew install python libmagic
```

## Install a Redistributable Package

The release artifacts are:

```text
erecb_fileintel-0.1.0-py3-none-any.whl
erecb_fileintel-0.1.0.tar.gz
```

Copy one artifact to the new machine. The wheel is preferred. Create and activate a virtual environment, then install it:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install /path/to/erecb_fileintel-0.1.0-py3-none-any.whl
```

To install the source archive instead:

```bash
python -m pip install /path/to/erecb_fileintel-0.1.0.tar.gz
```

Verify that the command is available:

```bash
erecb-fileintel --help
```

The listed subcommands include `init-db`, `scan`, `watch`, `show-summary`, and `merge-db`.

## Configure a Working Directory

Create a working directory, copy `config.example.yaml` from the source archive or repository as `config.yaml`, then create the default input and database directories:

```bash
mkdir -p in dbs
cp /path/to/config.example.yaml config.yaml
```

To collect only local hashes initially, set the following in `config.yaml`:

```yaml
input_dir: in
watch_depth: 1
database_path: dbs/fileintel.sqlite3

enrichment:
  enabled_providers: []
```

Initialize the database:

```bash
erecb-fileintel --config config.yaml init-db
```

The default database path is `dbs/fileintel.sqlite3`. Repeating `init-db` validates and reuses an existing compatible File Intel database; it does not erase existing records.

## Enable CTX.IO Enrichment

Create a key file containing only the CTX.IO key and restrict its permissions:

```bash
printf '%s\n' 'YOUR_CTX_IO_API_KEY' > ctx_io_api_key.txt
chmod 600 ctx_io_api_key.txt
```

Enable the provider in `config.yaml`:

```yaml
enrichment:
  enabled_providers:
    - ctx_io

providers:
  ctx_io:
    api_key_path: ctx_io_api_key.txt
    base_url: https://api.ctx.io/v1
```

Do not place the API key in `config.yaml` or commit the key file to version control.

## Run the Tool

Run a one-time recursive scan:

```bash
erecb-fileintel --config config.yaml scan /path/to/scan
```

Run watcher mode for the configured `in/` directory:

```bash
erecb-fileintel --config config.yaml watch
```

Show accumulated database counts:

```bash
erecb-fileintel --config config.yaml show-summary
```

## Merge a Database From Another Machine

Stop any watcher that uses the destination database, copy the other machine's SQLite database into `dbs/`, preview the merge, then merge with a backup:

```bash
erecb-fileintel merge-db \
  --source dbs/fileintel2.sqlite3 \
  --dest dbs/fileintel.sqlite3 \
  --dry-run

erecb-fileintel merge-db \
  --source dbs/fileintel2.sqlite3 \
  --dest dbs/fileintel.sqlite3 \
  --backup
```

The source database remains unchanged. The merge retains both machines' scan and provider lookup history, adds new tags and file names, and reports conflicts or unavailable raw-response files as warnings.

## Development Installation

From a source checkout, install the project in editable mode:

```bash
python3 -m pip install -e .
```

For a one-off run without installation:

```bash
PYTHONPATH=src python3 -m erecb_fileintel --help
```
