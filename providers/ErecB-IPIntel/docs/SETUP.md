# Setup Guide

This guide describes how to install ERecB-IPIntel `0.1.1` from source or from a redistributable package, then prepare a local working directory.

## Requirements

- Python 3.11 or newer
- `pip`
- A CTX.IO API key for enrichment commands

The base package has no required third-party runtime dependencies. YAML config files require the optional `yaml` extra, which installs PyYAML. TOML and JSON config files work without optional dependencies.

## Install From a Wheel

Copy the wheel from `dist/` to the target machine, then run:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install erecb_ipintel-0.1.1-py3-none-any.whl
```

Confirm that the command was installed:

```bash
erecb-ipintel --help
```

If you need YAML config support on the target machine:

```bash
python3 -m pip install PyYAML
```

## Install From Source

From the project root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
```

For editable development installs:

```bash
python3 -m pip install -e .
```

## Build Redistributable Artifacts

From the project root, build both a wheel and a source archive:

```bash
python3 -m build
```

The output files are created under `dist/`:

```text
dist/erecb_ipintel-0.1.1-py3-none-any.whl
dist/erecb_ipintel-0.1.1.tar.gz
```

If the `build` module is unavailable, install it in your build environment first:

```bash
python3 -m pip install build
```

## Prepare a Working Directory

The CLI resolves relative runtime paths from the current working directory unless a config file points elsewhere. A normal local layout is:

```text
workdir/
  in/
  output/
  dbs/
  ctx_io_api_key.txt
  config.toml        optional
```

Create the directories and initialize the database:

```bash
mkdir -p in output dbs
erecb-ipintel init-db
```

## Configure CTX.IO Credentials

Credential lookup order is:

1. `providers.ctx_io.api_key` in config
2. `CTX_IO_API_KEY` environment variable
3. `ctx_io_api_key.txt` in the runtime root

Using an environment variable:

```bash
export CTX_IO_API_KEY='YOUR_CTX_IO_API_KEY'
```

Using the local compatibility file:

```bash
printf 'YOUR_CTX_IO_API_KEY\n' > ctx_io_api_key.txt
chmod 600 ctx_io_api_key.txt
```

Do not commit API keys, databases, or extraction outputs.

## Configuration File

The CLI searches for `config.yaml`, `config.yml`, `config.toml`, or `config.json` in the runtime root. You can also pass a file explicitly:

```bash
erecb-ipintel --config /path/to/config.toml status
```

A complete TOML example is available in [config.example.toml](../config.example.toml).

## Next Steps

See the [Usage Guide](USAGE.md) for scanning, progress reporting, unique-IP enrichment, and resumable `--max-ips`/`--consume` workflows.
