# ERecB-FileIntel

ERecB-FileIntel scans directories for executable files, computes SHA-256 and MD5 hashes, enriches those hashes through intelligence providers, and stores the merged result in SQLite.

## Quick Start

```bash
export ERECB_MODE_PROFILE=/path/to/config/connected.yaml
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml init-db
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml scan /path/to/target
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml watch
```

Scanning, exchange queue operations, and database snapshots require the connected profile;
database merges require the air-gap profile. Use `--mode-profile PATH` to select a profile
for an individual command.

The first provider implementation is CTX.IO. Request-bundle imports are offline and do not need
credentials. `homework run` requires CTX.IO credentials, read from `CTX_IO_API_KEY` or the
configured key file (default `ctx_io_api_key.txt`).

## Documentation

- [Setup](docs/SETUP.md)
- [Usage](docs/USAGE.md)

## Redistributable Packages

Build artifacts are generated under `dist/`:

```text
erecb_fileintel-0.1.0-py3-none-any.whl
erecb_fileintel-0.1.0.tar.gz
```
