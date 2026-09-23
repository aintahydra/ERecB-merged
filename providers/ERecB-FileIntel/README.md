# ERecB-FileIntel

ERecB-FileIntel scans directories for executable files, computes SHA-256 and MD5 hashes, enriches those hashes through intelligence providers, and stores the merged result in SQLite.

## Quick Start

```bash
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml init-db
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml scan /path/to/target
PYTHONPATH=src python3 -m erecb_fileintel --config config.example.yaml watch
```

The first provider implementation is CTX.IO. Put the CTX.IO API key path in the config; the default is `ctx_io_api_key.txt`.

## Documentation

- [Setup](docs/SETUP.md)
- [Usage](docs/USAGE.md)

## Redistributable Packages

Build artifacts are generated under `dist/`:

```text
erecb_fileintel-0.1.0-py3-none-any.whl
erecb_fileintel-0.1.0.tar.gz
```
