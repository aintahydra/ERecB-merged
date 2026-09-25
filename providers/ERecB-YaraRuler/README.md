# YaraRuler

YaraRuler is a passive CLI scanner that synchronizes YARA rule repositories, builds
a validated binary rule cache, filters target files, and exports JSON or CSV reports.
Target files are never executed, imported, or invoked.

## Install

Python 3.11+ and the platform prerequisites for `yara-python` are required.

```bash
python -m pip install -e .
```

Install optional libmagic support with `python -m pip install -e '.[magic]'`.

## Use

```bash
export ERECB_MODE_PROFILE=/path/to/config/connected.yaml
yararuler update-rules
yararuler scan --target-dir ./in --exec-only --output report.json
yararuler scan --target-dir ./in --all --glob '*.bin' --format csv --output report.csv
```

Rule-source synchronization and cache export require the connected profile. Cache activation
requires the air-gap profile. Set `ERECB_MODE_PROFILE` for the machine or pass
`--mode-profile PATH` to one command.

Configuration is read from `config.toml`; use `--config PATH` to select another file.
Logs go to stderr. Use `--output -` to write a report to stdout.

Distribution installation, offline setup, configuration, command examples, and
troubleshooting are documented in `docs/installation-and-usage.md`. The architecture
and as-built status are documented under `design/`.
