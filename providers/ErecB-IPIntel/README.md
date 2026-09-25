# ERecB-IPIntel

ERecB-IPIntel is a local command-line tool for collecting IP addresses from files and enriching them with IP intelligence. It scans configured input directories, writes deduplicated `IP; PATH` extraction files, and stores enrichment results in a portable SQLite database.

Scan and enrichment commands print bounded percentage progress to standard error. Enrichment reduces extraction tuples to unique canonical IPs before calling providers, so repeated appearances of one IP do not cause repeated paid API requests.

Rate-limited enrichment can be resumed with `erecb-ipintel enrich FILE --max-ips LIMIT --consume`. Completed IP tuples are removed atomically while unselected, failed, and rate-limited IP tuples remain for the next run.

The first provider implementation is CTX.IO. The provider interface is intentionally narrow so additional providers can be added later.

## Quick Start

From a checked-out source tree:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
```

Initialize a working directory and database:

```bash
mkdir -p in output dbs
printf 'YOUR_CTX_IO_API_KEY\n' > ctx_io_api_key.txt
erecb-ipintel init-db
```

Scan a directory and enrich the output:

```bash
export ERECB_MODE_PROFILE=/path/to/config/connected.yaml
erecb-ipintel scan in/sample
erecb-ipintel enrich output/ips_sample_YYMMDD-HHMMSS.txt
erecb-ipintel status
```

Provider enrichment, request-queue processing, and database snapshots require the connected
profile. Snapshot merges require the air-gap profile. Select either with
`--mode-profile PATH` for one command.

For redistribution, build artifacts are written to `dist/`:

```bash
python3 -m build
```

Install the wheel on another machine:

```bash
python3 -m pip install erecb_ipintel-0.1.1-py3-none-any.whl
```

## Documentation

- [Setup Guide](docs/SETUP.md)
- [Usage Guide](docs/USAGE.md)
- [한국어 설치 및 사용 안내서](docs/GUIDE_KO.md)
- [Example TOML Config](config.example.toml)

## Runtime Files

The tool uses the current working directory as its default runtime root. By default it reads from `in/`, writes extraction files to `output/`, stores SQLite data in `dbs/ipintel.sqlite3`, and reads CTX.IO credentials from `ctx_io_api_key.txt` when no explicit config or environment key is provided.

Generated artifacts and credentials should remain local and are ignored by `.gitignore`.
