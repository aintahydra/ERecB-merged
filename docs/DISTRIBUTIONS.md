# Offline distributions

Two self-contained bundles are in `dist/`:

- `erecb-merged-airgap-linux-x86_64-py313.tar.gz`
- `erecb-merged-connected-linux-x86_64-py313.tar.gz`

They contain all five project wheels, runtime dependency wheels, the role profile, an installer,
GHIntel/YaraRuler/FileIntel/IPIntel configuration examples, and `SHA256SUMS`. These builds target
Linux x86-64, CPython 3.13, and glibc 2.34 or newer. Both
machines must use compatible OS/architecture and YARA runtimes for compiled-cache transfer.
`python-magic` also needs the OS `libmagic` library (on Kali/Debian: `libmagic1`). The bundles
contain software only—no databases, captures, credentials, request bundles, or YARA cache.

## Install

Copy the appropriate archive to the machine, verify it through your media-handling process,
then extract and install:

```sh
sha256sum -c erecb-merged-airgap-linux-x86_64-py313.tar.gz.sha256
tar -xzf erecb-merged-airgap-linux-x86_64-py313.tar.gz
cd erecb-merged-airgap-linux-x86_64-py313
sha256sum -c SHA256SUMS
./install.sh airgap
mkdir -p in dbs rules/cache output data transfer
```

On the connected host, verify/extract the `connected` archive and run `./install.sh connected`.
Each archive is about 179 MB. The installer creates `.venv` and installs only from the bundled
wheelhouse; it does not use the network.
Override its interpreter with `PYTHON_BIN=/path/to/python3.13` if needed. Create/copy operational
`in/`, `dbs/`, `rules/cache/`, `transfer/`, and (for connected providers) configured provider
settings next to the bundle. Never copy air-gap captures to the connected machine.

## Run

Air-gap machine, from the extracted bundle directory:

```sh
. .venv/bin/activate
erecb-triage --check --config config/airgap.yaml
erecb-triage --once --config config/airgap.yaml
erecb-triage captures list --config config/airgap.yaml
erecb-triage report --capture ID --config config/airgap.yaml
erecb-triage requests export --capture ID --output transfer/requests.json --config config/airgap.yaml
```

Connected machine, after copying the request JSON and `.sha256` sidecar:

```sh
. .venv/bin/activate
export ERECB_MODE_PROFILE="$PWD/config/connected.yaml"
cp config/ghintel.example.toml config/ghintel.toml
cp config/yararuler.example.toml config/yararuler.toml
erecb-ipintel requests import transfer/requests.json
erecb-fileintel requests import transfer/requests.json
ghintel requests import transfer/requests.json --config config/ghintel.toml
erecb-ipintel homework run --limit 20
erecb-fileintel homework run --limit 20
ghintel homework run --limit 20 --config config/ghintel.toml
```

Use `homework list` with the same provider commands to inspect queues. After enrichment,
snapshot each database with its provider CLI; manually copy snapshots/manifests back, then on
the air-gap machine run `erecb-triage db import --fileintel ... --ipintel ... --ghintel ...
--dry-run` before the same command without `--dry-run`. Full options and YARA-cache return
steps are in [`TWO_MACHINE_RUNBOOK.md`](TWO_MACHINE_RUNBOOK.md).

`--limit 20` caps a run at 20 eligible queue items; fewer may run if fewer are ready. CTX.IO
credentials are required when homework is run, not when request bundles are imported. Put the
key in `ctx_io_api_key.txt` in the runtime directory or export `CTX_IO_API_KEY`.

The GHIntel example is based on `providers/ERecB-GHIntel/config.example.toml`. Since it lives
in `config/`, its `paths` use `../in`, `../dbs`, and `../output` to reach the bundle's runtime
directories. Choose the LLM with `[enrichment].provider`; export its API key (for Gemini,
`GEMINI_API_KEY`) before homework runs. Set `GITHUB_TOKEN` for authenticated GitHub API quota;
public API calls can otherwise be unauthenticated and more limited. Request
imports themselves need no provider credentials. Review `allow_source_upload` before enabling
LLM enrichment: it permits repository source documents to be sent to that provider.

To build YARA's rule cache on the connected machine, edit `config/yararuler.toml`'s
`[[rules.sources]]` entries; the example defaults to `https://github.com/Yara-Rules/rules.git`.
`update-rules` clones/updates enabled repositories under `rules/sources/` and builds the active
cache; no manual clone is needed. Then export it for return:

```sh
yararuler --config config/yararuler.toml update-rules
yararuler --config config/yararuler.toml cache-export --output transfer/yara-cache
```

To rebuild the bundles on the release host, run `packaging/build-distributions.sh` with
Python 3.13 and Internet access. It writes ignored artifacts under `dist/`; review dependency
updates and test the generated packages on both target machines before distribution.
