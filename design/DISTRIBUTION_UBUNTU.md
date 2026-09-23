# Ubuntu Distribution and Installation Guide

## Release artifacts

The `dist/` directory contains:

```text
erecb_triage-<version>-py3-none-any.whl  # installable wheel
erecb_triage-<version>.tar.gz            # source distribution and YAML profiles
SHA256SUMS                               # transfer verification
```

Verify artifacts before installation:

```bash
cd /path/to/dist
sha256sum -c SHA256SUMS
```

## Base installation

On Ubuntu with Python 3.10 or newer:

```bash
sudo apt update
sudo apt install -y python3-venv
python3 -m venv /opt/erecb-triage/.venv
. /opt/erecb-triage/.venv/bin/activate
python -m pip install /path/to/erecb_triage-<version>-py3-none-any.whl
erecb-triage --help
```

Running `erecb-triage --once` without `--config` uses built-in staging/unarchiving defaults.
For named YAML profiles, unpack the source distribution and copy the required `config/*.yaml`
file into an operator-owned configuration directory:

```bash
tar -xzf erecb_triage-<version>.tar.gz
install -D -m 0640 erecb_triage-<version>/config/watcher_all.yaml /etc/erecb-triage/watcher_all.yaml
```

Adapt paths in the copied profile; never store secrets there.

## Optional adapter dependencies

Install optional Python extras only for enabled processors:

```bash
python -m pip install 'erecb-triage[fileintel,yara]'
```

For FileIntel magic classification, install the Ubuntu libmagic runtime/development package
appropriate to the deployment image (commonly `libmagic1`; package names can vary by release).
For YARA, use a compatible `yara-python` wheel or build environment with libyara. Verify the
selected profile after installation:

```bash
erecb-triage --config /etc/erecb-triage/watcher_all.yaml --check
```

## Operator-owned deployment inputs

Release artifacts exclude captures, reports, staging state, producer databases, YARA caches, and
credentials. Supply them separately with least-privilege permissions:

```text
/var/lib/erecb-triage/in/                 writable by drop mechanism
/var/lib/erecb-triage/middle-earth/       writable by triage service
/var/lib/erecb-triage/output/             writable by triage service
/var/lib/erecb-triage/data/               writable by triage service
/srv/erecb-producers/dbs/*.sqlite3        readable, not writable, by triage service
/srv/yararuler/cache/                     readable, not writable, by triage service
```

Use an unprivileged service account. The triage service must not have write permission to
producer databases, rule caches/sources, or credentials. See `../docs/OPERATOR_RUNBOOK.md` for
recovery and retention guidance.

## Large-capture deployment capacity

The shipped configuration accepts 100 GiB archives, 200 GiB extracted content, and 200,000
extracted files. `InputStager` temporarily holds a private archive copy and the extracted payload
before publishing it. When `in/` and `middle-earth/` share storage, provision at least 450 GiB
free for one maximum-size capture, in addition to retained inputs, captures, databases, and
reports. Keep the service account quota and filesystem monitoring aligned with that envelope.

## Build a release from source

From a reviewed source checkout with build tooling already installed:

```bash
python -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist
python -c "from setuptools.build_meta import build_sdist; print(build_sdist('dist'))"
cd dist
sha256sum erecb_triage-*.whl erecb_triage-*.tar.gz > SHA256SUMS
```

Run the verification suite and perform a clean wheel install/import/CLI smoke test before
publishing. Do not publish `.env`, token files, producer DBs, caches, captures, reports, or
generated temporary state.
