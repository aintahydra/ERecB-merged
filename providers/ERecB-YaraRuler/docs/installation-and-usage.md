# Installing and using YaraRuler distributions

## Distribution files

Release artifacts are written to `dist/`:

```text
yararuler-0.1.1-py3-none-any.whl
yararuler-0.1.1.tar.gz
SHA256SUMS
```

The wheel is the preferred installation format. The `tar.gz` file is a Python source
distribution and is useful when a wheel cannot be used or when the source needs to be
inspected before installation.

YaraRuler supports Python 3.11 or newer on standard Linux distributions and macOS.
Git must be installed for `update-rules`. The package declares these Python runtime
dependencies, which pip normally installs automatically:

- `yara-python`
- `pydantic`
- `typer`

`python-magic` and the platform `libmagic` library are optional. When unavailable,
executable discovery continues with file signatures, shebangs, and extensions.

## Verify transferred files

Transfer the two package files and `SHA256SUMS` to the destination machine. From the
directory containing them, verify that neither file changed in transit:

```bash
sha256sum -c SHA256SUMS
```

On macOS, where `sha256sum` is not installed by default, use:

```bash
shasum -a 256 yararuler-0.1.1-py3-none-any.whl
shasum -a 256 yararuler-0.1.1.tar.gz
```

Compare that output with `SHA256SUMS`.

## Install from the wheel

Use a virtual environment so YaraRuler and its dependencies remain isolated:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ./yararuler-0.1.1-py3-none-any.whl
yararuler --help
```

Although the YaraRuler wheel itself is platform-independent, `yara-python` may use a
platform-specific wheel. If pip must build it from source, install the compiler and
YARA development prerequisites provided by the destination operating system first.

## Install from the source archive

The source archive requires a Python build backend during installation. With internet
or an appropriately populated package index:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install ./yararuler-0.1.1.tar.gz
yararuler --help
```

The source archive also contains the implementation design, tests, and example
`config.toml`. Prefer the wheel for offline or routine deployments because it does not
need to build YaraRuler itself.

## Offline installation

Prepare dependencies on an internet-connected machine with the same operating system,
CPU architecture, and Python minor version as the offline destination:

```bash
mkdir offline-bundle
python -m pip download \
  --dest offline-bundle \
  ./yararuler-0.1.1-py3-none-any.whl
```

Transfer the entire `offline-bundle/` directory. Install without accessing a package
index:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install \
  --no-index \
  --find-links ./offline-bundle \
  yararuler
```

Use the wheel-based procedure for offline installation. Installing the source archive
offline additionally requires the build-system packages declared in `pyproject.toml`.

## Create the configuration

YaraRuler reads `config.toml` from the current directory unless `--config PATH` is
provided. The installed wheel intentionally does not create or overwrite a local
configuration. Copy the example from the source archive/repository or create this
minimal configuration beside the directory from which commands will be run:

```toml
[paths]
rules_dir = "rules"
target_dir = "in"

[rules]
cache_dir = "rules/cache"
quarantine_dir = "rules/quarantine"

[[rules.sources]]
name = "community-rules"
url = "https://github.com/Yara-Rules/rules.git"
enabled = true

[scan]
threads = 1
timeout_seconds = 30
default_selector = "exec-only"
follow_symlinks = false
include_strings = false
max_file_size_bytes = 0

[report]
format = "json"
output = "report.json"
pretty_json = true

[logging]
level = "INFO"
```

Relative paths in the configuration resolve relative to the directory containing the
configuration file. Unknown keys and invalid values are rejected before work starts.
Source names must be unique.

Use a configuration at another location like this:

```bash
yararuler --config /etc/yararuler/config.toml update-rules
yararuler --config /etc/yararuler/config.toml scan
```

## Synchronize and compile rules

Clone or update all enabled repositories, validate each `.yar`/`.yara` file, quarantine
invalid rules, and publish a compiled cache:

```bash
yararuler update-rules
```

Add a repository for one invocation without changing `config.toml`:

```bash
yararuler update-rules --source https://example.org/security/rules.git
```

Managed repositories are stored under `rules/sources/`. Invalid rules and diagnostic
sidecars are written under `rules/quarantine/`. Successful compiled generations are
stored under `rules/cache/generations/`, and `rules/cache/active` selects the generation
used by scans. A failed update leaves the previously active generation usable.

For ERecB Triage integration, install YaraRuler 0.1.1 or later and point
`processors.yara_scan.cache_dir` at this `rules/cache` directory. Do not point Triage
at `rules/sources/` or a raw Git checkout. The producer publishes an immutable compiled
generation with the `active` pointer, `manifest.json`, and `rules.yac`; after an upgrade
from 0.1.0, run `yararuler update-rules --force-rebuild` to replace the old incompatible
manifest schema.

YaraRuler refuses to overwrite dirty managed Git checkouts or follow unsafe rule
include paths. Git is always invoked non-interactively.

## Scan files

Scan executable and script candidates below the configured target directory:

```bash
yararuler scan --exec-only --output report.json
```

Override the target directory:

```bash
yararuler scan \
  --target-dir ./in \
  --exec-only \
  --output report.json
```

Scan all readable regular files whose basenames end in `.bin`:

```bash
yararuler scan \
  --target-dir ./in \
  --all \
  --glob '*.bin' \
  --output report.json
```

Combine executable detection, basename globs, and path regular expressions:

```bash
yararuler scan \
  --exec-only \
  --glob 'sample_*' \
  --regex '^in/(release|staging)/' \
  --threads 4 \
  --timeout 30 \
  --include-strings \
  --output report.json
```

`--all` and `--exec-only` are mutually exclusive. Repeated glob values are ORed,
repeated regex values are ORed, and the selector, glob family, and regex family are
ANDed. Globs match basenames; regexes search the normalized report-relative path.

Files are inspected as data only. YaraRuler never executes, imports, or invokes a
target artifact.

## Report formats

JSON is the default and preserves scan metadata, file results, matches, and recoverable
errors:

```bash
yararuler scan --all --format json --output report.json
```

CSV contains one row per matched file/rule pair. A metadata/error sidecar named
`<output>.metadata.json` is written with file-based CSV output:

```bash
yararuler scan --all --format csv --output report.csv
```

Use `--output -` to write the main report to stdout. Logs and progress remain on
stderr so JSON and CSV stdout can be piped safely.

Hashes are calculated only for matched files. MD5 is reported solely as an artifact
identifier; SHA-256 should be used for integrity comparisons.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Command completed successfully; no matches is also success |
| 2 | Invalid CLI use or configuration |
| 3 | Rule synchronization or cache build failed |
| 4 | Compiled cache is missing, stale, incompatible, or corrupt |
| 5 | Scan completed and reported one or more recoverable file errors |
| 6 | Report output failed |
| 70 | Unexpected internal failure |

## Common problems

`compiled rule cache is unavailable`

: Run `yararuler update-rules` with the same configuration before scanning.

`yara-python is not installed`

: Reinstall without `--no-deps`, or add the correct `yara-python` wheel for the target
  Python version, operating system, and architecture to the offline bundle.

Git authentication fails or prompts are suppressed

: Configure non-interactive Git credentials or SSH keys before running `update-rules`.
  YaraRuler deliberately does not open interactive credential prompts.

Rules appear under `rules/quarantine/`

: Inspect the corresponding `.error.json` sidecar. Unsupported YARA modules, syntax
  errors, obsolete constructs, missing includes, and includes escaping the repository
  root are rejected without stopping valid rules from being cached.

Some files are not selected by `--exec-only`

: Install the optional libmagic integration, add an appropriate extension, or use
  `--all` with a glob/regex constraint.

The scan exits with code 5 but produced a report

: Review the top-level JSON `errors` array or the CSV metadata sidecar. Permission
  errors, disappearing files, timeouts, and files modified during scanning are isolated
  and do not prevent other candidates from being scanned.
