#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
python_bin=${PYTHON_BIN:-python3.13}
out="$repo_dir/dist"
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/erecb-release.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
mkdir -p "$work_dir/build" "$work_dir/wheelhouse"

"$python_bin" -m pip wheel --no-deps --wheel-dir "$work_dir/build" .
for package_dir in providers/ERecB-FileIntel providers/ERecB-GHIntel \
  providers/ErecB-IPIntel providers/ERecB-YaraRuler; do
  "$python_bin" -m pip wheel --no-deps --wheel-dir "$work_dir/build" "$repo_dir/$package_dir"
done
"$python_bin" -m pip download --only-binary=:all: --dest "$work_dir/wheelhouse" \
  --find-links "$work_dir/build" erecb-triage==0.1.6 erecb-fileintel==0.1.0 \
  erecb-ipintel==0.1.1 ghintel==0.1.2 yararuler==0.1.1 python-magic yara-python

for role in airgap connected; do
  bundle="$work_dir/erecb-merged-$role-linux-x86_64-py313"
  mkdir -p "$bundle/wheelhouse" "$bundle/config"
  cp "$work_dir/wheelhouse/"*.whl "$bundle/wheelhouse/"
  cp "config/$role.yaml" "$bundle/config/$role.yaml"
  cp providers/ERecB-GHIntel/config.example.toml "$bundle/config/ghintel.example.toml"
  cp providers/ERecB-YaraRuler/config.toml "$bundle/config/yararuler.example.toml"
  cp providers/ERecB-FileIntel/config.example.yaml "$bundle/config/fileintel.example.yaml"
  cp providers/ErecB-IPIntel/config.example.toml "$bundle/config/ipintel.example.toml"
  sed -i \
    -e 's/input_dir = "in"/input_dir = "..\/in"/' \
    -e 's/db_dir = "dbs"/db_dir = "..\/dbs"/' \
    -e 's/output_dir = "output"/output_dir = "..\/output"/' \
    "$bundle/config/ghintel.example.toml"
  sed -i \
    -e 's/rules_dir = "rules"/rules_dir = "..\/rules"/' \
    -e 's/target_dir = "in"/target_dir = "..\/in"/' \
    -e 's/cache_dir = "rules\/cache"/cache_dir = "..\/rules\/cache"/' \
    -e 's/quarantine_dir = "rules\/quarantine"/quarantine_dir = "..\/rules\/quarantine"/' \
    "$bundle/config/yararuler.example.toml"
  cp docs/DISTRIBUTIONS.md docs/TWO_MACHINE_RUNBOOK.md "$bundle/"
  cp packaging/install-offline.sh "$bundle/install.sh"
  chmod 755 "$bundle/install.sh"
  (
    cd "$bundle"
    find wheelhouse config install.sh DISTRIBUTIONS.md TWO_MACHINE_RUNBOOK.md -type f -print0 \
      | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  tar -C "$work_dir" -czf "$out/$(basename "$bundle").tar.gz" "$(basename "$bundle")"
  (cd "$out" && sha256sum "$(basename "$bundle.tar.gz")" > "$(basename "$bundle.tar.gz").sha256")
done

printf 'Built distributions:\n  %s\n  %s\n' \
  "$out/erecb-merged-airgap-linux-x86_64-py313.tar.gz" \
  "$out/erecb-merged-connected-linux-x86_64-py313.tar.gz"
