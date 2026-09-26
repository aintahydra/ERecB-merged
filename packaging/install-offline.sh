#!/bin/sh
set -eu

role=${1:-}
case "$role" in
  airgap|connected) ;;
  *) printf 'Usage: %s {airgap|connected}\n' "$0" >&2; exit 2 ;;
esac

bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_bin=${PYTHON_BIN:-python3.13}
command -v "$python_bin" >/dev/null 2>&1 || {
  printf 'Required interpreter not found: %s\n' "$python_bin" >&2
  exit 1
}
"$python_bin" -c 'import platform, sys; assert sys.version_info[:2] == (3, 13), sys.version; assert platform.system() == "Linux" and platform.machine() == "x86_64", platform.platform()'

"$python_bin" -m venv "$bundle_dir/.venv"
"$bundle_dir/.venv/bin/python" -m pip install --force-reinstall --no-index \
  --find-links "$bundle_dir/wheelhouse" \
  erecb-triage==0.1.6 erecb-fileintel==0.1.0 erecb-ipintel==0.1.1 \
  ghintel==0.1.2 yararuler==0.1.1 python-magic yara-python
"$bundle_dir/.venv/bin/python" -m pip check

for cli in erecb-triage erecb-fileintel erecb-ipintel ghintel yararuler; do
  "$bundle_dir/.venv/bin/$cli" --help >/dev/null
done

printf 'Installed %s role. Start with:\n  cd %s\n  . .venv/bin/activate\n  export ERECB_MODE_PROFILE=config/%s.yaml\n' \
  "$role" "$bundle_dir" "$role"
