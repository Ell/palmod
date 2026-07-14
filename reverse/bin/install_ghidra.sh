#!/usr/bin/env bash
set -euo pipefail

version="12.1.2"
release_date="20260605"
archive="ghidra_${version}_PUBLIC_${release_date}.zip"
archive_sha256="b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d"
release_tag="Ghidra_12.1.2_build"
tools_root="${PALMOD_TOOLS_ROOT:-$HOME/.local/share/palmod/tools}"
install_dir="$tools_root/ghidra_${version}_PUBLIC"
archive_path="$tools_root/$archive"
venv="$tools_root/pyghidra-venv"
distribution="$install_dir/Ghidra/Features/PyGhidra/pypkg/dist"

mkdir -p "$tools_root"
if [[ ! -d "$install_dir" ]]; then
  curl --fail --location --continue-at - \
    --output "$archive_path" \
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/$release_tag/$archive"
  printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum --check
  unzip -q "$archive_path" -d "$tools_root"
fi

if [[ ! -x "$install_dir/support/analyzeHeadless" ]]; then
  echo "Ghidra extraction is incomplete: $install_dir" >&2
  exit 1
fi
printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum --check

if [[ ! -x "$venv/bin/python" ]]; then
  command -v uv >/dev/null || {
    echo "uv is required to provision the pinned PyGhidra Python" >&2
    exit 1
  }
  uv venv --python 3.13 "$venv"
fi
uv pip install --python "$venv/bin/python" --no-index \
  --find-links "$distribution" 'pyghidra==3.1.0'

JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk}" \
GHIDRA_INSTALL_DIR="$install_dir" \
  "$venv/bin/python" -c \
  'import pyghidra; print(f"Ghidra ready; PyGhidra {pyghidra.__version__}")'
