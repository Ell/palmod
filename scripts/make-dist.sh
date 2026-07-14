#!/usr/bin/env bash
# Assemble a self-contained Palmod release tarball: prebuilt binaries + the
# loader + shipped profiles + example plugins + a launcher. Used by both
# `make dist` and the release CI workflow.
#
#   scripts/make-dist.sh [version]
#
# `version` defaults to `git describe`. Requires a prior release build:
#   cargo build --release -p palmod-run -p palmodctl
#   cmake --build build/native   (Release, libpalmod.so present)
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
name="palmod-${version}-linux-x86_64"
staging="dist/$name"

run_bin="target/release/palmod-run"
ctl_bin="target/release/palmodctl"
loader="build/native/libpalmod.so"

for artifact in "$run_bin" "$ctl_bin" "$loader"; do
  [[ -f "$artifact" ]] || {
    echo "make-dist: missing build artifact: $artifact" >&2
    echo "make-dist: run 'make dist' (which builds first) or build release binaries." >&2
    exit 1
  }
done

rm -rf "$staging"
mkdir -p "$staging/bin" "$staging/lib" "$staging/profiles" "$staging/plugins" "$staging/docs"

install -m 0755 "$run_bin" "$ctl_bin" "$staging/bin/"
install -m 0644 "$loader" "$staging/lib/"

# Shrink the shipped binaries; harmless if strip is unavailable.
if command -v strip >/dev/null 2>&1; then
  strip --strip-unneeded "$staging/bin/palmod-run" "$staging/bin/palmodctl" \
    "$staging/lib/libpalmod.so" 2>/dev/null || true
fi
install -m 0755 packaging/run.sh "$staging/run.sh"
install -m 0644 packaging/INSTALL.md "$staging/INSTALL.md"
install -m 0644 README.md LICENSE "$staging/"

# Ship only validated top-level profiles (not the candidates/ staging area).
shopt -s nullglob
profiles=(profiles/*.toml)
if (( ${#profiles[@]} == 0 )); then
  echo "make-dist: no shipped profiles in profiles/*.toml" >&2
  exit 1
fi
install -m 0644 "${profiles[@]}" "$staging/profiles/"

# Example plugins (each is a manifest.json + main.lua directory).
cp -r plugins/. "$staging/plugins/"

# A copy of the plugin API reference for offline authoring.
[[ -f docs/plugin-api.md ]] && install -m 0644 docs/plugin-api.md "$staging/docs/"

tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "$staging"
echo "dist/$name.tar.gz"
