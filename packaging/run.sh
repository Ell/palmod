#!/usr/bin/env bash
# Palmod launcher for the extracted release tarball. It fills in the paths to the
# bundled loader, profiles, and plugins, then hands off to palmod-run. You only
# need to point it at your PalServer binary and pass the usual server arguments.
#
#   ./run.sh --server /path/to/PalServer-Linux-Shipping -- -port=8211 -useperfthreads
#
# Anything after `--` is forwarded to the server. Any palmod-run flag you add
# (for example --control-socket /run/palmod.sock) overrides the defaults below.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The reflection backend is the real in-process hook backend; override by
# exporting PALMOD_HOOK_BACKEND before invoking this script.
export PALMOD_HOOK_BACKEND="${PALMOD_HOOK_BACKEND:-reflection}"

exec "$here/bin/palmod-run" \
  --library "$here/lib/libpalmod.so" \
  --profiles "$here/profiles" \
  --plugin-dir "$here/plugins" \
  "$@"
