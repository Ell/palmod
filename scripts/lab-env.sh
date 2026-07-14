#!/usr/bin/env bash
# Source this file to point Palmod tooling at the disposable Linux server lab.

palmod_repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

export PALMOD_LAB_ROOT="${PALMOD_LAB_ROOT:-$HOME/.cache/palmod/lab/24088465}"
export PALMOD_SERVER="${PALMOD_SERVER:-$PALMOD_LAB_ROOT/Pal/Binaries/Linux/PalServer-Linux-Shipping}"
export PALMOD_PROFILE_DIR="${PALMOD_PROFILE_DIR:-$palmod_repo/profiles}"
export PALMOD_PLUGIN_DIR="${PALMOD_PLUGIN_DIR:-$palmod_repo/plugins}"
export PALMOD_RUNTIME="${PALMOD_RUNTIME:-$palmod_repo/build/native/libpalmod.so}"

# Keep every mutable server path isolated from the checked-out depot and any
# production server tree.
export HOME="${PALMOD_LAB_HOME:-$HOME/.cache/palmod/lab-home}"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
