# Install and run Palmod

There are two ways to run Palmod: install a prebuilt **release tarball** (fastest —
no toolchain, no build), or **build from source** (for development, or to support a
server build no shipped profile covers). Either way you point it at a Palworld
dedicated server you already run.

## Quick install (release tarball)

Download the latest `palmod-<version>-linux-x86_64.tar.gz` from the project's
Releases, then extract it and point `run.sh` at your server binary:

```sh
tar -xzf palmod-*-linux-x86_64.tar.gz
cd palmod-*-linux-x86_64
./run.sh --server /path/to/Pal/Binaries/Linux/PalServer-Linux-Shipping \
  -- -port=8211 -useperfthreads -NoAsyncLoadingThread
```

That's the whole install. The tarball bundles the launcher (`bin/palmod-run`), the
operator CLI (`bin/palmodctl`), the loader (`lib/libpalmod.so`), a **validated
profile for Steam build 24088465**, and the example plugins; `run.sh` fills in all
the paths and selects the reflection hook backend for you. Edit or add plugins
under `plugins/` and they hot-reload within about a second. In-game, commands use a
`!` prefix (e.g. `!GiveItem`, `!FindItem`). The bundled `INSTALL.md` documents the
extracted layout, and [`docs/plugin-api.md`](plugin-api.md) covers writing your own.

If your server is a different build, or you want to work on Palmod itself, build
from source below.

## Build from source

Run every command from the repository root unless noted. Server binaries are
**not** needed to build or test — only to actually launch a server.

## 1. Prerequisites

Building the loader needs:

- **Rust 1.95.0** — pinned in [`rust-toolchain.toml`](../rust-toolchain.toml)
  (`channel = "1.95.0"`, `profile = minimal`, components `clippy` + `rustfmt`).
  If you use `rustup`, it installs and selects this toolchain automatically.
- **A C++20 compiler** (the dev setup uses Clang 17).
- **CMake** and **Ninja** — the `Makefile` configures the native build with
  `-G Ninja`, so Ninja is required.
- **pkg-config**.
- **Lua 5.4 development headers** (the dev setup uses Lua 5.4.8).

That's the whole list for building and testing. The reverse-engineering / lab
tooling needs a few more things (Python 3, gdb, optionally Ghidra + OpenJDK 21
and a Frida Gum devkit) — see [`docs/toolchain.md`](toolchain.md). You do **not**
need any of those to build the loader or launch a server.

## 2. Build

```
make build
```

This runs both halves of the project:

- `cargo build --workspace` — produces the Rust binaries `palmod-run` (launcher),
  `palmodctl` (control CLI), and `palrev` (reverse/profile tool) in
  `target/debug/`.
- `cmake -S native -B build/native -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DPALMOD_BUILD_TESTS=ON` followed by `cmake --build` — produces the native
  loader `build/native/libpalmod.so`, which is injected via `LD_PRELOAD`.

Builds use bounded parallelism by default (2 jobs). Speed it up with
`make build PALMOD_BUILD_JOBS=8`.

Optional checks:

```
make test     # cargo tests + native ctest + reverse-pipeline Python unittests
make check    # build + test + fmt/clippy/shell-syntax (bash -n)/whitespace gates
make dist     # assemble a release tarball in dist/ (binaries + loader + profiles + plugins)
```

## 3. Get a compatibility profile

A **compatibility profile** is a TOML file bound to one exact server ELF. It
contains no game code — only a fingerprint of the target binary (SHA-256, GNU
build-id, size, image base), masked "anchor" byte patterns, function/hook
addresses, and a reflection-layout block. It is what lets the loader hook the
server safely.

The gate is strict and it is the **only** enforcement on hooking (no signing, no
keys):

1. `palmod-run` fingerprints your server ELF and scans the `--profiles`
   directory (top level only, `*.toml`).
2. **No matching profile** → the server starts **vanilla**, with nothing
   injected (unless you pass `--require-profile`, which makes it fail instead).
3. **Exactly one match, but `status = "candidate"`** → `palmod-run` **refuses to
   launch** and errors out. It does not fall back to vanilla in this case.
4. **A `validated` match** → every anchor's bytes are re-verified against the ELF
   immediately before hand-off, then the loader is injected.

### The bundled profile

A **validated** profile for Steam build `24088465` (UE 5.1.1) ships at the top
level of `profiles/`, which is exactly where the default `--profiles profiles`
looks:

```
profiles/palworld-linux-24088465.toml          # validated — used by default
profiles/candidates/palworld-linux-24088465.toml  # candidate — review/staging only
```

So if your server **is** build `24088465`, hooks install out of the box: the
loader fingerprints your ELF, matches this profile, re-verifies its anchor bytes
against your binary, and injects. The `candidates/` subdirectory is the staging
area a profile passes through before promotion (`palrev approve`) and is not
scanned at launch. See [`profiles/README.md`](../profiles/README.md) for the
layout and how to add a profile for another build.

### Verify a profile against a binary (no server needed to launch)

The static gate checks a profile's fingerprint and anchor bytes against an ELF:

```
make reverse-verify \
  SERVER_BINARY=/srv/pal/Pal/Binaries/Linux/PalServer-Linux-Shipping \
  VERIFY_PROFILE=profiles/candidates/palworld-linux-24088465.toml
```

Both variables have defaults (the `24088465` lab tree and the bundled
candidate). If the ELF isn't present, the target prints a skip instead of
failing.

### Other server builds

Every address in the bundled profile is specific to build `24088465` and
transfers to no other build. For any other server build you must regenerate a
profile from scratch with the reverse pipeline (fingerprint → analyze → live
dump/probe → `palrev approve` to promote it to `validated`). That workflow is
documented in [`docs/reversing.md`](reversing.md).

## 4. Run your server under Palmod

The launcher is `target/debug/palmod-run`. It sets the server working directory,
stages `steamclient.so`, applies the profile gate above, and injects the loader.

```
PALMOD_HOOK_BACKEND=reflection target/debug/palmod-run \
  --server /srv/pal/Pal/Binaries/Linux/PalServer-Linux-Shipping \
  --profiles profiles \
  --library build/native/libpalmod.so \
  --plugin-dir plugins \
  --state-dir .palmod-state \
  --control-socket /run/user/1000/palmod/control.sock \
  -- -port=8211 -useperfthreads -NoAsyncLoadingThread
```

Each flag:

- `--server` (**required**) — must point directly at a file literally named
  `PalServer-Linux-Shipping` under `.../Pal/Binaries/Linux/`, and be executable.
  `PalServer.sh` is intentionally rejected.
- `--profiles` (default `profiles`) — directory of `*.toml` profiles to match
  against, scanned non-recursively.
- `--library` (default `build/native/libpalmod.so`) — the loader `.so` to
  `LD_PRELOAD`.
- `--plugin-dir` (default `plugins`) — directory of plugins to autoload.
- `--state-dir` (default `.palmod-state`, created `0700`) — holds the crash
  quarantine file.
- `--control-socket` (optional; env `PALMOD_CONTROL_SOCKET`; default
  `$XDG_RUNTIME_DIR/palmod/control.sock`) — the operator control socket.
- `--crash-limit` (default `3`) and `--crash-window-seconds` (default `600`) —
  this many non-clean exits inside the window quarantines the profile, after
  which it falls back to vanilla until you pass `--clear-quarantine`.
- `--clear-quarantine` — clear a prior crash quarantine before launching.
- `--require-profile` — fail instead of starting vanilla when no exact profile
  matches.
- `-- <server args>` — everything after `--` is passed straight to PalServer,
  after the launcher's mandatory injected `Pal` first argument. The three shown
  (`-port=8211 -useperfthreads -NoAsyncLoadingThread`) are ordinary PalServer
  arguments, not Palmod flags.

**`PALMOD_HOOK_BACKEND` is important.** `palmod-run` does not set it, and the
loader defaults to a no-op backend that loads plugins but installs **no game
hooks**. Export `PALMOD_HOOK_BACKEND=reflection` (as above) to get the real
data-pointer/vtable hooks. The value `frida-gum-passive` selects the optional
Frida backend, but only if the loader was compiled with the Frida devkit;
otherwise it fails closed. Either way, hooks install only when steps 3–4 above
found a `validated`, fingerprint-exact, anchor-verified profile.

Other loader env vars: `PALMOD_DISABLE_AUTOLOAD=1` skips plugin autoload.

## 5. Add plugins

Plugins live under the `--plugin-dir` directory (default `plugins/`). Each plugin
is its own subdirectory containing a `manifest.json` plus a Lua entrypoint:

```
plugins/
  myplugin/
    manifest.json
    main.lua
```

A minimal `manifest.json` (schema is
[`sdk/plugin-manifest.schema.json`](../sdk/plugin-manifest.schema.json)):

```json
{
  "schema_version": 1,
  "id": "myplugin",
  "version": "0.1.0",
  "entrypoint": "main.lua",
  "commands": [
    { "name": "Hello", "permission": "everyone", "suppress": true }
  ]
}
```

Field rules: `schema_version` must be `1`; `id` matches
`^[a-z][a-z0-9_.-]{1,63}$` and must be unique; `entrypoint` is a bare `*.lua`
filename (no path separators); optional `memory_limit_bytes` (1 MiB – 32 MiB,
default 32 MiB) and `instruction_limit` (1000 – 250000, default 250000) bound the
plugin's Lua state; each entry in `commands` has a `name`, a `permission` of
`"everyone"` or `"server.admin"`, and a boolean `suppress`.

The Lua entrypoint uses the `palmod.*` API plus an embedded stdlib (no `require`
needed). See [`docs/plugin-api.md`](plugin-api.md) for the full surface, and the
three working examples in `plugins/give_item/`, `plugins/find_item/`, and
`plugins/hook_watch/`.

**Hot reload:** the loader watches the plugin directory and reloads on file edits
within about a second. Reloads are transactional — a bad edit is rejected and the
previously loaded plugins keep running.

**In-game vs. control:** in-game, players invoke commands with a `!` prefix
(e.g. `!GiveItem`); the client swallows `/`-prefixed commands for non-admins, so
they never reach the server.

## 6. Talk to the running server

`palmodctl` connects to the control socket that the loader creates when it is
injected (so the socket only exists when you launched **with** an injected
profile). The socket lives in a `0700` directory owned by you, and the client
verifies via `SO_PEERCRED` that the socket file's owner and the connected server
process are the same local user — a consistency check that it wasn't planted by a
different local user.

```
target/debug/palmodctl status                    # runtime + plugin state
target/debug/palmodctl reload                     # reload ALL plugins (transactional)
target/debug/palmodctl invoke GiveItem Wood Player 5
```

It uses the same socket default as `palmod-run` (`--socket`, env
`PALMOD_CONTROL_SOCKET`); `--timeout-ms` defaults to `5000`. Over the control
socket you pass the bare command name (no `!` prefix); commands run with local
operator authority.

Note: `palmodctl reload` accepts an optional plugin id, but the runtime
currently only supports reloading **all** plugins transactionally — passing a
single id returns an error. Omit the id (or just edit a file and let hot reload
pick it up).

## 7. Troubleshooting

- **Server starts but no hooks / plugins do nothing.** First confirm you exported
  `PALMOD_HOOK_BACKEND=reflection`; without it the loader uses the no-op backend
  and installs no hooks. Otherwise, no `validated` profile matched your server ELF,
  so the loader is running vanilla by design. A validated profile ships for build
  `24088465`; a different build needs its own profile (see below).
- **`palmod-run` refuses to launch with a "candidate, not validated" error.** A
  profile matched your ELF exactly but its `status` is `candidate` (e.g. you pointed
  `--profiles` at `profiles/candidates/`). Use the shipped validated profile in
  `profiles/`, or promote a candidate with `palrev approve` (see
  [`profiles/README.md`](../profiles/README.md)) — the loader will not hook on a
  candidate.
- **Server starts vanilla and you wanted it to fail instead.** Pass
  `--require-profile` so a missing/mismatched profile is a hard error.
- **"Profile mismatch" / anchors don't verify.** This is intentional: the loader
  refuses to install any hook unless the ELF exactly matches a validated profile
  (fingerprint + live anchor bytes). A mismatched build gets zero hooks — "never
  corrupt a mismatched build." You need a profile generated for that exact build.
- **Build fails looking for Lua.** Install the Lua 5.4 **development** headers
  (not just the runtime) and make sure `pkg-config` can find them.
- **CMake can't find a generator.** Install Ninja — the Makefile configures with
  `-G Ninja`.
- **`palmodctl` can't connect.** The control socket only exists while a server is
  running that was launched **with** an injected profile. Check that
  `--control-socket` / `PALMOD_CONTROL_SOCKET` point at the same path the server
  used, and that you're running as the same user.
- **Server keeps falling back to vanilla after crashes.** Repeated non-clean
  exits quarantine the profile in `.palmod-state/quarantine.json`. Clear it with
  `--clear-quarantine`.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
