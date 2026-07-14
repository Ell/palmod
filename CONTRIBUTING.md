# Contributing to Palmod

Thanks for your interest in Palmod, a native Linux modding framework for the
Palworld dedicated server. This guide gets you from a clean checkout to a green
build, and explains the conventions the project holds contributions to. It is
written for people who have not seen the codebase before — you do not need a
Palworld server, or any game binaries, to build, test, or contribute to the core.

## Prerequisites

The core (Rust workspace + native loader) builds and tests with no server
binaries and no game assets. You need:

- **Rust `1.95.0`** — pinned in `rust-toolchain.toml`; `rustup` installs and
  selects it automatically when you build in the repo. It brings `clippy` and
  `rustfmt`.
- **A C++20 compiler** (the reference setup uses Clang 17).
- **CMake** and **Ninja** — the build hard-codes the Ninja generator.
- **pkg-config**.
- **Lua 5.4 development headers** — the loader embeds Lua for the plugin runtime.
  Without them the native library still builds, but with plugin execution
  compiled out (`PALMOD_HAS_LUA=0`), so install them for a full build.

The reverse-engineering test suite (`make reverse-test`) additionally needs
**Python 3**. Deep reversing tools (Ghidra, Frida) are optional and only needed
for the lab workflow — see [docs/toolchain.md](docs/toolchain.md) for the exact
pinned versions.

## Workspace layout

| Path | What it is |
| --- | --- |
| `crates/` | The Rust workspace. `palmod-run` (the launcher that injects the loader), `palmodctl` (control-socket CLI), `palrev` (reverse/profile tooling), and the shared `palmod-profile` library. |
| `native/` | The C++20 in-process loader, built with CMake/Ninja into `build/native/libpalmod.so` and injected via `LD_PRELOAD`. Reflection-based UE5 hooking, the generic hook/call engines, the plugin runtime, and the control server live here. |
| `sdk/` | The plugin SDK: the embedded Lua stdlib (`sdk/lua/stdlib.lua`), the API annotations (`sdk/lua/palmod.lua`), C headers under `sdk/include/`, and the manifest JSON schema (`sdk/plugin-manifest.schema.json`). |
| `plugins/` | Example Lua plugins — `give_item`, `find_item`, `hook_watch`. Good starting points for your own. |
| `reverse/` | The reverse-engineering / profile pipeline: Python tools under `reverse/bin/`, binary-free tests under `reverse/tests/`, and forensic findings under `reverse/findings/`. |
| `profiles/` | Compatibility profiles (TOML) that bind the runtime to one exact server ELF. |
| `docs/` | Architecture, plugin API, security model, reversing workflow, toolchain, and design notes. |
| `scripts/` | Lab and helper shell scripts (checked with `shellcheck`). |

For how these pieces fit together at runtime, read
[docs/architecture.md](docs/architecture.md).

## Build and run the gates

All commands run from the repository root.

```sh
make build   # build the Rust workspace and the native loader
make test    # run all Rust, native (ctest), and reverse-pipeline (Python) tests
make check   # build + test, then run every formatting/lint/hygiene gate
```

- `make build` runs `cargo build --workspace` and configures + builds the native
  loader (`cmake -S native -B build/native -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
  -DPALMOD_BUILD_TESTS=ON`).
- `make test` runs `cargo test --workspace --all-features`, the native `ctest`
  suite, and the reverse-pipeline Python `unittest` fixtures.
- `make check` is the full pre-submit gate. On top of `build` + `test` it runs
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`, `bash -n scripts/*.sh`, and `git diff --check`
  (trailing-whitespace / conflict-marker hygiene).

Run `make help` to list every target, or `make clean` to remove build artifacts.
Build parallelism is bounded by default; override with, e.g., `make build
PALMOD_BUILD_JOBS=8`.

**Before opening a pull request, run `make check` and make sure it is clean.**
Continuous integration (`.github/workflows/ci.yml`) runs the same gates on every
push and pull request across three jobs — Rust (fmt, `clippy -D warnings`, tests),
native (configure with `-DPALMOD_REQUIRE_LUA=ON`, build, `ctest`), and reverse
fixtures (Python tests + `shellcheck`). None of them require server binaries.

## Coding standards

**Rust.** Edition 2024, minimum version 1.95. The workspace denies `unsafe_code`
by default and treats Clippy's `all` and `pedantic` groups as warnings (see
`[workspace.lints]` in `Cargo.toml`); a crate that genuinely needed unsafe/FFI
would opt in locally (none currently do). Keep code `cargo fmt`-clean and warning-free under `clippy -D warnings` —
CI rejects anything that is not.

**Native C++.** C++20 with no compiler extensions
(`CMAKE_CXX_EXTENSIONS OFF`). `palmod_core` compiles with
`-Wall -Wextra -Wpedantic -Wconversion -Wshadow` and is expected to stay
warning-clean; do not silence warnings with casts where a real fix is possible.
The shared library is built with hidden symbol visibility, so only export what
must be exported.

**Shell.** CI runs `shellcheck` over the scripts under `scripts/` and `reverse/`;
`make check` additionally runs `bash -n scripts/*.sh` as a local syntax gate.

**Whitespace.** No trailing whitespace and no leftover conflict markers —
`git diff --check` is part of `make check`.

## Adding a plugin

A plugin is a subdirectory of the plugin directory (`plugins/` by default)
containing a `manifest.json` and a Lua entrypoint. The loader autoloads plugins
and hot-reloads them within about a second of an edit, transactionally — a broken
edit keeps the previously loaded set running.

1. Create `plugins/<your_plugin>/manifest.json`. The schema is
   `sdk/plugin-manifest.schema.json`:
   - `schema_version` — must be `1`.
   - `id` — matches `^[a-z][a-z0-9_.-]{1,63}$` and must be unique across plugins.
   - `version` — a free-form string.
   - `entrypoint` — a bare `*.lua` filename (no path separators) resolved next to
     the manifest.
   - `memory_limit_bytes` (optional) — 1 MiB..32 MiB, default 32 MiB.
   - `instruction_limit` (optional) — 1000..250000 per callback, default 250000.
   - `commands` (optional array, ≤ 64) — each `{ "name", "permission", "suppress" }`
     where `permission` is `"everyone"` or `"server.admin"` and `suppress` is a
     boolean. Every declared command **must** be registered from Lua via
     `palmod.on_command`, or the plugin fails to load.

2. Write the entrypoint against the `palmod.*` API. The primitives
   (`palmod.on_command`, `palmod.on_event`, `palmod.hook`, `palmod.call`,
   reflection reads) and the embedded stdlib helpers (`palmod.reply`,
   `palmod.broadcast`, `palmod.paginate`, `palmod.inventory_of`, ...) are
   available with no `require`. The full surface is documented in
   [docs/plugin-api.md](docs/plugin-api.md). In-game, commands are invoked with a
   `!` prefix (e.g. `!GiveItem`).

3. Copy an example as a starting point: `plugins/give_item/` (an admin mutation
   command over `palmod.call`), `plugins/find_item/` (a read-only data-table
   lookup), or `plugins/hook_watch/` (observation-only `palmod.hook`s, no
   commands).

Plugins run in their own isolated Lua state off the game thread with memory and
instruction budgets; `io`, `os`, `require`, `load`, and similar are removed. This
is a stability boundary, not a trust boundary — every plugin gets the full API,
so only run plugins whose Lua you have read. See
[docs/security.md](docs/security.md) for the model.

## The reverse / profile pipeline

Palmod never patches an arbitrary binary. The runtime only installs hooks when the
target server ELF **exactly** matches a validated compatibility profile —
fingerprint plus live anchor-byte preimages. That is the whole safety gate; there
is no signing or trusted-key step. A profile is a TOML file that carries fingerprints
and offsets, never game code.

At a high level, adding support for a new server build means producing a profile
for it with the `palrev` tool: fingerprint the ELF, seed a candidate, gather live
evidence on a disposable lab server, and promote the candidate to `validated`. The
static, server-free gate is `make reverse-verify` (verifies a profile's anchor
bytes against an ELF you provide). The live steps require a throwaway lab server
and are described, in order, in the
[reversing workflow](docs/reversing.md) and the
[lab runbook](docs/lab-runbook.md).

**Never commit game binaries, game assets, or copyrighted server files.** Profiles
and evidence records contain only fingerprints, offsets, and byte patterns — no
game code.

## Reporting issues and opening pull requests

- **Bugs and feature requests:** open a GitHub issue. For a runtime or
  compatibility bug, include the Steam build number of your server, the profile
  you were using, the relevant structured JSON log lines, and clear reproduction
  steps.
- **Pull requests:** keep them focused, run `make check` locally first, and
  describe what you changed and how you verified it. New behavior should come with
  tests where the existing suites make that practical (Rust unit tests, native
  `ctest`, or reverse-pipeline fixtures).
- **Security-relevant reports:** review the trust and build-safety model in
  [docs/security.md](docs/security.md) before filing, so the report lands against
  what the runtime actually enforces.

Please keep contributions free of personal data — no personal handles, emails, or
references to private/production server trees in code, docs, or test fixtures.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
