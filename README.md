# Palmod

Palmod is a native Linux modding framework for the Palworld **dedicated server**.
It loads into the server process with `LD_PRELOAD` and hooks the game through
Unreal Engine 5's own reflection data — a UE4SS-equivalent for the Linux server,
rather than an RCON sidecar. Commands and events originate inside the PalServer
process; plugins are sandboxed Lua 5.4 and can hook or call any of the game's
reflected `UFunction`s by name, with no per-function native code.

## Highlights

- **Generic hook engine** — `palmod.hook("SomeUFunction", fn)` observes any of the
  game's ~26k reflected `UFunction`s, resolved live by name (case-insensitive, like
  `palmod.call`). Decoded parameters arrive as `event.args` keyed by parameter name.
  No per-function native code, and no per-function config or catalog.
- **Generic call engine** — `palmod.call("/Script/Pkg.Class:Func", args [, target])`
  invokes any `UFunction` by name; parameters are encoded from live reflection and
  dispatched via `ProcessEvent` on the game thread.
- **Read-side reflection** — `palmod.find_object`, `find_all_of`, `get`,
  `class_of`, and `datatable_rows` read live object and DataTable state.
- **Embedded Lua stdlib** — `palmod.reply` (private reply to a command's issuer),
  `broadcast`, `players`, `player_state`, `resolve_uid`, `inventory_of`, and
  `paginate` ship in every plugin sandbox (no `require`).
- **Events and commands** — `palmod.on_command(name, fn)` and
  `palmod.on_event(kind, fn)`; the built-in event kind is `"chat"`, and any hooked
  `UFunction` name is also an event kind.
- **Hot reload** — editing a plugin file reloads the plugin set within ~1s,
  transactionally; a bad edit keeps the previous plugins running.
- **Live-validated example plugins** — `give_item`, `find_item`, and `hook_watch`
  are pure Lua over the generic engine.
- **The operator owns the box** — plugins have full access. There is no capability
  gating and no trust tiers; you run your own mods. The only enforcement is build
  safety and stability (see [Security and trust model](#security-and-trust-model)).

## What a plugin looks like

A plugin is a directory under `plugins/` with a `manifest.json` and a Lua
entrypoint. Here is a trimmed `plugins/give_item/main.lua` — an admin command that
resolves a player's inventory and grants an item, replying privately to whoever ran
it (the real file adds count/id validation):

```lua
local ADD_ITEM = "/Script/Pal.PalPlayerInventoryData:AddItem_ServerInternal"

palmod.on_command("GiveItem", function(context)
    local args = context.args
    if #args < 2 or #args > 3 then
        palmod.reply(context, "Usage: !GiveItem <item_id> <player> [count]")
        return
    end
    local count = tonumber(args[3]) or 1

    -- Target the resolved player's inventory; fall back to the first live one.
    local target = palmod.inventory_of(args[2]) or "PalPlayerInventoryData"
    palmod.call(ADD_ITEM, {
        StaticItemId = args[1],
        Count = math.tointeger(count),
        IsAssignPassive = false,
        LogDelay = 0.0,
        bNotifyLog = true,
    }, target)

    palmod.reply(context, "Gave " .. count .. " " .. args[1] .. " to " .. args[2])
end)
```

Its `manifest.json` declares the command and its budgets:

```json
{
  "schema_version": 1,
  "id": "palmod.give_item",
  "version": "0.1.0",
  "entrypoint": "main.lua",
  "memory_limit_bytes": 8388608,
  "instruction_limit": 50000,
  "commands": [
    { "name": "GiveItem", "permission": "server.admin", "suppress": true }
  ]
}
```

In-game, commands use a `!` prefix (e.g. `!GiveItem Wood Player 5`) — Palworld's
client swallows `/`-prefixed lines locally for non-admins, so they never reach the
server. See the [plugin API reference](docs/plugin-api.md) for the full surface.

## Install

**Fastest — the release tarball.** Download the latest
`palmod-<version>-linux-x86_64.tar.gz` from Releases, extract it, and point the
bundled launcher at your server binary:

```sh
tar -xzf palmod-*-linux-x86_64.tar.gz && cd palmod-*-linux-x86_64
./run.sh --server /path/to/PalServer-Linux-Shipping -- -port=8211 -useperfthreads
```

It bundles the loader, a validated profile for Steam build 24088465, and the
example plugins; if your server is that build, hooks install immediately.

**From source** (for development or other server builds):

1. Install the prerequisites: Rust 1.95, a C++20 compiler, CMake, Ninja,
   pkg-config, and Lua 5.4 development headers. Server binaries are **not** needed
   to build or test.
2. Build the launcher, CLIs, and native loader: `make build` (or `make dist` for a
   release tarball).
3. A validated profile for build 24088465 ships in `profiles/`; any other build
   needs its own (Palmod refuses to hook a build it has no matching profile for).
   Drop your plugins into `plugins/`.
4. Launch the server under the loader, e.g.
   `PALMOD_HOOK_BACKEND=reflection target/debug/palmod-run --server <PalServer-Linux-Shipping> -- <server args>`.

Full instructions — including the profile pipeline for other builds — are in
[docs/install.md](docs/install.md); see [docs/toolchain.md](docs/toolchain.md) for
pinned tool versions.

## How it works

Palmod is not injected as a child process; the `palmod-run` launcher fingerprints
the target ELF, seals the matching profile into an in-memory descriptor, and hands
it to the server via `LD_PRELOAD`. Inside the process, a bootstrap thread waits for
the engine to construct, then installs the game-thread pump and hooks by swapping
Unreal data pointers (`UFunction::Func` / vtable slots) — no inline code patching.
The chat hook and generic-hook stubs decode `FFrame` locals on the game thread and
hand events to per-plugin Lua workers off-thread; plugin `palmod.call`s are queued
back to the game thread and dispatched through `ProcessEvent`. See
[docs/architecture.md](docs/architecture.md) for the end-to-end component map and
[docs/reversing.md](docs/reversing.md) for how profiles are produced.

## Security and trust model

The operator owns the box and runs their own plugins, so plugins have full access —
there is no capability gating, no trust tiers, and no required signing. The only
two enforced guarantees are:

- **Build safety** — the loader refuses to install any hook unless the target
  server ELF exactly matches a validated compatibility profile (fingerprint plus
  live anchor-byte preimages). This is a "never corrupt a mismatched build"
  guarantee, checked once in the launcher and again in-process before any hook is
  armed. A mismatched build gets zero hooks and runs vanilla.
- **Stability** — each plugin runs in its own isolated Lua state with memory and
  per-callback instruction budgets; dangerous standard libraries (`io`, `os`,
  `require`, `load`) are removed; and plugin work runs off the game thread with
  time budgets.

Command-level `permission` (`everyone` / `server.admin`) is a simple ACL enforced
against the game's own admin state, not a Palmod trust tier. See
[docs/security.md](docs/security.md) for the complete model.

## Project status

Palmod is pre-1.0 research-grade software, but it genuinely works: the generic
hook and call engines, read reflection, the Lua stdlib, and the example plugins are
all live-validated on the pinned server build (Steam build 24088465, UE 5.1.1). The
runtime, launcher, hook engine, and plugin API are build-agnostic; the addresses
live entirely in the compatibility profile. To run on any other build you
regenerate and validate a profile for that ELF — none of the pinned addresses carry
over. See [docs/design/roadmap.md](docs/design/roadmap.md) for direction and the
[reflection & mappings strategy](docs/design/reflection-mappings.md).

## Documentation

- [Install and run](docs/install.md)
- [Plugin API reference](docs/plugin-api.md)
- [Architecture](docs/architecture.md)
- [Security and trust model](docs/security.md)
- [Reversing workflow](docs/reversing.md)
- [Toolchain](docs/toolchain.md)
- [Lab runbook](docs/lab-runbook.md)
- [Roadmap](docs/design/roadmap.md)
- [Contributing](CONTRIBUTING.md)

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
