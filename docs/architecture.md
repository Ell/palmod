# Architecture

Palmod is an in-process mod framework for the native Linux Palworld dedicated
server. It is not an RCON wrapper and it does not infer game state from a sidecar
API. A launcher injects a small shared object with `LD_PRELOAD`; that runtime
validates the exact server build, installs only profile-approved hooks, reads
and drives the game through Unreal Engine reflection, and hosts sandboxed Lua
plugins. In effect it is a UE4SS-equivalent built for the headless Linux server.

This document describes how the pieces fit together and, in particular, how work
crosses the boundary between the game thread and the off-thread plugin workers.
Security posture (the build gate, the plugin sandbox, the control-socket
authentication) is summarized here only where it shapes the design; the
authoritative treatment is in [docs/security.md](security.md).

## Overview

```text
palmod-run (parent process, not injected)
  fingerprint PalServer ELF -> select exactly one matching validated profile
  seal profile JSON into a memfd -> pass the fd to the child (the trust handoff)
  LD_PRELOAD=libpalmod.so exec PalServer-Linux-Shipping

PalServer-Linux-Shipping (server process, libpalmod.so injected)
  loader constructor -> spawn detached bootstrap thread -> return
  bootstrap thread:
    read + verify sealed profile -> fingerprint self -> verify anchor bytes
    wait for GEngine/GUObjectArray to exist
    load plugins (each: own thread, own Lua state)
    install hooks: GEngine::Tick pump, chat hook, generic UFunction hooks from subscribed plugin kinds
  game thread (server's own): swapped Func/vtable slots
    Tick drain -> ProcessEvent dispatch of queued calls
    chat + generic-hook trampolines decode FFrame Locals
  control-server thread: SOCK_SEQPACKET accept loop  <- palmodctl
  plugin-watch thread: 1s mtime poll -> transactional reload
```

The runtime fails closed. An absent, unknown, or malformed profile means no game
hooks are installed at all.

## The out-of-process launcher (`palmod-run`)

`palmod-run` (`crates/palmod-run`) is the parent process, not the injected code.
It exists to set up a trustworthy handoff and then inject the loader:

- **Preflight and layout.** It requires `--server` to name a
  `PalServer-Linux-Shipping` binary under a `.../Pal/Binaries/Linux/` tree
  (the `PalServer.sh` wrapper is rejected), infers the server root, and stages
  `steamclient.so` from the Steam depot into place (hash-verified, never
  overwriting a differing file).
- **Profile selection.** It fingerprints the target ELF (SHA-256 + GNU build-id
  + machine/bits/endian/type + image base + file size) and scans `--profiles`
  (top level only). Exactly one profile must match the fingerprint and carry
  `status = validated`; more than one match, a candidate-only match, or no match
  each has a defined outcome. There are no signatures or keys — the fingerprint
  plus the live anchor bytes are the whole gate.
- **The sealed handoff.** The selected profile is serialized to canonical JSON,
  hashed, written into a `memfd_create(MFD_ALLOW_SEALING)` descriptor, and sealed
  with `F_SEAL_SHRINK|GROW|WRITE|SEAL`. The memfd is deliberately **not**
  `CLOEXEC`, so the child inherits it; that inherited sealed fd is the trust
  handoff. The launcher passes its number as `PALMOD_PROFILE_FD` and the digest
  as `PALMOD_PROFILE_SHA256`, alongside `PALMOD_PLUGIN_DIR`,
  `PALMOD_CONTROL_SOCKET`, and `PALMOD_STATE_DIR`.
- **Spawn and supervision.** It sets the working directory to the server root,
  strips inherited `PALMOD_*`/`LD_PRELOAD`, prepends `libpalmod.so` to
  `LD_PRELOAD`, and forwards `SIGINT`/`SIGTERM`/`SIGHUP`. A clean signal-driven
  stop is recorded as planned, not as a crash.
- **Crash quarantine.** Repeated non-clean exits inside a sliding window
  quarantine that profile id in `state-dir/quarantine.json`; a quarantined
  profile launches vanilla (no injection) until `--clear-quarantine`.

Launch and flag details are in [docs/install.md](install.md).

## In-process bootstrap

Injection enters through `palmod_bootstrap()`, a
`__attribute__((constructor(200)))` in `native/src/bootstrap.cpp`. The
constructor does almost nothing: unless `PALMOD_DISABLE_AUTOLOAD=1`, it calls
`start_process_runtime_async()`, which idempotently `pthread_create`s and
detaches a **bootstrap thread** and returns. All heavy startup — the profile
gate, waiting for the engine, installing hooks, loading the first plugins — runs
on that detached thread, never in the loader constructor, so blocking waits are
safe and the dynamic loader is never held up.

## The build gate

Before anything is hooked, `Runtime::start` (`native/src/runtime.cpp`) runs a
single-shot gate. It refuses a plaintext `PALMOD_PROFILE` path entirely (the
sealed fd is the only accepted channel), reads the inherited memfd and confirms
it is fully sealed and not `CLOEXEC`, recomputes its SHA-256 and constant-time
compares it against `PALMOD_PROFILE_SHA256`, parses it as a `schema=1`
`BuildProfile`, fingerprints `/proc/self/exe`, and requires an exact match of
`status=validated` + executable SHA-256 + ELF build-id + file size. Finally it
re-reads each anchor's expected bytes from the live process image (via
`process_vm_readv`, honoring `??` wildcards) and requires every non-wildcard byte
to match. A fingerprint or anchor-byte mismatch transitions to
`RuntimeState::UnsupportedBuild`, while a profile-integrity failure (a refused
plaintext `PALMOD_PROFILE` path, a SHA-256 length or compare mismatch, a
sealed-memfd read failure, or a schema parse failure) transitions to
`RuntimeState::Failed`. Either way the gate returns **before** any hook is
installed — the "never corrupt a mismatched build" guarantee. The parsed profile also carries the reflection facts (offsets, vtable
VAs, `GUObjectArray`/`GEngine` addresses, chat and admin layout) used by
everything below; there is no baked generic-hook catalog — hook targets are
resolved live by name (see the generic hook engine). See
[docs/security.md](security.md) and [docs/reversing.md](reversing.md).

## Hook backend selection

Interception is a pluggable `HookBackend` (`native/src/hook_backend.cpp`),
chosen by `PALMOD_HOOK_BACKEND`:

- `reflection` — the production backend: data-pointer / vtable-slot hooks driven
  by validated reflection facts. It is fail-closed and installs nothing without a
  validated reflection layout.
- `frida-gum-passive` — an optional inline-hook backend, present only when built
  against the Frida Gum devkit; otherwise an unavailable stub.
- unset / default — a no-op backend that loads plugins but installs no game
  hooks.

The runtime holds one backend for the process lifetime.

## Hook mechanism: atomic pointer swaps

The reflection backend never rewrites code. It installs a hook by atomically
swapping a single aligned data pointer:

- **`UFunction::Func` swap** — every reflected UFunction has a `Func` member (a
  `void*` exec-thunk pointer at a per-build offset inside the UFunction header).
  Overwriting that pointer redirects the engine's own dispatch of that function
  to our trampoline. This is the UE4SS-style interception point.
- **vtable-slot swap** — for periodic work we swap one entry of `GEngine`'s
  vtable (its `Tick` slot) to a trampoline, giving us a callback that runs every
  frame on the game thread.

`PointerSlotHook` (`native/src/reflection_backend.cpp`) does this: it validates
8-byte alignment (refusing a non-atomic write), `mprotect`s the containing page
writable, records the original pointer, then performs a single
release-ordered `std::atomic_ref` store of the replacement. `uninstall`
restores the original the same way.

Data-pointer swaps are chosen over inline code patching on purpose. An aligned
8-byte store is atomic on x86-64, so the swap needs no thread suspension and no
instruction relocation, and it can never leave a half-written instruction in a
concurrently executing function — the only race is which pointer a caller
observes, and both values are valid function entries. Inline patching (used only
by the optional Frida backend for the rare non-reflection site) has none of
those guarantees.

Turning a profile's exec-thunk RVA into the live `Func` slot to overwrite is the
job of `ReflectionResolver::resolve` (`native/src/reflection_resolver.cpp`). It
parses `/proc/self/maps` for private, writable, non-file-backed regions, scans
them (in fault-tolerant `process_vm_readv` chunks) for a word equal to the thunk
address, and accepts a candidate slot only when the word at `slot - func_offset`
equals the UFunction vtable VA (confirming a real UFunction header) **and** the
match is unique across the scan. Zero or multiple matches are refused rather than
guessed.

## Engine-readiness wait

`LD_PRELOAD` runs before the engine constructs `GEngine` and `GUObjectArray`, so
the backend cannot hook immediately. It polls the profile's `GEngine` global
(up to ~240s, fault-safe reads) and treats the engine as ready only when both
`GEngine`'s vtable pointer and its `Tick` slot entry land inside the executable
image. Individual hooks are fail-open — a miss logs and continues, and the chat
hook retries for up to ~180s because `BroadcastChatMessage`'s UFunction may
register after `GEngine` becomes valid — but the backend as a whole fails only if
nothing installs.

## Generic hook engine

Palmod can hook any of the game's ~26k reflected UFunctions by name with no
per-function native code and no baked catalog. A plugin subscribes via
`palmod.hook("FuncName", fn)` (sugar for an event subscription). At the end of
`Runtime::start`, `install_generic_hooks` takes each plugin's subscribed hook
kinds — each is simply a UFunction name — and resolves it **live**, exactly like
`pal.call`: `find_function` locates the `UFunction` in `GUObjectArray`
(case-insensitive) and `read_struct_layout` reads its parameter layout from
reflection. Nothing is baked into the profile. The result is a `GenericHookSpec`
(name, the live `Func` slot to swap, FFrame Locals offset, decoded parameter
layout).

Routing uses a fixed static **stub pool** (`native/src/generic_hook.cpp`).
`GenericHookTable` generates, at compile time, an array of `kCapacity`
trampolines `stub<0..N>` via `std::index_sequence`; each is a distinct function
whose only distinguishing feature is its compile-time index `I`. Installing a
hook claims a free entry, resolves the target's live `Func` slot, and
pointer-swaps it to `stubs()[id]`. When the engine later dispatches that
UFunction, control lands in `stub<I>` **on the game thread** (it is the game's
own exec thunk), which calls `dispatch(I, context, fframe, result)`. `dispatch`
reads the `FFrame::Locals` pointer at the spec's offset, calls `decode_parms` to
turn the live parameter buffer into named `event.args`, delivers the event, and
then **always** chains the original exec thunk. Generic hooks are
observation-only; they never suppress the original function.

`decode_parms` (`native/src/parms_decode.cpp`) is the shared decoder for both
hook parameters and read-side property reads. It reads fault-safely
(`process_vm_readv`) so it is safe over live, racing objects, and handles the
integer/float/bool/enum scalars, object/class/weak pointers (as opaque numeric
handles — observation only), `FString`, `FName` (index resolved to text),
`TArray`, and nested structs (depth-bounded).

## Generic call / mutation engine

Mutation uses the reverse path: `palmod.call("/Script/Pkg.Class:Func", args[,
target])`. Because a UObject call must happen where the objects are stable, the
call is not executed inline — the plugin worker enqueues a
`SemanticAction{CallFunction}` onto the game-thread action queue, and
`ReflectionHookBackend::execute_call` runs it during the tick drain **on the game
thread**:

1. Parse the `/Script/Pkg.Class:Func` path into function + owning class and
   locate the `UFunction` in `GUObjectArray`; pick the target (an explicit
   object handle, or the first live non-CDO instance of the class).
2. `read_struct_layout` reads the parameter layout **live** from reflection
   (walking the UStruct `ChildProperties` chain — element size, internal offset,
   inner/struct layouts), so nothing is baked into the profile.
3. `encode_parms` writes a Parms buffer from the Lua args (scalars, bool/float,
   enum/byte, `FString` and `TArray` backed by stable pools, `FName` via the
   name encoder, nested structs); absent params are left zeroed at their ABI
   default.
4. `read_vtable_slot` reads `ProcessEvent` from the target's vtable at the
   profile's `process_event_vtable_slot`, and `call_process_event` invokes the
   standard `UObject::ProcessEvent(UFunction, Parms)` dispatch.

This is why mutation goes through `ProcessEvent` rather than a bespoke native
call per function: one encode/dispatch path covers every reflected function, with
no per-command native code.

## Read-side reflection

The read API surfaced to plugins is `ReflectionReader`
(`native/src/reflection_reader.cpp`): `find_object`, `find_all_of`, `get`
(property read), `class_of`, and `datatable_rows`. It is built over
`ObjectArray` (`native/src/object_array.cpp`), which walks the chunked
`GUObjectArray` with direct in-process reads — the walk touches ~155k objects and
runs where UObjects are stable, guarded by a canonical-address check. Property
reads locate the `FProperty` up the super chain and decode straight from the
object's absolute offset via `decode_parms`. Read handles are opaque generational
integers; plugins never receive raw Unreal pointers. Reads issued from plugin
workers run off the game thread, which is why `decode_parms` is fault-safe.

## Chat hook, events, and command routing

Chat is a bespoke hook rather than a generic one. `ChatHook`
(`native/src/chat_hook.cpp`) intercepts `BroadcastChatMessage`; its trampoline
runs on the game thread, fault-safe-reads the `FFrame::Locals`, and decodes
sender, text, category, and the sender's GUID. From there:

- **Every** chat line is emitted as a `chat` `PluginEvent` and fanned out to
  subscribed plugins (off-thread).
- If the text begins with `!`, the backend resolves the sender's server-side
  admin state by walking `GUObjectArray` and reading the game's own
  `PalPlayerController.bAdmin` (correlated by sender UID), translates `!` to `/`,
  and calls `Runtime::on_chat` -> `CommandRouter::route`
  (`native/src/command_router.cpp`). The router tokenizes (quote/escape aware,
  bounded), looks up the canonical command, enforces the per-command
  `everyone` / `server.admin` permission against that admin state, and dispatches
  to the owning plugin (off-thread).
- The trampoline's return value is the suppression decision: if the router
  matched a suppressing command, the original broadcast is not chained (the line
  is swallowed); otherwise it chains through.

The `!` prefix exists because Palworld's client swallows `/`-prefixed lines
locally for non-admins, so they never reach the server.

## Event fan-out to plugins

`Runtime::deliver_event` is the one funnel from game-thread hooks to plugins. A
hook decodes its payload into a `PluginEvent` (kind, sequence, source/text/
subject, handle, number, and — for generic hooks — `args` keyed by parameter
name) and calls `deliver_event`, which enqueues a copy onto each subscribed
plugin's event deque. Delivery is asynchronous and filtered by each plugin's
subscribed-kind set, so a hot game-thread hook never runs plugin code inline. The
documented event kinds are `chat`, `player.join`, and `player.leave`; every
generic hook adds its UFunction name as a kind. The plugin-facing surface (event
fields, the `palmod.*` primitives, the embedded Lua stdlib) is documented in
[docs/plugin-api.md](plugin-api.md).

## The game-thread action queue

`ActionQueue` (`native/src/action_queue.cpp`) is the single thread boundary from
off-thread plugin workers back to the game thread. `push` (called from a plugin
worker when Lua invokes `palmod.call`) is mutex-guarded and bounded; over
capacity it increments a dropped counter and returns false, surfaced to Lua as
"game-thread action queue is full". `drain` enforces that it only ever runs on
the bound game thread — it records the first draining thread id and refuses (with
an `action.wrong_thread` log) to execute on any other — so a semantic action can
never be dispatched from the wrong thread.

The reason the queue exists: reading and especially **calling** UObjects safely
requires the game thread, where object lifetimes and the engine's own invariants
hold. Encoding parameters from live reflection, resolving the target, and
invoking `ProcessEvent` all happen there. The `GEngine::Tick` trampoline is the
pump: each frame it calls `Runtime::on_game_tick` -> `actions_.drain` ->
`execute_action_on_game_thread` -> the backend's `execute_call`. `CallFunction`
is currently the only `SemanticAction` kind.

## Plugin runtime

Each plugin is an `Instance` (`native/src/plugin_runtime.cpp`) with its own
`std::thread` and its own Lua 5.4 `lua_State`, running command and event
callbacks off the game thread. Isolation is about stability, not capability: a
custom allocator enforces a per-plugin memory budget, an instruction-count hook
enforces a per-callback instruction budget (re-armed each invocation), and only
`base`/`table`/`string`/`math`/`utf8` are opened (`io`/`os`/`require`/`load`/
`dofile`/`loadfile`/`collectgarbage` are removed). All plugins receive the full
`palmod.*` API — there is no capability gating or trust tiering; see
[docs/security.md](security.md). A worker loop waits on its command/event deques,
builds the Lua context/event table, and `pcall`s the handler; a `palmod.call`
inside a handler becomes a `SemanticAction` pushed to the action queue.

## The control socket

`ControlServer` (`native/src/control_server.cpp`) is a side channel into the same
router and reload paths, started by `Runtime::start` **only after the profile
gate passes** (so a co-preloaded subprocess without a valid profile fd cannot
create the socket). It is an `AF_UNIX` `SOCK_SEQPACKET` endpoint at an absolute
path, `chmod` 0600, refusing to replace a stale path that is not a
same-uid-owned socket. Its own accept thread handles one packet per connection:
`SO_PEERCRED` must equal the server's euid, the request is a single bounded JSON
object, and the response is a single JSON object. `Runtime::control_request`
enforces a strict envelope and implements `ping`, `status` / `plugins.list`
(runtime state, hook backend, action-queue depth/drops, profile id, executable
digests, per-plugin state), `plugins.reload` (full transactional reload only),
and `command.invoke` (routed as a local operator with admin auth). The client is
`palmodctl` (`crates/palmodctl`).

## The hot-reload watcher

`start_plugin_watch` (`native/src/runtime.cpp`) runs a thread that, about once a
second, computes the newest regular-file mtime under the plugin directory
(recursive, fresh `stat`) and, on any increase, calls `reload_plugins`. Reloads
are **transactional**: a fresh `PluginSet` (new router + runtime, reattaching the
reflection reader) is built and its `load_directory_report` must succeed, or the
swap is abandoned and the previously loaded plugins keep running. On success the
set is swapped atomically under a unique lock and the old set is destroyed after
draining its already-accepted callbacks. The same path backs the control
socket's `plugins.reload`.

## Threading model summary

- **Loader constructor** (library load): spawns the bootstrap thread and returns.
- **Bootstrap thread** (detached): the whole profile gate, the engine-readiness
  wait, all hook installation, and the first plugin load. Blocking is fine here.
- **Game thread** (the server's own, entered through swapped `Func`/vtable
  slots): the `GEngine::Tick` drain (dispatching `palmod.call` via
  `ProcessEvent`), the chat trampoline, and the generic-hook stubs. The
  `GUObjectArray` walk and parameter encode/decode run here where objects are
  stable.
- **Control-server thread**: the uid-gated `SOCK_SEQPACKET` accept loop.
- **Plugin-watch thread**: the ~1s mtime poll and transactional reload.
- **Per-plugin worker threads** (one each): isolated Lua state with memory and
  instruction budgets, running callbacks off the game thread and pushing
  `SemanticAction`s to the queue.

The dominant data flow is one-directional: game-thread trampolines decode FFrame
Locals into `PluginEvent`s / `CommandInvocation`s enqueued to off-thread plugin
workers; a worker runs Lua and pushes a `SemanticAction`; the `GEngine::Tick`
drain executes it via `ProcessEvent` back on the game thread. The control socket
is a side channel into the same router and reload paths, and the profile gate
plus live anchor bytes are the sole hard enforcement before any hook is armed.

## Components

- `crates/palmod-run`: the out-of-process launcher and the only supported
  injection path (fingerprint, profile selection, sealed handoff, supervision,
  crash quarantine).
- `crates/palmodctl`: local operator client for status, reload, and command
  invocation over the bounded Unix `SOCK_SEQPACKET` control socket.
- `crates/palrev`: ELF fingerprinting and profile inspection/generation tools.
- `crates/palmod-profile`: the profile format and its fingerprint/anchor matching
  logic, shared by the launcher and the reverse tools.
- `native/`: the injected C++20 runtime — bootstrap, build gate, hook backends,
  reflection resolver, generic hook/call engines, chat hook, object array and
  read-side reflection, action queue, plugin runtime, control server, hot-reload
  watcher, plus a fake-server test harness.
- `sdk/`: the stable plugin manifest schema and the Lua-facing API, including the
  embedded stdlib run into every plugin sandbox.
- `plugins/`: first-party example plugins built purely on the generic engine
  (`give_item`, `find_item`, `hook_watch`).
- `reverse/` and `profiles/`: the structural reversing pipeline and the
  reviewable build profiles + evidence it produces.

## Compatibility boundary

Plugins target semantic function names and reflected properties, not addresses. A
build profile maps those semantics to one exact PalServer build and carries the
fingerprint, anchor preimages, reflection facts, and validation status. Updating
Palworld therefore requires a profile/revalidation cycle
([docs/reversing.md](reversing.md)) rather than recompiling plugins.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
