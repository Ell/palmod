# Palmod roadmap & status

A living map of what exists, what's proven, and what's next. Updated 2026-07-12.
Pairs with [reflection-mappings.md](reflection-mappings.md) and the per-build
findings in `reverse/findings/`.

## One-line vision

A UE4SS-equivalent mod framework for the **native Linux Palworld dedicated
server**: LD_PRELOAD injection, operator-supplied Lua plugins, a **general typed event
bus** (chat is just one event), fail-closed behind build-matched per-build
profiles. Hooking is **reflection/data-pointer swaps**, not inline patching.

## Architecture decisions (settled)

- **Reflection-first hooking.** Intercept by swapping `UFunction::Func` (and, for
  ticks, a vtable slot) — atomic 8-byte pointer stores, no relocator, no
  thread-suspend. Frida-Gum is an optional inline fallback only. Mutation is a
  direct ABI call, not a hook.
- **General event framework.** A hook decodes its payload into a typed
  `PluginEvent` and fans it out async to subscribed plugins (`on_event`).
  Command recognition + suppression is the one *bounded synchronous* native layer
  on top (can't run plugin Lua inside a game-thread hook).
- **Fail closed on *build*, not on plugins.** No hooks without a validated
  profile matching the exact ELF + live anchor bytes (crash-safety). Plugins have
  **full access** — no capability or permission model, no "trusted" vs
  "untrusted" plugin (it's the operator's own code); what remains is stability
  (off-thread + budgets), not a trust boundary. There is **no profile signing,
  keys, or trust store** — correctness is the exact ELF
  fingerprint + live anchor bytes, not authorship.
- **Adopt the UE4SS reflection model** for maintainability — resolve by name +
  read offsets live rather than pinning RVAs. See reflection-mappings.md.

## Built and tested (native `make check` green)

- Loader/launcher: sealed-memfd profile handoff, ELF fingerprint + anchor
  preimage verification, crash quarantine (`palmod-run`).
- Profiles: `crates/palmod-profile` (no signing/keys); the launcher + native
  runtime enforce fingerprint + anchors + `status=validated`. `[reflection]`
  schema section carries `ufunction_func_offset`, `ufunction_vtable_va`.
- Plugin sandbox: isolated Lua 5.4 per plugin, allocator/instruction budgets,
  transactional reload.
- **Event framework**: `PluginEvent`, Lua `on_event`,
  async per-plugin delivery, `PluginRuntime`/`Runtime::deliver_event` fan-out.
- **Player resolution**: `PlayerDirectory` (stable-id wins, unique display name,
  else refuse), fed by `on_player_join/leave`, enforced on the game thread.
- **Adapter-availability gate**: game thread refuses actions whose semantic
  adapter the profile doesn't declare.
- **Reflection hooking primitives**: `PointerSlotHook` (atomic swap+restore,
  mprotect-guarded), `ReflectionResolver` (in-process scan for a thunk pointer,
  validate vtable at `slot-func_offset` — ASLR-robust, no registry walk needed),
  `ReflectionHookBackend` (fail-closed).
- **Chat pipeline (mechanism-tested against synthetic memory)**: `utf16_to_utf8`,
  `decode_chat_event` (FPalChatMessage → chat event), `ChatHook` (resolve
  BroadcastChatMessage Func slot → swap → trampoline reads FFrame.Locals → decode
  → deliver → chain original). Delivery seam `HookCallbacks::on_event` →
  `Runtime::deliver_event`.
- **Reverse tooling**: dependency-free UHT scanner, `verify_profile.py` (static +
  `--pid` live), capstone `decode_abi.py`, and a full **lab harness**
  (`make lab-preflight|observe|probe|capture|start|stop`) that boots the real
  server and reads its memory.

## Proven on the real server (build 24088465, UE 5.1.1)

- Fingerprint + all 20 anchors byte-exact (static and in **live** memory).
- All 6 hook thunks independently rediscovered; real-vs-ret-stub triaged.
- Calling conventions recovered (e.g. `AddItem_ServerInternal` @ `0x74cc500` =
  `(this, FName item, i32 count, bool, bool) + xmm0 float`).
- **Reflection layout**: `UFunction::Func` offset `0xd8`, `UFunction` vtable
  `0x1a48018`.
- **Live chat capture**: server-side choke point is `BroadcastChatMessage`
  (`0x720a0e0`), NOT EnterChat. `FPalChatMessage`: sender FString `+0x08`, message
  FString `+0x28`, UTF-16. Decoded a real "Player"/"test message" message.
- **Palworld client eats `/`-commands locally** (admin-gated) — player chat
  commands must use a non-slash prefix (e.g. `!pal`).

## Next (immediate)

- ~~Confirm the `UFunction::Func` swap catches `BroadcastChatMessage`~~ **DONE
  (live-validated 2026-07-12):** the exec thunk `0x6a819a0` fires on chat →
  ProcessEvent-dispatched → the reflection swap intercepts chat; no Gum fallback.
- ~~Profile plumbing for the chat hook~~ **DONE:** `[reflection.chat]` carries
  `broadcast_thunk_rva` + `fframe_locals_offset` + sender/text offsets (Rust
  `ChatHookFacts`, native `BuildProfile.chat_*`, candidate profile populated);
  `ReflectionHookBackend::install` builds the resolver + `ChatHook` from those and
  delivers via `HookCallbacks::on_event` → `Runtime::deliver_event`. Per-hook
  fail-closed. All unit-tested.

Remaining to a live end-to-end run (operational, not code unknowns):
1. Select the reflection backend (`PALMOD_HOOK_BACKEND=reflection`) and mark a
   profile `validated` (`palrev approve`) so the fail-closed runtime will run + hook.
2. A ProcessEvent-vtable tick hook to drain the action queue on the game thread
   (still uses the injected test slot; needs its own reversing).
3. **Inventory adapter**: `FName` construct + obtain player inventory `this` →
   direct call `AddItem_ServerInternal` (ABI + Parms layout already recovered).

## Generic "hook anything by name" engine (in progress)

The goal ("automatically support all hooks in the game since we generate the
dump"): `pal.hook("SomeUFunction", fn)` works for any of the ~26,800 functions
with no per-function C++.

Data foundation — **DONE**: the reflection dump carries, per function, both the
swap target (`func_rva` = `UFunction::Func` exec thunk RVA) and the param layout
(name/type/offset). Query via `schema.function_thunk_rva(name)` +
`function_params(name)`.

Generic decoder core — **DONE + tested** (`native/src/parms_decode.cpp`,
`decode_parms`): given a `Parms` buffer + the param layout, decodes int/float/
bool/enum/`FString`→UTF-8/`FName`→pool into a `{name, number|text}` arg list;
struct/object/array skipped for now. Unit-tested against synthetic Parms
(`test_parms_decode`), all warnings clean.

Multi-hook routing — **DONE + tested** (`native/src/generic_hook.cpp`,
`GenericHookTable`): many functions have distinct Func thunks, but every hook
swaps its slot to the same trampoline, so the trampoline must learn *which*
UFunction fired. Resolved via a **stub pool** — a compile-time pool of
`kCapacity` (128) distinct static trampoline stubs, each carrying its index →
its table entry. No FFrame.Node reversing needed; caps concurrent hooks at 128
(bump the constant, or upgrade to an FFrame.Node registry, if that's ever hit).
`install(spec, resolver, fname, deliver)` resolves the Func slot, claims a free
stub, swaps; the stub decodes that entry's Parms via `decode_parms` into a
`GenericEvent{name, args}` and chains the original. Unit-tested with two
functions hooked at once, verifying independent routing + exact slot restore
(`test_generic_hook`).

Typed event payload — **DONE**: `PluginEvent` now carries `std::vector<EventArg>
args`, marshaled into Lua as `event.args[name] = value` (string or number) in
`invoke_event`. Flat/bespoke events leave it empty; generic hooks fill it from
`decode_parms`.

`pal.hook(name, fn)` Lua API + full pipeline — **DONE + tested** (Rust + native +
reverse all green, warning-clean):
- **Lua**: `palmod.hook(name, fn)` subscribes to a function-named event (sugar
  over `on_event`); `event.args` surfaces the decoded params.
- **Live resolution (no catalog)**: hooking is resolved LIVE by name, exactly
  like `pal.call` — the backend finds the UFunction in `GUObjectArray`
  (`find_function`, case-insensitive), takes its Func slot (UFunction +
  `func_offset`) as the atomic swap target, and reads its parameter layout live
  (`read_struct_layout`). The profile no longer carries a `functions` catalog.
  The FFrame Locals offset is a build-wide `reflection.fframe_locals_offset`
  (default `0x18`); Rust `ReflectionProfile` carries `fframe_locals_offset`
  (round-trips, validated).
- **Wiring**: after the backend installs, `Runtime::install_generic_hooks`
  gathers `PluginRuntime::subscribed_event_kinds()` and, for each subscribed
  function name, builds a `GenericHookSpec` and calls
  `HookBackend::install_generic_hook`, which resolves the slot live.
- **Backend**: `ReflectionHookBackend::install_generic_hook` resolves the slot
  (stored resolver) → `GenericHookTable` swap → decode → deliver a `PluginEvent`
  via `callbacks.on_event`. Tested end-to-end against a synthetic UFunction
  (`test_reflection_generic_hook`).

Blueprint support + FName resolution — **DONE + tested**:
- **Blueprint functions are first-class**: any package root (`/Script`, `/Game`,
  `/Engine`, plugin roots) resolves live by name — Blueprint (`/Game/...`)
  functions hook exactly like native ones.
- **Live layouts**: because hooking resolves by name against `GUObjectArray`, the
  backend reads each function's parameter layout live (`read_struct_layout`) at
  install time — there is no baked catalog to generate or ship. (The
  `gen_hook_catalog.py` generator, the `make hook-catalog` target, and
  `test_gen_hook_catalog` have been removed.)
- **FName resolution**: native `FNamePool` (`fname_pool.cpp`) reads the live name
  pool; `ReflectionHookBackend` builds it from `reflection.fname_pool_blocks_va`
  (native + Rust `ReflectionProfile.fname_pool_blocks_va`, candidate profile
  populated `= 0xc07b0c0`) and passes its resolver into `decode_parms`, so
  `NameProperty` args now decode to strings (item ids, tags) not indices. Tested
  (`test_fname_pool` + end-to-end in `test_reflection_generic_hook`).

**The generic "hook anything by name" engine is complete and production-
wireable.** `decode_parms` covers the full common FProperty surface: signed/
unsigned ints, floats, bool, enum, `FString`→UTF-8, `FName`→string, object/class
pointers→handles, `ArrayProperty` (of scalars **or structs**) → a Lua list, and
`StructProperty` → a nested keyed Lua table (recursive, depth-bounded). The whole
chain is plumbed: dumper captures element `inner_size` + struct layouts (Outer
paths, `_inner_size`); the generator emits `inner_type`/`inner_size`/nested
`fields`; profile `ParameterProfile` + native `ParamSpec` carry them; the runtime
marshals arrays/structs recursively — all verified through real Lua in
`test_generic_hook_lua` (array sum + `struct.X`). A reference plugin ships at
`plugins/hook_watch`.

Remaining decoder polish only: `Set`/`Map` properties (rare); exposing a struct's
raw address as a handle. The **FFrame.Node registry** upgrade path (read the
executing `UFunction*` from `FFrame`; `Locals` is `+0x18`, Node offset would need
live reversing) stays available if the 128-hook stub-pool cap is ever reached.

## Mutation path (write side) — reflection-driven, and LIVE-VALIDATED

**DONE + validated live (2026-07-13):** gave 5 Wood to a connected player on the
real server — item appeared in-game, no crash. Every ingredient came from
reflection + the binary, zero hardcoded layout: item id `"Wood"→0x1573ad` (FName
pool reverse-lookup), `this=0x7f160eb9fa00` (GUObjectArray walk for the non-CDO
`BP_PalPlayerInventoryData_C`), impl `0x74cc500` + ABI (disassembled the exec
thunk). Called via gdb on the game thread (break on the chat thunk). Full recipe +
confirmed facts in the `palmod-giveitem-live-validated` memory. Remaining: wire
the direct-ABI call into the native inventory adapter so it runs through the
loader instead of gdb (all mechanisms already built + unit-tested).

Important correction (now proven): the mutation path (call a UFunction to *change*
game state, e.g. `GiveItem` → `AddItem_ServerInternal`) is **built from
reflection**, the same as the read side. It does **not** need hand-reversed memory
layout — every offset and address comes from the dump. **The whole write-side mechanism is now built and
unit-tested offline** (all synthetic-memory tested, `make check` green):

- **Encode Parms** — `parms_encode.cpp` `encode_parms`: the write-side inverse of
  `decode_parms`, places typed values at reflected offsets (scalars + `NameProperty`
  via an `FNameEncoder`). Round-trips through the decoder (`test_parms_encode`).
- **Find the target `this`** — `object_walk.cpp` `follow_pointer_chain`: walks a
  chain of *reflected* pointer offsets (player → inventory component → data),
  fail-closed on any bad link (`test_object_walk`).
- **Invoke** — `invoke.cpp` `read_vtable_slot` + `call_process_event`: read
  `UObject::ProcessEvent`'s address from the target's vtable slot and dispatch
  `(function, parms)`. The ProcessEvent ABI is stable UE; only its slot/address are
  build-specific (`test_invoke`).
- **Capstone** — `generic_call.cpp` `call_ufunction`: resolves the UFunction object
  from its exec thunk via the *same* `ReflectionResolver` the hook path uses
  (`slot - func_offset`), encodes the Parms, and dispatches via ProcessEvent —
  fail-closed. Full encode→resolve→invoke chain tested with a synthetic UFunction +
  target + fake ProcessEvent, verifying the forwarded Parms decode back to the
  inputs (`test_generic_call`).

So the write engine is symmetric with the read engine — reflection-driven,
mechanism-complete, offline-tested. The **only** things left need the running
server, and none is "reverse the layout": (1) the `ProcessEvent` vtable **slot
index**; (2) the specific player→inventory **navigation path** (offsets are
reflected; the path wants a live graph to confirm); (3) `FName` reverse-lookup
(string→index) needs a little pool allocator metadata (block count/used size); and
(4) **end-to-end validation** — because a bad mutating call crashes the whole
server, we prove it live before trusting it. That's safety, not a data dependency.

## Next (strategic — the big lever)

Adopt the UE4SS reflection model on Linux: find `GUObjectArray` + `FName` pool,
build an in-process reflection dumper, cross-validate against the community
Palworld `.usmap`, and drive profile generation from the dump instead of hand
reversing. See [reflection-mappings.md](reflection-mappings.md). This retires most
manual offset work and makes updates a re-dump, not a re-reverse.

## Constraints / gotchas for future sessions

- `make lab-observe`/`probe`/`capture` must **own** the server process (yama
  `ptrace_scope=1` lets only an ancestor read `/proc/<pid>/mem`).
- gdb `-batch` breakpoint commands **abort (exit 2, killing the server)** on any
  error — keep pointer-follow filters tight (`($p>>40)==0x7f`).
- Foreground `sleep` in a harness Bash call is blocked — use a `run_in_background`
  until-loop for readiness waits.
- Optimized builds **dead-store-eliminate** writes only read via opaque scans —
  synthetic-memory tests need an `__asm__ __volatile__(... "memory")` barrier.
- Always confirm a build actually compiled before trusting a test result (a
  failed build leaves a stale binary).
- clippy pedantic wants underscored hex literals (`0x01a4_8018`).
