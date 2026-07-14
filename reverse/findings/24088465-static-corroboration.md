# Static corroboration — PalServer Linux build 24088465

Date: 2026-07-12. Tools: repo `palrev` + dependency-free
`reverse/palrevlib` mmap scanner + `objdump`. **No Ghidra, no running server.**

This record advances the candidate profile from evidence-ladder rung 1
(`candidate`) to rung 2 (`corroborated`). It does **not** validate anything:
rungs 3 (`observed`) and 4 (`validated`) still require a passive dynamic probe
and a disposable-server semantic test. The runtime remains fail-closed.

## Target

- Binary: `~/.cache/palmod/lab/24088465/Pal/Binaries/Linux/PalServer-Linux-Shipping`
- SHA-256 `a05788ead7619db22a1509c43241c16d289ed7040e8bcbb2e36e13e223e822f9`
- GNU build id `217802a00653a9c4`, size 196281496, ET_EXEC, image base `0x200000`.

## What was verified against the real binary

1. **Fingerprint** — SHA-256, build id, size, and image base all match the
   candidate profile exactly (confirmed independently by `palrev fingerprint`
   and by direct ELF parsing).
2. **Anchor preimages** — all **20** anchors in
   `profiles/candidates/palworld-linux-24088465.toml` have byte-exact
   `expected_bytes` at `image_base + rva`, with executability matching each
   anchor's `validators`.
3. **Independent rediscovery** — the mmap UHT name/thunk-pair scanner, run from
   scratch on the raw binary, rediscovered all six exec thunks at the *same*
   addresses (score 115 each), and confirmed each thunk contains an `E8`
   relative `call` into the claimed implementation:

   | reflected name            | exec thunk  | implementation |
   |---------------------------|-------------|----------------|
   | RequestAddItem_ToServer   | `0x6bdf6b0` | `0x6ed5fa0` (ret stub) |
   | RequestAddItem_ForDebug   | `0x6c5ef00` | `0x74cc460` (ret stub) |
   | AddItem_ServerInternal    | `0x6c5ecf0` | `0x74cc500` (real)     |
   | SendChatToBroadcast       | `0x69e2db0` | `0x70f9f40` (ret stub) |
   | BroadcastChatMessage      | `0x6a819a0` | `0x720a0e0` (real)     |
   | EnterChat                 | `0x6c6e980` | `0x74ef9e0` (real)     |

## ABI note: chat command ingress (EnterChat @ `0x74ef9e0`)

`EnterChat(rdi = player component, rsi = chat-value struct, edx = bool)`.
The chat value yields a string as `{ data_ptr = [rax], len_int32 = [rax+8] }`.
The command-detection logic is inline at `0x74efb4b` and `0x74efc05`:

```
movzx ecx, WORD PTR [rdx]   ; load one code unit
cmp   cx, 0x2f              ; compare to '/'
...
cmp   eax, 0x82             ; length bound (130)
```

**Chat text is UTF-16** (16-bit code units), and the game itself treats a
leading `/` as the command sigil. This contradicts the current native
`command_router`, which tokenizes chat as UTF-8/ASCII bytes. The eventual chat
adapter must transcode UTF-16 → UTF-8 before routing, or the router must learn
UTF-16. Filed as required work for the `observed` phase, not fixed
speculatively (no real chat adapter exists yet).

## Recovered calling conventions (capstone, `reverse/bin/decode_abi.py`)

Prologue argument-register recovery on the three real implementations. System V
AMD64; integer/pointer args fill `rdi,rsi,rdx,rcx,r8,r9` and float args fill
`xmm0..` independently, so an interleaved `float` lands in `xmm0` regardless of
its declared position.

- **AddItem_ServerInternal @ `0x74cc500`** — `rdi,rsi,rdx,rcx,r8 + xmm0`.
  Reads as `AddItem_ServerInternal(this, FName item, int32 count,
  bool is_assign_passive, float log_delay, bool unknown) -> bool`. The declared
  `float log_delay` is confirmed by the lone `xmm0` use. **This is the calling
  convention the real GiveItem adapter must marshal into before calling.**
- **BroadcastChatMessage @ `0x720a0e0`** — `rdi,rsi` (this + FPalChatMessage by
  ref), no float. Matches the declared single param.
- **EnterChat @ `0x74ef9e0`** — `rdi,rsi,rdx` (context + chat value + bool),
  no float. Matches the declared params and the exec-thunk register moves.

All three exec thunks contain a confirmed tail `E8 call` into their
implementation. These are ABI *hints* recovered structurally, still pending
dynamic confirmation.

## Recovered reflection layout (2026-07-12, `make lab-probe`)

Scanning the live server's writable memory for each exec-thunk pointer finds, per
function, exactly one read-only reference (the UHT registration table in the
binary) and several writable references (the reflection objects built at
startup). Cross-referencing the writable hits — every real `UFunction` shares the
class vtable — resolves the layout:

- **`UFunction` vtable = `0x1a48018`** (RVA `0x1848018`, in the binary's rodata).
- **`UFunction::Func` offset = `0xd8`** for build 24088465.

With that, exactly one writable hit per target is a genuine `UFunction::Func`
field (UObject header present at `slot - 0xd8`); the rest are native-function
lookup / delegate copies. So to intercept `EnterChat`, the reflection backend
swaps the qword at `UFunction(EnterChat) + 0xd8`.

**Runtime resolution needs no registry walk.** The heap addresses are per-run
(ASLR), but the backend runs in-process (LD_PRELOAD) and the exec-thunk VA is
build-fixed, so it locates the slot by scanning its own memory for that thunk
pointer and confirming the vtable at `slot - 0xd8` — using only the constants
above. This is implemented and tested as `ReflectionResolver`
(`native/src/reflection_resolver.cpp`). A `GUObjectArray`/name-lookup walk is
therefore unnecessary for hooking. Remaining: the FFrame-decoding trampolines and
carrying these constants in a validated profile.

## EnterChat FFrame decode (for the chat trampoline)

Disassembling the EnterChat exec thunk (`0x6c6e980`) shows the standard UE
`FFrame` decode a reflection hook trampoline must replicate to read the chat
argument. Args: `rdi = Context`, `rsi = FFrame& Stack`, `rdx = Result`. The
thunk reads from `FFrame` at:

- `Stack.Code` at `+0x20` (checked non-null to pick the compiled-in vs script
  path; also decremented near the end),
- the compiled-in `FProperty` chain pointer at `+0x88`, advanced by `+0x20` per
  step,
- `Stack.Locals`/property source at `+0x18`, passed to the step helpers
  (`0x7b48ff0`, `0x7b49020`, `0x7a94e80`).

It decodes a **16-byte refcounted chat value** into a local (`[data_ptr,
refcount_obj]`, with a `lock add [refcount_obj+8], 1` atomic addref — a
TSharedPtr-like handle) plus a trailing `bool`, then tail-calls the impl
(`0x74ef9e0`). The chat string itself is UTF-16 (see the slash-compare finding).
Remaining trampoline work: decode this handle to reach the FString, transcode
UTF-16→UTF-8, route through the command router, and optionally suppress — best
finalized with a live chat message observed under the harness.

## Server-side chat path + FPalChatMessage layout (live capture, 2026-07-12)

Captured under `make lab-capture` (gdb breakpoints on the running server while a
real client sent chat). Findings:

- **`EnterChat` is NOT the server-side receive path** — it never fired for
  client chat. The server-side chat choke point is
  **`PalGameStateInGame::BroadcastChatMessage`** (impl `0x720a0e0`), which fires
  for every message. `rdi = GameState`, `rsi = FPalChatMessage*`.
- **`FPalChatMessage` layout** (each string is an FString `{u16* data, i32 num,
  i32 max}`, text is UTF-16):
  - `+0x08` = sender-name data ptr, `+0x10` = num, `+0x14` = max — decoded to the
    player name (`"Player"`).
  - `+0x28` = message-text data ptr, `+0x30` = num, `+0x34` = max — decoded to the
    typed message (`"PALMODcapture7788"`, num `0x12` = 17 chars + null).
  - `+0x00` = a code/vtable pointer; `+0x18` = a 32-bit id/hash of the sender.
- **The client eats `/`-prefixed commands** — a client-typed `/GiveItem` returned
  "not logged in as admin" locally and never reached the server. So a chat-command
  trigger for normal players must use a **non-slash prefix** (e.g. `!pal ...`);
  slash-commands only reach the server for authenticated admins.

Chat trampoline design (next): reflection-hook `BroadcastChatMessage` (swap its
`UFunction::Func` via `ReflectionResolver` on thunk `0x6a819a0`), read the message
FString at `+0x28`, transcode UTF-16→UTF-8, route through the command router, and
suppress (skip original) when it matches our prefix. Open question to confirm
empirically: whether `BroadcastChatMessage` is dispatched via ProcessEvent
(reflection swap works) or called directly in C++ (needs the inline Gum fallback).
Its multicast-RPC nature strongly suggests reflection dispatch.

## Reflection globals + object layout (live, 2026-07-12, `find_reflection.py`)

Toward generating our own `.usmap` on the Linux server (see
docs/design/reflection-mappings.md). Recovered live and confirmed stable across
two fresh-ASLR runs:

- **`GUObjectArray` found.** Its `ObjObjects.Objects` field (`FUObjectItem**`) is
  a fixed global at **VA `0xc11d888` (RVA `0xbf1d888`)** — stable while the heap
  moved, confirming a `.bss` global. The `FUObjectArray` global begins just before
  it (Objects is the first field of the inner `FChunkedFixedUObjectArray`; expect
  `MaxElements/NumElements/MaxChunks/NumChunks` at `Objects + 0x10..0x1c`).
- **`FUObjectItem` size = 24** (`{UObject* Object, i32 Flags, i32 ClusterRoot, i32
  Serial}`); the array is chunked, entry `i` at `chunk_base + i*24`.
- **UObjectBase layout (UE 5.1) confirmed:** `vtable@0x00`, `ObjectFlags@0x08`
  (i32), `InternalIndex@0x0c` (i32), `ClassPrivate@0x10` (UClass*),
  `NamePrivate@0x18` (FName = i32 ComparisonIndex @0x18 + i32 Number @0x1c),
  `OuterPrivate@0x20` (UObject*).
- **vtables:** `UFunction` = `0x1a48018`, `UClass` = `0x1a47c08`. A UObject is
  validated by its vtable landing in the image range.
- EnterChat's `UFunction` had InternalIndex 10100 and FName ComparisonIndex
  **314463** (both stable) — the latter is the pool index for "EnterChat".

Remaining for a full dumper: (a) the **FName pool** global + `FNameEntry` layout
to resolve ComparisonIndex → string; (b) `UStruct` (`SuperStruct`, `Children`,
`ChildProperties`, `PropertiesSize`) and `FField`/`FProperty` (`Next`,
`NamePrivate`, `Offset_Internal`, `ArrayDim`, `ElementSize`) layouts to read
properties + their live offsets; (c) the walker + `.usmap`/JSON serializer.

## LIVE VALIDATION of reflection hooking (2026-07-12)

With a real client connected (`make lab-capture` +
`reverse/gdb/broadcast_chat_capture.gdb`, breakpoints on the exec thunk `0x6a819a0`
AND the impl `0x720a0e0`), a plain chat message "reflectiontest" was sent. Result:

- **The exec thunk `0x6a819a0` fired** (3×) — `BroadcastChatMessage` IS
  ProcessEvent-dispatched, so swapping its `UFunction::Func` (our `ChatHook`)
  intercepts chat for real. No inline/Gum fallback needed.
- The message decoded from the live `FPalChatMessage` (UTF-16 "reflectiontest"),
  confirming the trampoline's decode path on real data.

This validates the entire chat pipeline end to end: reversing → `ReflectionResolver`
→ `PointerSlotHook` → `ChatHook` trampoline → `decode_chat_event` → event bus. Every
piece was unit-tested against synthetic memory; the live run confirms the two
real-world assumptions (reflection dispatch + FFrame/FPalChatMessage layout).

Harness gotcha burned here: gdb hung on debuginfod auto-download for the 196 MB
binary + EOS/Steam .so's — must `set debuginfod enabled off` + `DEBUGINFOD_URLS=""`
(now in scripts/lab-capture.sh). Also the server binds udp/8211 early (~99 MiB)
before the world finishes loading; port-bound is not "joinable".

## Reflection-hooking plan (preferred over inline patching)

Interception will use atomic data-pointer swaps, not inline code hooks. The
`ReflectionHookBackend` skeleton and the `PointerSlotHook` primitive exist and
are tested; they fail closed until a validated reflection layout is supplied.
The layout facts still to recover (need the reflection object layout, best
confirmed on the disposable server) are:

- `UFunction::Func` field offset for this build — the slot to swap to intercept
  a reflected function such as `EnterChat`. The UHT registration tables we
  verified are the source that populates these `Func` pointers at startup.
- A periodic game-thread callback slot — a `ProcessEvent` vtable entry, or a
  per-frame tick `UFunction` — to drive the action-queue drain without an inline
  tick hook.
- The `AddItem_ServerInternal` call binding: its address (`0x74cc500`,
  recovered convention above) plus how to obtain the target player's inventory
  `this` and construct an `FName` for the item id. Direct call, no hook.

## Live-image observation (2026-07-12, `make lab-observe`)

The disposable server boots cleanly (main ELF mapped at load base `0x200000`,
matching `image_base`; ~1.2 GiB RSS, 42 threads, udp/8211 bound). All **20**
profile anchors were read back byte-exact from the running process's
`/proc/<pid>/mem`, so the exact code we identified statically is present and
unmodified in the live server. This is the seed of the `observed` rung. What it
does not yet show: that each thunk is *reached* on the game thread at the
expected frequency — that needs a breakpoint/uprobe-style probe, the next step.

Harness note: the observer must own the server process (yama `ptrace_scope=1`
only lets an ancestor read `/proc/<pid>/mem`), so `observe_live.py` launches it
as a child rather than attaching to a daemonized instance.

## Still blocked (rungs 3–4)

- Passive Frida probe on the running server (`palrev probe`) to confirm each
  thunk is reached on the expected thread with expected data. Needs the server
  running (≥12 GiB free; ~14 available now) and a working Frida Python module
  (currently import-broken) plus a `frida-server`.
- Disposable-server semantic test proving AddItem actually grants an item and
  rolls back, then `palrev approve` promotes the candidate → `validated`
  (fingerprint + anchor bytes + passive evidence re-checked; no signing).
- Ghidra is not installed; full decompilation of the AddItem calling convention
  and the authoritative admin check still needs it (or more objdump work).
