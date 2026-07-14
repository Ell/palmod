# Reflection & mappings strategy

Status: design (2026-07-12). Supersedes the "hand-pin every function RVA in the
profile" approach for anything beyond the initial vertical slice.

## Why this exists

We are building the equivalent of UE4SS for the **native Linux Palworld dedicated
server**. UE4SS has **zero Linux support** (confirmed) — it is Windows-first (DLL
injection, MSVC, Windows hooking libs), so it is not drop-in. But its *method* and
the Palworld community's *data* are highly reusable. This doc records how.

Palworld runs **Unreal Engine 5.1.1**. All UE-layout constants below are
5.1-specific and build-specific; treat every hex offset as a candidate until
confirmed on our exact Linux build (24088465) via the lab harness.

## How UE4SS avoids per-game offsets (the model we should adopt)

UE4SS does **not** hardcode "BroadcastChatMessage is at 0x720a0e0" or "chat text
is at +0x28." It finds a small set of **engine globals** via AOB (byte-pattern)
signature scans — `GUObjectArray`, the `FName` pool, `ProcessEvent`, `GMalloc`,
`GNatives` — and then gets **everything else from the engine's own reflection
metadata at runtime**:

- functions resolved **by name** by walking `GUObjectArray`,
- **property byte offsets read live from `FProperty::Offset_Internal`** — never
  hardcoded.

Per UE version it only re-finds ~6 globals; reflection provides the rest. This is
far more update-resilient than pinning every RVA, and we are already halfway there
(our `reverse/palrevlib` UHT-table scanner finds functions by reflected name).

## The .usmap file format (what it is, and what it is NOT)

`.usmap` (Unreal Mappings) is a binary **serialization schema** — the type system
of a UE game — consumed by asset tools (FModel, UAssetGUI) and mod loaders.

Binary layout (16-byte header + payload):

| off | type | field |
|-----|------|-------|
| 0x00 | u16 | magic `0x30C4` |
| 0x02 | u8  | version |
| 0x03 | i32 | HasVersionInfo flag |
| 0x07 | u8  | CompressionMethod (None or ZStandard) |
| 0x08 | u32 | CompressedSize |
| 0x0C | u32 | DecompressedSize |
| 0x10 | …   | (compressed) payload |

Payload (after decompression) = three sections:
1. **Name table**: `u32 count`, then `u16 len + char[len]` (deduplicated strings).
2. **Enums**: `u32 count`, then per enum: name index + `u16 member count` + member
   name indices.
3. **Structs/classes**: `u32 count`, then per struct: name index, super-struct name
   index, property count + serializable count, then property records —
   **{ schema index, array dim, name index, recursive type }**.

**Critical: `.usmap` stores property name, type, and serialization ORDER — NOT
byte offsets.** It exists for unversioned property *serialization* (reader matches
by schema order/index), so it never needs memory offsets. Therefore:

- `.usmap` gives us the **"what"**: every `UClass`/`UFunction`/`UStruct`, every
  property's name/type/order. E.g. it tells us `FPalChatMessage` has a sender
  `FString` and a message `FString` and their order — but not that the message is
  at `+0x28`.
- Memory **offsets** (the "where") we get separately: read live from
  `FProperty::Offset_Internal`, or compute from the ordered type list + alignment
  (reliable only for pure-reflected structs; native USTRUCTs can have
  non-`UPROPERTY` members that create gaps — we saw exactly this in
  `FPalChatMessage`: a code ptr at +0x00 and a hash at +0x18 between the reflected
  strings).

## Reusing the community Palworld .usmap

A public Palworld `Mappings.usmap` exists (UE 5.1.1) — see Sources. Reuse plan:

1. **Parse it** (documented format above) into a schema: all classes, functions,
   structs, property names/types/order.
2. Use it as the **map of what to hook and what fields exist** — replacing
   guesswork. It gives us the full inventory: chat functions, `AddItem`
   variants, admin/permission fields, item-id enums, player structs, etc.
3. It does **not** give offsets or addresses — those stay our job on the Linux
   binary. So `.usmap` = schema oracle; live reflection = offsets; our ELF
   fingerprinting = addresses.

Caveat: community dumps are made from the **Windows client**. The *schema* is
identical across platforms for the same game version; *addresses* are not (Linux
server ≠ Windows client, Clang/Itanium ≠ MSVC). Reflected-property offsets are
generally identical across x64 platforms for the same build, but we read them
live on Linux anyway, so this is moot for us.

## Creating our own mappings on the Linux server

The update-resilient endgame: an **in-process reflection dumper** (a diagnostic
`LD_PRELOAD` build — no ptrace, we run inside the server) that walks the live
reflection and emits a schema **with authoritative memory offsets**. This is what
UE4SS's dumper does; we do it on Linux.

Steps:
1. **Find `GUObjectArray`** (the `FUObjectArray` global) and the **`FName` pool**
   on the Linux binary — via AOB signature scan or by anchoring off data we
   already locate (the UHT registration tables, the `UFunction` vtable at
   `0x1a48018`).
2. **Walk `GUObjectArray`** → every `UObject`; filter to `UStruct`/`UClass`/
   `UFunction` (by `ClassPrivate`/vtable).
3. For each, read from the live object:
   - `NamePrivate` (`FName`) → resolve via the `FName` pool → string,
   - the `ChildProperties` (`FField`) chain → per `FProperty`: name (`FName`),
     type (`FFieldClass`), **`Offset_Internal` (the memory offset)**, `ArrayDim`,
     `ElementSize`,
   - `SuperStruct`, `Children`.
4. Emit either a real `.usmap` (schema, for tooling parity) **and/or** a richer
   JSON schema-with-offsets (what we actually need for hooking).

Layout constants for the Linux 5.1 build (`reverse/bin/find_reflection.py`
recovers these live). **Recovered + confirmed stable (build 24088465):**
- `GUObjectArray.ObjObjects.Objects` (`FUObjectItem**`) fixed global @ VA
  `0xc11d888` (RVA `0xbf1d888`); the `FUObjectArray` global begins just before it.
- `FUObjectItem` size `24`; chunked, entry `i` @ `chunk_base + i*24`.
- UObjectBase: `vtable@0x00`, `ObjectFlags@0x08`, `InternalIndex@0x0c`,
  `ClassPrivate@0x10`, `NamePrivate@0x18` (FName {i32 cmp @0x18, i32 num @0x1c}),
  `OuterPrivate@0x20`.
- vtables: `UFunction` `0x1a48018`, `UClass` `0x1a47c08`. `UFunction::Func` @
  `+0xd8`.

**Recovered (all confirmed live):**
- `FNamePool.Blocks` (`uint8*[]`) fixed global @ VA `0xc07b0c0` (RVA `0xbe7b0c0`).
  FName decode: block = `id >> 16`, byte offset = `(id & 0xffff) * 2`, entry =
  `Blocks[block] + offset`; header `u16` (Len = `hdr >> 6`, wide = `hdr & 1`),
  chars follow.
- `UStruct.ChildProperties` @ `0x50` (`FField*`).
- `FField`: `ClassPrivate` @ `0x08` (FFieldClass*, has FName @ `0x00` = the
  property type name), `Next` @ `0x20`, `NamePrivate` @ `0x28`.
- `FProperty`: `ElementSize` @ `0x38`, `Offset_Internal` @ `0x4c`.

**The dumper exists and works** (`make lab-dump` →
`reverse/bin/dump_reflection.py`, backed by `reverse/palrevlib/reflection.py`).
On build 24088465 it walked **155,505 objects → 45,526 structs, 155,388
properties** with authoritative offsets. It confirmed every hand-reversed value,
e.g. `PalChatMessage`: `Sender@8 (Str)`, `Message@40 (Str)`; and gives the full
inventory ABI `AddItem_ServerInternal`: `StaticItemId@0 (Name), Count@8 (Int),
IsAssignPassive@12 (Bool), LogDelay@16 (Float), bNotifyLog@20 (Bool),
ReturnValue@21 (Enum)`. Output is a JSON schema-with-offsets (richer than
`.usmap`); a `.usmap` serializer for tooling parity is a later add.

Inner types are captured too (`FProperty` base size `0x78`; inner ref @ `+0x78`):
StructProperty→`<Guid>`, ArrayProperty→`<StructProperty<Guid>>`, Object/Enum
targets, etc. Consumable via `reverse/palrevlib/schema.py` + `make reflect-check`
(cross-checks the runtime's hardcoded chat offsets against the dump).

Each function's `UFunction::Func` (exec thunk) RVA is captured too (`func_rva`,
26,801/26,804 functions on build 24088465; verified e.g. `BroadcastChatMessage` →
`0x6a819a0`). With `func_rva` (the swap target) + the param layout (offsets +
types) the dump is now the complete data foundation for a **generic hook by
name**: `pal.hook("Foo", fn)` → look up `func_rva` + params → resolve the slot →
swap to a generic trampoline → decode params from the layout → deliver an event.
Query via `schema.function_thunk_rva(name)` / `function_params(name)`.

Remaining for generic hooking (native build): a generic Parms decoder (per
FProperty type: int/float/bool/`FString`→UTF-8/`FName`→pool, struct/object as
opaque handles), a typed event payload (map of `{param: value}` rather than the
flat `PluginEvent` fields), and the `pal.hook(name, fn)` Lua API.

TODO polish: `UStruct.SuperStruct` (inheritance); UEnum values (UEnum stores a
Names array, not ChildProperties); a real `.usmap` *binary* serializer for tooling
parity (we already have the richer JSON-with-offsets, which the runtime uses).

Payoff: this **replaces essentially all manual per-function/offset reversing**
(BroadcastChatMessage, AddItem, chat field `+0x28`, player fields, item enums)
with one live dump, cross-validated against the community `.usmap`, regenerated
per game update.

## Phased plan

1. **Now (done/in progress):** direct address+offset reversing for the first
   vertical slice (chat event, GiveItem) — enough offsets hand-recovered + live
   captured to build and unit-test the pipeline. Keep going to a first working
   live hook.
2. **Next:** find `GUObjectArray` + `FName` pool on the Linux server; build the
   in-process reflection dumper. Emit schema-with-offsets.
3. **Then:** parse the community Palworld `.usmap`; cross-validate our dump; drive
   `palrev` profile generation from the dump instead of hand authoring. Resolve
   functions by name at runtime through reflection (drop static RVAs where we
   can).
4. **Ongoing:** per game update, re-run the dumper + re-fingerprint; the profile
   regenerates instead of being re-reversed by hand.

## Sources

- [.usmap format — Dumper-7 MappingGenerator (DeepWiki)](https://deepwiki.com/hswangrui/Dumper-7/4.2-mappinggenerator-usmap-files)
- [UnrealMappingsDumper (TheNaeem)](https://github.com/TheNaeem/UnrealMappingsDumper)
- [UE4SS dumpers / DumpUSMAP](https://docs.ue4ss.com/feature-overview/dumpers.html)
- [RE-UE4SS](https://github.com/UE4SS-RE/RE-UE4SS)
- [Palworld Mappings.usmap — PalworldModding/UsefulFiles](https://github.com/PalworldModding/UsefulFiles/blob/master/Mappings.usmap)
- [elliotks/Palworld-FModel (usmap + AES)](https://github.com/elliotks/Palworld-FModel)
- [Unofficial Modding Guide — UE4SS and Mappings](https://unofficial-modding-guide.com/posts/ue4ss_and_mappings/)
