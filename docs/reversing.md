# Reproducible reversing workflow

The reverse pipeline turns an exact PalServer Linux ELF into reviewable
evidence. It does not turn a plausible address into a validated runtime profile
automatically.

## Toolchain stance

Because this is Unreal, the automated backbone is structural, not a full
decompile (see the next section). Discovery, byte verification, and ABI recovery
run in the dependency-free pipeline. The heavyweight tools are reserved and
optional:

- Headless Ghidra/PyGhidra is a scriptable program database for one-time deep
  decompilation the structural tools cannot reach (complex control flow, the
  authoritative admin check). It is not on the automated path.
- Frida is the dynamic microscope for the `observed` rung — confirming a
  candidate is reached on the expected thread with expected data — and supplies
  the optional inline-hook Gum backend. It is not required to hook: production
  interception prefers atomic data-pointer swaps (see the architecture doc).

UE4SS remains a valuable Unreal-specific reference for reflection discovery,
object/function modeling, and pattern organization. Its current Windows hook
and ABI assumptions are not copied into the Linux runtime. Palmod borrows the
separation between discovery, generated metadata, and a stable plugin surface,
then supplies Linux ELF, Itanium C++ ABI, and native-server-specific adapters.

## Lightweight structural path (the automated backbone)

Because this is Unreal, UHT reflection emits regular `{name-ptr, exec-thunk-ptr}`
registration tables, so *discovery* does not require a full Ghidra analysis. The
dependency-free `reverse/palrevlib` mmap scanner rediscovers every reflected
function's exec thunk structurally, in under a second and with no privileges,
and it reproduces cleanly across game updates. `reverse/bin/verify_profile.py`
(wrapped by `make reverse-verify SERVER_BINARY=...`) is the automatable static
gate: it checks the fingerprint, verifies every anchor's preimage bytes,
resolves each exec thunk's direct call to its implementation, and triages real
implementations from generated `ret` stubs — exit non-zero on any anchor or
fingerprint failure.

The profile this pipeline produces is deliberately small: `[reflection]` roots
and offsets, a few non-reflected hook facts (`[reflection.chat]`,
`[reflection.engine_tick]`, `[reflection.admin]`), the `[elf]` fingerprint, and a
short build-identity anchor set for verification. It carries **no per-function
hook catalog** — hooking resolves each reflected `UFunction` live by name at
runtime (case-insensitively, reading its parameter layout from the live object),
exactly as `pal.call` does, so no baked function definitions are generated or
required.

For deeper ABI recovery without Ghidra, `reverse/bin/decode_abi.py` (optional
`capstone` extra, see `reverse/requirements-optional.txt`) disassembles each exec
thunk and native implementation to recover incoming argument registers — enough
to reconstruct a callable calling convention. Ghidra is therefore **optional and
off the automated path**: reserve it for one-time deep decompilation the
structural tools cannot reach (complex control flow, the authoritative admin
check), not for routine discovery. Frida stays scoped to the
in-process production Gum backend and the passive `observed`-rung probe; on
hosts with root, eBPF uprobes (`bpftrace`) are a lighter alternative for passive
observation only.

## Evidence ladder

Every semantic target moves through these states:

1. `candidate`: found by a static heuristic, string xref, or table shape.
2. `corroborated`: independent static strategies agree and the surrounding
   disassembly matches the expected Unreal construct.
3. `observed`: a passive dynamic probe confirms call behavior and invariants.
4. `validated`: a disposable-server scenario proves the semantic effect and
   rollback behavior for the exact build fingerprint.

Only `validated` entries may authorize a runtime hook. The distinction is stored
in machine-readable profile data and enforced by the launcher and runtime.

## Unreal targets

Prefer engine structures that survive stripping over brittle whole-function
byte signatures:

- reflected UTF-16/ASCII names and their xrefs;
- UHT native registration tables containing `(name, exec-thunk)` pairs;
- generated `exec` thunks and parameter-decoding shapes;
- `UFunction` / native function registration paths;
- `ProcessEvent`-family dispatch and world-tick boundaries;
- authoritative controller/admin checks and stable player identity fields.

Signatures should anchor invariant control/data relationships and wildcard
relocations or build-specific addresses. A profile still records hook-site
preimage bytes so a false match cannot patch memory.

## Current candidate

The initial Linux build is Steam build `24088465`, depot manifest
`3392720560779800260`, GNU build ID `217802a00653a9c4`, and SHA-256
`a05788ead7619db22a1509c43241c16d289ed7040e8bcbb2e36e13e223e822f9`.
Static triage found the reflected name `RequestAddItem_ToServer` at virtual
address `0x00c9ad28`, a possible generated thunk at `0x06bdf6b0`, and a possible
implementation at `0x06ed5fa0`. Exact segment-aware inspection then showed that
the latter begins with `ret`; it is a generated/default no-op stub, not an
inventory mutation primitive.

A better semantic candidate is the reflected `AddItem_ServerInternal`: string
VA `0x00cbe617`, native table entry `0x017d4620`, exec thunk `0x06c5ecf0`, and
real call target `0x074cc500`. Its thunk decodes an `FName`, `int32`, `float`, and
two booleans and returns a boolean. `RequestAddItem_ForDebug` also resolves to a
no-op stub. All of these remain explicitly unvalidated until automated export,
prototype recovery, object-lifetime work, and disposable-server probes agree.

## Promotion checklist

- Fingerprint exactly matches the analyzed ELF.
- Script output is deterministic on a fresh Ghidra project.
- At least two independent static observations support the target.
- Calling convention, parameter layout, and pointer lifetimes are documented.
- Passive probe validates module bounds, thread identity, and call frequency.
- Fake harness exercises install, failure rollback, and stale handles.
- Disposable server proves the semantic behavior and a negative case.
- Profile marked `validated` once evidence is attached. The runtime then enforces
  the exact ELF fingerprint + live anchor bytes at launch — there is no signing or
  trusted keys.
