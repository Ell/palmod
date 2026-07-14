# Trust and safety model

Palmod runs **in-process** in the Palworld dedicated server via `LD_PRELOAD` and
hooks the engine through UE5 reflection. It has the same authority as the server
itself, so a wrong offset or a stray write could corrupt or crash the process.
That is the risk this model addresses: **not breaking your own server**.

It is deliberately *not* a model for defending against the mods you install. You
own the box, and you run your own plugins — you read their Lua before you drop
them in. Palmod enforces exactly two things: **build safety** (never touch a
server binary it doesn't exactly recognize) and **stability** (a buggy plugin
can't take down the game loop). Everything else is out of scope by design.

## What Palmod does NOT do (removed by design)

Earlier drafts of this project described a capability-scoped, signed, trust-tiered
model. None of that exists in the code, and it is not coming back. To be explicit:

- **No capability gating.** Every plugin gets the full `palmod.*` API
  unconditionally. There is no capability manifest, no per-plugin grant list. A
  plugin may hook any of the game's reflected `UFunction`s, call any function,
  read any object, and register any command.
- **No trust tiers.** There is no "trusted" vs "untrusted" plugin — just plugins.
  All loaded plugins are equally full-powered.
- **No required signing.** There is no cryptographic profile signature and nothing
  is gated on one. See [Profiles are not signed](#profiles-are-not-signed) below.
- **No anti-spoofing.** Palmod has no anti-spoof layer. Where a command is marked
  admin-only, admin status is read from the game's own live state
  (`PalPlayerController.bAdmin`), not from any Palmod identity machinery.

If you see any of those concepts in older docs, treat them as stale. The source
under `crates/`, `native/`, and `sdk/` is authoritative.

## Guarantee 1 — Build safety

This is the only hard gate on installing hooks: Palmod refuses to arm a single
hook unless the target server ELF **exactly** matches a validated compatibility
profile. The guarantee is "never corrupt a mismatched build." It is a fingerprint
plus a byte-preimage match — no signatures, no keys — and it is enforced twice:
once in the launcher before the server is spawned, and once inside the loader
before any hook is armed.

A compatibility profile (see [docs/reversing.md](reversing.md) for how one is
produced) binds to exactly one ELF and carries:

- an `[elf]` fingerprint: SHA-256, GNU build id, machine, bits, endianness, ELF
  type, image base, and file size;
- a `status` of `candidate` or `validated`;
- one or more `[anchors.*]`: masked byte patterns (`"48 8b ?? 90"`, with `??`
  wildcards) at a given RVA, with optional `executable` / `unique` validators.
  These are the "never corrupt a mismatched build" preimages.

### Launcher side (`palmod-run`)

`palmod-run` (`crates/palmod-run/src/main.rs`) is the parent process; it never
injects blindly.

- `run()` fingerprints the target ELF up front and hands that fingerprint to
  `select_profile()`, which scans the `--profiles` directory (top level,
  non-recursive) and keeps only profiles whose `[elf]` fingerprint **exactly**
  matches (SHA-256 + build id + machine + bits + endian + ELF type + image base +
  file size). It requires **exactly one** match, and that match must be
  `status = validated`.
  - No matching profile → the server starts **vanilla**, with nothing injected
    (unless you pass `--require-profile`, which makes it fail instead).
  - A single match that is only `candidate` → the launcher **refuses to launch**
    (it does not silently fall back to vanilla).
- Immediately before hand-off, `verify_anchor_bytes()` re-reads the ELF and checks
  every anchor's masked bytes at `image_base + rva`, plus each anchor's validators.
- The verified profile is serialized to canonical JSON, written into an
  `MFD_ALLOW_SEALING` memfd, sealed with `F_SEAL_SHRINK | GROW | WRITE | SEAL`, and
  passed to the child as `PALMOD_PROFILE_FD` (the fd number), `PALMOD_PROFILE_SHA256`
  (a digest of the JSON), and `PALMOD_PROFILE_ID`. The fd is deliberately **not**
  `CLOEXEC`: this inherited, sealed descriptor is the trust hand-off. A
  plaintext-path profile is never passed.

### Loader side (in-process)

`Runtime::start` (`native/src/runtime.cpp`) re-verifies everything before it arms a
hook, so a compromised or mismatched environment cannot smuggle a profile past it:

- The plaintext `PALMOD_PROFILE` env var is **refused outright** — only a sealed
  `PALMOD_PROFILE_FD` is accepted.
- `read_sealed_profile()` requires the inherited fd to be `>= 3`, not `CLOEXEC`, a
  **fully sealed** memfd (all four seals present), and 1 B–4 MiB.
- It recomputes the SHA-256 of the memfd bytes and compares against
  `PALMOD_PROFILE_SHA256` with a constant-time comparison.
- `BuildProfile::parse_json` parses the profile; `exactly_matches()` re-checks
  `status == validated` plus SHA-256, ELF build id, and file size against
  `fingerprint_self()` (which fingerprints `/proc/self/exe`).
- `verify_anchors()` re-reads each anchor's bytes from the **live** process image
  (`process_vm_readv`) and matches the masked pattern.

On any fingerprint or anchor mismatch, the runtime enters `UnsupportedBuild` and
returns **before** any hook is installed. A mismatched build gets zero hooks — it
runs as a plain, unmodified server.

### Crash quarantine

Repeated non-clean exits are treated as a build-safety signal too. `palmod-run`
tracks a sliding failure window in `--state-dir/quarantine.json`; reaching
`--crash-limit` (default 3) failures within `--crash-window-seconds` (default 600)
quarantines that profile id, after which it launches vanilla until you pass
`--clear-quarantine`. A clean stop (SIGINT/SIGTERM) is not counted as a crash.

### Profiles are not signed

There is **no** cryptographic profile signature anywhere in the code, and nothing
is gated on one. SHA-256 is used only for (a) the ELF fingerprint and (b)
integrity of the sealed-memfd hand-off between launcher and loader — never for
authenticity. The launcher and reverse tooling say so directly in comments
("no signatures or trusted keys"; "No signing").

The only "promotion" concept is the profile `status` enum: `candidate` →
`validated`. That flag is **unsigned** — flipping it to `validated` (via
`palrev approve`, which re-checks the exact fingerprint, the static anchor bytes,
and that the runtime evidence was gathered passively) is a maturity marker, not a
signature. Treat profile signing as absent, not as an optional convenience.

## Guarantee 2 — Stability (per-plugin isolation)

Plugins have full functional access; the sandbox exists only to stop a *buggy*
plugin from destabilizing the server, not to constrain a *malicious* one. From
`native/src/plugin_runtime.cpp`:

- **Isolation.** Each plugin is its own `lua_State` (Lua 5.4) on its own dedicated
  thread, running off the game thread. Plugin-issued game calls (`palmod.call`)
  are pushed to a bounded game-thread action queue and executed on the engine
  tick, so plugin work never runs where a fault would corrupt live objects.
- **Memory budget.** A custom allocator enforces the manifest's
  `memory_limit_bytes` (default 32 MiB, clamped 1 MiB–32 MiB). Over-budget
  allocations fail rather than growing without bound.
- **Instruction budget.** A count hook (`LUA_MASKCOUNT`, every 1000 instructions)
  enforces the manifest's `instruction_limit` (default 250,000, clamped
  1,000–250,000). It is re-armed for plugin init and for **each** command and
  event callback; overrunning raises a Lua error instead of hanging the worker.
- **Dangerous stdlibs removed.** `open_safe_libraries()` opens **only** `base`,
  `table`, `string`, `math`, and `utf8`, then nils `dofile`, `loadfile`, `load`,
  and `collectgarbage`. Not opened at all: `io`, `os`, `require`/`package`,
  `debug`, `coroutine`. Plugins are kept to the semantic API — again for
  stability, not as a trust boundary.
- **Other bounds.** Command and event queues are each capped at 256 pending items;
  `manifest.json` must be ≤ 256 KiB; `commands` ≤ 64; a `palmod.call` path is
  ≤ 256 bytes with ≤ 64 args; the entrypoint must be a bare `*.lua` filename (no
  path separators, no `.`/`..`); the plugin id must match `[a-z][a-z0-9_.-]{1,63}`.

Hot reload is transactional: a bad edit fails to load and the previously running
plugin set keeps running (see [docs/architecture.md](architecture.md)).

## Operator control socket

The operator control surface (driven by `palmodctl`, and by the `command.invoke` /
`plugins.reload` / `status` methods) is a local Unix socket, not a network
listener. From `native/src/control_server.cpp` and `Runtime::control_request`:

- It is an `AF_UNIX` `SOCK_SEQPACKET | SOCK_CLOEXEC` socket at an absolute path.
  After `bind` it is `chmod` to `0600` (owner read/write only). `safe_remove_stale`
  refuses to replace a path that is not a socket or is owned by a different uid.
- The socket is created only **after** the profile gate passes, so a co-preloaded
  process with no valid profile fd can't stand up the control surface.
- Every connection is authenticated by Unix identity: `SO_PEERCRED` must report a
  uid equal to the server's `geteuid()`, else the request is rejected with "peer
  credentials rejected." Only the same local user who runs the server can drive it.
- Each connection carries a 2-second receive timeout, is one request → one
  response, and packets are capped at 64 KiB (`MSG_TRUNC`-guarded). Requests use a
  strict `{id, method, params}` envelope and a fixed method allowlist; unknown
  methods return `method_not_found`.
- A `command.invoke` from the socket is routed with `AuthState::Admin` and
  `PrincipalKind::LocalOperator` carrying the peer uid — i.e. the local operator is
  trusted as admin by virtue of Unix identity, distinct from in-game admin.

The default socket path is a private `0700` directory under `XDG_RUNTIME_DIR`
(`$XDG_RUNTIME_DIR/palmod/control.sock`), overridable with `--control-socket` or
`PALMOD_CONTROL_SOCKET`. See [docs/install.md](install.md) for launch details.

## Command permission (an ACL, not a trust tier)

Distinct from plugin powers: an individual **command** can be marked admin-only.
This is a per-command ACL, not a capability or trust tier.

- A manifest's per-command `permission` is `everyone` or `server.admin` only.
- `CommandRouter::route` rejects a `server.admin` command unless the caller's
  `AuthState == Admin`. Admin status comes from the **game's own** admin state:
  `resolve_player_auth` reads `PalPlayerController.bAdmin`, correlated to the chat
  sender's UID. It is read from live game state — there is no Palmod-side identity
  or anti-spoof layer, and an operator on the local control socket is admin by Unix
  identity as described above.

## Threat model and non-goals

Palmod's security scope is narrow and intentional:

- **In scope:** never patching a server binary Palmod does not exactly recognize
  (build safety), and keeping a buggy plugin from crashing or hanging the server
  (stability). Plus keeping the local control surface local and owner-only.
- **Out of scope by design:** Palmod does **not** sandbox against a malicious
  operator — the operator owns the machine and has full authority. It does **not**
  sandbox against a malicious plugin — plugins are code you chose to install and
  run, with full access to the game via reflection; read them before you deploy
  them. It does **not** authenticate remote callers (there is no network control
  surface), and it does **not** attempt to out-argue the game's own admin state.

If you need to run untrusted third-party plugins, that is not a use case Palmod
currently defends — vet the Lua yourself.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
