# hook_watch — generic by-name hook example

Demonstrates `palmod.hook("FunctionName", fn)`: observe any game `UFunction` by
name (resolved live), with its parameters decoded into `event.args`.

## How it works

- `palmod.hook(name, fn)` subscribes to a function by its reflected name. The
  runtime resolves the `UFunction` live from `GUObjectArray` (case-insensitive) —
  no profile catalog needed — installs a `UFunction::Func` reflection hook on its
  `Func` slot, reads its parameter layout live, and delivers each call as an event.
  This works for any of the game's reflected `UFunction`s by name.
- `event.args[param]` holds the decoded arguments: integers/floats/bools/enums as
  numbers, `FString` as UTF-8 strings, `FName` resolved to strings (when the
  profile supplies `reflection.fname_pool_blocks_va`), object pointers as numeric
  handles. Struct/array parameters are omitted for now.
- Hooking is **observation-only** — the original function always runs.

Both native (`/Script/...`) and Blueprint (`/Game/...`) functions are supported,
resolved live by name with no per-function configuration.
