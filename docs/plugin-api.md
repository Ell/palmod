# Plugin API

A Palmod plugin is a directory containing a `manifest.json` and a Lua 5.4
entrypoint. Plugins target semantic Palmod APIs — reflected `UFunction` and
class names — never PalServer addresses or Unreal object layouts. Everything a
plugin can do goes through one global table, `palmod`, plus a pure-Lua standard
library that is preloaded into every plugin.

This page is the authoring reference. For building and launching the loader see
[docs/install.md](install.md); for how the runtime is wired together see
[docs/architecture.md](architecture.md); for the trust and safety model see
[docs/security.md](security.md).

## Plugin layout

Drop a subdirectory into your plugin directory (default `plugins/`, overridable
with `palmod-run --plugin-dir`). The loader scans one `manifest.json` per
subdirectory, then runs the entrypoint it names:

```
plugins/
  my_plugin/
    manifest.json
    main.lua
```

### `manifest.json`

The manifest is a JSON object of at most 256 KiB. Fields:

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `schema_version` | yes | integer | Must be exactly `1`. |
| `id` | yes | string | Unique across loaded plugins. Length 2–64, matching `^[a-z][a-z0-9_.-]{1,63}$` (first char lowercase `a`–`z`; the rest lowercase letters, digits, `_`, `.`, `-`). |
| `version` | yes | string | Free-form, non-empty. Not otherwise validated. |
| `entrypoint` | yes | string | A bare `*.lua` filename resolved relative to the manifest's directory. Length 1–128; no `/` or `\`; not `.` or `..`; must be an existing regular file. |
| `memory_limit_bytes` | no | integer | Per-plugin Lua allocator budget. Default `33554432` (32 MiB); allowed range 1 MiB (`1048576`) – 32 MiB (`33554432`). |
| `instruction_limit` | no | integer | Lua instruction budget, re-armed for each callback and for plugin init. Default `250000`; allowed range `1000`–`250000`. |
| `commands` | yes | array | At most 64 entries (may be empty). Each entry declares a command (see below). |

Each entry in `commands` is an object:

| Field | Required | Type | Notes |
| --- | --- | --- | --- |
| `name` | yes | string | The command name, matched case-insensitively against `palmod.on_command`. 1–32 characters, must start with a letter, and may contain only letters, digits, `_`, and `-` (`^[A-Za-z][A-Za-z0-9_-]{0,31}$`). |
| `permission` | yes | string | Exactly `"everyone"` or `"server.admin"`. Any other value rejects the plugin. |
| `suppress` | yes | boolean | When `true`, a matched chat command line is swallowed and not forwarded to game chat. |

Anything out of range — a bad `schema_version`, an unsafe `entrypoint`, a
duplicate `id`, an unknown `permission`, a budget outside its window — rejects
that plugin (the rest still load).

**Load-time coupling:** after the entrypoint runs, every command declared in
`commands` must have been registered with `palmod.on_command`, or the plugin
fails to start with `plugin did not register declared command: <name>`. A plugin
with an empty `commands` array (like `hook_watch`) registers no commands and only
uses hooks and events.

Example manifest (the bundled `give_item` plugin):

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

### `main.lua`

The entrypoint runs once at load. Register your command and event handlers at the
top level; the `palmod` global and the standard library are already in scope, so
there is no `require`:

```lua
palmod.on_command("Hello", function(context)
  palmod.reply(context, "Hi, " .. context.player .. "!")
end)
```

## Lifecycle

- **Isolation.** Each plugin gets its own `lua_State` on its own dedicated
  thread, off the game thread. Plugins never share Lua globals with one another.
- **Standard-library preamble.** Before your entrypoint runs — and before the
  instruction budget is armed — the loader executes an embedded pure-Lua preamble
  (`sdk/lua/stdlib.lua`) that installs the higher-level helpers
  (`palmod.reply`, `palmod.broadcast`, `palmod.paginate`, and the rest). You get
  them for free in every plugin.
- **Callbacks run off the game thread.** Command and event handlers execute on
  your plugin's worker thread, each with a fresh instruction budget. Game-state
  changes you request through `palmod.call` are queued and dispatched on the game
  thread at the next engine tick.
- **Hot reload.** Editing any file under the plugin directory triggers a
  transactional reload within about a second: the loader builds a fresh plugin
  set and swaps it in only if it loads cleanly. A bad edit keeps the previous
  plugins running, so you can iterate live without risking the server. You can
  also force a reload over the control socket with `palmodctl reload`.

Plugins have **full access** to the `palmod` API. There is no capability model,
no permission tiers on the API surface, and no "trusted" versus "untrusted"
plugin — it is your box running your own Lua, so a plugin may register any
command, subscribe to any event, hook any reflected function by name, and issue
any call. The only things the runtime enforces are not about trust:

1. **Build safety.** Hooks install only against a profile whose fingerprint and
   anchor bytes exactly match the running PalServer ELF, so a wrong offset can
   never corrupt a mismatched build.
2. **Stability.** Each plugin runs off the game thread inside memory and
   instruction budgets, with the dangerous standard libraries removed (see
   [Sandbox](#sandbox-stability-not-trust)).

## Commands

Declare a command in the manifest, then register a handler:

```lua
palmod.on_command(name, function(context) ... end)
```

`name` must match a manifest-declared command (case-insensitive); registering an
unknown command name raises an error. Re-registering the same command replaces
the prior handler.

In-game, players invoke commands with a **`!` prefix** — for example
`!GiveItem Wood Player 5`. Palworld's client swallows `/`-prefixed lines locally
for non-admins, so they never reach the server; the chat hook translates the `!`
form before routing. Over the control socket you invoke the bare command name
(`palmodctl invoke GiveItem Wood Player 5`).

### Command context

Your handler receives one `context` table:

| Field | Type | Meaning |
| --- | --- | --- |
| `command` | string | The invoked command name. |
| `raw` | string | The raw command text. |
| `player` | string | The issuing player's display name. |
| `player_handle` | integer | Opaque player handle. |
| `is_admin` | boolean | True iff the caller authenticated as a server admin. |
| `principal` | string | `"local_operator"` (control socket) or `"in_game_player"`. |
| `operator_uid` | integer | Local-operator UID; `0` for in-game players. |
| `args` | table | 1-based array of positional string arguments (whitespace-tokenized upstream). |

Argument parsing (quoting, tokenization) and the `server.admin` permission check
happen natively before your handler runs — a `server.admin` command only reaches
your handler when the caller is an authenticated admin. Admin status is read from
the game's own login state, not from a Palmod-specific tier.

### Private replies

Answer the issuer privately with `palmod.reply(context, text)` — only they see
the line. It resolves `context.player` to a `PlayerUId` and scopes the chat
message to that one player; if the UId can't be resolved (a local-operator
console, or a player who just left) it falls back to a server-wide broadcast.
Prefer `palmod.reply` over `palmod.broadcast` for command responses.

## Events

Subscribe to asynchronous event snapshots:

```lua
palmod.on_event(kind, function(event) ... end)
```

`kind` is a lowercase string of 1–64 bytes. The one built-in kind is:

- `"chat"` — every chat line (`event.source` = sender, `event.text` = message).

Any hooked `UFunction` name is also a valid event kind: subscribing to it here (or
via the `palmod.hook` sugar) delivers a decoded event keyed by that function name.

Connection join/leave are tracked internally — they maintain the player directory
behind `palmod.players`, `palmod.player_state`, and the other lookups — but are
**not** yet delivered as plugin events. To react to a player joining or leaving
today, hook a concrete join/leave `UFunction` by name via `palmod.hook`.

Events are delivered off the game thread to every subscribed plugin.

### Event object

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | The event kind (for `palmod.hook`, the `UFunction` name). |
| `sequence` | integer | Monotonic event sequence number. |
| `source` | string | Kind-dependent, e.g. chat sender / joining player name. |
| `text` | string | Kind-dependent, e.g. chat message text. |
| `subject` | string | Kind-dependent, e.g. a stable player id. |
| `handle` | integer | Opaque player handle, when applicable. |
| `number` | integer | Kind-dependent numeric payload. |
| `args` | table | Decoded named parameters for by-name hooks: `args[paramName] = value`. Empty for the flat `chat` event. |

## Reflection primitives

These native functions live on the `palmod` global.

### `palmod.hook(function_name, fn)`

Hook any of the game's reflected `UFunction`s by name — no per-function native
code and no per-function config. `function_name` is a reflected function name
(1–64 bytes, case-insensitive), e.g. `"AddItem_ServerInternal"`. The name is
resolved **live** against the running game (the runtime finds the `UFunction` in
`GUObjectArray` and reads its parameter layout on the fly), so any of the game's
~26k reflected functions works with no baked catalog. `palmod.hook` is exact
sugar for `palmod.on_event`: it subscribes to an event whose kind is the function
name, and the runtime auto-installs a generic hook for any subscribed name it can
resolve. Decoded parameters arrive on `event.args`, keyed by parameter name.
Hooking is **observation-only** — the original function always runs afterward,
and a name that resolves to no live `UFunction` simply never fires.

```lua
palmod.hook("AddItem_ServerInternal", function(event)
  palmod.log("info", string.format("gave %sx %s",
    tostring(event.args.Count), tostring(event.args.StaticItemId)))
end)
```

Parameters decode by type: integers (signed/unsigned 8–64-bit), floats,
booleans and enums as numbers; `FString` and `FName` as strings; object/class
pointers as opaque numeric handles; arrays as 1-based Lua tables; and nested
structs as tables keyed by field name (depth-bounded, array elements capped).

### `palmod.call(function_path, args [, target])`

Call any `UFunction` by its full UE path — parameters are encoded from live
reflection and dispatched via `ProcessEvent` on the game thread.

- `function_path` (string, ≤ 256 bytes) — e.g.
  `"/Script/Pal.PalPlayerInventoryData:AddItem_ServerInternal"`.
- `args` (table, ≤ 64 top-level entries) — string-keyed entries become the
  function's parameters by name (see marshaling below). Absent parameters are
  left zeroed (the ABI default).
- `target` (optional) — a **string** names a class to call on (the first live
  instance is used); an **integer** is a specific object handle from
  `find_object` / `find_all_of`. Omit it to call on the first live instance of
  the path's owning class.

`palmod.call` is valid **only inside a callback** (a command or event handler);
calling it at top level raises `actions are only valid inside a callback`. It
enqueues the call and returns immediately — the actual dispatch happens on the
next game tick. If the game-thread queue is full it raises
`game-thread action queue is full`.

Argument marshaling (how `args` values become parameters):

- number → numeric value; boolean → `1.0` / `0.0`; string → text.
- a table with a non-nil `[1]` → an **array** (iterated `1..#t`).
- a table without `[1]` → a **struct**; only string keys are taken, each
  recursed as a named member.

```lua
palmod.call("/Script/Pal.PalGameStateInGame:BroadcastChatMessage", {
  ChatMessage = { Sender = "[Palmod]", Message = "Server restarting soon." },
})
```

### `palmod.find_object(class [, name])` → integer | nil

The first live object that is-a `class` (optionally also named `name`). Returns
an opaque integer handle, or `nil` if nothing matched or the reflection reader is
unavailable.

### `palmod.find_all_of(class [, max])` → integer[]

Up to `max` live objects that are-a `class`. `max` defaults to 256, clamped to
1–4096. Returns a 1-based array of handles (empty if none).

### `palmod.get(handle, property)` → any | nil

Read a property from an object handle, resolved through the class chain. Returns
the decoded value — a number, a string, a 1-based array table, or a struct table
keyed by field name — or `nil` if the property is absent.

```lua
for _, ps in ipairs(palmod.find_all_of("PalPlayerState")) do
  palmod.log("info", "player: " .. tostring(palmod.get(ps, "PlayerNamePrivate")))
end
```

### `palmod.class_of(handle)` → string | nil

The class name of an object handle, or `nil`.

### `palmod.datatable_rows(name [, max])` → string[]

The row-key strings of a named `UDataTable` (resolved internally by object
name). `max` defaults to 4096, clamped to 1–65536. Returns a 1-based array of
strings (empty if the table or reader is unavailable).

```lua
local ids = palmod.datatable_rows("DT_ItemDataTable_Common")
```

### `palmod.log(level, message)`

Write a structured log line tagged with your plugin id. `level` is `"debug"`,
`"warn"`, `"error"`, or anything else (including `"info"`) → info. `message` is
truncated to 2048 bytes.

## Standard-library helpers

Pure-Lua helpers built on the primitives above, embedded into every plugin — no
`require`. They speak Palworld's class and function names so you don't have to.

### `palmod.broadcast(text)`

Send a chat line to everyone on the server (from sender `[Palmod]`).

### `palmod.reply(context, text)`

Reply privately to the command issuer (see [Private replies](#private-replies)).
Falls back to `palmod.broadcast` when the issuer's UId can't be resolved.

### `palmod.player_state(name)` → integer | nil

The live `PalPlayerState` handle for a connected player's display name, or `nil`.

### `palmod.resolve_uid(name)` → table | nil

The player's `PlayerUId` GUID as `{A, B, C, D}` (read from their
`PalPlayerState`), or `nil`.

### `palmod.players()` → string[]

The display names of all connected players.

### `palmod.inventory_of(name)` → integer | nil

The `PalPlayerInventoryData` handle owned by a connected player's name (matched
by `OwnerPlayerUId`), or `nil`. Pass it as the `target` of `palmod.call` to act
on that specific player's inventory.

### `palmod.paginate(items, width)` → string[]

Pack a list of strings into `", "`-joined pages no wider than `width` (default
80) characters, so a long result survives Palworld's chat length cap. Always
returns at least one (possibly empty) page. Elements are `tostring`'d.

## Sandbox (stability, not trust)

The sandbox exists to keep a buggy plugin from destabilizing the server, not to
restrict what plugins may do:

- **Memory budget** — a per-plugin allocator limit (`memory_limit_bytes`,
  default 32 MiB); over-budget allocations fail.
- **Instruction budget** — a per-callback Lua instruction cap
  (`instruction_limit`, default 250000), re-armed for each command, each event,
  and plugin init; overrunning it aborts that callback.
- **Removed standard libraries** — only `base`, `table`, `string`, `math`, and
  `utf8` are open. `io`, `os`, `package`/`require`, `debug`, and `coroutine` are
  not loaded, and `load`, `loadfile`, `dofile`, and `collectgarbage` are removed.
- **Off the game thread** — callbacks run on a worker thread with bounded
  command and event queues; game mutations go through the tick-drained action
  queue, so a slow or looping plugin cannot stall the engine.

These are budgets for stability. Within them, every plugin has the full API.

## Complete examples

### `give_item` — an admin command with a targeted call

`manifest.json` declares `GiveItem` as `server.admin` and `suppress: true`.

```lua
-- plugins/give_item/main.lua
local ADD_ITEM = "/Script/Pal.PalPlayerInventoryData:AddItem_ServerInternal"

palmod.on_command("GiveItem", function(context)
  local args = context.args
  if #args < 2 or #args > 3 then
    palmod.reply(context, "Usage: !GiveItem <item_id> <player> [count] (count: 1-9999)")
    return
  end

  local count = 1
  if args[3] ~= nil then
    count = math.tointeger(tonumber(args[3]))
    if count == nil or count < 1 or count > 9999 then
      palmod.reply(context, "Invalid count")
      return
    end
  end

  if not string.match(args[1], "^[A-Za-z0-9_]+$") then
    palmod.reply(context, "Invalid item id")
    return
  end

  -- Target the resolved player's inventory; fall back to the first live one.
  local target = palmod.inventory_of(args[2]) or "PalPlayerInventoryData"
  palmod.call(ADD_ITEM, {
    StaticItemId = args[1],
    Count = count,
    IsAssignPassive = false,
    LogDelay = 0.0,
    bNotifyLog = true,
  }, target)

  palmod.reply(context, "Gave " .. count .. " " .. args[1] .. " to " .. args[2])
end)
```

### `find_item` — read-side reflection and pagination

`manifest.json` declares `FindItem` as `everyone`, `suppress: true`.

```lua
-- plugins/find_item/main.lua
palmod.on_command("FindItem", function(context)
  local query = string.lower(context.args[1] or "")
  if query == "" then
    palmod.reply(context, "Usage: !FindItem <substring> [page]")
    return
  end
  local page = math.tointeger(tonumber(context.args[2])) or 1
  if page < 1 then page = 1 end

  local hits = {}
  for _, id in ipairs(palmod.datatable_rows("DT_ItemDataTable_Common")) do
    if string.find(string.lower(id), query, 1, true) then
      hits[#hits + 1] = id
    end
  end

  if #hits == 0 then
    palmod.reply(context, "No items matching '" .. query .. "'")
    return
  end

  local pages = palmod.paginate(hits, 80)
  if page > #pages then page = #pages end
  palmod.reply(context, string.format("%d items (p%d/%d): %s",
    #hits, page, #pages, pages[page]))
end)
```

### `hook_watch` — observe game functions by name

`manifest.json` has an empty `commands` array; the plugin only hooks.

```lua
-- plugins/hook_watch/main.lua
palmod.hook("AddItem_ServerInternal", function(event)
  palmod.log("info", string.format("AddItem: item=%s count=%s",
    tostring(event.args.StaticItemId), tostring(event.args.Count)))
end)

palmod.hook("BroadcastChatMessage", function(event)
  palmod.log("info", "BroadcastChatMessage fired")
end)
```

Any of the game's reflected `UFunction`s is hookable by name — there is no
catalog to generate. See [docs/reversing.md](reversing.md) for how profiles are
produced.

---

Palworld is a trademark of Pocketpair, Inc. This project is independent and does
not distribute game binaries or assets.
