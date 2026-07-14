# Give Item reference plugin

In-game: `!GiveItem <item_id> <player> [count]`. Mod commands use a `!` prefix
(not `/`) because the Palworld client eats `/`-prefixed messages for non-admins —
`!` always reaches the server via chat, where the native command router recognizes
it (translating `!`→`/` internally), resolves the sender's **server-side** admin
status (Palworld's own admin login: `PalPlayerController.bAdmin`, matched by the
chat `SenderPlayerUId`), enforces `permission = server.admin`, and **suppresses**
the broadcast. Only an authenticated Palworld admin can dispatch it — checked on
the server, never trusting the client. Lua validates the arguments off-thread and
emits an opaque `inventory.give` action; the native inventory adapter executes it
on the game thread (drained via the `GEngine::Tick` pump).

The plugin has no filesystem, process, package-loading, network, debug, or raw
Unreal pointer access.
