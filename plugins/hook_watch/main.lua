-- Example: hook arbitrary game functions by name and observe their arguments.
--
-- `palmod.hook(name, fn)` installs a reflection hook for any UFunction, resolved
-- live from the game's reflection by name — no per-function configuration and no
-- baked catalog. When the function runs, `event.args` holds its decoded
-- parameters keyed by name. Hooking is observation-only: the original still runs.
--
-- The names below are examples; adjust to taste.

-- Log every item the server hands out.
palmod.hook("AddItem_ServerInternal", function(event)
    palmod.log("info", string.format(
        "AddItem: item=%s count=%s",
        tostring(event.args.StaticItemId),
        tostring(event.args.Count)))
end)

-- Observe chat broadcasts as a generic hook (chat is also its own "chat" event;
-- this shows the by-name path works for the same function).
palmod.hook("BroadcastChatMessage", function(event)
    palmod.log("info", "BroadcastChatMessage fired")
end)
