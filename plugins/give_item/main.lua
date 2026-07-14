-- Pure Lua over generic blocks + the palmod stdlib: resolve the target player's
-- inventory by name (stdlib palmod.inventory_of walks PlayerState.PlayerUId ->
-- the PalPlayerInventoryData whose OwnerPlayerUId matches), then call
-- AddItem_ServerInternal on that exact object. Replies are private to the issuer.
local ADD_ITEM = "/Script/Pal.PalPlayerInventoryData:AddItem_ServerInternal"
local ITEM_TABLE = "DT_ItemDataTable_Common"

-- Known item ids (lowercased), loaded lazily from the item DataTable and cached.
-- SAFETY: passing an id the game can't resolve makes AddItem_ServerInternal
-- SIGSEGV (crashes the whole server), so an unknown id must be rejected BEFORE
-- the call — this validation is a guard, not a nicety.
local item_set
local function known_item(id)
    if item_set == nil then
        local rows = palmod.datatable_rows(ITEM_TABLE)
        if #rows == 0 then return false end  -- table unreadable: fail closed, don't cache
        item_set = {}
        for _, row in ipairs(rows) do item_set[string.lower(row)] = true end
    end
    return item_set[string.lower(id)] == true
end

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

    -- Reject unknown items before calling AddItem (an unknown id crashes the server).
    if not known_item(args[1]) then
        palmod.reply(context, "Unknown item: " .. args[1] .. " — use !FindItem to look it up")
        return
    end

    -- Target the resolved player's inventory; fall back to the first live one.
    local target = palmod.inventory_of(args[2]) or "PalPlayerInventoryData"
    palmod.call(ADD_ITEM, {
        StaticItemId = args[1],
        Count = count,
        IsAssignPassive = false,
        LogDelay = 0.0,
        bNotifyLog = false,  -- suppress the game's item-added notification
    }, target)

    palmod.reply(context, "Gave " .. count .. " " .. args[1] .. " to " .. args[2])
end)
