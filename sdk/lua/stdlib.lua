-- Palmod standard library — pure-Lua helpers layered over the native primitives
-- (palmod.call / find_all_of / get / datatable_rows / ...). This file is embedded
-- into the loader at build time and run as a preamble in EVERY plugin's sandbox,
-- so any script can use palmod.reply, palmod.broadcast, etc. with no `require`.
--
-- It is "batteries included" for Palworld specifically: the class/function names
-- below are Palworld's, but every helper is expressed entirely through the
-- generic reflection blocks — there is no per-command native code.
--
-- Editing this file needs a native rebuild (it is compiled in); plugins under
-- plugins/ still hot-reload on save.

local BROADCAST = "/Script/Pal.PalGameStateInGame:BroadcastChatMessage"
local SENDER = "[Palmod]"

-- Two FGuids are equal when all four dwords match.
local function guid_eq(a, b)
    return a ~= nil and b ~= nil
        and a.A == b.A and a.B == b.B and a.C == b.C and a.D == b.D
end

-- Send a chat line to everyone on the server.
function palmod.broadcast(text)
    palmod.call(BROADCAST, { ChatMessage = { Sender = SENDER, Message = tostring(text) } })
end

-- The live PalPlayerState handle for a connected player's display name, or nil.
function palmod.player_state(name)
    for _, ps in ipairs(palmod.find_all_of("PalPlayerState")) do
        if palmod.get(ps, "PlayerNamePrivate") == name then return ps end
    end
    return nil
end

-- The PlayerUId Guid ({A,B,C,D}) for a connected player's name, or nil.
function palmod.resolve_uid(name)
    local ps = palmod.player_state(name)
    if ps == nil then return nil end
    return palmod.get(ps, "PlayerUId")
end

-- Names of all connected players.
function palmod.players()
    local names = {}
    for _, ps in ipairs(palmod.find_all_of("PalPlayerState")) do
        local n = palmod.get(ps, "PlayerNamePrivate")
        if type(n) == "string" and n ~= "" then names[#names + 1] = n end
    end
    return names
end

-- The PalPlayerInventoryData handle owned by a connected player's name, or nil.
function palmod.inventory_of(name)
    local uid = palmod.resolve_uid(name)
    if uid == nil then return nil end
    for _, inv in ipairs(palmod.find_all_of("PalPlayerInventoryData")) do
        if guid_eq(palmod.get(inv, "OwnerPlayerUId"), uid) then return inv end
    end
    return nil
end

-- Reply privately to the player who issued a command — only they see the line.
-- Falls back to a global broadcast when the issuer's UId can't be resolved (e.g.
-- the command came from the local operator console, or the player just left):
-- setting ReceiverPlayerUIds to a single entry scopes the message to that player;
-- leaving it empty broadcasts to everyone.
function palmod.reply(context, text)
    local uid = context and context.player and palmod.resolve_uid(context.player)
    if uid == nil then
        palmod.broadcast(text)
        return
    end
    palmod.call(BROADCAST, {
        ChatMessage = {
            Sender = SENDER,
            Message = tostring(text),
            ReceiverPlayerUIds = { uid },
        },
    })
end

-- Pack a list of short strings into ", "-joined pages no wider than `width`
-- (default 80) characters, so a long result survives Palworld's chat length cap
-- and can be paged. Always returns at least one (possibly empty) page string.
function palmod.paginate(items, width)
    width = width or 80
    local pages, current, length = {}, {}, 0
    for _, item in ipairs(items) do
        item = tostring(item)
        local add = #item + (length == 0 and 0 or 2)  -- ", " separator
        if length > 0 and length + add > width then
            pages[#pages + 1] = table.concat(current, ", ")
            current, length, add = {}, 0, #item
        end
        current[#current + 1] = item
        length = length + add
    end
    if #current > 0 then pages[#pages + 1] = table.concat(current, ", ") end
    if #pages == 0 then pages[1] = "" end
    return pages
end
