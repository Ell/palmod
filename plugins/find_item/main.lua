-- Search the item master DataTable by substring — pure Lua over generic blocks
-- plus the palmod stdlib: palmod.datatable_rows reads the table's row keys (the
-- item ids), palmod.paginate packs the matches into chat-sized pages, and
-- palmod.reply answers privately to whoever ran the command.

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

    -- Page through a large result set with `!FindItem <query> <page>`.
    local pages = palmod.paginate(hits, 80)
    if page > #pages then page = #pages end
    palmod.reply(context, string.format("%d items (p%d/%d): %s",
        #hits, page, #pages, pages[page]))
end)
