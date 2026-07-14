---@meta palmod

---@class PalmodCommandContext
---@field command string
---@field args string[]
---@field raw string
---@field player string
---@field player_handle integer
---@field is_admin boolean
---@field principal "in_game_player"|"local_operator"
---@field operator_uid integer

---@class PalmodEvent
---@field kind string
---@field sequence integer
---@field source string   # e.g. chat sender / joining player name
---@field text string     # e.g. chat message text
---@field subject string  # e.g. stable player id
---@field handle integer  # opaque player handle, when applicable
---@field number integer
---@field args table<string, string|number>  # decoded params of a pal.hook'd game function

---@class PalmodApi
palmod = {}

---Register the handler declared by the plugin manifest.
---@param command string
---@param handler fun(context: PalmodCommandContext)
function palmod.on_command(command, handler) end

---Subscribe to an asynchronous event snapshot. The one built-in kind delivered
---today is "chat". Any hooked game function name is also an event kind (see
---palmod.hook). Player connection join/leave are tracked internally but are not
---yet delivered as plugin events.
---@param kind string
---@param handler fun(event: PalmodEvent)
function palmod.on_event(kind, handler) end

---Hook any game function by its reflected name (e.g. "BroadcastChatMessage").
---If the validated profile's function catalog lists it, the runtime installs a
---reflection hook automatically; the decoded arguments arrive in `event.args`
---keyed by parameter name. Sugar for on_event with a function-name kind.
---@param function_name string
---@param handler fun(event: PalmodEvent)
function palmod.hook(function_name, handler) end

---Call any game UFunction by its UE path, generically. The runtime resolves it
---in the object array, reads its parameter layout live, encodes `args` (a table
---keyed by the reflected parameter names — nested tables for struct/array params),
---and dispatches it via ProcessEvent on the game thread. `target_class` names the
---class of the object to call it on (defaults to the function's owning class; the
---first live instance is used).
---@param function_path string
---@param args table
---@param target_class? string
function palmod.call(function_path, args, target_class) end

---Find the first live object that is-a `class` (optionally named `name`).
---Returns an opaque object handle (integer) or nil.
---@param class string
---@param name? string
---@return integer|nil
function palmod.find_object(class, name) end

---Find up to `max` (default 256) live objects that are-a `class`.
---@param class string
---@param max? integer
---@return integer[]
function palmod.find_all_of(class, max) end

---Read a property from an object handle, resolved through the class chain.
---Returns the decoded value: number/string, an array (list), or a struct (table
---keyed by field name); nil if the property is absent.
---@param handle integer
---@param property string
---@return any
function palmod.get(handle, property) end

---The class name of an object handle, or nil.
---@param handle integer
---@return string|nil
function palmod.class_of(handle) end

---Read the row keys (e.g. item ids) of a named UDataTable. Returns a list of
---strings; empty when the table or reflection is unavailable.
---@param table_name string
---@return string[]
function palmod.datatable_rows(table_name) end

---@param level "debug"|"info"|"warn"|"error"
---@param message string
function palmod.log(level, message) end

--- Standard library ---------------------------------------------------------
-- Pure-Lua helpers built on the primitives above, embedded from sdk/lua/stdlib.lua
-- and available in every plugin with no `require`.

---Send a chat line to everyone on the server.
---@param text string
function palmod.broadcast(text) end

---Reply privately to the player who issued a command (only they see it). Falls
---back to a global broadcast when the issuer's UId can't be resolved.
---@param context PalmodCommandContext
---@param text string
function palmod.reply(context, text) end

---The live PalPlayerState handle for a connected player's display name, or nil.
---@param name string
---@return integer|nil
function palmod.player_state(name) end

---The PlayerUId Guid ({A,B,C,D}) for a connected player's name, or nil.
---@param name string
---@return table|nil
function palmod.resolve_uid(name) end

---Names of all connected players.
---@return string[]
function palmod.players() end

---The PalPlayerInventoryData handle owned by a connected player's name, or nil.
---@param name string
---@return integer|nil
function palmod.inventory_of(name) end

---Pack short strings into ", "-joined pages no wider than `width` (default 80),
---so long results survive Palworld's chat cap. Returns >= 1 page string.
---@param items string[]
---@param width? integer
---@return string[]
function palmod.paginate(items, width) end

return palmod
