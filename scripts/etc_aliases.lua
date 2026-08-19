--[[

    etc_aliases.lua v0.01 by Aybo  /  requested by Sopor

        - operator-configurable command aliases (#327)
        - usage: [+!#]addalias <alias> <target>
                 [+!#]delalias <alias>
                 [+!#]aliases

        Aliases are stored grouped-by-target on disk
        (`cfg/aliases.tbl`) so the human-edited file mirrors
        Sopor's natural shape

            return {
                usersearch     = { "us" },
                trafficmanager = { "tm", "trma" },
            }

        and inverted to a flat `{ [alias] = target, ... }` map in
        memory for O(1) `resolve(alias) -> target | nil`.

        At dispatch time `etc_hubcommands` (v0.07+) consults the
        resolver on direct-lookup misses. Real commands always
        win - a registered command name can never be aliased
        away. Adding an alias that already names a command is
        rejected at `+addalias` time.

        Persistence: every successful add / del immediately
        re-groups the in-memory flat map and writes it through
        `util.savetable` (atomic + path-safe via Phase 7 #266).
        `+reload` re-runs onStart, which re-loads + re-inverts.

        Public surface

            resolve(name)       -- string | nil
            get_aliases_tbl()   -- inner flat map

        Both are getters (closures over the file-scope upvalue),
        NOT direct table exports, to survive +reload (the
        #239 / #238 stale-rebind hazard).

        v0.01: by Aybo
            - initial implementation, closes #327
            - ADC handlers + HTTP API endpoints
              (GET / POST / DELETE /v1/aliases)

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_aliases"
local scriptversion = "0.01"

local cmd_add  = "addalias"
local cmd_del  = "delalias"
local cmd_list = "aliases"

local aliases_file = "cfg/aliases.tbl"


--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

local minlevel        = cfg.get( "etc_aliases_minlevel" )
local report_activate = cfg.get( "etc_aliases_report" )
local report_hubbot   = cfg.get( "etc_aliases_report_hubbot" )
local report_opchat   = cfg.get( "etc_aliases_report_opchat" )
local llevel          = cfg.get( "etc_aliases_llevel" )

local report = hub.import( "etc_report" )


--// table lookups
local hub_getbot   = hub.getbot
local hub_import   = hub.import
local hub_debug    = hub.debug
local util_load    = util.loadtable
local util_save    = util.savetable
local util_spairs  = util.spairs
local utf_match    = utf.match
local utf_format   = utf.format
local table_sort   = table.sort
local table_concat = table.concat


--// lang
local help_title_add  = "etc_aliases.lua - addalias"
local help_usage_add  = lang.help_usage_add  or "[+!#]addalias <alias> <target>"
local help_desc_add   = lang.help_desc_add   or "Add a command alias (alias -> target)"

local help_title_del  = "etc_aliases.lua - delalias"
local help_usage_del  = lang.help_usage_del  or "[+!#]delalias <alias>"
local help_desc_del   = lang.help_desc_del   or "Remove a command alias"

local help_title_list = "etc_aliases.lua - aliases"
local help_usage_list = lang.help_usage_list or "[+!#]aliases"
local help_desc_list  = lang.help_desc_list  or "List configured aliases and built-in command names"

local ucmd_menu_add   = lang.ucmd_menu_add   or { "Hub", "Aliases", "add alias" }
local ucmd_menu_del   = lang.ucmd_menu_del   or { "Hub", "Aliases", "delete alias" }
local ucmd_menu_list  = lang.ucmd_menu_list  or { "Hub", "Aliases", "list aliases" }
local ucmd_popup_alias  = lang.ucmd_popup_alias  or "Alias (letters only):"
local ucmd_popup_target = lang.ucmd_popup_target or "Target command:"

local msg_denied            = lang.msg_denied            or "You are not allowed to use this command."
local msg_usage_add         = lang.msg_usage_add         or "Usage: [+!#]addalias <alias> <target>"
local msg_usage_del         = lang.msg_usage_del         or "Usage: [+!#]delalias <alias>"
local msg_bad_alias         = lang.msg_bad_alias         or "Invalid alias '%s' - aliases may contain letters only (a-z, A-Z)."
local msg_alias_is_command  = lang.msg_alias_is_command  or "'%s' is already a real command and cannot be aliased."
local msg_alias_exists      = lang.msg_alias_exists      or "Alias '%s' already maps to '%s'. Use +delalias '%s' first."
local msg_target_missing    = lang.msg_target_missing    or "Unknown target command '%s'."
local msg_no_such_alias     = lang.msg_no_such_alias     or "No such alias '%s'."
local msg_added             = lang.msg_added             or "%s added alias '%s' -> '%s'."
local msg_deleted           = lang.msg_deleted           or "%s removed alias '%s' (was '-> %s')."
local msg_list_header       = lang.msg_list_header       or "\n=== ALIASES ==="
local msg_list_footer       = lang.msg_list_footer       or "=== END ===\n"
local msg_list_empty        = lang.msg_list_empty        or "(no operator-defined aliases)"
local msg_list_section_a    = lang.msg_list_section_a    or "Operator-defined aliases:"
local msg_list_section_b    = lang.msg_list_section_b    or "Built-in command names:"
local msg_err               = lang.msg_err               or "etc_aliases.lua: error: database file (cfg/aliases.tbl) corrupt or missing, a new one was created."


----------
--[CODE]--
----------

-- File-scope upvalue. onStart re-assigns this on every +reload,
-- so the closures in the public return table (resolve /
-- get_aliases_tbl) transparently see the new map. NEVER export
-- `aliases_tbl` directly - that's the #239 / #238 rebind hazard.
local aliases_tbl = { }


-- Convert the on-disk grouped form { target = {alias, ...} }
-- to the in-memory flat form { alias = target, ... }. Tolerant
-- of non-string keys / values / non-table value lists so a
-- mildly corrupt file still loads as much as it can.
local function invert_grouped( grouped )
    local flat = { }
    if type( grouped ) ~= "table" then return flat end
    for target, alist in pairs( grouped ) do
        if type( target ) == "string" and type( alist ) == "table" then
            for _, alias in ipairs( alist ) do
                if type( alias ) == "string" then
                    flat[ alias ] = target
                end
            end
        end
    end
    return flat
end


-- Inverse: in-memory flat -> on-disk grouped, with each
-- per-target alias list sorted for deterministic file output.
local function group_by_target( flat )
    local grouped = { }
    for alias, target in pairs( flat ) do
        if not grouped[ target ] then grouped[ target ] = { } end
        grouped[ target ][ #grouped[ target ] + 1 ] = alias
    end
    for _, list in pairs( grouped ) do table_sort( list ) end
    return grouped
end


-- Persist current state to disk. Caller is responsible for
-- having mutated aliases_tbl in memory already. Returns the
-- savetable result so the caller can react to a write failure
-- (rare; would mean cfg/ is read-only).
local function persist( )
    return util_save( group_by_target( aliases_tbl ), "aliases", aliases_file )
end


-- Resolve through the live etc_hubcommands.has() predicate. We
-- can't cache hubcmd at file scope because at module-load
-- etc_hubcommands hasn't necessarily registered its `add`
-- function via onStart yet, depending on listener-chain order.
-- Lazy import inside the helper is the standard luadch idiom
-- (cmd_topic / etc_msgmanager all do this).
local function is_real_command( name )
    local hubcmd = hub_import( "etc_hubcommands" )
    if not hubcmd or not hubcmd.has then return false end
    return hubcmd.has( name )
end


-- Shared action helpers used by BOTH the ADC chat-cmd path AND
-- the HTTP API path. Each returns
--     ok=true,                 msg
--     ok=nil,  err_code (str), msg
-- so the HTTP handler can map err_code -> HTTP status while
-- the ADC handler just replies the msg verbatim. err_code
-- values: "bad_alias" / "conflict_command" / "exists" /
-- "no_target" / "not_found".
local do_add_alias = function( alias, target, actor_label )
    if type( alias ) ~= "string" or not utf_match( alias, "^%a+$" ) then
        return nil, "bad_alias", utf_format( msg_bad_alias, tostring( alias ) )
    end
    if type( target ) ~= "string" or not utf_match( target, "^%a+$" ) then
        return nil, "bad_alias", utf_format( msg_bad_alias, tostring( target ) )
    end
    if is_real_command( alias ) then
        return nil, "conflict_command", utf_format( msg_alias_is_command, alias )
    end
    local existing = aliases_tbl[ alias ]
    if existing then
        return nil, "exists", utf_format( msg_alias_exists, alias, existing, alias )
    end
    if not is_real_command( target ) then
        return nil, "no_target", utf_format( msg_target_missing, target )
    end
    aliases_tbl[ alias ] = target
    persist( )
    return true, nil, utf_format( msg_added, actor_label or "?", alias, target )
end

local do_del_alias = function( alias, actor_label )
    if type( alias ) ~= "string" or not utf_match( alias, "^%a+$" ) then
        return nil, "bad_alias", utf_format( msg_bad_alias, tostring( alias ) )
    end
    local target = aliases_tbl[ alias ]
    if not target then
        return nil, "not_found", utf_format( msg_no_such_alias, alias )
    end
    aliases_tbl[ alias ] = nil
    persist( )
    return true, nil, utf_format( msg_deleted, actor_label or "?", alias, target )
end


-- Build the +aliases list output. Two sections: operator-defined
-- aliases (sorted by alias name) and built-in command names
-- (grouped by function identity so multi-name registrations
-- like {useruptime, uu} appear on one row).
local function format_list( )
    local lines = { msg_list_header, "", msg_list_section_a }
    local any_alias = false
    for alias, target in util_spairs( aliases_tbl ) do
        lines[ #lines + 1 ] = string.format( "  [ALIAS]    %-16s -> %s", alias, target )
        any_alias = true
    end
    if not any_alias then
        lines[ #lines + 1 ] = "  " .. msg_list_empty
    end
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_list_section_b

    local hubcmd = hub_import( "etc_hubcommands" )
    if hubcmd and hubcmd.list then
        -- Group commands by function identity. tostring(fn) yields
        -- "function: 0x..." which is stable per process; two
        -- distinct functions can never collide on the same string.
        -- The visible row order is then determined by the sort
        -- on `g.first` (the alphabetically smallest name in each
        -- group) so the output is fully stable across hub
        -- restarts even though `pairs(commands)` order is not.
        local groups = { }
        local order = { }
        for _, entry in ipairs( hubcmd.list( ) ) do
            local key = tostring( entry.fn )
            if not groups[ key ] then
                groups[ key ] = { names = { }, first = entry.name }
                order[ #order + 1 ] = key
            end
            local g = groups[ key ]
            g.names[ #g.names + 1 ] = entry.name
            if entry.name < g.first then g.first = entry.name end
        end
        for _, g in pairs( groups ) do table_sort( g.names ) end
        table_sort( order, function( a, b ) return groups[ a ].first < groups[ b ].first end )
        for _, key in ipairs( order ) do
            lines[ #lines + 1 ] = "  [BUILT-IN] " .. table_concat( groups[ key ].names, ", " )
        end
    end

    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_list_footer
    return table_concat( lines, "\n" )
end


------------------
--[ADC HANDLERS]--
------------------

local on_addalias = function( user, command, parameters )
    if user:level( ) < minlevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    local alias, target = utf_match( parameters or "", "^(%S+)%s+(%S+)%s*$" )
    if not ( alias and target ) then
        user:reply( msg_usage_add, hub_getbot( ) )
        return PROCESSED
    end
    local _ok, _err, msg = do_add_alias( alias, target, user:nick( ) )
    user:reply( msg, hub_getbot( ) )
    if _ok and report then
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    end
    if _ok then
        audit.fire( audit.build( "alias.add", user, nil, nil,
            { alias = alias, target = target } ) )
    end
    return PROCESSED
end

local on_delalias = function( user, command, parameters )
    if user:level( ) < minlevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    local alias = utf_match( parameters or "", "^(%S+)%s*$" )
    if not alias then
        user:reply( msg_usage_del, hub_getbot( ) )
        return PROCESSED
    end
    local _ok, _err, msg = do_del_alias( alias, user:nick( ) )
    user:reply( msg, hub_getbot( ) )
    if _ok and report then
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    end
    if _ok then
        audit.fire( audit.build( "alias.remove", user, nil, nil,
            { alias = alias } ) )
    end
    return PROCESSED
end

local on_listalias = function( user, command, parameters )
    if user:level( ) < minlevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    user:reply( format_list( ), hub_getbot( ) )
    return PROCESSED
end


-------------------
--[HTTP HANDLERS]--
-------------------

-- err_code -> HTTP status. Kept tiny so the table-of-truth is
-- right next to the handler that consumes it.
local _err_to_status = {
    bad_alias        = 400,
    conflict_command = 409,
    exists           = 409,
    no_target        = 404,
    not_found        = 404,
}

local http_list_aliases = function( req )
    local items = { }
    for alias, target in util_spairs( aliases_tbl ) do
        items[ #items + 1 ] = { alias = alias, target = target }
    end
    return { status = 200, data = {
        aliases = items,
        count   = #items,
    } }
end

local http_create_alias = function( req )
    local body = req.body or { }
    local alias  = body.alias
    local target = body.target
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local ok, err_code, msg = do_add_alias( alias, target, actor_label )
    if not ok then
        return { status = _err_to_status[ err_code ] or 400, error = {
            code    = err_code or "invalid",
            message = msg,
        } }
    end
    if report then
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    end
    audit.fire( audit.build( "alias.add",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { alias = alias, target = target } ) )
    return { status = 201, data = {
        action = "added",
        alias  = alias,
        target = target,
    } }
end

local http_delete_alias = function( req )
    local alias = req.path_vars and req.path_vars.alias
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local previous = aliases_tbl[ alias ]
    local ok, err_code, msg = do_del_alias( alias, actor_label )
    if not ok then
        return { status = _err_to_status[ err_code ] or 400, error = {
            code    = err_code or "invalid",
            message = msg,
        } }
    end
    if report then
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    end
    audit.fire( audit.build( "alias.remove",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { alias = alias, previous_target = previous } ) )
    return { status = 200, data = {
        action   = "deleted",
        alias    = alias,
        previous = previous,
    } }
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onStart", { },
    function( )
        --// load + invert
        local on_disk = util_load( aliases_file )
        if on_disk == nil then
            -- File missing or unreadable. Create an empty grouped
            -- table on disk and continue. opchat feed mirrors
            -- cmd_topic / etc_msgmanager error-recovery shape.
            on_disk = { }
            util_save( on_disk, "aliases", aliases_file )
            local opchat = hub_import( "bot_opchat" )
            if opchat then opchat.feed( msg_err ) end
        end
        aliases_tbl = invert_grouped( on_disk )

        --// help, ucmd, hubcmd
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title_add,  help_usage_add,  help_desc_add,  minlevel )
            help.reg( help_title_del,  help_usage_del,  help_desc_del,  minlevel )
            help.reg( help_title_list, help_usage_list, help_desc_list, minlevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_add,
                cmd_add,
                { "%[line:" .. ucmd_popup_alias .. "]", "%[line:" .. ucmd_popup_target .. "]" },
                { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_del,  cmd_del,
                { "%[line:" .. ucmd_popup_alias .. "]" },
                { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_list, cmd_list, { }, { "CT1" }, minlevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_add,  on_addalias, minlevel ) )
        assert( hubcmd.add( cmd_del,  on_delalias, minlevel ) )
        assert( hubcmd.add( cmd_list, on_listalias, minlevel ) )

        --// HTTP API endpoints (#327, raw hub.http_register because
        --// this is a global config resource, not SID-scoped).
        if hub.http_register then
            hub.http_register( "GET", "/v1/aliases", "read", http_list_aliases, {
                plugin = scriptname,
                description = "list operator-defined command aliases (= ADC `+aliases` operator-defined section)",
                response_schema = {
                    aliases = { type = "array",   required = true },
                    count   = { type = "integer", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/aliases", "admin", http_create_alias, {
                plugin = scriptname,
                description = "create a new operator-defined alias (= ADC `+addalias <alias> <target>`)",
                request_schema = {
                    alias  = { type = "string", required = true, max_length = 64 },
                    target = { type = "string", required = true, max_length = 64 },
                },
                response_schema = {
                    action = { type = "string", required = true },
                    alias  = { type = "string", required = true },
                    target = { type = "string", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/aliases/{alias}", "admin", http_delete_alias, {
                plugin = scriptname,
                description = "remove an operator-defined alias (= ADC `+delalias <alias>`)",
                response_schema = {
                    action   = { type = "string", required = true },
                    alias    = { type = "string", required = true },
                    previous = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)


hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )


--// public //--

-- Both getters close over the file-scope `aliases_tbl` upvalue.
-- onStart's `aliases_tbl = invert_grouped(...)` rebind is
-- visible through the closure on every call, so +reload of
-- this module does NOT leave importers (etc_hubcommands)
-- holding a stale reference. Same pattern as
-- etc_msgmanager.get_block_tbl (#238 / #239 hazard avoided).
return {

    resolve = function( name )
        if type( name ) ~= "string" then return nil end
        return aliases_tbl[ name ]
    end,

    get_aliases_tbl = function( ) return aliases_tbl end,

}
