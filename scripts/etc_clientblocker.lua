--[[

    etc_clientblocker.lua v0.10 by Aybo
    based on etc_clientblocker_v0.2 (pulsar / upstream luadch/scripts)
    promoted into core (#81)

        - blocks clients on connect by Lua-pattern match against
          their BINF AP+VE field (`user:version()` returns the
          concatenated "<AP> <VE>" form)
        - patterns + per-pattern kick reasons live in
          `scripts/data/etc_clientblocker.tbl` so the operator can
          edit them live via `+addblocker / +delblocker` or via
          the HTTP API (`POST / DELETE /v1/clientblocker`)
        - operator levels are exempt by default
          (`etc_clientblocker_check_levels[60..80]` = false) so an
          operator who adds a self-matching pattern does not lock
          themselves out
        - audit-fires `client.block.kick` on every block kick
          and `client.block.add / .remove` on every pattern edit

        Public surface

            resolve(version_string) -> reason | nil
                deterministic lookup against the live in-memory
                table; primary use is the unit test, but also
                handy for diagnostics

            get_patterns_tbl()      -> the live flat map
                getter, NOT a direct export, to survive +reload
                rebinds (#239 / #238 hazard avoided)

        v0.11: by Aybo
            - seed BUNDLED_DEFAULTS only when the .tbl file is
              MISSING on disk (not just empty). An operator who
              +delblocker'd all 6 bundled defaults intentionally
              now keeps the empty .tbl across +reload cycles.
              Recovery from the script-sync edge case (where
              the .tbl already existed pre-update as an empty
              stub) is a one-line `rm scripts/data/etc_clientblocker.tbl`
              + +reload, or copy patterns from
              examples/data/etc_clientblocker.tbl.example.

        v0.10: by Aybo
            - promoted from luadch-ng/scripts into core (#81)
            - replaces hardcoded inline `client_tbl` with a
              persistent `scripts/data/etc_clientblocker.tbl`
            - adds ADC commands `+addblocker / +delblocker /
              +blocker`
            - adds HTTP API endpoints
              (GET / POST / DELETE /v1/clientblocker)
            - emits audit events
            - F-INF-1d nil-VE guard preserved from upstream v0.2

        Listener-chain note: this plugin MUST sit AFTER
        `hub_inf_manager.lua` in cfg.scripts. The structural
        BINF validation (forbidden flags / identity spoofing) is
        a hard precondition for the client-policy match; running
        the policy filter on un-validated INFs would be a layering
        inversion. The default examples/cfg/cfg.tbl already puts
        them in the right order.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_clientblocker"
local scriptversion = "0.12"

local cmd_add  = "addblocker"
local cmd_del  = "delblocker"
local cmd_list = "blocker"

local patterns_file = "scripts/data/etc_clientblocker.tbl"


--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

local oplevel         = cfg.get( "etc_clientblocker_oplevel" )
local check_levels    = cfg.get( "etc_clientblocker_check_levels" ) or { }
local default_reason  = cfg.get( "etc_clientblocker_default_reason" )
local max_pattern_len = cfg.get( "etc_clientblocker_max_pattern_len" ) or 200

local report_activate = cfg.get( "etc_clientblocker_report" )
local report_hubbot   = cfg.get( "etc_clientblocker_report_hubbot" )
local report_opchat   = cfg.get( "etc_clientblocker_report_opchat" )
local report_llevel   = cfg.get( "etc_clientblocker_llevel" )

local report = hub.import( "etc_report" )


--// table lookups
local hub_escapefrom = hub.escapefrom
local hub_escapeto   = hub.escapeto
local hub_getbot     = hub.getbot
local hub_import     = hub.import
local hub_debug      = hub.debug
local util_load      = util.loadtable
local util_save      = util.savetable
local util_spairs    = util.spairs
local util_strip     = util.strip_control_bytes
local utf_match      = utf.match
local utf_format     = utf.format
local table_concat   = table.concat
local string_find    = string.find


--// lang
local help_title_add  = "etc_clientblocker.lua - addblocker"
local help_usage_add  = lang.help_usage_add  or "[+!#]addblocker <pattern> [reason]"
local help_desc_add   = lang.help_desc_add   or "Block all clients whose AP+VE matches the Lua pattern. Pattern is the first whitespace-token; everything after it is the kick reason (defaults to etc_clientblocker_default_reason)."

local help_title_del  = "etc_clientblocker.lua - delblocker"
local help_usage_del  = lang.help_usage_del  or "[+!#]delblocker <pattern|N>"
local help_desc_del   = lang.help_desc_del   or "Remove a client-blocker pattern by literal pattern OR by 1-based row number from +blocker output."

local help_title_list = "etc_clientblocker.lua - blocker"
local help_usage_list = lang.help_usage_list or "[+!#]blocker"
local help_desc_list  = lang.help_desc_list  or "List configured client-blocker patterns."

local ucmd_menu_add   = lang.ucmd_menu_add   or { "Hub", "Client Blocker", "add pattern" }
local ucmd_menu_del   = lang.ucmd_menu_del   or { "Hub", "Client Blocker", "delete pattern" }
local ucmd_menu_list  = lang.ucmd_menu_list  or { "Hub", "Client Blocker", "list patterns" }
local ucmd_popup_pat    = lang.ucmd_popup_pat    or "Lua pattern (e.g. AirDC%+%+%s2):"
local ucmd_popup_reason = lang.ucmd_popup_reason or "Kick reason (optional):"

local msg_denied             = lang.msg_denied             or "You are not allowed to use this command."
local msg_usage_add          = lang.msg_usage_add          or "Usage: [+!#]addblocker <pattern> [reason]"
local msg_usage_del          = lang.msg_usage_del          or "Usage: [+!#]delblocker <pattern|N>"
local msg_bad_pattern        = lang.msg_bad_pattern        or "Invalid Lua pattern (empty, too long, or fails compile)."
local msg_pattern_exists     = lang.msg_pattern_exists     or "Pattern '%s' is already configured. Use +delblocker first."
local msg_no_such_pattern    = lang.msg_no_such_pattern    or "No such pattern '%s'."
local msg_added              = lang.msg_added              or "%s added client-blocker pattern '%s' (reason: %s)."
local msg_deleted            = lang.msg_deleted            or "%s removed client-blocker pattern '%s'."
local msg_list_header        = lang.msg_list_header        or "\n=== CLIENT BLOCKER ==="
local msg_list_footer        = lang.msg_list_footer        or "=== END ===\n"
local msg_list_empty         = lang.msg_list_empty         or "(no patterns configured)"
local msg_report             = lang.msg_report             or "[ CLIENT BLOCKER ]--> The user %s with IP %s is running %s and is not allowed in this hub. Matching pattern: %s"


----------
--[CODE]--
----------

-- Bundled default cheat / mod client blocklist. Sourced here in
-- the Lua module rather than in scripts/data/etc_clientblocker.tbl
-- so a docker-compose script-sync onto an existing testhub (which
-- copies scripts/*.lua but NOT scripts/data/) cannot silently lose
-- the defaults. onStart seeds these into the operator-managed .tbl
-- file when the file is missing OR empty - thereafter the .tbl is
-- the single source of truth and operators control it via
-- +addblocker / +delblocker / HTTP API.
local BUNDLED_DEFAULTS = {
    [ "^CleanDC%+%+.+" ]   = "CleanDC++ is not allowed in this hub. Please switch to AirDC++ and reconnect!",
    [ "^RSX%+%+.+" ]       = "RSX++ is not allowed in this hub. Please switch to AirDC++ and reconnect!",
    [ "^CrZ%+%+.+" ]       = "CrZ++ is not allowed in this hub. Please switch to AirDC++ and reconnect!",
    [ "^SmVDC%+%+.-$" ]    = "SmVDC++ is not allowed in this hub. Please switch to AirDC++ and reconnect!",
    [ "^DC@fe%+%+.-$" ]    = "Modified BCDC++ is not allowed in this hub. Please switch to AirDC++ and reconnect!",
    [ "^FearDC.+" ]        = "FearDC is not allowed in this hub. Please switch to AirDC++ and reconnect!",
}


-- File-scope upvalue. onStart re-assigns this on every +reload,
-- so the closures in the public return table (resolve /
-- get_patterns_tbl) transparently see the new map. NEVER export
-- `patterns_tbl` directly - that's the #239 / #238 rebind hazard.
local patterns_tbl = { }


-- Validate an operator-supplied pattern.
--   - non-empty string
--   - length-capped (etc_clientblocker_max_pattern_len)
--   - URL-path-safe: no `/`, `?`, `#`, `&` chars. The HTTP DELETE
--     endpoint identifies the pattern via a path-var; the router
--     uses `([^/]+)` and does not percent-decode, so a `/` in the
--     pattern would make the pattern undeletable via HTTP (silent
--     404). Real-world DC client AP/VE strings are alphanumeric
--     + `+`/`.`/`-`, so disallowing these four chars rules out
--     zero legitimate use. Fail loud at edit time instead.
--   - not a bare `.` / `..` dot-segment: these are collapsed by URL
--     path normalization (the browser AND a server-side path.Clean
--     rewrite `/v1/clientblocker/..` before it reaches the route), so
--     such a pattern is likewise undeletable via HTTP (#617). Same
--     class as the char check above; a lone `.`/`..` also matches
--     nearly every VE tag, so it is never a legitimate pattern.
--   - compile-probe via pcall(string.find, "", pat) so we fail
--     loud at edit time, never silent at onConnect kick time
-- Returns: true | nil, err_msg.
local function validate_pattern( pat )
    if type( pat ) ~= "string" or pat == "" then
        return nil, msg_bad_pattern
    end
    if #pat > max_pattern_len then
        return nil, msg_bad_pattern
    end
    if pat:find( "[/?#&]" ) then
        return nil, msg_bad_pattern
    end
    if pat == "." or pat == ".." then    -- #617: dot-segment, undeletable via HTTP path
        return nil, msg_bad_pattern
    end
    local ok = pcall( string_find, "", pat )
    if not ok then
        return nil, msg_bad_pattern
    end
    return true
end


-- Persist current state to disk. Caller is responsible for
-- having mutated patterns_tbl in memory already. Returns the
-- savetable result so the caller can react to a write failure
-- (rare; would mean scripts/data/ is read-only).
local function persist( )
    return util_save( patterns_tbl, "patterns", patterns_file )
end


-- Resolve operator-supplied reason -> the effective string the
-- kick will use. Treats nil and empty-string the same (= "use the
-- cfg default"). Single helper to avoid drift between the ADC
-- chat-cmd path and the HTTP API path.
local function _effective_reason( reason )
    if type( reason ) == "string" and reason ~= "" then
        return reason
    end
    return default_reason
end


-- Shared action helpers used by BOTH the ADC chat-cmd path AND
-- the HTTP API path. Each returns
--     ok=true,                 msg
--     ok=nil,  err_code (str), msg
-- so the HTTP handler can map err_code -> HTTP status while
-- the ADC handler just replies the msg verbatim. err_code
-- values: "bad_pattern" / "exists" / "not_found".
local do_add_pattern = function( pattern, reason, actor_label )
    local ok, vmsg = validate_pattern( pattern )
    if not ok then
        return nil, "bad_pattern", vmsg
    end
    if patterns_tbl[ pattern ] ~= nil then
        return nil, "exists", utf_format( msg_pattern_exists, pattern )
    end
    reason = _effective_reason( reason )
    patterns_tbl[ pattern ] = reason
    persist( )
    return true, nil, utf_format( msg_added, actor_label or "?", pattern, reason )
end

local do_del_pattern = function( pattern, actor_label )
    if type( pattern ) ~= "string" or pattern == "" then
        return nil, "bad_pattern", msg_bad_pattern
    end
    if patterns_tbl[ pattern ] == nil then
        return nil, "not_found", utf_format( msg_no_such_pattern, pattern )
    end
    local previous = patterns_tbl[ pattern ]
    patterns_tbl[ pattern ] = nil
    persist( )
    return true, previous, utf_format( msg_deleted, actor_label or "?", pattern )
end


-- The onConnect check. Extracted as a named local for clarity +
-- testability. Returns PROCESSED if a kick was emitted, nil
-- otherwise. F-INF-1d preserved: a client with no VE has
-- nothing to match against, so skip - mirrors the "no rule
-- applies" semantic for any other missing input.
local check_clients = function( user )
    local user_level = user:level( )
    if not check_levels[ user_level ] then return end

    local version = user:version( )
    if not version or version == "" then return end

    local user_client = hub_escapefrom( version )
    -- Snapshot keys into a sorted local array BEFORE iterating
    -- rather than `util_spairs(patterns_tbl)`. Sorted-pairs gives
    -- deterministic actor-attribution + match-reason on collision
    -- (two patterns matching the same VE would otherwise pick a
    -- hash-order dependent reason - confusing in audit logs),
    -- but `util.spairs` stashes an internal `orderedIndex` array
    -- on the iterated table and only clears it on iterator
    -- exhaustion. The `return PROCESSED` below would leave that
    -- artifact attached to patterns_tbl, contaminating the next
    -- persist() / GET /v1/clientblocker / +blocker output. The
    -- snapshot-then-ipairs form sidesteps the leak without
    -- changing the externally-visible ordering.
    local ordered = { }
    for pat in pairs( patterns_tbl ) do
        ordered[ #ordered + 1 ] = pat
    end
    table.sort( ordered )
    for _, pattern in ipairs( ordered ) do
        local reason = patterns_tbl[ pattern ]
        local ok, hit = pcall( string_find, user_client, pattern )
        if ok and hit then
            -- System actor: audit.lua's _snapshot_actor turns a
            -- plain string into { nick=<string>, level=0, sid="",
            -- cid="", ip="" } - the canonical shorthand for plugin-
            -- fired events with no operator behind them.
            audit.fire( audit.build( "client.block.kick",
                scriptname, user, reason,
                { pattern = pattern, version = version } ) )
            -- Human-readable opchat / hubbot report. The audit log
            -- carries the same fields in structured form for
            -- compliance / forensics; this banner is for live
            -- staff awareness. Imported from Sopor v0.4.
            if report then
                local user_ip = user:ip( ) or "?"
                local rmsg = utf_format( msg_report,
                    user:nick( ) or "?", user_ip, version, pattern )
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, rmsg )
            end
            user:kill( "ISTA 231 " .. hub_escapeto( reason ) .. " TL-1\n" )
            return PROCESSED
        end
    end
end


-- Build the +blocker list output. Entries are numbered so the
-- operator can call `+delblocker <N>` instead of having to retype
-- the full `^pattern.+` literal - the `^` prefix on the bundled
-- defaults is otherwise easy to miss.
local function format_list( )
    local lines = { msg_list_header, "" }
    local any = false
    local n = 0
    for pat, reason in util_spairs( patterns_tbl ) do
        n = n + 1
        lines[ #lines + 1 ] = string.format( "  %d. [%s]  ->  %s", n, pat, reason )
        any = true
    end
    if not any then
        lines[ #lines + 1 ] = "  " .. msg_list_empty
    end
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_list_footer
    return table_concat( lines, "\n" )
end


-- Resolve a +delblocker argument to a target pattern. Accepts
--   - a positive integer  -> 1-based index into the sorted list
--   - any other string    -> literal pattern key
-- Returns: pattern_string | nil. Out-of-range index returns nil so
-- the caller surfaces the existing not_found error path. A pattern
-- that LITERALLY is a positive integer (e.g. operator added "1" via
-- +addblocker) can only be deleted by editing the .tbl directly;
-- documented edge case.
local function resolve_del_target( arg )
    if type( arg ) ~= "string" or arg == "" then return nil end
    local n = tonumber( arg )
    if n and n == math.floor( n ) and n > 0 then
        local ordered = { }
        for pat in pairs( patterns_tbl ) do ordered[ #ordered + 1 ] = pat end
        table.sort( ordered )
        return ordered[ n ]    -- nil if out of range
    end
    return arg
end


------------------
--[ADC HANDLERS]--
------------------

local on_addblocker = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    -- First whitespace-token = pattern; everything else = reason.
    -- The pattern may contain `%`, `(`, `)`, `+`, `.` etc.; only
    -- whitespace separates it from the reason.
    local pattern, reason = utf_match( parameters or "", "^(%S+)%s*(.*)$" )
    if not pattern or pattern == "" then
        user:reply( msg_usage_add, hub_getbot( ) )
        return PROCESSED
    end
    if reason == "" then reason = nil end
    local _ok, _err, msg = do_add_pattern( pattern, reason, user:nick( ) )
    user:reply( msg, hub_getbot( ) )
    if _ok then
        if report then
            report.send( false, false, true, oplevel, msg )
        end
        audit.fire( audit.build( "client.block.add", user, nil, nil,
            { pattern = pattern, reason = _effective_reason( reason ) } ) )
    end
    return PROCESSED
end

local on_delblocker = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    local arg = utf_match( parameters or "", "^(%S+)%s*$" )
    if not arg then
        user:reply( msg_usage_del, hub_getbot( ) )
        return PROCESSED
    end
    -- Operator may pass a 1-based row number from +blocker output
    -- instead of the literal pattern; resolve here.
    local pattern = resolve_del_target( arg ) or arg
    local _ok, payload, msg = do_del_pattern( pattern, user:nick( ) )
    user:reply( msg, hub_getbot( ) )
    if _ok then
        local previous_reason = payload
        if report then
            report.send( false, false, true, oplevel, msg )
        end
        audit.fire( audit.build( "client.block.remove", user, nil, nil,
            { pattern = pattern, previous_reason = previous_reason } ) )
    end
    return PROCESSED
end

local on_listblocker = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    -- 3-arg user:reply -> DMSG (hub-to-user private message) so the
    -- list shows in the operator's PM window, not main chat. Same
    -- choice as cmd_help. AirDC++ also renders multi-line DMSG
    -- correctly where the BMSG path appeared empty for some
    -- clients (#81 testhub feedback).
    user:reply( format_list( ), hub_getbot( ), hub_getbot( ) )
    return PROCESSED
end


-------------------
--[HTTP HANDLERS]--
-------------------

local _err_to_status = {
    bad_pattern = 400,
    exists      = 409,
    not_found   = 404,
}

local http_list_patterns = function( req )
    local items = { }
    for pat, reason in util_spairs( patterns_tbl ) do
        items[ #items + 1 ] = { pattern = pat, reason = reason }
    end
    return { status = 200, data = {
        patterns = items,
        count    = #items,
    } }
end

local http_create_pattern = function( req )
    local body = req.body or { }
    local pattern = body.pattern
    local reason  = body.reason
    local actor_label = util_strip( req.token_label or "http-api" )
    local ok, err_code, msg = do_add_pattern( pattern, reason, actor_label )
    if not ok then
        return { status = _err_to_status[ err_code ] or 400, error = {
            code    = err_code or "invalid",
            message = msg,
        } }
    end
    audit.fire( audit.build( "client.block.add",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { pattern = pattern, reason = _effective_reason( reason ) } ) )
    return { status = 201, data = {
        action  = "added",
        pattern = pattern,
        reason  = patterns_tbl[ pattern ],
    } }
end

local http_delete_pattern = function( req )
    local pattern = req.path_vars and req.path_vars.pattern
    local actor_label = util_strip( req.token_label or "http-api" )
    -- do_del_pattern packs into the second return slot either the
    -- err_code (on failure) or the previous reason (on success);
    -- keep them aliased through the same local but read them with
    -- the right name in each branch for clarity.
    local ok, payload, msg = do_del_pattern( pattern, actor_label )
    if not ok then
        local err_code = payload
        return { status = _err_to_status[ err_code ] or 400, error = {
            code    = err_code or "invalid",
            message = msg,
        } }
    end
    local previous_reason = payload
    audit.fire( audit.build( "client.block.remove",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { pattern = pattern, previous_reason = previous_reason } ) )
    return { status = 200, data = {
        action   = "deleted",
        pattern  = pattern,
        previous = previous_reason,
    } }
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onConnect", { }, check_clients )

hub.setlistener( "onStart", { },
    function( )
        --// load
        local on_disk = util_load( patterns_file )
        local file_missing = ( on_disk == nil )
        if file_missing then
            -- File doesn't exist (or is unreadable). On the next
            -- block of code we seed bundled defaults INTO it -
            -- treat this as the canonical "first run" path, not
            -- an error condition (no opchat feed).
            on_disk = { }
        end
        patterns_tbl = { }
        if type( on_disk ) == "table" then
            for k, v in pairs( on_disk ) do
                if type( k ) == "string" and type( v ) == "string" then
                    patterns_tbl[ k ] = v
                end
            end
        end

        -- Seed BUNDLED_DEFAULTS ONLY when the operator-data file is
        -- MISSING on disk. We deliberately do NOT seed when the file
        -- exists with an empty patterns table - that case is the
        -- operator's explicit "I want zero patterns" state, and
        -- silently re-injecting defaults on every +reload would
        -- undo that intent.
        --
        -- Operators who lost their bundled defaults via a one-off
        -- script-sync edge case (the .tbl already existed pre-update
        -- as an empty stub) can recover by either:
        --   - deleting scripts/data/etc_clientblocker.tbl on disk and
        --     +reload (triggers the file-missing branch -> seed)
        --   - or copying patterns out of
        --     examples/data/etc_clientblocker.tbl.example into the
        --     .tbl and +reload.
        if file_missing then
            for k, v in pairs( BUNDLED_DEFAULTS ) do patterns_tbl[ k ] = v end
            util_save( patterns_tbl, "patterns", patterns_file )
        end

        --// help, ucmd, hubcmd
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title_add,  help_usage_add,  help_desc_add,  oplevel )
            help.reg( help_title_del,  help_usage_del,  help_desc_del,  oplevel )
            help.reg( help_title_list, help_usage_list, help_desc_list, oplevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_add, cmd_add,
                { "%[line:" .. ucmd_popup_pat .. "]", "%[line:" .. ucmd_popup_reason .. "]" },
                { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_del, cmd_del,
                { "%[line:" .. ucmd_popup_pat .. "]" },
                { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_list, cmd_list, { }, { "CT1" }, oplevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_add,  on_addblocker, oplevel ) )
        assert( hubcmd.add( cmd_del,  on_delblocker, oplevel ) )
        assert( hubcmd.add( cmd_list, on_listblocker, oplevel ) )

        --// HTTP API endpoints (#81, raw hub.http_register because
        --// the resource key is a pattern string, not a SID).
        if hub.http_register then
            hub.http_register( "GET", "/v1/clientblocker", "read", http_list_patterns, {
                plugin = scriptname,
                description = "list configured client-blocker patterns (= ADC `+blocker`)",
                response_schema = {
                    patterns = { type = "array",   required = true },
                    count    = { type = "integer", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/clientblocker", "admin", http_create_pattern, {
                plugin = scriptname,
                description = "add a client-blocker pattern (= ADC `+addblocker <pattern> [reason]`)",
                request_schema = {
                    pattern = { type = "string", required = true, max_length = 4096 },
                    reason  = { type = "string", required = false, max_length = 1024 },
                },
                response_schema = {
                    action  = { type = "string", required = true },
                    pattern = { type = "string", required = true },
                    reason  = { type = "string", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/clientblocker/{pattern}", "admin", http_delete_pattern, {
                plugin = scriptname,
                description = "remove a client-blocker pattern (= ADC `+delblocker <pattern>`)",
                response_schema = {
                    action   = { type = "string", required = true },
                    pattern  = { type = "string", required = true },
                    previous = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)


hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )


--// public //--

return {

    resolve = function( version_string )
        if type( version_string ) ~= "string" then return nil end
        local ok, escaped = pcall( hub_escapefrom, version_string )
        if not ok then return nil end
        for pat, reason in pairs( patterns_tbl ) do
            local hok, hit = pcall( string_find, escaped, pat )
            if hok and hit then return reason end
        end
        return nil
    end,

    get_patterns_tbl = function( ) return patterns_tbl end,

}
