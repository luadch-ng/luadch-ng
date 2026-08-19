--[[

    etc_blacklist.lua by pulsar

        v0.9:
            - HTTP API: GET /v1/blacklist (read), DELETE /v1/blacklist/{nick}
              (admin)  #82 Phase 4 PR-3

        v0.8: by pulsar
            - removed "hub.reloadusers()"
            - removed "hub.restartscripts()"

        v0.7:
            - small fix in help function  / thx Sopor

        v0.6:
            - add table lookups
            - fix permission
            - cleaning code
            - fix database import  / thx DerWahre
            - add "deleted by" info

        v0.5:
            - changed database path and filename
            - from now on all scripts uses the same database folder

        v0.4:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.3:
            - added: seperate levelcheck for delete feature

        v0.2:
            - added: hub.restartscripts() & hub.reloadusers()

        v0.1:
            - show blacklisted users
            - delete blacklisted users

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_blacklist"
local scriptversion = "0.10"

local cmd = "blacklist"
local cmd_p_show = "show"
local cmd_p_del = "del"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_debug = hub.debug
local hub_import = hub.import
local utf_match = utf.match
local utf_format = utf.format
local hub_getbot = hub.getbot()
local util_loadtable = util.loadtable
local util_savetable = util.savetable

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg_get( "language" )
local oplevel = cfg_get( "etc_blacklist_oplevel" )
local masterlevel = cfg_get( "etc_blacklist_masterlevel" )
local blacklist_file = "scripts/data/cmd_delreg_blacklist.tbl"

--// msgs
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )

local help_title = "etc_blacklist.lua - Show"
local help_usage = lang.help_usage or "[+!#]blacklist show"
local help_desc = lang.help_desc or "show denylisted users"

local help_title2 = "etc_blacklist.lua - Del"
local help_usage2 = lang.help_usage2 or "[+!#]blacklist del <nick>"
local help_desc2 = lang.help_desc2 or "delete user from denylist"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]blacklist show  /  [+!#]blacklist del <nick>"

local msg_01 = lang.msg_01 or "\t  Username: "
local msg_02 = lang.msg_02 or "\t  Deleted on: "
local msg_06 = lang.msg_06 or "\t  Deleted by: "
local msg_03 = lang.msg_03 or "\t  Reason: "
local msg_04 = lang.msg_04 or "The following user was deleted from Denylist: "
local msg_05 = lang.msg_05 or "Error: User not found."

local ucmd_menu_show = lang.ucmd_menu_show or { "Hub", "etc", "Denylist", "show" }
local ucmd_menu_del = lang.ucmd_menu_del or { "Hub", "etc", "Denylist", "user delete" }
local ucmd_nick = lang.ucmd_nick or "Username:"

local msg_out = lang.msg_out or [[


=== DENYLIST =========================================================================================
%s
========================================================================================= DENYLIST ===
  ]]


----------
--[CODE]--
----------

local onbmsg = function( user, adccmd, parameters )
    local blacklist_tbl = util_loadtable( blacklist_file ) or {}
    local param1 = utf_match( parameters, "^(%S+)" )
    local param2 = utf_match( parameters, "^%a+ (%S+)" )
    local user_level = user:level()
    if param1 == cmd_p_show then
        if user_level >= oplevel then
            local msg = ""
            for k, v in pairs( blacklist_tbl ) do
                local date = blacklist_tbl[ k ][ "tDate" ] or ""
                local by = blacklist_tbl[ k ][ "tBy" ] or ""
                local reason = blacklist_tbl[ k ][ "tReason" ] or ""
                msg = msg .. "\n" ..
                msg_01 .. k .. "\n" ..
                msg_02 .. date .. "\n" ..
                msg_06 .. by .. "\n" ..
                msg_03 .. reason .. "\n"
            end
            local blacklist = utf_format( msg_out, msg )
            user:reply( blacklist, hub_getbot )
            return PROCESSED
        else
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
    end
    if param1 == cmd_p_del then
        if user_level >= masterlevel then
            if blacklist_tbl[ param2 ] then
                blacklist_tbl[ param2 ] = nil
                util_savetable( blacklist_tbl, "blacklist_tbl", blacklist_file )
                user:reply( msg_04 .. param2, hub_getbot )
                audit.fire( audit.build( "blacklist.remove", user,
                    { nick = param2 }, nil, nil ) )
                return PROCESSED
            else
                user:reply( msg_05, hub_getbot )
                return PROCESSED
            end
        else
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
    end
    user:reply( msg_usage, hub_getbot )
    return PROCESSED
end

-- HTTP handler: GET /v1/blacklist (#82 Phase 4 PR-3). Read scope.
-- Returns 200 with `data: {entries: [{nick, blacklisted_at, by,
-- reason}, ...]}`. `blacklisted_at` is the raw stored string
-- `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s
-- persistence format, not ISO 8601). Entries are returned in the
-- order pairs() yields them (Lua hash-table order; clients should
-- sort if a stable order is needed).
--
-- The file is loaded on-demand (same pattern as the ADC `+blacklist
-- show` cmd at the onbmsg handler above). cmd_delreg also writes
-- to this file on-demand without an in-memory cache, so there is
-- no cross-plugin staleness window. Lua is single-threaded and
-- neither plugin yields between load and save, so independent
-- load-modify-save in both plugins cannot interleave.
--
-- Note: cmd_delreg has its own `blacklist_del` function for the
-- ADC `+delreg <nick>` blacklist-cleanup branch. We deliberately
-- do NOT import it here - sharing would create a hub.import
-- dependency back into cmd_delreg, and the rebind hazard
-- documented in reference_lua_plugin_exports applies (a future
-- cmd_delreg refactor that rebinds the file-local could leave
-- this plugin holding a stale function reference). Each plugin
-- doing its own loadtable+modify+savetable IS the safe pattern.
--
-- The ADC-side `etc_blacklist_oplevel` gate does NOT apply on
-- the HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
-- #264 PR-B filter/sort spec for /v1/blacklist. Operates on the
-- formatted entry shape so getters match the response field names.
-- blacklisted_at is a "YYYY-MM-DD / HH:MM:SS" string per
-- cmd_delreg's persistence format - lex-sortable, parse_query
-- passes through unchanged.
local _blacklist_filter_spec = {
    string_fields = {
        nick   = function( e ) return e.nick   or "" end,
        by     = function( e ) return e.by     or "" end,
        reason = function( e ) return e.reason or "" end,
    },
    date_fields = {
        blacklisted_at = {
            -- Return nil for missing dates so `_before` queries do
            -- NOT false-match empty-string entries (empty < any date
            -- in lex order).
            get         = function( e )
                local v = e.blacklisted_at
                if not v or v == "" then return nil end
                return v
            end,
            parse_query = function( q ) return q end,
        },
    },
    sortable_fields = {
        nick           = function( e ) return e.nick           or "" end,
        by             = function( e ) return e.by             or "" end,
        blacklisted_at = function( e ) return e.blacklisted_at or "" end,
    },
    default_sort_field      = "nick",
    default_sort_descending = false,
}

local http_handler_list_blacklist = function( req )
    local blacklist_tbl = util_loadtable( blacklist_file ) or {}
    local entries = {}
    for nick, entry in pairs( blacklist_tbl ) do
        entries[ #entries + 1 ] = {
            nick           = nick,
            blacklisted_at = ( entry and entry.tDate )   or "",
            by             = ( entry and entry.tBy )     or "",
            reason         = ( entry and entry.tReason ) or "",
        }
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _blacklist_filter_spec, entries
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = { entries = rows },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- HTTP handler: DELETE /v1/blacklist/{nick} (#82 Phase 4 PR-3).
-- Admin scope. Removes a single nick from the blacklist file and
-- returns the snapshot of the removed entry so the operator's
-- audit / undo flow has the deletion record. Returns **404
-- E_NOT_FOUND** if `{nick}` is not on the blacklist (idempotent
-- 200 would mask the typo case where an operator misspells the
-- target nick).
--
-- No X-Confirm gate: single-nick removal is reversible by issuing
-- ADC `+delreg <nick> <reason>` against the same nick, which
-- adds it back to the blacklist (or by `POST /v1/registered` if
-- the nick was on the blacklist only as a reg-denylist marker
-- without an underlying reg). The cost of accidental removal is
-- bounded.
--
-- The ADC-side `etc_blacklist_masterlevel` gate (typically
-- owner-only) does NOT apply on the HTTP path: the bearer
-- token's `admin` scope IS the authorisation gate.
local http_handler_delete_blacklist_entry = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local blacklist_tbl = util_loadtable( blacklist_file ) or {}
    local entry = blacklist_tbl[ nick ]
    if not entry then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "nick '" .. nick .. "' is not on the blacklist" } }
    end
    blacklist_tbl[ nick ] = nil
    util_savetable( blacklist_tbl, "blacklist_tbl", blacklist_file )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "blacklist.remove",
        { nick = actor_label, sid = "<http>" },
        { nick = nick }, nil,
        { previous_reason = ( entry and entry.tReason ) or nil } ) )
    return { status = 200, data = {
        action = "blacklist-removed",
        nick   = nick,
        removed = {
            blacklisted_at = ( entry and entry.tDate )   or "",
            by             = ( entry and entry.tBy )     or "",
            reason         = ( entry and entry.tReason ) or "",
        },
    } }
end

hub.setlistener( "onStart", {},
    function()
        help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
            help.reg( help_title2, help_usage2, help_desc2, masterlevel )
        end
        ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_show, cmd, { cmd_p_show }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_del, cmd, { cmd_p_del, "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, masterlevel )
        end
        hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, oplevel ) )
        -- HTTP API endpoints (#82 Phase 4 PR-3).
        if hub.http_register then
            hub.http_register( "GET", "/v1/blacklist", "read", http_handler_list_blacklist, {
                plugin = scriptname,
                description = "list blacklisted nicks (= ADC `+blacklist show`); each entry: nick + blacklisted_at + by + reason",
                response_schema = {
                    entries = { type = "array", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/blacklist/{nick}", "admin", http_handler_delete_blacklist_entry, {
                plugin = scriptname,
                description = "remove a nick from the blacklist (= ADC `+blacklist del <nick>`); returns the deleted entry as `removed`",
                response_schema = {
                    action  = { type = "string", required = true },
                    nick    = { type = "string", required = true },
                    removed = { type = "object", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .." **" )