--[[

    cmd_mass.lua by blastbeat

        - this script adds commands to send pm mass messages
        - usage: [+!#]mass <MSG> / [+!#]masslvl <LEVEL> <MSG> / [+!#]masshub <MSG>

        v0.20:
            - route the "  |  allowed levels: " help-desc appender
              through lang (msg_allowed_levels). Part of #301 i18n cleanup.

        v0.19:
            - HTTP API: POST /v1/announce (admin scope)  #82 deferred Phase-2-spec
            - extract do_announce_all / _hub / _level helpers shared by ADC + HTTP

        v0.17: by pulsar
            - small fix in onStart listener

        v0.16: by pulsar
            - improved dateparser()
            - renamed and split "msg_out_op" to "msg_out_lvl" & "msg_out_hub"
            - possibility to send mass without sender  / requested by Sopor
            - some code improvements
            - using one single "onbmsg" function now

        v0.15: by pulsar
            - removed "cmd_mass_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_mass_minlevel"

        v0.14: by pulsar
            - changed date style in output messages to: yyyy-mm-dd
            - code cleaning

        v0.13: by pulsar
            - changed visual output style

        v0.12: by pulsar
            - send mass to specific levels for ops
            - code cleaning
            - table lookups

        v0.11: by pulsar
            - changed visual output style
            - table lookups

        v0.10: by pulsar
            - changed rightclick style

        v0.09: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.08: by blastbeat
            - updated script api
            - regged hubcommand

        v0.07: by blastbeat
            - mass will be send by hub bot now
            - fixed 'sends first word only' bug

        v0.06: by blastbeat
            - some clean ups

        v0.05: by blastbeat
            - added language files and ucmd

        v0.04: by blastbeat
            - updated script api

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_mass"
local scriptversion = "0.21"

local cmd = "mass"
local cmd_lvl = "masslvl"
local cmd_hub = "masshub"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_getbot = hub.getbot()
local hub_getusers = hub.getusers
local hub_broadcast = hub.broadcast
local hub_import = hub.import
local hub_debug = hub.debug
local utf_match = utf.match
local utf_format = utf.format
local util_getlowestlevel = util.getlowestlevel
local os_date = os.date
local table_sort = table.sort

--// imports
local oplevel = cfg_get( "cmd_mass_oplevel" )
local permission = cfg_get( "cmd_mass_permission" )
local levels = cfg_get( "levels" )
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub_debug( err )

--// msgs
local help_title = "cmd_mass.lua - Users"
local help_usage = lang.help_usage or "[+!#]mass <MSG>"
local help_desc = lang.help_desc or "sends a pm with <MSG> to all users"

local help_title_op = "cmd_mass.lua - Ops"
local help_usage_op = lang.help_usage_op or "[+!#]masslvl <LEVEL> <MSG> / [+!#]masshub <MSG>"
local help_desc_op = lang.help_desc_op or "sends a pm with <MSG> to all users with specific level / sends a pm with <MSG> without sender"
local msg_allowed_levels = lang.msg_allowed_levels or "  |  allowed levels: "

local ucmd_menu = lang.ucmd_menu or { "User", "Messages", "Mass", "to all" }
local ucmd_menu_hub = lang.ucmd_menu_hub or { "User", "Messages", "Mass", "to all (without sender)" }
local ucmd_menu_1 = lang.ucmd_menu_1 or "User"
local ucmd_menu_2 = lang.ucmd_menu_2 or "Messages"
local ucmd_menu_3 = lang.ucmd_menu_3 or "Mass"
local ucmd_menu_4 = lang.ucmd_menu_4 or "to level"
local ucmd_what = lang.ucmd_what or "Message:"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]mass <MSG>"
local msg_usage_lvl = lang.msg_usage_lvl or "Usage: [+!#]masslvl <LEVEL> <MSG>"
local msg_usage_hub = lang.msg_usage_hub or "Usage: [+!#]masshub <MSG>"
local msg_lvl_exists = lang.msg_lvl_exists or "Level %s does not exist."
local msg_ok = lang.msg_ok or "Mass was sent to all users with level: "
local msg_out = lang.msg_out or [[


=== MASS MESSAGE ======================================================================================================

Sender:  %s   |   Date:  %s   |   Time:  %s

Message:  %s

====================================================================================================== MASS MESSAGE ===
  ]]

local msg_out_lvl = lang.msg_out_lvl or [[


=== MASS MESSAGE ======================================================================================================

Sender:  %s   |   Date:  %s   |   Time:  %s  |  Sent to all users with level:  %s

Message:  %s

====================================================================================================== MASS MESSAGE ===
  ]]

local msg_out_hub = lang.msg_out_hub or [[


=== MASS MESSAGE ======================================================================================================

Date:  %s   |   Time:  %s

Message:  %s

====================================================================================================== MASS MESSAGE ===
  ]]

--// functions
local dateparser
local onbmsg


----------
--[CODE]--
----------

local minlevel = util_getlowestlevel( permission )

-- Closes upstream luadch/luadch#217: append the actual list of
-- permitted levels to help_desc. util_getlowestlevel returns just
-- the lowest TRUE-keyed level, which is misleading when there are
-- false-gaps above it (e.g. {[20]=true, [30]=false, [60]=true}
-- shows "Min Level: 20" but levels 30-50 are actually denied).
do
    local allowed = { }
    for k, v in pairs( permission ) do
        if v == true then allowed[ #allowed + 1 ] = k end
    end
    table_sort( allowed )
    local parts = { }
    for _, lvl in ipairs( allowed ) do
        local name = levels and levels[ lvl ]
        parts[ #parts + 1 ] = name and ( lvl .. " " .. name ) or tostring( lvl )
    end
    if #parts > 0 then
        help_desc = help_desc .. msg_allowed_levels .. table.concat( parts, ", " )
    end
end

dateparser = function()
    return os_date( "%Y" ) .. "-" .. os_date( "%m" ) .. "-" .. os_date( "%d" ), os_date( "%X" )
end

-- Shared action helpers used by BOTH the ADC `+mass` / `+masslvl` /
-- `+masshub` chat-cmds AND the HTTP `POST /v1/announce` path (#82).
-- Each helper builds the surface-specific message banner and
-- dispatches the broadcast. Callers are responsible for input
-- validation; the helpers trust their arguments.
--
-- `sender` is the actor-label flowing into the "Sender: X" line of
-- the banner: a nick for the ADC path, a non-secret token label
-- for the HTTP path. The "hub" variant omits the sender entirely
-- by design (matches the ADC `+masshub` semantic).

local do_announce_all = function( msg, sender )
    local date, time = dateparser()
    local mass = utf_format( msg_out, sender, date, time, msg )
    hub_broadcast( mass, hub_getbot, hub_getbot )
end

local do_announce_hub = function( msg )
    local date, time = dateparser()
    local mass = utf_format( msg_out_hub, date, time, msg )
    hub_broadcast( mass, hub_getbot, hub_getbot )
end

-- Returns the count of recipients (non-bot users at the given
-- level) that the banner was sent to. Useful for the HTTP
-- response's recipient-count field; ADC path ignores it.
local do_announce_level = function( msg, sender, lvl )
    local date, time = dateparser()
    local levelname = cfg_get( "levels" )[ lvl ] or "UNREG"
    local mass = utf_format( msg_out_lvl, sender, date, time, lvl .. " [ " .. levelname .. " ]", msg )
    local sent = 0
    for sid, target in pairs( hub_getusers() ) do
        if not target:isbot() and target:level() == lvl then
            target:reply( mass, hub_getbot, hub_getbot )
            sent = sent + 1
        end
    end
    return sent
end

onbmsg = function( user, command, param )
    local user_nick, user_level = user:nick(), user:level()
    --// mass
    if command == cmd then
        if not permission[ user_level ] then
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
        local msg = utf_match( param, "(.+)" )
        if not msg then
            user:reply( msg_usage, hub_getbot )
            return PROCESSED
        end
        do_announce_all( msg, user_nick )
        audit.fire( audit.build( "hub.announce.all", user, nil, msg, nil ) )
        return PROCESSED
    end
    --// masslvl
    if command == cmd_lvl then
        if user_level < oplevel then
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
        local lvl, msg = utf_match( param, "(%d+) (.+)" )
        local lvl = tonumber( lvl )
        if not ( lvl and msg ) then
            user:reply( msg_usage_lvl, hub_getbot )
            return PROCESSED
        end
        if not levels[ lvl ] then
            local txt = utf_format( msg_lvl_exists, lvl )
            user:reply( txt, hub_getbot )
            return PROCESSED
        end
        local sent = do_announce_level( msg, user_nick, lvl )
        local levelname = cfg_get( "levels" )[ lvl ] or "UNREG"
        user:reply( msg_ok .. lvl .. " [ " .. levelname .. " ]", hub_getbot )
        audit.fire( audit.build( "hub.announce.level", user, nil, msg,
            { level = lvl, recipients = sent } ) )
        return PROCESSED
    end
    --// masshub
    if command == cmd_hub then
        if user_level < oplevel then
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
        local msg = utf_match( param, "(.+)" )
        if not msg then
            user:reply( msg_usage_hub, hub_getbot )
            return PROCESSED
        end
        do_announce_hub( msg )
        audit.fire( audit.build( "hub.announce.hub", user, nil, msg, nil ) )
        return PROCESSED
    end
end

-- HTTP handler: POST /v1/announce (#82). Admin scope.
--
-- Body shape:
--   {message: string required (max 1024 chars, control-byte
--             sanitised),
--    scope: "all"|"hub"|"level" required (router-validated enum),
--    level: integer optional (REQUIRED when scope=level, must
--           reference a valid entry in cfg.levels)}
--
-- ADC-side `cmd_mass_permission` / `oplevel` do NOT apply on the
-- HTTP path: the bearer token's `admin` scope IS the authorisation
-- gate (consistent with the rest of #82). The "level" enum value
-- supports the operator's existing tooling around +masslvl without
-- requiring three separate HTTP endpoints.
--
-- Response per §7.1.1: `{action: "announce", scope, message,
-- level?, sender, recipients?}`. `sender` is the token's non-
-- secret label flowing into the banner's "Sender:" line (for
-- scope=all/level - the "hub" scope omits sender from the banner
-- by design, but the response still carries it for audit).
-- `recipients` is the count of matched users for scope=level
-- (broadcast variants omit it since "all online minus bots" is
-- derivable via /v1/stats).
local http_handler_announce = function( req )
    local body = req.body or { }
    local message = body.message
    if not message or message == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty 'message' field" } }
    end
    local scope = body.scope
    -- The enum validator at the schema level catches non-string +
    -- non-enum values, but we still need a runtime fall-through
    -- since the schema treats missing as not-an-error.
    if scope ~= "all" and scope ~= "hub" and scope ~= "level" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "scope must be 'all', 'hub', or 'level'" } }
    end
    local clean_msg = util.strip_control_bytes( message )
    -- #177 C: the banner's "Sender:" line was embedding a token fingerprint
    -- (the token's comment + first4...last4) and broadcasting it to every
    -- recipient on scope=all/level. Show the hubbot nick instead - the
    -- announce already goes out from the hub bot, so recipients see the
    -- hubbot, never a token label. The audit trail records the real operator.
    local sender = util.strip_control_bytes( hub.getbot():nick() )

    local data = {
        action  = "announce",
        scope   = scope,
        message = clean_msg,
        sender  = sender,
    }

    local actor_for_audit = { nick = util_http.operator_label( req ), sid = "<http>" }
    if scope == "all" then
        do_announce_all( clean_msg, sender )
        audit.fire( audit.build( "hub.announce.all", actor_for_audit, nil, clean_msg, nil ) )
    elseif scope == "hub" then
        do_announce_hub( clean_msg )
        audit.fire( audit.build( "hub.announce.hub", actor_for_audit, nil, clean_msg, nil ) )
    else    -- scope == "level"
        local lvl = body.level
        if type( lvl ) ~= "number" or lvl % 1 ~= 0 then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "scope='level' requires integer 'level' field" } }
        end
        if not levels[ lvl ] then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "level " .. tostring( lvl ) .. " does not exist in cfg.levels" } }
        end
        local recipients = do_announce_level( clean_msg, sender, lvl )
        data.level = lvl
        data.recipients = recipients
        audit.fire( audit.build( "hub.announce.level", actor_for_audit, nil, clean_msg,
            { level = lvl, recipients = recipients } ) )
    end

    return { status = 200, data = data }
end

hub.setlistener( "onStart", { },
    function( )
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
            help.reg( help_title_op, help_usage_op, help_desc_op, oplevel )
        end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { "%[line:" .. ucmd_what .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_hub, cmd_hub, { "%[line:" .. ucmd_what .. "]" }, { "CT1" }, oplevel )
            local tbl = {}
            local i = 1
            for k, v in pairs( levels ) do
                if k > 0 then
                    tbl[ i ] = k
                    i = i + 1
                end
            end
            table_sort( tbl )
            for _, level in pairs( tbl ) do
                ucmd.add( { ucmd_menu_1, ucmd_menu_2, ucmd_menu_3, ucmd_menu_4, levels[ level ] }, cmd_lvl, { level, "%[line:" .. ucmd_what .. "]" }, { "CT1" }, oplevel )
            end
        end
        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        --assert( hubcmd.add( { cmd, cmd_lvl, cmd_hub }, onbmsg ) )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        assert( hubcmd.add( cmd_lvl, onbmsg, oplevel ) )
        assert( hubcmd.add( cmd_hub, onbmsg, oplevel ) )
        -- HTTP API endpoint (#82). Coexists with the three ADC
        -- chat-cmds above. Raw hub.http_register (not util_http)
        -- because this is a hub-control endpoint with no SID target.
        if hub.http_register then
            hub.http_register( "POST", "/v1/announce", "admin", http_handler_announce, {
                plugin = scriptname,
                description = "send a mass message (= ADC `+mass` / `+masshub` / `+masslvl`); body { message, scope: 'all'|'hub'|'level', level?: int }",
                request_schema = {
                    message = { type = "string", required = true, max_length = 1024 },
                    scope   = { type = "string", required = true, enum = { "all", "hub", "level" } },
                    level   = { type = "integer", required = false },
                },
                response_schema = {
                    action  = { type = "string", required = true },
                    scope   = { type = "string", required = true },
                    message = { type = "string", required = true },
                    sender  = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )