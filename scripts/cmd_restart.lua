--[[

    cmd_restart.lua by blastbeat

        - this script adds a command "restart" to restart the hub
        - usage: [+!#]restart [<MSG>]

        v0.12:
            - HTTP API: POST /v1/restart (X-Confirm required)  #82 Phase 3 PR-1
            - extract do_restart() helper shared by ADC + HTTP paths

        v0.11: by pulsar
            - prevent message output if no reason given

        v0.10: by blastbeat
            - improve shutdown/exit logic

        v0.09: by pulsar
            - added "update_lastlogout" function
            - removed table lookups

        v0.08: by pulsar
            - possibility to send optional mass msg  / thx Sopor

        v0.07: by pulsar
            - add table lookups
            - clean code
            - removed "cmd_restart_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_restart_minlevel"

        v0.06: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.05: by pulsar
            - add ascii countdown mode
            - toggle countown on/off

        v0.04: by blastbeat
            - updated script api
            - renamed command
            - regged hubcommand

        v0.03: by blastbeat
            - added language files and ucmd

        v0.02: by blastbeat
            - updated script api

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_restart"
local scriptversion = "0.12"

local cmd = "restart"

--// imports
local hubcmd
local scriptlang = cfg.get( "language" )
local permission = cfg.get( "cmd_restart_permission" )
local toggle_countdown = cfg.get( "cmd_restart_toggle_countdown" )

--// msgs
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )

local help_title = "cmd_restart.lua"
local help_usage = lang.help_usage or "[+!#]restart [<MSG>]"
local help_desc = lang.help_desc or "Restarts hub"

local ucmd_menu = lang.ucmd_menu or { "Hub", "Core", "Hub restart", "CLICK" }
local ucmd_msg = lang.ucmd_msg or "Mass Message (optional)"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_ok = lang.msg_ok or "Hub restarted."
local msg_hub_disabled = lang.msg_hub_disabled or "Hub is restarting."
local msg_countdown = lang.msg_countdown or "*** Hubrestart in ***"
local msg_restart = lang.msg_restart or [[


=== HUB RESTART ======================================================================================================

  %s

====================================================================================================== HUB RESTART ===

  ]]


----------
--[CODE]--
----------

local digital = {

    [0] = [[
                                                        ####
                                                        #     #
                                                        #     #
                                                        #     #
                                                        ####
        ]],
    [1] = [[
                                                           #
                                                           #
                                                           #
                                                           #
                                                           #
        ]],
    [2] = [[
                                                        ####
                                                               #
                                                        ####
                                                        #
                                                        ####
        ]],
    [3] = [[
                                                        ####
                                                               #
                                                        ####
                                                               #
                                                        ####
        ]],
    [4] = [[
                                                        #     #
                                                        #     #
                                                        ####
                                                               #
                                                               #
        ]],
    [5] = [[
                                                        ####
                                                        #
                                                        ####
                                                               #
                                                        ####
        ]],
    [6] = [[
                                                        ####
                                                        #
                                                        ####
                                                        #     #
                                                        ####
        ]],
    [7] = [[
                                                        ####
                                                               #
                                                               #
                                                               #
                                                               #
        ]],
    [8] = [[
                                                        ####
                                                        #     #
                                                        ####
                                                        #     #
                                                        ####
        ]],
    [9] = [[
                                                        ####
                                                        #     #
                                                        ####
                                                               #
                                                               #
        ]],
}

local minlevel = util.getlowestlevel( permission )
local list = { }
local countdown = 10

local update_lastlogout = function()
    local user_tbl = hub.getregusers()
    for i, v in pairs( user_tbl ) do
        if ( user_tbl[ i ].is_bot ~= 1 ) and ( user_tbl[ i ].is_online == 1 ) then
            user_tbl[ i ].lastlogout = util.date()
        end
    end
    cfg.saveusers( user_tbl )
end

local do_exit = function()
    -- T1.5 of #147: spec-compliant ISTA 212 emission ("Hub disabled")
    -- to every connected user before the socket close. The hub-disabled
    -- state is also the right code for a restart - "I'm going away,
    -- briefly, then coming back" - and prevents clients from treating
    -- the disconnect as a network glitch + immediate reconnect race.
    for _, u in pairs( hub.getusers() ) do
        u:sendsta( 212, msg_hub_disabled )
    end
    hub.shutdown()
    local starttime = os.time()
    return function()
        local diff = os.time() - starttime
        if diff >= 2 then
            update_lastlogout()
            hub.restart()
        end
    end
end

local do_countdown = function()
    local starttime = os.time()
    return function()
        if digital[ countdown ] then
            hub.broadcast( msg_countdown .. "\n\n" .. digital[ countdown ], hub.getbot() )
        end
        if countdown == 0 then
            hub.setlistener( "onTimer", {}, do_exit())
            countdown = -1
        elseif os.time() - starttime >= 1 then
            starttime = os.time()
            countdown = countdown - 1
        end
    end
end

local in_progress = false

-- Block main-chat broadcasts once a restart is queued: the hub will be
-- down in seconds, and the existing countdown messages are bot output
-- (not subject to onBroadcast) so the visual countdown remains visible.
hub.setlistener( "onBroadcast", { },
    function( )
        if in_progress then
            return PROCESSED
        end
    end
)

-- Shared action helper used by BOTH the ADC `+restart` chat-cmd
-- path AND the HTTP `POST /v1/restart` path (#82 Phase 3 PR-1).
-- Performs the broadcast (if a message was supplied) and arms the
-- exit timer. Callers MUST guard `in_progress` BEFORE calling and
-- set it to true on success - the helper does not own that flag,
-- because the ADC and HTTP surfaces report "already in progress"
-- with different semantics (silent return PROCESSED vs. 409).
--
-- Control-byte sanitisation of `comment` is done here (defence in
-- depth around adclib::escape, matching cmd_disconnect / cmd_redirect /
-- cmd_gag / cmd_ban from Phase 2).
local do_restart = function( comment )
    if comment and comment ~= "" then
        local clean_comment = util.strip_control_bytes( comment )
        hub.broadcast( utf.format( msg_restart, clean_comment ), hub.getbot(), hub.getbot() )
    end
    if toggle_countdown then
        hub.setlistener( "onTimer", {}, do_countdown( ) )
    else
        hub.setlistener( "onTimer", {}, do_exit( ) )
    end
end

local onbmsg = function( user, command, parameters )
    if not permission[ user:level() ] then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    if in_progress then -- restart was already issued
        return PROCESSED
    end
    in_progress = true
    local comment = utf.match( parameters, "^(.*)" )
    -- Fire BEFORE do_restart arms the exit timer (the timer's
    -- callback closes the process via hub.shutdown + hub.restart;
    -- audit fires queued there would never reach the writer).
    audit.fire( audit.build( "hub.restart", user, nil,
        ( comment and comment ~= "" and comment or nil ),
        { countdown = not not toggle_countdown } ) )
    do_restart( comment )
    if not toggle_countdown then
        user:reply( msg_ok, hub.getbot() )
    end
    return PROCESSED
end

-- HTTP handler: POST /v1/restart (#82 Phase 3 PR-1). The
-- `X-Confirm: yes` header is enforced by the router (see
-- core/http_router.lua _xconfirm_required); a missing header
-- returns 400 E_CONFIRMATION_REQUIRED before this handler runs.
-- The ADC-side `cmd_restart_permission` level check does NOT apply
-- on the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
--
-- A concurrent second call (while a restart is already armed)
-- returns 409 E_CONFLICT - matches the ADC path's silent
-- early-return semantically. Idempotent retries should use
-- `X-Idempotency-Key`: the router replays the 200 response for
-- 5 min without re-running the handler.
local http_handler_restart = function( req )
    if in_progress then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "restart already in progress" } }
    end
    in_progress = true
    local message = ( req.body and req.body.message ) or ""
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    -- Fire BEFORE do_restart (see ADC-path rationale above).
    audit.fire( audit.build( "hub.restart",
        { nick = actor_label, sid = "<http>" }, nil,
        ( message ~= "" and util.strip_control_bytes( message ) or nil ),
        { countdown = not not toggle_countdown } ) )
    do_restart( message )
    local clean_message = util.strip_control_bytes( message )
    return { status = 200, data = {
        action    = "restart",
        message   = clean_message,
        -- Coerce to bool (cfg may return any truthy value; dkjson
        -- serialises non-bool truthy values as-is, which would
        -- violate the boolean response_schema).
        countdown = not not toggle_countdown,
    } }
end

hub.setlistener( "onStart", { },
    function( )
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub.import( "etc_usercommands" )  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { "%[line:" .. ucmd_msg .. "]" }, { "CT1" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoint (#82 Phase 3 PR-1). Coexists with the
        -- ADC `+restart` chat-cmd above; both call into do_restart.
        -- Raw hub.http_register (not util_http) because this is a
        -- hub-control endpoint with no SID target.
        if hub.http_register then
            hub.http_register( "POST", "/v1/restart", "admin", http_handler_restart, {
                plugin = scriptname,
                description = "restart the hub (= ADC `+restart [MSG]`); requires X-Confirm: yes header. body { message?: string }",
                request_schema = {
                    message = { type = "string", max_length = 1024 },
                },
                response_schema = {
                    action    = { type = "string", required = true },
                    countdown = { type = "boolean", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
