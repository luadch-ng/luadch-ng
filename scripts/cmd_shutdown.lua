--[[

    cmd_shutdown.lua by blastbeat

        - this script adds a command "shutdown" to shutdown the hub
        - usage: [+!#]shutdown [<MSG>]

        v0.11:
            - HTTP API: POST /v1/shutdown (X-Confirm required)  #82 Phase 3 PR-2
            - extract do_shutdown() helper shared by ADC + HTTP paths
            - ADC `+shutdown` now skips the banner broadcast on empty
              comment (was always broadcasting an empty banner; matches
              cmd_restart behaviour)

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
            - removed "cmd_shutdown_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_shutdown_minlevel"

        v0.06: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.05: by pulsar
            - add ascii countdown mode
            - toggle countown on/off

        v0.04: by blastbeat
            - updated script api
            - regged hubcommand

        v0.03: by blastbeat
            - added language files and ucmd

        v0.02: by blastbeat
            - updated script api

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_shutdown"
local scriptversion = "0.11"

local cmd = "shutdown"

--// imports
local hubcmd
local scriptlang = cfg.get( "language" )
local permission = cfg.get( "cmd_shutdown_permission" )
local toggle_countdown = cfg.get( "cmd_shutdown_toggle_countdown" )

--// msgs
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

local help_title = "cmd_shutdown.lua"
local help_usage = lang.help_usage or "[+!#]shutdown [<MSG>]"
local help_desc = lang.help_desc or "shutdowns hub"

local ucmd_menu = lang.ucmd_menu or { "Shutdown hub" }
local ucmd_msg = lang.ucmd_msg or "Mass Message (optional)"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_ok = lang.msg_ok or "Shutdown hub..."
local msg_hub_disabled = lang.msg_hub_disabled or "Hub is shutting down."
local msg_countdown = lang.msg_countdown or "*** Hubshutdown in ***"

local msg_shutdown = lang.msg_shutdown or [[


=== HUB SHUTDOWN ======================================================================================================

  %s

====================================================================================================== HUB SHUTDOWN ===

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
    -- to every connected user before the socket close. Without this,
    -- clients see a bare disconnect indistinguishable from a network
    -- glitch and may auto-reconnect immediately.
    for _, u in pairs( hub.getusers() ) do
        u:sendsta( 212, msg_hub_disabled )
    end
    hub.shutdown()
    local starttime = os.time()
    return function()
        local diff = os.time() - starttime
        if diff >= 3 then
            update_lastlogout()
            hub.exit()
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
            hub.requestexit();
            countdown = -1
        elseif os.time() - starttime >= 1 then
            starttime = os.time()
            countdown = countdown - 1
        end
    end
end

local in_progress = false

-- Block main-chat broadcasts once a shutdown is queued: the hub will be
-- down in seconds, and the existing countdown messages are bot output
-- (not subject to onBroadcast) so the visual countdown remains visible.
hub.setlistener( "onBroadcast", { },
    function( )
        if in_progress then
            return PROCESSED
        end
    end
)

-- Shared action helper used by BOTH the ADC `+shutdown` chat-cmd
-- path AND the HTTP `POST /v1/shutdown` path (#82 Phase 3 PR-2).
-- Performs the broadcast (if a message was supplied) and triggers
-- the exit sequence: either the ASCII countdown timer or the
-- immediate `hub.requestexit()` (which fires `onShutdown`, which
-- in turn arms `do_exit()`). Callers MUST guard `in_progress`
-- BEFORE calling and set it to true on success - the helper does
-- not own that flag, because the ADC and HTTP surfaces report
-- "already in progress" with different semantics (silent return
-- PROCESSED vs. 409).
--
-- Control-byte sanitisation of `comment` is done here (defence in
-- depth around adclib::escape, matching cmd_disconnect / cmd_redirect /
-- cmd_gag / cmd_ban from Phase 2 and cmd_restart from Phase 3 PR-1).
-- Pre-v0.11 the ADC path broadcast even with an empty `comment`
-- (resulting in a banner with an empty `%s` slot); this is fixed
-- to match cmd_restart and to avoid the spurious empty banner.
local do_shutdown = function( comment )
    if comment and comment ~= "" then
        local clean_comment = util.strip_control_bytes( comment )
        hub.broadcast( utf.format( msg_shutdown, clean_comment ), hub.getbot(), hub.getbot() )
    end
    if toggle_countdown then
        hub.setlistener( "onTimer", {}, do_countdown( ) )
    else
        hub.requestexit()
    end
end

local onbmsg = function( user, command, parameters )
    if not permission[ user:level() ] then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    if in_progress then -- shutdown was already issued
        return PROCESSED
    end
    in_progress = true
    local comment = utf.match( parameters, "^(.*)" )
    -- Fire BEFORE do_shutdown arms the exit timer (process gone
    -- afterwards; the audit listener cannot consume queued events).
    audit.fire( audit.build( "hub.shutdown", user, nil,
        ( comment and comment ~= "" and comment or nil ),
        { countdown = not not toggle_countdown } ) )
    do_shutdown( comment )
    if not toggle_countdown then
        user:reply( msg_ok, hub.getbot() )
    end
    return PROCESSED
end

-- HTTP handler: POST /v1/shutdown (#82 Phase 3 PR-2). The
-- `X-Confirm: yes` header is enforced by the router (see
-- core/http_router.lua _xconfirm_required); a missing header
-- returns 400 E_CONFIRMATION_REQUIRED before this handler runs.
-- The ADC-side `cmd_shutdown_permission` level check does NOT
-- apply on the HTTP path: the bearer token's `admin` scope IS
-- the authorisation gate.
--
-- A concurrent second call (while a shutdown is already armed)
-- returns 409 E_CONFLICT - matches the ADC path's silent
-- early-return semantically. Idempotent retries should use
-- `X-Idempotency-Key`: the router replays the 200 response for
-- 5 min without re-running the handler.
local http_handler_shutdown = function( req )
    if in_progress then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "shutdown already in progress" } }
    end
    in_progress = true
    local message = ( req.body and req.body.message ) or ""
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    -- Fire BEFORE do_shutdown (see ADC-path rationale above).
    audit.fire( audit.build( "hub.shutdown",
        { nick = actor_label, sid = "<http>" }, nil,
        ( message ~= "" and util.strip_control_bytes( message ) or nil ),
        { countdown = not not toggle_countdown } ) )
    do_shutdown( message )
    local clean_message = util.strip_control_bytes( message )
    return { status = 200, data = {
        action    = "shutdown",
        message   = clean_message,
        -- Coerce to bool (cfg may return any truthy value; dkjson
        -- serialises non-bool truthy values as-is, which would
        -- violate the boolean response_schema).
        countdown = not not toggle_countdown,
    } }
end

hub.setlistener( "onShutdown", { },
    function( )
        hub.setlistener( "onTimer", {}, do_exit( ) )
        return PROCESSED
    end
)

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
        -- HTTP API endpoint (#82 Phase 3 PR-2). Coexists with the
        -- ADC `+shutdown` chat-cmd above; both call into do_shutdown.
        -- Raw hub.http_register (not util_http) because this is a
        -- hub-control endpoint with no SID target.
        if hub.http_register then
            hub.http_register( "POST", "/v1/shutdown", "admin", http_handler_shutdown, {
                plugin = scriptname,
                description = "shutdown the hub (= ADC `+shutdown [MSG]`); requires X-Confirm: yes header. body { message?: string }",
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
