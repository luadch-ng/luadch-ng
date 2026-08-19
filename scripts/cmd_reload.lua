--[[

    cmd_reload.lua by blastbeat

        - this script adds a command "reload" to reload cfg, user db and scripts
        - usage: [+!#]reload
        
        v0.04:
            - HTTP API: POST /v1/reload (X-Confirm required)  #82 deferred Phase-2-spec item

        v0.03: by pulsar
            - add table lookups
            - clean code
            - removed "cmd_reg_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_reload_minlevel"
        
        v0.02: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"
            
        v0.01: by blastbeat

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_reload"
local scriptversion = "0.04"

local cmd = "reload"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_debug = hub.debug
local hub_getbot = hub.getbot()
local hub_import = hub.import
local hub_reloadcfg = hub.reloadcfg
local hub_restartscripts = hub.restartscripts
local utf_match = utf.match
local util_getlowestlevel = util.getlowestlevel

--// imports
local hubcmd
local scriptlang = cfg_get( "language" )
local permission = cfg_get( "cmd_reload_permission" )

--// msgs
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub_debug( err )

local help_title = "cmd_reload.lua"
local help_usage = lang.help_usage or "[+!#]reload"
local help_desc = lang.help_desc or "reloads complete configuration: cfg.tbl, user.tbl, scripts"

local ucmd_menu = lang.ucmd_menu or { "Hub", "Core", "Hub reload" }

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_ok = lang.msg_ok or "Configuration reloaded."


----------
--[CODE]--
----------

local minlevel = util_getlowestlevel( permission )

local onbmsg = function( user, command )
    if not permission[ user:level( ) ] then
        user:reply( msg_denied, hub_getbot )
        return PROCESSED
    end
    -- Fire BEFORE the destructive call: hub_restartscripts() unloads
    -- every plugin (including the audit-log writer), so an
    -- audit.fire after the call would have no listener subscribed.
    audit.fire( audit.build( "hub.reload", user, nil, nil, nil ) )
    hub_reloadcfg()
    hub_restartscripts()
    user:reply( msg_ok, hub.getbot() )
    return PROCESSED
end

-- HTTP handler: POST /v1/reload (#82 deferred Phase-2-spec item).
-- The `X-Confirm: yes` header is enforced by the router (see
-- core/http_router.lua _xconfirm_required); a missing header
-- returns 400 E_CONFIRMATION_REQUIRED before this handler runs.
-- The ADC-side `cmd_reload_permission` level check does NOT apply
-- on the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate (consistent with the rest of #82).
--
-- Lua is single-threaded so no concurrent-reload guard is needed
-- (the second call cannot start until the first returns). The
-- idempotency cache (§6.2) makes retries with the same
-- X-Idempotency-Key safe - the cached 200 replays instead of
-- re-running the handler, which is the desired behaviour
-- ("don't double-reload on operator-tool retry").
--
-- `hub.restartscripts()` clears the entire HTTP route table and
-- re-registers everything via plugin onStart listeners. The
-- handler closure currently executing is captured + safe under
-- Lua semantics, so the response generation after the call
-- proceeds normally on the existing socket.
local http_handler_reload = function( req )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    -- Fire BEFORE the destructive call (see ADC-path rationale above).
    audit.fire( audit.build( "hub.reload",
        { nick = actor_label, sid = "<http>" }, nil, nil, nil ) )
    hub_reloadcfg()
    hub_restartscripts()
    return { status = 200, data = {
        action   = "reload",
        reloaded = { "cfg", "scripts" },
    } }
end

hub.setlistener( "onStart", { },
    function( )
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub_import( "etc_usercommands" )  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { }, { "CT1" }, minlevel )
        end
        hubcmd = hub_import( "etc_hubcommands" )  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoint (#82). Coexists with the ADC `+reload`
        -- chat-cmd above. Raw hub.http_register (not util_http)
        -- because this is a hub-control endpoint with no SID target.
        if hub.http_register then
            hub.http_register( "POST", "/v1/reload", "admin", http_handler_reload, {
                plugin = scriptname,
                description = "reload cfg.tbl + scripts (= ADC `+reload`); requires X-Confirm: yes header. No request body.",
                response_schema = {
                    action   = { type = "string", required = true },
                    reloaded = { type = "array", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
