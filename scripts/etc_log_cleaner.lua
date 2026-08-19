--[[

    etc_log_cleaner.lua by pulsar

        usage: [+!#]cleanlog error|cmd
        
        v0.9:
            - HTTP API: DELETE /v1/log/{name} (admin scope)  #82 Phase 3 PR-5

        v0.8:
            - improved rightclick entries  / thx Sopor
            - improved some parts of code (table lookups etc)
            - changed "help_usage"
            - added "msg_usage"

        v0.7:
            - changed rightclick style

        v0.6:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.5:
            - cleaning code

        v0.4:
            - added lang feature

        v0.3:
            - added help feature

        v0.2:
            - added "cmd.log"

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_log_cleaner"
local scriptversion = "0.9"

-- Allowed log names for the HTTP `DELETE /v1/log/{name}` endpoint
-- (#82 Phase 3 PR-5). The ADC `+cleanlog <name>` cmd supports the
-- same set; spec line in docs/HTTP_API.md §10.2 was originally
-- aspirational about adding `event` / `script` later (the plugin
-- never supported those - the spec was wrong, not the plugin).
local HTTP_LOG_PATHS = {
    error = "log/error.log",
    cmd   = "log/cmd.log",
}

local cmd = "cleanlog"

local cmd_p_error = "error"
local cmd_p_cmd = "cmd"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_debug = hub.debug
local hub_import = hub.import
local hub_getbot = hub.getbot()
local utf_match = utf.match
local io_open = io.open

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )
local minlevel = cfg_get( "etc_log_cleaner_minlevel" )
local activate_error = cfg_get( "etc_log_cleaner_activate_error" )
local activate_cmd = cfg_get( "etc_log_cleaner_activate_cmd" )

local logfile_error = "log/error.log"
local logfile_cmd = "log/cmd.log"

--// msgs
local help_title = "etc_log_cleaner.lua"
local help_usage = lang.help_usage or "[+!#]cleanlog error|cmd"
local help_desc = lang.help_desc or "Cleans logfiles"

local failmsg = lang.failmsg or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]cleanlog error|cmd"

local activate_error_msg = lang.activate_error_msg or "The 'error.log' cleaner is disabled"
local activate_cmd_msg = lang.activate_cmd_msg or "The 'cmd.log' cleaner is disabled"

local logfile_error_msg = lang.logfile_error_msg or "The 'error.log' was cleaned"
local logfile_cmd_msg = lang.logfile_cmd_msg or "The 'cmd.log' was cleaned"

local ucmd_menu_error = lang.ucmd_menu_error or { "Hub", "Logs", "clean", "error.log" }
local ucmd_menu_cmd = lang.ucmd_menu_cmd or { "Hub", "Logs", "clean", "cmd.log" }


----------
--[CODE]--
----------

local cleanlog = function( log )
    local f = io_open( log, "w+" )
    f:write()
    f:close()
end

-- File-size lookup for the HTTP response's `bytes_before` field.
-- Returns 0 if the file does not exist or cannot be sized.
local file_size = function( path )
    local f = io_open( path, "r" )
    if not f then return 0 end
    local n = f:seek( "end" ) or 0
    f:close()
    return n
end

-- HTTP handler: DELETE /v1/log/{name} (#82 Phase 3 PR-5).
-- Admin scope. `{name}` must be one of the keys in HTTP_LOG_PATHS
-- (currently `error` or `cmd`). Truncates the corresponding file
-- to 0 bytes and returns 200 with `data: {action:"log-cleared",
-- name, bytes_before}` per §7.1.1 (hub-control variant: no
-- `sid`/`nick`).
--
-- The ADC-side `etc_log_cleaner_activate_error` /
-- `_activate_cmd` flags do NOT apply on the HTTP path: the
-- bearer token's `admin` scope IS the authorisation gate
-- (consistent with the rest of Phase 3 and matching the
-- "admin token = god mode" convention from Phase 2 PRs). An
-- operator who needs to deny cleanup from a specific token
-- should simply not issue that token at admin scope.
local http_handler_clean_log = function( req )
    local name = req.path_vars and req.path_vars.name
    local path = name and HTTP_LOG_PATHS[ name ]
    if not path then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "log name must be one of: error, cmd" } }
    end
    local bytes_before = file_size( path )
    -- Truncate via "w+" mode (creates file if absent). The write+
    -- close pair flushes the empty buffer to disk. cleanlog crashes
    -- if io.open returns nil (no permission / disk full); we accept
    -- that here because the legacy ADC path has the same risk
    -- profile and the http_router catches handler errors as
    -- 500 E_INTERNAL.
    cleanlog( path )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "log.clear",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { name = name, bytes_before = bytes_before } ) )
    return { status = 200, data = {
        action       = "log-cleared",
        name         = name,
        bytes_before = bytes_before,
    } }
end

local onbmsg = function( user, adccmd, parameters, txt )
    local user_level = user:level()
    local id = utf_match( parameters, "^(%S+)$" )
    if user_level < minlevel then
        user:reply( failmsg, hub_getbot )
        return PROCESSED
    end
    if id == cmd_p_error then
        if activate_error then
            cleanlog( logfile_error )
            user:reply( logfile_error_msg, hub_getbot )
            audit.fire( audit.build( "log.clear", user, nil, nil, { name = "error" } ) )
        else
            user:reply( activate_error_msg, hub_getbot )
        end
        return PROCESSED
    end
    if id == cmd_p_cmd then
        if activate_cmd then
            cleanlog( logfile_cmd )
            user:reply( logfile_cmd_msg, hub_getbot )
            audit.fire( audit.build( "log.clear", user, nil, nil, { name = "cmd" } ) )
        else
            user:reply( activate_cmd_msg, hub_getbot )
        end
        return PROCESSED
    end
    user:reply( msg_usage, hub_getbot )
    return PROCESSED
end

hub.setlistener( "onStart", {},
    function()
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_error, cmd, { cmd_p_error }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_cmd, cmd, { cmd_p_cmd }, { "CT1" }, minlevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoint (#82 Phase 3 PR-5). Write-endpoint;
        -- admin scope. Bypasses the ADC-side activate_X cfg gates.
        if hub.http_register then
            hub.http_register( "DELETE", "/v1/log/{name}", "admin", http_handler_clean_log, {
                plugin = scriptname,
                description = "truncate a hub log file (= ADC `+cleanlog <name>`); {name} is one of: error, cmd",
                response_schema = {
                    action       = { type = "string", required = true },
                    name         = { type = "string", required = true },
                    bytes_before = { type = "integer", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )