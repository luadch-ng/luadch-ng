--[[

    cmd_errors.lua by blastbeat

        - this script adds a command "errors" to get hub errors, it also feeds errors to hubowners
        - usage: [+!#]errors

        v0.13:
            - HTTP API: GET /v1/log/error?lines=N (admin scope)  #82 Phase 3 PR-3
            - extract read_log_tail() helper shared by ADC + HTTP paths
            - ADC `+errors` tail off-by-one fixed (now exactly maxlines)

        v0.12: by pulsar
            - removed table lookups
            - removed unused code
            - changed visuals

        v0.11: by pulsar
            - added "onError" listener to feed errors to hubowners
            - added maxlines limit to send

        v0.10: by pulsar
            - improve rightclick entries  / thx Sopor

        v0.09: by pulsar
            - removed "cmd_errors_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_errors_minlevel"

        v0.08: by pulsar
            - add table lookups
            - send msg instead of " " if error.log is empty

        v0.07: by pulsar
            - changed rightclick style

        v0.06: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.05: by blastbeat
            - fixed small bug

        v0.04: by blastbeat
            - updated script api
            - regged hubcommand

        v0.03: by blastbeat
            - some clean ups

        v0.02: by blastbeat
            - added language files and ucmd

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_errors"
local scriptversion = "0.13"

-- HTTP API §6.4 tail-style cap. Matches the limit/offset cap of
-- 1000 documented for list endpoints. The ADC path keeps the
-- historical `maxlines = 200` (defined below) as both default
-- AND hard cap; the HTTP path uses 200 as default but lets
-- callers go up to 1000 via ?lines=N.
local HTTP_MAX_LINES = 1000

local cmd = "errors"

local maxlines = 200

--// imports
local scriptlang = cfg.get( "language" )
local permission = cfg.get( "cmd_errors_permission" )
local path = "log/error.log"

--// msgs
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )

local help_title = "cmd_errors.lua"
local help_usage = lang.help_usage or "[+!#]errors"
local help_desc = lang.help_desc or "Sends error.log"

local ucmd_menu = lang.ucmd_menu or { "Hub", "Logs", "show", "error.log" }

local msg_denied = lang.msg_denied or "[ ERRORS ]--> You are not allowed to use this command."
local msg_noerrors = lang.msg_noerrors or "[ ERRORS ]--> No errors."


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission )
local report_send

-- Shared log-tail reader used by BOTH the ADC `+errors` chat-cmd
-- path AND the HTTP `GET /v1/log/error` path (#82 Phase 3 PR-3).
-- Returns (lines_table, total_count). `lines_table` carries the
-- last `n` lines of the file (or all lines if `n` is nil or the
-- file has fewer than `n` lines). `total_count` is the file's
-- total line count (useful for the HTTP response: "200 returned
-- of 1500 total"). Returns ({}, 0) if the file does not exist.
local read_log_tail = function( log_path, n )
    local file = io.open( log_path, "r" )
    if not file then return { }, 0 end
    local all = { }
    for line in file:lines() do all[ #all + 1 ] = line end
    file:close()
    local total = #all
    if n and total > n then
        local out = { }
        for i = total - n + 1, total do
            out[ #out + 1 ] = all[ i ]
        end
        return out, total
    end
    return all, total
end

local onbmsg = function( user, command, parameters )
    if not permission[ user:level() ] then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    local tbl = read_log_tail( path, maxlines )
    if next( tbl ) == nil then
        user:reply( msg_noerrors, hub.getbot() )
    else
        user:reply( "\n\n" .. table.concat( tbl, "\n" ) .. "\n", hub.getbot(), hub.getbot() )
    end
    return PROCESSED
end

-- HTTP handler: GET /v1/log/error?lines=N (#82 Phase 3 PR-3).
-- Admin scope. Returns the last N lines (default 200, capped at
-- 1000 per §6.4 tail-style cap). Non-numeric or out-of-range
-- `lines` values are clamped to the default rather than rejected,
-- consistent with the §6.4 spec for read endpoints. Returns
-- 200 + empty `lines` array if the file does not exist (matches
-- the ADC path's "No errors." semantic without surfacing a 404
-- for a missing file that has not been written yet).
--
-- The ADC-side `cmd_errors_permission` level check does NOT
-- apply on the HTTP path: the bearer token's `admin` scope IS
-- the authorisation gate.
local http_handler_log_error = function( req )
    local n = tonumber( req.query and req.query.lines ) or maxlines
    if n < 1 then n = maxlines end
    if n > HTTP_MAX_LINES then n = HTTP_MAX_LINES end
    local lines, total = read_log_tail( path, n )
    return { status = 200, data = {
        lines       = lines,
        returned    = #lines,
        total_lines = total,
    } }
end

hub.setlistener( "onError", { },  -- when this function produces any error, it wont be reported to avoid endless loops
    function( msg )
        report_send( true, true, false, 100, msg )  -- new method
    end
)

hub.setlistener( "onStart", { },
    function( )
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { }, { "CT1" }, minlevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        local report = hub.import( "etc_report" )
        assert( report )
        report_send = report.send
        -- HTTP API endpoint (#82 Phase 3 PR-3). Read-only; admin
        -- scope (operator log; not for unprivileged read tokens).
        if hub.http_register then
            hub.http_register( "GET", "/v1/log/error", "admin", http_handler_log_error, {
                plugin = scriptname,
                description = "tail the hub error log (= ADC `+errors`); query ?lines=N (default 200, max 1000)",
                response_schema = {
                    lines       = { type = "array", required = true },
                    returned    = { type = "integer", required = true },
                    total_lines = { type = "integer", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )