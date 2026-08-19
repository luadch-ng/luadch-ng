--[[

    etc_cmdlog.lua by pulsar

        Description: logs commands and saves it to a log file (who, what, when)
        
        Usage: [+!#]cmdlog show

        v1.5:
            - fix (#460): the log baked the localized labels (msg1/msg2) into
              each line at write-time, so "+cmdlog show" and GET /v1/log/cmd
              never re-localized - every entry was frozen in whatever language
              was active when it was logged, and a hub whose language changed
              showed a mix. Entries are now stored language-neutral (fields
              separated by the US control byte) and the labels are applied at
              read-time in the current language, on both the ADC and HTTP path.
              Old baked lines predating this version have no delimiter and are
              rendered as-is (their frozen language) rather than dropped.
              Control bytes in args/nick are now stripped, which also closes a
              latent newline-in-args log-format corruption.

        v1.4:
            - fix: the language lookups read "lang.failmsg1" / "lang.failmsg2",
              but the lang files define the keys as "msg_denied" / "msg_nofile"
              - both lookups returned nil, the "or" fallback to the hardcoded
                English literal fired every time, and the German translations
                were unreachable regardless of cfg.language

        v1.3:
            - HTTP API: GET /v1/log/cmd?lines=N (admin scope)  #82 Phase 3 PR-4

        v1.2:
            - fix "onBroadcast" function
                - improved command check
                - solved issue with commands without params

        v1.1:
            - improve rightclick entries  / thx Sopor

        v1.0:
            - add table lookups
            - cleaning code
            - change date style

        v0.9:
            - changed visual output style

        v0.8:
            - removed "etc_cmdlog_label_top" and "etc_cmdlog_label_bottom" var
            - changed visual output style
            - code cleaning
            - table lookups

        v0.7:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.6:
            - removed main output

        v0.5:
            - added file exists check

        v0.4:
            - added lang feature

        v0.3:
            - code cleaning
            - help feature

        v0.2:
            - some optical changes
            - choose: send to main/pm

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_cmdlog"
local scriptversion = "1.5"

-- HTTP API tail-style cap per docs/HTTP_API.md §6.4. Same value
-- as cmd_errors.lua for consistency across log endpoints.
local HTTP_DEFAULT_LINES = 200
local HTTP_MAX_LINES = 1000

local cmd = "cmdlog"
local cmd_p = "show"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local hub_getbot = hub.getbot()
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_import = hub.import
local hub_debug = hub.debug
local utf_match = utf.match
local utf_format = utf.format
local os_date = os.date
local io_open = io.open
local util_strip = util.strip_control_bytes
local table_concat = table.concat

-- #460: entries are stored as US-delimited (0x1f) language-neutral
-- fields "ts <US> cmd <US> args <US> nick". The delimiter is a control
-- byte, so strip_control_bytes (applied to every field at write-time)
-- guarantees it never appears inside a field; a line without it is an
-- old baked entry (v1.4 and earlier) rendered as-is at read-time.
local FIELD_SEP = "\31"
local LINE_PAT  = "^([^\31]*)\31([^\31]*)\31([^\31]*)\31(.*)$"

--// imports
local logfile = "log/cmd.log"
local minlevel = cfg_get( "etc_cmdlog_minlevel" )
local command_tbl = cfg_get( "etc_cmdlog_command_tbl" ) or {}
-- #96: commands listed here have their post-command-name argument string
-- replaced with <redacted> in cmd.log, so passwords supplied via
-- +setpass / +newpw never land on disk.
local redact_args = cfg_get( "etc_cmdlog_redact_args" ) or {}
local scriptlang = cfg_get( "language" )

--// msgs
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )

local help_title = "etc_cmdlog.lua"
local help_usage = lang.help_usage or "[+!#]cmdlog show"
local help_desc = lang.help_desc or "Shows the command log"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_nofile = lang.msg_nofile or "No 'cmd.log' found."
local msg_usage = lang.msg_usage or "Usage: [+!#]cmdlog show"

local msg1 = lang.msg1 or "   |   Command: [+!#]"
local msg2 = lang.msg2 or "   |   used by: "

local msg_out = lang.msg_out or [[[


=== COMMAND LOGGER ========================================================================================

%s
======================================================================================== COMMAND LOGGER ===

      ]]

local ucmd_menu = lang.ucmd_menu or { "Hub", "Logs", "show", "cmd.log" }


----------
--[CODE]--
----------

hub.setlistener( "onBroadcast", {},
    function( user, adccmd, txt )
        local s1 = utf_match( txt, "^[+!#](%S+)" )
        local s2 = utf_match( txt, "^[+!#]%S+ (.+)" )
        if command_tbl[ s1 ] then
            if redact_args[ s1 ] then
                s2 = "<redacted>"
            else
                s2 = s2 or ""
            end
            -- #460: store language-neutral fields; labels are applied at
            -- read-time. strip_control_bytes keeps the delimiter out of any
            -- field and prevents a newline in args from breaking the line.
            -- Guard the open so a missing/unwritable log/ dir can't crash
            -- this onBroadcast listener (which fires for every broadcast).
            local f = io_open( logfile, "a" )
            if f then
                f:write( os_date( "%Y-%m-%d / %H:%M:%S" ) .. FIELD_SEP .. util_strip( s1 ) .. FIELD_SEP .. util_strip( s2 ) .. FIELD_SEP .. util_strip( user:nick() ) .. "\n" )
                f:close()
            end
        end
        return nil
    end
)

-- #460: render one stored line for display in the CURRENT language. A
-- new-format line is four US-delimited fields (ts, cmd, args, nick) and
-- gets the current msg1/msg2 labels here. A line without the delimiter
-- is an old baked entry (v1.4 and earlier) and is returned as-is so its
-- frozen language survives rather than being dropped or mis-parsed.
local render_line = function( line )
    local ts, c, a, n = line:match( LINE_PAT )
    if not ts then return line end
    return " [ " .. ts .. " ]" .. msg1 .. c .. " " .. a .. msg2 .. n
end

local onbmsg = function( user, adccmd, parameters, txt )
    local id = utf_match( parameters, "^(%S+)$" )
    if id == cmd_p then
        if user:level() >= minlevel then
            local msg_log
            local file, err = io_open( logfile, "r" )
            if file then
                -- #460: render each stored line in the current language
                -- (old baked lines pass through render_line unchanged).
                local out = { }
                for line in file:lines() do out[ #out + 1 ] = render_line( line ) end
                file:close()
                msg_log = utf_format( msg_out, table_concat( out, "\n" ) )
                user:reply( msg_log, hub_getbot, hub_getbot )
                return PROCESSED
            else
                user:reply( msg_nofile, hub_getbot )
                return PROCESSED
            end
        else
            user:reply( msg_denied, hub_getbot )
            return PROCESSED
        end
    else
        user:reply( msg_usage, hub_getbot )
        return PROCESSED
    end
end

-- Log-tail reader: returns (lines_table, total_count). This is a
-- deliberate duplicate of cmd_errors.lua's `read_log_tail` (Phase
-- 3 PR-3) to keep this plugin self-contained; if a third log-tail
-- consumer arrives, lift to core/util.lua. Returns ({}, 0) if
-- the file does not exist.
local read_log_tail = function( log_path, n )
    local file = io_open( log_path, "r" )
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

-- HTTP handler: GET /v1/log/cmd?lines=N (#82 Phase 3 PR-4).
-- Admin scope. Mirrors GET /v1/log/error (PR-3) shape:
-- {lines: [string], returned: int, total_lines: int}. Each tail line
-- is rendered in the hub's current language (#460) via the same
-- render_line as `+cmdlog show`, so the contract is unchanged (still
-- a list of display strings) but no longer frozen/mixed-language; old
-- baked lines pass through unchanged.
--
-- The ADC-side `etc_cmdlog_minlevel` check does NOT apply on the
-- HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
local http_handler_log_cmd = function( req )
    local n = tonumber( req.query and req.query.lines ) or HTTP_DEFAULT_LINES
    if n < 1 then n = HTTP_DEFAULT_LINES end
    if n > HTTP_MAX_LINES then n = HTTP_MAX_LINES end
    local lines, total = read_log_tail( logfile, n )
    for i = 1, #lines do lines[ i ] = render_line( lines[ i ] ) end
    return { status = 200, data = {
        lines       = lines,
        returned    = #lines,
        total_lines = total,
    } }
end

local hubcmd

hub.setlistener("onStart", {},
    function()
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { cmd_p }, { "CT1" }, minlevel )
        end
        hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoint (#82 Phase 3 PR-4). Read-only;
        -- admin scope (operator log, same as /v1/log/error).
        if hub.http_register then
            hub.http_register( "GET", "/v1/log/cmd", "admin", http_handler_log_cmd, {
                plugin = scriptname,
                description = "tail the command log (= ADC `+cmdlog show`); query ?lines=N (default 200, max 1000)",
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

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

---------
--[END]--
---------