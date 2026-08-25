--[[

    etc_chatlog.lua by Motnahp

        v1.7:
            - extract record_line() helper (build + trim + persist) shared by the
              onBroadcast listener and a new exported log_line()
            - export log_line(nick, message) so hub-originated main-chat posts (which
              do not fire onBroadcast) can be recorded - used by cmd_talk for the
              hubbot's +talk / POST /v1/chat posts  (webui#177 A)

        v1.6:
            - HTTP API: GET /v1/chatlog?lines=N (read scope)  #82 Phase 4 PR-1
            - extract get_log_tail() helper shared by ADC + HTTP paths

        1.51: by Sopor
            - fix for: etc_chatlog.lua:299: bad argument #1 to 'byte' (string expected, got nil) (listener: onBroadcast; script: 'etc_chatlog.lua')

        v1.5: by pulsar
            - suppresses the output if there are no entries
            - changed some visuals

        v1.4: by pulsar
            - better command check
                - fix: #162 -> https://github.com/luadch/luadch/issues/162
            - removed "max_characters" functionality from code
                - fix: #62 -> https://github.com/luadch/luadch/issues/62
                - fix: #158 -> https://github.com/luadch/luadch/issues/158

        v1.3: by pulsar
            - set "saveit" to 1
            - changed visuals

        v1.2: by pulsar
            - removed table lookups
            - prevent users who do not have the permission to chat in the main (etc_msgmanager_permission_main) not to be logged

        v1.1: by pulsar
            - fix #62 / thx Sopor
                - added "max_characters" for default amount of characters for each post at Login

        v1.0: by pulsar
            - fix missing permission check in "onLogin" listener  / thx Sopor

        v0.9: by pulsar
            - removed "etc_chatlog_min_level" import
                - using util.getlowestlevel( tbl ) instead of "etc_chatlog_min_level"

        v0.8: by pulsar
            - change date style
            - remove dateparser() function

        v0.7: by Motnahp
            - fix permission vars

        v0.6: by pulsar
            - changed visual output style

        v0.5: by pulsar
            - changed visual output style

        v0.4: by pulsar
            - add lang feature
            - code cleaning
            - table lookups
            - export scriptsettings to "cfg/cfg.tbl"

        v0.3: by Motnahp
            - changed save methode -> no more (failed) commands will be logged

        v0.2: by Motnahp
            - cleanup and improved performance

        v0.1: by Motnahp
            - logs mainchat to table
            - logs exceptions, because not everyone wants to see chathistory on login
            - adds commands [+!#]history [show|toggle|reset_t_logs|reset_t_exceptions|showexceptions]
                > explained in Settings > help msgs >
            - adds help for commands
            - adds ucmd

]]--


--[[ Settings ]]--

local scriptname = "etc_chatlog"
local scriptversion = "1.7"

-- HTTP API §6.4 tail-style ceiling. The §6.4 list-endpoint cap
-- is 1000, but for chatlog the effective bound is also the
-- in-memory buffer size which the onBroadcast trim loop keeps
-- equal to `cfg etc_chatlog_max_lines` (default 200). The HTTP
-- handler picks `min(cfg.etc_chatlog_max_lines, 1000)` so the
-- §6.4 ceiling acts as an upper bound for operators who raised
-- the cfg above 1000.
local HTTP_MAX_LINES = 1000

local cmd = "history"

-- cmd parameters --
local prm1 = "show"
local prm2 = "toggle"
local prm3 = "reset_t_logs"
local prm4 = "reset_t_exceptions"
local prm5 = "showexceptions"

-- permissions --
local min_level_adv = cfg.get( "etc_chatlog_min_level_adv" )
local permission = cfg.get( "etc_chatlog_permission" )
local max_lines = cfg.get( "etc_chatlog_max_lines" )
local default_lines = cfg.get( "etc_chatlog_default_lines" )

--// imports
local hubcmd, help

--// local tabels and storage paths --
local exceptions_path = "scripts/data/etc_chatlog_exceptions.tbl"
local log_path = "scripts/data/etc_chatlog_log.tbl"
local t_exceptions = util.loadtable( exceptions_path ) or { }  -- load the exceptions
local t_log = util.loadtable( log_path ) or { }  -- load the log
local msgmanager_permission = cfg.get( "etc_msgmanager_permission_main" )

--// functions
local buildlog
local show_t_exceptions

--// variables
local savehistory = 0
local saveit = 1  -- chat arrivals to save t_log

local scriptlang = cfg.get "language"
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )

--// msgs
local help_title = "etc_chatlog.lua - Users"  -- for regs
local help_usage = lang.help_usage or "[+!#]history show [<lines>] und [+!#]history toggle"
local help_desc = lang.help_desc or "Shows the last written messages in mainchat, you can toggle it on/off."

local help_titleo = "etc_chatlog.lua - Owners"  -- for owner
local help_usageo = lang.help_usageo or "[+!#]history [reset_t_logs|reset_t_exceptions]  / or: [+!#]history showexceptions"
local help_desco = lang.help_desco or "Delete Chatlog / or: delete list of deniers."

local msg_denied = lang.msg_denied or "[ CHATLOG ]--> You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]history show [<lines>] und [+!#]history toggle"
local msg_leave = lang.msg_leave or "[ CHATLOG ]--> Chatlog mode: off"
local msg_join = lang.msg_join or "[ CHATLOG ]--> Chatlog mode: on"
local msg_del_log = lang.msg_del_log or "[ CHATLOG ]--> Chatlog was cleaned."
local msg_del_exceptions = lang.msg_del_exceptions or "[ CHATLOG ]--> List of Chatlog-deniers was cleaned."  -- debug
local msg_intro = lang.msg_intro or "The last  %s  post(s):"
local msg_deniers = lang.msg_deniers or "\nList of Chatlog-deniers:"
local msg_empty = lang.msg_empty or "[ CHATLOG ]--> No entry"

local ucmd_menu_show = lang.ucmd_menu_show or { "Hub", "etc", "Chatlog", "show" }  -- reg
local ucmd_menu_toggle = lang.ucmd_menu_toggle or { "Hub", "etc", "Chatlog", "Mode", "on\\off" }  -- reg
local ucmd_menu_reset_t_log = lang.ucmd_menu_reset_t_log or { "Hub", "etc", "Chatlog", "Admin", "clean Chatlog" }  -- owner
local ucmd_menu_showexceptions = lang.ucmd_menu_showexceptions or { "Hub", "etc", "Chatlog", "Admin", "show Chatlog-deniers" }  -- owner
local ucmd_menu_reset_t_exceptions = lang.ucmd_menu_reset_t_exceptions or { "Hub", "etc", "Chatlog", "Admin", "clean Chatlog-deniers" }  -- owner
local ucmd_popup = lang.ucmd_popup or "How many posts?"

local logo_1 = lang.logo_1 or [[


=== CHATLOG =====================================================================================
%s
   ]]

local logo_2 = lang.logo_2 or [[

===================================================================================== CHATLOG ===
  ]]


--[[   Code   ]]--

local min_level = util.getlowestlevel( permission )

local tbl_is_empty = function( tbl )
    if next( tbl ) == nil then return true else return false end
end

local onbmsg = function( user, adccmd, parameters )
    local local_prms = parameters.." "
    local user_level = user:level( )
    local id, amount = utf.match( local_prms, "^(%S+) (.*)" )
    amount = utf.match( local_prms, "^%S+ ([-]?%d+)" )
    if not amount then
        amount = default_lines
    else
        amount = tonumber(amount)
    end
    if id == prm1 then  -- show
        if user_level >= min_level then
            if not tbl_is_empty( t_log ) then
                user:reply( buildlog( amount, false ), hub.getbot() )
            else
                user:reply( msg_empty, hub.getbot() )
            end
        else
            user:reply( msg_denied, hub.getbot())
        end
        return PROCESSED
    end

    if id == prm2 then  -- toggle
        local inlist, nick, cid, hash = false, user:nick( ), user:cid( ), user:hash( )
        if permission[ user_level ]  then
            local key, except
            for i, excepttbl in ipairs( t_exceptions ) do  -- is user in t_exceptions?
                key = i
                except = excepttbl
                if except.nick == nick then
                    inlist = true  -- to check if he is in the list and want to leave
                    break
                elseif except.cid == cid and except.hash == hash then
                    inlist = true  -- to check if he is in the list and want to leave
                    break
                end
            end
            if inlist then  -- to check if he is in the list yet, if yes remove him of t_exceptions
                table.remove( t_exceptions, key )
                util.savearray( t_exceptions, exceptions_path )
                user:reply( msg_join, hub.getbot() )
            else  -- if not add him to t_exceptions
                t_exceptions[ #t_exceptions + 1 ] = {
                    nick = user:nick( ),
                    cid = user:cid( ),
                    hash = user:hash( )
                }
                util.savearray( t_exceptions, exceptions_path )
                user:reply( msg_leave, hub.getbot() )
            end
            return PROCESSED
        else
            user:reply( msg_denied, hub.getbot() )
        end
    end

    if id == prm3 then  -- reset t_log
        if user_level >= min_level_adv then  -- owners only
            t_log = { }
            util.savearray( t_log, log_path )
            user:reply( msg_del_log, hub.getbot() )
        else
            user:reply( msg_denied, hub.getbot() )
        end
        return PROCESSED
    end

    if id == prm4 then  -- reset t_exceptions
        if user_level >= min_level_adv then  -- owners only
            t_exceptions = { }
            util.savearray( t_exceptions, exceptions_path )
            user:reply( msg_del_exceptions, hub.getbot() )
        else
            user:reply( msg_denied, hub.getbot() )
        end
        return PROCESSED
    end

    if id == prm5 then  -- show t_exceptions
        if user_level >= min_level_adv then  -- owners only
            user:reply( show_t_exceptions( ), hub.getbot() )
        else
            user:reply( msg_denied, hub.getbot() )
        end
        return PROCESSED
    end

    user:reply( msg_usage, hub.getbot() )  -- if no id hittes
    return PROCESSED
end

-- Shared chatlog-tail reader used by BOTH the ADC `+history show`
-- chat-cmd path (via buildlog() below) AND the HTTP `GET /v1/chatlog`
-- path (#82 Phase 4 PR-1). Returns the last `n` entries from `t_log`
-- as structured rows; `total` is the number of entries currently in
-- the log buffer.
--
-- Invariant relied on by callers: `#t_log <= max_lines` (enforced
-- by the onBroadcast trim loop below). The HTTP handler picks its
-- own `hard_cap` against `max_lines`; this function only clamps
-- against the live buffer size.
local get_log_tail = function( n )
    local total = #t_log
    if n < 0 then n = 0 end
    if n > total then n = total end
    local out = { }
    local start = total - n + 1
    for i = start, total do
        local entry = t_log[ i ]
        if entry then
            out[ #out + 1 ] = {
                timestamp = entry[ 1 ] or "",
                nick      = entry[ 2 ] or "",
                message   = entry[ 3 ] or "",
            }
        end
    end
    return out, total
end

-- HTTP handler: GET /v1/chatlog?lines=N (#82 Phase 4 PR-1).
-- Read scope. Returns the last N entries (default = cfg
-- `etc_chatlog_default_lines`, capped at min(cfg
-- `etc_chatlog_max_lines`, HTTP_MAX_LINES=1000) per §6.4 tail-style
-- cap). Non-numeric or out-of-range `lines` values are clamped to
-- the default rather than rejected, consistent with §6.4. Returns
-- 200 + empty `lines` array if no chatlog entries have been
-- recorded yet (matches the ADC path's empty-log semantic without
-- surfacing a 404).
--
-- Each entry carries the raw stored timestamp string
-- `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s
-- persistence format, not ISO 8601; clients that need ISO can
-- parse it). `message` is already `hub.escapefrom`-decoded by the
-- onBroadcast listener so it is plain UTF-8 text, not ADC wire.
--
-- The ADC-side `etc_chatlog_permission` level table + the
-- per-user exception opt-out do NOT apply on the HTTP path: the
-- bearer token's `read` scope IS the authorisation gate. The
-- exception-list mechanism is for chat-side users opting out of
-- the join-time banner reroll; an operator with an API token is
-- expected to see the full history.
local http_handler_chatlog = function( req )
    local hard_cap = max_lines
    if hard_cap > HTTP_MAX_LINES then hard_cap = HTTP_MAX_LINES end
    local n = tonumber( req.query and req.query.lines ) or default_lines
    if n < 1 then n = default_lines end
    if n > hard_cap then n = hard_cap end
    local lines, total = get_log_tail( n )
    return { status = 200, data = {
        lines       = lines,
        returned    = #lines,
        total_lines = total,
    } }
end

hub.setlistener( "onStart", { },
    function( )
        local help = hub.import "cmd_help"
        if help then
            help.reg( help_title, help_usage, help_desc, min_level )  -- reg help
            help.reg( help_titleo, help_usageo, help_desco, min_level_adv )  -- owner help
        end
        local ucmd = hub.import "etc_usercommands"  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu_show, cmd, { prm1, "%[line:" .. ucmd_popup .. " (max." .. max_lines .. ")" .. "]"}, { "CT1" }, min_level )  -- show
            ucmd.add( ucmd_menu_toggle, cmd, { prm2 }, { "CT1" }, min_level )  -- toggle
            ucmd.add( ucmd_menu_reset_t_log, cmd, { prm3 }, { "CT1" }, min_level_adv )  -- reset t_log
            ucmd.add( ucmd_menu_showexceptions, cmd, { prm5 }, { "CT1" }, min_level_adv )  -- shows t_exception
            ucmd.add( ucmd_menu_reset_t_exceptions, cmd, { prm4 }, { "CT1" }, min_level_adv )  -- reset t_exceptions
        end
        hubcmd = hub.import "etc_hubcommands"  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, min_level ) )
        -- HTTP API endpoint (#82 Phase 4 PR-1). Read-only; `read`
        -- scope per spec §10.2.
        if hub.http_register then
            hub.http_register( "GET", "/v1/chatlog", "read", http_handler_chatlog, {
                plugin = scriptname,
                description = "tail the main-chat history (= ADC `+history show`); query ?lines=N (default cfg etc_chatlog_default_lines, max 1000 / cfg etc_chatlog_max_lines)",
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

hub.setlistener( "onLogin", { },
    function( user, nick )
        local allows, nick, cid, hash = true, user:nick( ), user:cid( ), user:hash( )
        local key
        if permission[ user:level() ] then
            for i, excepttbl in ipairs( t_exceptions ) do  -- is user in t_exception ?
                if excepttbl.nick == nick then
                    allows = false  -- does the user want to read the chatlog?
                    break
                elseif excepttbl.cid == cid and excepttbl.hash == hash then
                    allows = false  -- does the user want to read the chatlog?
                    break
                end
            end
            if allows and ( not tbl_is_empty( t_log ) ) then
                user:reply( buildlog( default_lines, true ), hub.getbot() )
            end
        end
        return nil
    end
)

-- Append one line to the chat-log buffer: build the entry, trim to
-- max_lines, persist every `saveit` arrivals. Shared by the
-- onBroadcast listener below AND the exported `log_line`, so
-- hub-originated main-chat posts (which do NOT fire onBroadcast) can
-- still be recorded. Callers do their own gating.
local record_line = function( nick, message )
    savehistory = savehistory + 1  -- increment savehistory to save if it reaches saveit
    local t = {  -- build table
        [1] = os.date( "%Y-%m-%d / %H:%M:%S" ),
        [2] = nick,
        [3] = message
    }
    table.insert( t_log, t )  -- add table to t_log
    for x = 1, #t_log -  max_lines do  -- remove an item of t_log it there are to many items in
        table.remove( t_log, 1 )
    end
    if savehistory >= saveit then  -- save t_log and set savehistory 0
        savehistory = 0
        util.savearray( t_log, log_path )
    end
end

-- Exported: record a main-chat line originating from another plugin.
-- cmd_talk uses it for the hubbot's `+talk` / `POST /v1/chat` posts,
-- which go out via hub.broadcast and therefore never fire
-- onBroadcast - without this they would be absent from the log and
-- the GET /v1/chatlog feed. Bypasses the onBroadcast gating on
-- purpose (the hubbot is not subject to chat filters). No-op on bad
-- input.
local log_line = function( nick, message )
    if type( nick ) ~= "string" or type( message ) ~= "string" then return end
    record_line( util.strip_control_bytes( nick ), util.strip_control_bytes( message ) )
end

hub.setlistener( "onBroadcast", { },
    function( user, adccmd, msg)
        local data = hub.escapefrom(adccmd[6]) -- get current mainchat message, don't use 'msg'; reason: mainchat message might be changed by another script in the meantime
        local msg = string.match( msg, "^%s*(.*)" ) -- this pattern will generate an error ^%s*(.*%S) so i have changed it 2022-12-11
        local result = string.byte( msg, 1 )
        if msgmanager_permission[ user:level() ] and result ~= 33 and result ~= 35 and result ~= 43 then  -- in ASCII (decimal): 33 = "!"; 35 = "#"; 43 = "+"
            record_line( user:nick( ), data )
        end
    end
)

hub.setlistener( "onExit", { },
    function( )  -- save both tables
        util.savearray( t_log, log_path )
        util.savearray( t_exceptions, exceptions_path )
    end
)

buildlog = function( amount_lines, login )  -- builds the logmsg
    local amount = ( amount_lines or default_lines )
    if amount >= max_lines then  -- make sure nobody lets it "spam"
        amount = max_lines
    end
    local log_msg = "\n"
    local lines_msg = ""
    -- set variables for loop
    local x = amount
    if amount > #t_log then  -- makes sure it doesn't send more as it got
        x,amount = #t_log,#t_log
    end
    x = #t_log - x

    for i,v in ipairs( t_log ) do  -- loop thru the table
        if i > x then   -- makes sure it doesn't send more than you want
            if login then
                log_msg = log_msg .. " [ " .. v[ 1 ] .. " ] <" .. v[ 2 ] .. "> " .. v[ 3 ] .. "\n"  -- for msg at login
            else
                log_msg = log_msg .. "[" .. i .. "] - [ " .. v[ 1 ] .. " ] <" .. v[ 2 ] .. "> " .. v[ 3 ] .. "\n"  -- for msg at cmd
            end
        end
    end
    lines_msg = utf.format( msg_intro, amount )  -- adds amount into 'header'
    --log_msg = utf.format( logo_1, lines_msg ) .. log_msg .. logo_2  --  combines 'header' and logos with history
    log_msg = lines_msg .. "\n" .. log_msg

    return log_msg
end

show_t_exceptions = function ( )  -- returns t_exceptions
    local msg = ""
    for i, excepttbl in ipairs( t_exceptions ) do
        msg = msg.."\n\t\t\t\t\t  " .. ( excepttbl.nick or "-nobody-" )
    end
    return utf.format( logo_1, msg_deniers ) .. msg .. logo_2
end

hub.debug( "** Loaded " .. scriptname .. ".lua **" )

-- Exported module (webui#177 A): `log_line` lets cmd_talk mirror the
-- hubbot's main-chat posts into the log. The `_`-prefixed entries are
-- unit-test hooks only.
return {
    log_line      = log_line,
    _record_line  = record_line,
    _get_log_tail = get_log_tail,
    _t_log        = t_log,
}

--[[   End    ]]--
