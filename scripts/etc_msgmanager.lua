--[[

    etc_msgmanager.lua by pulsar

        description: this script blocks chats (main/pm) for predefined levels (check cfg/cfg.tbl)

        usage:

        [+!#]msgmanager blockmain <NICK>  -- blocks users main messages
        [+!#]msgmanager blockpm <NICK>  -- blocks users pm messages
        [+!#]msgmanager blockboth <NICK>  -- blocks users main + pm messages
        [+!#]msgmanager unblock <NICK>  -- unblock user
        [+!#]msgmanager showusers  -- show all blocked users
        [+!#]msgmanager showsettings  -- show settings from 'cfg.tbl'

        v0.12:
            - carry a chat block over to the new nick on +nickchange /
              HTTP rename. block_tbl is keyed by firstnick; a rename only
              updated user.tbl, so the block was silently dropped - an
              operator could unblock a user just by renaming them. An
              onAudit tap on reg.nickchange now re-keys block_tbl (covers
              the ADC self / othernick / othernicku paths AND the HTTP
              API). Reported by Sopor.

        v0.11:
            - resolve an online target by firstnick when a nick-prefix is
              active: usr_nick_prefix re-keys the hub's nick table to the
              PREFIXED nick, so `+msgmanager blockmain|blockpm|blockboth|unblock
              <base nick>` silently hit the "user offline" path (no
              block/unblock) on a prefixed online user. The block store
              already keys by firstnick, so only the ADC resolution was
              affected (the HTTP path keys by the {nick} path param
              directly). Same firstnick-fallback idiom as
              etc_trafficmanager (upstream luadch/luadch#240). Nick-prefix
              resolution fix.

        v0.10:
            - route the block-mode labels "main" / "pm" / "main + pm"
              through lang (msg_mode_main/pm/both); previously they
              were injected as English literals into the otherwise-
              translated msg_block / msg_report_block templates.
              Part of #301 i18n cleanup.

        v0.8:
            - HTTP API: GET /v1/msgmanager (read), POST/DELETE
              /v1/msgmanager/{nick} (admin)  #82 Phase 4 PR-5

        v0.6:
            - show blocked levels on command "showusers"
            - fix: #144

        v0.5:
            - changed visuals
            - removed table lookups
            - simplify 'activate' logic

        v0.4:
            - removed send_report() function, using report import functionality now

        v0.3:
            - check if target is a bot  / thx Kaas
            - fixed "msg_report_block"
            - fixed "msg_report_unblock"
            - fixed "msg_notonline"  / thx Sopor

        v0.2:
            - possibility to block/unblock single users from userlist  / requested by DarkDragon
            - show list of all blocked users
            - show settings
            - add new table lookups, imports, msgs
            - rewrite some parts of code

        v0.1:
            - possibility to block main chat for predefined levels
            - possibility to block pm chat for predefined levels

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_msgmanager"
local scriptversion = "0.12"

local cmd = "msgmanager"
local cmd_b1 = "blockmain"
local cmd_b2 = "blockpm"
local cmd_b3 = "blockboth"
local cmd_u = "unblock"
local cmd_su = "showusers"
local cmd_ss = "showsettings"

--// imports
local block_file = "scripts/data/etc_msgmanager.tbl"
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local activate = cfg.get( "etc_msgmanager_activate" )
local permission = cfg.get( "etc_msgmanager_permission" )
local permission_pm = cfg.get( "etc_msgmanager_permission_pm" )
local permission_main = cfg.get( "etc_msgmanager_permission_main" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "etc_msgmanager_report" )
local report_hubbot = cfg.get( "etc_msgmanager_report_hubbot" )
local report_opchat = cfg.get( "etc_msgmanager_report_opchat" )
local llevel = cfg.get( "etc_msgmanager_llevel" )

--// functions
local block_tbl
local get_blocklevels
local get_bool
local onbmsg
local is_online
local is_blocked
local find_online_by_firstnick

--// msgs
local help_title = lang.help_title or "etc_msgmanager.lua"
local help_usage = lang.help_usage or "[+!#]msgmanager showusers|showsettings|blockmain <NICK>|blockpm <NICK>|blockboth <NICK>|unblock <NICK>"
local help_desc = lang.help_desc or "Shows blocked users | show settings | block main chats | block pm chats | block both | unblock user"

local msg_denied_main = lang.msg_denied_main or "You are not allowed to write messages in main chat."
local msg_denied_pm = lang.msg_denied_pm or "You are not allowed to write private messages."
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_god = lang.msg_god or "You are not allowed to block this user."
local msg_stillblocked = lang.msg_stillblocked or "This user is already blocked."
local msg_notonline = lang.msg_notonline or "User is offline."
local msg_notfound = lang.msg_notfound or "User not found."
local msg_isbot = lang.msg_isbot or "User is a bot."
local msg_block = lang.msg_block or "[ MSGMANAGER ]--> Block user: %s  |  Mode:  %s"
local msg_unblock = lang.msg_unblock or "[ MSGMANAGER ]--> Unblock user:  %s"
local msg_report_block = lang.msg_report_block or "[ MSGMANAGER ]--> User:  %s  |  has blocked user:  %s  |  IP:  %s  |  mode:  %s"
local msg_report_unblock = lang.msg_report_unblock or "[ MSGMANAGER ]--> User:  %s  |  has unblocked user:  %s  |  IP:  %s"

-- #301 PR-3: mode display words routed through lang. The msg_block /
-- msg_report_block templates expect a mode token here; previously
-- the literal "main" / "pm" / "main + pm" was injected directly.
local msg_mode_main = lang.msg_mode_main or "main"
local msg_mode_pm   = lang.msg_mode_pm   or "pm"
local msg_mode_both = lang.msg_mode_both or "main + pm"

local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "Hub", "etc", "Message Manager", "show settings" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or { "Hub", "etc", "Message Manager", "show blocked users" }
local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Message Manager", "block", "main" }
local ucmd_menu_ct2_2 = lang.ucmd_menu_ct2_2 or { "Message Manager", "block", "pm" }
local ucmd_menu_ct2_3 = lang.ucmd_menu_ct2_3 or { "Message Manager", "block", "both" }
local ucmd_menu_ct2_4 = lang.ucmd_menu_ct2_4 or { "Message Manager", "unblock" }

local msg_usage = lang.msg_usage or [[


=== MESSAGE MANAGER ===========================================================

Usage:

    [+!#]msgmanager blockmain <NICK>  -- blocks users main messages
    [+!#]msgmanager blockpm <NICK>  -- blocks users pm messages
    [+!#]msgmanager blockboth <NICK>  -- blocks users main + pm messages
    [+!#]msgmanager unblock <NICK>  -- unblock user
    [+!#]msgmanager showusers  -- show all blocked users
    [+!#]msgmanager showsettings  -- show settings from 'cfg.tbl'

=========================================================== MESSAGE MANAGER ===
  ]]

local msg_users = lang.msg_users or [[


=== MESSAGE MANAGER ================================

Blocked MAIN levels:

%s
Blocked PM levels:

%s

Blocked users:

               Blockmode              Username
  -------------------------------------------------------------------------------------

%s
  -------------------------------------------------------------------------------------
               m = main   |   p = pm   |   b = both

================================ MESSAGE MANAGER ===
  ]]

local msg_settings = lang.msg_settings or [[


=== MESSAGE MANAGER =====================================

   Script is active:  %s

   Blocked MAIN levels:

%s
   Blocked PM levels:

%s
===================================== MESSAGE MANAGER ===
  ]]


----------
--[CODE]--
----------

if not activate then
   hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
   return
end

local oplevel = util.getlowestlevel( permission )

--// get all levelnames from blocked table in sorted order
get_blocklevels = function()
    local levels = cfg.get( "levels" ) or {}
    local msg1, msg2 = "", ""
    local tbl = {}
    local i = 1
    for k, v in pairs( permission_main ) do
        if k >= 0 then
            if not v then
                tbl[ i ] = k
                i = i + 1
            end
        end
    end
    table.sort( tbl )
    for _, level in pairs( tbl ) do
        msg1 = msg1 .. "\t" .. levels[ level ] .. "\n"
    end
    tbl = {}
    local i = 1
    for k, v in pairs( permission_pm ) do
        if k >= 0 then
            if not v then
                tbl[ i ] = k
                i = i + 1
            end
        end
    end
    table.sort( tbl )
    for _, level in pairs( tbl ) do
        msg2 = msg2 .. "\t" .. levels[ level ] .. "\n"
    end
    return msg1, msg2
end

--// returns value of a bool as string
get_bool = function( var )
    local msg = "false"
    if var then msg = "true" end
    return msg
end

-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub.isnickonline( <base
-- nick> ) returns nil for a prefixed online user and the block/unblock
-- paths would silently take the "user offline" branch. firstnick is the
-- ORIGINAL nick, captured once at login and never re-keyed, so iterating
-- it is robust against ANY nick-prefix scheme (the block store already
-- keys by firstnick). Same idiom as etc_trafficmanager's
-- find_online_by_firstnick (closed upstream luadch/luadch#240). Kept
-- plugin-local rather than changed in core hub.isnickonline, whose
-- exact-current-nick semantics back availability checks elsewhere.
-- firstnick fallback -> the shared core helper (#537 dedup).
find_online_by_firstnick = hub.find_online_by_firstnick

--// check if target user is online
is_online = function( user, target )
    local target = hub.isnickonline( target ) or find_online_by_firstnick( target )
    if target then
        if target:isbot() then
            return "bot"
        else
            return target:firstnick(), target:nick(), target:level(), target:ip()
        end
    end
    return nil
end

--// check if target user is already blocked
is_blocked = function( nick, level, mode )
    for k, v in pairs( block_tbl ) do
        if k == nick then return true end
    end
    if not permission_pm[ level ] and mode == "pm" then
        return true
    end
    if not permission_main[ level ] and mode == "main" then
        return true
    end
    return false
end

onbmsg = function( user, command, parameters )
    local user_nick = user:nick()
    local user_level = user:level()
    local target_firstnick, target_nick, target_level
    local p1 = utf.match( parameters, "^(%S+)" )
    local p2, p3 = utf.match( parameters, "^(%S+) (%S+)" )
    --// [+!#]msgmanager showsettings
    if ( p1 == cmd_ss ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local levels_main, levels_pm = get_blocklevels()
        local msg = utf.format( msg_settings, get_bool( activate ), levels_main, levels_pm )
        user:reply( msg, hub.getbot() )
        return PROCESSED
    end
    --// [+!#]msgmanager showusers
    if ( p1 == cmd_su ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local levels_main, levels_pm = get_blocklevels()
        local msg = ""
        for k, v in pairs( block_tbl ) do
            msg = msg .. "\t" .. v .. "\t\t" .. k .. "\n"
        end
        local msg_out = utf.format( msg_users, levels_main, levels_pm, msg )
        user:reply( msg_out, hub.getbot() )
        return PROCESSED
    end
    --// [+!#]msgmanager blockmain <NICK>
    if ( ( p2 == cmd_b1 ) and p3 ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target_firstnick, target_nick, target_level, target_ip = is_online( user, p3 )
        if target_firstnick then
            if target_firstnick ~= "bot" then
                if ( ( permission[ user_level ] or 0 ) < target_level ) then
                    user:reply( msg_god, hub.getbot() )
                    return PROCESSED
                end
                if not is_blocked( target_firstnick, target_level ) then
                    block_tbl[ target_firstnick ] = "m"
                    util.savetable( block_tbl, "block_tbl", block_file )
                    local msg = utf.format( msg_block, target_nick, msg_mode_main )
                    user:reply( msg, hub.getbot() )
                    msg = utf.format( msg_report_block, user_nick, target_nick, target_ip or "?", msg_mode_main )
                    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                    audit.fire( audit.build( "msgmanager.block", user,
                        { nick = target_firstnick }, nil, { mode = "main" } ) )
                    return PROCESSED
                else
                    user:reply( msg_stillblocked, hub.getbot() )
                    return PROCESSED
                end
            else
                user:reply( msg_isbot, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_notonline, hub.getbot() )
            return PROCESSED
        end
    end
    --// [+!#]msgmanager blockpm <NICK>
    if ( ( p2 == cmd_b2 ) and p3 ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target_firstnick, target_nick, target_level, target_ip = is_online( user, p3 )
        if target_firstnick then
            if target_firstnick ~= "bot" then
                if ( ( permission[ user_level ] or 0 ) < target_level ) then
                    user:reply( msg_god, hub.getbot() )
                    return PROCESSED
                end
                if not is_blocked( target_firstnick, target_level ) then
                    block_tbl[ target_firstnick ] = "p"
                    util.savetable( block_tbl, "block_tbl", block_file )
                    local msg = utf.format( msg_block, target_nick, msg_mode_pm )
                    user:reply( msg, hub.getbot() )
                    msg = utf.format( msg_report_block, user_nick, target_nick, target_ip or "?", msg_mode_pm )
                    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                    audit.fire( audit.build( "msgmanager.block", user,
                        { nick = target_firstnick }, nil, { mode = "pm" } ) )
                    return PROCESSED
                else
                    user:reply( msg_stillblocked, hub.getbot() )
                    return PROCESSED
                end
            else
                user:reply( msg_isbot, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_notonline, hub.getbot() )
            return PROCESSED
        end
    end
    --// [+!#]msgmanager blockboth <NICK>
    if ( ( p2 == cmd_b3 ) and p3 ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target_firstnick, target_nick, target_level, target_ip = is_online( user, p3 )
        if target_firstnick then
            if target_firstnick ~= "bot" then
                if ( ( permission[ user_level ] or 0 ) < target_level ) then
                    user:reply( msg_god, hub.getbot() )
                    return PROCESSED
                end
                if not is_blocked( target_firstnick, target_level ) then
                    block_tbl[ target_firstnick ] = "b"
                    util.savetable( block_tbl, "block_tbl", block_file )
                    local msg = utf.format( msg_block, target_nick, msg_mode_both )
                    user:reply( msg, hub.getbot() )
                    msg = utf.format( msg_report_block, user_nick, target_nick, target_ip or "?", msg_mode_both )
                    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                    audit.fire( audit.build( "msgmanager.block", user,
                        { nick = target_firstnick }, nil, { mode = "both" } ) )
                    return PROCESSED
                else
                    user:reply( msg_stillblocked, hub.getbot() )
                    return PROCESSED
                end
            else
                user:reply( msg_isbot, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_notonline, hub.getbot() )
            return PROCESSED
        end
    end
    --// [+!#]msgmanager unblock <NICK>
    if ( ( p2 == cmd_u ) and p3 ) then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target_firstnick, target_nick, target_level, target_ip = is_online( user, p3 )
        if target_firstnick then
            local found = false
            for k, v in pairs( block_tbl ) do
                if k == target_firstnick then
                    block_tbl[ k ] = nil
                    found = true
                    break
                end
            end
            if found then
                util.savetable( block_tbl, "block_tbl", block_file )
                local msg = utf.format( msg_unblock, target_nick )
                user:reply( msg, hub.getbot() )
                msg = utf.format( msg_report_unblock, user_nick, target_nick, target_ip or "?" )
                report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                audit.fire( audit.build( "msgmanager.unblock", user,
                    { nick = target_firstnick }, nil, nil ) )
                return PROCESSED
            else
                user:reply( msg_notfound, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_notonline, hub.getbot() )
            return PROCESSED
        end
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

--// main
hub.setlistener( "onBroadcast", { },
    function( user, adccmd, msg )
        local user_firstnick, user_level = user:firstnick(), user:level()
        local block = is_blocked( user_firstnick, user_level, "main" )
        if block then
            user:reply( msg_denied_main, hub.getbot() )
            return PROCESSED
        end
    end
)

--// pm
hub.setlistener( "onPrivateMessage", {},
    function( user, targetuser, adccmd, msg )
        local user_firstnick, user_level = user:firstnick(), user:level()
        local block= is_blocked( user_firstnick, user_level, "pm" )
        if block then
            user:reply( msg_denied_pm, hub.getbot(), targetuser )
            return PROCESSED
        end
    end
)

--// HTTP API helpers + handlers (#82 Phase 4 PR-5).

-- Map between the public API enum and the internal letter codes
-- stored in block_tbl. Internal storage stays unchanged so the
-- ADC `+msgmanager showusers` output continues to display
-- `m`/`p`/`b` letters; the HTTP surface uses readable enum
-- values instead.
local _http_mode_to_letter = { main = "m", pm = "p", both = "b" }
local _http_letter_to_mode = { m = "main", p = "pm", b = "both" }

-- Levels currently blacklisted in the cfg permission tables
-- (cfg.etc_msgmanager_permission_main / _pm). Returned sorted so
-- clients get a stable order across requests without needing to
-- sort themselves.
local _http_blocked_levels = function( permission_tbl )
    local tbl = {}
    for k, v in pairs( permission_tbl or {} ) do
        if type( k ) == "number" and k >= 0 and not v then
            tbl[ #tbl + 1 ] = k
        end
    end
    table.sort( tbl )
    return tbl
end

-- HTTP handler: GET /v1/msgmanager (#82 Phase 4 PR-5). Read scope.
-- Combined view of currently-blocked nicks + cfg settings (mirrors
-- ADC `+msgmanager showusers` + `showsettings` merged into one
-- response because operator clients want both views together).
--
-- Returns 200 with `data: {blocks: [{nick, mode}, ...],
-- settings: {activate, blocked_main_levels, blocked_pm_levels}}`.
-- `mode` is `"main"|"pm"|"both"` (HTTP enum form; internal storage
-- is `m`/`p`/`b` single letters - mapped at the boundary so the
-- API surface is readable but the persisted file format stays
-- compatible with the ADC ShowUsers display).
--
-- The ADC-side `etc_msgmanager_oplevel` gate does NOT apply on
-- the HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
-- #264 PR-B: filter/sort spec for /v1/msgmanager. Operates on the
-- formatted {nick, mode} entry shape; the `settings` sibling stays
-- outside the filter scope (it's per-hub config, not per-block).
local _msgmanager_filter_spec = {
    string_fields = {
        nick = function( e ) return e.nick or "" end,
        mode = function( e ) return e.mode or "" end,
    },
    sortable_fields = {
        nick = function( e ) return e.nick or "" end,
    },
    default_sort_field      = "nick",
    default_sort_descending = false,
}

local http_handler_list_msgmanager = function( req )
    local blocks = {}
    for nick, letter in pairs( block_tbl or {} ) do
        blocks[ #blocks + 1 ] = {
            nick = nick,
            mode = _http_letter_to_mode[ letter ] or letter,
        }
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _msgmanager_filter_spec, blocks
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = {
            blocks   = rows,
            settings = {
                activate            = activate and true or false,
                blocked_main_levels = _http_blocked_levels( permission_main ),
                blocked_pm_levels   = _http_blocked_levels( permission_pm ),
            },
        },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- HTTP handler: POST /v1/msgmanager/{nick} (#82 Phase 4 PR-5).
-- Admin scope. Adds a per-nick chat-block override to block_tbl
-- and persists. Body `{mode: "main"|"pm"|"both" required}` -
-- schema-enum-validated; missing / unknown mode returns 400.
--
-- Resolution: target nick is treated as the firstnick (stable
-- registered identifier). For HTTP we do NOT require the target
-- to be online (a divergence from the ADC `+msgmanager blockmain`
-- path which requires `hub.isnickonline`); offline registered
-- nicks can be pre-blocked so the moment they reconnect the
-- onBroadcast / onPrivateMessage filter fires. The ADC level-
-- ladder + autoblock checks do NOT apply on the HTTP path: the
-- bearer token's `admin` scope IS the authorisation gate.
--
-- Returns **409 E_CONFLICT** if the nick is already in block_tbl
-- (operator must `DELETE` first to change mode; mode-change in
-- place is intentionally not supported, matching the ADC
-- `msg_stillblocked` semantic). Returns **400 E_BAD_INPUT** for
-- empty / missing nick or invalid mode.
--
-- Response: 200 with `data: {action: "blocked", nick, mode}` per
-- §7.1.1.
local http_handler_block_user = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    local mode = body.mode
    local letter = mode and _http_mode_to_letter[ mode ]
    if not letter then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "mode must be one of 'main' | 'pm' | 'both'" } }
    end
    if block_tbl[ nick ] then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "nick '" .. nick .. "' is already blocked - DELETE first to change mode" } }
    end
    block_tbl[ nick ] = letter
    util.savetable( block_tbl, "block_tbl", block_file )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "msgmanager.block",
        { nick = actor_label, sid = "<http>" },
        { nick = nick }, nil, { mode = mode } ) )
    return { status = 200, data = {
        action = "blocked",
        nick   = nick,
        mode   = mode,
    } }
end

-- HTTP handler: DELETE /v1/msgmanager/{nick} (#82 Phase 4 PR-5).
-- Admin scope. Removes the per-nick override from block_tbl and
-- persists. Returns **404 E_NOT_FOUND** if the nick is not in
-- block_tbl (an idempotent 200 would mask typos - operator gets
-- explicit feedback that the typo'd nick was never blocked, in
-- the same spirit as the cmd_gag DELETE semantic).
--
-- Offline-tolerant (no online check) - the per-nick override is
-- a stored key, not a session attribute, so an operator can lift
-- it without the target having to be present. This diverges from
-- the ADC `+msgmanager unblock` cmd which requires the target to
-- be online (pre-existing chat-cmd UX limitation; the HTTP path
-- intentionally fixes it).
--
-- Response: 200 with `data: {action: "unblocked", nick,
-- previous_mode}` per §7.1.1; `previous_mode` is the mode the
-- entry was set to before removal so the operator's audit / undo
-- flow has the snapshot.
--
-- The ADC-side `etc_msgmanager_oplevel` gate does NOT apply on
-- the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
local http_handler_unblock_user = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local letter = block_tbl[ nick ]
    if not letter then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "nick '" .. nick .. "' is not blocked" } }
    end
    block_tbl[ nick ] = nil
    util.savetable( block_tbl, "block_tbl", block_file )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "msgmanager.unblock",
        { nick = actor_label, sid = "<http>" },
        { nick = nick }, nil,
        { previous_mode = _http_letter_to_mode[ letter ] or letter } ) )
    return { status = 200, data = {
        action        = "unblocked",
        nick          = nick,
        previous_mode = _http_letter_to_mode[ letter ] or letter,
    } }
end

--// script start
hub.setlistener( "onStart", {},
    function()
        block_tbl = util.loadtable( block_file ) or {}
        --// help, ucmd, hucmd
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct1_1, cmd, { cmd_ss }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct1_2, cmd, { cmd_su }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct2_1, cmd, { cmd_b1, "%[userNI]" }, { "CT2" }, oplevel )
            ucmd.add( ucmd_menu_ct2_2, cmd, { cmd_b2, "%[userNI]" }, { "CT2" }, oplevel )
            ucmd.add( ucmd_menu_ct2_3, cmd, { cmd_b3, "%[userNI]" }, { "CT2" }, oplevel )
            ucmd.add( ucmd_menu_ct2_4, cmd, { cmd_u,  "%[userNI]" }, { "CT2" }, oplevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, oplevel ) )
        -- HTTP API endpoints (#82 Phase 4 PR-5). Only registered
        -- when the plugin is `activate=true` (early-return at top
        -- of file already short-circuits the entire module otherwise,
        -- so this onStart never runs in that case).
        if hub.http_register then
            hub.http_register( "GET", "/v1/msgmanager", "read", http_handler_list_msgmanager, {
                plugin = scriptname,
                description = "list per-nick chat blocks + cfg blocklevel settings (= ADC `+msgmanager showusers` + `showsettings`)",
                response_schema = {
                    blocks   = { type = "array",  required = true },
                    settings = { type = "object", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/msgmanager/{nick}", "admin", http_handler_block_user, {
                plugin = scriptname,
                description = "block a nick from main / pm / both chat channels (= ADC `+msgmanager blockmain|blockpm|blockboth`)",
                request_schema = {
                    mode = { type = "string", required = true, enum = { "main", "pm", "both" } },
                },
                response_schema = {
                    action = { type = "string", required = true },
                    nick   = { type = "string", required = true },
                    mode   = { type = "string", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/msgmanager/{nick}", "admin", http_handler_unblock_user, {
                plugin = scriptname,
                description = "lift a per-nick chat block (= ADC `+msgmanager unblock`); offline-tolerant",
                response_schema = {
                    action        = { type = "string", required = true },
                    nick          = { type = "string", required = true },
                    previous_mode = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

--// keep a chat block attached to its user across a nick rename.
-- block_tbl is keyed by firstnick; +nickchange (and the HTTP rename)
-- renames the user in user.tbl but not here, so without this the block
-- was silently lost on rename (reported by Sopor). audit.fire is
-- unconditional (core/audit.lua), so one onAudit tap catches every
-- reg.nickchange - the ADC self / othernick / othernicku paths AND the
-- HTTP API. Returns nil (never PROCESSED) so the etc_auditlog /
-- http_events onAudit taps still receive the event.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        if old_nick == new_nick or block_tbl[ old_nick ] == nil then return nil end
        -- If a stale entry already sits under the new nick, the renamed
        -- user's own block wins - overwrite keeps it intact.
        block_tbl[ new_nick ] = block_tbl[ old_nick ]
        block_tbl[ old_nick ] = nil
        util.savetable( block_tbl, "block_tbl", block_file )
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--
--
-- `get_block_tbl()` exposes the in-memory blocklist to importers
-- so they can query block state on hot paths (cmd_accinfo's
-- `+accinfoop` ADC banner + `GET /v1/registered/{nick}`'s
-- msg_blocked field) without re-reading `etc_msgmanager.tbl`
-- from disk on every call. The closure captures the file-scope
-- `block_tbl` upvalue, so it transparently re-resolves after
-- the onStart `block_tbl = util.loadtable(...)` rebind that
-- fires on `+reload` (same #239-class hazard as cmd_ban's
-- exported `bans` table - a direct table reference export
-- would go stale after the rebind; the function getter does
-- not). Closes #238.
return {
    get_block_tbl = function() return block_tbl end,

    -- Internal test seams (nick-prefix resolution regression). `_`-prefixed
    -- per the repo convention for non-contract, test-only exports (see
    -- docs/PLUGIN_API.md §8); NOT part of the hub.import("etc_msgmanager")
    -- contract.
    _onbmsg                   = onbmsg,
    _is_online                = is_online,
    _find_online_by_firstnick = find_online_by_firstnick,
}