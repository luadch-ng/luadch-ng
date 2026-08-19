--[[

    cmd_accinfo.lua by blastbeat

        - this script adds a command "accinfo" get infos about a reguser
        - usage: [+!#]accinfo sid|nick <SID>|<NICK> / [+!#]accinfoop sid|nick <SID>|<NICK>

        v0.37: by Aybo
            - add the `show_reguser_password` cfg toggle (shared with
              cmd_usersearch, default false). When an operator sets it
              true, +accinfo / +accinfoop show the reguser's stored
              password again instead of "<REDACTED>" - the pre-v0.32
              behaviour, now opt-in. Default keeps the #95 redaction
              (no password copied into client-side chat logs); the
              per-user hierarchy gate and the password-free HTTP surface
              are unchanged. Requested by hub operators who need to tell
              a user their forgotten password (many older users cannot
              self-reset). See docs/SECURITY.md for the tradeoff.

        v0.36:
            - permanent-ban awareness on the HTTP surface (#444): the
              GET /v1/registered/{nick} `ban` object now carries
              `permanent` and, for a permanent ban, omits
              `remaining_seconds` / `expires_at` (time_seconds 0) - the
              same shape cmd_ban's GET /v1/bans emits, so both endpoints
              describe the same ban identically. The ADC `+accinfo`
              display already rendered a permanent ban as msg_forever
              ("forever" / "dauerhaft") and is unchanged.

        v0.35:
            - route the msgmanager block-mode labels "Main" / "PM" /
              "Main + PM" through lang (msg_mode_main/pm/both).
              Part of #301 i18n cleanup.

        v0.34:
            - #238 hot-path: replace `util.loadtable( msgmanager_file )`
              in both the ADC `+accinfoop` (get_msgmanager) and HTTP
              `GET /v1/registered/{nick}` (http_format_msgblock) helpers
              with the live in-memory blocklist exposed by
              etc_msgmanager v0.7's `get_block_tbl()` getter. Avoids
              a synchronous disk read on every accinfo-style request.
              Behaviour identical; perf-only. Fallback to loadtable
              kept if etc_msgmanager is not loaded (matches the
              existing `if msgmanager_activate then` gate).

        v0.33:
            - HTTP API (#82 registered-users family PR-2, #236):
                - GET /v1/registered/{nick}   (read; expanded view = ADC `+accinfoop`)
            - Coexist with ADC `+accinfo` / `+accinfoop`; ADC paths unchanged.

        v0.32: by Aybo
            - redact the password column in both output formats. The
              hub stores ADC passwords as cleartext-equivalent (HPAS
              challenge-response is protocol-mandated; F-AUTH-1) so
              echoing them back through chat / PM puts copies into
              client-side chat logs unnecessarily. Admins who genuinely
              need to know a registered user's password should reset
              it via +setpass instead of reading it from accinfo.
              Sub-task of #95.

        v0.31: by pulsar
            - added "hub_email" to output msg
                - request by Sopor / fix #185 -> https://github.com/luadch/luadch/issues/185

        v0.30: by pulsar
            - added "years" to util.formatseconds
                - changed get_bantime()

        v0.29: by pulsar
            - fix #141 -> https://github.com/luadch/luadch/issues/141

        v0.28: by pulsar
            - changed visuals

        v0.27: by pulsar
            - added tcp_ports_ipv6, ssl_ports_ipv6
            - changed visuals
            - hide port 0 addys  / thx Sopor

        v0.26: by pulsar
            - get "search_flag_blocked" from "cfg/cfg.tbl"
            - removed "search_flag_blocked" from language files
            - changed visuals

        v0.25: by pulsar
            - changed msg_god / thx Sopor

        v0.24: by pulsar
            - using lastseen instead of lastlogout
            - clean code

        v0.23: by pulsar
            - removed table lookups
            - shows expanded accinfo as default (op level)
            - fix #31 / thx Sopor
                - shows if user is banned or not

        v0.22: by pulsar
            - fix #107 / thx Sopor
                - shows if the user is blocked by trafficmanager/msgmanager

        v0.21: by pulsar
            - removed "by CID" (Easy cleanup of codebase milestone)

        v0.20: by pulsar
            - fix small bug  / thx Night & WitchHunter
            - small improvements with output msg  / thx Sopor

        v0.19: by pulsar
            - fix small bug for unreg users in "onBroadcast" listener

        v0.18: by pulsar
            - add additional cmd and ucmd's for oplevel to show accinfo with user comment

        v0.17: by pulsar
            - show reg description if exists

        v0.16: by pulsar
            - fix problem with "profile.is_online"

        v0.15: by pulsar
            - removed "cmd_accinfo_minlevel" import
            - removed "cmd_accinfo_oplevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_accinfo_oplevel"

        v0.14: by pulsar
            - using new luadch date style

        v0.13: by pulsar
            - add new minlevel definition

        v0.12: by pulsar
            - improved method to read lastlogout
            - removed lastconnect info (uninteresting)

        v0.11: by pulsar
            - fix problem with utf.match  / thx Kungen

        v0.10: by pulsar
            - added lastlogout info
            - rewrite some parts of the code

        v0.09: by pulsar
            - typo fix in lang var  / thx jrock
            - caching new table lookups
            - change output msg if param is missing  / thx Motnahp

        v0.08: by pulsar
            - possibility to toggle advanced ct2 rightclick (shows complete userlist)
                - export var to "cfg/cfg.tbl"

        v0.07: by pulsar
            - Last user connect:
                - check if user is online and if send info instead of time
                - check if user never been logged
            - caching some new table lookups
            - sort some parts of code

        v0.06: by pulsar
            - added Last user connect to output  / thx fly out to Kungen for the idea

        v0.05: by pulsar
            - fix rightclick permissions
            - removed CID from output
            - added levelname to output
            - changed visual output style

        v0.04: by pulsar
            - changed rightclick style

        v0.03: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.02: by pulsar
            - added: show hubname + address + keyprint (if active)

        v0.01: by blastbeat

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_accinfo"
local scriptversion = "0.37"

local cmd = "accinfo"
local cmd2 = "accinfoop"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local permission = cfg.get( "cmd_accinfo_permission" )
local tcp = cfg.get( "tcp_ports" )
local ssl = cfg.get( "ssl_ports" )
local tcp_ipv6 = cfg.get( "tcp_ports_ipv6" )
local ssl_ipv6 = cfg.get( "ssl_ports_ipv6" )
local host = cfg.get( "hub_hostaddress" )
local hname = cfg.get( "hub_name" )
local hmail = cfg.get( "hub_email" )
local use_keyprint = cfg.get( "use_keyprint" )
local keyprint_type = cfg.get( "keyprint_type" )
local keyprint_hash = cfg.get( "keyprint_hash" )
local advanced_rc = cfg.get( "cmd_accinfo_advanced_rc" )
local show_password = cfg.get( "show_reguser_password" )
local msgmanager_activate = cfg.get( "etc_msgmanager_activate" )
local trafficmanager_activate = cfg.get( "etc_trafficmanager_activate" )
local ban = hub.import( "cmd_ban")
local bans_tbl = ban.bans
local search_flag_blocked = cfg.get( "etc_trafficmanager_flag_blocked" )

-- #238: hot-path msgmanager lookup uses etc_msgmanager's live
-- in-memory blocklist via the v0.7 `get_block_tbl()` getter
-- instead of `util.loadtable( msgmanager_file )` on every call.
-- A function-based getter (not a direct table reference) is
-- required because etc_msgmanager's `block_tbl = util.loadtable(...)`
-- runs on every onStart - i.e. on every `+reload` - and a direct
-- export would go stale (same #239-class hazard as cmd_ban's
-- `bans`). `msgmgr_module` is `nil` if etc_msgmanager isn't
-- whitelisted in cfg.scripts; both helpers fall back to the
-- disk-load path in that case (also matches the
-- `if msgmanager_activate then` gate the helpers already guard
-- on).
local msgmgr_module = hub.import( "etc_msgmanager" )
local msgmgr_get_block_tbl = msgmgr_module and msgmgr_module.get_block_tbl

--// msgs
local help_title = "cmd_accinfo.lua - Users"
local help_usage = lang.help_usage or "[+!#]accinfo sid|nick|cid <SID>|<NICK>"
local help_desc = lang.help_desc or "Sends accinfo about a reguser by SID or NICK; no arguments -> about yourself"

local help_title2 = "cmd_accinfo.lua - Operators"
local help_usage2 = lang.help_usage2 or "[+!#]accinfoop sid|nick <SID>|<NICK>"
local help_desc2 = lang.help_desc2 or "Sends accinfo (expanded) about a reguser by SID or NICK; no arguments -> about yourself"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or  "Usage: [+!#]accinfo sid|nick <SID>|<NICK> / [+!#]accinfoop sid|nick <SID>|<NICK>"
local msg_off = lang.msg_off or "[ ACCINFO ]--> User not found/regged."
local msg_god = lang.msg_god or "You are not allowed to view the accinfo from this user"
local msg_years = lang.msg_years or " years, "
local msg_days = lang.msg_days or " days, "
local msg_hours = lang.msg_hours or " hours, "
local msg_minutes = lang.msg_minutes or " minutes, "
local msg_seconds = lang.msg_seconds or " seconds"
local msg_unknown = lang.msg_unknown or "<UNKNOWN>"
local msg_redacted = lang.msg_redacted or "<REDACTED>"
local msg_online = lang.msg_online or "user is online"
local msg_keyprint = lang.msg_keyprint or "  (with Keyprint)"
local msg_accinfo = lang.msg_accinfo or [[


=== ACCINFO ==================================================================================================================

    Nickname: %s
    Password: %s

    Level: %s  [ %s ]

    Regged by: %s
    Regged since: %s
    Comment: %s

    Last seen: %s

    Traffic blocked: %s
    Messages blocked: %s
    Nickname is banned: %s

    Hubname: %s
    Hubmail: %s

    Hubaddress: %s
================================================================================================================== ACCINFO ===

   ]]

local msg_accinfo2 = lang.msg_accinfo2 or [[


=== ACCINFO ==================================================================================================================

    Nickname: %s
    Password: %s

    Level: %s  [ %s ]

    Regged by: %s
    Regged since: %s

    Last seen: %s

    Hubname: %s
    Hubmail: %s

    Hubaddress: %s
================================================================================================================== ACCINFO ===

   ]]

local ucmd_nick = lang.ucmd_nick or "Nick:"

local ucmd_menu_ct0 = lang.ucmd_menu_ct0 or { "About You", "show Accinfo" }
local ucmd_menu_ct4 = lang.ucmd_menu_ct4 or "User"
local ucmd_menu_ct5 = lang.ucmd_menu_ct5 or "Accinfo"
local ucmd_menu_ct6 = lang.ucmd_menu_ct6 or "by Nick from List"

local ucmd_menu_ct1_op = lang.ucmd_menu_ct1_op or { "User", "Accinfo" }
local ucmd_menu_ct3_op = lang.ucmd_menu_ct3_op or { "Show", "Accinfo" }
local ucmd_menu_ct4_op = lang.ucmd_menu_ct4_op or "User"
local ucmd_menu_ct5_op = lang.ucmd_menu_ct5_op or "Accinfo"
local ucmd_menu_ct6_op = lang.ucmd_menu_ct6_op or "by Nick from List"

local msg_msgmanager = lang.msg_msgmanager or "%s %s"
local msg_msgmanager_1 = lang.msg_msgmanager_1 or "YES / Blockmode: "
local msg_msgmanager_2 = lang.msg_msgmanager_2 or "NO"
-- #301 PR-3: mode display names routed through lang (Main / PM /
-- Main + PM are DC jargon and STAY english per the don't-germanize
-- guardrail, but uniform-coverage means they go through lang.X).
local msg_mode_main = lang.msg_mode_main or "Main"
local msg_mode_pm   = lang.msg_mode_pm   or "PM"
local msg_mode_both = lang.msg_mode_both or "Main + PM"

local msg_trafficmanager_1 = lang.msg_trafficmanager_1 or "YES"
local msg_trafficmanager_2 = lang.msg_trafficmanager_2 or "NO"
local msg_bans_yes = lang.msg_bans_yes or "YES / banned by: %s / bantime remaining: %s"
local msg_bans_no = lang.msg_bans_no or "NO"
local msg_forever = lang.msg_forever or "forever"

--// database
local description_file = "scripts/data/cmd_reg_descriptions.tbl"
local msgmanager_file = "scripts/data/etc_msgmanager.tbl"


----------
--[CODE]--
----------

local addy = "\n"

local tbl_isEmpty = function( tbl )
    if next( tbl ) == nil then return true else return false end
end

local get_keyprint = function( str )
    if use_keyprint then
        return "\n\t" .. str .. keyprint_type .. keyprint_hash .. msg_keyprint .. "\n"
    else
        return "\n"
    end
end

--// tcp_ports
if not tbl_isEmpty( tcp ) and ( tcp[ 1 ] > 0 ) then
    addy = addy .. "\n\t[ IPv4 ]\n\n"
    if #tcp > 1 then
        for i, port in ipairs( tcp ) do
            addy = addy .. "\tadc://" .. host .. ":" .. port .. "\n"
        end
    else
        addy = addy .. "\tadc://" .. host .. ":" .. tcp[ 1 ] .. "\n"
    end
end
--// ssl_ports
if not tbl_isEmpty( ssl ) and ( ssl[ 1 ] > 0 ) then
    if #ssl > 1 then
        addy = addy .. "\n\t[ IPv4 SSL ]\n\n"
        for i, port in ipairs( ssl ) do
            addy = addy .. "\tadcs://" .. host .. ":" .. port .. get_keyprint( "adcs://" .. host .. ":" .. port )
        end
    else
        addy = addy .. "\n\t[ IPv4 SSL ]\n\n"
        addy = addy .. "\tadcs://" .. host .. ":" .. ssl[ 1 ] .. get_keyprint( "adcs://" .. host .. ":" .. ssl[ 1 ] )
    end
end
--// tcp_ports_ipv6
if not tbl_isEmpty( tcp_ipv6 ) and ( tcp_ipv6[ 1 ] > 0 ) then
    addy = addy .. "\n\t[ IPv6 ]\n\n"
    if #tcp_ipv6 > 1 then
        for i, port in ipairs( tcp_ipv6 ) do
            addy = addy .. "\tadc://" .. host .. ":" .. port .. "\n"
        end
    else
        addy = addy .. "\tadc://" .. host .. ":" .. tcp_ipv6[ 1 ] .. "\n"
    end
end
--// ssl_ports_ipv6
if not tbl_isEmpty( ssl_ipv6 ) and ( ssl_ipv6[ 1 ] > 0 ) then
    if #ssl_ipv6 > 1 then
        addy = addy .. "\n\t[ IPv6 SSL ]\n\n"
        for i, port in ipairs( ssl_ipv6 ) do
            addy = addy .. "\tadcs://" .. host .. ":" .. port .. get_keyprint( "adcs://" .. host .. ":" .. port )
        end
    else
        addy = addy .. "\n\t[ IPv6 SSL ]\n\n"
        addy = addy .. "\tadcs://" .. host .. ":" .. ssl_ipv6[ 1 ] .. get_keyprint( "adcs://" .. host .. ":" .. ssl_ipv6[ 1 ] )
    end
end

local get_lastseen = function( profile )
    local lastseen
    local ll = profile.lastseen
    local found = false
    for sid, user in pairs( hub.getusers() ) do
        if user:firstnick() == profile.nick then found = true break end
    end
    if found then
        lastseen = msg_online
    elseif ll then
        local sec, y, d, h, m, s = util.difftime( util.date(), ll )
        lastseen = y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    else
        lastseen = msg_unknown
    end
    return lastseen
end

local get_regdescription = function( profile )
    local description_tbl = util.loadtable( description_file ) or {}
    local desc = ""
    for k, v in pairs( description_tbl ) do
        if k == profile.nick then
            desc = v[ "tReason" ]
            break
        end
    end
    return desc
end

local get_trafficmanager = function( profile )
    if trafficmanager_activate then
        local isBlocked = false
        for sid, user in pairs( hub.getusers() ) do
            if profile.nick == user:firstnick() then
                local desc = user:description() or ""
                local isBlocked, b = string.find( desc, search_flag_blocked, 1, true )
                if isBlocked then return msg_trafficmanager_1 end
            end
        end
    end
    return msg_trafficmanager_2
end

local get_msgmanager = function( profile )
    if msgmanager_activate then
        -- #238: in-memory getter if available, disk loadtable
        -- as a guarded fallback (etc_msgmanager not loaded).
        local msgmanager_tbl = ( msgmgr_get_block_tbl and msgmgr_get_block_tbl() )
                               or util.loadtable( msgmanager_file )
                               or {}
        local info = msgmanager_tbl[ profile.nick ] or ""
        if info == "m" then return utf.format( msg_msgmanager, msg_msgmanager_1, msg_mode_main ) end
        if info == "p" then return utf.format( msg_msgmanager, msg_msgmanager_1, msg_mode_pm ) end
        if info == "b" then return utf.format( msg_msgmanager, msg_msgmanager_1, msg_mode_both ) end
    end
    return msg_msgmanager_2
end

local is_banned = function( username )
    local by_nick, start, time, reason
    for k, v in pairs( bans_tbl ) do
        if v.nick == username then
            by_nick = v.by_nick
            start = v.start
            time = v.time
            reason = v.reason
            return by_nick, start, time, reason
        end
    end
    return nil
end

local get_bantime = function( remaining )
    if tostring( remaining ):find( "-" ) then
        return msg_forever
    else
        local y, d, h, m, s = util.formatseconds( remaining )
        return y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    end
end

-- password cell for +accinfo / +accinfoop: the real stored password
-- when the operator has enabled show_reguser_password, else "<REDACTED>".
-- One tested definition for the toggle/redaction decision (#95 reversal,
-- exposed as the `_password_cell` seam). The hierarchy gate that decides
-- WHETHER this user may be inspected sits in the callers, not here.
local password_cell = function( pw )
    if not show_password then return msg_redacted end
    if pw == nil or pw == "" then return msg_unknown end
    return pw
end

local onbmsg = function( user, command, parameters )
    local level = user:level()
    if level < 10 then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    local me = utf.match( parameters, "^(%S+)" )
    local by, id = utf.match( parameters, "^(%S+) (.*)" )
    local target
    local _, regnicks, regcids = hub.getregusers()
    local _, usersids = hub.getusers()
    if ( me == nil ) then
        local usercid, usernick = user:cid(), user:firstnick()
        target = regnicks[ usernick ] or regcids.TIGR[ usercid ]
    else
        if not ( ( by == "sid" or by == "nick" or by == "cid" ) and id ) then
            user:reply( msg_usage, hub.getbot() )
            return PROCESSED
        else
            target = (
            by == "nick" and regnicks[ id ] ) or
            ( by == "cid" and regcids.TIGR[ id ] ) or
            ( by == "sid" and ( usersids[ id ] and usersids[ id ]:isregged() and usersids[ id ]:profile() ) )    -- OMG
        end
    end
    if not target then
        user:reply( msg_off, hub.getbot() )
        return PROCESSED
    end
    local targetlevel = tonumber( target.level ) or 100
    local targetlevelname = cfg.get( "levels" )[ targetlevel ] or "Unreg"
    if not ( me == nil ) and ( ( permission[ level ] or 0 ) < targetlevel ) then
        user:reply( msg_god, hub.getbot() )
        return PROCESSED
    end
    local accinfo = utf.format(
        msg_accinfo2,
        target.nick or msg_unknown,
        password_cell( target.password ),
        targetlevel or msg_unknown,
        targetlevelname or msg_unknown,
        target.by or msg_unknown,
        target.date or msg_unknown,
        get_lastseen( target ),
        hname or msg_unknown,
        hmail or msg_unknown,
        addy or msg_unknown
    )
    user:reply( accinfo, hub.getbot(), hub.getbot() )
    return PROCESSED
end

hub.setlistener( "onBroadcast", {},
    function( user, adccmd, parameters )
        local level = user:level()
        local cmd, _ = utf.match( parameters, "^[+!#](%S+) (.+)" )
        local me = utf.match( parameters, "^[+!#]%S+ (%S+)" )
        local by, id = utf.match( parameters, "^[+!#]%S+ (%S+) (.*)" )
        if cmd == cmd2 then
            if level < 10 then
                user:reply( msg_denied, hub.getbot() )
                return PROCESSED
            end
            local target
            local _, regnicks, regcids = hub.getregusers()
            local _, usersids = hub.getusers()
            if ( me == nil ) then
                local usercid, usernick = user:cid(), user:firstnick()
                target = regnicks[ usernick ] or regcids.TIGR[ usercid ]
            else
                if not ( ( by == "sid" or by == "nick" or by == "cid" ) and id ) then
                    user:reply( msg_usage, hub.getbot() )
                    return PROCESSED
                else
                    target = (
                    by == "nick" and regnicks[ id ] ) or
                    ( by == "cid" and regcids.TIGR[ id ] ) or
                    ( by == "sid" and ( usersids[ id ] and usersids[ id ]:isregged() and usersids[ id ]:profile() ) )    -- OMG
                end
            end
            if not target then
                user:reply( msg_off, hub.getbot() )
                return PROCESSED
            end
            local targetlevel = tonumber( target.level ) or 100
            local targetlevelname = cfg.get( "levels" )[ targetlevel ] or "Unreg"
            if not ( user.profile() == target ) and ( ( permission[ level ] or 0 ) < targetlevel ) then
                user:reply( msg_god, hub.getbot() )
                return PROCESSED
            end

            local ban_msg = msg_bans_no
            local by_nick, start, time, reason = is_banned( target.nick )
            if by_nick then
                local remaining = time - os.difftime( os.time(), start )
                ban_msg = utf.format( msg_bans_yes, by_nick, get_bantime( remaining ) )
            end
            local accinfo = utf.format(
                msg_accinfo,
                target.nick or msg_unknown,
                password_cell( target.password ),
                targetlevel or msg_unknown,
                targetlevelname or msg_unknown,
                target.by or msg_unknown,
                target.date or msg_unknown,
                get_regdescription( target ),
                get_lastseen( target ),
                get_trafficmanager( target ),
                get_msgmanager( target ),
                ban_msg,
                hname or msg_unknown,
                hmail or msg_unknown,
                addy or msg_unknown
            )
            user:reply( accinfo, hub.getbot(), hub.getbot() )
            return PROCESSED
        end
        return nil
    end
)

-- HTTP API endpoint (#82 registered-users family PR-2, #236).
-- Coexist with the ADC `+accinfo` / `+accinfoop` chat-cmds above.
-- Registered via raw `hub.http_register` (NOT util_http) because
-- nick is the natural primary key (§7.4 / §10.2) - matches the
-- cmd_ban PR-4 precedent for non-SID-target resources, and the
-- sibling cmd_reg PR-1 (#237) registration of `/v1/registered`.
--
-- The HTTP path returns the EXPANDED view (= ADC `+accinfoop`
-- semantics: ban + traffic / msg-block state included). The ADC-
-- side `level < 10` gate does NOT apply on the HTTP path - the
-- bearer token's `read` scope is the authorisation gate. Password
-- is omitted entirely (matches the v0.32 redaction policy /
-- sub-task of #95: the HPAS challenge-response is protocol-
-- mandated cleartext-equivalent, but the API surface never echoes
-- it back).

local http_format_ban = function( target_nick )
    if not target_nick or target_nick == "" then return nil end
    for _, b in pairs( bans_tbl ) do
        if b.nick == target_nick then
            local entry = {
                by_nick           = b.by_nick or "",
                reason            = b.reason or "",
                start             = b.start or 0,
                time_seconds      = b.permanent and 0 or ( b.time or 0 ),
                permanent         = b.permanent or false,
            }
            -- Mirror cmd_ban's GET /v1/bans shape (#444): a permanent
            -- ban carries no remaining_seconds and no expires_at - both
            -- surfaces must describe the same ban the same way, or a
            -- consumer of /v1/registered cannot tell a permanent ban
            -- from an expired-not-yet-pruned one.
            if not b.permanent then
                local remaining = ( b.time or 0 ) - os.difftime( os.time(), b.start or 0 )
                entry.remaining_seconds = remaining
                if remaining > 0 then
                    entry.expires_at = os.date( "!%Y-%m-%dT%H:%M:%SZ", b.start + b.time )
                end
            end
            return entry
        end
    end
    return nil
end

local http_format_msgblock = function( target_nick )
    if not msgmanager_activate then return nil end
    -- #238: in-memory getter if available, disk loadtable
    -- as a guarded fallback (etc_msgmanager not loaded).
    local msgmanager_tbl = ( msgmgr_get_block_tbl and msgmgr_get_block_tbl() )
                           or util.loadtable( msgmanager_file )
                           or {}
    local info = msgmanager_tbl[ target_nick ]
    if info == "m" then return { mode = "main" } end
    if info == "p" then return { mode = "pm" } end
    if info == "b" then return { mode = "main+pm" } end
    return nil
end

local http_is_traffic_blocked = function( target_nick )
    if not trafficmanager_activate then return false end
    for _, user in pairs( hub.getusers() ) do
        if user:firstnick() == target_nick then
            local desc = user:description() or ""
            if string.find( desc, search_flag_blocked, 1, true ) then
                return true
            end
        end
    end
    return false
end

local http_is_online = function( target_nick )
    for _, user in pairs( hub.getusers() ) do
        if user:firstnick() == target_nick then return true end
    end
    return false
end

local http_handler_get_reguser = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local _, regnicks, _ = hub.getregusers()
    local profile = regnicks[ nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "'" } }
    end
    -- Bots are excluded from /v1/registered for surface uniformity
    -- (matches PR-1 GET list humans-only filter + PR-1 PATCH guard).
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "' (bots are not addressable via /v1/registered)" } }
    end

    local level = tonumber( profile.level ) or 0
    local levels = cfg.get( "levels" ) or {}
    local desc_tbl = util.loadtable( description_file ) or {}
    local d = desc_tbl[ nick ]

    local data = {
        nick            = profile.nick or "",
        level           = level,
        level_name      = levels[ level ] or "Unreg",
        by              = profile.by or "",
        regged_at       = profile.date or "",
        lastseen        = tonumber( profile.lastseen ) or 0,
        is_online       = http_is_online( profile.nick ),
        comment         = ( d and d.tReason ) or "",
        traffic_blocked = http_is_traffic_blocked( profile.nick ),
        msg_blocked     = http_format_msgblock( profile.nick ),
        ban             = http_format_ban( profile.nick ),
    }
    return { status = 200, data = data }
end

hub.setlistener( "onStart", {},
    function()
        local oplevel = util.getlowestlevel( permission )
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, 10 )
            help.reg( help_title2, help_usage2, help_desc2, oplevel )
        end
        local ucmd = hub.import( "etc_usercommands" )    -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu_ct0, cmd, { }, { "CT1" }, 10 )
            ucmd.add( ucmd_menu_ct1_op, cmd2, { "nick", "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct3_op, cmd2, { "sid", "%[userSID]" }, { "CT2" }, oplevel )

            if advanced_rc then
                local regusers, reggednicks, reggedcids = hub.getregusers()
                local usertbl = {}
                for i, user in ipairs( regusers ) do
                    if ( user.is_bot ~=1 ) and user.nick then
                      table.insert( usertbl, user.nick )
                    end
                end
                table.sort( usertbl )
                for _, nick in pairs( usertbl ) do
                    ucmd.add( { ucmd_menu_ct4, ucmd_menu_ct5, ucmd_menu_ct6, nick }, cmd, { "nick", nick }, { "CT1" }, oplevel )
                    ucmd.add( { ucmd_menu_ct4_op, ucmd_menu_ct5_op, ucmd_menu_ct6_op, nick }, cmd2, { "nick", nick }, { "CT1" }, oplevel )
                end
            end
        end
        local hubcmd = hub.import( "etc_hubcommands" )    -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, 10 ) )

        if hub.http_register then
            hub.http_register( "GET", "/v1/registered/{nick}", "read", http_handler_get_reguser, {
                plugin = scriptname,
                description = "expanded account info for a registered user (= ADC `+accinfoop`); humans only - bots return 404",
                response_schema = {
                    nick            = { type = "string",  required = true },
                    level           = { type = "integer", required = true },
                    level_name      = { type = "string",  required = true },
                    by              = { type = "string",  required = true },
                    regged_at       = { type = "string",  required = true },
                    lastseen        = { type = "integer", required = true },
                    is_online       = { type = "boolean", required = true },
                    comment         = { type = "string",  required = true },
                    traffic_blocked = { type = "boolean", required = true },
                    msg_blocked     = { type = "object" },    -- null when not blocked
                    ban             = { type = "object" },    -- null when not banned
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

return {
    _password_cell = password_cell,    -- unit-test seam (reguser-password toggle)
}