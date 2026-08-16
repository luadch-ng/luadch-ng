--[[

    cmd_ban.lua by blastbeat

        - this script adds a command "ban" and "unban" to ban/unban users by nick/cid/ip or show/clear all banned users

        - usage ban: [+!#]ban nick|cid|ip <NICK>|<CID>|<IP> [<time> <reason>] / [+!#]ban show|showhis [<NICK>]|clear|clearhis
        - usage unban: [+!#]unban nick|cid|ip <NICK>|<CID>|<IP>

            - <time> are ban minutes; negative are not allowed
            - <time> and <reason> are optional
            - the keyword `permanent` in the <time> slot bans forever

        v0.48:
            - feat: periodic onTimer sweep prunes expired non-permanent
              bans. Before this, an expired tempban was only removed
              lazily on the banned user's next onConnect, so a ban on
              someone who never returns lingered in `bans` (and in
              `+ban show` / GET /v1/bans / the WebUI) forever. The sweep
              removes exactly what onConnect would - an expired
              non-permanent ban, identical `remaining < 0` test -
              throttled to once per 60s, in place (preserves the exported
              ban.bans reference, #239), skipping permanent bans (their
              placeholder time 0 reads as expired, the same guard as
              onConnect). Silent, like the onConnect prune it mirrors.

        v0.47:
            - carry a ban over to the new nick on +nickchange / HTTP
              rename. A by-nick ban record carries .nick = firstnick (cid /
              ip bans are rename-invariant) and history is keyed by
              firstnick; a rename only updated user.tbl, so a pure by-nick
              ban was silently bypassable by renaming the account. An
              onAudit tap on reg.nickchange now re-keys both the bans list
              and the history map (covers the ADC self / othernick /
              othernicku paths AND the HTTP API).

        v0.46:
            - feat: add a `permanent` entry to the right-click Ban submenu
              (CT2), alongside the existing 1 hour ... 1 year / other
              durations. Sends `+ban sid <SID> permanent <reason>` - the
              #444 keyword path on the SID target (prefix-agnostic). New
              lang key ucmd_menu_perm (en "permanent" / de "dauerhaft");
              the sent keyword itself stays the fixed literal `permanent`.

        v0.45:
            - fix: resolve an online target by firstnick when a nick-prefix
              is active. usr_nick_prefix re-keys the hub's nick table to
              the PREFIXED nick, so `+ban nick <base nick> ...` (and the
              HTTP POST /v1/bans nick target) silently took the OFFLINE
              path on a prefixed online user: the ban was stored but the
              user was NOT kicked (the operator believed they had removed
              them). Both the ADC nick branch and http_find_online now
              fall back to firstnick. Same idiom as etc_trafficmanager's
              find_online_by_firstnick (closed upstream luadch/luadch#240).
              This is what looked like "permanent ban does not kick" on the
              testhub - it was the nick-prefix resolution, not #444. #444
              permanent itself is unaffected.

        v0.44:
            - feat: permanent ban via the `permanent` keyword in the
              <time> slot (`+ban nick <NICK> permanent [<REASON>]`) and
              the HTTP body flag `permanent: true`. Stores a real
              `ban.permanent = true` marker (time 0), never a magic
              negative - a negative <time> stays rejected (v0.43). The
              expiry check never prunes a permanent ban; the kick uses
              ADC STA 231 + TL-1 (the "permanently banned" code + the
              no-expiry TL-1 marker) via cmd_ban's own two-arg kill (the
              TL-1 rides on the IQUI, same as the timed path's TL<sec>),
              NOT a 30-year finite 232. Same 231/TL-1 semantics the
              etc_clientblocker / etc_geoip / etc_proxydetect kicks use,
              though those embed TL-1 on the STA line instead. show /
              history / the HTTP list
              render "permanent" instead of a countdown. New lang key
              msg_permanent (en "permanent" / de "dauerhaft"); the
              keyword itself is a fixed literal, not translated. #444.

        v0.43:
            - fix: reject a <time> below 1 instead of silently losing the ban.
              is_integer() accepts negatives (-5 == math.floor( -5 )), so
              "+ban nick X -5 reason" stored bantime = -300; the login expiry
              check then computed an always-negative remaining and PRUNED the
              entry - the target was kicked once and walked straight back in
              while the operator believed X was banned. help_desc + both lang
              files promised "negative values means ban forever", a feature
              removed back in v0.15 ("removed the ban forever crap"); the
              promise is now gone and the parser rejects it (new "msg_badtime").
              Matches the HTTP path, which has enforced min = 1 since #82.
            - removed the commented-out ban-forever block: it referenced
              "msg_forever", which no lang file defines, so it could not have
              been re-enabled by uncommenting anyway

        v0.42:
            - fix #320: enforce hierarchy check on the offline-by-nick
              ban path. Pre-fix, the `permission[level] < target:level()`
              guard on the online path was silently bypassed when the
              target was an offline registered user (the offline branch
              resolved the target via regnicks[] - a profile TABLE with
              a `.level` field, not an object with a `:level()` method -
              and returned at addban() before the check could run). A
              low-level op could ban a higher-level offline user incl.
              the hubowner. cid / ip offline branches have no profile
              lookup and stay unchecked by design.

        v0.39:
            - fix: strip control bytes from POST /v1/bans `target`
              field before it reaches addban() / disk / ops broadcast.
              Other fields (reason, actor_label) were already stripped;
              `target` was an oversight in PR #234.

        v0.38:
            - fix #239: cleanbans() now mutates the `bans` table in
              place instead of rebinding `bans = {}`. The exported
              `ban.bans` reference (captured at module-load time by
              importers like cmd_accinfo's `local bans_tbl = ban.bans`)
              previously went stale across `+ban clear`, so
              `+accinfoop` and the HTTP `GET /v1/registered/{nick}`
              ban field surfaced ghost entries that no longer
              existed on disk. Only `cleanbans()` rebound the local;
              all other mutations (add / del / HTTP delete-by-index)
              already used `table.insert` / `table.remove` /
              `bans[k] = ...` in place. Smoke regression test added.

        v0.37: by Aybo
            - HTTP API endpoints (#82 Phase 2 PR-4):
                GET    /v1/bans                  (= +ban show)
                GET    /v1/bans/history[?nick=]  (= +ban showhis)
                POST   /v1/bans                  (= +ban nick|cid|ip|sid X T R)
                DELETE /v1/bans/{id}             (= +unban; {id} = 1-based
                                                  index from GET /v1/bans)
              Registered via raw hub.http_register (NOT the util_http
              SID helper - bans have nick/cid/ip targets, not a single
              {sid}). The ADC `+ban` / `+unban` cmds are unchanged.
            - DELETE-by-index race window: between GET /v1/bans (read
              indices) and DELETE /v1/bans/{id} another mutation may
              shift indices. Operator tooling must refresh between
              deletes. Documented in HTTP_API.md §10.2 footnote.
            - HTTP path applies `util.strip_control_bytes` to `reason`
              and `req.token_label` (operator-controlled cfg comment)
              before they reach the bans table / opchat report frame.
            - HTTP path does NOT apply the ADC-side
              `permission[level] < target:level()` hierarchy guard:
              the bearer token's `admin` scope IS the authorisation
              gate (matches PR-1 / PR-2 / PR-3 convention).

        v0.36: by pulsar
            - added "years" to util.formatseconds
                - changed get_bantime()

        v0.35: by pulsar
            - prevent nick bans if user is not online/regged

        v0.34: by pulsar
            - added more tempban options  / request by Tantrix
                - Fix #150

        v0.33: by pulsar
            - removed the ban forever crap
            - fix #32 -> https://github.com/luadch/luadch/issues/32

        v0.32: by pulsar
            - changed visuals

        v0.31: by pulsar
            - fix issue: https://github.com/luadch/luadch/issues/69
                - add "del()" function to export unban functionality in other scripts
            - add feature: https://github.com/luadch/luadch/issues/134
                - possibility to show the ban history of a user
            - removed table lookups
            - some changes in the rightclick menu

        v0.30: by pulsar
            - removed genOrderedIndex(), orderedNext() and orderedPairs() function, using new util.spairs() instead

        v0.29: by pulsar
            - ban export function: add()
                - set default "user_level" from "100" to "60"
                    - if a script is using the ban import function then it uses level "60" if user = nil
            - added ban history  / requested by Kungen
                - added new vars, functions, table lookups, ucmds
                - added ban state active/expired  / requested by Sopor
            - improved user:kill()

        v0.28: by pulsar
            - changed "addban" function, added additional routine (routine written by Jerker) to check if the user still exists,
              and if, rewrite old ban with the new one  / thx Jerker, Sopor, Kungen
            - changing some parts of code
            - add ban export functionality to use the ban function in other scripts
            - add complete unban command functionality from cmd_unban.lua
            - removed send_report() function, using report import functionality now
            - show default bantime in "ucmd_time" (rightclick bantime dialog)  / requested by Sopor
            - using "clear" parameter instead of "clean"  / requested by Sopor

        v0.27: by pulsar
            - typo fix  / thx Kaas
            - fixed "get_bantime()"  / thx BlinG
            - add "msg_forever"

        v0.26: by pulsar
            - removed "cmd_ban_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_ban_minlevel"
            - add is_integer() function to check if the used bantime is integer  / thx sopor
            - add new cmd: [+!#]ban clean  / requested by Tork
                - cleans the complete ban table (only lvl 100)

        v0.25: by pulsar
            - check if opchat is activated

        v0.24: by pulsar
            - fix missing report msg if target was banned via CT1
            - using "user:firstnick()" for "banned by"
            - fix permissions
            - add command: [+!#]ban show
                - shows a list of all banned users

        v0.23: by pulsar
            - add function to calculate ban time in days, hours, minutes, seconds
            - add some new table lookups

        v0.22: by pulsar
            - add some new table lookups
            - add possibility to send report to opchat

        v0.21: by pulsar
            - changed listener: from "onLogin" to "onConnect"  / thx fly out to Kungen
                - fixes problem where banned users can see userlist on login

        v0.20: by Night
            - permission fix

        v0.19: by pulsar
            - changed rightclick style

        v0.18: by pulsar
            - changed database path and filename
            - from now on all scripts uses the same database folder

        v0.17: by pulsar
            - fix lang and rightclicks for the v0.16 modifications
            - fix permission bug
            - changed listener: from "onConnect" to "onLogin"
            - if target is online and has higher level then he becomes a report

        v0.16: by Night
            - disallow banning users with same or lower reglevel
            - allow higher reglevel than the banner to allways enter hub
            - allow banning offline users by nick, ip, cid
            - add [+!#]ban ip

        v0.15: by pulsar
            - bugfix: ban bots

        v0.14: by pulsar
            - export scriptsettings to "cfg/cfg.tbl"

        v0.13: by pulsar
            - ban user by firstnick (without nicktag)

        v0.12: by blastbeat
            - updated script api
            - regged hubcommand

        v0.11: by blastbeat
            - some clean ups

        v0.10: by blastbeat
            - added language module

        v0.09: by blastbeat
            - added usercommand

        v0.08: by blastbeat
            - added english and german language files

        v0.07: by blastbeat
            - added report function, removed opchat, some clean up

        v0.06: by blastbeat
            - updated script api, cached table lookups, cleaned up code

        v0.05: by blastbeat
            - added by_level to ban table

        v0.04: by blastbeat
            - renamend to cmd_ban.lua

        v0.03: by blastbeat
            - added ban by nick and cid
            - added perm ban via negative ban time
            - added public interface to banfile

        v0.02: by blastbeat
            - fixed typo
            - added opchat setting

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_ban"
local scriptversion = "0.48"

local cmd = "ban"
local cmd2 = "unban"

--// imports - ban
local hubcmd, help, ucmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local default_time = cfg.get( "cmd_ban_default_time" )
local permission = cfg.get( "cmd_ban_permission" )
local report_activate = cfg.get( "cmd_ban_report" )
local report_hubbot = cfg.get( "cmd_ban_report_hubbot" )
local report_opchat = cfg.get( "cmd_ban_report_opchat" )
local llevel = cfg.get( "cmd_ban_llevel" )
local bans_path = "scripts/data/cmd_ban_bans.tbl"
local bans = util.loadtable( bans_path ) or {}
local history_path = "scripts/data/cmd_ban_history.tbl"
local history = util.loadtable( history_path ) or {}
local report = hub.import( "etc_report" )

--// imports - unban
local permission2 = cfg.get( "cmd_unban_permission" )

--// msgs - ban
local help_title = lang.help_title or "cmd_ban.lua - Ban"
local help_usage = lang.help_usage or "[+!#]ban nick|cid|ip <NICK>|<CID>|<IP> [<TIME> <REASON>] / [+!#]ban show|showhis [<NICK>]|clear|clearhis"
local help_desc = lang.help_desc or "bans user; <time> are ban minutes and must be 1 or greater"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_notint = lang.msg_notint or "It's not allowed to use decimal numbers for bantime."
local msg_badtime = lang.msg_badtime or "Bantime must be 1 minute or greater."
local msg_reason = lang.msg_reason or "No reason."
local msg_permanent = lang.msg_permanent or "permanent"
local msg_usage = lang.msg_usage or "Usage: [+!#]ban nick|cid|ip <NICK>|<CID>|<IP> [<TIME>|permanent <REASON>] / [+!#]ban show|showhis [<NICK>]|clear|clearhis"
local msg_off = lang.msg_off or "User not found."
local msg_god = lang.msg_god or "You cannot ban user with higher level than you."
local msg_bot = lang.msg_bot or "User is a bot."
local msg_ban = lang.msg_ban or "[ BAN ]--> You were banned by: %s  |  reason: %s  |  remaining ban time: "  -- do not delete '%s'!
local msg_ok = lang.msg_ok or "[ BAN ]--> User:  %s  was banned by:  %s  |  bantime: %s  |  reason: %s"
local msg_ban_attempt = lang.msg_ban_attempt or "[ BAN ]--> User:  %s  with lower level than you has tried to ban you! because: %s"
local msg_clean_bans = lang.msg_clean_bans or "[ BAN ]--> Ban table was cleared by: "
local msg_clean_banhistory = lang.msg_clean_banhistory or "[ BAN ]--> Ban history was cleared by: "

local msg_years = lang.msg_years or " years, "
local msg_days = lang.msg_days or " days, "
local msg_hours = lang.msg_hours or " hours, "
local msg_minutes = lang.msg_minutes or " minutes, "
local msg_seconds = lang.msg_seconds or " seconds"

local ucmd_menu1 = lang.ucmd_menu1 or { "Ban", "1 hour" }
local ucmd_menu2 = lang.ucmd_menu2 or { "Ban", "2 hours" }
local ucmd_menu3 = lang.ucmd_menu3 or { "Ban", "6 hours" }
local ucmd_menu4 = lang.ucmd_menu4 or { "Ban", "12 hours" }
local ucmd_menu5 = lang.ucmd_menu5 or { "Ban", "1 day" }
local ucmd_menu6 = lang.ucmd_menu6 or { "Ban", "2 days" }
local ucmd_menu7 = lang.ucmd_menu7 or { "Ban", "1 week" }
local ucmd_menu7_1 = lang.ucmd_menu7_1 or { "Ban", "1 month" }
local ucmd_menu7_2 = lang.ucmd_menu7_2 or { "Ban", "6 months" }
local ucmd_menu7_3 = lang.ucmd_menu7_3 or { "Ban", "1 year" }
local ucmd_menu_perm = lang.ucmd_menu_perm or { "Ban", "permanent" }
local ucmd_menu8 = lang.ucmd_menu8 or { "Ban", "other" }
local ucmd_menu9 = lang.ucmd_menu9 or { "User", "Control", "Ban", "by NICK" }
local ucmd_menu10 = lang.ucmd_menu10 or { "User", "Control", "Ban", "by CID" }
local ucmd_menu11 = lang.ucmd_menu11 or { "User", "Control", "Ban", "by IP" }
local ucmd_menu12 = lang.ucmd_menu12 or { "User", "Control", "Ban", "show", "bans" }
local ucmd_menu13 = lang.ucmd_menu13 or { "User", "Control", "Ban", "clear", "bans" }
local ucmd_menu14 = lang.ucmd_menu14 or { "User", "Control", "Ban", "show", "ban history", "all" }
local ucmd_menu16 = lang.ucmd_menu16 or { "User", "Control", "Ban", "show", "ban history", "by NICK" }
local ucmd_menu15 = lang.ucmd_menu15 or { "User", "Control", "Ban", "clear", "ban history" }

local ucmd_time = lang.ucmd_time or "Time in minutes (default: %s)"
local ucmd_reason = lang.ucmd_reason or "Reason"

local lblNick = lang.lblNick or " Nick: "
local lblCid = lang.lblCid or " CID: "
local lblIp = lang.lblIp or " IP: "
local lblReason = lang.lblReason or " Reason: "
local lblBy = lang.lblBy or " banned by: "
local lblTime = lang.lblTime or " banned till: "

local msg_his_nick = lang.msg_his_nick or "Nick: "
local msg_his_ban = lang.msg_his_ban or "Ban #"
local msg_his_date = lang.msg_his_date or "Date: "
local msg_his_bantime = lang.msg_his_bantime or "Bantime: "
local msg_his_reason = lang.msg_his_reason or "Reason: "
local msg_his_by = lang.msg_his_by or "Banned by: "
local msg_his_state = lang.msg_his_state or "State: "
local msg_his_active = lang.msg_his_active or "active"
local msg_his_expired = lang.msg_his_expired or "expired"

local msg_out = lang.msg_out or [[


=== BANS =====================================================================================
%s
===================================================================================== BANS ===
  ]]

local msg_out2 = lang.msg_out2 or [[


=== BAN HISTORY ===============================================================================
%s
=============================================================================== BAN HISTORY ===
  ]]


--// msgs - unban
local help_title2 = lang.help_title2 or "cmd_ban.lua - Unban"
local help_usage2 = lang.help_usage2 or "[+!#]unban nick|cid|ip <NICK>|<CID>|<IP>"
local help_desc2 = lang.help_desc2 or "unbans user by NICK/CID/IP"

local msg_usage2 = lang.msg_usage2 or "Usage: [+!#]unban nick|cid|ip <NICK>|<CID>|<IP>"
local msg_god2 = lang.msg_god2 or "You are not allowed to unban this user."
local msg_ok2 = lang.msg_ok2 or "[ UNBAN ]--> User:  %s  removed ban of:  %s"

local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "User", "Control", "Unban", "by NICK" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or { "User", "Control", "Unban", "by CID" }
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or { "User", "Control", "Unban", "by IP" }

local ucmd_ip = lang.ucmd_ip or "IP:"
local ucmd_cid = lang.ucmd_cid or "CID:"
local ucmd_nick = lang.ucmd_nick or "Nick:"


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission )
local minlevel2 = util.getlowestlevel( permission2 )

local is_integer = function( num )
    return num == math.floor( num )
end

local get_bantime = function( remaining )
    if tostring( remaining ):find( "-" ) then
        return remaining
    else
        local y, d, h, m, s = util.formatseconds( remaining )
        return y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    end
end

local parsedate = function( date )
    local str = tostring( date )
    local Y, M, D = str:sub( 1, 4 ), str:sub( 5, 6 ), str:sub( 7, 8 )
    local h, m, s = str:sub( 9, 10 ), str:sub( 11, 12 ), str:sub( 13, 14 )
    return Y .. "-" .. M .. "-" .. D .. " / " .. h .. ":" .. m .. ":" .. s
end

local add = function( user, target, bantime, reason, script, permanent )  -- ban export function
    -- `permanent` (optional, backward-compatible 6th arg) stores a ban
    -- that never expires. When set, the stored `time` is 0 and the
    -- `permanent` flag governs the expiry check, the show/history render
    -- and the ADC STA code (231 + TL-1 instead of 232 + TL<seconds>).
    local key = #bans + 1
    local user_firstnick, user_level
    if user then
        user_firstnick = user:firstnick()
        user_level = user:level()
    else
        user_firstnick = ""
        user_level = 60
    end
    local target_firstnick = target:firstnick()
    local target_cid = target:cid()
    local target_hash = target:hash()
    local target_ip = target:ip()
    if not script then script = user_firstnick end
    for i, bantbl in ipairs( bans ) do
        if bantbl.nick == target_firstnick then
            key = i
            break
        end
        if bantbl.cid == target_cid then
            key = i
            break
        end
        if bantbl.ip == target_ip then
            key = i
            break
        end
    end
    bans[ key ] = {
        nick = target_firstnick,
        cid = target_cid,
        hash = target_hash,
        ip = target_ip,
        time = permanent and 0 or bantime,
        permanent = permanent or nil,
        start = os.time( os.date( "*t" ) ),
        reason = reason,
        by_nick = script,
        by_level = user_level
    }
    local i
    if type( history[ target_firstnick ] ) == "nil" then
        history[ target_firstnick ] = {}
        i = 1
    else
        i = #history[ target_firstnick ] + 1
    end
    history[ target_firstnick ][ i ] = { date = util.date(), reason = reason, bantime = permanent and 0 or bantime, permanent = permanent or nil, by_nick = script, start = os.time( os.date( "*t" ) ), }
    util.savearray( bans, bans_path )
    util.savetable( history, "history_tbl", history_path )
    local target_msg = utf.format( msg_ban, script, reason ) .. ( permanent and msg_permanent or get_bantime( bantime ) )
    if permanent then
        -- ADC STA 231 = "Permanently banned" paired with the no-expiry
        -- TL-1. Kept in cmd_ban's two-arg kill form so the TL-1 rides on
        -- the IQUI (like the timed path's TL<sec>), rather than the STA
        -- line where etc_clientblocker / etc_geoip / etc_proxydetect put
        -- their TL-1 - same 231/TL-1 semantics, cmd_ban's own framing.
        -- This is the CORRECT 231 pairing; #147 T1.5 moved TIME-LIMITED
        -- bans off 231 precisely because 231 with a FINITE TL is
        -- self-contradictory - a permanent ban with TL-1 is not.
        target:kill( "ISTA 231 " .. hub.escapeto( target_msg ) .. "\n", "TL-1" )
    else
        -- ADC STA 232 = "Temporarily banned, flag TL" (T1.5 of #147).
        target:kill( "ISTA 232 " .. hub.escapeto( target_msg ) .. "\n", "TL" .. bantime )
    end
    return PROCESSED
end

local del = function( target )
    if target then
        for i, ban_tbl in ipairs( bans ) do
            if ban_tbl.nick == target then
                table.remove( bans, i )
                util.savearray( bans, bans_path )
            end
        end
    end
end

local addban = function( by, id, bantime, reason, level, nick, victim, permanent )
    local key = #bans + 1
    if not victim then
        for i, bantbl in ipairs( bans ) do
            if ( by == "nick" and bantbl.nick == id ) then
                key = i
                break
            elseif ( by == "cid" and bantbl.cid == id and bantbl.hash == "TIGR" ) then
                key = i
                break
            elseif ( by == "ip" and bantbl.ip == id ) then
                key = i
                break
            end
        end
    end
    bans[ key ] = {
        nick = victim and victim:firstnick() or by == "nick" and id or "",
        cid = victim and victim:cid() or by == "cid" and id or "",
        hash = victim and victim:hash() or "TIGR",
        ip = victim and victim:ip() or by == "ip" and id or "",
        time = permanent and 0 or bantime,
        permanent = permanent or nil,
        start = os.time( os.date( "*t" ) ),
        reason = reason,
        by_nick = nick,
        by_level = level
    }
    local n, i = victim and victim:firstnick() or by == "nick" and id or "", nil
    if n ~= "" then
        if type( history[ n ] ) == "nil" then
            history[ n ] = {}
            i = 1
        else
            i = #history[ n ] + 1
        end
        history[ n ][ i ] = { date = util.date(), reason = reason, bantime = permanent and 0 or bantime, permanent = permanent or nil, by_nick = nick, start = os.time( os.date( "*t" ) ), }
    end
    util.savearray( bans, bans_path )
    util.savetable( history, "history_tbl", history_path )
    -- #263 PR-B: surface ban-add into the GET /v1/events stream.
    -- No-op if http_events is not present (older hub).
    if http_events and http_events.emit then
        http_events.emit( "ban_added", {
            id          = key,
            target_type = by,
            target      = tostring( id or "" ),
            nick        = bans[ key ].nick,
            cid         = bans[ key ].cid,
            ip          = bans[ key ].ip,
            reason      = reason or "",
            by_nick     = nick or "",
            ban_seconds = permanent and 0 or bantime,
            permanent   = permanent or false,
        } )
    end
    return key  -- 1-based index of the newly-written / upserted entry
                -- (the HTTP POST /v1/bans path needs it; ADC callers
                -- ignore the return).
end

local showbans = function()
    local msg = ""
    for i, banstbl in ipairs( bans ) do
        local time_label = banstbl.permanent and msg_permanent
            or get_bantime( banstbl.time - os.difftime( os.time(), banstbl.start ) )
        msg = msg .. "\n [" .. i .. "]\n\t" ..
              lblNick .. "\t" .. banstbl.nick .. "\n\t" ..
              lblCid .. "\t" .. banstbl.cid .. "\n\t" ..
              lblIp .. "\t" .. banstbl.ip .. "\n\t" ..
              lblReason .. "\t" .. banstbl.reason .. "\n\t" ..
              lblBy .. "\t" .. banstbl.by_nick .. "\n\t" ..
              lblTime .. "\t" .. time_label .. "\n"
    end
    return utf.format( msg_out, msg )
end

local showhistory = function( hnick )
    local msg, found = "", false
    if hnick then
        for k, v in util.spairs( history ) do
            if k == hnick then
                found = true
                msg = msg .. "\n" .. msg_his_nick .. k .. "\n"
                for i, t in ipairs( v ) do
                    local state, time_label
                    if t.permanent then
                        state, time_label = msg_his_active, msg_permanent
                    else
                        local remaining = t.bantime - os.difftime( os.time(), t.start )
                        state = tostring( remaining ):find( "-" ) and msg_his_expired or msg_his_active
                        time_label = get_bantime( t.bantime )
                    end
                    msg = msg .. "\n\t" .. msg_his_ban .. i .. ":\n" ..
                          "\t\t" .. msg_his_state .. state .. "\n" ..
                          "\t\t" .. msg_his_date .. parsedate( t.date ) .. "\n" ..
                          "\t\t" .. msg_his_bantime .. time_label .. "\n" ..
                          "\t\t" .. msg_his_reason .. t.reason .. "\n" ..
                          "\t\t" .. msg_his_by .. t.by_nick .. "\n"
                end
            end
        end
        if not found then
            return msg_off
        end
        return utf.format( msg_out2, msg )
    else
        for k, v in util.spairs( history ) do
            msg = msg .. "\n" .. msg_his_nick .. k .. "\n"
            for i, t in ipairs( v ) do
                local state, time_label
                if t.permanent then
                    state, time_label = msg_his_active, msg_permanent
                else
                    local remaining = t.bantime - os.difftime( os.time(), t.start )
                    state = tostring( remaining ):find( "-" ) and msg_his_expired or msg_his_active
                    time_label = get_bantime( t.bantime )
                end
                msg = msg .. "\n\t" .. msg_his_ban .. i .. ":\n" ..
                      "\t\t" .. msg_his_state .. state .. "\n" ..
                      "\t\t" .. msg_his_date .. parsedate( t.date ) .. "\n" ..
                      "\t\t" .. msg_his_bantime .. time_label .. "\n" ..
                      "\t\t" .. msg_his_reason .. t.reason .. "\n" ..
                      "\t\t" .. msg_his_by .. t.by_nick .. "\n"
            end
        end
        return utf.format( msg_out2, msg )
    end
end

local cleanbans = function()
    -- In-place clear instead of `bans = {}` rebind: the exported
    -- `ban.bans` reference (line ~1089) is captured at module-load
    -- time, so a local-rebind would leave importers
    -- (cmd_accinfo's `local bans_tbl = ban.bans`) holding a stale
    -- snapshot - and `+ban clear` is the only mutation that
    -- previously REBOUND the local. Mutating in place keeps the
    -- export reference live across `+ban clear`. Closes #239.
    for k in pairs( bans ) do bans[ k ] = nil end
    util.savearray( bans, bans_path )
end

local cleanhistory = function()
    history = {}
    util.savetable( history, "history_tbl", history_path )
end

--// HTTP API (#82 Phase 2 PR-4)
--
-- The four endpoints below (GET / GET history / POST / DELETE) are
-- registered via raw `hub.http_register` rather than the
-- `util_http.http_register_user_action` helper because cmd_ban's
-- target keys are nick / cid / ip (and optionally sid as a transient
-- lookup), not a single `{sid}` path variable. The helper assumes
-- the simpler shape and would not fit.

-- Convert a stored ban entry to its HTTP response form. `idx` is the
-- 1-based index into the `bans` array - operators use it as the
-- {id} in DELETE /v1/bans/{id}. `remaining_seconds` reflects
-- live remaining time (negative = expired but not yet pruned;
-- pruning happens on the banned user's `onConnect` OR the 60s
-- onTimer sweep, whichever comes first). `expires_at` is ISO 8601
-- UTC, omitted when remaining is negative.
local format_ban_entry = function( idx, ban )
    local entry = {
        id              = idx,
        nick            = ban.nick or "",
        cid             = ban.cid or "",
        hash            = ban.hash or "",
        ip              = ban.ip or "",
        reason          = ban.reason or "",
        by_nick         = ban.by_nick or "",
        by_level        = ban.by_level or 0,
        ban_seconds     = ban.permanent and 0 or ban.time,
        ban_start       = ban.start,
        permanent       = ban.permanent or false,
    }
    if ban.permanent then
        -- No remaining_seconds and no expires_at: a permanent ban has
        -- neither. Consumers key off `permanent` (the expires_at date
        -- filter naturally excludes it, same as an already-expired ban).
        entry.remaining_seconds = nil
    else
        local remaining = ban.time - os.difftime( os.time(), ban.start )
        entry.remaining_seconds = remaining
        if remaining > 0 then
            entry.expires_at = os.date( "!%Y-%m-%dT%H:%M:%SZ", ban.start + ban.time )
        end
    end
    return entry
end

local format_history_entry = function( h )
    local state
    if h.permanent then
        state = "active"
    else
        local remaining = h.bantime - os.difftime( os.time(), h.start )
        state = remaining <= 0 and "expired" or "active"
    end
    return {
        date       = h.date,
        reason     = h.reason or "",
        by_nick    = h.by_nick or "",
        bantime    = h.permanent and 0 or h.bantime,
        start      = h.start,
        state      = state,
        permanent  = h.permanent or false,
    }
end

-- Resolve a target by criteria; returns the online user object or
-- nil. SID is online-only; nick / cid / ip use the hub's online
-- lookup. Offline fallback for `nick` is done by the caller via
-- `hub.getregusers()` because it must distinguish "offline regged"
-- (allowed) from "completely unknown" (rejected).
-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub.isnickonline( <base
-- nick> ) returns nil for a prefixed online user and the nick ban would
-- silently take the OFFLINE branch: the ban is stored but the user is not
-- kicked. firstnick is the ORIGINAL nick, captured once at login and
-- never re-keyed, so iterating it is robust against ANY nick-prefix
-- scheme. Same idiom as etc_trafficmanager's find_online_by_firstnick
-- (closed upstream luadch/luadch#240). Kept plugin-local rather than
-- changed in core hub.isnickonline, whose exact-current-nick semantics
-- back availability checks ("is this nick free?") in cmd_reg /
-- cmd_nickchange.
-- firstnick fallback -> the shared core helper (#537 dedup).
local find_online_by_firstnick = hub.find_online_by_firstnick

local http_find_online = function( target_type, target )
    if target_type == "sid" then return hub.issidonline( target ) end
    if target_type == "nick" then return hub.isnickonline( target ) or find_online_by_firstnick( target ) end
    if target_type == "cid" then return hub.iscidonline( target ) end
    if target_type == "ip" then return hub.isiponline( target ) end
    return nil
end

local http_handler_list_bans, http_handler_list_history,
      http_handler_create_ban, http_handler_delete_ban

-- #264 PR-B: filter/sort spec for /v1/bans. Operates on the
-- formatted ban-entry shape (post-format_ban_entry); pre-format
-- all entries upfront because the ban list is small (typical
-- 10-100) and downstream getters need stable id + expires_at.
-- `target_type` filter from #264 spec is intentionally omitted -
-- it is not a stored ban field; inferring from which of
-- cid/ip/nick is non-empty would be a separate enhancement.
local _bans_filter_spec = {
    string_fields = {
        nick    = function( e ) return e.nick    or "" end,
        cid     = function( e ) return e.cid     or "" end,
        ip      = function( e ) return e.ip      or "" end,
        by_nick = function( e ) return e.by_nick or "" end,
        reason  = function( e ) return e.reason  or "" end,
    },
    integer_fields = {
        ban_seconds = function( e ) return tonumber( e.ban_seconds ) or 0 end,
    },
    date_fields = {
        -- expires_at is the ISO 8601 "YYYY-MM-DDTHH:MM:SSZ" string
        -- only set on still-active bans (remaining > 0). Lex-compare
        -- against the same format works since it is a fixed-width
        -- representation. nil entries (already-expired bans) fail
        -- the comparison, which is the intended behaviour: a
        -- "find bans expiring between X and Y" query naturally
        -- excludes already-expired ones.
        expires_at = {
            get         = function( e ) return e.expires_at end,
            parse_query = function( q ) return q end,
        },
    },
    sortable_fields = {
        id          = function( e ) return tonumber( e.id )          or 0  end,
        nick        = function( e ) return e.nick                    or "" end,
        by_nick     = function( e ) return e.by_nick                 or "" end,
        ban_seconds = function( e ) return tonumber( e.ban_seconds ) or 0  end,
        ban_start   = function( e ) return tonumber( e.ban_start )   or 0  end,
    },
    default_sort_field      = "id",
    default_sort_descending = false,
}

http_handler_list_bans = function( req )
    local entries = {}
    for i, ban in ipairs( bans ) do
        entries[ #entries + 1 ] = format_ban_entry( i, ban )
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _bans_filter_spec, entries
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = { bans = rows },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

http_handler_list_history = function( req )
    local filter_nick = req.query and req.query.nick
    local out = {}
    if filter_nick and filter_nick ~= "" then
        local entries = history[ filter_nick ]
        if entries then
            local list = {}
            for _, h in ipairs( entries ) do
                list[ #list + 1 ] = format_history_entry( h )
            end
            out[ filter_nick ] = list
        end
    else
        for nick, entries in pairs( history ) do
            local list = {}
            for _, h in ipairs( entries ) do
                list[ #list + 1 ] = format_history_entry( h )
            end
            out[ nick ] = list
        end
    end
    return { status = 200, data = { history = out } }
end

http_handler_create_ban = function( req )
    local body = req.body or {}
    local target_type = body.target_type
    local raw_target = body.target
    if not raw_target or raw_target == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty `target` field" } }
    end
    -- Strip control bytes BEFORE addban persists to bans_tbl on disk
    -- and BEFORE the report.send broadcast to ops. Reason / actor
    -- already sanitised below; target was an oversight in PR #234
    -- (#82 Phase 2). Schema enforces max_length=64 but not byte class.
    -- util.strip_control_bytes replaces control bytes with `?` (not
    -- delete) so the stripped result is never empty when raw_target
    -- was non-empty; no second empty-check needed.
    local target_id = util.strip_control_bytes( raw_target )
    -- `permanent: true` bans forever (ADC STA 231 + TL-1); it ignores
    -- duration_minutes and stores time 0 + the permanent flag - the
    -- HTTP mirror of the ADC `+ban ... permanent` keyword.
    local permanent = ( body.permanent == true )
    -- duration_minutes optional; falls back to cfg cmd_ban_default_time.
    local duration_minutes, bantime
    if permanent then
        duration_minutes, bantime = nil, 0
    else
        duration_minutes = body.duration_minutes or default_time
        if not duration_minutes or duration_minutes < 1 then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "missing duration_minutes and cfg cmd_ban_default_time is unset" } }
        end
        bantime = duration_minutes * 60
    end
    local clean_reason = util.strip_control_bytes(
        ( body.reason and body.reason ~= "" ) and body.reason or msg_reason
    )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )

    -- Resolve target. SID is strictly online-only; nick has an
    -- offline-regged fallback; cid / ip are blind-add (no offline
    -- lookup path - matches ADC behaviour).
    local victim = http_find_online( target_type, target_id )
    if not victim then
        if target_type == "sid" then
            return { status = 404, error = { code = "E_NOT_FOUND",
                message = "no such online sid" } }
        end
        if target_type == "nick" then
            local _, regnicks, _ = hub.getregusers()
            if not regnicks[ target_id ] then
                return { status = 404, error = { code = "E_NOT_FOUND",
                    message = "unknown nick (not online and not registered)" } }
            end
        end
    end
    if victim and victim:isbot() then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "target is a bot; cannot ban via this endpoint" } }
    end

    -- For SID targets, addban needs the victim object so the
    -- persisted entry carries nick/cid/ip resolved from the live
    -- session (matches the ADC-side `by == "sid"` path).
    local addban_victim = nil
    local addban_by = target_type
    local addban_id = target_id
    if target_type == "sid" then
        if not victim then
            -- already handled above, but defensive
            return { status = 404, error = { code = "E_NOT_FOUND",
                message = "no such online sid" } }
        end
        addban_victim = victim
    end

    -- by_level = 100 on HTTP path: a bearer admin token has no ADC
    -- level (it is the operator's bypass), so the persisted ban
    -- gets the highest level so it survives operator-vs-operator
    -- ADC `+unban` attempts (only level >= ban.by_level can lift).
    local new_idx = addban( addban_by, addban_id, bantime, clean_reason,
                            100, actor_label, addban_victim, permanent )
    local entry = bans[ new_idx ]

    -- Caller-invoked report + kill, matching the ADC-path ordering
    -- (PR-1 / PR-2 convention).
    local target_display = ( victim and hub.escapefrom( victim:nick() ) )
                           or ( target_type == "nick" and target_id )
                           or ( entry.nick ~= "" and entry.nick )
                           or target_id
    local message = utf.format( msg_ok, target_display, actor_label,
                                ( permanent and msg_permanent or get_bantime( bantime ) ), clean_reason )
    report.send( report_activate, report_hubbot, report_opchat, llevel, message )
    if victim then
        if permanent then
            -- 231 (permanent) + TL-1, matching the ADC `+ban ... permanent` path.
            victim:kill( "ISTA 231 " .. hub.escapeto( message ) .. "\n", "TL-1" )
        else
            -- 232 (temporary ban with TL) per ADC STA semantics; matches
            -- the ADC `+ban` path. The TL value is bantime in seconds.
            victim:kill( "ISTA 232 " .. hub.escapeto( message ) .. "\n", "TL" .. bantime )
        end
    end
    local _audit_target = { }
    _audit_target[ target_type ] = target_id
    if entry.nick and entry.nick ~= "" then _audit_target.nick = entry.nick end
    audit.fire( audit.build( "ban.add",
        { nick = actor_label, sid = "<http>" }, _audit_target,
        ( clean_reason ~= "" and clean_reason or nil ),
        { by = target_type, duration_sec = bantime, permanent = permanent or nil, online = ( victim ~= nil ) } ) )

    local data = {
        action           = "ban",
        id               = new_idx,
        target_type      = target_type,
        target           = target_id,
        target_nick      = entry.nick ~= "" and entry.nick or nil,
        duration_minutes = duration_minutes,
        permanent        = permanent,
        reason           = clean_reason,
        by               = actor_label,
        expires_at       = ( not permanent ) and os.date( "!%Y-%m-%dT%H:%M:%SZ", entry.start + entry.time ) or nil,
    }
    return { status = 200, data = data }
end

http_handler_delete_ban = function( req )
    local id_str = req.path_vars and req.path_vars.id
    local id = tonumber( id_str )
    if not id or id < 1 or id ~= math.floor( id ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "invalid {id} - must be a positive integer (1-based index from GET /v1/bans)" } }
    end
    local entry = bans[ id ]
    if not entry then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no ban at index " .. id .. " (use GET /v1/bans to list current indices; indices shift on every removal)" } }
    end
    -- Snapshot before mutation; the response surfaces what was
    -- removed so the operator's audit / undo flow has the data.
    local removed = {
        id      = id,
        nick    = entry.nick or "",
        cid     = entry.cid or "",
        ip      = entry.ip or "",
        reason  = entry.reason or "",
        by_nick = entry.by_nick or "",
    }
    table.remove( bans, id )
    util.savearray( bans, bans_path )

    -- #263 PR-B: surface unban into the GET /v1/events stream.
    if http_events and http_events.emit then
        http_events.emit( "ban_removed", {
            id      = id,
            nick    = removed.nick,
            cid     = removed.cid,
            ip      = removed.ip,
            reason  = removed.reason,
            by_nick = removed.by_nick,
        } )
    end

    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    -- The ADC `+unban nick|cid|ip X` path picks a target_type
    -- string for msg_ok2; we lift whichever criterion was non-empty
    -- as the display label, preferring nick > cid > ip.
    local display = removed.nick ~= "" and removed.nick
                    or removed.cid ~= "" and removed.cid
                    or removed.ip
    local message = utf.format( msg_ok2, actor_label, display or "" )
    report.send( report_activate, report_hubbot, report_opchat, llevel, message )
    audit.fire( audit.build( "ban.remove",
        { nick = actor_label, sid = "<http>" },
        { nick = removed.nick or "", cid = removed.cid or "", ip = removed.ip or "" },
        nil, { id = id } ) )

    return { status = 200, data = {
        action  = "unban",
        id      = id,
        removed = removed,
        by      = actor_label,
    } }
end

local onbmsg = function( user, command, parameters )
    local level = user:level( )
    if level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    local by, id = utf.match( parameters, "^(%S+) (%S+)" )
    local mode = utf.match( parameters, "^(%S+)" )
    local hnick = utf.match( parameters, "^%S+ (%S+)" )
    -- The 3rd token is either a <TIME> in minutes or the literal keyword
    -- `permanent`. It is a fixed literal (like show/clear/nick), NOT
    -- translated - only the DISPLAY label msg_permanent is localised.
    local time_token = utf.match( parameters, "^%S+ %S+ (%S+)" )
    local permanent = ( time_token == "permanent" )
    local time, reason
    if permanent then
        -- everything after the `permanent` token is the reason
        reason = utf.match( parameters, "^%S+ %S+ %S+ (.*)" )
    else
        time = tonumber( utf.match( parameters, "^%S+ %S+ ([-]?%S+)" ) )
        reason = ( time and utf.match( parameters, "^%S+ %S+ [-]?%S+ (.*)" ) ) or ( ( time == nil ) and utf.match( parameters, "^%S+ %S+ (.*)" ) )
    end
    time = time or default_time
    reason = reason or msg_reason
    local bantime = permanent and 0 or time * 60
    local usernick = hub.escapefrom( user:nick() )
    local userfirstnick = hub.escapefrom( user:firstnick() )
    if mode == "show" then
        user:reply( showbans(), hub.getbot() )
        return PROCESSED
    end
    if mode == "clear" then
        if level < 100 then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        cleanbans()
        user:reply( msg_clean_bans .. user:nick(), hub.getbot() )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_clean_bans .. user:nick() )
        audit.fire( audit.build( "ban.clear", user, nil, nil, nil ) )
        return PROCESSED
    end
    -----------------------------------------------------------------------
    if ( mode == "showhis" ) and hnick then
        user:reply( showhistory( hnick ), hub.getbot() )
        return PROCESSED
    end
    if mode == "showhis" then
        user:reply( showhistory(), hub.getbot() )
        return PROCESSED
    end
    -----------------------------------------------------------------------
    if mode == "clearhis" then
        if level < 100 then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        cleanhistory()
        user:reply( msg_clean_banhistory .. user:nick(), hub.getbot() )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_clean_banhistory .. user:nick() )
        audit.fire( audit.build( "ban.history.clear", user, nil, nil, nil ) )
        return PROCESSED
    end

    -- Time validation is skipped for a `permanent` ban: there is no
    -- <TIME> to validate (bantime is 0 + the permanent flag governs
    -- everything downstream). The keyword path is the sanctioned
    -- alternative to a magic negative time, which the checks below
    -- still reject.
    if not permanent then
        if not is_integer( time ) then
            user:reply( msg_notint, hub.getbot() )
            return PROCESSED
        end
        -- Reject <time> below 1. `is_integer` above accepts negatives
        -- (-5 == math.floor(-5)), so without this a `+ban nick X -5 r`
        -- stored bantime = -300; the expiry check at login computes a
        -- remaining that is always negative and PRUNES the ban - the
        -- target was kicked once and then walked straight back in, while
        -- the operator believed they had banned them. Zero is rejected
        -- for the same reason (a 0-minute ban expires instantly).
        -- Matches the HTTP path, which has enforced `min = 1` since #82
        -- (request_schema + the duration_minutes < 1 guard) - this closes
        -- the divergence between the two entry points. A real permanent
        -- ban uses the `permanent` keyword above (ADC STA 231 + TL-1),
        -- never a magic negative.
        if time < 1 then
            user:reply( msg_badtime, hub.getbot() )
            return PROCESSED
        end
    end
    if not ( ( by == "sid" or by == "nick" or by == "cid" or by == "ip" ) and id ) then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end
    local target = ( by == "nick" and ( hub.isnickonline( id ) or find_online_by_firstnick( id ) ) ) or
                   ( by == "sid" and hub.issidonline( id ) ) or
                   ( by == "cid" and hub.iscidonline( id ) ) or
                   ( by == "ip" and hub.isiponline( id ) )
    if not target then
        if by == "sid" then
            user:reply( msg_off, hub.getbot() )
            return PROCESSED
        elseif by == "nick" then
            local _, regnicks, _ = hub.getregusers()
            target = regnicks[ id ]
            if not target then
                user:reply( msg_off, hub.getbot() )
                return PROCESSED
            end
            -- #320: offline hierarchy check. `target` here is the
            -- registered-user profile TABLE from regnicks (has a
            -- `.level` field), not an online user OBJECT (which has
            -- a `:level()` method). The online-target hierarchy
            -- check further below only fires when `target` is the
            -- user object - on this offline-by-nick branch the code
            -- returns at the addban() line below before it can run.
            -- Without this check a low-level op can ban a higher-
            -- level offline registered user (incl. hubowner). The
            -- cid / ip offline branches have no profile lookup and
            -- no hierarchy info, so they remain unchecked by design.
            if permission[ level ] < ( target.level or 0 ) then
                user:reply( msg_god, hub.getbot() )
                return PROCESSED
            end
        end
        if string.find( bantime, "-" ) then
            user:reply( msg_usage, hub.getbot() )
            return PROCESSED
        else
            addban( by, id, bantime, reason, level, userfirstnick, nil, permanent )
            local message = utf.format( msg_ok, id, usernick, ( permanent and msg_permanent or get_bantime( bantime ) ), reason )
            report.send( report_activate, report_hubbot, report_opchat, llevel, message )
            user:reply( message, hub.getbot() )
            local _target = { }
            _target[ by ] = id
            audit.fire( audit.build( "ban.add", user, _target,
                ( reason ~= msg_reason and reason or nil ),
                { by = by, duration_sec = bantime, permanent = permanent or nil, online = false } ) )
            return PROCESSED
        end
    end
    if target:isbot() then
        user:reply( msg_bot, hub.getbot() )
        return PROCESSED
    end
    if permission[ level ] < target:level( ) then
        user:reply( msg_god, hub.getbot() )
        target:reply( utf.format( msg_ban_attempt, usernick, hub.escapefrom( reason ) ), hub.getbot(), hub.getbot() )
        return PROCESSED
    end
    local targetnick = target:nick()
    -- This is special:
    -- SID ban is with rightclick function so its good to assume its for online user,
    -- so lets ban by nick, cid, ip ( easier unbanning by nick as the only reason really.. )
    -- Otherwise its probobly better to respect the ban criteria since the user is really
    -- writing a command that spesifies only one ban criteria. (by Night)
    local victim = nil
    if by == "sid" then
        victim = target
    end
    if string.find( bantime, "-" ) then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    else
        addban( by, id, bantime, reason, level, userfirstnick, victim, permanent )
        local message = utf.format( msg_ok, hub.escapefrom( targetnick ), usernick, ( permanent and msg_permanent or get_bantime( bantime ) ), reason )
        report.send( report_activate, report_hubbot, report_opchat, llevel, message )
        if permanent then
            -- 231 (permanent) + TL-1, the no-expiry pairing (see add()).
            target:kill( "ISTA 231 " .. hub.escapeto( message ) .. "\n", "TL-1" )
        else
            -- 232 (temporary ban with TL) per ADC STA semantics. 230 is
            -- "generic kick" - lacks the ban-list intent.
            target:kill( "ISTA 232 " .. hub.escapeto( message ) .. "\n", "TL" .. bantime )
        end
        user:reply( message, hub.getbot() )
        audit.fire( audit.build( "ban.add", user, target,
            ( reason ~= msg_reason and reason or nil ),
            { by = by, duration_sec = bantime, permanent = permanent or nil, online = true } ) )
        return PROCESSED
    end
end

hub.setlistener( "onBroadcast", {},
    function( user, adccmd, txt )
        local user_nick = user:nick()
        local user_level = user:level()
        local cmd = utf.match( txt, "^[+!#](%S+)" )
        local by, id = utf.match( txt, "^[+!#]%S+ (%S+) (%S+)" )
        if cmd == cmd2 then
            if user_level < minlevel then
                user:reply( msg_denied, hub.getbot() )
                return PROCESSED
            end
            if not ( ( by == "ip" or by == "nick" or by == "cid" ) and id ) then
                user:reply( msg_usage2, hub.getbot() )
                return PROCESSED
            end
            for i, ban_tbl in ipairs( bans ) do
                if ban_tbl[ by ] == id then
                    if permission2[ user_level ] < ( ban_tbl.by_level or 100 ) then
                        user:reply( msg_god2, hub.getbot() )
                        return PROCESSED
                    end
                    local removed_entry = ban_tbl
                    table.remove( bans, i )
                    util.savearray( bans, bans_path )
                    local message = utf.format( msg_ok2, user_nick, id )
                    report.send( report_activate, report_hubbot, report_opchat, llevel, message )
                    user:reply( message, hub.getbot() )
                    audit.fire( audit.build( "ban.remove", user,
                        { nick = removed_entry.nick or "", cid = removed_entry.cid or "",
                          ip = removed_entry.ip or "" },
                        nil, { by = by, id = i } ) )
                    return PROCESSED
                end
            end
            user:reply( msg_off, hub.getbot() )
            return PROCESSED
        end
        return nil
    end
)

hub.setlistener( "onConnect", {},
    function( user )
        local nick, cid, hash, ip = user:firstnick(), user:cid(), user:hash(), user:ip()
        local what, key, ban, message
        for i, bantbl in ipairs( bans ) do
            key = i
            ban = bantbl
            if ban.nick == nick then
                what = "nick"
                break
            elseif ban.cid == cid and ban.hash == hash then
                what = "cid"
                break
            elseif ban.ip == ip then
                what = "ip"
                break
            end
        end
        if what then
            if user:level() >= tonumber( ban.by_level ) then
                table.remove( bans, key )  -- remove ban entry
                util.savearray( bans, bans_path )  -- save table
                user:reply( utf.format( msg_ban_attempt, ban.by_nick, ban.reason ), hub.getbot(), hub.getbot() )  -- and send info
                return nil  -- user can login without problems
            end
            -- A permanent ban NEVER expires and MUST NOT be pruned:
            -- guard before the remaining-time math below, whose
            -- `string.find(remaining, "-")` would otherwise treat the
            -- placeholder time (0) as an already-expired ban and delete
            -- it - a silent unban. The higher-level bypass above still
            -- applies (an op above the banner can log in and lift it).
            if ban.permanent then
                message = utf.format( msg_ban, ban.by_nick, ban.reason ) .. msg_permanent
                user:kill( "ISTA 231 " .. hub.escapeto( message ) .. "\n", "TL-1" )
                return PROCESSED
            end
            local remaining = ban.time - os.difftime( os.time(), ban.start )
            if string.find( remaining, "-" ) then
                table.remove( bans, key )
                util.savearray( bans, bans_path )
            else
                message = utf.format( msg_ban, ban.by_nick, ban.reason ) .. get_bantime( remaining )
                -- remember: never fire listenter X inside listener X; will cause infinite loop
                -- also: never fire listener X in listener Y, where listener Y fires listener X; will as well cause a infinite loop.
                --scripts.firelistener( "onFailedAuth", user:nick( ), user:ip( ), user:cid( ), "Banned for "  .. get_bantime( remaining ) .. " (" .. ban.reason .. ")" )
                user:kill( "ISTA 232 " .. hub.escapeto( message ) .. "\n", "TL" .. remaining )
                return PROCESSED
            end
        end
        return nil
    end
)

-- Periodic sweep: prune bans that have expired but whose banned user has
-- not reconnected. The onConnect handler above only prunes on the banned
-- user's NEXT connect attempt, so a tempban on someone who never returns
-- lingers in `bans` - and in `+ban show` / GET /v1/bans / the WebUI -
-- forever. This timer removes exactly what onConnect would: an expired
-- NON-permanent ban, using the identical `remaining < 0` test (for the
-- integer remaining here that is `string.find( remaining, "-" )` without
-- the string coercion). It only changes WHEN an expired ban disappears
-- (on a timer vs. on the banned user's reconnect), never whether an active
-- ban is enforced.
--
-- Permanent bans are skipped: their placeholder time 0 makes remaining go
-- negative, so an unguarded sweep would delete them - the same trap the
-- onConnect handler guards at its `if ban.permanent` line.
--
-- Silent by design (no report / no audit): the onConnect prune this
-- mirrors is also silent, and a busy hub can expire many tempbans at once
-- - a per-expiry opchat line would be spam.
--
-- In-place table.remove, never a `bans = {}` rebind: importers capture the
-- exported ban.bans reference at load (cmd_accinfo), so a rebind leaves
-- them stale - the #239 lesson that also governs cleanbans(). Backward
-- iteration keeps the indices valid across removals. Throttled to once per
-- 60s because onTimer fires every second.
local _last_sweep = os.time()
local _sweep_interval = 60
local sweep_expired_bans = function()
    if os.time() - _last_sweep < _sweep_interval then return end
    _last_sweep = os.time()
    if #bans == 0 then return end
    local now = os.time()
    local changed = false
    for i = #bans, 1, -1 do
        local ban = bans[ i ]
        if not ban.permanent and ( ban.time - os.difftime( now, ban.start ) ) < 0 then
            table.remove( bans, i )
            changed = true
        end
    end
    if changed then util.savearray( bans, bans_path ) end
end

hub.setlistener( "onTimer", {},
    function( )
        sweep_expired_bans()
        return nil
    end
)

--// keep a ban attached to its user across a nick rename. A by-nick ban
-- record carries .nick = firstnick (cid / ip bans are rename-invariant),
-- and history is keyed by firstnick; +nickchange (and the HTTP rename)
-- renames the user in user.tbl but not here, so without this a pure
-- by-nick ban was silently bypassable by renaming the account. audit.fire
-- is unconditional (core/audit.lua), so one onAudit tap catches every
-- reg.nickchange. Returns nil (never PROCESSED) so the etc_auditlog /
-- http_events onAudit taps still receive the event.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        -- guard "": a cid/ip-only ban stores .nick = "", so an empty
        -- old_nick (should never happen) must not match those records.
        if old_nick == new_nick or old_nick == "" then return nil end
        local changed = false
        for _, b in ipairs( bans ) do
            if b.nick == old_nick then b.nick = new_nick; changed = true end
        end
        if changed then util.savearray( bans, bans_path ) end
        if history[ old_nick ] ~= nil then
            history[ new_nick ] = history[ old_nick ]
            history[ old_nick ] = nil
            util.savetable( history, "history_tbl", history_path )
        end
        return nil
    end
)

hub.setlistener( "onStart", {},
    function( )
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
            help.reg( help_title2, help_usage2, help_desc2, minlevel2 )
        end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            local ucmd_time = utf.format( ucmd_time, default_time )
            -- ban
            ucmd.add( ucmd_menu9, cmd, { "nick", "%[line:User Nick]", "%[line:" .. ucmd_time .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu10, cmd, { "cid", "%[line:User CID]", "%[line:" .. ucmd_time .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu11, cmd, { "ip", "%[line:User IP]", "%[line:" .. ucmd_time .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu12, cmd, { "show" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu13, cmd, { "clear" }, { "CT1" }, 100 )
            ucmd.add( ucmd_menu14, cmd, { "showhis" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu16, cmd, { "showhis", "%[line:User Nick]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu15, cmd, { "clearhis" }, { "CT1" }, 100 )

            ucmd.add( ucmd_menu1, cmd, { "sid", "%[userSID]", "60", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 1 hour
            ucmd.add( ucmd_menu2, cmd, { "sid", "%[userSID]", "120", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 2 hours
            ucmd.add( ucmd_menu3, cmd, { "sid", "%[userSID]", "360", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 6 hours
            ucmd.add( ucmd_menu4, cmd, { "sid", "%[userSID]", "720", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 12 hours
            ucmd.add( ucmd_menu5, cmd, { "sid", "%[userSID]", "1440", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 1 day
            ucmd.add( ucmd_menu6, cmd, { "sid", "%[userSID]", "2880", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 2 days
            ucmd.add( ucmd_menu7, cmd, { "sid", "%[userSID]", "10080", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 1 week
            ucmd.add( ucmd_menu7_1, cmd, { "sid", "%[userSID]", "40320", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 1 month
            ucmd.add( ucmd_menu7_2, cmd, { "sid", "%[userSID]", "241920", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 6 month
            ucmd.add( ucmd_menu7_3, cmd, { "sid", "%[userSID]", "525600", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- 1 year
            -- `permanent` is the #444 keyword (fixed literal in the time slot), not a minute count.
            ucmd.add( ucmd_menu_perm, cmd, { "sid", "%[userSID]", "permanent", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel ) -- permanent
            ucmd.add( ucmd_menu8, cmd, { "sid", "%[userSID]", "%[line:" .. ucmd_time .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel )
            -- unban
            ucmd.add( ucmd_menu_ct1_1, cmd2, { "nick", "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, minlevel2 )
            ucmd.add( ucmd_menu_ct1_2, cmd2, { "cid", "%[line:" .. ucmd_cid .. "]" }, { "CT1" }, minlevel2 )
            ucmd.add( ucmd_menu_ct1_3, cmd2, { "ip", "%[line:" .. ucmd_ip .. "]" }, { "CT1" }, minlevel2 )
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert(  hubcmd.add( cmd, onbmsg, minlevel ) )

        -- HTTP API endpoints (#82 Phase 2 PR-4). The ADC chat-cmds
        -- (`+ban`, `+unban`) above are unchanged - this is a
        -- coexist migration. Registered via raw hub.http_register
        -- (not util_http.http_register_user_action) because bans
        -- have nick / cid / ip / sid targets, not a single {sid}.
        if hub.http_register then
            hub.http_register( "GET", "/v1/bans", "read", http_handler_list_bans, {
                plugin = scriptname,
                description = "list active bans (= ADC `+ban show`)",
                response_schema = {
                    bans = { type = "array", required = true },
                },
            } )
            hub.http_register( "GET", "/v1/bans/history", "read", http_handler_list_history, {
                plugin = scriptname,
                description = "list ban history (= ADC `+ban showhis`); query ?nick=<NICK> for a single-nick view",
                response_schema = {
                    history = { type = "object", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/bans", "admin", http_handler_create_ban, {
                plugin = scriptname,
                description = "create a ban (= ADC `+ban nick|cid|ip|sid X T R`); body { target_type, target, duration_minutes?, permanent?, reason? }. permanent:true bans forever and ignores duration_minutes.",
                request_schema = {
                    target_type      = { type = "string", required = true, enum = { "nick", "cid", "ip", "sid" } },
                    target           = { type = "string", required = true, max_length = 64 },
                    -- 525600 minutes = 1 year. Same cap as the ADC-side ucmd_menu7_3.
                    duration_minutes = { type = "integer", required = false, min = 1, max = 525600 },
                    -- permanent:true = ADC `+ban ... permanent` (STA 231 + TL-1);
                    -- ignores duration_minutes and stores a never-expiring ban.
                    permanent        = { type = "boolean", required = false },
                    reason           = { type = "string", required = false, max_length = 256 },
                },
                response_schema = {
                    action = { type = "string", required = true },
                    id     = { type = "integer", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/bans/{id}", "admin", http_handler_delete_ban, {
                plugin = scriptname,
                description = "remove a ban by index (= ADC `+unban`). {id} is the 1-based index from GET /v1/bans; indices shift after every removal - re-list between deletes",
                response_schema = {
                    action  = { type = "string", required = true },
                    id      = { type = "integer", required = true },
                    removed = { type = "object", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {    -- export bans

    add = add,  -- use ban = hub.import( "cmd_ban"); ban.add( user, target, bantime, reason, script ) in other scripts to ban a user (bantime = seconds)
    del = del,  -- use ban = hub.import( "cmd_ban"); ban.del( target ) in other scripts to unban a user
    -- NOTE: the internal `addban` function is NOT in the public
    -- export table here (only `add` and `del` are). As of Phase 2
    -- PR-4 (v0.37) `addban` returns the 1-based index of the
    -- newly-written / upserted ban entry (was implicit nil before);
    -- the HTTP POST /v1/bans handler needs that index. ADC callers
    -- in this file ignore the return - kept additive on purpose.
    bans = bans,
    bans_path = bans_path,

    -- Internal test seams (nick-prefix resolution regression). `_`-prefixed
    -- per the repo convention for non-contract, test-only exports (see
    -- docs/PLUGIN_API.md §8); NOT part of the hub.import("cmd_ban") contract.
    _onbmsg                   = onbmsg,
    _http_find_online         = http_find_online,
    _find_online_by_firstnick = find_online_by_firstnick,

}
