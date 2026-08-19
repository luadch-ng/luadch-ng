--[[

    usr_uptime.lua by pulsar  / requested by Sopor

        usage: [+!#]useruptime [CT1 <FIRSTNICK> | CT2 <NICK>]

        v0.13: by Aybo
            - carry a user's accumulated uptime over to the new nick on
              +nickchange / HTTP rename. uptime_tbl is keyed by firstnick;
              a rename only updated user.tbl, so the stats were orphaned
              and read as zero under the new nick. An onAudit tap on
              reg.nickchange now re-keys the entry (covers the ADC self /
              othernick / othernicku paths AND the HTTP API).

        v0.12: by Aybo
            - fix undercounting on busy hubs and across +reload
              (reported by Sopor: 24/7 users showing only a few hours
              per month, "22h" common = time since the last restart).
              Two bugs, both meaning accumulated online time lived only
              in RAM and was lost on the next restart / crash:
              (1) set_stop reset the global `start` timer-gate on EVERY
              logout. onTimer only credits online users when
              `os.time() - start >= delay` (60s), so on a hub with a
              logout more than once per 60s that gate never reached 60
              and the periodic credit block never fired - 24/7 users
              (who never log out) were never credited by the timer,
              only their RAM `now - last_tick` delta grew, and it was
              dropped on restart. Fix: set_stop no longer touches
              `start`; the timer's 60s cadence is now independent of
              logout activity.
              (2) last_tick is RAM-only, set only in set_start
              (onLogin). A +reload re-runs onStart but fires no onLogin
              for users who stayed connected, so their last_tick stayed
              nil and the timer skipped them until they reconnected.
              Fix: onStart re-seeds last_tick for users already online.
              Max loss on a crash / restart is now <= one tick (60s)
              per user. Pre-fix accumulated data cannot be
              reconstructed and stays as-is.

        v0.11: by Aybo
            - drop always-zero "years" from per-month display
              (fix #328, reported by Sopor). A calendar month
              holds <= 31 days = ~2.7M s, while formatseconds
              only rolls a year at 365 days = ~31.5M s, so the
              year column was pure noise. Switched to the
              4-value (hubstart=true) form of formatseconds and
              removed `y .. msg_years` from the rendered line.
              The `msg_years` key is also dropped from this
              plugin's lang files; 14 other plugins keep their
              own `msg_years` for legitimate year-scale spans.

        v0.10: by Aybo
            - rewrite the per-month accounting (fix #127, original
              report upstream luadch/luadch#193 by Sopor).
            - Pre-fix: set_start stored session_start on login,
              set_stop wrote (now - session_start) into the
              LOGOUT month's "complete". If the session crossed
              a month boundary, the logout month got ~0 seconds
              credited (new_entry had just reset session_start
              to "now"), and get_useruptime's else-branch
              displayed (now - session_start) for the LOGIN month
              which grew into months or years for long sessions.
            - Fix: per-minute tick-credit. onTimer walks online
              users, credits (now - last_tick[nick]) into the
              CURRENT month's "complete", updates last_tick.
              onLogout credits the final partial minute and
              clears the tracking. Sessions that cross a month
              boundary land their time in whichever month each
              tick fires in - 60s misattribution at the actual
              rollover instant is the design trade-off.
            - get_useruptime drops the else-branch that derived
              "uptime" from session_start. session_start is no
              longer set or read.
            - Existing data: rows with garbage "years online"
              values from the pre-fix bug stay as-is; they are
              not retroactively rewritten because the real
              uptime can't be reconstructed. From the fix
              onwards numbers are accurate.

        v0.9.1: by pulsar
            - fix in "new_complete"

        v0.9: by pulsar
            - added "years" to util.formatseconds
                - changed get_useruptime()

        v0.8: by pulsar
            - commented out debug line

        v0.7: by pulsar
            - removed table lookups
            - small change in "msg_label"
            - fix #39 -> https://github.com/luadch/luadch/issues/39

        v0.6: by blastbeat
            - only send feed to opchat, if opchat is active

        v0.5:
            - reduce timer to 1 minute
            - fix: https://github.com/luadch/luadch/issues/81
                - add "opchat.feed()" function to report corrupt or missing database file

        v0.4:
            - saves uptime table every 10 minutes

        v0.3:
            - fixed get_useruptime() function (output msg)  / thx WitchHunter

        v0.2:
            - added "usr_uptime_minlevel"  / requested by WitchHunter
                - possibility to show your own uptime stats for minlevel

        v0.1:
            - this script counts the online time of the users
            - it also exports the users uptime database table for other scripts

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "usr_uptime"
local scriptversion = "0.13"

local cmd = { "useruptime", "uu" }

local uptime_file = "scripts/data/usr_uptime.tbl"


--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local uptime_tbl = util.loadtable( uptime_file )
local minlevel = cfg.get( "usr_uptime_minlevel" )
local permission = cfg.get( "usr_uptime_permission" )
local opchat = hub.import( "bot_opchat" )

--// msgs
local help_title = "usr_uptime.lua"
local help_usage = lang.help_usage or "[+!#]useruptime"
local help_desc = lang.help_desc or "Shows your uptime stats"

local help_title_op = "usr_uptime.lua - Operators"
local help_usage_op = lang.help_usage_op or "[+!#]useruptime CT1 <FIRSTNICK> | CT2 <NICK>"
local help_desc_op = lang.help_desc_op or "Shows the uptime stats of a user"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "[+!#]useruptime CT1 <FIRSTNICK> | CT2 <NICK>"
local msg_notfound = lang. msg_notfound or "User not found."

local msg_days = lang.msg_days or " days, "
local msg_hours = lang.msg_hours or " hours, "
local msg_minutes = lang.msg_minutes or " minutes, "
local msg_seconds = lang.msg_seconds or " seconds"

local msg_label = lang.msg_label or "\tYEAR\tMONTH\t\tUPTIME"
local msg_err = lang.msg_err or "usr_uptime.lua: error: database file (usr_uptime.tbl) corrupt or missing, a new one was created."

local ucmd_menu_ct1 = lang.ucmd_menu_ct1 or { "User", "Uptime stats" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or { "About You", "show Uptime stats" }
local ucmd_menu_ct2 = lang.ucmd_menu_ct2 or { "Show", "Uptime stats" }
local ucmd_desc = lang.ucmd_desc or "Users nick without nicktag:"

local month_name = lang.month_name or {

    [ 1 ] = "January\t",
    [ 2 ] = "February\t",
    [ 3 ] = "March\t",
    [ 4 ] = "April\t",
    [ 5 ] = "May\t",
    [ 6 ] = "June\t",
    [ 7 ] = "July\t",
    [ 8 ] = "August\t",
    [ 9 ] = "September",
    [ 10 ] = "October\t",
    [ 11 ] = "November",
    [ 12 ] = "December",
}

local msg_uptime = lang.msg_uptime or [[


=== USER UPTIME ========================================================================

        Uptime stats about:  %s

%s
%s
%s
======================================================================== USER UPTIME ===
  ]]


----------
--[CODE]--
----------

local delay = 1 * 60
local start = os.time()

-- Per-user last-credited-at timestamp. RAM-only; cleared on logout.
-- A hub crash loses at most the partial minute since the last save,
-- same as the pre-fix path. set_start initialises this; the timer
-- and set_stop both advance it after crediting.
local last_tick = { }

local oplevel = util.getlowestlevel( permission )

local new_entry = function( user )
    if not user:isbot() then
        if type( uptime_tbl ) == "nil" then
            uptime_tbl = { }
            util.savetable( uptime_tbl, "uptime", uptime_file )
            if opchat then opchat.feed( msg_err ) end
        end
        local month, year = tonumber( os.date( "%m" ) ), tonumber( os.date( "%Y" ) )
        local nick = user:firstnick()
        if type( uptime_tbl[ nick ] ) == "nil" then
            uptime_tbl[ nick ] = { }
        end
        if type( uptime_tbl[ nick ][ year ] ) == "nil" then
            uptime_tbl[ nick ][ year ] = { }
        end
        if type( uptime_tbl[ nick ][ year ][ month ] ) == "nil" then
            uptime_tbl[ nick ][ year ][ month ] = { complete = 0 }
        end
    end
end

-- Credit elapsed time since last_tick[nick] to the user's current
-- month, then advance the tick. Sessions that cross a month
-- boundary land their seconds in whichever month each tick fires
-- in - the ~60s misattribution at the actual rollover instant is
-- the design trade-off.
local credit_online_time = function( user, now )
    if user:isbot() then return end
    local nick = user:firstnick()
    local last = last_tick[ nick ]
    if not last then return end    -- user not tracked yet (never logged in this run)
    local delta = now - last
    if delta <= 0 then return end
    new_entry( user )    -- handles year/month rollover entry creation
    local year, month = tonumber( os.date( "%Y", now ) ), tonumber( os.date( "%m", now ) )
    local entry = uptime_tbl[ nick ][ year ][ month ]
    entry.complete = ( entry.complete or 0 ) + delta
    last_tick[ nick ] = now
end

local set_start = function( user )
    if user:isbot() then return end
    new_entry( user )
    last_tick[ user:firstnick() ] = os.time()
end

local set_stop = function( user )
    if user:isbot() then return end
    credit_online_time( user, os.time() )
    last_tick[ user:firstnick() ] = nil
    util.savetable( uptime_tbl, "uptime", uptime_file )
    -- v0.12: do NOT reset the global `start` here. `start` gates the
    -- onTimer 60s credit cadence; resetting it on every logout starved
    -- the periodic crediting on busy hubs, so 24/7 users were never
    -- credited and their online time was lost on the next restart.
end

local get_useruptime = function( firstnick )
    if type( uptime_tbl ) == "nil" then
        uptime_tbl = { }
        util.savetable( uptime_tbl, "uptime", uptime_file )
        if opchat then opchat.feed( msg_err ) end
    end
    if type( uptime_tbl[ firstnick ] ) == "nil" then return false end
    local msg = ""
    for i_1 = 2015, 2100, 1 do
        for year, month_tbl in pairs( uptime_tbl[ firstnick ] ) do
            if year == i_1 then
                msg = msg .. "\n"
                for i_2 = 1, 12, 1 do
                    for month, v in pairs( month_tbl ) do
                        if month == i_2 then
                            -- v0.10 fix #127: read only `complete`.
                            -- The pre-fix else-branch derived a fake
                            -- uptime from session_start when complete
                            -- was 0, which produced the "years online"
                            -- weirdness for sessions crossing a month
                            -- boundary.
                            local complete = v.complete or 0
                            -- v0.11 fix #328: drop years (always 0 for a per-month
                            -- counter, max 31 days < 365). hubstart=true gives the
                            -- 4-value (d, h, m, s) form.
                            local d, h, m, s = util.formatseconds( complete, true )
                            local uptime = d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
                            msg = msg .. "\t" .. year .. "\t" .. month_name[ month ] .. "\t" .. uptime .. "\n"
                        end
                    end
                end
            end
        end
    end
    local msg_sep = "\t" .. string.rep( "-", 140 )
    return utf.format( msg_uptime, firstnick, msg_label, msg_sep, msg )
end

--// export function
local tbl = function()
    if type( uptime_tbl ) == "nil" then
        uptime_tbl = {}
        util.savetable( uptime_tbl, "uptime", uptime_file )
        return false, msg_err
    else
        return uptime_tbl
    end
end

local onbmsg = function( user, command, parameters )
    local user_level, user_firstnick = user:level(), user:firstnick()
    local param1, param2 = utf.match( parameters, "^(%S+) (%S+)$" )
    if not ( param1 and param2 ) then
        if user_level >= minlevel then
            local uptime = get_useruptime( user_firstnick )
            if uptime then
                user:reply( uptime, hub.getbot() )
                return PROCESSED
            else
                user:reply( msg_notfound, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
    end
    if not permission[ user_level ] then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    if ( param1 == "CT1" ) and param2 then
        local uptime = get_useruptime( param2 )
        if uptime then
            user:reply( uptime, hub.getbot() )
            return PROCESSED
        else
            user:reply( msg_notfound, hub.getbot() )
            return PROCESSED
        end
    end
    if ( param1 == "CT2" ) and param2 then
        local target = hub.isnickonline( param2 )
        if target then
            local uptime = get_useruptime( target:firstnick() )
            if uptime then
                user:reply( uptime, hub.getbot() )
                return PROCESSED
            else
                user:reply( msg_notfound, hub.getbot() )
                return PROCESSED
            end
        end
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

--// keep a user's accumulated uptime attached across a nick rename.
-- uptime_tbl is keyed by firstnick; +nickchange (and the HTTP rename)
-- renames the user in user.tbl but not here, so without this a rename
-- orphaned the user's online-time stats (they read as zero under the new
-- nick). audit.fire is unconditional (core/audit.lua), so one onAudit tap
-- catches every reg.nickchange. Returns nil (never PROCESSED) so the
-- etc_auditlog / http_events onAudit taps still receive the event.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        if type( uptime_tbl ) ~= "table" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        if old_nick == new_nick or uptime_tbl[ old_nick ] == nil then return nil end
        uptime_tbl[ new_nick ] = uptime_tbl[ old_nick ]
        uptime_tbl[ old_nick ] = nil
        util.savetable( uptime_tbl, "uptime", uptime_file )
        return nil
    end
)

hub.setlistener( "onStart", {},
    function()
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
            help.reg( help_title_op, help_usage_op, help_desc_op, oplevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct1,   cmd[1], { "CT1", "%[line:" .. ucmd_desc .. "]" }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct1_2, cmd[1], { }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct2,   cmd[1], { "CT2", "%[userNI]" }, { "CT2" }, oplevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- v0.12: re-seed per-user tracking for users already online.
        -- onStart also fires on +reload, which re-runs the script
        -- WITHOUT a fresh onLogin for users who stayed connected;
        -- without this their last_tick is nil and the timer skips them
        -- until they reconnect, silently dropping their online time
        -- across the reload. No-op on a fresh hub start (nobody online).
        local now = os.time()
        for sid, user in pairs( hub.getusers() ) do
            if not user:isbot() then
                new_entry( user )
                last_tick[ user:firstnick() ] = now
            end
        end
        return nil
    end
)

hub.setlistener( "onExit", { },
    function()
        --// save database
        util.savetable( uptime_tbl, "uptime", uptime_file )
        return nil
    end
)

hub.setlistener( "onLogin", {},
    function( user )
        set_start( user )
        return nil
    end
)

hub.setlistener( "onLogout", {},
    function( user )
        set_stop( user )
        return nil
    end
)

hub.setlistener( "onTimer", {},
    function( )
        if os.time() - start >= delay then
            local now = os.time()
            -- v0.10 fix #127: credit per-minute tick into every
            -- online user's CURRENT month. Replaces the pre-fix
            -- model where time was inferred from session_start at
            -- logout, which mis-attributed sessions that crossed
            -- a month boundary.
            for sid, user in pairs( hub.getusers() ) do
                credit_online_time( user, now )
            end
            util.savetable( uptime_tbl, "uptime", uptime_file )
            start = now
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {    -- export bans

    tbl = tbl,  -- use: local usersuptime = hub.import( "usr_uptime"); local uptime_tbl, err = usersuptime.tbl() in other scripts to get the users uptime database table

}
