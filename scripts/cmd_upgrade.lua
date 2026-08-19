--[[

    cmd_upgrade.lua by blastbeat

        - this script adds a command "upgrade" to set or change the level of a user by sid/nick
        - usage: [+!#]upgrade sid|nick <SID>|<NICK> <LEVEL>

        v0.23:
            - fix #243: ADC `+upgrade nick` path now nil-guards
              the prefix-table indexing under cfg drift. THIS IS
              THE ACTUAL CRASH SITE of the family: cmd_upgrade
              indexes `prefix_table[level]` then concatenates
              `prefix .. target_firstnick` WITHOUT routing through
              `hub.escapeto` (which would have soaked the nil via
              `luaL_optstring`). Pre-fix the nil-concat caused
              `attempt to concatenate a nil value (local 'prefix')`
              when prefix_table had no entry for target_level
              (cfg drift, ad-hoc level, partial wipe). The other
              three family plugins (cmd_setpass / cmd_nickchange
              / cmd_delreg) got the same `activate and prefix_table`
              guard + `or ""` index fallback for consistency even
              though they do not actually crash.

        v0.22:
            - HTTP API (#82 registered-users family PR-5, #236):
                - PUT /v1/registered/{nick}/level   (admin; = ADC `+upgrade nick`)
            - Coexist with ADC `+upgrade`; ADC path unchanged.

        v0.21: by pulsar
            - removed "by CID" (Easy cleanup of codebase milestone)

        v0.20: by pulsar
            - removed "hub.reloadusers()"
            - using "hub.getregusers()" instead of "util.loadtable()"

        v0.19: by blastbeat
            - fixed upgrade logic

        v0.18: by pulsar
            - imroved user:kill()

        v0.17: by pulsar
            - small fix
            - check if old level = new level  / thx Sopor
            - removed send_report() function, using report import functionality now

        v0.16: by pulsar
            - removed "cmd_upgrade_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_upgrade_minlevel"

        v0.15: by pulsar
            - small fix

        v0.14: by pulsar
            - changed msg_out message

        v0.13: by pulsar
            - removed new method to save userdatabase
            - send report if a user without permission tries to upgrade
            - rewrite some parts of the code

        v0.12: by pulsar
            - improved method to save userdatabase

        v0.11: by pulsar
            - added new table lookup
            - add report feature
                - send report to hubbot (according llevel) and/or send report as feed to opchat

        v0.10: by pulsar
            - additional ct1 rightclick
            - possibility to toggle advanced ct2 rightclick (shows complete userlist)
                - export var to "cfg/cfg.tbl"

        v0.09: by Motnahp
            - small permission fix in CT2

        v0.08: by Motnahp
            - small fix in lang

        v0.07: by pulsar
            - possibility to upgrade offline users (CT1)
            - changed visual output style
            - table lookups
            - code cleaning

        v0.06: by pulsar
            - bugfix in "user:kill()" function
            - show sorted levelnames in rightclick (CT2)

        v0.05: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"
            - fix a permission bug

        v0.04: by blastbeat
            - updated script api
            - regged hubcommand

        v0.03: by blastbeat
            - some clean ups, added language file, ucmd

        v0.02: by blastbeat
            - added language files and ucmd

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_upgrade"
local scriptversion = "0.23"

local cmd = "upgrade"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local utf_match = utf.match
local utf_format = utf.format
local hub_getbot = hub.getbot()
local hub_getusers = hub.getusers
local hub_getregusers = hub.getregusers
local hub_escapeto = hub.escapeto
local hub_import = hub.import
local hub_debug = hub.debug
local hub_issidonline = hub.issidonline
local hub_isnickonline = hub.isnickonline
local util_loadtable = util.loadtable
local util_getlowestlevel = util.getlowestlevel
local cfg_saveusers = cfg.saveusers
local table_insert = table.insert
local table_sort = table.sort

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub_debug( err )
local permission = cfg_get( "cmd_upgrade_permission" )
local advanced_rc = cfg_get( "cmd_upgrade_advanced_rc" )
local prefix_activate = cfg_get( "usr_nick_prefix_activate" )
local prefix_table = cfg_get( "usr_nick_prefix_prefix_table" )
local report = hub_import( "etc_report" )
local report_activate = cfg_get( "cmd_upgrade_report" )
local llevel = cfg_get( "cmd_upgrade_llevel" )
local report_hubbot = cfg_get( "cmd_upgrade_report_hubbot" )
local report_opchat = cfg_get( "cmd_upgrade_report_opchat" )

--// msgs
local msg_denied = lang.msg_denied or "You are not allowed to use this command or the target user has a higher level than you!"
local msg_usage = lang.msg_usage or "Usage: [+!#]upgrade sid|nick <sid>|<nick> <level>"
local msg_off = lang.msg_off or "User not found."
local msg_reg = lang.msg_reg or "User is not regged or a bot."
local msg_out = lang.msg_out or "%s  changed  %s  from level: %s [ %s ]  to level:  %s [ %s ]"
local msg_out_2 = lang.msg_out_2 or "%s  with level:  %s [ %s ]  has tried to change  %s  to level:  %s [ %s ]"
local msg_same = lang.msg_same or "This User still have this Level, no changes needed."

local help_title = "cmd_upgrade.lua"
local help_usage = lang.help_usage or "[+!#]upgrade sid|nick <sid>|<nick> <level>"
local help_desc = lang.help_desc or "sets level of user"

local ucmd_menu = lang.ucmd_menu or "Upgrade"
local ucmd_popup = lang.ucmd_popup or "Nickname:"

local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or "User"
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or "Control"
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or "Upgrade"
local ucmd_menu_ct1_4 = lang.ucmd_menu_ct1_4 or "by Nick from list"
local ucmd_menu_ct1_5 = lang.ucmd_menu_ct1_5 or "User"
local ucmd_menu_ct1_6 = lang.ucmd_menu_ct1_6 or "Control"
local ucmd_menu_ct1_7 = lang.ucmd_menu_ct1_7 or "Upgrade"
--local ucmd_menu_ct1_8 = lang.ucmd_menu_ct1_8 or "by Nick"


----------
--[CODE]--
----------

local minlevel = util_getlowestlevel( permission )

local onbmsg = function( user, command, parameters )
    local user_nick = user:nick()
    local user_level = user:level()
    local by, id, level = utf_match( parameters, "^(%S+) (%S+) (%d+)$" )
    if not ( by == "sid" or by == "nick" ) then
        user:reply( msg_usage, hub_getbot )
        return PROCESSED
    end
    if ( by == "sid" ) then
        local user_tbl = hub_getregusers()
        local target = ( by == "sid" and hub_issidonline( id ) )
        if not target then
            user:reply( msg_off, hub_getbot )
            return PROCESSED
        end
        if not target:isregged() or target:isbot() then
            user:reply( msg_reg, hub_getbot )
            return PROCESSED
        end
        local userlevelname = cfg_get( "levels" )[ tonumber( user_level ) ] or "Unreg"
        local targetlevelname = cfg_get( "levels" )[ tonumber( level ) ] or "Unreg"
        local targetoldlevelname = cfg_get( "levels" )[ tonumber( target:level() ) ] or "Unreg"
        if ( target:level( ) > user_level ) or ( tonumber( level ) > ( permission[ user_level ] or 0 ) ) or ( target:level( ) > ( permission[ user_level ] or 0 ) ) then
            user:reply( msg_denied, hub_getbot )
            local msg = utf_format( msg_out_2, user_nick, user_level, userlevelname, target:nick(), level, targetlevelname )
            report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
            return PROCESSED
        end
        local target_firstnick, target_oldlevel = target:firstnick(), target:level()
        if target_oldlevel == tonumber( level ) then
            user:reply( msg_same, hub_getbot )
            return PROCESSED
        end

         --// alternative method (works 100%)
        for k, v in pairs( user_tbl ) do
            if user_tbl[ k ].nick == target_firstnick then
                user_tbl[ k ].level = tonumber( level )
                local msg = utf_format( msg_out, user_nick, target:nick(), target_oldlevel, targetoldlevelname, level, targetlevelname )
                target:kill( "ISTA 230 " .. hub_escapeto( msg ) .. "\n", "TL300" )
                cfg_saveusers( user_tbl )
                user:reply( msg, hub_getbot )
                report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                audit.fire( audit.build( "reg.level.set", user,
                    { nick = target_firstnick, level = tonumber( level ) },
                    nil, { previous_level = target_oldlevel } ) )
                return PROCESSED
            end
        end

    end
    if by == "nick" then
        local user_tbl = hub_getregusers()
        local target_isbot = true
        local target_isregged = false
        local msg, target, target_nick, target_firstnick, target_level, targetlevelname, userlevelname, targetoldlevelname
        for k, v in pairs( user_tbl ) do
            if not user_tbl[ k ].is_bot then
                if user_tbl[ k ].nick == id then
                    target_firstnick = user_tbl[ k ].nick
                    target_level = user_tbl[ k ].level
                    targetlevelname = cfg_get( "levels" )[ tonumber( level ) ] or "Unreg"
                    targetoldlevelname = cfg_get( "levels" )[ tonumber( target_level ) ] or "Unreg"
                    userlevelname = cfg_get( "levels" )[ tonumber( user_level ) ] or "Unreg"
                    if ( tonumber( target_level ) > tonumber( user_level ) ) or ( tonumber( level ) > ( permission[ user_level ] or 0 ) ) or ( tonumber( target_level ) > ( permission[ user_level ] or 0 ) ) then
                        user:reply( msg_denied, hub_getbot )
                        msg = utf_format( msg_out_2, user_nick, user_level, userlevelname, target_firstnick, level, targetlevelname )
                        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                        return PROCESSED
                    end
                    if target_level == tonumber( level ) then
                        user:reply( msg_same, hub_getbot )
                        return PROCESSED
                    end
                    if prefix_activate and prefix_table then
                        -- `or ""` guards both the missing-key case
                        -- (prefix_table has no entry for target_level)
                        -- and the cfg-drift case (operator wiped the
                        -- table while prefix_activate=true). Pre-fix
                        -- the nil-concat crashed the ADC handler. #243.
                        local prefix = prefix_table[ target_level ] or ""
                        target_nick = prefix .. target_firstnick
                        target = hub_isnickonline( target_nick )
                        msg = utf_format( msg_out, user_nick, target_nick, target_level, targetoldlevelname, level, targetlevelname )
                        if target then
                            target:kill( "ISTA 230 " .. hub_escapeto( msg ) .. "\n", "TL300" )
                        end
                    else
                        target = hub_isnickonline( target_firstnick )
                        msg = utf_format( msg_out, user_nick, target_firstnick, target_level, targetoldlevelname, level, targetlevelname )
                        if target then
                            target:kill( "ISTA 230 " .. hub_escapeto( msg ) .. "\n", "TL300" )
                        end
                    end
                    local _previous_level = target_level
                    user_tbl[ k ].level = tonumber( level )
                    cfg_saveusers( user_tbl )
                    user:reply( msg, hub_getbot )
                    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                    audit.fire( audit.build( "reg.level.set", user,
                        { nick = target_firstnick, level = tonumber( level ) },
                        nil, { previous_level = _previous_level } ) )
                    return PROCESSED
                else
                    target_isregged = false
                end
            else
                target_isbot = true
            end
        end
        if not target_isregged then
            user:reply( msg_reg, hub_getbot )
            return PROCESSED
        end
        if target_isbot then
            user:reply( msg_reg, hub_getbot )
            return PROCESSED
        end
    end
end

-- HTTP API endpoint (#82 registered-users family PR-5, #236).
-- Coexist with the ADC `+upgrade` chat-cmd above. Registered via
-- raw `hub.http_register` because the resource is a sub-property
-- of the registered-users nick-keyed family (§10.2). Mirrors the
-- PR-1 / PR-2 / PR-3 / PR-4 pattern.
--
-- The ADC-side `cmd_upgrade_permission` ladder (admin can only
-- promote up to their own ceiling AND can't touch users above
-- their own level) does NOT apply on the HTTP path: the bearer
-- token's `admin` scope IS the authorisation gate (consistent
-- with all prior #82 phases).
local http_handler_set_level = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    local new_level = tonumber( body.level )
    if not new_level or new_level ~= math.floor( new_level ) or new_level < 0 then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or invalid `level` field (expected non-negative integer)" } }
    end
    new_level = math.floor( new_level )
    local levels = cfg_get( "levels" ) or {}
    if not levels[ new_level ] then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "unknown level " .. new_level .. " (not present in cfg.levels)" } }
    end

    local regusers_list, regnicks, _ = hub_getregusers()
    local profile = regnicks[ nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "'" } }
    end
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "' (bots are not addressable via /v1/registered)" } }
    end

    local previous_level = tonumber( profile.level ) or 0
    local new_level_name = levels[ new_level ] or "Unreg"

    local previous_level_name = levels[ previous_level ] or "Unreg"

    -- Idempotent: same level => 200 with online_kicked=false and
    -- no mutation. Matches PR-3 / PR-4 treatment of "same value";
    -- the ADC msg_same UX nicety is intentionally not replicated.
    if previous_level == new_level then
        return { status = 200, data = {
            action         = "level-changed",
            nick           = nick,
            level          = new_level,
            level_name     = new_level_name,
            previous_level = previous_level,
            online_kicked  = false,
        } }
    end

    -- Persist the mutation, then format the kill / audit message
    -- using the prefix-aware display nick so audit-trail entries
    -- match the ADC `+upgrade` path's chat-banner shape (the ADC
    -- nick-branch interpolates the prefixed nick).
    profile.level = new_level
    cfg_saveusers( regusers_list )

    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local display_nick = nick
    if prefix_activate and prefix_table and prefix_table[ previous_level ] then
        display_nick = prefix_table[ previous_level ] .. nick
    end
    local kill_msg = utf_format( msg_out, actor_label, display_nick,
                                 previous_level, previous_level_name,
                                 new_level, new_level_name )
    local online_kicked = false
    local target_user
    if prefix_activate and prefix_table then
        local prefix = prefix_table[ previous_level ] or ""
        target_user = hub_isnickonline( prefix .. nick )
    else
        target_user = hub_isnickonline( nick )
    end
    if target_user and not target_user:isbot() then
        target_user:kill( "ISTA 230 " .. hub_escapeto( kill_msg ) .. "\n", "TL300" )
        online_kicked = true
    end
    report.send( report_activate, report_hubbot, report_opchat, llevel, kill_msg )
    audit.fire( audit.build( "reg.level.set",
        { nick = actor_label, sid = "<http>" },
        { nick = nick, level = new_level },
        nil, { previous_level = previous_level, online_kicked = online_kicked } ) )

    return { status = 200, data = {
        action         = "level-changed",
        nick           = nick,
        level          = new_level,
        level_name     = new_level_name,
        previous_level = previous_level,
        online_kicked  = online_kicked,
    } }
end

hub.setlistener( "onStart", { },
    function( )
        help = hub_import( "cmd_help" )
        if help then help.reg( help_title, help_usage, help_desc, minlevel ) end
        ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            --// CT2
            local levels = cfg_get( "levels" ) or {}
            local lvltbl = {}
            for k, v in pairs( levels ) do
                if k > 0 then
                    lvltbl[ #lvltbl + 1 ] = k
                end
            end
            table_sort( lvltbl )
            for _, level in pairs( lvltbl ) do
                ucmd.add( { ucmd_menu, levels[ level ] }, cmd, { "sid", "%[userSID]", level }, { "CT2" }, minlevel )
            end
            --// CT1
            for _, level in pairs( lvltbl ) do
                ucmd.add( { ucmd_menu_ct1_5, ucmd_menu_ct1_6, ucmd_menu_ct1_7, levels[ level ] }, cmd, { "nick", "%[line:" .. ucmd_popup .. "]", level }, { "CT1" }, minlevel )
            end
            if advanced_rc then
                local regusers, reggednicks, _ = hub_getregusers()
                local usertbl = {}
                for i, user in ipairs( regusers ) do
                    if ( user.is_bot ~= 1 ) and user.nick then
                      table_insert( usertbl, user.nick )
                    end
                end
                table_sort( usertbl )
                for _, nick in pairs( usertbl ) do
                    for _, level in pairs( lvltbl ) do
                        ucmd.add( { ucmd_menu_ct1_1, ucmd_menu_ct1_2, ucmd_menu_ct1_3, ucmd_menu_ct1_4, nick, levels[ level ] }, cmd, { "nick", nick, level }, { "CT1" }, minlevel )
                    end
                end
            end
        end
        hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )

        if hub.http_register then
            hub.http_register( "PUT", "/v1/registered/{nick}/level", "admin", http_handler_set_level, {
                plugin = scriptname,
                description = "change the level of a registered user (= ADC `+upgrade nick`); humans only - bots return 404. kicks the online user with `ISTA 230 ... TL300` so the client picks up the new permission set on reconnect",
                request_schema = {
                    level = { type = "integer", required = true },
                },
                response_schema = {
                    action         = { type = "string",  required = true },
                    nick           = { type = "string",  required = true },
                    level          = { type = "integer", required = true },
                    level_name     = { type = "string",  required = true },
                    previous_level = { type = "integer", required = true },
                    online_kicked  = { type = "boolean", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
