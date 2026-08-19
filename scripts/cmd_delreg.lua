--[[

    cmd_delreg.lua by blastbeat

        - this script adds a command "delreg" to delreg users by nick
        - usage: [+!#]delreg nick <NICK>  |  [+!#]delreg nick <NICK> <DESCRIPTION>


        v0.33:
            - removed the unused "msg_reason" local: it read
              "lang.msg_reason", a key no cmd_delreg lang file defines
              (copy-pasted from cmd_ban, where the key exists and the
              local IS used). Nothing degraded because the local was
              never referenced, but the lookup was dead either way

        v0.32:
            - #243 family-wide consistency sweep: ADC `+delreg nick`
              path now uses the `activate and prefix_table` guard +
              `prefix_table[level] or ""` fallback, matching the
              HTTP path's pattern (PR-6 #245). cmd_delreg itself
              does not actually crash pre-fix because
              `hub.escapeto`'s C wrapper defaults nil to "" via
              `luaL_optstring` - but the explicit guard survives
              any future wrapper change. cmd_upgrade is the only
              actual crash site in the family (no escapeto wrapper).

        v0.31:
            - HTTP API (#82 registered-users family PR-6, #236):
                - DELETE /v1/registered/{nick}   (admin; X-Confirm required; = ADC `+delreg nick`)
            - Coexist with ADC `+delreg`; ADC path unchanged.
            - HTTP path is delreg-only (regged user removal); the
              blacklist-cleanup branch of +delreg (remove from
              cmd_delreg_blacklist.tbl when nick is NOT regged but
              IS on the blacklist) belongs conceptually to a
              future /v1/blacklist resource.

        v0.29: by pulsar
            - refresh "cfg/user.tbl.bak" if a user gets delregged

        v0.28: by pulsar
            - rewrite some parts
            - add comments for a better understanding
            - removed unused vars

        v0.27: by pulsar
            - changed visuals

        v0.26: by pulsar
            - fix #98 / thx Sopor
                - added missing import of ban function
            - fix #95 / thx Sopor
                - import trafficmanager block funktion
                    - remove user from blocks if exists
                - removed table lookups

        v0.25: by pulsar
            - remove delregged user from bans if exists  / thx Sopor
            - removed "hub.reloadusers()"
            - removed unused table lookups

        v0.24: by pulsar
            - fix typo  / thx Motnahp

        v0.23: by pulsar
            - imroved user:kill()

        v0.22: by pulsar
            - removed send_report() function, using report import functionality now
            - changed "os.date()" output style, consistent output of date (win/linux/etc)  / thx Sopor

        v0.21: by pulsar
            - remove description from "cmd_reg_descriptions.tbl" if user was delregged and description exists

        v0.20: by pulsar
            - removed "cmd_delreg_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_delreg_minlevel"

        v0.19: by pulsar
            - removed "hub.restartscripts()"
            - typo fix

        v0.18: by pulsar
            - check if opchat is activated

        v0.17: by pulsar
            - add "deleted by" info for blacklist entry
            - added "msg_ok2": if user was delregged with reason then the script shows it
            - add "blacklist_add" function and rewrite some parts of code

        v0.16: by pulsar
            - changing type of permission table (array of integer instead of array of boolean)

        v0.15: by pulsar
            - added some new table lookups
            - added possibility to send report as feed to opchat

        v0.14: by pulsar
            - fix bug with target user object

        v0.13: by pulsar
            - add some new table lookups
            - fix problem with disconnect users after delreg if using ct1 rightclick an user has nicktag
            - send error msg if user is not regged

        v0.12: by Night
            - permission fix

        v0.11: by pulsar
            - changed rightclick style

        v0.10: by pulsar
            - changed database path and filename
            - from now on all scripts uses the same database folder

        v0.09: by pulsar
            - bugfix: small error when delreg over CT1

        v0.08: by pulsar
            - bugfix: delreg bots

        v0.07: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.06: by pulsar
            - added blacklist function

        v0.05: by blastbeat
            - updated script api
            - regged hubcommand

        v0.04: by blastbeat
            - fixed report bug

        v0.03: by blastbeat
            - added language files, ucmds

        v0.02: by blastbeat
            - added report function

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_delreg"
local scriptversion = "0.33"

local cmd = "delreg"


--// imports
local hubcmd, help, ucmd
local permission = cfg.get( "cmd_delreg_permission" )
local scriptlang = cfg.get( "language" )
local activate = cfg.get( "usr_nick_prefix_activate" )
local prefix_table = cfg.get( "usr_nick_prefix_prefix_table" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "cmd_delreg_report" )
local llevel = cfg.get( "cmd_delreg_llevel" )
local report_hubbot = cfg.get( "cmd_delreg_report_hubbot" )
local report_opchat = cfg.get( "cmd_delreg_report_opchat" )
local ban = hub.import( "cmd_ban")
local block = hub.import( "etc_trafficmanager" )

--// msgs
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )

local msg_denied = lang.msg_denied or "[ DELREG ]--> You are not allowed to use this command or to delreg targets with this level."
local msg_usage = lang.msg_usage or "Usage: [+!#]delreg nick <NICK>  /  or del with denylist entry:  [+!#]delreg nick <NICK> <DESCRIPTION>"
local msg_error = lang.msg_error or "[ DELREG ]--> An error occurred: "
local msg_del = lang.msg_del or "[ DELREG ]--> You were delregged."
local msg_del_reason = lang.msg_del_reason or "[ DELREG ]--> You were delregged. Reason: %s"
local msg_bot = lang.msg_bot or "[ DELREG ]--> User is a bot."
local msg_ok = lang.msg_ok or "[ DELREG ]--> User  %s  was delregged by  %s"
local msg_ok2 = lang.msg_ok2 or "[ DELREG ]--> User  %s  was delregged and denylisted by  %s  reason: %s"
local msg_notfound = lang.msg_notfound or "[ DELREG ]--> User is not registered."
local msg_deblacklist = lang.msg_deblacklist or "[ DELREG ]--> User:  %s  was removed from the denylist by:  %s"

local help_title = "cmd_delreg.lua"
local help_usage = lang.help_usage or "[+!#]delreg nick <NICK>  /  or del with denylist entry:  [+!#]delreg nick <NICK> <DESCRIPTION>"
local help_desc = lang.help_desc or "delregs an existing user by nick or cid"

local ucmd_menu_ct1 = lang.ucmd_menu_ct1 or { "User", "Control", "Delreg", "by NICK" }
local ucmd_menu_ct2 = lang.ucmd_menu_ct2 or { "Delreg", "OK" }
local ucmd_nick = lang.ucmd_nick or "Nick:"
local ucmd_reason = lang.ucmd_reason or "Reason: (no denylist entry if empty)"

--// database
local blacklist_file = "scripts/data/cmd_delreg_blacklist.tbl"
local description_file = "scripts/data/cmd_reg_descriptions.tbl"


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission )
local cmd_options = { nick = "nick", nicku = "nicku" }

local blacklist_add = function( targetnick, nick, reason )
    local blacklist_tbl = util.loadtable( blacklist_file ) or {}
    blacklist_tbl[ targetnick ] = {}
    blacklist_tbl[ targetnick ][ "tDate" ] = os.date( "%Y-%m-%d / %H:%M:%S" )
    blacklist_tbl[ targetnick ][ "tReason" ] = reason
    blacklist_tbl[ targetnick ][ "tBy" ] = nick
    util.savetable( blacklist_tbl, "blacklist_tbl", blacklist_file )
end

-- Returns true if `targetnick` was on the blacklist and has now been
-- removed; false if no entry existed. Mirror of blacklist_add - lets
-- +delreg remove a blacklist entry without the operator hand-editing
-- cmd_delreg_blacklist.tbl. Closes upstream luadch/luadch#228.
local blacklist_del = function( targetnick )
    local blacklist_tbl = util.loadtable( blacklist_file ) or {}
    if not blacklist_tbl or not blacklist_tbl[ targetnick ] then
        return false
    end
    blacklist_tbl[ targetnick ] = nil
    util.savetable( blacklist_tbl, "blacklist_tbl", blacklist_file )
    return true
end

local description_del = function( targetnick )
    local description_tbl = util.loadtable( description_file ) or {}
    for k, v in pairs( description_tbl ) do
        if k == targetnick then
            description_tbl[ k ] = nil
            util.savetable( description_tbl, "description_tbl", description_file )
            break
        end
    end
end

local onbmsg = function( user, command, parameters )
    local user_nick = user:nick()
    local user_level = user:level()
    --// permission with regard to the minlevel
    if user_level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end

    local option, arg, reason = utf.match( parameters, "^(%S+) (%S+) ?(.*)" )

    if not ( option and arg ) or not cmd_options[ option ] then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end

    local target, target_firstnick, target_nick, target_level = nil, nil, nil, nil

    --// CT1 rightclick
    if option == "nick" then
        local regusers, reggednicks, reggedcids = hub.getregusers()
        local is_regged = false
        for i, usr in ipairs( regusers ) do
            if usr.nick == arg then
                if usr.is_bot == 1 then
                    user:reply( msg_bot, hub.getbot() )
                    return PROCESSED
                else
                    target_firstnick = usr.nick
                    target_level = usr.level
                    is_regged = true
                end
                break
            end
        end
        if is_regged then
            if activate and prefix_table then
                -- `or ""` guards both the missing-key case
                -- (prefix_table has no entry for target_level) and
                -- the cfg-drift case (operator wiped the table
                -- while activate=true). Pre-fix the nil-index
                -- crashed the ADC handler. #243.
                local prefix = hub.escapeto( prefix_table[ target_level ] or "" )
                target_nick = prefix .. target_firstnick
            else
                target_nick = target_firstnick
            end
            target = hub.isnickonline( target_nick )
        else
            -- Not regged. Maybe they are on the blacklist from an earlier
            -- delreg-with-reason; let +delreg remove that entry too,
            -- so the operator does not have to hand-edit the .tbl.
            -- Closes upstream luadch/luadch#228.
            if blacklist_del( arg ) then
                local message = utf.format( msg_deblacklist, arg, user_nick )
                user:reply( message, hub.getbot() )
                report.send( report_activate, report_hubbot, report_opchat, llevel, message )
                return PROCESSED
            end
            user:reply( msg_notfound, hub.getbot() )
            return PROCESSED
        end
    end
    --// CT2 rightclick
    if option == "nicku" then
        target = hub.isnickonline( arg )
        if target then
            if target:isbot() then
                user:reply( msg_bot, hub.getbot() )
                return PROCESSED
            else
                target_firstnick = target:firstnick()
                target_nick = target:nick()
                target_level = target:level()
            end
        else
            user:reply( msg_notfound, hub.getbot() )
            return PROCESSED
        end
    end
    --// permission with regard to the target
    if ( ( permission[ user_level ] or 0 ) < target_level ) then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    --// delreg
    local _, err = hub.delreguser( target_firstnick )
    if err then
        user:reply( msg_error .. err, hub.getbot() )
    else
        description_del( target_firstnick ) -- remove reg description if it exists (cmd_reg_descriptions.tbl)
        if ban then ban.del( target_firstnick ) end -- remove ban if it exists (cmd_ban_bans.tbl)
        if block then block.del( target_firstnick ) end -- remove block if it exists (etc_trafficmanager.tbl)
        --// report
        local message
        if reason ~= "" then
            blacklist_add( target_firstnick, user_nick, reason ) -- add target to blacklist
            message = utf.format( msg_ok2, target_nick, user_nick, reason )
        else
            message = utf.format( msg_ok, target_nick, user_nick )
        end
        user:reply( message, hub.getbot() )
        report.send( report_activate, report_hubbot, report_opchat, llevel, message )
        --// if target is online: disconnect
        if target then
            local del_msg = ( reason ~= "" ) and utf.format( msg_del_reason, reason ) or msg_del
            target:kill( "ISTA 230 " .. hub.escapeto( del_msg ) .. "\n", "TL-1" )
        end
        --// refresh "cfg/user.tbl.bak"
        cfg.checkusers()
        audit.fire( audit.build( "reg.remove", user,
            { nick = target_firstnick },
            ( reason ~= "" and reason or nil ),
            { blacklisted = ( reason ~= "" ) } ) )
    end
    return PROCESSED
end

-- HTTP API endpoint (#82 registered-users family PR-6, #236).
-- Coexist with the ADC `+delreg` chat-cmd above. Registered via
-- raw `hub.http_register` because the resource is the nick-keyed
-- registered-users family (§10.2). X-Confirm enforcement is
-- router-side (`core/http_router.lua` `_xconfirm_required` table
-- already lists `DELETE /v1/registered/{nick}`) - the handler
-- does NOT re-check.
--
-- The ADC-side `cmd_delreg_permission` ladder (admin can only
-- delreg users below their own ceiling) does NOT apply on the
-- HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
--
-- HTTP-only scope: this endpoint handles regged-user removal.
-- The ADC `+delreg` chat-cmd has a secondary path that removes a
-- nick from `cmd_delreg_blacklist.tbl` when the nick is NOT
-- regged but IS blacklisted; that blacklist-only path is
-- intentionally out of scope here and belongs to a future
-- `DELETE /v1/blacklist/{nick}` endpoint owned by `etc_blacklist`.
local http_handler_delreguser = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )

    -- Optional reason: empty / absent => no blacklist entry
    -- (matches ADC `+delreg nick <NICK>` without trailing reason).
    -- Non-empty reason adds the target to the cmd_delreg
    -- blacklist with date + by-label snapshots.
    local body = req.body or {}
    local clean_reason = ""
    if body.reason ~= nil then
        if type( body.reason ) ~= "string" then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "`reason` must be a string" } }
        end
        clean_reason = util.strip_control_bytes( body.reason )
    end

    local regusers_list, regnicks, _ = hub.getregusers()
    local profile = regnicks[ nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "'" } }
    end
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "' (bots are not addressable via /v1/registered)" } }
    end

    local target_level = tonumber( profile.level ) or 0

    -- Resolve online target FIRST so we can kick before persistence
    -- mutates the regnicks index (saveusers via delreguser may
    -- reload the array).
    local target_user
    if activate and prefix_table then
        local prefix = hub.escapeto( prefix_table[ target_level ] or "" )
        target_user = hub.isnickonline( prefix .. nick )
    else
        target_user = hub.isnickonline( nick )
    end

    local _, err = hub.delreguser( nick )
    if err then
        return { status = 500, error = { code = "E_INTERNAL",
            message = "hub.delreguser failed: " .. tostring( err ) } }
    end

    -- Cascade cleanups - same as the ADC path: remove the
    -- comment (cmd_reg_descriptions.tbl), remove any ban entry,
    -- remove any trafficmanager block. ban / block imports may
    -- be unavailable in stripped deployments (#98).
    description_del( nick )
    if ban then ban.del( nick ) end
    if block then block.del( nick ) end

    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local by_label = ( actor_label:gsub( "[%s]+", "_" ) )
    if by_label == "" then by_label = "http-api" end

    local blacklisted = false
    if clean_reason ~= "" then
        blacklist_add( nick, by_label, clean_reason )
        blacklisted = true
    end

    -- Refresh the user.tbl.bak backup (matches ADC v0.29 path).
    cfg.checkusers()

    -- Kick the online target with the appropriate message + TL-1
    -- (immediate kick); they get an explanation banner before
    -- the disconnect. Matches the ADC `+delreg` semantics.
    local online_kicked = false
    if target_user and not target_user:isbot() then
        local del_msg = ( clean_reason ~= "" )
            and utf.format( msg_del_reason, clean_reason )
            or msg_del
        target_user:kill( "ISTA 230 " .. hub.escapeto( del_msg ) .. "\n", "TL-1" )
        online_kicked = true
    end

    -- Audit / opchat report mirroring the ADC `+delreg`
    -- msg_ok / msg_ok2 split.
    local message
    if clean_reason ~= "" then
        message = utf.format( msg_ok2, nick, by_label, clean_reason )
    else
        message = utf.format( msg_ok, nick, by_label )
    end
    report.send( report_activate, report_hubbot, report_opchat, llevel, message )
    audit.fire( audit.build( "reg.remove",
        { nick = by_label, sid = "<http>" },
        { nick = nick },
        ( clean_reason ~= "" and clean_reason or nil ),
        { blacklisted = blacklisted, online_kicked = online_kicked } ) )

    return { status = 200, data = {
        action        = "delreg",
        nick          = nick,
        blacklisted   = blacklisted,
        online_kicked = online_kicked,
    } }
end

hub.setlistener( "onStart", {},
    function()
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub.import( "etc_usercommands" )  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu_ct1, cmd, { "nick", "%[line:" .. ucmd_nick .. "]", "%[line:" .. ucmd_reason .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct2, cmd, { "nicku", "%[userNI]", "%[line:" .. ucmd_reason .. "]" }, { "CT2" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )

        if hub.http_register then
            hub.http_register( "DELETE", "/v1/registered/{nick}", "admin", http_handler_delreguser, {
                plugin = scriptname,
                description = "delreg a registered user (= ADC `+delreg nick`); requires `X-Confirm: yes` (§4.6). humans only - bots return 404. body { reason?: string } - non-empty reason also adds the nick to the cmd_delreg blacklist",
                request_schema = {
                    reason = { type = "string", max_length = 256 },
                },
                response_schema = {
                    action        = { type = "string",  required = true },
                    nick          = { type = "string",  required = true },
                    blacklisted   = { type = "boolean", required = true },
                    online_kicked = { type = "boolean", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )