--[[

    cmd_nickchange.lua by pulsar

        description: this script adds a command "nickchange" to change the nick of your own

        usage: [+!#]nickchange <new_nick>

        note: this script needs "nick_change = true" in "cfg/cfg.tbl"

        v2.1:
            - #243 family-wide consistency sweep: ADC `+nickchange
              othernick` path now uses the `activate and prefix_table`
              guard + `prefix_table[level] or ""` fallback, matching
              the HTTP path's pattern (PR-4 #242). cmd_nickchange
              itself does not actually crash pre-fix because
              `hub.escapeto`'s C wrapper defaults nil to "" via
              `luaL_optstring` - but the explicit guard survives
              any future wrapper change. cmd_upgrade is the only
              actual crash site in the family (no escapeto wrapper).

        v2.0:
            - HTTP API (#82 registered-users family PR-4, #236):
                - PUT /v1/registered/{nick}/nick   (admin; = ADC `+nickchange othernick`)
            - Coexist with ADC `+nickchange`; ADC path unchanged.
            - Major version bump (1.x -> 2.x) reflects the new HTTP
              surface, not a breaking change on the ADC side.

        v1.9: by Aybo
            - drop file-scope cache of hub.getregusers() in favour of
              per-function fresh fetches. The cached reference went
              stale after hub.updateusers() reassigned _regusers, so
              subsequent +nickchange operations saved a stale snapshot
              to disk and silently lost any +reg entries added in
              between. Most plausible root cause for upstream
              luadch#189 ("Registered users suddenly loses their
              accounts").

        v1.8:
            - using "TL-1" for disconnects  / thx Sopor
                - fix #182 -> https://github.com/luadch/luadch/issues/182

        v1.7:
            - fix nil error in cmd_param_3 part  /thx Sopor
            - add botcheck

        v1.6:
            - added "hub.updateusers()"
                - fix #140 -> https://github.com/luadch/luadch/issues/140
            - changed visuals
            - removed table lookups

        v1.5:
            - fix #128
                - detect unknown nicks

        v1.4:
            - removed "hub.reloadusers()"
            - using "hub.getregusers()" instead of "util.loadtable()"

        v1.3:
            - added min_length/max_length restrictions

        v1.2:
            - improved user:kill()

        v1.1:
            - removed send_report() function, using report import functionality now
            - added description_check() function to change nick in the "cmd_reg_descriptions.tbl" too  / thx Sopor

        v1.0:
            - check if opchat is activated

        v0.9:
            - removed new method to save userdatabase

        v0.8:
            - improved method to save userdatabase

        v0.7:
            - added possibility to send report as feed to opchat

        v0.6:
            - additional ct1 rightclick
            - possibility to toggle advanced ct2 rightclick (shows complete userlist)
                - export var to "cfg/cfg.tbl"

        v0.5:
            - add missing level check to cmd_param_3
            - changes in isTaken() function

        v0.4:
            - fix nick taken bug
            - rewriting some code

        v0.3:
            - fix permission bug in cmd_param_1

        v0.2:
            - new check if new nick is already taken
            - possibility to change nick from other users (e.g. for OP)
            - caching new table lookups

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_nickchange"
local scriptversion = "2.1"

local cmd = "nickchange"
local cmd_param_1 = "mynick"
local cmd_param_2 = "othernick"
local cmd_param_3 = "othernicku"

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local nick_change = cfg.get( "nick_change" )
local min_length = cfg.get( "min_nickname_length" )
local max_length = cfg.get( "max_nickname_length" )
local minlevel = cfg.get( "cmd_nickchange_minlevel" )
local oplevel = cfg.get( "cmd_nickchange_oplevel" )
local activate = cfg.get( "usr_nick_prefix_activate" )
local prefix_table = cfg.get( "usr_nick_prefix_prefix_table" )
local advanced_rc = cfg.get( "cmd_nickchange_advanced_rc" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "cmd_nickchange_report" )
local report_hubbot = cfg.get( "cmd_nickchange_report_hubbot" )
local report_opchat = cfg.get( "cmd_nickchange_report_opchat" )

--// database
-- NOTE: user_tbl (= hub.getregusers()) is fetched fresh in every
-- function that needs it. The previous file-scope cache went stale
-- whenever hub.updateusers() reassigned _regusers, and any
-- subsequent +nickchange would then save the stale snapshot back to
-- disk - silently dropping registrations added in between (upstream
-- luadch#189). Always grabbing the live reference at the call site
-- closes that hole.
local description_file = "scripts/data/cmd_reg_descriptions.tbl"

--// msgs
local help_title = "cmd_nickchange.lua"
local help_usage = lang.help_usage or "[+!#]nickchange mynick <new_nick>  /  [+!#]nickchange othernick <old_nick> <new_nick>"
local help_desc = lang.help_desc or "change the nickname"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_denied2 = lang.msg_denied2 or "You are not allowed to change the nick of this user."
local msg_nochange = lang.msg_nochange or "[ NICKCHANGE ]--> There are no changes needed."
local msg_nicktaken = lang.msg_nicktaken or "[ NICKCHANGE ]--> Nick is already taken!"
local msg_ok = lang.msg_ok or "[ NICKCHANGE ]--> Nickname was changed to: "
local msg_disconnect = lang.msg_disconnect or "[ NICKCHANGE ]--> Nickchange successful, please reconnect with your new nick."
local msg_usage = lang.msg_usage or "Usage: [+!#]nickchange mynick <NEW_NICK>  /  [+!#]nickchange othernick <OLD_NICK> <NEW_NICK>"
local msg_length = lang.msg_length or "[ NICKCHANGE ]--> Nickname restrictions min/max: %s/%s"
local msg_op = lang.msg_op or "[ NICKCHANGE ]--> User %s changed his own nickname to: %s"
local msg_op2 = lang.msg_op2 or "[ NICKCHANGE ]--> User %s changed nickname from user: %s  to: %s"
local msg_notfound = lang.msg_notfound or "[ NICKCHANGE ]--> Nick not found."
local msg_bot = lang.msg_bot or "[ NICKCHANGE ]--> User is a bot."

local ucmd_menu_ct1_0 = lang.ucmd_menu_ct1_0 or { "User", "Control", "Change", "Nickname", "by Nick" }
local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "About You", "change nickname" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or "User"
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or "Control"
local ucmd_menu_ct1_4 = lang.ucmd_menu_ct1_4 or "Change"
local ucmd_menu_ct1_5 = lang.ucmd_menu_ct1_5 or "Nickname"
local ucmd_menu_ct1_6 = lang.ucmd_menu_ct1_6 or "by Nick from list"
local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Change", "nickname" }
local ucmd_popup = lang.ucmd_popup or "New nickname:"
local ucmd_popup2 = lang.ucmd_popup2 or "Nickname"

--// functions
local onbmsg, isTaken, isRegged, description_check


----------
--[CODE]--
----------

description_check = function( new_nick, old_nick )
    local tbl = util.loadtable( description_file ) or {}
    for k, v in pairs( tbl ) do
        if k == old_nick then
            local v1 = v[ "tBy" ]
            local v2 = v[ "tReason" ]
            tbl[ new_nick ] = {}
            tbl[ new_nick ][ "tBy" ] = v1
            tbl[ new_nick ][ "tReason" ] = v2
            tbl[ old_nick ] = nil
        end
    end
    util.savetable( tbl, "description_tbl", description_file )
end

--// check if new nick is taken
isTaken = function( oldnick, newnick )
    local user_tbl = hub.getregusers()
    for i, user in ipairs( user_tbl ) do
        if user.nick ~= oldnick then
            if user.nick == newnick then
                return true
            end
        end
    end
    return false
end

--// check if nick is regged
isRegged = function( nick )
    local user_tbl = hub.getregusers()
    for i, user in ipairs( user_tbl ) do
        if user.nick == nick then
            return true
        end
    end
    return false
end

onbmsg = function( user, command, parameters )
    local user_tbl = hub.getregusers()
    local user_level = user:level()
    local user_nick = user:nick()
    local user_firstnick = user:firstnick()
    if not nick_change then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    if not user:isregged() then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    if user_level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end

    local param_1, newnick = utf.match( parameters, "^(%S+)%s(%S+)$" )
    local param_2, oldnickfrom, newnickfrom = utf.match( parameters, "^(%S+)%s(%S+)%s(%S+)$" )

    if ( param_1 == cmd_param_1 ) and newnick then -- mynick
        local target = hub.isnickonline( newnick )
        if target then
            if target:isbot() then
                user:reply( msg_bot, hub.getbot() )
                return PROCESSED
            end
        end
        if string.len( newnick ) > max_length or string.len( newnick ) < min_length then
            user:reply( utf.format( msg_length, min_length, max_length ), hub.getbot() )
            return PROCESSED
        end
        if user_firstnick == newnick then
            user:reply( msg_nochange, hub.getbot() )
            return PROCESSED
        end
        if isTaken( user_firstnick, newnick ) then
            user:reply( msg_nicktaken, hub.getbot() )
            return PROCESSED
        else
            for k, v in pairs( user_tbl ) do
                if user_tbl[ k ].nick == user_firstnick then
                    user_tbl[ k ].nick = newnick
                    user:reply( msg_ok .. newnick, hub.getbot() )
                    user:kill( "ISTA 230 " .. hub.escapeto( msg_disconnect ) .. "\n", "TL-1" )
                    cfg.saveusers( user_tbl )
                    hub.updateusers()
                    description_check( newnick, user_firstnick )
                    local msg = utf.format( msg_op, user_firstnick, newnick )
                    report.send( report_activate, report_hubbot, report_opchat, oplevel, msg )
                    audit.fire( audit.build( "reg.nickchange", user,
                        { nick = newnick }, nil,
                        { previous_nick = user_firstnick, self_change = true } ) )
                    return PROCESSED
                end
            end
        end
    elseif ( param_2 == cmd_param_2 ) and oldnickfrom and newnickfrom then -- othernick
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target = hub.isnickonline( oldnickfrom )
        if target then
            if target:isbot() then
                user:reply( msg_bot, hub.getbot() )
                return PROCESSED
            end
        end
        if oldnickfrom == newnickfrom then
            user:reply( msg_nochange, hub.getbot() )
            return PROCESSED
        end
        if string.len( newnickfrom ) > max_length or string.len( newnickfrom ) < min_length then
            user:reply( utf.format( msg_length, min_length, max_length ), hub.getbot() )
            return PROCESSED
        end
        if not isRegged( oldnickfrom ) then
            user:reply( msg_notfound, hub.getbot() )
            return PROCESSED
        end
        if isTaken( oldnickfrom, newnickfrom ) then
            user:reply( msg_nicktaken, hub.getbot() )
            return PROCESSED
        else
            for k, v in pairs( user_tbl ) do
                if user_tbl[ k ].nick == oldnickfrom then
                    local prefix, target_user
                    local target_level = user_tbl[ k ].level
                    if user_level < target_level then
                        user:reply( msg_denied2, hub.getbot() )
                        return PROCESSED
                    end
                    if activate and prefix_table then
                        -- `or ""` guards both the missing-key case
                        -- (prefix_table has no entry for target_level)
                        -- and the cfg-drift case (operator wiped the
                        -- table while activate=true). Pre-fix the
                        -- nil-index crashed the ADC handler. #243.
                        prefix = hub.escapeto( prefix_table[ target_level ] or "" )
                        target_user = hub.isnickonline( prefix .. oldnickfrom )
                    else
                        target_user = hub.isnickonline( oldnickfrom )
                    end
                    user_tbl[ k ].nick = newnickfrom
                    user:reply( msg_ok .. newnickfrom, hub.getbot() )
                    if target_user then
                        target_user:reply( msg_ok .. newnickfrom, hub.getbot(), hub.getbot() )
                        target_user:kill( "ISTA 230 " .. hub.escapeto( msg_disconnect ) .. "\n", "TL-1" )
                    end
                    cfg.saveusers( user_tbl )
                    hub.updateusers()
                    description_check( newnickfrom, oldnickfrom )
                    local msg = utf.format( msg_op2, user_firstnick, oldnickfrom, newnickfrom )
                    report.send( report_activate, report_hubbot, report_opchat, oplevel, msg )
                    audit.fire( audit.build( "reg.nickchange", user,
                        { nick = newnickfrom }, nil,
                        { previous_nick = oldnickfrom, self_change = false } ) )
                    return PROCESSED
                end
            end
        end
    elseif ( param_2 == cmd_param_3 ) and oldnickfrom and newnickfrom then -- othernicku
        local target, target_level, target_nick, target_firstnick
        target = hub.isnickonline( oldnickfrom )
        if target then
            if target:isbot() then
                user:reply( msg_bot, hub.getbot() )
                return PROCESSED
            end
        else
            user:reply( msg_notfound, hub.getbot() )
            return PROCESSED
        end
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end

        for sid, users in pairs( hub.getusers() ) do
            if users:nick() == oldnickfrom then
                target_level = users:level()
                target_nick = users:nick()
                target_firstnick = users:firstnick()
            end
        end
        if target_firstnick == newnickfrom then
            user:reply( msg_nochange, hub.getbot() )
            return PROCESSED
        end
        if string.len( newnickfrom ) > max_length or string.len( newnickfrom ) < min_length then
            user:reply( utf.format( msg_length, min_length, max_length ), hub.getbot() )
            return PROCESSED
        end
        if isTaken( target_firstnick, newnickfrom ) then
            user:reply( msg_nicktaken, hub.getbot() )
            return PROCESSED
        else
            if user_level < target_level then -- error: attempt to compare number with nil
                user:reply( msg_denied2, hub.getbot() )
                return PROCESSED
            end
            local target = hub.isnickonline( target_nick )
            for k, v in pairs( user_tbl ) do
                if user_tbl[ k ].nick == target_firstnick then
                    user_tbl[ k ].nick = newnickfrom
                    user:reply( msg_ok .. newnickfrom, hub.getbot() )
                    target:reply( msg_ok .. newnickfrom, hub.getbot(), hub.getbot() )
                    target:kill( "ISTA 230 " .. hub.escapeto( msg_disconnect ) .. "\n", "TL-1" )
                    cfg.saveusers( user_tbl )
                    hub.updateusers()
                    description_check( newnickfrom, target_firstnick )
                    local msg = utf.format( msg_op2, user_firstnick, target_firstnick, newnickfrom )
                    report.send( report_activate, report_hubbot, report_opchat, oplevel, msg )
                    audit.fire( audit.build( "reg.nickchange", user,
                        { nick = newnickfrom }, nil,
                        { previous_nick = target_firstnick, self_change = false } ) )
                    return PROCESSED
                end
            end
        end
    else
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end
end

-- HTTP API endpoint (#82 registered-users family PR-4, #236).
-- Coexist with the ADC `+nickchange` chat-cmd above. Registered
-- via raw `hub.http_register` because the resource is a sub-
-- property of the registered-users nick-keyed family (§10.2).
-- Mirrors the PR-1 / PR-2 / PR-3 pattern.
--
-- The ADC-side `cfg.nick_change` global gate + `cmd_nickchange_*level`
-- ladders do NOT apply on the HTTP path: the bearer token's
-- `admin` scope IS the authorisation gate. `cfg.nick_change` is
-- the chat-side self-service feature flag for end users and
-- conceptually does not apply to an operator action via API.
local http_handler_set_nick = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local old_nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    if type( body.new_nick ) ~= "string" or body.new_nick == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty `new_nick` field" } }
    end
    local new_nick = util.strip_control_bytes( body.new_nick )
    -- Match the strictness of PR-3's password whitespace check
    -- via `%s` (rejects tab, CR, vertical tab, form-feed too -
    -- strip_control_bytes replaces those with `?` rather than
    -- deleting them, so an unstripped raw input `"foo\tbar"`
    -- would otherwise survive the lookup as `"foo?bar"`).
    if new_nick:find( "%s" ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "`new_nick` may not contain whitespace" } }
    end
    local nmin = tonumber( min_length ) or 1
    local nmax = tonumber( max_length ) or 64
    if #new_nick < nmin or #new_nick > nmax then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = utf.format( "new nick length must be between %s and %s characters", nmin, nmax ) } }
    end

    local regusers_list, regnicks, _ = hub.getregusers()
    local profile = regnicks[ old_nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. old_nick .. "'" } }
    end
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. old_nick .. "' (bots are not addressable via /v1/registered)" } }
    end

    -- Idempotent: renaming to the same nick is a 200 no-op (no
    -- mutation, no kick). Matches the PR-3 setpass approach -
    -- the ADC msg_nochange UX nicety is intentionally not
    -- replicated on the HTTP surface.
    if new_nick == old_nick then
        return { status = 200, data = {
            action        = "nick-changed",
            nick          = new_nick,
            previous_nick = old_nick,
            online_kicked = false,
        } }
    end

    -- Collision check against the registered set, excluding the
    -- current entry (same shape as the ADC isTaken helper).
    if regnicks[ new_nick ] then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "nick '" .. new_nick .. "' is already registered" } }
    end

    -- Mutate profile in place. regnicks values share table
    -- identity with regusers_list entries (hub.reguser builds
    -- both indexes from the same profile reference).
    profile.nick = new_nick

    -- Order matches the ADC `onbmsg` path: resolve+kick the
    -- online target FIRST while the kill-relevant lookup keys
    -- (the prefixed old nick) are still valid, THEN persist +
    -- rebuild the regnicks index. saveusers must come before
    -- updateusers because the latter reloads from disk.
    local online_kicked = false
    local target_user
    if activate and prefix_table then
        local prefix = hub.escapeto( prefix_table[ profile.level ] or "" )
        target_user = hub.isnickonline( prefix .. old_nick )
    else
        target_user = hub.isnickonline( old_nick )
    end
    if target_user and not target_user:isbot() then
        target_user:kill( "ISTA 230 " .. hub.escapeto( msg_disconnect ) .. "\n", "TL-1" )
        online_kicked = true
    end
    cfg.saveusers( regusers_list )
    -- hub.updateusers() rebuilds the internal regnicks index
    -- after the nick mutation. Without it `regnicks[ old_nick ]`
    -- and `regnicks[ new_nick ]` stay stale until the next
    -- restart; the ADC path calls it for the same reason
    -- (commit-history: fix #140).
    hub.updateusers()
    description_check( new_nick, old_nick )

    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local msg = utf.format( msg_op2, actor_label, old_nick, new_nick )
    report.send( report_activate, report_hubbot, report_opchat, oplevel, msg )
    audit.fire( audit.build( "reg.nickchange",
        { nick = actor_label, sid = "<http>" },
        { nick = new_nick }, nil,
        { previous_nick = old_nick, self_change = false } ) )

    return { status = 200, data = {
        action        = "nick-changed",
        nick          = new_nick,
        previous_nick = old_nick,
        online_kicked = online_kicked,
    } }
end

hub.setlistener( "onStart", {},
    function()
        help = hub.import( "cmd_help" )
        if help then help.reg( help_title, help_usage, help_desc, minlevel ) end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct1_1, cmd, { cmd_param_1, "%[line:" .. ucmd_popup .. "]" }, { "CT1" }, minlevel ) -- mynick - about you
            ucmd.add( ucmd_menu_ct1_0, cmd, { cmd_param_2, "%[line:" .. ucmd_popup2 .. "]", "%[line:" .. ucmd_popup .. "]" }, { "CT1" }, oplevel ) -- othernick - change nickname by NICK
            if advanced_rc then
                local user_tbl = hub.getregusers()
                local usertbl = {}
                for i, user in ipairs( user_tbl ) do
                    if ( user.is_bot ~=1 ) and user.nick then
                      table.insert( usertbl, user.nick )
                    end
                end
                table.sort( usertbl )
                for _, nick in pairs( usertbl ) do
                    ucmd.add( { ucmd_menu_ct1_2, ucmd_menu_ct1_3, ucmd_menu_ct1_4, ucmd_menu_ct1_5, ucmd_menu_ct1_6, nick }, cmd, { cmd_param_2, nick, "%[line:" .. ucmd_popup .. "]" }, { "CT1" }, oplevel )
                end
            end
            ucmd.add( ucmd_menu_ct2_1, cmd, { cmd_param_3, "%[userNI]", "%[line:" .. ucmd_popup .. "]" }, { "CT2" }, oplevel ) -- othernicku
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )

        if hub.http_register then
            hub.http_register( "PUT", "/v1/registered/{nick}/nick", "admin", http_handler_set_nick, {
                plugin = scriptname,
                description = "rename a registered user (= ADC `+nickchange othernick`); kicks the user if online so the client re-connects with the new nick. humans only - bots return 404",
                request_schema = {
                    new_nick = { type = "string", required = true, max_length = 64 },
                },
                response_schema = {
                    action        = { type = "string",  required = true },
                    nick          = { type = "string",  required = true },
                    previous_nick = { type = "string",  required = true },
                    online_kicked = { type = "boolean", required = true },
                },
            } )
        end
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )