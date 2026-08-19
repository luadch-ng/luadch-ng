--[[

    cmd_setpas.lua by blastbeat

        - this script adds a command "setpas" to set or change the password of your own or a user by nick
        - usage: [+!#]setpass nick <nick> <password>
        - [+!#]setpass myself <password> sets your own pasword

        v0.24:
            - audit_redact_body = true on PUT /v1/registered/{nick}/password
              so the new password does not land verbatim in api_audit.log.
              The body field for this route now logs as `[redacted]`.

        v0.23:
            - #243 family-wide consistency sweep: ADC `+setpass nick`
              path now uses the `activate and prefix_table` guard
              + `prefix_table[level] or ""` fallback, matching the
              HTTP path's pattern (PR-3 #241). cmd_setpass itself
              does not actually crash pre-fix because
              `hub.escapeto`'s C wrapper defaults nil to "" via
              `luaL_optstring` - but the explicit guard survives
              any future wrapper change and matches cmd_upgrade
              (the actual crash site, no escapeto wrapper).

        v0.22:
            - HTTP API (#82 registered-users family PR-3, #236):
                - PUT /v1/registered/{nick}/password   (admin; = ADC `+setpass nick`)
            - Coexist with ADC `+setpass`; ADC path unchanged.

        v0.21: by Aybo
            - drop the password echo from the *caller's* reply: when an admin
              types `+setpass nick Bob ...` they already know the value;
              echoing it back puts the cleartext into their chat history for
              no benefit. The *target* (Bob) still gets the new password via
              msg_ok2 - they need it to log in. Same fix on the
              `+setpass myself ...` path: caller IS target, knows the value.
              Closes one of four sub-tasks of #95; cmd_reg auto-generated
              passwords stay as-is (Phase-8 design call).

        v0.20: by pulsar
            - rightclick visibility according to minlevel; fix #179  / thx Sopor

        v0.19: by pulsar
            - changed check order  / thx Sopor

        v0.18: by pulsar
            - fix #101 / thx Sopor
                - fix typo
                - removed table lookups
            - add permission check to change own password

        v0.17: by blastbeat
            - use hub.getregusers() to fix #25

        v0.16: by pulsar
            - renamed "cmd_setpass_min_length" to "min_password_length"
            - added "max_password_length"
            - renamed "msg_length" to "msg_min_length"
            - added "msg_max_length"

        v0.15: by pulsar
            - renamed "cmd_setpas_permission" to "cmd_setpass_permission"
            - renamed "cmd_setpas_advanced_rc" to "cmd_setpass_advanced_rc"
            - renamed "cmd_setpas_min_length" to "cmd_setpass_min_length"

        v0.14: by pulsar
            - changed command "setpas" to "setpass"  / requested by Sopor
            - add "cmd_setpas_min_length" to set min length of the password  / requested by Sopor

        v0.13: by pulsar
            - removed "cmd_setpas_oplevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_setpas_oplevel"

        v0.12: by pulsar
            - removed new method to save userdatabase

        v0.11: by pulsar
            - improved method to save userdatabase

        v0.10: by pulsar
            - fix bug with target user object
            - additional ct1 rightclick
            - possibility to toggle advanced ct2 rightclick (shows complete userlist)
                - export var to "cfg/cfg.tbl"

        v0.09: by pulsar
            - fix small bug with "undeclared var"

        v0.08: by pulsar
            - possibility to change the password of the users over the userlist rightklick (oplevel)
            - caching new table lookups

        v0.07: by pulsar
            - fix missing var "msg_usage"

        v0.06: by pulsar
            - the password of an offline user can change now too
            - rewriting code
            - added oplevel for advanced rightclick

        v0.05: by pulsar
            - changed rightclick style

        v0.04: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.03: by pulsar
            - fixed bug: user can change her own password now

        v0.02: by blastbeat
            - updated script api
            - regged hubcommand

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_setpass"
local scriptversion = "0.24"

local cmd = "setpass"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// imports
local onbmsg, help, ucmd, hubcmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local permission = cfg.get( "cmd_setpass_permission" ) or { }
local permission_own_pw = cfg.get( "cmd_setpass_permission_own_pw" ) or { }
local activate = cfg.get( "usr_nick_prefix_activate" )
local prefix_table = cfg.get( "usr_nick_prefix_prefix_table" )
local advanced_rc = cfg.get( "cmd_setpass_advanced_rc" )
local min_length = cfg.get( "min_password_length" )
local max_length = cfg.get( "max_password_length" )

--// msgs
local help_title = "cmd_setpass.lua"
local help_usage = lang.help_usage or "[+!#]setpass nick <NICK> <PASS>  /  [+!#]setpass nick myself <PASS>"
local help_desc = lang.help_desc or "Sets password of a user or yourself"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_nochange = lang.msg_nochange or "There are no changes needed."
local msg_god = lang.msg_god or "You are not allowed to change the nick of this user."
local msg_reg = lang.msg_reg or "User is not regged or a bot."
local msg_ok = lang.msg_ok or "Password was changed."
local msg_ok2 = lang.msg_ok2 or "Your Password was changed to: "
local msg_usage = lang.msg_usage or "Usage: [+!#]setpass nick <NICK> <PASS>  /  [+!#]setpass nick myself <PASS>"
local msg_min_length = lang.msg_min_length or "Minimum length of the Password is: %s"
local msg_max_length = lang.msg_max_length or "Maximum length of the Password is: %s"

local ucmd_menu_ct1_0 = lang.ucmd_menu_ct1_0 or { "User", "Control", "Change", "Password", "by Nick" }
local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "About You", "change password" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or "User"
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or "Control"
local ucmd_menu_ct1_4 = lang.ucmd_menu_ct1_4 or "Change"
local ucmd_menu_ct1_5 = lang.ucmd_menu_ct1_5 or "password"
local ucmd_menu_ct1_6 = lang.ucmd_menu_ct1_6 or "by Nick from List"
local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Change", "password" }

local ucmd_pass = lang.ucmd_pass or "Password:"
local ucmd_nick = lang.ucmd_nick or "Nickname:"


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission_own_pw )
local oplevel = util.getlowestlevel( permission )

onbmsg = function( user, command, parameters )
    local user_tbl = hub.getregusers()
    local user_nick = user:nick()
    local user_level = user:level()
    local user_firstnick = user:firstnick()
    local target, prefix
    local myself = false
    local target_isbot = true
    local target_isregged = false
    local target_firstnick, target_nick, target_level, target_prefix

    if not user:isregged() then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end

    local by, targetname, pass = utf.match( parameters, "^(%S+) (%S+) (%S+)$" )

    if not pass then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end

    if targetname == "myself" then
        myself = true
        targetname = user_firstnick
    end
    if myself then
        if not permission_own_pw[ user_level ] then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
    end

    if pass:len() < min_length then
        user:reply( utf.format( msg_min_length, min_length ), hub.getbot() )
        return PROCESSED
    end
    if pass:len() > max_length then
        user:reply( utf.format( msg_max_length, max_length ), hub.getbot() )
        return PROCESSED
    end

    if by == "nicku" then target_prefix = true end

    if not target_prefix then
        for k, v in pairs( user_tbl ) do
            if not user_tbl[ k ].is_bot then
                if user_tbl[ k ].nick == targetname then
                    target_isbot = false
                    target_isregged = true
                    target_nick = user_tbl[ k ].nick
                    target_level = user_tbl[ k ].level
                    if target_nick == user_firstnick then
                        if user_tbl[ k ].password == pass then
                            user:reply( msg_nochange, hub.getbot() )
                            return PROCESSED
                        else
                            user_tbl[ k ].password = pass
                            user:reply( msg_ok, hub.getbot() )
                            cfg.saveusers( user_tbl )
                            audit.fire( audit.build( "reg.password.change", user,
                                { nick = target_nick, level = user_level },
                                nil, { self_change = true } ) )
                            return PROCESSED
                        end
                    end
                    if ( permission[ user_level ] or 0 ) < target_level then
                        user:reply( msg_god, hub.getbot() )
                        return PROCESSED
                    else
                        if activate and prefix_table then
                            -- `or ""` defence-in-depth: hub.escapeto's
                            -- C wrapper happens to default nil to ""
                            -- (luaL_optstring), so this site does NOT
                            -- crash pre-fix on cfg drift - but the
                            -- explicit guard matches the family-wide
                            -- pattern and survives any future
                            -- escapeto wrapper change. cmd_upgrade
                            -- is the actual crash site (no escapeto
                            -- wrapper). #243.
                            prefix = hub.escapeto( prefix_table[ target_level ] or "" )
                            target = hub.isnickonline( prefix .. target_nick )
                        else
                            target = hub.isnickonline( target_nick )
                        end
                        if user_tbl[ k ].password == pass then
                            user:reply( msg_nochange, hub.getbot() )
                            return PROCESSED
                        else
                            user_tbl[ k ].password = pass
                            user:reply( msg_ok, hub.getbot() )
                            if target then
                                target:reply( msg_ok2 .. pass, hub.getbot(), hub.getbot() )
                            end
                            cfg.saveusers( user_tbl )
                            audit.fire( audit.build( "reg.password.change", user,
                                { nick = target_nick, level = target_level }, nil,
                                { self_change = false } ) )
                            return PROCESSED
                        end
                    end
                end
            end
        end
    else
        for sid, target in pairs( hub.getusers() ) do
            if target:nick() == targetname then
                target_level = target:level()
                target_firstnick = target:firstnick()
                for k, v in pairs( user_tbl ) do
                    if not user_tbl[ k ].is_bot then
                        if user_tbl[ k ].nick == target_firstnick then
                            target_isbot = false
                            target_isregged = true
                            if target_firstnick == user_firstnick then
                                if user_tbl[ k ].password == pass then
                                    user:reply( msg_nochange, hub.getbot() )
                                    return PROCESSED
                                else
                                    user_tbl[ k ].password = pass
                                    user:reply( msg_ok, hub.getbot() )
                                    cfg.saveusers( user_tbl )
                                    audit.fire( audit.build( "reg.password.change", user,
                                        { nick = target_firstnick, level = user_level },
                                        nil, { self_change = true } ) )
                                    return PROCESSED
                                end
                            end
                            if ( permission[ user_level ] or 0 ) < target_level then
                                user:reply( msg_god, hub.getbot() )
                                return PROCESSED
                            else
                                if user_tbl[ k ].password == pass then
                                    user:reply( msg_nochange, hub.getbot() )
                                    return PROCESSED
                                else
                                    user_tbl[ k ].password = pass
                                    user:reply( msg_ok, hub.getbot() )
                                    target:reply( msg_ok2 .. pass, hub.getbot(), hub.getbot() )
                                    cfg.saveusers( user_tbl )
                                    audit.fire( audit.build( "reg.password.change", user,
                                        target, nil, { self_change = false } ) )
                                    return PROCESSED
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    if not target_isregged then
        user:reply( msg_reg, hub.getbot() )
        return PROCESSED
    end
    if target_isbot then
        user:reply( msg_reg, hub.getbot() )
        return PROCESSED
    end
end

-- HTTP API endpoint (#82 registered-users family PR-3, #236).
-- Coexist with the ADC `+setpass` chat-cmd above. Registered via
-- raw `hub.http_register` because the resource is a sub-property
-- of the registered-users nick-keyed family (§10.2). Mirrors the
-- PR-1 / PR-2 pattern.
--
-- The ADC-side `cmd_setpass_permission` ladder (admin can only
-- change passwords below their own ceiling) does NOT apply on
-- the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate (consistent with all prior #82 phases).
local http_handler_set_password = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    if type( body.password ) ~= "string" or body.password == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty `password` field" } }
    end
    local password = util.strip_control_bytes( body.password )
    if password:find( "%s" ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "`password` may not contain whitespace" } }
    end
    -- Defensive nil-guards: cfg.min_password_length /
    -- cfg.max_password_length default to 10 / 32 in cfg_defaults
    -- but a partial-migration / corrupt cfg.tbl could leave them
    -- nil. Comparing `#str < nil` would raise on the HTTP path
    -- and surface as a 500 instead of a clean 400; fall back to
    -- the documented defaults instead.
    local pmin = tonumber( min_length ) or 10
    local pmax = tonumber( max_length ) or 32
    if #password < pmin then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = utf.format( "password length must be at least %s characters", pmin ) } }
    end
    if #password > pmax then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = utf.format( "password length must be at most %s characters", pmax ) } }
    end

    local regusers_list, regnicks, _ = hub.getregusers()
    local profile = regnicks[ nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "'" } }
    end
    -- Bots have ADC-side passwords too (for opchat bot accounts)
    -- but rotating them via the registered-users surface would be
    -- inconsistent with the humans-only contract established in
    -- PR-1 GET list / PR-2 GET / PR-1 PATCH. Reject for symmetry.
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "' (bots are not addressable via /v1/registered)" } }
    end

    -- Mutate in place: regnicks values share table identity with
    -- regusers_list entries (see hub.reguser; same table is
    -- assigned to both indexes). saveusers persists the array.
    profile.password = password
    cfg.saveusers( regusers_list )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "reg.password.change",
        { nick = actor_label, sid = "<http>" },
        { nick = nick, level = tonumber( profile.level ) or 0 },
        nil, { self_change = false } ) )

    -- Notify the target if currently online so they know the new
    -- password (matches the ADC msg_ok2 behaviour). Respects the
    -- nick-prefix activation in cfg.tbl. `prefix_table` itself
    -- may be nil (operator wiped usr_nick_prefix_prefix_table);
    -- guard before indexing.
    local online_notified = false
    local target_user
    if activate and prefix_table then
        local prefix = hub.escapeto( prefix_table[ profile.level ] or "" )
        target_user = hub.isnickonline( prefix .. nick )
    else
        target_user = hub.isnickonline( nick )
    end
    -- `not target_user:isbot()` is belt-and-braces: the
    -- profile.is_bot bot-guard above already 404'd, so any
    -- `target_user` here must be a human. Kept as defensive
    -- check in case a future code path lets a bot through.
    if target_user and not target_user:isbot() then
        target_user:reply( msg_ok2 .. password, hub.getbot(), hub.getbot() )
        online_notified = true
    end

    return { status = 200, data = {
        action          = "password-set",
        nick            = nick,
        online_notified = online_notified,
    } }
end

hub.setlistener( "onStart", { },
    function( )
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )    -- reg help
        end
        ucmd = hub.import( "etc_usercommands" )    -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu_ct1_1, cmd, { "nick", "myself", "%[line:" .. ucmd_pass .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_0, cmd, { "nick", "%[line:" .. ucmd_nick .. "]", "%[line:" .. ucmd_pass .. "]" }, { "CT1" }, oplevel )
            if advanced_rc then
                local regusers, reggednicks, reggedcids = hub.getregusers( )
                local usertbl = {}
                for i, user in ipairs( regusers ) do
                    if ( user.is_bot ~=1 ) and user.nick then
                      table.insert( usertbl, user.nick )
                    end
                end
                table.sort( usertbl )
                for _, nick in pairs( usertbl ) do
                    ucmd.add( { ucmd_menu_ct1_2, ucmd_menu_ct1_3, ucmd_menu_ct1_4, ucmd_menu_ct1_5, ucmd_menu_ct1_6, nick }, cmd, { "nick", nick, "%[line:" .. ucmd_pass .. "]" }, { "CT1" }, oplevel )
                end
            end
            ucmd.add( ucmd_menu_ct2_1, cmd, { "nicku", "%[userNI]", "%[line:" .. ucmd_pass .. "]" }, { "CT2" }, oplevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )    -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel, { secret = true } ) ) -- #356 f/u: setpass carries a password inline; keep swallowing its forgot-prefix "cmd <args>" form

        if hub.http_register then
            hub.http_register( "PUT", "/v1/registered/{nick}/password", "admin", http_handler_set_password, {
                plugin = scriptname,
                description = "rotate the password of a registered user (= ADC `+setpass nick`); humans only - bots return 404",
                -- Body is the new password verbatim; redact from
                -- api_audit.log per §6.8.
                audit_redact_body = true,
                request_schema = {
                    password = { type = "string", required = true, max_length = 256 },
                },
                response_schema = {
                    action          = { type = "string",  required = true },
                    nick            = { type = "string",  required = true },
                    online_notified = { type = "boolean", required = true },
                },
            } )
        end
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )