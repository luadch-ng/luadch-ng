--[[

    cmd_redirect.lua by pulsar

        usage: [+!#]redirect <NICK> <URL>

        v0.8:
            - resolve an online target by firstnick when a nick-prefix is
              active: usr_nick_prefix re-keys the hub's nick table to the
              PREFIXED nick, so `+redirect <base nick> <url>` silently hit
              the "user offline" path (no redirect) on a prefixed online
              user. Same firstnick-fallback idiom as etc_trafficmanager
              (upstream luadch/luadch#240). Nick-prefix resolution fix.

        v0.7 (retro-noted):
            - split the redirect into the shared do_redirect helper for the
              HTTP POST /v1/users/{sid}/redirect path (#82 Phase 2 PR-2)

        v0.6:
            - changed visuals
            - removed table lookups
            - simplify 'activate' logic

        v0.5:
            - added additional ucmd entry to redirect user to default url
            - changes in "onbmsg" function

        v0.4:
            - removed send_report() function, using report import functionality now
            - small fix

        v0.3:
            - renamed script from "usr_redirect.lua" to "cmd_redirect.lua"
                - therefore changed import vars from cfg.tbl

        v0.2:
            - possibility to redirect single users from userlist  / requested by Andromeda
            - add new table lookups, imports, msgs

        v0.1:
            - this script redirects users, level specified according to redirect_level table

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_redirect"
local scriptversion = "0.9"

local cmd = "redirect"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local levelname = cfg.get( "levels" )
local activate = cfg.get( "cmd_redirect_activate" )
local permission = cfg.get( "cmd_redirect_permission" )
local redirect_level = cfg.get( "cmd_redirect_level" )
local redirect_url = cfg.get( "cmd_redirect_url" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "cmd_redirect_report" )
local report_hubbot = cfg.get( "cmd_redirect_report_hubbot" )
local report_opchat = cfg.get( "cmd_redirect_report_opchat" )
local llevel = cfg.get( "cmd_redirect_llevel" )

--// msgs
local help_title = "usr_redirect.lua"
local help_usage = lang.help_usage or "[+!#]redirect <NICK> <URL>"
local help_desc = lang.help_desc or "Redirect user to url"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]redirect <NICK> <URL>"
local msg_god = lang.msg_god or "You are not allowed to redirect this user."
local msg_isbot = lang.msg_isbot or "User is a bot."
local msg_notonline = lang.msg_notonline or "User is offline."
local msg_redirect = lang.msg_redirect or "[ REDIRECT ]--> User:  %s  was redirected to:  %s"
local msg_report_redirect = lang.msg_report_redirect or "[ REDIRECT ]--> User:  %s  has redirected user:  %s  |  to:  %s"

local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Redirect", "default URL" }
local ucmd_menu_ct2_2 = lang.ucmd_menu_ct2_2 or { "Redirect", "custom URL" }

local ucmd_url = lang.ucmd_url or "Redirect url:"

local msg_report = lang.msg_report or "[ REDIRECT ]--> User:  %s  |  with level:  %s [ %s ]  |  was auto redirected to:  %s"

--// functions
local listener
local is_online
local onbmsg
local find_online_by_firstnick


----------
--[CODE]--
----------

if not activate then
   hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
   return
end

local oplevel = util.getlowestlevel( permission )

-- Shared action helper used by BOTH the ADC `+redirect` chat-cmd
-- path AND the HTTP `POST /v1/users/{sid}/redirect` path (#82
-- Phase 2 PR-2). Performs ONLY the redirect (drives the outbound
-- IQUI's `RD` field via `target:redirect`); does NOT fire the
-- opchat report itself. Returns the formatted (msg_report_str,
-- target_nick, clean_url) tuple so each caller can compose its
-- own surface-specific feedback (operator chat echo for ADC; HTTP
-- response body for the REST surface) and call report.send at the
-- right moment. The multi-value return is tailored to this
-- plugin's two surfaces and is NOT a stable inter-PR contract;
-- each Phase 2 plugin's helper returns whatever its callers need.
--
-- Both `url` and `actor_label` are control-byte sanitised via
-- `util.strip_control_bytes` here (single source of truth across
-- the Phase 2 bundled-plugin migrations - defence in depth around
-- adclib::escape, which only handles ' ', '\n', '\\').
-- The caller is responsible for any policy checks (level
-- hierarchy, bot rejection); the helper trusts its inputs.
local do_redirect = function( target, url, actor_label )
    local clean_url   = util.strip_control_bytes( url )
    local clean_actor = util.strip_control_bytes( actor_label )
    local target_nick = target:nick()
    target:redirect( clean_url )
    local msg_report_str = utf.format( msg_report_redirect, clean_actor, target_nick, clean_url )
    return msg_report_str, target_nick, clean_url
end

listener = function( user )
    if redirect_level[ user:level() ] then
        local report_msg = utf.format( msg_report, user:nick(), user:level(), levelname[ user:level() ], redirect_url )
        user:redirect( redirect_url )
        report.send( report_activate, report_hubbot, report_opchat, llevel, report_msg )
    end
    return nil
end

-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub.isnickonline( <base
-- nick> ) returns nil for a prefixed online user and this command would
-- silently take the "user offline" path (no redirect). firstnick is the
-- ORIGINAL nick, captured once at login and never re-keyed, so iterating
-- it is robust against ANY nick-prefix scheme. Same idiom as
-- etc_trafficmanager's find_online_by_firstnick (closed upstream
-- luadch/luadch#240). Kept plugin-local rather than changed in core
-- hub.isnickonline, whose exact-current-nick semantics back availability
-- checks ("is this nick free?") in cmd_reg / cmd_nickchange.
-- firstnick fallback -> the shared core helper (#537 dedup).
find_online_by_firstnick = hub.find_online_by_firstnick

--// check if target user is online
is_online = function( target )
    local target = hub.isnickonline( target ) or find_online_by_firstnick( target )
    if target then
        if target:isbot() then
            return "bot"
        else
            return target, target:nick(), target:level()
        end
    end
    return nil
end

onbmsg = function( user, command, parameters )
    local target_nick, target_level
    local param, url = utf.match( parameters, "^(%S+) (%S+)" )
    --// [+!#]redirect <NICK> <URL>
    if ( param and url ) then
        if user:level() < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target, target_nick, target_level = is_online( param )
        if target then
            if target ~= "bot" then
                if ( ( permission[ user:level() ] or 0 ) < target_level ) then
                    user:reply( msg_god, hub.getbot() )
                    return PROCESSED
                end
                if url == "default" then url = redirect_url end
                local msg_report_str, t_nick, clean_url = do_redirect( target, url, user:nick() )
                -- Order preserved from v0.6: chat echo to the operator BEFORE
                -- the opchat report fires (the report can hit the same
                -- operator in opchat; historically they saw their own
                -- redirect echo first).
                user:reply( utf.format( msg_redirect, t_nick, clean_url ), hub.getbot() )
                report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report_str )
                audit.fire( audit.build( "user.redirect", user, target, nil, { url = clean_url } ) )
                return PROCESSED
            else
                user:reply( msg_isbot, hub.getbot() )
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

-- HTTP handler body: POST /v1/users/{sid}/redirect (#82 Phase 2 PR-2).
-- Preflight + envelope are owned by util.http_register_user_action
-- (PR-B); the handler below just resolves the url (body field or
-- cfg default fallback), drives the redirect, and returns the
-- url field for the envelope.
--
-- Admin scope. Body: { url: string? }; if `url` is missing or
-- empty, the cfg default (`cmd_redirect_url`) is used - the ADC-
-- side "url=default" sentinel string is intentionally NOT honoured
-- on the HTTP path (clean REST: don't leak internal sentinels
-- into the public API).
--
-- The ADC-side level-hierarchy / oplevel checks do NOT apply on
-- the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
local http_handler_redirect = function( req, target )
    local url = req.body and req.body.url
    if not url or url == "" then
        url = redirect_url    -- cfg default
    end
    if not url or url == "" then
        return nil, { status = 400, error = { code = "E_BAD_INPUT",
            message = "no url given and cfg cmd_redirect_url is unset" } }
    end
    -- The redirected user sees no actor (bare IQUI, no quitmsg), so there is
    -- nothing end-user-facing to attribute; the operator report + audit record
    -- the real operator (req.actor) rather than the API token label (#177 C).
    local actor_label = util_http.operator_label( req )
    local msg_report_str, _t_nick, clean_url = do_redirect( target, url, actor_label )
    -- HTTP path has no operator-chat to echo into; fire the opchat
    -- report directly so an opchat watcher sees a consistent line
    -- regardless of which surface drove the redirect.
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report_str )
    audit.fire( audit.build( "user.redirect",
        { nick = actor_label, sid = "<http>" }, target, nil, { url = clean_url } ) )
    return { url = clean_url }
end

--// script start
hub.setlistener( "onStart", {},
    function()
        --// help, ucmd, hucmd
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct2_1, cmd, { "%[userNI]", "default" }, { "CT2" }, oplevel )
            ucmd.add( ucmd_menu_ct2_2, cmd, { "%[userNI]", "%[line:" .. ucmd_url .. "]" }, { "CT2" }, oplevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, oplevel ) )
        -- HTTP API endpoint (#82 Phase 2 PR-2). The util_http
        -- helper is fail-soft; the whole script returns at module
        -- top if `cmd_redirect_activate` is false, so this
        -- registration is naturally gated on the same cfg flag as
        -- the ADC cmd.
        --
        -- URL scheme is locked to adc:// and adcs:// (case-
        -- insensitive) to keep an admin token from accidentally
        -- redirecting users to a `javascript:`, `file:///`,
        -- `http://evil/`, or other non-hub target. Legacy NMDC's
        -- `dchub://` is out of scope. The ADC chat-cmd path
        -- historically did NOT validate the scheme; this is
        -- defence in depth on the HTTP path only.
        util_http.http_register_user_action( scriptname,
            "POST", "/v1/users/{sid}/redirect", "redirect",
            http_handler_redirect, {
                description = "redirect (move) an online user to a new hub URL by SID; body { url: string optional - falls back to cfg cmd_redirect_url }",
                request_schema = {
                    url = { type = "string", max_length = 1024,
                            pattern = "^[Aa][Dd][Cc][Ss]?://" },
                },
            }
        )
        return nil
    end
)

--// if user connects
hub.setlistener( "onConnect", {}, listener )

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- Internal test seams (nick-prefix resolution regression). `_`-prefixed
-- per the repo convention for non-contract, test-only exports (see
-- docs/PLUGIN_API.md §8).
return {
    _onbmsg                   = onbmsg,
    _find_online_by_firstnick = find_online_by_firstnick,
}