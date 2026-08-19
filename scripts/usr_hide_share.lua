--[[

    usr_hide_share.lua by pulsar

        Usage: [+!#]hideshare <NICK>

        v0.7:
            - carry a hidden-share flag over to the new nick on
              +nickchange / HTTP rename. hide_share_tbl is keyed by
              firstnick; a rename only updated user.tbl, so the flag was
              silently dropped on rename and the user's share became
              visible again. An onAudit tap on reg.nickchange now re-keys
              hide_share_tbl (covers the ADC self / othernick / othernicku
              paths AND the HTTP API).

        v0.6:
            - resolve an online target by firstnick when a nick-prefix is
              active: usr_nick_prefix re-keys the hub's nick table to the
              PREFIXED nick, so `+hideshare <base nick>` silently hit the
              "user offline" path (no hide/unhide) on a prefixed online
              user. The hide store already keys by firstnick, so only
              resolution was affected. Same firstnick-fallback idiom as
              etc_trafficmanager (upstream luadch/luadch#240). Nick-prefix
              resolution fix.

        v0.5:
            - also hide the shared-file count (ADC INF SF), not just the
              share size (SS) - the file count stayed visible in clients

        v0.4:
            - removed table lookups
            - simplify 'activate' logic

        v0.3:
            - imroved user:kill()

        v0.2:
            - added help, lang
            - possibility to manually hide/unhide usershares
                - added ucmd, onbmsg
                - renamed "usr_hide_share_permission" to "usr_hide_share_restrictions"
                - using "usr_hide_share_permission" for cmd permissions
            - some english translation improvements  / thx Devious

        v0.1:
            - this script hides share of specified levels

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "usr_hide_share"
local scriptversion = "0.7"

local cmd = "hideshare"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local activate = cfg.get( "usr_hide_share_activate" )
local permission = cfg.get( "usr_hide_share_permission" )
local restrictions = cfg.get( "usr_hide_share_restrictions" )

local path = "scripts/data/usr_hide_share.tbl"

--// msgs
local help_title = "usr_hide_share.lua"
local help_usage = lang.help_usage or "[+!#]hideshare <NICK>"
local help_desc = lang.help_desc or "Hide/unhide the share of a user"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_isbot = lang.msg_isbot or "User is a bot."
local msg_notonline = lang.msg_notonline or "User is offline."
local msg_usage = lang.msg_usage or "Usage: [+!#]hideshare <NICK>"

local msg_default = lang.msg_default or "This user's share is hidden due to permission levels."
local msg_hide_user = lang.msg_hide_user or "Share hidden for: %s"
local msg_hide_target = lang.msg_hide_target or "Your share was hidden by: %s"
local msg_unhide_user = lang.msg_unhide_user or "Share restored for: %s  |  User was disconnected"
local msg_unhide_target = lang.msg_unhide_target or "Your share was restored by: %s  |  Therefore, you will be disconnected now"

local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Hide//unhide share", "OK" }

--// functions
local checkOnListener
local checkOnCommand
local onbmsg
local find_online_by_firstnick


----------
--[CODE]--
----------

if not activate then
   hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
   return
end

local hide_share_tbl = util.loadtable( path ) or {}
local oplevel = util.getlowestlevel( permission )
local share = "0"

--// check user on listener
checkOnListener = function( user, cmdx, se )
    if restrictions[ user:level() ] or hide_share_tbl[ user:firstnick() ] then
        -- ADC INF: SS = share size, SF = shared-file count. Both must be
        -- zeroed or the client still shows how many files the user shares.
        if cmdx then cmdx:setnp( "SS", share ); cmdx:setnp( "SF", share ) end
        user:inf():setnp( "SS", share )
        user:inf():setnp( "SF", share )
        if se then hub.sendtoall( "BINF " .. user:sid() .. " SS" .. share .. " SF" .. share .. "\n" ) end
    end
end

--// check user by using command
checkOnCommand = function( user, target )
    if restrictions[ target:level() ] then
        user:reply( msg_default, hub.getbot() )
    else
        if type( hide_share_tbl[ target:firstnick() ] ) == "nil" then
            --// add user to db
            hide_share_tbl[ target:firstnick() ] = 1
            util.savetable( hide_share_tbl, "hide_share_tbl", path )
            --// target share flag manipulation (SS = size, SF = file count)
            target:inf():setnp( "SS", share )
            target:inf():setnp( "SF", share )
            hub.sendtoall( "BINF " .. target:sid() .. " SS" .. share .. " SF" .. share .. "\n" )
            --// report
            target:reply( utf.format( msg_hide_target, user:nick() ), hub.getbot() )
            user:reply( utf.format( msg_hide_user, target:nick() ), hub.getbot() )
        else
            --// remove user from db
            hide_share_tbl[ target:firstnick() ] = nil
            util.savetable( hide_share_tbl, "hide_share_tbl", path )
            --// report & disconnect
            target:kill( "ISTA 230 " .. hub.escapeto( utf.format( msg_unhide_target, user:nick() ) ) .. "\n", "TL300" )
            user:reply( utf.format( msg_unhide_user, target:nick() ), hub.getbot() )
        end
    end
end

hub.setlistener( "onStart", {},
    function()
        --// help, ucmd, hucmd
        local help = hub.import( "cmd_help" )
        if help then help.reg( help_title, help_usage, help_desc, oplevel ) end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct2_1, cmd, { "%[userNI]" }, { "CT2" }, oplevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, oplevel ) )
        --// hide share
        for sid, user in pairs( hub.getusers() ) do
            checkOnListener( user, false, true )
        end
        return nil
    end
)

hub.setlistener( "onExit", {},
    function()
        for sid, user in pairs( hub.getusers() ) do
            checkOnListener( user, false, true )
        end
        return nil
    end
)

hub.setlistener( "onInf", {},
    function( user, cmdx )
        checkOnListener( user, cmdx, false )
        return nil
    end
)

hub.setlistener( "onConnect", {},
    function( user )
        checkOnListener( user, false, false )
        return nil
    end
)

-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub.isnickonline( <base
-- nick> ) returns nil for a prefixed online user and this command would
-- silently take the "user offline" path (no hide/unhide). firstnick is
-- the ORIGINAL nick, captured once at login and never re-keyed, so
-- iterating it is robust against ANY nick-prefix scheme (the hide store
-- already keys by firstnick). Same idiom as etc_trafficmanager's
-- find_online_by_firstnick (closed upstream luadch/luadch#240). Kept
-- plugin-local rather than changed in core hub.isnickonline, whose
-- exact-current-nick semantics back availability checks elsewhere.
-- firstnick fallback -> the shared core helper (#537 dedup).
find_online_by_firstnick = hub.find_online_by_firstnick

onbmsg = function( user, command, parameters )
    local user_nick, user_level = user:nick(), user:level()
    local target_nick, target_firstnick, target_level
    local param = utf.match( parameters, "^(%S+)" )
    --// [+!#]hideshare <NICK>
    if param then
        if user_level < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local target = hub.isnickonline( param ) or find_online_by_firstnick( param )
        if target then
            if not target:isbot() then
                checkOnCommand( user, target )
            else
                user:reply( msg_isbot, hub.getbot() )
            end
        else
            user:reply( msg_notonline, hub.getbot() )
        end
        return PROCESSED
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

--// keep a hidden-share flag attached to its user across a nick rename.
-- hide_share_tbl is keyed by firstnick; +nickchange (and the HTTP
-- rename) renames the user in user.tbl but not here, so without this
-- the flag was silently dropped on rename and the share became visible
-- again. audit.fire is unconditional (core/audit.lua), so one onAudit
-- tap catches every reg.nickchange - the ADC self / othernick /
-- othernicku paths AND the HTTP API. Returns nil (never PROCESSED) so
-- the etc_auditlog / http_events onAudit taps still receive the event.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        if old_nick == new_nick or hide_share_tbl[ old_nick ] == nil then return nil end
        -- If a stale entry already sits under the new nick, the renamed
        -- user's own flag wins - overwrite keeps it intact.
        hide_share_tbl[ new_nick ] = hide_share_tbl[ old_nick ]
        hide_share_tbl[ old_nick ] = nil
        util.savetable( hide_share_tbl, "hide_share_tbl", path )
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- Internal test seams (nick-prefix resolution regression). `_`-prefixed
-- per the repo convention for non-contract, test-only exports (see
-- docs/PLUGIN_API.md §8).
return {
    _onbmsg                   = onbmsg,
    _find_online_by_firstnick = find_online_by_firstnick,
}