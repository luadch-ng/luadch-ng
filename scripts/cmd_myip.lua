--[[

    cmd_myip.lua by pulsar

        usage: [+!#]myip [<NICK>]

        v0.4:
            - resolve an online target by firstnick when a nick-prefix is
              active: usr_nick_prefix re-keys the hub's nick table to the
              PREFIXED nick, so `+myip <base nick>` silently fell back to
              showing your OWN ip instead of the prefixed online user's.
              Same firstnick-fallback idiom as etc_trafficmanager (upstream
              luadch/luadch#240). Nick-prefix resolution fix (read-only).

        v0.3:
            - small improvements

        v0.2:
            - added userlist rightclick
            - caching some new table lookups

        v0.1:
            - shows your ip

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_myip"
local scriptversion = "0.4"

local cmd = "myip"

local minlevel = 0


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_getbot = hub.getbot()
local hub_debug = hub.debug
local hub_import = hub.import
local hub_isnickonline = hub.isnickonline
local utf_match = utf.match
local utf_format = utf.format

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )

--// msgs
local help_title = "cmd_myip.lua"
local help_usage = lang.help_usage or "[+!#]myip [<NICK>]"
local help_desc = lang.help_desc or "Shows IP from a user or yourself"

local ucmd_menu_ct1 = lang.ucmd_menu_ct1 or { "About You", "show IP" }
local ucmd_menu_ct2 = lang.ucmd_menu_ct2 or { "Show", "IP" }

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_ip = lang.msg_ip or "Your IP is: "
local msg_targetip = lang.msg_targetip or "Username: %s  |  IP: %s"


----------
--[CODE]--
----------

-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub_isnickonline( <base
-- nick> ) returns nil for a prefixed online user and `+myip <base nick>`
-- would silently fall back to showing the caller's own ip. firstnick is
-- the ORIGINAL nick, captured once at login and never re-keyed, so
-- iterating it is robust against ANY nick-prefix scheme. Same idiom as
-- etc_trafficmanager's find_online_by_firstnick (closed upstream
-- luadch/luadch#240). Kept plugin-local rather than changed in core
-- hub.isnickonline, whose exact-current-nick semantics back availability
-- checks elsewhere.
-- firstnick fallback -> the shared core helper (#537 dedup).
local find_online_by_firstnick = hub.find_online_by_firstnick

local onbmsg = function( user, command, parameters )
    local user_level = user:level()
    local user_ip = user:ip()
    local target_firstnick, target_ip
    if user_level < minlevel then
        user:reply( msg_denied, hub_getbot )
        return PROCESSED
    end
    local param = utf_match( parameters, "^(%S+)$" )
    if param then
        local target = hub_isnickonline( param ) or find_online_by_firstnick( param )
        if target then
            target_firstnick = target:firstnick()
            target_ip = target:ip()
            local msg = utf_format( msg_targetip, target_firstnick, target_ip )
            user:reply( msg, hub_getbot )
            return PROCESSED
        end
    end
    user:reply( msg_ip .. user_ip, hub_getbot )
    return PROCESSED
end

hub.setlistener( "onStart", {},
    function()
        help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct1, cmd, {}, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct2, cmd, { "%[userNI]" }, { "CT2" }, minlevel )
        end
        hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg ) )
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- Internal test seams (nick-prefix resolution regression). `_`-prefixed
-- per the repo convention for non-contract, test-only exports (see
-- docs/PLUGIN_API.md §8).
return {
    _onbmsg                   = onbmsg,
    _find_online_by_firstnick = find_online_by_firstnick,
}