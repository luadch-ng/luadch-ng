--[[

    cmd_botflag.lua by Aybo

        - adds a command "botflag" to toggle the ADC CT bot-icon bit on a
          registered account, so an external announcer client (e.g. Herald)
          renders with the bot icon in DC++/AirDC++ WITHOUT any privilege
          change. Closes #571.
        - usage: [+!#]botflag <nick> on|off

        Background: CT (client type) is a display-only INF field - the hub
        derives it from level at login and NOTHING reads it for
        authorization (auth gates on user:level()). This command only sets
        the profile flag `show_as_bot`; core/hub.lua's insertreglevel() ORs
        the CT bot bit (1) when the flag is set. The account stays a
        first-class registered human everywhere else - it is NOT the in-hub
        `is_bot` flag (which hub_bot_cleaner would DELETE while offline).

        The change takes effect on the account's NEXT login (insertreglevel
        runs once per session and CT is appended, not live-rewritten). A
        flagged account that is currently online keeps its old icon until it
        reconnects; the command tells both the operator and (if online) the
        target.

        v0.01: by Aybo
            - initial version (#571)

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_botflag"
local scriptversion = "0.01"

local cmd = "botflag"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// imports
local onbmsg, help, ucmd, hubcmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local permission = cfg.get( "cmd_botflag_permission" ) or { }

--// msgs
local help_title = "cmd_botflag.lua"
local help_usage = lang.help_usage or "[+!#]botflag <NICK> on|off"
local help_desc = lang.help_desc or "Toggles the bot icon (ADC CT bot bit) on a registered account, no privilege change"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]botflag <NICK> on|off"
local msg_reg = lang.msg_reg or "User '%s' is not a registered account (or is an in-hub bot)."
local msg_nochange = lang.msg_nochange or "There are no changes needed."
local msg_ok = lang.msg_ok or "Bot icon flag for '%s' set to %s. It applies on the account's next login."
local msg_notify = lang.msg_notify or "An operator changed your bot-icon flag (%s). Reconnect for it to take effect."
local word_on = lang.word_on or "on"
local word_off = lang.word_off or "off"

local ucmd_menu_on = lang.ucmd_menu_on or { "Hub", "Control", "Bot icon", "enable (by nick)" }
local ucmd_menu_off = lang.ucmd_menu_off or { "Hub", "Control", "Bot icon", "disable (by nick)" }
local ucmd_nick = lang.ucmd_nick or "Nickname:"


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission )

onbmsg = function( user, command, parameters )
    local user_level = user:level( )

    if not ( user:isregged( ) and permission[ user_level ] ) then
        user:reply( msg_denied, hub.getbot( ) )
        return PROCESSED
    end

    local targetname, state = utf.match( parameters or "", "^(%S+)%s+(%S+)$" )
    if not state then
        user:reply( msg_usage, hub.getbot( ) )
        return PROCESSED
    end
    state = utf.lower( state )
    local want
    if state == "on" then
        want = true
    elseif state == "off" then
        want = false
    else
        user:reply( msg_usage, hub.getbot( ) )
        return PROCESSED
    end

    -- Resolve the registered profile by the TYPED base nick. regnicks is
    -- keyed by the account's base nick (usr_nick_prefix does not re-key the
    -- reg store), so the typed nick maps directly here. Humans only: an
    -- in-hub bot (is_bot) must never carry show_as_bot.
    local regusers_list, regnicks = hub.getregusers( )
    local profile = regnicks[ targetname ]
    if ( not profile ) or ( tonumber( profile.is_bot ) == 1 ) then
        user:reply( utf.format( msg_reg, targetname ), hub.getbot( ) )
        return PROCESSED
    end

    local is_set = ( tonumber( profile.show_as_bot ) == 1 )
    if is_set == want then
        user:reply( msg_nochange, hub.getbot( ) )
        return PROCESSED
    end

    -- Mutate the live profile in place + persist. regnicks[nick] shares
    -- table identity with the regusers_list entry AND with any online
    -- user's user:profile(), so this is the single source of truth;
    -- insertreglevel reads it at the next login. No hub.updateusers() -
    -- nick/cid are unchanged, so the nick/cid indexes need no rebuild
    -- (mirrors cmd_setpass's mutate-in-place + saveusers idiom).
    profile.show_as_bot = want and 1 or nil
    cfg.saveusers( regusers_list )

    local word = want and word_on or word_off
    user:reply( utf.format( msg_ok, targetname, word ), hub.getbot( ) )

    -- Tell the target to reconnect (icon applies at next login only).
    -- Resolve via firstnick per the #473/#474 nick-prefix idiom - the
    -- online user may be keyed under a PREFIXED display nick.
    local target = hub.find_online_by_firstnick( targetname )
    if target then
        target:reply( utf.format( msg_notify, word ), hub.getbot( ), hub.getbot( ) )
    end

    audit.fire( audit.build( "reg.botflag.set", user,
        { nick = targetname, level = tonumber( profile.level ) or 0 },
        nil, { show_as_bot = want } ) )

    return PROCESSED
end

hub.setlistener( "onStart", { },
    function( )
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_on, cmd, { "%[line:" .. ucmd_nick .. "]", "on" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_off, cmd, { "%[line:" .. ucmd_nick .. "]", "off" }, { "CT1" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- Test seam (tests/unit/cmd_botflag_test.lua); mirrors cmd_gag.lua's _onbmsg.
return { _onbmsg = onbmsg }
