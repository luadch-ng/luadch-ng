--[[

        cmd_help.lua by blastbeat

        - this script adds a command "help"
        - it exports also a module to reg a help text which will be shown by help
        - usage: [+!#]help

        v0.07: (#591)
            - compact one-line-per-command layout: "[level]  <prefix><cmd> <args>
              <description>", command column aligned, drops the .lua-name title.
              Level shown first so it stays aligned even for very long commands.
            - the command is shown with a single copyable prefix (cfg
              cmd_help_prefix, default "+"); + ! # all work at the hub.

        v0.06: by pulsar
            - small typo fix
            - some small code changes
            - add table lookups

        v0.05: by pulsar
            - changed visual output style

        v0.04: by blastbeat
            - updated script api
            - regged hubcommand

        v0.03: by blastbeat
            - some clean ups

        v0.02: by blastbeat
            - added language files and ucmd

]]--


local scriptname = "cmd_help"
local scriptversion = "0.07"

local cmd = "help"

local minlevel = 0    -- minimum level to get the help

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_import = hub.import
local hub_debug = hub.debug
local hub_getbot = hub.getbot
local hub_debug = hub.debug
local utf_match = utf.match
local utf_format = utf.format
local table_concat = table.concat
local string_rep = string.rep
local string_format = string.format

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub_debug( err )

--// msgs
local help_title = lang.help_title or "cmd_help.lua"
local help_usage = lang.help_usage or "[+!#]help"
local help_desc = lang.help_desc or "Shows this help for hub commands"

local msg_out = lang.msg_out or [[


=== HUB COMMANDS ======================================================================================
(leading [number] = minimum level; a command also works with ! or #)
%s
====================================================================================== HUB COMMANDS ===
  ]]

local ucmd_menu = lang.ucmd_menu or { "General", "Help" }

--// The single, copyable command prefix shown in the list. +, ! and # are all
--// valid at the hub (core/hub.lua matches "^[+!#]"); default to "+", luadch's
--// convention (the docs and the hub's own "Did you mean +X?" hints use it).
local help_prefix = tostring( cfg_get( "cmd_help_prefix" ) or "+" )
--// Align the command column up to this width; the few very long multi-verb
--// commands overflow it (their description just starts later) instead of
--// padding every row out to their length.
local CMD_COL = 40

--// code
local help = {}

local reghelp = function( title, usage, desc, level )
    title, usage, desc = tostring( title ), tostring( usage ), tostring( desc )
    level = tonumber( level ) or 0
    help[ #help + 1 ] = { title = title, usage = usage, desc = desc, level = level }
end

local onbmsg = function( user, command, parameters )
    local level = user:level()
    --// pass 1: keep the entries this user may see, normalize each to a single
    --// copyable "<prefix><command> <args>" form, and find the width to align
    --// the (capped) command column.
    local rows, width = {}, 0
    for _, tbl in ipairs( help ) do
        if level >= tbl.level then
            local c = tbl.usage
            c = c:gsub( "^%[%+!#%]", "" )   -- strip the leading "[+!#]" marker ...
            c = c:gsub( "^[%+!#]", "" )     -- ... or a single leading + ! #
            c = help_prefix .. c
            c = c:gsub( "%[%+!#%]", help_prefix )   -- and any further "[+!#]" a
                                                    -- second usage form carries
                                                    -- ("+cmd a  /  [+!#]cmd b")
            local w = #c
            if w > width and w <= CMD_COL then width = w end
            rows[ #rows + 1 ] = { cmd = c, desc = tbl.desc, level = tbl.level }
        end
    end
    --// pass 2: one aligned line per command - "[level]  command  description".
    --// Level first so it stays aligned even when a long command overflows the
    --// command column.
    local tmp = {}
    for _, r in ipairs( rows ) do
        local pad = width - #r.cmd
        if pad < 0 then pad = 0 end
        -- %3.0f, not %3d: tolerate a plugin that ever registers a fractional
        -- level (%d errors on a non-integer in Lua 5.4); real levels are ints.
        tmp[ #tmp + 1 ] = string_format( "  [%3.0f]  %s%s  %s",
            r.level, r.cmd, string_rep( " ", pad ), r.desc )
    end
    local msg = utf_format( msg_out, table_concat( tmp, "\n" ) )
    user:reply( msg, hub_getbot(), hub_getbot() )
    return PROCESSED
end

hub.setlistener( "onStart", { },
    function( )
        local ucmd = hub_import( "etc_usercommands" )    -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { }, { "CT1" }, minlevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )    -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg ) )
        return nil
    end
)

reghelp( help_title, help_usage, help_desc, minlevel )

hub_debug( "** Loaded "..scriptname.." "..scriptversion.." **" )

--// public //--

return {

    reg = reghelp,

}