--[[

    cmd_hubinfo.lua by pulsar

        usage: [+!#]hubinfo

        v0.31:
            - fix #445: read the hub-runtime store from its new home
              `scripts/data/hub_runtime.tbl` (was `core/hci.lua`,
              which every upgrade clobbered with zeros). Dropped the
              local check_hci() (hub_runtime owns creation + the
              one-time migration; this plugin is now a pure reader)
              and made get_hubruntime() re-read on each call instead
              of caching at load - the cached value went stale as the
              60s onTimer advanced the counter.

        v0.30:
            - route the get_levels() "Level:  " row label through lang
              (msg_level_label). Part of #301 i18n cleanup.

        v0.29:
            - added "years" to util.formatseconds
                - changed check_uptime()
                - changed get_hubruntime()

        v0.28:
            - added get_certinfos() function; based on "etc_keyprint.lua" by blastbeat
                - shows validity and signature informations about the hubcert

        v0.27:
            - functions simplified: check_os(), check_cpu(), check_ram_total(), check_ram_free()
            - codebase has been cleaned up
            - added user levels

        v0.26:
            - support for Raspberry Pi 4  / thx Sopor

        v0.25:
            - check if ports are empty or 0  / thx Sopor

        v0.24:
            - added "hub_email"

        v0.23:
            - added check_hci() function

        v0.22:
            - added dynamic date on copyright info
            - added reg_only info

        v0.21:
            - removed table lookups
            - changed some english language parts / thx Sopor

        v0.20:
            - fixed issue #100 -> https://github.com/luadch/luadch/issues/100
            - added ipv6 ports

        v0.19:
            - changed check_cpu for Linux to match cpu info for RPi1 based on ARMv6
            - rewrite check_cpu to reduce code

        v0.18:
            - removed fallback string from "use_ssl" var

        v0.17:
            - added TLS Mode  / requested by Tork

        v0.16:
            - prevent possible unknown "uname" outputs on windows systems
                - changes in check_os()
                - changes in check_cpu()
                - changes in check_ram_total()
                - changes in check_ram_free()

        v0.15:
            - increase performance by caching functions on start
            - show Ubuntu version
            - show Debian Version
            - show Raspbian Version

        v0.14:
            - shows the complete hub runtime since the first hubstart

        v0.13:
            - recognize Debian, Raspbian, Ubuntu
            - rewrite some parts of code

        v0.12:
            - added hub_website, hub_network, hub_owner

        v0.11:
            - removed function: convert_size()
                - now using: util.formatbytes()

        v0.10:
            - fix some code to prevent possible nil errors on some linux/unix machines
            - sort some parts of code

        v0.09:
            - fix the following functions to prevent possible nil errors if luadch has not the required permissions
              to get informations from the OS: check_os(), check_cpu(), check_ram_total(), check_ram_free()

        v0.08:
            - fix typo
            - shows hubshare

        v0.07:
            - changed visual output style

        v0.06:
            - small fix on cfg.get vars

        v0.05:
            - added "onlogin" feature

        v0.04:
            - add some useful functions to make things easyer / thx Night
            - shows hub_name, hub_hostaddress, tcp_ports, ssl_ports, use_ssl, use_keyprint, keyprint_type, keyprint_hash
            - shows better OS view
            - shows CPU
            - shows RAM total
            - shows RAM free

        v0.03:
            - rename cmd_version.lua to cmd_hubinfo.lua
            - code cleaning
            - shows copyright
            - shows uptime
            - shows amount of running scripts
            - shows memory usage
            - shows users regged total
            - shows online users total
            - shows online users regged
            - shows online users unreg
            - shows online users active
            - shows online users passive
            - shows operating system

        v0.02:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.01:
            - shows the hubversion

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_hubinfo"
local scriptversion = "0.31"

local cmd = "hubinfo"

--// imports
-- #206 Tier 2: reach the ssl module via the whitelisted global
-- instead of `require`. May be `false` if luasec failed to load
-- (init.lua keeps the optional-lib pattern); guarded everywhere.
local luasec = ssl
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or {}; err = err and hub.debug( err )
local minlevel = cfg.get( "cmd_hubinfo_minlevel" )
local onlogin = cfg.get( "cmd_hubinfo_onlogin" )
local hub_name = cfg.get( "hub_name" )
local hub_hostaddress = cfg.get( "hub_hostaddress" )
local reg_only = cfg.get( "reg_only" ); if reg_only then reg_only = "true" else reg_only = "false" end
local tcp_ports = cfg.get( "tcp_ports" )
local ssl_ports = cfg.get( "ssl_ports" )
local tcp_ports_ipv6 = cfg.get( "tcp_ports_ipv6" )
local ssl_ports_ipv6 = cfg.get( "ssl_ports_ipv6" )
local use_ssl = cfg.get( "use_ssl" )
local use_keyprint = cfg.get( "use_keyprint" )
local keyprint_type = cfg.get( "keyprint_type" )
local keyprint_hash = cfg.get( "keyprint_hash" )
local hub_website = cfg.get( "hub_website" ) or ""
local hub_network = cfg.get( "hub_network" ) or ""
local hub_email = cfg.get( "hub_email" ) or ""
local hub_owner = cfg.get( "hub_owner" ) or ""
local ssl_params = cfg.get( "ssl_params" )
-- #445: read-only reader of hub_runtime's store, now under scripts/data/
-- (was core/hci.lua, clobbered on every upgrade). hub_runtime owns
-- creation + the one-time migration; this plugin never writes it.
local hci_file = "scripts/data/hub_runtime.tbl"
local cfg_levels = cfg.get( "levels" )

--// table constants from "core/const.lua"
local const_file = "core/const.lua"
local const_tbl = util.loadtable( const_file ) or {}
local const_PROGRAM = const_tbl[ "PROGRAM_NAME" ]
local const_VERSION = const_tbl[ "VERSION" ]
local const_COPYRIGHT = const_tbl[ "COPYRIGHT" ]
local const_FORK = const_tbl[ "FORK" ]

--// functions
local get_ssl_value
local get_tls_mode
local get_kp_value
local get_kp
local get_levels
local trim
local split
local onbmsg
local output
local check_uptime
local get_hubruntime
local check_script_amount
local check_mem_usage
local check_users
local get_os
local check_os
local check_cpu
local check_ram_total
local check_ram_free
local check_hubshare
local checkTable
local get_certinfos

--// vars to cache functions (onStart listener)
local cache_get_kp_value
local cache_get_ssl_value
local cache_get_kp
local cache_check_script_amount
local cache_check_os
local cache_check_cpu
local cache_check_ram_total

--// msgs
local help_title = "cmd_hubinfo.lua"
local help_usage = lang.help_usage or "[+!#]hubinfo"
local help_desc = lang.help_desc or "Sends a list of basic informations about the hub"

local ucmd_menu = lang.ucmd_menu or { "General", "Hubversion" }

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_years = lang.msg_years or " years, "
local msg_days = lang.msg_days or " days, "
local msg_hours = lang.msg_hours or " hours, "
local msg_minutes = lang.msg_minutes or " minutes, "
local msg_seconds = lang.msg_seconds or " seconds"
local msg_unknown = lang.msg_unknown or "<UNKNOWN>"
local msg_level_label = lang.msg_level_label or "        Level:  "
local msg_out = lang.msg_out or [[


=== HUBINFO =====================================================================================

   [ HUB ]

        Hubname:  %s
        Address: %s

        Reg only: %s

        ADC Port IPv4:  %s
        ADCS Port IPv4:  %s
        ADC Port IPv6:  %s
        ADCS Port IPv6:  %s

        Use SSL:  %s
        TLS Mode:  %s
        Use Keyprint:  %s
        Keyprint:  %s

        Version:  %s %s
        Copyright:  %s

        Uptime (complete):  %s
        Uptime (session):  %s

        Running scripts:  %s
        Memory usage:  %s

        Hub share:  %s

        Hub website:  %s
        Hub Network:  %s
        Hub eMail:  %s
        Hub owner:  %s

   [ CERTIFICATE ]

        Validity

             Not Before:   %s
             Not After:      %s

        Signature

             Algorithm:     %s

   [ USERS ]

        Total registered:      %s
        Total online:            %s
        Reg. online:     %s
        Unreg. online:  %s
        Active online:          %s
        Passive online:       %s

   [ USER LEVELS ]

%s
   [ SYSTEM ]

        OS:     %s
        CPU:   %s
        RAM total:  %s
        RAM free:  %s

===================================================================================== HUBINFO ===
  ]]


----------
--[CODE]--
----------

-- #445: no check_hci() here anymore. hub_runtime owns creating +
-- migrating the store; get_hubruntime() below re-reads it defensively on
-- each call, so a not-yet-created file just reads as 0.

--// get use_ssl value
get_ssl_value = function()
    if use_ssl then
        if scriptlang == "de" then return "JA" elseif scriptlang == "en" then return "YES" else return "YES" end
    else
        if scriptlang == "de" then return "NEIN" elseif scriptlang == "en" then return "NO" else return "NO" end
    end
    return msg_unknown
end

get_tls_mode = function()
    if use_ssl then
        return string.sub( ssl_params.protocol, 4 ):gsub( "_", "." )
    end
    return ""
end

--// get use_keyprint value
get_kp_value = function()
    if use_keyprint then
        if scriptlang == "de" then return "JA" elseif scriptlang == "en" then return "YES" else return "YES" end
    else
        if scriptlang == "de" then return "NEIN" elseif scriptlang == "en" then return "NO" else return "NO" end
    end
    return msg_unknown
end

--// get keyprint if use_keyprint is true
get_kp = function()
    if use_keyprint then
        return keyprint_type .. keyprint_hash
    end
    return ""
end

--// get user levels
get_levels = function( levels )
    local s = ""
    for x = 0, 100, 1 do
        if levels[ x ] then s = s .. msg_level_label .. x .. "\t\t=  " .. levels[ x ] .. "\n" end
    end
    return s
end

--// trim whitespaces from both ends of a string
trim = function( s )
    return string.find( s, "^%s*$" ) and "" or string.match( s, "^%s*(.*%S)" )
end

--// split strings  / by Night
split = function( s, delim, newline )
    local i = string.find( s, delim ) + 1
    if not i then i = 0 end
    local j = string.find( s, newline, i ) - 1
    if not j then j = - 1 end
    return string.sub( s, i, j )
end

--// uptime
check_uptime = function()
    local y, d, h, m, s = util.formatseconds( os.difftime( os.time(), signal.get( "start" ) ) )
    local hub_uptime = y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    return hub_uptime
end

--// uptime complete
get_hubruntime = function()
    -- #445: re-read the store on each call (was a load-time cache that
    -- went stale as hub_runtime's 60s onTimer advanced the counter).
    -- F-PLG-2 (#133): defensive `or {}` / `or 0` so a missing / mid-run-
    -- failed loadtable degrades to 0 instead of crashing the listener.
    local hci_tbl = util.loadtable( hci_file ) or {}
    local hubruntime = hci_tbl.hubruntime or 0
    local y, d, h, m, s = util.formatseconds( hubruntime )
    return y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
end

--// running scripts amount
check_script_amount = function()
    local scripts = cfg.get( "scripts" )
    local amount = 0
    for k, v in pairs( scripts ) do
        amount = amount + 1
    end
    return amount
end

--// memory usage
check_mem_usage = function()
    return util.formatbytes( collectgarbage( "count" ) * 1024 )
end

--// hubshare
check_hubshare = function()
    local hshare = 0
    for sid, user in pairs( hub.getusers() ) do
        if not user:isbot() then
            -- Phase 8a F-INF-1: user:share() is nil for clients that
            -- did not declare SS in their BINF; treat as 0.
            local ushare = user:share() or 0
            hshare = hshare + ushare
        end
    end
    hshare = util.formatbytes( hshare )
    return hshare
end

--// users
check_users = function()
    local regged_total, online_total, online_regged, online_unregged, online_active, online_passive = 0, 0, 0, 0, 0, 0
    local regusers, reggednicks, reggedcids = hub.getregusers()
    for i, user in ipairs( regusers ) do
        if ( user.is_bot ~= 1 ) and user.nick then
            regged_total = regged_total + 1
        end
    end
    for sid, user in pairs( hub.getusers() ) do
        if not user:isbot() then
            online_total = online_total + 1
            if user:isregged() then
                online_regged = online_regged + 1
            else
                online_unregged = online_unregged + 1
            end
            if user:hasfeature( "TCP4" ) or user:hasfeature( "TCP6" ) then
                online_active = online_active + 1
            else
                online_passive = online_passive + 1
            end
        end
    end
    return regged_total, online_total, online_regged, online_unregged, online_active, online_passive
end

-- #206 Tier-2 Sub-PR-3: the host-OS / CPU / RAM probes (which
-- shell out via io.popen) moved into `core/sysinfo.lua`. The
-- plugin sandbox no longer reaches `io.popen` at all; the
-- bundled `sysinfo` core module exposes the same data through
-- a curated interface.

--// system environment
get_os = function()
    return sysinfo.os_kind()
end

--// operating system
check_os = function()
    return sysinfo.os_name()
end

--// processor
check_cpu = function()
    return sysinfo.cpu_info() or msg_unknown
end

--// ram total
check_ram_total = function()
    return sysinfo.ram_total() or msg_unknown
end

--// ram free
check_ram_free = function()
    return sysinfo.ram_free() or msg_unknown
end

--// check if ports table are empty or 0
checkTable = function( tbl )
    local tbl_isEmpty = function( tbl )
        if next( tbl ) == nil then return true else return false end
    end
    if not tbl_isEmpty( tbl ) and ( tbl[ 1 ] > 0 ) then
        return table.concat( tbl, ", " )
    else
        return "DISABLED"
    end
end

--// hubcert infos
get_certinfos = function()
    if not luasec then
        return msg_unknown, msg_unknown, msg_unknown
    end
    -- #206 Tier 2: ssl.x509 is attached to the ssl module table
    -- in init.lua; plugins reach it directly without `require`.
    local x509 = luasec.x509
    local ssl_params = cfg.get( "ssl_params" )
    local cert_path = ssl_params and ssl_params.certificate
    if not cert_path then
        return msg_unknown, msg_unknown, msg_unknown
    end
    local fd = io.open( tostring( cert_path ), "r" )
    if not fd then
        return msg_unknown, msg_unknown, msg_unknown
    end
    local cert_str = fd:read( "*all" )
    if not cert_str then
        fd:close()
        return msg_unknown, msg_unknown, msg_unknown
    end
    local cert = x509.load( cert_str )
    if not cert then
        fd:close()
        return msg_unknown, msg_unknown, msg_unknown
    end
    local notbefore = cert:notbefore() or msg_unknown
    local notafter = cert:notafter() or msg_unknown
    local getsignaturename = string.upper( cert:getsignaturename() ) or msg_unknown
    fd:close()
    return notbefore, notafter, getsignaturename
end

--// output message
output = function()
    return utf.format( msg_out,
        "\t\t" .. hub_name,
        "\t\t" .. hub_hostaddress,
        "\t\t" .. reg_only,
        "\t\t" .. checkTable( tcp_ports ),
        "\t\t" .. checkTable( ssl_ports ),
        "\t" .. checkTable( tcp_ports_ipv6 ),
        "\t" .. checkTable( ssl_ports_ipv6 ),
        "\t\t" .. cache_get_ssl_value,
        "\t\t" .. get_tls_mode(),
        "\t" .. cache_get_kp_value,
        "\t\t" .. cache_get_kp,
        "\t\t" .. const_PROGRAM, const_VERSION,
        "\t\t" .. const_COPYRIGHT ..
        " (2007-" .. os.date( "%Y" ) .. "), " .. const_FORK,
        "\t" .. get_hubruntime(),
        "\t" .. check_uptime(),
        "\t" .. cache_check_script_amount,
        "\t" .. check_mem_usage(),
        "\t\t" .. check_hubshare(),
        "\t\t" .. hub_website,
        "\t" .. hub_network,
        "\t\t" .. hub_email,
        "\t\t" .. hub_owner,
        "\t" .. select( 1, get_certinfos() ),
        "\t" .. select( 2, get_certinfos() ),
        "\t" .. select( 3, get_certinfos() ),
        "\t" .. select( 1, check_users() ),
        "\t" .. select( 2, check_users() ),
        "\t" .. select( 3, check_users() ),
        "\t" .. select( 4, check_users() ),
        "\t" .. select( 5, check_users() ),
        "\t" .. select( 6, check_users() ),
        get_levels( cfg_levels ),
        "\t\t" .. cache_check_os,
        "\t\t" .. cache_check_cpu,
        "\t\t" .. cache_check_ram_total,
        "\t\t" .. check_ram_free()
    )
end

onbmsg = function( user )
    local user_level = user:level()
    if user_level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    user:reply( output(), hub.getbot() )
    return PROCESSED
end

hub.setlistener( "onLogin", {},
    function( user )
        if onlogin then
            local user_level = user:level()
            if user_level >= minlevel then
                user:reply( output(), hub.getbot() )
                return nil
            end
        end
    end
)

hub.setlistener( "onStart", {},
    function()
        --// caching functions
        cache_get_kp_value = get_kp_value()
        cache_get_ssl_value = get_ssl_value()
        cache_get_kp = get_kp()
        cache_check_script_amount = check_script_amount()
        cache_check_os = check_os()
        cache_check_cpu = check_cpu()
        cache_check_ram_total = check_ram_total()

        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd, {}, { "CT1" }, minlevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )