--[[

    etc_lockdown.lua v0.01 by Aybo ( #501 )

        Transient "maintenance mode": temporarily admit only users at or
        above a chosen level, kick everyone below, and refuse new logins
        below it with a clear message and a reconnect hint - until the
        operator lifts it (or an optional timer expires). Distinct from
        `reg_only`, which is a PERMANENT access tier; this is a quick
        on/off switch for staff to reconfigure or test while the hub
        stays up.

        Command ( min level etc_lockdown_command_minlevel, default 60 ):

            [+!#]lockdown <level> [minutes] [reason]   enable
            [+!#]lockdown off                          disable
            [+!#]lockdown status                       show current state

        <level>    mandatory; admit users whose level >= <level>. Self-
                   lockout guard: you cannot set a level ABOVE your own
                   (a HUBOWNER at 100 can never lock themselves out; a
                   level-60 op cannot set 80).
        [minutes]  optional whole minutes ( like +ban's <time> ); omit
                   for an indefinite lockdown lifted only by `off`.
        [reason]   optional. The token after <level> is taken as
                   [minutes] only when it is a positive integer; a non-
                   numeric token means "no time", and everything from
                   there is the reason ( mirrors +ban's time-vs-reason
                   split so the operator muscle memory carries over ).

        Behaviour:
          - onConnect vetoes a login from level < the active level with
            ISTA 226 + an IQUI TL so the client reconnects on its own
            ( TL = remaining seconds when timed, else the configured
            etc_lockdown_default_retry ). Bots never fire onConnect, so
            they are exempt with no special case.
          - on enable, online users below the level are kicked with the
            same message; staff at/above the level are untouched.
          - whitelisted IPs ( core/whitelist - hublist pingers etc. ) are
            admitted when etc_lockdown_exempt_whitelist is true, so the
            hub stays visible on hublists during a lockdown ( essential
            under reg_only, where info pingers must log in ). This is a
            deliberate, plugin-scoped exemption from a manual gate.
          - state persists to scripts/data/etc_lockdown.tbl as an
            ABSOLUTE expiry timestamp, so a +reload neither resets nor
            extends the deadline; a lockdown that expired while the hub
            was down is cleared on boot.

        Off by default: add { "etc_lockdown.lua", enabled = false } to
        cfg.scripts to load it.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname    = "etc_lockdown"
local scriptversion = "0.01"

local cmd_main = "lockdown"

--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname )
lang = lang or { }
if lang_err then hub.debug( lang_err ) end

local command_minlevel = cfg.get( "etc_lockdown_command_minlevel" ) or 60
local default_retry    = cfg.get( "etc_lockdown_default_retry" ) or 120
local exempt_whitelist = cfg.get( "etc_lockdown_exempt_whitelist" )
if exempt_whitelist == nil then exempt_whitelist = true end

local report_activate = cfg.get( "etc_lockdown_report" )
local report_hubbot   = cfg.get( "etc_lockdown_report_hubbot" )
local report_opchat   = cfg.get( "etc_lockdown_report_opchat" )
local report_llevel   = cfg.get( "etc_lockdown_llevel" )

local report = hub.import( "etc_report" )

local store_path = "scripts/data/etc_lockdown.tbl"

--// table lookups
local hub_getbot    = hub.getbot
local hub_getusers  = hub.getusers
local hub_escapeto  = hub.escapeto
local hub_import    = hub.import
local utf_match     = utf.match
local utf_format    = utf.format
local os_time       = os.time
local math_floor    = math.floor
local math_ceil     = math.ceil
local math_type     = math.type

-- ADC status code for the refuse. 226 is the hub's "access restricted"
-- family ( same code as reg_only, of which a maintenance min-level gate
-- is the transient sibling ). The reconnect timeout rides on the IQUI as
-- the `TL` flag ( user:kill's quitstring1 ), NOT crammed into the ISTA
-- line - the correct 2-arg form ( see usr_share / cmd_ban ).
local ISTA_CODE = "226"

-- Upper bound on a timed lockdown, in whole minutes ( 1 year - already
-- absurd for a maintenance window ). Guards against a typo, and against a
-- float / inf slipping past the integer check into overflow or a
-- never-expiring "timed" lockdown.
local MAX_MINUTES = 525600


--// lang
local help_title = "etc_lockdown.lua - maintenance gate"
local help_usage = lang.help_usage or "[+!#]lockdown <level> [minutes] [reason] | off | status"
local help_desc  = lang.help_desc  or "Temporarily admit only users at or above <level>; kick + refuse everyone below until you run `lockdown off` (or the timer expires)."

local ucmd_menu_status = lang.ucmd_menu_status or { "Hub", "Lockdown", "status" }
local ucmd_menu_off    = lang.ucmd_menu_off    or { "Hub", "Lockdown", "off" }
local ucmd_menu_on     = lang.ucmd_menu_on     or { "Hub", "Lockdown", "enable" }
local ucmd_popup_level  = lang.ucmd_popup_level  or "Minimum level to admit (e.g. 60):"
local ucmd_popup_min    = lang.ucmd_popup_min    or "Minutes (empty = indefinite):"
local ucmd_popup_reason = lang.ucmd_popup_reason or "Reason (optional):"

local msg_denied       = lang.msg_denied       or "[ LOCKDOWN ]--> You are not allowed to use this command."
local msg_usage        = lang.msg_usage        or "Usage: [+!#]lockdown <level> [minutes] [reason] | off | status"
local msg_bad_level    = lang.msg_bad_level    or "[ LOCKDOWN ]--> <level> must be a whole number 0-100, or use: off / status"
local msg_notint       = lang.msg_notint       or "[ LOCKDOWN ]--> Time must be a whole number of minutes."
local msg_badtime      = lang.msg_badtime      or "[ LOCKDOWN ]--> Time must be between 1 and 525600 minutes."
local msg_self_lockout = lang.msg_self_lockout or "[ LOCKDOWN ]--> You cannot lock down at level %d - it is above your own level ( %d )."
local msg_enabled      = lang.msg_enabled      or "[ LOCKDOWN ]--> %s enabled lockdown: min level %d, %s. Kicked %d online user( s )."
local msg_disabled     = lang.msg_disabled     or "[ LOCKDOWN ]--> %s lifted the lockdown."
local msg_already_off  = lang.msg_already_off  or "[ LOCKDOWN ]--> Lockdown is not active."
local msg_indefinite   = lang.msg_indefinite   or "indefinite"
local msg_status_off   = lang.msg_status_off   or "[ LOCKDOWN ]--> Lockdown is OFF."
local msg_status_on    = lang.msg_status_on    or "[ LOCKDOWN ]--> Lockdown is ON  |  min level: %d  |  remaining: %s  |  message: %s  |  by: %s"
local msg_expired      = lang.msg_expired      or "[ LOCKDOWN ]--> Lockdown ( min level %d ) expired and was lifted."
local msg_default_kick = lang.msg_default_kick or "The hub is in maintenance mode. Please try again later."
local msg_kick         = lang.msg_kick         or "[ LOCKDOWN ]--> %s"


----------
--[CODE]--
----------

-- Coerce a corrupt / hand-edited store to a safe inactive state. An
-- `active=true` record missing a numeric `level` ( or with a non-numeric
-- `expires_at` ) would otherwise crash EVERY onConnect on the level
-- comparison against nil = a hub-wide login block. Degrade untrusted
-- on-disk input to safe rather than trusting its shape.
local function sane_state( s )
    if type( s ) ~= "table" or not s.active then return { active = false } end
    if type( s.level ) ~= "number" then return { active = false } end
    if s.expires_at ~= nil and type( s.expires_at ) ~= "number" then return { active = false } end
    return s
end

-- Persisted lockdown state. Shape ( when active ):
--   { active=true, level=N, message=<str|nil>, expires_at=<abs os.time|nil>,
--     by_nick=<str>, by_level=<int>, started_at=<abs os.time> }
-- Loaded once at module load; util.loadtable returns nil on a fresh hub.
local state = sane_state( util.loadtable( store_path ) )

local function persist( )
    util.savetable( state, "etc_lockdown_state", store_path )
end

-- Active NOW = flagged active AND ( no deadline OR deadline in the future ).
-- A passed deadline reads as inactive here WITHOUT mutating state; onTimer
-- performs the actual clear + notify, so this stays side-effect free and is
-- safe to call from the onConnect hot path.
local function is_active_now( )
    if not state.active then return false end
    if state.expires_at and os_time( ) >= state.expires_at then return false end
    return true
end

-- The refuse message body: the operator's reason, else the default.
local function refuse_text( )
    local m = ( state.message and state.message ~= "" ) and state.message or msg_default_kick
    return utf_format( msg_kick, m )
end

-- Seconds until the client should retry: remaining time when timed, else
-- the configured default so clients keep re-knocking until `lockdown off`.
local function retry_seconds( )
    if state.expires_at then
        local rem = state.expires_at - os_time( )
        if rem < 1 then rem = 1 end
        return rem
    end
    return default_retry
end

-- Refuse / kick one user: send the ISTA message, then IQUI with a TL so
-- the client reconnects on its own once the lockdown lifts.
local function kick_user( user )
    user:kill(
        "ISTA " .. ISTA_CODE .. " " .. hub_escapeto( refuse_text( ) ) .. "\n",
        "TL" .. retry_seconds( )
    )
end

-- Is this user exempt from the gate? Staff at/above the level pass; a
-- whitelisted IP passes when the toggle is on.
local function is_exempt( user )
    if user:level( ) >= state.level then return true end
    if exempt_whitelist and whitelist.is_whitelisted( user:ip( ) or "" ) then return true end
    return false
end

-- Kick every online user below the level ( minus the exempt ). getusers()
-- is humans-only ( no bots ). Snapshot the victims BEFORE killing so we
-- never mutate the users table mid-iteration.
local function kick_online_below( )
    local victims = { }
    for _, user in pairs( hub_getusers( ) ) do
        if not is_exempt( user ) then
            victims[ #victims + 1 ] = user
        end
    end
    for _, user in ipairs( victims ) do
        kick_user( user )
    end
    return #victims
end

-- Parse "[minutes] [reason]" from the tail after <level>. A leading
-- numeric token is the intended duration ( validated: whole, >= 1 );
-- a non-numeric leading token means no time and the whole tail is the
-- reason. Mirrors cmd_ban's <time>-vs-<reason> split.
-- Returns: minutes|nil, reason|nil, err_key|nil
local function parse_time_reason( rest )
    rest = rest or ""
    local tok, tail = utf_match( rest, "^(%S+)%s*(.*)$" )
    if not tok or tok == "" then return nil, nil, nil end
    local n = tonumber( tok )
    if n == nil then
        return nil, rest, nil                        -- non-numeric -> reason only
    end
    -- A numeric first token is an intended duration: require a whole
    -- integer in a sane range. math.type rejects floats AND inf / nan
    -- ( "1e3", "1e999" ) - the overflow-safe form of cmd_ban's
    -- `n ~= floor(n)` integer check.
    if math_type( n ) ~= "integer" then return nil, nil, "notint" end
    if n < 1 or n > MAX_MINUTES then return nil, nil, "badtime" end
    return n, ( tail ~= "" and tail or nil ), nil    -- minutes + optional reason
end

-- Enable. `actor` is the invoking user ( already past the self-lockout
-- guard, so >= level -> never kicked ). Returns the number kicked.
local function enable_lockdown( level, minutes, reason, actor )
    state = {
        active     = true,
        level      = level,
        message    = reason,
        expires_at = minutes and ( os_time( ) + minutes * 60 ) or nil,
        by_nick    = ( actor and actor:firstnick( ) ) or "?",
        by_level   = ( actor and actor:level( ) ) or 0,
        started_at = os_time( ),
    }
    persist( )
    return kick_online_below( )
end

-- Disable. Returns whether a lockdown was actually active.
local function disable_lockdown( )
    local was = state.active
    state = { active = false }
    persist( )
    return was
end

local function format_status( )
    if not is_active_now( ) then
        return msg_status_off
    end
    local remaining
    if state.expires_at then
        -- is_active_now() above guarantees now < expires_at, so the
        -- remainder is positive; ceil shows "1 min" for anything under a
        -- minute.
        remaining = math_ceil( ( state.expires_at - os_time( ) ) / 60 ) .. " min"
    else
        remaining = msg_indefinite
    end
    local m = ( state.message and state.message ~= "" ) and state.message or msg_default_kick
    return utf_format( msg_status_on, state.level, remaining, m, state.by_nick or "?" )
end

local function send_report( msg )
    if report then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel, msg )
    end
end


------------------
--[ADC HANDLERS]--
------------------

-- onConnect veto. Registered at load time ( no imports needed ) so the
-- gate is live the moment the plugin loads.
local function on_connect( user )
    if not is_active_now( ) then return end
    if is_exempt( user ) then return end
    kick_user( user )
    return PROCESSED
end

local function on_lockdown( user, command, parameters )
    if user:level( ) < command_minlevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end

    local first, rest = utf_match( parameters or "", "^(%S+)%s*(.*)$" )
    first = first or ""
    rest  = rest or ""
    local verb = first:lower( )

    if verb == "" then
        user:reply( msg_usage, hub_getbot( ) )
        return PROCESSED
    end

    if verb == "off" then
        local was = disable_lockdown( )
        if was then
            local msg = utf_format( msg_disabled, user:firstnick( ) )
            user:reply( msg, hub_getbot( ) )
            send_report( msg )
            audit.fire( audit.build( "lockdown.disable", user, nil, nil, { } ) )
        else
            user:reply( msg_already_off, hub_getbot( ) )
        end
        return PROCESSED
    end

    if verb == "status" then
        user:reply( format_status( ), hub_getbot( ) )
        return PROCESSED
    end

    -- Otherwise the first token must be the <level>.
    local level = tonumber( first )
    if not level or level ~= math_floor( level ) or level < 0 or level > 100 then
        user:reply( msg_bad_level, hub_getbot( ) )
        return PROCESSED
    end

    -- Self-lockout guard: never let an operator raise the bar above
    -- their own level ( a HUBOWNER at 100 can lock everyone else out;
    -- nobody can lock themselves out ).
    if level > user:level( ) then
        user:reply( utf_format( msg_self_lockout, level, user:level( ) ), hub_getbot( ) )
        return PROCESSED
    end

    local minutes, reason, err = parse_time_reason( rest )
    if err == "notint" then
        user:reply( msg_notint, hub_getbot( ) )
        return PROCESSED
    elseif err == "badtime" then
        user:reply( msg_badtime, hub_getbot( ) )
        return PROCESSED
    end

    local kicked = enable_lockdown( level, minutes, reason, user )
    local when = minutes and ( minutes .. " min" ) or msg_indefinite
    local msg = utf_format( msg_enabled, user:firstnick( ), level, when, kicked )
    user:reply( msg, hub_getbot( ) )
    send_report( msg )
    audit.fire( audit.build( "lockdown.enable", user, nil, reason, {
        level   = level,
        minutes = minutes,
        kicked  = kicked,
    } ) )
    return PROCESSED
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onConnect", { }, on_connect )

-- Auto-expiry. onTimer fires frequently; the deadline check is cheap and
-- lifts the lockdown at most one tick late.
hub.setlistener( "onTimer", { },
    function( )
        if state.active and state.expires_at and os_time( ) >= state.expires_at then
            local level = state.level
            disable_lockdown( )
            local msg = utf_format( msg_expired, level )
            send_report( msg )
            audit.fire( audit.build( "lockdown.expire", scriptname, nil, nil,
                { level = level } ) )
        end
        return nil
    end
)

hub.setlistener( "onStart", { },
    function( )
        -- A lockdown that expired while the hub was down: clear it on boot
        -- ( no notice - nobody was here to be locked out ).
        if state.active and state.expires_at and os_time( ) >= state.expires_at then
            state = { active = false }
            persist( )
        end

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, command_minlevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_status, cmd_main .. " status", { }, { "CT1" }, command_minlevel )
            ucmd.add( ucmd_menu_off,    cmd_main .. " off",    { }, { "CT1" }, command_minlevel )
            ucmd.add( ucmd_menu_on,
                cmd_main .. " %[line:" .. ucmd_popup_level .. "] %[line:" .. ucmd_popup_min ..
                "] %[line:" .. ucmd_popup_reason .. "]",
                { }, { "CT1" }, command_minlevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_main, on_lockdown, command_minlevel ) )

        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// expose internals for unit tests
return {
    _parse_time_reason  = parse_time_reason,
    _is_active_now      = function( ) return is_active_now( ) end,
    _state              = function( ) return state end,
    _on_connect         = on_connect,
    _on_lockdown        = on_lockdown,
    _kick_online_below  = kick_online_below,
    _format_status      = format_status,
    _enable_lockdown    = enable_lockdown,
    _disable_lockdown   = disable_lockdown,
}
