--[[

    tests/unit/usr_uptime_test.lua

    Regression tests for scripts/usr_uptime.lua per-user online-time
    accounting (v0.12 fix, reported by Sopor - 24/7 users showing only a
    few hours/month, "22h" common = time since last restart).

    Two bugs, both meaning accumulated online time lived only in RAM and
    was lost on the next restart:

      1. set_stop reset the global `start` timer-gate on EVERY logout.
         onTimer only credits online users when `os.time()-start >= 60`,
         so on a hub with a logout more than once per 60s that gate never
         reached 60 and 24/7 users (who never log out) were never
         credited by the timer. -> Test "busy hub".

      2. last_tick is RAM-only, set only in set_start (onLogin). A
         +reload re-runs onStart but fires no onLogin for users who
         stayed connected, so their last_tick stayed nil and the timer
         skipped them. -> Test "reload".

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    os.time / os.date are driven by a controllable clock; the plugin's
    listeners are captured at load and fired by hand.

    Run: lua5.4 tests/unit/usr_uptime_test.lua

]]--

----------------------------------------------------------------------
-- tiny harness
----------------------------------------------------------------------
local checks, failures = 0, 0
local function truthy( label, v )
    checks = checks + 1
    if not v then failures = failures + 1; io.write( "FAIL " .. label .. " (got " .. tostring( v ) .. ")\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then failures = failures + 1
        io.write( string.format( "FAIL %-52s got=%s want=%s\n", label, tostring( got ), tostring( want ) ) )
    else io.write( "ok   " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- controllable clock + mutable state the stubs close over
----------------------------------------------------------------------
local _real_os = os
local _base = _real_os.time( { year = 2026, month = 7, day = 15, hour = 12, min = 0, sec = 0 } )
local _now  = _base
local _saved                       -- persisted uptime table (survives "reload")
local _online                      -- sid -> user (what hub.getusers returns)
local _listeners                   -- event -> fn

local YEAR  = tonumber( _real_os.date( "%Y", _base ) )
local MONTH = tonumber( _real_os.date( "%m", _base ) )

----------------------------------------------------------------------
-- sandbox-global stubs
----------------------------------------------------------------------
_G.type = type; _G.pairs = pairs; _G.tonumber = tonumber
_G.string = string; _G.table = table
_G.PROCESSED = "PROCESSED"
_G.utf = { match = function( ) end, format = function( ) return "" end }

-- os: time() and no-arg date() follow the controlled clock; date(fmt,t)
-- with an explicit t is honoured. Everything else delegates to real os.
_G.os = setmetatable( {
    time = function( ) return _now end,
    date = function( fmt, t ) return _real_os.date( fmt, t or _now ) end,
}, { __index = _real_os } )

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        if k == "usr_uptime_minlevel" then return 10 end
        if k == "usr_uptime_permission" then return { [ 50 ] = true, [ 60 ] = true } end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    loadtable      = function( ) return _saved end,
    savetable      = function( t )
        -- Faithful to core/util.lua: the serialiser does `for k in pairs(t)`,
        -- which errors "bad argument #1 to 'for iterator' (table expected,
        -- got nil)" on a nil argument exactly as the hub does. A table
        -- reference-persists (simulates on-disk), so tests 1-3 are unchanged.
        for _ in pairs( t ) do break end
        _saved = t
    end,
    getlowestlevel = function( ) return 50 end,
    formatseconds  = function( ) return 0, 0, 0, 0 end,
}

local _imports = {
    bot_opchat        = nil,
    cmd_help          = { reg = function( ) end },
    etc_usercommands  = { add = function( ) end },
    etc_hubcommands   = { add = function( ) return true end },
}
_G.hub = {
    setlistener  = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    import       = function( name ) return _imports[ name ] end,
    getusers     = function( ) return _online end,
    getbot       = function( ) return { } end,
    isnickonline = function( ) return nil end,
    debug        = function( ) end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function make_user( nick )
    return {
        isbot     = function( ) return false end,
        firstnick = function( ) return nick end,
        level     = function( ) return 100 end,
        reply     = function( ) end,
    }
end

local function load_plugin( )
    _listeners = { }
    assert( loadfile( "scripts/usr_uptime.lua" ) )( )
end

local function fire( ev, ... )
    local fn = _listeners[ ev ]
    if fn then return fn( ... ) end
end

local function credited( nick )
    local u = _saved and _saved[ nick ]
    if not u or not u[ YEAR ] or not u[ YEAR ][ MONTH ] then return 0 end
    return u[ YEAR ][ MONTH ].complete or 0
end

----------------------------------------------------------------------
-- Test 1: busy hub. A is online 24/7; other users churn (a logout more
-- than once per 60s). A must still be credited by the periodic timer.
-- Pre-fix: set_stop's start-reset starves the timer -> A credited 0.
----------------------------------------------------------------------
_saved  = { }
_online = { }
_now    = _base
load_plugin( )

local userA = make_user( "Alice" )
_online[ 1 ] = userA
fire( "onLogin", userA )            -- last_tick[Alice] = _base

for i = 1, 300 do
    _now = _now + 1
    fire( "onTimer" )
    if i % 30 == 0 then
        -- a transient user logs out ~every 30s -> resets `start` pre-fix
        fire( "onLogout", make_user( "transient" .. i ) )
    end
end

local c1 = credited( "Alice" )
truthy( "busy hub: 24/7 user credited by timer despite churn (>=240 of 300s), got " .. c1,
    c1 >= 240 )

----------------------------------------------------------------------
-- Test 2: +reload. A stays connected across a reload (no fresh onLogin).
-- onStart must re-seed A's tracking, else the timer skips A forever.
-- Pre-fix: after reload A is untracked -> stops accumulating.
----------------------------------------------------------------------
_saved  = { }
_online = { }
_now    = _base
load_plugin( )

local userB = make_user( "Bob" )
_online[ 1 ] = userB
fire( "onLogin", userB )

for _ = 1, 120 do _now = _now + 1; fire( "onTimer" ) end
local before_reload = credited( "Bob" )
truthy( "pre-reload: quiet hub credits online user (~120s), got " .. before_reload,
    before_reload >= 100 )

-- simulate +reload: re-run the script (RAM last_tick reset; _saved
-- persists via util.loadtable), then the hub fires onStart. Bob is
-- still online.
load_plugin( )
fire( "onStart" )

for _ = 1, 120 do _now = _now + 1; fire( "onTimer" ) end
local after_reload = credited( "Bob" )
truthy( "reload: online user keeps accumulating across +reload (+>=100s), got "
    .. before_reload .. " -> " .. after_reload,
    after_reload >= before_reload + 100 )

----------------------------------------------------------------------
-- Test 3: sanity - a clean single-session credit tracks elapsed time
-- and a logout persists it. Passes pre- and post-fix; guards the happy
-- path.
----------------------------------------------------------------------
_saved  = { }
_online = { }
_now    = _base
load_plugin( )

local userC = make_user( "Carol" )
_online[ 1 ] = userC
fire( "onLogin", userC )
for _ = 1, 120 do _now = _now + 1; fire( "onTimer" ) end
fire( "onLogout", userC )
_online[ 1 ] = nil
eq( "single session: 120s online credited exactly on logout", credited( "Carol" ), 120 )

----------------------------------------------------------------------
-- Test 4: hub-crash regression (v0.13.1). A freshly updated / empty hub
-- whose scripts/data/usr_uptime.tbl is MISSING (util.loadtable -> nil)
-- must not crash when the 60s onTimer tick fires before any login has
-- lazily created the table. Pre-fix uptime_tbl stayed nil and onTimer
-- called util.savetable( nil, ... ), which errors in the serialiser
-- ("bad argument #1 to 'for iterator' (table expected, got nil)"); the
-- savetable stub above reproduces that error faithfully.
----------------------------------------------------------------------
_saved  = nil                       -- missing / unreadable store -> loadtable returns nil
_online = { }                       -- empty hub: no login lazily creates the table
_now    = _base
load_plugin( )

_now = _base + 61                   -- open the 60s onTimer credit gate
local ok, err = pcall( function( ) fire( "onTimer" ) end )
truthy( "missing store + empty hub: onTimer does not crash on save (err="
    .. tostring( err ) .. ")", ok )
truthy( "missing store: onTimer persists a table, not nil (got "
    .. type( _saved ) .. ")", type( _saved ) == "table" )

----------------------------------------------------------------------
if failures > 0 then
    io.write( string.format( "\n%d passed, %d failed\n", checks - failures, failures ) )
    os.exit( 1 )
end
io.write( string.format( "\n%d passed, 0 failed\n", checks ) )
