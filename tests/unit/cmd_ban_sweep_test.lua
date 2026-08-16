--[[

    tests/unit/cmd_ban_sweep_test.lua

    Regression test for the periodic expired-ban sweep (cmd_ban v0.48).

    Before v0.48 an expired NON-permanent ban was only pruned lazily, on
    the banned user's next onConnect. A tempban on someone who never comes
    back lingered in `bans` - and in `+ban show` / GET /v1/bans / the WebUI
    - forever. v0.48 adds an onTimer sweep that removes exactly what the
    onConnect handler would (an expired non-permanent ban, identical
    `remaining < 0` test), just on a timer instead of waiting for a
    reconnect. It must:
      - register an onTimer listener at all (the sweep),
      - throttle to once per 60s (onTimer fires every second - do not
        savearray on every tick),
      - prune an expired non-permanent ban and persist once (changed),
      - NEVER prune a permanent ban (its placeholder time 0 reads as
        long-expired - the same trap the onConnect handler guards),
      - keep a still-active ban,
      - mutate `bans` IN PLACE (importers capture the exported ban.bans
        reference - a rebind would leave them stale, the #239 lesson),
      - not savearray when a sweep removed nothing.

    FAIL-PRE-FIX: on the unpatched plugin (<= v0.47) there is no onTimer
    listener, so the sweep never runs - the "onTimer registered" check and
    every prune assertion are red.

    Run: lua5.4 tests/unit/cmd_ban_sweep_test.lua

]]--

-- A controllable clock. The plugin reads `os.time` as a GLOBAL each call
-- (no `local os = os` capture), so overriding _G.os drives both the sweep
-- throttle baseline (_last_sweep = os.time() at load) and the remaining
-- calc. difftime is overridden as a - b; everything else falls through to
-- the real os (date, exit, ...).
local real_os = os
local fake_now = 1000000
local T0 = fake_now                 -- load-time baseline: _last_sweep = os.time() = T0
_G.os = setmetatable( {
    time     = function( ) return fake_now end,
    difftime = function( a, b ) return a - b end,
}, { __index = real_os } )

-- cfg the plugin reads at load.
local _cfg = {
    language              = "en",
    cmd_ban_default_time  = 60,
    cmd_ban_permission    = { [ 60 ] = 60, [ 100 ] = 100 },
    cmd_ban_report        = false,
    cmd_ban_report_hubbot = false,
    cmd_ban_report_opchat = false,
    cmd_ban_llevel        = 80,
    cmd_unban_permission  = { [ 60 ] = 60, [ 100 ] = 100 },
}

_G.PROCESSED = "PROCESSED"
_G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type

-- Seed bans in place: the plugin binds `bans = util.loadtable(bans_path)`
-- to THIS table and exports it as ban.bans, so asserting on p.bans (below)
-- inspects exactly what the sweep mutates.
local SEED = {
    { nick = "Active",  cid = "", hash = "TIGR", ip = "", time = 7200, start = T0,        reason = "r", by_nick = "op", by_level = 60 },
    { nick = "Expired", cid = "", hash = "TIGR", ip = "", time = 60,   start = T0 - 3600, reason = "r", by_nick = "op", by_level = 60 },
    { nick = "Perm",    cid = "", hash = "TIGR", ip = "", time = 0, permanent = true, start = T0 - 3600, reason = "r", by_nick = "op", by_level = 60 },
}

local saved = 0
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    loadtable = function( path )
        if type( path ) == "string" and path:find( "cmd_ban_bans" ) then return SEED end
        return { }
    end,
    getlowestlevel = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
    savearray = function( ) saved = saved + 1 end,
    savetable = function( ) end,
    strip_control_bytes = function( s ) return s end,
    formatseconds = function( ) return 0, 0, 0, 0, 0 end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }

-- Capture the listeners the plugin registers at load (we fire onTimer).
local listeners = { }
_G.hub = {
    setlistener              = function( event, tbl, fn ) listeners[ event ] = fn end,
    debug                    = function( ) end,
    getbot                   = function( ) return "bot" end,
    getregusers              = function( ) return { } end,
    import                   = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    isnickonline             = nil,
    find_online_by_firstnick = function( ) return nil end,
}

local p = assert( loadfile( "scripts/cmd_ban.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- The export reference must be the very table we seeded (in-place proof).
ok( "ban.bans is the seeded table (export ref)", p.bans == SEED )

local onTimer = listeners.onTimer
ok( "onTimer listener is registered (the sweep exists)", type( onTimer ) == "function" )
onTimer = ( type( onTimer ) == "function" ) and onTimer or function( ) end

-- 1) Throttle: a fire within 60s of load must not sweep or save.
onTimer( )
ok( "throttled within 60s: nothing pruned", #p.bans == 3 )
ok( "throttled within 60s: no save",        saved == 0 )

-- 2) Past the interval: the expired non-permanent ban is pruned, once.
fake_now = T0 + 120
onTimer( )
ok( "after interval: one entry pruned",     #p.bans == 2 )
ok( "after interval: exactly one save",     saved == 1 )
ok( "mutation was IN PLACE (export ref preserved)", p.bans == SEED )

local by = { }
for _, b in ipairs( p.bans ) do by[ b.nick ] = b end
ok( "active ban kept",        by.Active ~= nil )
ok( "permanent ban kept",     by.Perm ~= nil )
ok( "expired ban removed",    by.Expired == nil )

-- 3) Far future: the once-active ban is now expired and removed, but the
--    permanent ban survives even when it is the last one left (the guard).
fake_now = T0 + 100000
onTimer( )
by = { }
for _, b in ipairs( p.bans ) do by[ b.nick ] = b end
ok( "far-future: now-expired active ban removed", by.Active == nil )
ok( "far-future: permanent ban STILL kept",       by.Perm ~= nil )
ok( "far-future: only the permanent ban remains", #p.bans == 1 )
ok( "far-future: the extra removal saved again",  saved == 2 )

-- 4) A sweep that removes nothing must not save (no disk churn per tick).
fake_now = T0 + 200000
local saved_before = saved
onTimer( )
ok( "no-op sweep: no save",                   saved == saved_before )
ok( "no-op sweep: permanent ban still there", #p.bans == 1 )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
