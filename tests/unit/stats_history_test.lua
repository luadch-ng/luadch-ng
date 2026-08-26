--[[

    tests/unit/stats_history_test.lua

    Feature contract for scripts/etc_stats_history.lua (#665): the
    multi-tier RRD-style consolidation (`_record_tier`) + the sampler fan-out
    + the GET /v1/stats/history handler.

    `_record_tier(points, slot, cap, now, count)` must:
      - align a new bucket to `now - now % slot` and push it,
      - keep the MAX count while `now` stays in the same slot,
      - trim the oldest points once the array exceeds `cap`.

    onStart must seed one sample into all three tiers and register the GET
    handler; the handler must return the tier matching `?range` (default 24h,
    unknown -> 24h) with `{t, count}` points.

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/stats_history_test.lua

]]--

local checks, failures = 0, 0
local function ok( label, cond, extra )
    checks = checks + 1
    if not cond then failures = failures + 1
        io.write( "FAIL " .. label .. ( extra and ( " - " .. tostring( extra ) ) or "" ) .. "\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- mutable state the stubs close over
----------------------------------------------------------------------
local _store           -- what util.loadtable returns (and savetable persists back)
local _saved           -- last util.savetable payload
local _online_count    -- how many online users hub.getusers returns
local _now             -- what os.time returns
local _listeners       -- event -> fn
local _http            -- "METHOD path" -> handler

local _real_os = os
local _real_io = io

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math
_G.os = setmetatable( { time = function( ) return _now end }, { __index = _real_os } )
-- The plugin probes the store file with io.open before util.loadtable (so a
-- missing file logs nothing). Stub io.open to always succeed so load_store
-- reads the injected `_store` via the util.loadtable stub; io.write etc. fall
-- through to the real io so this harness's own output still works.
_G.io = setmetatable( { open = function( ) return { close = function( ) end } end }, { __index = _real_io } )

_G.util = {
    loadtable = function( ) return _store end,
    -- persist back so a subsequent load (e.g. the endpoint) sees the sample
    savetable = function( t ) _saved = t; _store = t end,
}

local function make_online( n )
    local t = { }
    for i = 1, n do t[ i ] = { isbot = function( ) return false end } end
    return t
end

_G.hub = {
    setlistener   = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    getusers      = function( ) return make_online( _online_count ) end,
    http_register = function( method, path, _scope, handler ) _http[ method .. " " .. path ] = handler end,
    debug         = function( ) end,
}

local function load_plugin( )
    _listeners = { }
    _http = { }
    _saved = nil
    return assert( loadfile( "scripts/etc_stats_history.lua" ) )( )
end

----------------------------------------------------------------------
-- Group 1: _record_tier consolidation (pure)
----------------------------------------------------------------------
_store = nil; _online_count = 0; _now = 1000
local plugin = load_plugin( )
local rt = plugin._record_tier
ok( "exports _record_tier", type( rt ) == "function" )

local pts = { }
rt( pts, 600, 144, 1000, 5 )                 -- now 1000, slot 600 -> bucket 600
ok( "first push aligns bucket to now - now%slot", pts[ 1 ] and pts[ 1 ].t == 600, pts[ 1 ] and pts[ 1 ].t )
ok( "first push stores the count",               pts[ 1 ] and pts[ 1 ].c == 5, pts[ 1 ] and pts[ 1 ].c )

rt( pts, 600, 144, 1100, 8 )                 -- 1100 -> same bucket 600, higher count
ok( "same bucket keeps the max (raises)",        #pts == 1 and pts[ 1 ].c == 8, pts[ 1 ].c )

rt( pts, 600, 144, 1150, 3 )                 -- same bucket, lower count -> ignored
ok( "same bucket ignores a lower count",         #pts == 1 and pts[ 1 ].c == 8, pts[ 1 ].c )

rt( pts, 600, 144, 1300, 4 )                 -- 1300 -> bucket 1200, new
ok( "a later slot pushes a new bucket",          #pts == 2 and pts[ 2 ].t == 1200 and pts[ 2 ].c == 4,
    pts[ 2 ] and ( pts[ 2 ].t .. "/" .. pts[ 2 ].c ) )

-- capacity trim: cap 2, push three distinct buckets -> oldest dropped
local p2 = { }
rt( p2, 600, 2, 600,  1 )
rt( p2, 600, 2, 1200, 2 )
rt( p2, 600, 2, 1800, 3 )
ok( "capacity trim drops the oldest bucket",
    #p2 == 2 and p2[ 1 ].t == 1200 and p2[ 2 ].t == 1800, #p2 .. ":" .. p2[ 1 ].t )

-- a backward clock step (a sample landing in an OLDER slot than the last) is
-- dropped, keeping the endpoint's oldest -> newest ordering intact
local p3 = { }
rt( p3, 600, 144, 2000, 5 )                  -- bucket 1800
rt( p3, 600, 144, 1000, 9 )                  -- bucket 600 < 1800 -> dropped
ok( "backward clock step is dropped (order preserved)",
    #p3 == 1 and p3[ 1 ].t == 1800 and p3[ 1 ].c == 5, #p3 .. ":" .. p3[ 1 ].t )

----------------------------------------------------------------------
-- Group 2: onStart seeds one sample into all three tiers
----------------------------------------------------------------------
_store = nil; _online_count = 3; _now = 100000
load_plugin( )
assert( _listeners[ "onStart" ], "onStart not registered" )
_listeners[ "onStart" ]( )
ok( "onStart persisted a store",           _saved ~= nil )
ok( "tier1 seeded with the online count",  _saved and _saved.tier1 and #_saved.tier1 == 1 and _saved.tier1[ 1 ].c == 3 )
ok( "tier2 seeded with the online count",  _saved and _saved.tier2 and #_saved.tier2 == 1 and _saved.tier2[ 1 ].c == 3 )
ok( "tier3 seeded with the online count",  _saved and _saved.tier3 and #_saved.tier3 == 1 and _saved.tier3[ 1 ].c == 3 )

----------------------------------------------------------------------
-- Group 3: GET /v1/stats/history returns the tier matching ?range
----------------------------------------------------------------------
local GET = _http[ "GET /v1/stats/history" ]
ok( "onStart registered GET /v1/stats/history", GET ~= nil )
if GET then
    local r = GET( { } )                                   -- no query -> default 24h
    ok( "default range is 24h / 600s",   r.data.range == "24h" and r.data.interval_sec == 600,
        r.data.range .. "/" .. r.data.interval_sec )
    ok( "points carry {t, count}",       r.data.points[ 1 ] and r.data.points[ 1 ].count == 3 and r.data.points[ 1 ].t ~= nil )

    local r7 = GET( { query = { range = "7d" } } )
    ok( "range 7d -> tier2 / 3600s",     r7.data.range == "7d" and r7.data.interval_sec == 3600 )

    local r30 = GET( { query = { range = "30d" } } )
    ok( "range 30d -> tier3 / 21600s",   r30.data.range == "30d" and r30.data.interval_sec == 21600 )

    local rbad = GET( { query = { range = "bogus" } } )
    ok( "unknown range falls back to 24h", rbad.data.range == "24h" )
end

----------------------------------------------------------------------
-- Group 4: load_store degrades safely (the #445 io.open-probe path)
----------------------------------------------------------------------
local ls = plugin._load_store
ok( "exports _load_store", type( ls ) == "function" )

-- io.open returns nil (missing file): util.loadtable must be SKIPPED (no
-- checkfile-error log) and the tiers come back empty, not crash.
_store = { tier1 = { { t = 1, c = 9 } } }   -- would be returned IF loadtable ran
_G.io = setmetatable( { open = function( ) return nil end }, { __index = _real_io } )
local s_missing = ls( )
ok( "missing file (io.open nil) -> loadtable skipped, empty tiers",
    #s_missing.tier1 == 0 and #s_missing.tier2 == 0 and #s_missing.tier3 == 0 )
-- restore the always-succeed io.open stub for the remaining cases
_G.io = setmetatable( { open = function( ) return { close = function( ) end } end }, { __index = _real_io } )

-- corrupt store (loadtable returns a non-table) -> empty tiers
_store = "garbage"
local s_corrupt = ls( )
ok( "corrupt store degrades to empty tiers", type( s_corrupt.tier1 ) == "table" and #s_corrupt.tier1 == 0 )

-- partial store: a present tier is kept, absent tiers are seeded empty
_store = { tier1 = { { t = 600, c = 3 } } }
local s_partial = ls( )
ok( "partial store: present tier kept, missing tiers seeded",
    #s_partial.tier1 == 1 and s_partial.tier1[ 1 ].c == 3
    and type( s_partial.tier2 ) == "table" and #s_partial.tier2 == 0 )

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL stats_history_test\n" ); os.exit( 1 ) end
io.write( "OK stats_history_test\n" )
