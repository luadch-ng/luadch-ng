--[[

    tests/unit/etc_records_test.lua

    Regression test for scripts/etc_records.lua v0.9 (#465): a missing /
    empty / truncated / corrupt etc_records.tbl must not crash the onLogin
    max-tracking listeners.

    `records` is a positional 8-slot table. The onLogin (+ onTimer)
    handlers do `new > tonumber(records[3|6|8])` in hubshare / onliners /
    topshare. Before v0.9 the load did `util.loadtable(p) or { }` - which
    guards a nil TABLE but not nil SLOTS - so an empty / partial file left
    records[3|6|8] nil and every login raised "attempt to compare nil with
    number", spamming the error log. v0.9 seeds each slot at load.

    Provably fails pre-fix: on v0.8 firing onLogin against an empty records
    table errors inside hubshare(); the pcall below catches it and the
    assertion fails.

    The stubs return ZERO online users and log in a user with share 0, so
    none of the three comparisons beats its (seeded) record - no record is
    written and no broadcast path runs, so this test needs no bc* stubs.

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/etc_records_test.lua

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
local _loaded          -- what util.loadtable returns for the records file
local _online          -- what hub.getusers returns
local _listeners       -- event -> fn
local _saved           -- last util.savearray payload (unused by the no-record path)
local _http            -- "METHOD path" -> handler, captured from hub.http_register in onStart

local _real_os = os

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math
_G.PROCESSED = "PROCESSED"
_G.utf = { match = function( ) end, format = function( ) return "" end }
_G.os = setmetatable( {
    time = function( ) return 1000 end,
    date = function( fmt, t ) return _real_os.date( fmt, t or 1000 ) end,
}, { __index = _real_os } )

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        if k == "etc_records_delay" then return 60 end
        if k == "etc_records_reportlvl" then return 0 end   -- numeric: sendItTo compares against it
        -- sendPM / sendMain left nil (falsy) so the record-write broadcast
        -- path runs its user loop but sends nothing (no user:reply needed).
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    loadtable   = function( ) return _loaded end,
    savearray   = function( t ) _saved = t end,
    formatbytes = function( n ) return tostring( n ) .. " B" end,
    strip_control_bytes = function( s ) return s end,
}

_G.hub = {
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    -- onStart asserts etc_hubcommands is present; return a minimal stub so
    -- onStart can run (and register the HTTP handlers) in the #618 case below.
    import      = function( name )
        if name == "etc_hubcommands" then return { add = function( ) return true end } end
        return nil
    end,
    getbot      = function( ) return { } end,
    getusers    = function( ) return _online end,
    debug       = function( ) end,
    broadcast   = function( ) end,
    http_register = function( method, path, _scope, handler ) _http[ method .. " " .. path ] = handler end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function make_user( nick, share )
    return {
        isbot     = function( ) return false end,
        firstnick = function( ) return nick end,
        nick      = function( ) return nick end,
        share     = function( ) return share end,
        level     = function( ) return 100 end,   -- sendItTo reads user:level()
        reply     = function( ) end,
    }
end

local function load_plugin( )
    _listeners = { }
    _saved = nil
    _http = { }
    assert( loadfile( "scripts/etc_records.lua" ) )( )
end

-- fire onLogin under pcall; returns true on clean run, false + err on crash
local function fire_login( user )
    local fn = _listeners[ "onLogin" ]
    if not fn then return false, "no onLogin listener registered" end
    return pcall( fn, user, user.nick and user:nick( ) )
end

----------------------------------------------------------------------
-- Case 1: completely empty file (util.loadtable -> {}). The core bug.
----------------------------------------------------------------------
_loaded = { }
_online = { }                          -- zero online users
load_plugin( )
local u = make_user( "alice", 0 )      -- share 0: never beats a record
local okrun, err = fire_login( u )
ok( "empty records file: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 2: truncated file - only the date/time slots survived, the
-- numeric max slots [3]/[6]/[8] are missing.
----------------------------------------------------------------------
_loaded = { [1] = "2020-01-01", [2] = "12:00:00", [4] = "2020-01-01", [5] = "12:00:00" }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "bob", 0 ) )
ok( "truncated records file: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3: corrupt file - a numeric max slot persisted as a non-numeric
-- string. tonumber(...) or N must repair it, not crash the compare.
----------------------------------------------------------------------
_loaded = { [3] = "garbage", [6] = "x", [8] = "y" }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "carol", 0 ) )
ok( "corrupt (non-numeric) max slots: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3b: isolate the records[6] (onliners) crash site. records[3] is
-- valid so hubshare() passes, but records[6] is nil -> onliners()'
-- `onlineusers > tonumber(records[6])` is the compare that must not
-- crash. Without this, all the crash cases above short-circuit at
-- records[3] in hubshare() and the [6]/[8] sites are never red-proven.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", nil, "none", 0 }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "dan", 0 ) )
ok( "nil records[6] only (onliners site): onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3c: isolate the records[8] (topshare) crash site. records[3] and
-- [6] valid so hubshare()/onliners() pass; records[8] nil -> topshare()'
-- `target_usershare > tonumber(records[8])` is the compare under test.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", 5, "none", nil }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "eve", 0 ) )
ok( "nil records[8] only (topshare site): onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 4: a well-formed existing file must still work AND preserve its
-- values - a login with a bigger share updates the record via savearray.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", 5, "dave", 50 }
_online = { [1] = make_user( "erin", 999999 ) }   -- one online user, big share
load_plugin( )
okrun, err = fire_login( make_user( "erin", 999999 ) )
ok( "well-formed file: onLogin does not crash", okrun, err )
ok( "well-formed file: a bigger share was recorded (savearray fired)", _saved ~= nil )
if _saved then
    ok( "recorded share slot is numeric and grew", type( _saved[3] ) == "number" and _saved[3] >= 100, _saved[3] )
end

----------------------------------------------------------------------
-- Case 5: #618 - a fresh (never-recorded) hub reports hub_share.total_bytes
-- = 0, not the legacy vestigial 1. Fire onStart to register the HTTP
-- handlers, then call GET /v1/records and assert all three counters are 0.
-- Regression per CLAUDE.md 1a.7: on the pre-fix init guard (`records[3]
-- ... or 1`) this GET returned total_bytes = 1 and this assertion FAILED;
-- post-fix (`or 0`) it returns 0.
----------------------------------------------------------------------
_loaded = { }                          -- fresh hub: empty records file
_online = { }                          -- no online users -> onStart samples nothing
load_plugin( )
assert( _listeners[ "onStart" ], "onStart not registered" )
_listeners[ "onStart" ]( )
local GET = _http[ "GET /v1/records" ]
ok( "records: GET /v1/records registered in onStart", GET ~= nil )
if GET then
    local r = GET( { } )
    ok( "records: fresh hub_share.total_bytes is 0 (#618)", r.data.hub_share.total_bytes == 0, r.data.hub_share.total_bytes )
    ok( "records: fresh max_users.count is 0",             r.data.max_users.count == 0,        r.data.max_users.count )
    ok( "records: fresh top_sharer.share_bytes is 0",      r.data.top_sharer.share_bytes == 0, r.data.top_sharer.share_bytes )
    ok( "records: fresh top_sharer.nick is 'none'",        r.data.top_sharer.nick == "none",   r.data.top_sharer.nick )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL etc_records_test\n" ); os.exit( 1 ) end
io.write( "OK etc_records_test\n" )
