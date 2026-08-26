--[[

    tests/unit/etc_records_test.lua

    Regression test for scripts/etc_records.lua.

    Two concerns are covered:

    1. #465 crash-safety (v0.9): a missing / empty / truncated / corrupt
       records file must not crash the onLogin max-tracking listeners.
       Since v0.11 the store is a NAMED-KEY table and load_records()
       migrates the legacy positional format on load - so these cases now
       also prove the MIGRATION degrades gracefully on a broken legacy file.

    2. #647 named store + two new peaks (v0.11): the record store migrates
       from the positional 8-slot table to a named-key table, PRESERVING
       every existing value (a 3.1.x operator keeps their records across the
       3.1 -> 3.2 upgrade), and gains two silent peaks - hub_files (peak
       total filecount) and top_file_sharer (biggest single filecount) -
       surfaced at GET /v1/records and in `+records show`.

    Provably fails pre-fix (per CLAUDE.md 1a.7): on v0.10 (positional store,
    no filecount tracking) GET /v1/records has no hub_files / top_file_sharer
    objects and the store never rebinds to a named shape, so cases 6 + 7
    (and the named-store assertion in case 4) FAIL; they PASS on v0.11. The
    mock provides both util.savearray and util.savetable so the old plugin
    runs cleanly and only the new-behaviour assertions go red.

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
local _saved           -- last util.savetable payload (named store, v0.11+)
local _saved_legacy    -- last util.savearray payload (legacy path, for RED runs)
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
    savetable   = function( t ) _saved = t end,         -- v0.11 named store
    savearray   = function( t ) _saved_legacy = t end,  -- legacy path (old plugin, RED runs)
    formatbytes = function( n ) return tostring( n ) .. " B" end,
    strip_control_bytes = function( s ) return s end,
}

_G.hub = {
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    -- onStart asserts etc_hubcommands is present; return a minimal stub so
    -- onStart can run (and register the HTTP handlers).
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
local function make_user( nick, share, files )
    return {
        isbot     = function( ) return false end,
        firstnick = function( ) return nick end,
        nick      = function( ) return nick end,
        share     = function( ) return share end,
        files     = function( ) return files or 0 end,
        level     = function( ) return 100 end,   -- sendItTo reads user:level()
        reply     = function( ) end,
    }
end

local function load_plugin( )
    _listeners = { }
    _saved = nil
    _saved_legacy = nil
    _http = { }
    assert( loadfile( "scripts/etc_records.lua" ) )( )
end

-- fire onLogin under pcall; returns true on clean run, false + err on crash
local function fire_login( user )
    local fn = _listeners[ "onLogin" ]
    if not fn then return false, "no onLogin listener registered" end
    return pcall( fn, user, user.nick and user:nick( ) )
end

-- register the HTTP handlers, then return the GET /v1/records handler.
local function get_records_handler( )
    assert( _listeners[ "onStart" ], "onStart not registered" )
    _listeners[ "onStart" ]( )
    return _http[ "GET /v1/records" ]
end

----------------------------------------------------------------------
-- Case 1: completely empty file (util.loadtable -> {}). load_records
-- returns fresh defaults; onLogin with zero online users / share 0 must
-- not crash.
----------------------------------------------------------------------
_loaded = { }
_online = { }                          -- zero online users
load_plugin( )
local okrun, err = fire_login( make_user( "alice", 0 ) )
ok( "empty records file: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 2: truncated legacy positional file - only the date/time slots
-- survived, the numeric max slots [3]/[6]/[8] are missing. Migration must
-- coerce the missing numerics to 0, not crash.
----------------------------------------------------------------------
_loaded = { [1] = "2020-01-01", [2] = "12:00:00", [4] = "2020-01-01", [5] = "12:00:00" }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "bob", 0 ) )
ok( "truncated legacy file: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3: corrupt legacy file - a numeric max slot persisted as a
-- non-numeric string. Migration's tonumber(...) or 0 must repair it.
----------------------------------------------------------------------
_loaded = { [3] = "garbage", [6] = "x", [8] = "y" }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "carol", 0 ) )
ok( "corrupt (non-numeric) legacy slots: onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3b: nil [6] only (onliners site) - [3] valid so hubshare passes,
-- [6] nil exercises onliners' max-compare.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", nil, "none", 0 }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "dan", 0 ) )
ok( "nil legacy [6] (onliners site): onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 3c: nil [8] only (topshare site) - [3]/[6] valid, [8] nil
-- exercises topshare's max-compare.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", 5, "none", nil }
_online = { }
load_plugin( )
okrun, err = fire_login( make_user( "eve", 0 ) )
ok( "nil legacy [8] (topshare site): onLogin does not crash", okrun, err )

----------------------------------------------------------------------
-- Case 4: a well-formed legacy file migrates AND a login with a bigger
-- share updates the record via the NAMED store (util.savetable). This is
-- one of the RED-on-v0.10 cases: the old plugin saves via savearray, so
-- _saved (savetable) stays nil and the named-store assertions fail.
----------------------------------------------------------------------
_loaded = { "2020-01-01", "12:00:00", 100, "2020-01-01", "12:00:00", 5, "dave", 50 }
_online = { [1] = make_user( "erin", 999999, 4242 ) }   -- one online user, big share + files
load_plugin( )
okrun, err = fire_login( make_user( "erin", 999999, 4242 ) )
ok( "well-formed legacy file: onLogin does not crash", okrun, err )
ok( "record written via named savetable", _saved ~= nil )
if _saved then
    ok( "named store: hub_share.bytes is numeric and grew",
        type( _saved.hub_share ) == "table" and _saved.hub_share.bytes >= 100, _saved.hub_share and _saved.hub_share.bytes )
end

----------------------------------------------------------------------
-- Case 5: fresh (never-recorded) hub - every counter 0, every nick
-- "none", INCLUDING the two new #647 records. (#618 kept for hub_share.)
----------------------------------------------------------------------
_loaded = { }                          -- fresh hub: empty records file
_online = { }                          -- no online users
load_plugin( )
local GET = get_records_handler( )
ok( "GET /v1/records registered in onStart", GET ~= nil )
if GET then
    local r = GET( { } ).data
    ok( "fresh hub_share.total_bytes is 0 (#618)", r.hub_share.total_bytes == 0, r.hub_share.total_bytes )
    ok( "fresh max_users.count is 0",              r.max_users.count == 0,        r.max_users.count )
    ok( "fresh top_sharer.share_bytes is 0",       r.top_sharer.share_bytes == 0, r.top_sharer.share_bytes )
    ok( "fresh top_sharer.nick is 'none'",         r.top_sharer.nick == "none",   r.top_sharer.nick )
    -- #647 new records (RED on v0.10: these objects do not exist).
    ok( "fresh hub_files.count is 0 (#647)",             ( r.hub_files or { } ).count == 0, r.hub_files and r.hub_files.count )
    ok( "fresh top_file_sharer.file_count is 0 (#647)",  ( r.top_file_sharer or { } ).file_count == 0, r.top_file_sharer and r.top_file_sharer.file_count )
    ok( "fresh top_file_sharer.nick is 'none' (#647)",   ( r.top_file_sharer or { } ).nick == "none", r.top_file_sharer and r.top_file_sharer.nick )
end

----------------------------------------------------------------------
-- Case 6: MIGRATION value preservation (#647). A well-formed legacy
-- positional file migrates to the named store, and GET /v1/records
-- reports the SAME legacy values (share 100, users 5, top dave/50) plus
-- the two new records seeded to their defaults. RED on v0.10: the new
-- objects are nil.  No online users, so onStart samples nothing that
-- could overwrite the migrated values.
----------------------------------------------------------------------
_loaded = { "2019-05-05", "08:00:00", 100, "2019-06-06", "09:00:00", 5, "dave", 50 }
_online = { }
load_plugin( )
GET = get_records_handler( )
if GET then
    local r = GET( { } ).data
    ok( "migrate: hub_share.total_bytes preserved (100)", r.hub_share.total_bytes == 100, r.hub_share.total_bytes )
    ok( "migrate: hub_share.recorded_at preserved",       r.hub_share.recorded_at == "2019-05-05 / 08:00:00", r.hub_share.recorded_at )
    ok( "migrate: max_users.count preserved (5)",         r.max_users.count == 5, r.max_users.count )
    ok( "migrate: top_sharer.nick preserved (dave)",      r.top_sharer.nick == "dave", r.top_sharer.nick )
    ok( "migrate: top_sharer.share_bytes preserved (50)", r.top_sharer.share_bytes == 50, r.top_sharer.share_bytes )
    -- new records seeded (RED on v0.10: nil).
    ok( "migrate: hub_files.count seeded 0 (#647)",            ( r.hub_files or { } ).count == 0, r.hub_files and r.hub_files.count )
    ok( "migrate: top_file_sharer.nick seeded 'none' (#647)", ( r.top_file_sharer or { } ).nick == "none", r.top_file_sharer and r.top_file_sharer.nick )
end

----------------------------------------------------------------------
-- Case 7: the two new peaks actually track (#647). Three online users
-- with filecounts (100 / 250 / 777); the biggest (carol, 777) logs in.
-- hub_files aggregates the online SF sum (1127); top_file_sharer records
-- the login user's single filecount (777). RED on v0.10 (no SF tracking).
----------------------------------------------------------------------
_loaded = { }
local carol = make_user( "carol", 5, 777 )
_online = { make_user( "alice", 10, 100 ), make_user( "bob", 20, 250 ), carol }
load_plugin( )
GET = get_records_handler( )
okrun, err = fire_login( carol )
ok( "filecount peaks: onLogin does not crash", okrun, err )
if GET then
    local r = GET( { } ).data
    ok( "hub_files aggregates online SF sum (1127)",     ( r.hub_files or { } ).count == 1127, r.hub_files and r.hub_files.count )
    ok( "top_file_sharer records login user (carol)",    ( r.top_file_sharer or { } ).nick == "carol", r.top_file_sharer and r.top_file_sharer.nick )
    ok( "top_file_sharer.file_count is the single peak (777)", ( r.top_file_sharer or { } ).file_count == 777, r.top_file_sharer and r.top_file_sharer.file_count )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL etc_records_test\n" ); os.exit( 1 ) end
io.write( "OK etc_records_test\n" )
