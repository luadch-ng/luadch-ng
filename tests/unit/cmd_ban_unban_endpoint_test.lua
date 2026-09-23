--[[

    tests/unit/cmd_ban_unban_endpoint_test.lua

    Regression test for the per-operator permission ceiling on BOTH mutating
    cmd_ban HTTP endpoints (#708 arc):
      - POST /v1/bans        (create ban, action A1 / #709) - cmd_ban_permission
      - DELETE /v1/bans/{id} (unban,      action A7 / #716) - cmd_unban_permission

    CREATE (POST /v1/bans): the handler must refuse to ban a target above the
    acting operator's cmd_ban_permission ceiling, mirroring the ADC `+ban` guard
    `permission[level] < target:level()`. Target level = the live level for an
    online victim, else the stored registered level for an offline nick. The
    check sits STRICTLY BEFORE `addban(...)`.
    Cases (offline nick "baduser" registered at level 100):
      - operator (60) -> 403 E_FORBIDDEN, and NO ban is added
      - no resolvable actor level -> ceiling skipped -> 200 (ban added)
      - hubowner (100) -> within ceiling -> 200 (ban added)
    FAIL-PRE-FIX: without the ceiling block the DENY case reaches addban,
    returns 200 and adds the entry - the test is red.

    UNBAN (DELETE /v1/bans/{id}): the handler must refuse to lift a ban whose
    recorded `by_level` is above the operator's cmd_unban_permission ceiling,
    mirroring the ADC `+unban` guard `permission2[user_level] < (ban.by_level
    or 100)`. HTTP-created bans store by_level=100, so only a ceiling>=100
    operator lifts them. The check sits after the 404 not-found guard and
    STRICTLY BEFORE `table.remove(bans, id)`.
    Cases (the ban entry has by_level = 100):
      - operator (60) -> 403 E_FORBIDDEN, and the ban is NOT removed
      - no resolvable actor level -> ceiling skipped -> 200 (ban removed)
      - hubowner (100) -> within ceiling -> 200 (ban removed)
    FAIL-PRE-FIX: without the ceiling block the DENY case returns 200 and
    removes the ban - the test is red.

    Run: lua5.4 tests/unit/cmd_ban_unban_endpoint_test.lua

]]--

local real_os = os
_G.os = setmetatable( {
    time     = function( ) return 1000000 end,
    difftime = function( a, b ) return a - b end,
}, { __index = real_os } )

local _cfg = {
    language              = "en",
    cmd_ban_default_time  = 60,
    cmd_ban_permission    = { [ 50 ] = 50, [ 60 ] = 60, [ 100 ] = 100 },
    cmd_ban_report        = false,
    cmd_ban_report_hubbot = false,
    cmd_ban_report_opchat = false,
    cmd_ban_llevel        = 80,
    cmd_unban_permission  = { [ 50 ] = 50, [ 60 ] = 60, [ 100 ] = 100 },
}

_G.PROCESSED = "PROCESSED"
_G.string = string; _G.table = table; _G.math = math
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type

-- The plugin binds `bans = util.loadtable(bans_path)` to SEED and exports it
-- as p.bans, so we reseed p.bans in place before each case.
local SEED = { }

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
    savearray           = function( ) end,
    savetable           = function( ) end,
    strip_control_bytes = function( s ) return s end,
    formatseconds       = function( ) return 0, 0, 0, 0, 0 end,
    date                = function( ) return "2026-01-01" end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }
_G.hub = {
    setlistener              = function( ) end,
    debug                    = function( ) end,
    getbot                   = function( ) return { nick = function( ) return "bot" end } end,
    getregusers              = function( ) return { }, { }, { } end,
    import                   = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    isnickonline             = function( ) return nil end,
    find_online_by_firstnick = function( ) return nil end,
}
_G.util_http = {
    operator_label = function( req ) return ( req and req.actor ) or "http-api" end,
    actor_level    = function( req ) return req and req._actor_level end,
    ceiling_denied = function( permission, operator_level, target_level )
        if operator_level == nil or target_level == nil then return false end
        local ceiling = ( permission and permission[ operator_level ] ) or 0
        return ceiling < target_level
    end,
}

local p = assert( loadfile( "scripts/cmd_ban.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_create_ban, "cmd_ban must export _http_handler_create_ban" )
assert( p and p._http_handler_delete_ban, "cmd_ban must export _http_handler_delete_ban" )
assert( p.bans == SEED, "p.bans must be the seeded table" )

local function seed_one( )
    for i = #p.bans, 1, -1 do p.bans[ i ] = nil end
    p.bans[ 1 ] = { nick = "baduser", cid = "", ip = "", hash = "TIGR",
                    reason = "r", by_nick = "op", by_level = 100,
                    time = 0, permanent = true, start = 1000000 }
end
local function req( actor_level ) return { path_vars = { id = "1" }, _actor_level = actor_level } end

-- ==== create-ban ceiling (POST /v1/bans, #708 A1 / #709) ====
-- Offline nick "baduser" registered at level 100 -> a mid-level operator is over
-- their cmd_ban_permission ceiling. http_find_online resolves nil (offline), so the
-- target level comes from the registered record; the ceiling check runs before addban.
local real_getregusers = hub.getregusers
hub.getregusers = function( ) return { }, { baduser = { level = 100 } }, { } end
local function creq( actor_level )
    return { actor = "op", _actor_level = actor_level,
             body = { target_type = "nick", target = "baduser", duration_minutes = 60, reason = "r" } }
end
local function clear_bans( ) for i = #p.bans, 1, -1 do p.bans[ i ] = nil end end

do
    clear_bans( )
    local r = p._http_handler_create_ban( creq( 60 ) )
    ok( "create: op (60) banning a level-100 nick -> denied", r and r.status == 403 )
    ok( "create: denial code is E_FORBIDDEN", r and r.error and r.error.code == "E_FORBIDDEN" )
    ok( "create: a denied ban did NOT add an entry", #p.bans == 0 )
end
do
    clear_bans( )
    local r = p._http_handler_create_ban( creq( nil ) )
    ok( "create: no actor level -> ceiling skipped (200)", r and r.status == 200 )
    ok( "create: skip added the ban", #p.bans == 1 )
end
do
    clear_bans( )
    local r = p._http_handler_create_ban( creq( 100 ) )
    ok( "create: hubowner (100) clears the ceiling (200)", r and r.status == 200 )
end
hub.getregusers = real_getregusers

do
    seed_one( )
    local r = p._http_handler_delete_ban( req( 60 ) )
    ok( "unban: op (60) lifting a by_level-100 ban -> denied", r and r.status == 403 )
    ok( "unban: denial code is E_FORBIDDEN", r and r.error and r.error.code == "E_FORBIDDEN" )
    ok( "unban: a denied unban did NOT remove the ban", p.bans[ 1 ] ~= nil )
end
do
    seed_one( )
    local r = p._http_handler_delete_ban( req( nil ) )
    ok( "unban: no actor level -> ceiling skipped (200)", r and r.status == 200 )
    ok( "unban: skip removed the ban", p.bans[ 1 ] == nil )
end
do
    seed_one( )
    local r = p._http_handler_delete_ban( req( 100 ) )
    ok( "unban: hubowner (100) clears the ceiling (200)", r and r.status == 200 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
