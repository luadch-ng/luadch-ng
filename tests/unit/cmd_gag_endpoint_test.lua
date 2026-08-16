--[[

    tests/unit/cmd_gag_endpoint_test.lua

    Regression test for the GET /v1/gags read endpoint (cmd_gag v0.15).
    The handler lists the gags the hub is currently enforcing, for the
    WebUI's status-aware Gag/Ungag toggle. It must:
      - list EVERY entry present in gag_tbl (= the ADC `+gag show`
        surface), INCLUDING one already past its expires_at that the
        60s cleanup timer has not yet swept - check_user_input does not
        consult expires_at, so the hub keeps muting such a user and
        reporting the gag as active is what matches enforcement,
      - emit added_at / expires_at as ISO 8601 UTC (HTTP_API §7.4,
        matching the POST sibling + /v1/bans), nil-guarded so a
        permanent gag (no expires_at) or a pre-v0.09 entry (no
        added_at) does not get stamped with the current time,
      - resolve each entry's live sid via hub.find_online_by_firstnick
        (so the WebUI can join a gag onto /v1/users[].sid), leaving sid
        nil for an offline gagged reguser.

    FAIL-PRE-FIX: on the unpatched plugin (<= v0.14) there is no
    _http_handler_list_gags export, so the call is `attempt to call a
    nil value` - the test is red. The behavioural assertions pin the
    handler logic.

    Run: lua5.4 tests/unit/cmd_gag_endpoint_test.lua

]]--

-- Mutable cfg + the sandbox-global stubs the plugin reads at load.
local _cfg = {
    language                = "en",
    cmd_gag_permission      = { [50] = 50, [60] = 60, [100] = 100 },
    hub_bot                 = "HubBot",
    cmd_gag_user_notifiy    = false,
    cmd_gag_report          = false,
    cmd_gag_llevel          = 80,
    cmd_gag_report_hubbot   = false,
    cmd_gag_report_opchat   = false,
    bot_opchat_nick         = "OpChat",
    bot_opchat_permission   = { [100] = 100 },
    bot_regchat_nick        = "RegChat",
    bot_regchat_permission  = { [100] = 100 },
}

_G.PROCESSED = "PROCESSED"
_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    loadtable = function( ) return { } end,
    getlowestlevel = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
    strip_control_bytes = function( s ) return s end,
    savearray = function( ) end,
    formatseconds = function( ) return 0, 0, 0, 0, 0 end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }

-- A single online user (OnlineBob) resolvable by firstnick, exposing a
-- sid. Everyone else is offline (nil). The handler binds
-- find_online_by_firstnick from this table at LOAD time, so it must be
-- set before loadfile.
local ONLINE = {
    OnlineBob = { sid = function( ) return "AAAB" end },
}
_G.hub = {
    setlistener            = function( ) end,
    debug                  = function( ) end,
    getbot                 = function( ) return "bot" end,
    getregusers            = function( ) return { } end,
    import                 = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    isnickonline           = nil,
    find_online_by_firstnick = function( nick ) return ONLINE[ nick ] end,
}

local p = assert( loadfile( "scripts/cmd_gag.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- Same UTC ISO 8601 formatter the handler uses, so the expected values
-- are computed the identical way (no timezone drift - `!` forces UTC).
local function iso( epoch ) return os.date( "!%Y-%m-%dT%H:%M:%SZ", epoch ) end

-- Seed the live gag table in place (the plugin returned the very same
-- table as _gag_tbl, so the handler iterates what we push here).
local function seed( entries )
    for i = #p._gag_tbl, 1, -1 do p._gag_tbl[ i ] = nil end
    for _, e in ipairs( entries ) do p._gag_tbl[ #p._gag_tbl + 1 ] = e end
end

local now    = os.time( )
local FUTURE = now + 3600
local PAST   = now - 3600
seed( {
    { user_nick = "OnlineBob",    mode = "mute",       added_by = "op",  added_at = 1000 },                     -- online, permanent
    { user_nick = "OfflineAlice", mode = "kennylize",  added_by = "op2", added_at = 1001 },                     -- offline, permanent
    { user_nick = "ExpiredGus",   mode = "shadowmute", added_by = "op",  added_at = 900,  expires_at = PAST },  -- past expiry, still enforced -> listed
    { user_nick = "TimedTom",     mode = "mute",       added_by = "op",  added_at = 1002, expires_at = FUTURE },-- future expiry, offline
} )

local res = p._http_handler_list_gags( { } )

ok( "status is 200",                res and res.status == 200 )
ok( "envelope carries data.gags",   res and res.data and type( res.data.gags ) == "table" )

local gags = ( res and res.data and res.data.gags ) or { }
ok( "every enforced gag is listed (4 of 4, incl. past-expiry)", #gags == 4 )

-- index by firstnick for order-independent assertions
local by = { }
for _, g in ipairs( gags ) do by[ g.firstnick ] = g end

ok( "OnlineBob listed",                         by.OnlineBob ~= nil )
ok( "OnlineBob carries the resolved sid",       by.OnlineBob and by.OnlineBob.sid == "AAAB" )
ok( "OnlineBob mode preserved",                 by.OnlineBob and by.OnlineBob.mode == "mute" )
ok( "OnlineBob added_by preserved",             by.OnlineBob and by.OnlineBob.added_by == "op" )
ok( "OnlineBob added_at is ISO 8601 UTC",       by.OnlineBob and by.OnlineBob.added_at == iso( 1000 ) )
ok( "OnlineBob permanent -> expires_at nil",    by.OnlineBob and by.OnlineBob.expires_at == nil )

ok( "OfflineAlice listed",                      by.OfflineAlice ~= nil )
ok( "OfflineAlice sid is nil (offline)",        by.OfflineAlice and by.OfflineAlice.sid == nil )
ok( "OfflineAlice mode preserved",              by.OfflineAlice and by.OfflineAlice.mode == "kennylize" )

-- enforcement-truth: a gag past its expiry but not yet swept is STILL
-- muting the user (check_user_input ignores expires_at), so it must be
-- listed with its (past) expiry, not hidden.
ok( "ExpiredGus (past expiry) STILL listed",    by.ExpiredGus ~= nil )
ok( "ExpiredGus expires_at is ISO of the past", by.ExpiredGus and by.ExpiredGus.expires_at == iso( PAST ) )
ok( "ExpiredGus sid is nil (offline)",          by.ExpiredGus and by.ExpiredGus.sid == nil )

ok( "TimedTom (future expiry) listed",          by.TimedTom ~= nil )
ok( "TimedTom expires_at is ISO of the future", by.TimedTom and by.TimedTom.expires_at == iso( FUTURE ) )
ok( "TimedTom sid is nil (offline)",            by.TimedTom and by.TimedTom.sid == nil )

-- empty store -> empty list, still a well-formed envelope
seed( { } )
local empty = p._http_handler_list_gags( { } )
ok( "empty store: status 200",                  empty and empty.status == 200 )
ok( "empty store: gags is an empty array",      empty and empty.data and #empty.data.gags == 0 )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
