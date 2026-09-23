--[[

    tests/unit/cmd_delreg_endpoint_test.lua

    Regression test for the per-operator permission ceiling on
    DELETE /v1/registered/{nick} (cmd_delreg, #708 arc action A4).

    The HTTP delreg handler must refuse to delreg a target ABOVE the acting
    operator's cmd_delreg_permission ceiling, mirroring the ADC `+delreg`
    guard `(permission[user_level] or 0) < target_level`. The check sits
    right after the target level is resolved and BEFORE hub.delreguser
    mutates anything.

    To keep an ALLOWED / SKIPPED request from actually deleting, the mock
    hub.delreguser returns an error, so a request that PASSES the ceiling
    falls through to the 500 "delreguser failed" path - distinguishing it
    from the 403 DENY (which returns before delreguser is ever called).

    Cases:
      - below-ceiling operator (60) on a level-100 target -> 403 E_FORBIDDEN
      - no resolvable actor level -> ceiling skipped -> 500 (past the ceiling)
      - hubowner (100) clears the ceiling -> 500 (past the ceiling)

    FAIL-PRE-FIX: without the ceiling block the DENY case returns 500
    (delreguser stub error) instead of 403 - the test is red.

    Run: lua5.4 tests/unit/cmd_delreg_endpoint_test.lua

]]--

local _regnicks = {
    Vip = { level = 100, is_bot = 0 },
}

local _cfg = {
    cmd_delreg_permission        = { [50] = 50, [60] = 60, [100] = 100 },
    language                     = "en",
    usr_nick_prefix_activate     = false,
    usr_nick_prefix_prefix_table = { },
    cmd_delreg_report            = false,
    cmd_delreg_llevel            = 80,
    cmd_delreg_report_hubbot     = false,
    cmd_delreg_report_opchat     = false,
}

_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    checkusers   = function( ) end,
}
_G.util = {
    loadtable           = function( ) return { } end,
    strip_control_bytes = function( s ) return s end,
    getlowestlevel      = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
}
_G.hub = {
    setlistener  = function( ) end,
    debug        = function( ) end,
    escapeto     = function( s ) return s end,
    import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    getregusers  = function( ) return { }, _regnicks, { } end,
    -- forced error so a request that PASSES the ceiling stops at the 500
    -- path (before any real cascade), marking "ceiling cleared".
    delreguser   = function( ) return nil, "test-stop" end,
    isnickonline = function( ) return nil end,
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

local p = assert( loadfile( "scripts/cmd_delreg.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_delreguser, "cmd_delreg must export _http_handler_delreguser" )

local function req( actor_level )
    return { path_vars = { nick = "Vip" }, _actor_level = actor_level }
end

do
    local r = p._http_handler_delreguser( req( 60 ) )
    ok( "delreg: below-ceiling op (60) on a level-100 target -> denied", r and r.status == 403 )
    ok( "delreg: denial code is E_FORBIDDEN", r and r.error and r.error.code == "E_FORBIDDEN" )
end
do
    -- no resolvable actor level -> ceiling skipped -> reaches delreguser (500 stub)
    local r = p._http_handler_delreguser( req( nil ) )
    ok( "delreg: no actor level -> ceiling skipped (500 past ceiling, not 403)", r and r.status == 500 )
end
do
    -- hubowner (ceiling 100) clears a level-100 target -> reaches delreguser (500)
    local r = p._http_handler_delreguser( req( 100 ) )
    ok( "delreg: hubowner (100) clears the ceiling (500 past ceiling, not 403)", r and r.status == 500 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
