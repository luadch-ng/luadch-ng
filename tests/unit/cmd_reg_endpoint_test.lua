--[[

    tests/unit/cmd_reg_endpoint_test.lua

    Regression test for the per-operator permission ceiling on
    POST /v1/registered (cmd_reg, #708 arc action A5).

    Unlike the other #708 actions, the reg ceiling is on the GRANTED level
    (the body's requested `level`), not a target user's level: an operator
    may not register a user at a level ABOVE their cmd_reg_permission
    ceiling, mirroring the ADC `+reg` guard `permission[user_level] < level`.
    The check sits right after the level is validated and BEFORE
    hub.reguser mutates anything.

    To keep an ALLOWED / SKIPPED request from actually registering, the mock
    hub.reguser returns an error, so a request that PASSES the ceiling falls
    through to the 500 "reguser failed" path - distinguishing it from the
    403 DENY (which returns before hub.reguser is ever called).

    Cases:
      - operator (60) granting level 100 (above ceiling 60) -> 403 E_FORBIDDEN
      - no resolvable actor level -> ceiling skipped -> 500 (past the ceiling)
      - hubowner (100) granting level 60 (within ceiling) -> 500 (past ceiling)

    FAIL-PRE-FIX: without the ceiling block the DENY case returns 500
    (reguser stub error) instead of 403 - the test is red.

    Run: lua5.4 tests/unit/cmd_reg_endpoint_test.lua

]]--

local _cfg = {
    language               = "en",
    cmd_reg_permission     = { [50] = 50, [60] = 60, [100] = 100 },
    tcp_ports              = { },
    ssl_ports              = { 5001 },
    tcp_ports_ipv6         = { },
    ssl_ports_ipv6         = { 5001 },
    hub_hostaddress        = "127.0.0.1",
    hub_name               = "TestHub",
    hub_email              = "a@b.c",
    use_keyprint           = false,
    keyprint_type          = "",
    keyprint_hash          = "",
    min_nickname_length    = 3,
    max_nickname_length    = 64,
    cmd_reg_report         = false,
    cmd_reg_llevel         = 80,
    cmd_reg_report_hubbot  = false,
    cmd_reg_report_opchat  = false,
    levels                 = { [0] = "Unreg", [40] = "SVIP", [60] = "Operator", [100] = "Hubowner" },
}

_G.os = os; _G.string = string; _G.table = table; _G.math = math
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    checkusers   = function( ) end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    loadtable           = function( ) return { } end,   -- empty blacklist
    strip_control_bytes = function( s ) return s end,
    generatepass        = function( ) return "genpass1" end,
    getlowestlevel      = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }
_G.hub = {
    setlistener = function( ) end,
    debug       = function( ) end,
    escapeto    = function( s ) return s end,
    import      = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    getregusers = function( ) return { }, { }, { } end,
    -- forced error so a request PAST the ceiling stops at the 500 path
    reguser     = function( ) return nil, "test-stop" end,
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

local p = assert( loadfile( "scripts/cmd_reg.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_create_reguser, "cmd_reg must export _http_handler_create_reguser" )

local function req( granted_level, actor_level )
    return { body = { nick = "Newbie", level = granted_level }, _actor_level = actor_level }
end

do
    local r = p._http_handler_create_reguser( req( 100, 60 ) )
    ok( "reg: op (60) granting level 100 (above ceiling) -> denied", r and r.status == 403 )
    ok( "reg: denial code is E_FORBIDDEN", r and r.error and r.error.code == "E_FORBIDDEN" )
end
do
    -- no resolvable actor level -> ceiling skipped -> reaches hub.reguser (500 stub)
    local r = p._http_handler_create_reguser( req( 60, nil ) )
    ok( "reg: no actor level -> ceiling skipped (500 past ceiling, not 403)", r and r.status == 500 )
end
do
    -- hubowner (ceiling 100) granting level 60 -> within ceiling -> 500 (past)
    local r = p._http_handler_create_reguser( req( 60, 100 ) )
    ok( "reg: hubowner (100) granting level 60 clears the ceiling (500, not 403)", r and r.status == 500 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
