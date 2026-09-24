--[[

    tests/unit/cmd_disconnect_endpoint_test.lua

    Regression test for the per-operator hierarchy guard on
    DELETE /v1/users/{sid} (cmd_disconnect, #708 arc A9 / #718).

    The HTTP disconnect handler must refuse to kick a target ABOVE the acting
    operator's own level, mirroring the ADC `+disconnect` guard
    `user_level < targetuser_level`. Unlike the cmd_*_permission ceiling actions
    (ban/gag/redirect/...), disconnect uses a plain level compare (no permission
    map), so the check is a direct `op_level ~= nil and target:level() > op_level`,
    NOT util_http.ceiling_denied. It sits at the START of the handler, before
    do_disconnect kills anything. The handler returns `(nil, {status=403,...})`
    on deny (the util_http.http_register_user_action error contract).

    Cases (target is level 100):
      - operator (60) -> 403 E_FORBIDDEN, and the target is NOT kicked
      - no resolvable actor level -> guard skipped -> proceeds (target kicked)
      - operator (100) -> at/above the target -> proceeds (target kicked)

    FAIL-PRE-FIX: without the guard the DENY case proceeds, kills the target and
    returns no error - the test is red.

    Run: lua5.4 tests/unit/cmd_disconnect_endpoint_test.lua

]]--

local _cfg = {
    language                      = "en",
    cmd_disconnect_minlevel       = 20,
    cmd_disconnect_llevel         = 80,
    cmd_disconnect_report         = false,
    cmd_disconnect_report_hubbot  = false,
    cmd_disconnect_report_opchat  = false,
    usr_nick_prefix_activate      = false,
    usr_nick_prefix_prefix_table  = { },
}

_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( ) return "" end,
}
_G.util = {
    strip_control_bytes = function( s ) return s end,
    getlowestlevel      = function( tbl )
        if type( tbl ) ~= "table" then return 0 end
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }

-- Capture whether the target was actually kicked (the mutation).
local killed = false
_G.hub = {
    setlistener              = function( ) end,
    debug                    = function( ) end,
    escapeto                 = function( s ) return s end,
    getbot                   = function( ) return { nick = function( ) return "bot" end } end,
    isnickonline             = function( ) return nil end,
    getusers                 = function( ) return { } end,
    import                   = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
}
_G.util_http = {
    operator_label = function( req ) return ( req and req.actor ) or "http-api" end,
    actor_level    = function( req ) return req and req._actor_level end,
}

local p = assert( loadfile( "scripts/cmd_disconnect.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_disconnect, "cmd_disconnect must export _http_handler_disconnect" )

local function target( level )
    return {
        level = function( ) return level end,
        nick  = function( ) return "victim" end,
        kill  = function( ) killed = true end,
    }
end
local function req( actor_level ) return { _actor_level = actor_level, body = { reason = "r" } } end

do
    killed = false
    local data, err = p._http_handler_disconnect( req( 60 ), target( 100 ) )
    ok( "disconnect: op (60) kicking a level-100 target -> denied", err and err.status == 403 )
    ok( "disconnect: denial code is E_FORBIDDEN", err and err.error and err.error.code == "E_FORBIDDEN" )
    ok( "disconnect: a denied kick did NOT kill the target", killed == false )
    ok( "disconnect: deny returns no data table", data == nil )
end
do
    killed = false
    local data, err = p._http_handler_disconnect( req( nil ), target( 100 ) )
    ok( "disconnect: no actor level -> guard skipped (proceeds)", err == nil and data ~= nil )
    ok( "disconnect: skip kicked the target", killed == true )
end
do
    killed = false
    local data, err = p._http_handler_disconnect( req( 100 ), target( 100 ) )
    ok( "disconnect: op (100) at the target level clears the guard (proceeds)", err == nil and data ~= nil )
    ok( "disconnect: allow kicked the target", killed == true )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
