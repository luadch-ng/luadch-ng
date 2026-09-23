--[[

    tests/unit/cmd_setpass_endpoint_test.lua

    Regression test for the per-operator permission ceiling on
    PUT /v1/registered/{nick}/password (cmd_setpass, #708 arc action A6).

    The HTTP setpass handler must refuse to change the password of a target
    ABOVE the acting operator's cmd_setpass_permission ceiling, mirroring
    the ADC `+setpass nick` guard `(permission[user_level] or 0) < target_level`.
    The check sits after the target is resolved (404 not-found / bot guards)
    and BEFORE `profile.password = ...` / `cfg.saveusers` mutate anything.

    An ALLOWED / SKIPPED request reaches the normal 200 (the mock
    cfg.saveusers is a no-op and the target resolves offline), so 403 (deny)
    vs 200 (allow/skip) is the distinguisher.

    Cases (target Vip is level 100):
      - operator (60) -> 403 E_FORBIDDEN (ceiling 60 < 100)
      - no resolvable actor level -> ceiling skipped -> 200
      - hubowner (100) -> within ceiling -> 200

    FAIL-PRE-FIX: without the ceiling block the DENY case returns 200 - red.

    Run: lua5.4 tests/unit/cmd_setpass_endpoint_test.lua

]]--

local _regnicks = {
    Vip = { level = 100, is_bot = 0, password = "oldpassword" },
}

local _cfg = {
    language                       = "en",
    cmd_setpass_permission         = { [50] = 50, [60] = 60, [100] = 100 },
    cmd_setpass_permission_own_pw  = { [100] = true },
    usr_nick_prefix_activate       = false,
    usr_nick_prefix_prefix_table   = { },
    cmd_setpass_advanced_rc        = false,
    min_password_length            = 10,
    max_password_length            = 32,
}

_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    saveusers    = function( ) end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.util = {
    strip_control_bytes = function( s ) return s end,
    getlowestlevel      = function( tbl )
        local lo
        for lvl in pairs( tbl ) do if not lo or lvl < lo then lo = lvl end end
        return lo or 0
    end,
}
_G.audit = { build = function( ) return { } end, fire = function( ) end }
_G.hub = {
    setlistener  = function( ) end,
    debug        = function( ) end,
    escapeto     = function( s ) return s end,
    getbot       = function( ) return "bot" end,
    import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    getregusers  = function( ) return { }, _regnicks, { } end,
    isnickonline = function( ) return nil end,   -- target offline -> no notify
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

local p = assert( loadfile( "scripts/cmd_setpass.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_set_password, "cmd_setpass must export _http_handler_set_password" )

local function req( actor_level )
    return { path_vars = { nick = "Vip" }, body = { password = "newpassword12" }, _actor_level = actor_level }
end

do
    local r = p._http_handler_set_password( req( 60 ) )
    ok( "setpass: below-ceiling op (60) on a level-100 target -> denied", r and r.status == 403 )
    ok( "setpass: denial code is E_FORBIDDEN", r and r.error and r.error.code == "E_FORBIDDEN" )
end
do
    -- no resolvable actor level -> ceiling skipped -> normal 200
    local r = p._http_handler_set_password( req( nil ) )
    ok( "setpass: no actor level -> ceiling skipped (200, not 403)", r and r.status == 200 )
end
do
    -- hubowner (ceiling 100) clears a level-100 target -> normal 200
    local r = p._http_handler_set_password( req( 100 ) )
    ok( "setpass: hubowner (100) clears the ceiling (200, not 403)", r and r.status == 200 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
