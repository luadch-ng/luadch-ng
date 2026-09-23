--[[

    tests/unit/cmd_redirect_endpoint_test.lua

    Regression test for the per-operator permission ceiling on
    POST /v1/users/{sid}/redirect (cmd_redirect, #708 arc action A3).

    The HTTP redirect handler must refuse to redirect a target ABOVE the
    acting operator's cmd_redirect_permission ceiling, mirroring the ADC
    `+redirect` guard `(permission[user:level()] or 0) < target_level`.
    The check is the FIRST statement of the handler, before the url
    resolution, so a below-ceiling operator is rejected with 403 before
    anything happens.

    Cases (the url is deliberately left empty and cfg cmd_redirect_url is
    unset, so an ALLOWED / SKIPPED request falls through to the 400
    no-url path - distinguishing it from the 403 DENY without needing the
    real do_redirect side effects):
      - below-ceiling operator (60) on a level-100 target -> 403 E_FORBIDDEN
      - no resolvable actor level -> ceiling skipped -> 400 no-url (not 403)
      - hubowner (100) clears the ceiling -> 400 no-url (not 403)

    FAIL-PRE-FIX: without the ceiling block the DENY case returns 400
    (no-url) instead of 403 - the test is red.

    Run: lua5.4 tests/unit/cmd_redirect_endpoint_test.lua

]]--

local _cfg = {
    language                    = "en",
    levels                      = { [0] = "Unreg", [60] = "Operator", [100] = "Hubowner" },
    cmd_redirect_activate       = true,
    cmd_redirect_permission     = { [50] = 50, [60] = 60, [100] = 100 },
    cmd_redirect_level          = { },
    cmd_redirect_url            = "",   -- unset: an allowed request hits the 400 no-url path
    cmd_redirect_report         = false,
    cmd_redirect_report_hubbot  = false,
    cmd_redirect_report_opchat  = false,
    cmd_redirect_llevel         = 80,
}

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
    loadtable           = function( ) return { } end,
    strip_control_bytes = function( s ) return s end,
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
    getbot      = function( ) return "bot" end,
    getregusers = function( ) return { } end,
    import      = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
}
-- util_http: the operator label + the permission-ceiling helpers the HTTP
-- redirect handler uses (#708). actor_level is driven per-call by
-- req._actor_level; ceiling_denied mirrors the real util_http logic.
_G.util_http = {
    operator_label = function( req ) return ( req and req.actor ) or "http-api" end,
    actor_level    = function( req ) return req and req._actor_level end,
    ceiling_denied = function( permission, operator_level, target_level )
        if operator_level == nil or target_level == nil then return false end
        local ceiling = ( permission and permission[ operator_level ] ) or 0
        return ceiling < target_level
    end,
}

local p = assert( loadfile( "scripts/cmd_redirect.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_redirect, "cmd_redirect must export _http_handler_redirect" )

local vip = {
    level = function( ) return 100 end,
    nick  = function( ) return "Vip" end,
}

do
    local d, e = p._http_handler_redirect( { _actor_level = 60 }, vip )
    ok( "redirect: below-ceiling op (60) on a level-100 target -> denied", d == nil and e and e.status == 403 )
    ok( "redirect: denial code is E_FORBIDDEN", e and e.error and e.error.code == "E_FORBIDDEN" )
end
do
    -- no resolvable actor level -> ceiling SKIPPED -> falls through to the
    -- 400 no-url path (backward-compatible with a direct token call)
    local d, e = p._http_handler_redirect( { }, vip )
    ok( "redirect: no actor level -> ceiling skipped (400 no-url, not 403)", d == nil and e and e.status == 400 )
end
do
    -- hubowner (ceiling 100) clears a level-100 target -> passes the ceiling,
    -- then hits the 400 no-url (distinguishes ALLOW from the 403 DENY)
    local d, e = p._http_handler_redirect( { _actor_level = 100 }, vip )
    ok( "redirect: hubowner (100) clears the ceiling (400 no-url, not 403)", d == nil and e and e.status == 400 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
