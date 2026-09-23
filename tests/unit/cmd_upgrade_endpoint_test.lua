--[[

    tests/unit/cmd_upgrade_endpoint_test.lua

    Regression test for the per-operator permission ceiling on
    PUT /v1/registered/{nick}/level (cmd_upgrade, #708 arc action A8).

    Unlike the other #708 actions, +upgrade enforces a TRIPLE guard (ADC
    cmd_upgrade.lua ~209) - DENY when the operator level resolves AND any of:
      (a) the target's CURRENT level is above the operator's own level,
      (b) the GRANTED level is above the operator's ceiling,
      (c) the target's CURRENT level is above the operator's ceiling.
    (b)/(c) are the shared ceiling_denied; (a) is a direct hierarchy compare.
    The check sits after the target is resolved and BEFORE the level mutation.

    permission = { [50]=40, [60]=50, [65]=80, [100]=100 }. The [60]=50 entry
    (ceiling below its own level) isolates (b) and (c); the [65]=80 entry
    (ceiling ABOVE its own level) isolates (a) - a level-70 target is above the
    operator's own level 65 but below the ceiling 80, so only (a) trips:
      (a) op 60 upgrading a level-70 target        -> trips (a) AND (c)
      (a-isolated) op 65 upgrading a level-70 to 45 -> 70 > 65 own only
      (b) op 60 granting level 55 to a level-40    -> 55 > 50 (ceiling)
      (c) op 60 upgrading a level-55 target to 45  -> 55 > 50 (ceiling), not >60
      skip: no actor level                          -> 200
      allow: hubowner (100) upgrading 40 -> 60      -> 200

    FAIL-PRE-FIX: without the triple block every deny case returns 200.

    Run: lua5.4 tests/unit/cmd_upgrade_endpoint_test.lua

]]--

local _regnicks = {
    Sup = { nick = "Sup", level = 70, is_bot = 0 },
    Mid = { nick = "Mid", level = 55, is_bot = 0 },
    Reg = { nick = "Reg", level = 40, is_bot = 0 },
}
local function reset_levels( )
    _regnicks.Sup.level = 70
    _regnicks.Mid.level = 55
    _regnicks.Reg.level = 40
end

local _cfg = {
    language                     = "en",
    -- [65]=80 has a ceiling ABOVE its own level, so a level-70 target trips ONLY
    -- branch (a) (70>65 own, but 70<=80 ceiling) - isolating the own-level rule.
    cmd_upgrade_permission       = { [ 50 ] = 40, [ 60 ] = 50, [ 65 ] = 80, [ 100 ] = 100 },
    cmd_upgrade_advanced_rc      = false,
    usr_nick_prefix_activate     = false,
    usr_nick_prefix_prefix_table = { },
    cmd_upgrade_report           = false,
    cmd_upgrade_llevel           = 80,
    cmd_upgrade_report_hubbot    = false,
    cmd_upgrade_report_opchat    = false,
    levels                       = { [0] = "Unreg", [40] = "SVIP", [45] = "L45", [55] = "L55", [60] = "Operator", [70] = "Supervisor", [100] = "Hubowner" },
}

_G.os = os; _G.string = string; _G.table = table; _G.math = math
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
    getbot       = function( ) return { nick = function( ) return "bot" end } end,
    getusers     = function( ) return { }, { } end,
    getregusers  = function( ) return { }, _regnicks, { } end,
    escapeto     = function( s ) return s end,
    issidonline  = function( ) return nil end,
    isnickonline = function( ) return nil end,   -- target offline -> no kick
    import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
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

local p = assert( loadfile( "scripts/cmd_upgrade.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_set_level, "cmd_upgrade must export _http_handler_set_level" )

local function req( nick, granted, actor_level )
    return { path_vars = { nick = nick }, body = { level = granted }, _actor_level = actor_level }
end

do -- (a) target current level (70) above the operator's own level (60)
    reset_levels( )
    local r = p._http_handler_set_level( req( "Sup", 40, 60 ) )
    ok( "upgrade (a): target above operator's own level -> 403", r and r.status == 403 )
    ok( "upgrade (a): E_FORBIDDEN + no mutation", r and r.error and r.error.code == "E_FORBIDDEN" and _regnicks.Sup.level == 70 )
end
do -- (a) ISOLATED: op level 65 (ceiling 80, ABOVE its own level) upgrading a
    -- level-70 target to 45 - trips ONLY (a): 70 > 65 (own) YES, granted 45 <= 80,
    -- target 70 <= 80. So a regression that breaks ONLY branch (a) is caught here.
    reset_levels( )
    local r = p._http_handler_set_level( req( "Sup", 45, 65 ) )
    ok( "upgrade (a) isolated: target above own level only (ceiling clears) -> 403", r and r.status == 403 )
    ok( "upgrade (a) isolated: no mutation", _regnicks.Sup.level == 70 )
end
do -- (b) granted level (55) above the operator's ceiling (50)
    reset_levels( )
    local r = p._http_handler_set_level( req( "Reg", 55, 60 ) )
    ok( "upgrade (b): granted level above ceiling -> 403", r and r.status == 403 )
    ok( "upgrade (b): no mutation", _regnicks.Reg.level == 40 )
end
do -- (c) target current level (55) above the operator's ceiling (50) but not their own level
    reset_levels( )
    local r = p._http_handler_set_level( req( "Mid", 45, 60 ) )
    ok( "upgrade (c): target current above ceiling -> 403", r and r.status == 403 )
end
do -- skip: no resolvable actor level -> ceiling skipped -> 200
    reset_levels( )
    local r = p._http_handler_set_level( req( "Reg", 55, nil ) )
    ok( "upgrade: no actor level -> ceiling skipped (200)", r and r.status == 200 )
end
do -- allow: hubowner (ceiling 100) upgrading a level-40 target to 60
    reset_levels( )
    local r = p._http_handler_set_level( req( "Reg", 60, 100 ) )
    ok( "upgrade: hubowner clears the triple guard (200)", r and r.status == 200 )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
