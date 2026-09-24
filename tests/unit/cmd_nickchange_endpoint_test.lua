--[[

    tests/unit/cmd_nickchange_endpoint_test.lua

    Regression test for the per-operator hierarchy guard AND the operator
    attribution on PUT /v1/registered/{nick}/nick (cmd_nickchange, #726).

    Two fixes under test:
      1. Hierarchy guard (#726 / #718 class): the HTTP nickchange handler must
         refuse to rename a registered user ABOVE the acting operator's own
         level - otherwise a mid-level operator opened up by the WebUI
         capability model could rename the hubowner. nickchange has no
         cmd_*_permission ceiling map, so the check is a direct level compare
         `op_level ~= nil and target_level > op_level` (mirrors cmd_disconnect's
         #718 guard), NOT util_http.ceiling_denied. It sits before any mutation.
      2. Attribution (#726 / #713 class): the report + audit actor must be the
         X-Actor operator (util_http.operator_label), not the raw API token
         label (req.token_label) the handler used before.

    Cases (target reguser is level 100):
      - operator (60) -> 403 E_FORBIDDEN, and the profile is NOT renamed
      - no resolvable actor level -> guard skipped -> rename proceeds (200)
      - operator (100) at/above the target -> rename proceeds (200), and the
        audit actor is the X-Actor operator nick, not the token label

    FAIL-PRE-FIX:
      - without the guard the DENY case renames the level-100 target and
        returns 200 - red.
      - without the attribution fix the audit actor is the token label ("tok..")
        instead of the operator nick - red.

    Run: lua5.4 tests/unit/cmd_nickchange_endpoint_test.lua

]]--

local _cfg = {
    language                       = "en",
    nick_change                    = true,
    min_nickname_length            = 1,
    max_nickname_length            = 64,
    cmd_nickchange_minlevel        = 20,
    cmd_nickchange_oplevel         = 60,
    usr_nick_prefix_activate       = false,
    usr_nick_prefix_prefix_table   = { },
    cmd_nickchange_advanced_rc     = false,
    cmd_nickchange_report          = false,
    cmd_nickchange_report_hubbot   = false,
    cmd_nickchange_report_opchat   = false,
}

_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring
_G.ipairs = ipairs; _G.pairs = pairs; _G.type = type

-- The reg set the handler resolves its target from; swapped per case
-- (a successful rename mutates profile.nick in place).
local regusers_list, regnicks

_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    saveusers    = function( ) end,
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
    loadtable = function( ) return { } end,
    savetable = function( ) end,
}

-- Capture the audit actor nick (the attribution under test).
local captured_actor = nil
_G.audit = {
    build = function( _action, actor ) captured_actor = actor and actor.nick; return { } end,
    fire  = function( ) end,
}

_G.hub = {
    setlistener  = function( ) end,
    debug        = function( ) end,
    escapeto     = function( s ) return s end,
    isnickonline = function( ) return nil end,   -- target offline -> no kick path
    updateusers  = function( ) end,
    import       = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        return nil
    end,
    getregusers  = function( ) return regusers_list, regnicks end,
}
_G.util_http = {
    operator_label = function( req ) return ( req and req.actor ) or "http-api" end,
    actor_level    = function( req ) return req and req._actor_level end,
}

local p = assert( loadfile( "scripts/cmd_nickchange.lua" ) )( )

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

assert( p and p._http_handler_set_nick, "cmd_nickchange must export _http_handler_set_nick" )

local OLD_NICK = "target_user"
local NEW_NICK = "renamed_user"

local function make_regset( level )
    local profile = { nick = OLD_NICK, level = level, is_bot = 0 }
    regusers_list = { profile }
    regnicks = { [ OLD_NICK ] = profile }
    return profile
end

local function req( actor_level, actor_nick )
    return {
        path_vars    = { nick = OLD_NICK },
        body         = { new_nick = NEW_NICK },
        _actor_level = actor_level,
        actor        = actor_nick,
        token_label  = "tok(1234)",   -- the pre-fix attribution source
    }
end

-- DENY: operator (60) renaming a level-100 reguser
do
    local profile = make_regset( 100 )
    local out = p._http_handler_set_nick( req( 60, "op60" ) )
    ok( "nickchange: op (60) renaming a level-100 reg -> 403", out and out.status == 403 )
    ok( "nickchange: denial code is E_FORBIDDEN", out and out.error and out.error.code == "E_FORBIDDEN" )
    ok( "nickchange: a denied rename did NOT mutate the profile", profile.nick == OLD_NICK )
end

-- SKIP: no resolvable actor level -> guard skipped -> rename proceeds
do
    local profile = make_regset( 100 )
    local out = p._http_handler_set_nick( req( nil, "opX" ) )
    ok( "nickchange: no actor level -> guard skipped (proceeds 200)", out and out.status == 200 )
    ok( "nickchange: skip renamed the profile", profile.nick == NEW_NICK )
end

-- ALLOW + attribution: operator (100) at the target level proceeds; audit
-- actor is the X-Actor operator nick, not the token label.
do
    local profile = make_regset( 100 )
    captured_actor = nil
    local out = p._http_handler_set_nick( req( 100, "op100" ) )
    ok( "nickchange: op (100) at the target level clears the guard (200)", out and out.status == 200 )
    ok( "nickchange: allow renamed the profile", profile.nick == NEW_NICK )
    ok( "nickchange: audit actor is the X-Actor operator, not the token label", captured_actor == "op100" )
end

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
