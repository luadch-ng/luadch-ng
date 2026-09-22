--[[

    tests/unit/cmd_rules_endpoint_test.lua

    Regression test for scripts/cmd_rules.lua content endpoints (v0.07).

    Mirror of etc_motd_endpoint_test: the same operator-owned store + GET/PUT/
    DELETE /v1/rules + seed-freeze guarantee, minus the {nick} substitution
    (rules are sent verbatim). Kept structurally identical on purpose so the two
    plugins cannot drift (CLAUDE.md 1a.1).

      - Endpoints REGISTER in onStart. RED pre-fix (v0.06 has no "GET /v1/rules").
      - Fresh hub: onStart seeds from lang.msg_rules, origin="seed".
      - PUT sets operator text, origin="operator", is_default=false.
      - FREEZE: reload with a persisted store (operator OR seed) does NOT
        re-seed / refresh, even when the lang default changed. Anti-clobber
        guarantee; RED on an unconditional / auto-refreshing seed.
      - DELETE resets to the current lang default, origin="seed".
      - PUT validation: non-string / over-cap / missing -> 400 E_BAD_INPUT.
      - sanitise: CRLF->LF, control bytes -> '?', tab/newline survive.
      - delivery: `+rules` (onbmsg) sends the live text to a user >= minlevel.

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/cmd_rules_endpoint_test.lua

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
local DEFAULT_RULES = "=== RULES ===\nBe excellent to each other.\n=== RULES ==="

local _store_exists
local _loaded
local _saved
local _listeners
local _http
local _onbmsg          -- the +rules handler, captured from etc_hubcommands.add
local _lang_rules = DEFAULT_RULES   -- what cfg.loadlanguage yields for msg_rules

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table
_G.PROCESSED = "PROCESSED"

local real_open = io.open
io.open = function( path, mode )
    if path == "scripts/data/cmd_rules.tbl" then
        if _store_exists then return { close = function( ) end } end
        return nil
    end
    return real_open( path, mode )
end

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        if k == "cmd_rules_minlevel" then return 10 end
        if k == "cmd_rules_destination_main" then return true end
        if k == "cmd_rules_destination_pm" then return false end
        return nil
    end,
    loadlanguage = function( ) return { msg_rules = _lang_rules }, nil end,
}

_G.util = {
    loadtable = function( ) return _loaded end,
    savetable = function( t ) _saved = t end,
}

_G.util_http = { operator_label = function( req ) return ( req and req.token_label ) or "http-api" end }
_G.audit = { fire = function( ) end, build = function( ) return { } end }

_G.hub = {
    getbot        = function( ) return { } end,
    debug         = function( ) end,
    setlistener   = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    http_register = function( method, path, _scope, handler ) _http[ method .. " " .. path ] = handler end,
    import        = function( name )
        if name == "cmd_help" then return { reg = function( ) end } end
        if name == "etc_usercommands" then return { add = function( ) end } end
        if name == "etc_hubcommands" then return { add = function( _c, fn ) _onbmsg = fn; return true end } end
        return nil
    end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( )
    _listeners = { }
    _saved = nil
    _http = { }
    _onbmsg = nil
    assert( loadfile( "scripts/cmd_rules.lua" ) )( )
end

local function start( )
    assert( _listeners[ "onStart" ], "onStart not registered" )
    _listeners[ "onStart" ]( )
end

----------------------------------------------------------------------
-- Case 1: fresh hub. onStart seeds + registers. RED pre-fix (v0.06).
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
local GET = _http[ "GET /v1/rules" ]
local PUT = _http[ "PUT /v1/rules" ]
local DEL = _http[ "DELETE /v1/rules" ]
ok( "GET /v1/rules registered in onStart (v0.07)",    GET ~= nil )
ok( "PUT /v1/rules registered in onStart (v0.07)",    PUT ~= nil )
ok( "DELETE /v1/rules registered in onStart (v0.07)", DEL ~= nil )
ok( "fresh hub: seed persisted with origin=seed",
    type( _saved ) == "table" and _saved.origin == "seed" and _saved.text == DEFAULT_RULES,
    _saved and _saved.origin )
if GET then
    local r = GET( { } ).data
    ok( "fresh hub: GET text == lang default", r.text == DEFAULT_RULES, r.text )
    ok( "fresh hub: is_default is true",       r.is_default == true, tostring( r.is_default ) )
    ok( "fresh hub: default == lang default",  r.default == DEFAULT_RULES, r.default )
end

----------------------------------------------------------------------
-- Case 2: PUT sets operator text.
----------------------------------------------------------------------
if PUT and GET then
    local resp = PUT( { body = { text = "Rule 1\nRule 2" }, token_label = "tok" } )
    ok( "PUT: status 200",                resp.status == 200, resp.status )
    ok( "PUT: response is_default false",  resp.data and resp.data.is_default == false )
    ok( "PUT: persisted origin=operator",  _saved.origin == "operator" and _saved.text == "Rule 1\nRule 2", _saved.origin )
    local r = GET( { } ).data
    ok( "PUT: GET returns the new text live", r.text == "Rule 1\nRule 2", r.text )
    ok( "PUT: GET is_default false",          r.is_default == false, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 3 (FREEZE, operator): reload with a persisted operator store -> no re-seed.
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "Operator owned rules", origin = "operator" }
load_plugin( )
start( )
ok( "freeze(operator): no re-seed write on reload", _saved == nil, _saved and _saved.origin )
do
    local r = _http[ "GET /v1/rules" ]( { } ).data
    ok( "freeze(operator): text preserved",   r.text == "Operator owned rules", r.text )
    ok( "freeze(operator): is_default false", r.is_default == false, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 4 (FREEZE, seed, no auto-refresh): stale seed text is not refreshed.
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "OLD SEEDED RULES", origin = "seed" }
load_plugin( )
start( )
ok( "freeze(seed): no refresh write on reload", _saved == nil, _saved and _saved.text )
do
    local r = _http[ "GET /v1/rules" ]( { } ).data
    ok( "freeze(seed): stale seed NOT refreshed to new lang default", r.text == "OLD SEEDED RULES", r.text )
    ok( "freeze(seed): is_default true", r.is_default == true, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 5: DELETE resets to the current lang default.
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "Operator owned rules", origin = "operator" }
load_plugin( )
start( )
do
    local resp = _http[ "DELETE /v1/rules" ]( { token_label = "tok" } )
    ok( "DELETE: status 200",            resp.status == 200, resp.status )
    ok( "DELETE: text == lang default",  resp.data.text == DEFAULT_RULES, resp.data.text )
    ok( "DELETE: is_default true",       resp.data.is_default == true, tostring( resp.data.is_default ) )
    ok( "DELETE: persisted origin=seed", _saved.origin == "seed" and _saved.text == DEFAULT_RULES, _saved.origin )
end

----------------------------------------------------------------------
-- Case 6: PUT validation.
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
do
    local PUT6 = _http[ "PUT /v1/rules" ]
    local r1 = PUT6( { body = { text = true }, token_label = "tok" } )
    ok( "validation: non-string text -> 400", r1.status == 400 and r1.error and r1.error.code == "E_BAD_INPUT", r1.status )
    local r2 = PUT6( { body = { text = string.rep( "x", 16385 ) }, token_label = "tok" } )
    ok( "validation: over-cap text -> 400",   r2.status == 400 and r2.error and r2.error.code == "E_BAD_INPUT", r2.status )
    local r3 = PUT6( { body = { }, token_label = "tok" } )
    ok( "validation: missing text -> 400",    r3.status == 400 and r3.error and r3.error.code == "E_BAD_INPUT", r3.status )
end

----------------------------------------------------------------------
-- Case 7: sanitise.
----------------------------------------------------------------------
do
    local PUT7 = _http[ "PUT /v1/rules" ]
    PUT7( { body = { text = "a\r\nb\0c\td\r e" }, token_label = "tok" } )
    ok( "sanitise: CRLF->LF, NUL->?, tab kept",
        _saved.text == "a\nb?c\td\n e", ( _saved.text:gsub( "\n", "\\n" ):gsub( "\t", "\\t" ) ) )
end

----------------------------------------------------------------------
-- Case 8: delivery. `+rules` (onbmsg) sends the live text to a user >= minlevel.
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
do
    _http[ "PUT /v1/rules" ]( { body = { text = "Live rules text" }, token_label = "tok" } )
    assert( _onbmsg, "onbmsg (+rules handler) not registered" )
    local sent = { }
    local user = {
        level = function( ) return 10 end,
        reply = function( _self, msg ) sent[ #sent + 1 ] = msg end,
    }
    _onbmsg( user )
    ok( "delivery: +rules sends the live text", sent[ 1 ] == "Live rules text", sent[ 1 ] )

    local below = { level = function( ) return 5 end, reply = function( _self, m ) sent[ #sent + 1 ] = m end }
    local before = #sent
    _onbmsg( below )
    ok( "delivery: below minlevel gets nothing", #sent == before, #sent )
end

----------------------------------------------------------------------
-- Case 9: empty lang default - the REAL sv case (scripts/lang/sv/cmd_rules.json
-- ships msg_rules=""). onStart must NOT persist an empty seed override; GET
-- falls back to the empty default, flagged is_default; +rules sends nothing.
----------------------------------------------------------------------
_lang_rules = ""; _store_exists = false; _loaded = nil
load_plugin( )
start( )
ok( "empty default (sv): seed skipped ( no write )", _saved == nil, _saved and _saved.origin )
do
    local r = _http[ "GET /v1/rules" ]( { } ).data
    ok( "empty default (sv): text is empty",   r.text == "", "[" .. tostring( r.text ) .. "]" )
    ok( "empty default (sv): is_default true", r.is_default == true, tostring( r.is_default ) )
    -- +rules on an empty ruleset sends nothing ( the msg ~= "" delivery guard )
    local sent = { }
    local user = { level = function( ) return 10 end, reply = function( _s, m ) sent[ #sent + 1 ] = m end }
    _onbmsg( user )
    ok( "empty default (sv): +rules sends nothing", #sent == 0, #sent )
end
_lang_rules = DEFAULT_RULES

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL cmd_rules_endpoint_test\n" ); os.exit( 1 ) end
io.write( "OK cmd_rules_endpoint_test\n" )
