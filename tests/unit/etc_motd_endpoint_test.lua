--[[

    tests/unit/etc_motd_endpoint_test.lua

    Regression test for scripts/etc_motd.lua content endpoints (v0.10).

    Proves the operator-owned MOTD store + GET/PUT/DELETE /v1/motd added in
    v0.10, and - the load-bearing anti-clobber guarantee - that a seeded
    text is FROZEN: a later boot / lang update never overwrites it.

      - Endpoints REGISTER in onStart. Provably fails pre-fix (per CLAUDE.md
        1a.7): on v0.09 the handler map has no "GET /v1/motd" etc., so the
        registration assertions go RED; they pass on v0.10.
      - Fresh hub (no store): onStart seeds the store from lang.msg_motd,
        origin="seed", GET reports it with is_default=true.
      - PUT sets the operator text, is_default=false, persisted origin="operator".
      - FREEZE: reloading with a persisted store (operator OR seed origin) does
        NOT re-seed / refresh - even when the lang default has since changed.
        This is the guarantee that a lang update cannot clobber edited text; it
        would go RED on an unconditional / auto-refreshing seed.
      - DELETE resets to the current lang default, origin="seed".
      - PUT validation: non-string / over-cap -> 400 E_BAD_INPUT.
      - sanitise: CRLF normalises to LF, other control bytes -> '?', tab/newline
        survive.
      - delivery: onLogin substitutes {nick} and %s and reads the text live.

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/etc_motd_endpoint_test.lua

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
-- A multi-line banner default with both placeholder forms, so we exercise
-- newline preservation and {nick}/%s substitution.
local DEFAULT_MOTD = "=== MOTD ===\nWelcome, {nick} and %s\n=== MOTD ==="

local _store_exists    -- does io.open( motd_file ) find a file? ( fresh vs reload )
local _loaded          -- what util.loadtable returns for the store
local _saved           -- last util.savetable payload ( nil until a write )
local _listeners       -- event -> fn
local _http            -- "METHOD path" -> handler, captured from hub.http_register
local _lang_motd = DEFAULT_MOTD   -- what cfg.loadlanguage yields for msg_motd

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table
_G.PROCESSED = "PROCESSED"

-- Control io.open ONLY for the store peek; keep the real io for io.write output.
local real_open = io.open
io.open = function( path, mode )
    if path == "scripts/data/etc_motd.tbl" then
        if _store_exists then return { close = function( ) end } end
        return nil
    end
    return real_open( path, mode )
end

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        if k == "etc_motd_activate" then return true end
        if k == "etc_motd_permission" then return { [ 10 ] = true } end
        if k == "etc_motd_destination_main" then return true end
        if k == "etc_motd_destination_pm" then return false end
        return nil
    end,
    loadlanguage = function( ) return { msg_motd = _lang_motd }, nil end,
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
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( )
    _listeners = { }
    _saved = nil
    _http = { }
    assert( loadfile( "scripts/etc_motd.lua" ) )( )
end

-- fire onStart (seeds + registers the HTTP handlers)
local function start( )
    assert( _listeners[ "onStart" ], "onStart not registered" )
    _listeners[ "onStart" ]( )
end

----------------------------------------------------------------------
-- Case 1: fresh hub. onStart seeds the store from lang, GET registers and
-- reports the default flagged is_default. RED pre-fix: GET is nil (v0.09).
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
local GET  = _http[ "GET /v1/motd" ]
local PUT  = _http[ "PUT /v1/motd" ]
local DEL  = _http[ "DELETE /v1/motd" ]
ok( "GET /v1/motd registered in onStart (v0.10)",    GET ~= nil )
ok( "PUT /v1/motd registered in onStart (v0.10)",    PUT ~= nil )
ok( "DELETE /v1/motd registered in onStart (v0.10)", DEL ~= nil )
ok( "fresh hub: seed persisted with origin=seed",
    type( _saved ) == "table" and _saved.origin == "seed" and _saved.text == DEFAULT_MOTD,
    _saved and _saved.origin )
if GET then
    local r = GET( { } ).data
    ok( "fresh hub: GET text == lang default", r.text == DEFAULT_MOTD, r.text )
    ok( "fresh hub: is_default is true",       r.is_default == true, tostring( r.is_default ) )
    ok( "fresh hub: default == lang default",  r.default == DEFAULT_MOTD, r.default )
end

----------------------------------------------------------------------
-- Case 2: PUT sets operator text; GET reflects it live; persisted origin
-- flips to "operator"; is_default is false.
----------------------------------------------------------------------
if PUT and GET then
    local resp = PUT( { body = { text = "Custom line 1\nCustom line 2" }, token_label = "tok" } )
    ok( "PUT: status 200",              resp.status == 200, resp.status )
    ok( "PUT: response text echoes",    resp.data and resp.data.text == "Custom line 1\nCustom line 2", resp.data and resp.data.text )
    ok( "PUT: response is_default false", resp.data and resp.data.is_default == false, resp.data and tostring( resp.data.is_default ) )
    ok( "PUT: persisted origin=operator", _saved.origin == "operator" and _saved.text == "Custom line 1\nCustom line 2", _saved.origin )
    local r = GET( { } ).data
    ok( "PUT: GET returns the new text live", r.text == "Custom line 1\nCustom line 2", r.text )
    ok( "PUT: GET is_default false",          r.is_default == false, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 3 (FREEZE, operator): reload with a persisted operator store. onStart
-- must NOT re-seed - the text stays the operator's, no save happens.
-- RED on an unconditional seed (would overwrite with the default).
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "Operator owned MOTD", origin = "operator" }
load_plugin( )
start( )
ok( "freeze(operator): no re-seed write on reload", _saved == nil, _saved and _saved.origin )
do
    local r = _http[ "GET /v1/motd" ]( { } ).data
    ok( "freeze(operator): text preserved", r.text == "Operator owned MOTD", r.text )
    ok( "freeze(operator): is_default false", r.is_default == false, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 4 (FREEZE, seed, no auto-refresh): reload with a persisted SEED store
-- whose text differs from the CURRENT lang default (simulating a lang update
-- landing after the seed). onStart must NOT refresh it. This is the exact
-- anti-clobber guarantee; RED on an auto-refreshing seed.
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "OLD SEEDED DEFAULT", origin = "seed" }
load_plugin( )
start( )
ok( "freeze(seed): no refresh write on reload", _saved == nil, _saved and _saved.text )
do
    local r = _http[ "GET /v1/motd" ]( { } ).data
    ok( "freeze(seed): stale seed text NOT refreshed to new lang default",
        r.text == "OLD SEEDED DEFAULT", r.text )
    ok( "freeze(seed): is_default true", r.is_default == true, tostring( r.is_default ) )
end

----------------------------------------------------------------------
-- Case 5: DELETE resets to the current lang default, origin=seed.
----------------------------------------------------------------------
_store_exists = true; _loaded = { text = "Operator owned MOTD", origin = "operator" }
load_plugin( )
start( )
do
    local resp = _http[ "DELETE /v1/motd" ]( { token_label = "tok" } )
    ok( "DELETE: status 200",             resp.status == 200, resp.status )
    ok( "DELETE: text == lang default",   resp.data.text == DEFAULT_MOTD, resp.data.text )
    ok( "DELETE: is_default true",        resp.data.is_default == true, tostring( resp.data.is_default ) )
    ok( "DELETE: persisted origin=seed",  _saved.origin == "seed" and _saved.text == DEFAULT_MOTD, _saved.origin )
    local r = _http[ "GET /v1/motd" ]( { } ).data
    ok( "DELETE: GET reflects default",   r.text == DEFAULT_MOTD and r.is_default == true, r.text )
end

----------------------------------------------------------------------
-- Case 6: PUT validation.
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
do
    local PUT6 = _http[ "PUT /v1/motd" ]
    local r1 = PUT6( { body = { text = 123 }, token_label = "tok" } )
    ok( "validation: non-string text -> 400", r1.status == 400 and r1.error and r1.error.code == "E_BAD_INPUT", r1.status )
    local r2 = PUT6( { body = { text = string.rep( "x", 16385 ) }, token_label = "tok" } )
    ok( "validation: over-cap text -> 400",   r2.status == 400 and r2.error and r2.error.code == "E_BAD_INPUT", r2.status )
    local r3 = PUT6( { body = { }, token_label = "tok" } )   -- missing text
    ok( "validation: missing text -> 400",    r3.status == 400 and r3.error and r3.error.code == "E_BAD_INPUT", r3.status )
end

----------------------------------------------------------------------
-- Case 7: sanitise. CRLF -> LF, other control bytes -> '?', tab + newline kept.
----------------------------------------------------------------------
do
    local PUT7 = _http[ "PUT /v1/motd" ]
    PUT7( { body = { text = "a\r\nb\0c\td\r e" }, token_label = "tok" } )
    -- \r\n -> \n ; \0 -> ? ; \t kept ; lone \r ( before space ) -> \n
    ok( "sanitise: CRLF->LF, NUL->?, tab kept",
        _saved.text == "a\nb?c\td\n e", ( _saved.text:gsub( "\n", "\\n" ):gsub( "\t", "\\t" ) ) )
end

----------------------------------------------------------------------
-- Case 8: delivery. onLogin substitutes {nick} + %s and reads the text live
-- (after a PUT, without a reload).
----------------------------------------------------------------------
_store_exists = false; _loaded = nil
load_plugin( )
start( )
do
    _http[ "PUT /v1/motd" ]( { body = { text = "Hi {nick} and %s" }, token_label = "tok" } )
    local sent = { }
    local user = {
        level     = function( ) return 10 end,
        firstnick = function( ) return "Alice" end,
        reply     = function( _self, msg ) sent[ #sent + 1 ] = msg end,
    }
    assert( _listeners[ "onLogin" ], "onLogin not registered" )
    _listeners[ "onLogin" ]( user )
    ok( "delivery: {nick} and %s both -> firstnick, live text",
        sent[ 1 ] == "Hi Alice and Alice", sent[ 1 ] )

    -- A firstnick containing '%' must NOT crash the handler: with the nick as a
    -- gsub *replacement string*, "%b" ( % + non-digit ) raises "invalid use of
    -- '%' in replacement string". The function-replacement form inserts it
    -- verbatim. This case aborts the whole test ( uncaught error ) on the old
    -- string-replacement code, so it is a real regression guard.
    local sent2 = { }
    local pctuser = {
        level     = function( ) return 10 end,
        firstnick = function( ) return "a%b" end,
        reply     = function( _self, msg ) sent2[ #sent2 + 1 ] = msg end,
    }
    _listeners[ "onLogin" ]( pctuser )
    ok( "delivery: '%' in firstnick is inserted verbatim, no crash",
        sent2[ 1 ] == "Hi a%b and a%b", sent2[ 1 ] )
end

----------------------------------------------------------------------
-- Case 9: empty lang default ( e.g. an untranslated lang file ). onStart must
-- NOT persist an empty seed override; GET falls back to the empty default,
-- flagged is_default. Guards the seed-skip branch that keeps an empty override
-- from masking a later non-empty default.
----------------------------------------------------------------------
_lang_motd = ""; _store_exists = false; _loaded = nil
load_plugin( )
start( )
ok( "empty default: seed skipped ( no write )", _saved == nil, _saved and _saved.origin )
do
    local r = _http[ "GET /v1/motd" ]( { } ).data
    ok( "empty default: text is empty",  r.text == "", "[" .. tostring( r.text ) .. "]" )
    ok( "empty default: is_default true", r.is_default == true, tostring( r.is_default ) )
    ok( "empty default: default is empty", r.default == "", "[" .. tostring( r.default ) .. "]" )
end
_lang_motd = DEFAULT_MOTD

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL etc_motd_endpoint_test\n" ); os.exit( 1 ) end
io.write( "OK etc_motd_endpoint_test\n" )
