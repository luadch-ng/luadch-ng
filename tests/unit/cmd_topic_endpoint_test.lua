--[[

    tests/unit/cmd_topic_endpoint_test.lua

    Regression test for scripts/cmd_topic.lua GET /v1/topic (v0.06).

    Proves the read-only topic endpoint added in v0.06:
      - GET /v1/topic is REGISTERED in onStart. Provably fails pre-fix
        (per CLAUDE.md 1a.7): on v0.05 the handler map has no
        "GET /v1/topic", so the registration assertion goes RED; it
        passes on v0.06.
      - default hub (no custom topic stored) -> { topic = hub_description,
        is_default = true, default = hub_description }.
      - a stored custom topic -> { topic = <custom>, is_default = false }.
      - GET reflects live state: after the existing POST sets a topic, GET
        returns it; after POST resets (empty body), GET returns the default
        again. This ties the new reader to the existing writer over the
        shared module store.

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/cmd_topic_endpoint_test.lua

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
local HUB_DESC = "Default Hub Topic"

local _loaded          -- what util.loadtable returns for the topic store
local _saved           -- last util.savetable payload
local _listeners       -- event -> fn
local _http            -- "METHOD path" -> handler, captured from hub.http_register

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table
_G.PROCESSED = "PROCESSED"
_G.utf = { match = function( ) end, format = function( ) return "" end }

_G.cfg = {
    get = function( k )
        if k == "language" then return "en" end
        if k == "cmd_topic_minlevel" then return 80 end
        if k == "hub_description" then return HUB_DESC end
        if k == "cmd_topic_llevel" then return 0 end
        -- report activate / hubbot / opchat left nil (falsy): report.send is
        -- a no-op stub, so the POST path runs but announces nothing.
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    loadtable           = function( ) return _loaded end,
    savetable           = function( t ) _saved = t end,
    strip_control_bytes = function( s ) return s end,
}

-- POST path fires an audit event; stub it so the roundtrip case can run.
_G.audit = { fire = function( ) end, build = function( ) return { } end }

_G.hub = {
    getbot      = function( ) return { } end,
    broadcast   = function( ) end,
    escapeto    = function( s ) return s end,
    sendtoall   = function( ) end,
    debug       = function( ) end,
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    http_register = function( method, path, _scope, handler ) _http[ method .. " " .. path ] = handler end,
    import      = function( name )
        if name == "etc_report" then return { send = function( ) end } end
        if name == "etc_hubcommands" then return { add = function( ) return true end } end
        if name == "cmd_help" then return { reg = function( ) end } end
        if name == "etc_usercommands" then return { add = function( ) end } end
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
    assert( loadfile( "scripts/cmd_topic.lua" ) )( )
end

-- fire onStart (registers the HTTP handlers), then return GET + POST handlers.
local function handlers( )
    assert( _listeners[ "onStart" ], "onStart not registered" )
    _listeners[ "onStart" ]( )
    return _http[ "GET /v1/topic" ], _http[ "POST /v1/topic" ]
end

----------------------------------------------------------------------
-- Case 1: default hub (empty store, no custom topic). GET must register
-- AND report the cfg.hub_description as the live topic, flagged default.
-- RED pre-fix: GET is nil (never registered on v0.05).
----------------------------------------------------------------------
_loaded = { }
load_plugin( )
local GET, POST = handlers( )
ok( "GET /v1/topic registered in onStart (v0.06)", GET ~= nil )
if GET then
    local r = GET( { } ).data
    ok( "default hub: topic == hub_description", r.topic == HUB_DESC, r.topic )
    ok( "default hub: is_default is true",       r.is_default == true, tostring( r.is_default ) )
    ok( "default hub: default == hub_description", r.default == HUB_DESC, r.default )
end

----------------------------------------------------------------------
-- Case 2: a custom topic is already stored (topic_tbl.new). GET returns
-- it verbatim, is_default false. default still reports hub_description.
----------------------------------------------------------------------
_loaded = { new = "Welcome to the hub!", old = "an older topic" }
load_plugin( )
GET = handlers( )
if GET then
    local r = GET( { } ).data
    ok( "custom topic: topic == stored new",         r.topic == "Welcome to the hub!", r.topic )
    ok( "custom topic: is_default is false",          r.is_default == false, tostring( r.is_default ) )
    ok( "custom topic: default still hub_description", r.default == HUB_DESC, r.default )
end

----------------------------------------------------------------------
-- Case 3: GET reflects live mutations by the existing POST writer. Set a
-- topic via POST, GET returns it; reset via POST (empty body), GET returns
-- the default again. Proves the reader reads the same live module store the
-- writer mutates (do_set_topic / do_reset_topic).
----------------------------------------------------------------------
_loaded = { }
load_plugin( )
GET, POST = handlers( )
ok( "POST /v1/topic still registered", POST ~= nil )
if GET and POST then
    POST( { body = { topic = "Maintenance tonight 22:00" }, token_label = "test-token" } )
    local r = GET( { } ).data
    ok( "after POST-set: GET returns the new topic", r.topic == "Maintenance tonight 22:00", r.topic )
    ok( "after POST-set: is_default is false",       r.is_default == false, tostring( r.is_default ) )

    POST( { body = { }, token_label = "test-token" } )   -- empty body -> reset
    r = GET( { } ).data
    ok( "after POST-reset: GET returns the default",  r.topic == HUB_DESC, r.topic )
    ok( "after POST-reset: is_default is true",        r.is_default == true, tostring( r.is_default ) )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL cmd_topic_endpoint_test\n" ); os.exit( 1 ) end
io.write( "OK cmd_topic_endpoint_test\n" )
