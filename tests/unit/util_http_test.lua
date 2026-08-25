--[[

    tests/unit/util_http_test.lua

    Unit tests for core/util_http.lua's
    `http_register_user_action` helper (#82 Phase 2 PR-B).
    Focus: the preflight (sid + online + non-bot) + response
    envelope construction, including the spoof-guard that drops
    handler-supplied values at the convention keys
    (`action` / `sid` / `nick`).

    Stubs `use "hub"` to return a fake hub module table with a
    capturable `http_register` and a controllable
    `issidonline`. The test invokes the captured route handler
    directly with synthetic `req` tables to exercise each branch.

    Run: lua5.4 tests/unit/util_http_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- shim layer (matches the http_router_test pattern)
----------------------------------------------------------------------

local _captured_route = nil    -- last (method, path, scope, handler, meta) registered

local _stub_users = { }    -- sid -> mock user object | "_bot_sid_marker"

local _mock_hub_obj = {
    http_register = function( method, path, scope, handler, meta )
        _captured_route = { method = method, path = path, scope = scope,
                            handler = handler, meta = meta }
        return true
    end,
    issidonline = function( sid )
        return _stub_users[ sid ]
    end,
}

local _mock_hub_module = { object = function( ) return _mock_hub_obj end }

local _real = {
    pairs = pairs, type = type,
    hub   = _mock_hub_module,
    -- operator_label resolves `use "util"` lazily for strip_control_bytes;
    -- mirror production semantics (control chars -> '?', non-string -> "").
    util  = { strip_control_bytes = function( s ) return ( type( s ) == "string" ) and ( s:gsub( "%c", "?" ) ) or "" end },
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "util_http_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local util_http = assert( loadfile( "core/util_http.lua" ) )( )

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- mock user-object factory
----------------------------------------------------------------------

local function make_user( nick, isbot )
    return {
        nick = function( _ ) return nick end,
        isbot = function( _ ) return isbot or false end,
    }
end

----------------------------------------------------------------------
-- 1. Registration: helper proxies through to hub.http_register
----------------------------------------------------------------------

do
    _captured_route = nil
    local handler_calls = 0
    local rv = util_http.http_register_user_action(
        "test_plugin", "DELETE", "/v1/users/{sid}", "disconnect",
        function( req, target ) handler_calls = handler_calls + 1; return { } end,
        { description = "test" }
    )
    eq( "register: returns true (hub_obj.http_register stub returned true)", rv, true )
    eq( "register: captured method", _captured_route.method, "DELETE" )
    eq( "register: captured path", _captured_route.path, "/v1/users/{sid}" )
    eq( "register: hard-coded scope == admin", _captured_route.scope, "admin" )
    eq( "register: meta.plugin filled with scriptname",
        _captured_route.meta.plugin, "test_plugin" )
    eq( "register: meta.description preserved",
        _captured_route.meta.description, "test" )
    eq( "register: handler was NOT called at registration time", handler_calls, 0 )
end

----------------------------------------------------------------------
-- 2. Preflight: missing sid -> 400 E_BAD_INPUT
----------------------------------------------------------------------

do
    local handler_calls = 0
    local route_handler = _captured_route.handler
    local resp = route_handler( { path_vars = { } } )
    eq( "preflight: missing sid -> 400", resp.status, 400 )
    eq( "preflight: missing sid -> E_BAD_INPUT", resp.error.code, "E_BAD_INPUT" )

    local resp2 = route_handler( { path_vars = { sid = "" } } )
    eq( "preflight: empty sid -> 400", resp2.status, 400 )
end

----------------------------------------------------------------------
-- 3. Preflight: SID not online -> 404 E_NOT_FOUND
----------------------------------------------------------------------

do
    _stub_users = { }
    local route_handler = _captured_route.handler
    local resp = route_handler( { path_vars = { sid = "ZZZZ" } } )
    eq( "preflight: offline sid -> 404", resp.status, 404 )
    eq( "preflight: offline sid -> E_NOT_FOUND", resp.error.code, "E_NOT_FOUND" )
end

----------------------------------------------------------------------
-- 4. Preflight: target is a bot -> 409 E_CONFLICT with verb in msg
----------------------------------------------------------------------

do
    _stub_users = { BOT1 = make_user( "hubbot", true ) }
    local route_handler = _captured_route.handler
    local resp = route_handler( { path_vars = { sid = "BOT1" } } )
    eq( "preflight: bot sid -> 409", resp.status, 409 )
    eq( "preflight: bot sid -> E_CONFLICT", resp.error.code, "E_CONFLICT" )
    eq( "preflight: bot error mentions action_verb",
        resp.error.message:find( "disconnect", 1, true ) ~= nil, true )
end

----------------------------------------------------------------------
-- 5. Success: helper builds the §7.1.1 envelope; handler data merged
----------------------------------------------------------------------

do
    _stub_users = { ABCD = make_user( "alice" ) }
    -- re-register with a handler that returns {reason="flood"}
    _captured_route = nil
    util_http.http_register_user_action(
        "p", "DELETE", "/v1/users/{sid}", "disconnect",
        function( req, target ) return { reason = "flood" } end,
        nil
    )
    local route_handler = _captured_route.handler
    local resp = route_handler( { path_vars = { sid = "ABCD" } } )
    eq( "envelope: status 200", resp.status, 200 )
    eq( "envelope: data.action == disconnect", resp.data.action, "disconnect" )
    eq( "envelope: data.sid", resp.data.sid, "ABCD" )
    eq( "envelope: data.nick", resp.data.nick, "alice" )
    eq( "envelope: data.reason (handler-supplied)", resp.data.reason, "flood" )
end

----------------------------------------------------------------------
-- 6. SECURITY: handler MUST NOT be able to spoof convention fields
----------------------------------------------------------------------

do
    _stub_users = { ABCD = make_user( "alice" ) }
    _captured_route = nil
    util_http.http_register_user_action(
        "p", "DELETE", "/v1/users/{sid}", "disconnect",
        function( req, target )
            -- A buggy or malicious plugin tries to lie about who
            -- got disconnected. The helper MUST silently drop the
            -- spoof attempt and keep the canonical values.
            return {
                action = "EVIL_ACTION",
                sid    = "EVIL_SID",
                nick   = "EVIL_NICK",
                reason = "innocent-looking",
            }
        end,
        nil
    )
    local route_handler = _captured_route.handler
    local resp = route_handler( { path_vars = { sid = "ABCD" } } )
    eq( "spoof-guard: action stays canonical", resp.data.action, "disconnect" )
    eq( "spoof-guard: sid stays canonical", resp.data.sid, "ABCD" )
    eq( "spoof-guard: nick stays canonical", resp.data.nick, "alice" )
    eq( "spoof-guard: handler's non-convention field IS merged",
        resp.data.reason, "innocent-looking" )
end

----------------------------------------------------------------------
-- 7. Handler error path: (nil, err) returned -> err passed through verbatim
----------------------------------------------------------------------

do
    _stub_users = { ABCD = make_user( "alice" ) }
    _captured_route = nil
    util_http.http_register_user_action(
        "p", "POST", "/v1/users/{sid}/x", "x",
        function( req, target )
            return nil, { status = 409, error = { code = "E_CONFLICT",
                message = "already in that state" } }
        end,
        nil
    )
    local resp = _captured_route.handler( { path_vars = { sid = "ABCD" } } )
    eq( "handler-error: status passes through", resp.status, 409 )
    eq( "handler-error: error code passes through", resp.error.code, "E_CONFLICT" )
    eq( "handler-error: no envelope wrapping", resp.data, nil )
end

----------------------------------------------------------------------
-- 8. Fail-soft: missing hub.http_register -> returns false, no crash
----------------------------------------------------------------------

do
    local saved = _mock_hub_obj.http_register
    _mock_hub_obj.http_register = nil
    local rv = util_http.http_register_user_action(
        "p", "GET", "/v1/foo", "foo",
        function( ) return { } end, nil
    )
    eq( "fail-soft: returns false when http_register absent", rv, false )
    _mock_hub_obj.http_register = saved
end

----------------------------------------------------------------------
-- 9. operator_label: the accountability actor for a WebUI-driven action
--    (audit / stored records / opchat report) - webui#177 C. Resolves the
--    real operator asserted in X-Actor (req.actor), falling back to the
--    token's non-secret label, then "http-api". This is NEVER the
--    end-user-visible attribution (that is the hubbot).
----------------------------------------------------------------------

do
    eq( "operator: req.actor (X-Actor) wins",
        util_http.operator_label( { actor = "opNick", token_label = "tok (aB..Yz)" } ), "opNick" )
    eq( "operator: falls back to token_label when actor absent",
        util_http.operator_label( { token_label = "tok (aB..Yz)" } ), "tok (aB..Yz)" )
    eq( "operator: falls back to token_label when actor is empty",
        util_http.operator_label( { actor = "", token_label = "tok" } ), "tok" )
    eq( "operator: falls back to http-api when neither present",
        util_http.operator_label( { } ), "http-api" )
    eq( "operator: nil req -> http-api (no crash)",
        util_http.operator_label( nil ), "http-api" )
    eq( "operator: control bytes stripped from actor",
        util_http.operator_label( { actor = "op\1Nick" } ), "op?Nick" )
end

----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
