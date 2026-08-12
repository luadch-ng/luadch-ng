--[[

    tests/unit/http_router_test.lua

    Unit tests for the pure-Lua-bit functions of core/http_router.lua
    (constant_time_eq, validate_schema, envelope helpers, token
    resolution, schema validator, request-id shape) plus targeted
    dispatch() coverage (OPTIONS introspection, the top-level body-shape
    guard, handler-crash traceback logging). Full end-to-end request
    paths are smoke-tested against a real hub.

    The router uses `use "cfg"` and `use "out"` and `use "dkjson"`
    at file scope; we stub them here so the module can load in a
    standalone interpreter.

    Run: lua5.4 tests/unit/http_router_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

-- minimal `use` shim, lockstep with http_router.lua's imports.
-- http_router.lua snapshots `cfg.get` to a local at module-load
-- time (`local cfg_get = cfg.get`), so we MUST NOT swap the
-- _mock_cfg.get field after the module loads - the local won't
-- track the swap. Instead, the original closure reads tunable
-- module-locals so per-test config (e.g. shrunk idempotency cap)
-- can be applied without reassigning the function.
local _stub_cfg_tokens = { }
local _stub_cfg_idem_cap = nil    -- nil = use default; integer overrides
local _last_audit_args = nil
local _last_error_args = nil
-- auth-verify (POST /v1/auth/verify) test state.
local _authverify_allow = true             -- toggled by the rate-limit test
local _hashpas_calls = { }                 -- records adclib.hashpas calls (timing-equalization test)
local _mock_regusers_by_nick = { }         -- populated per auth-verify test
local function _stub_hashpas( pw, salt )   -- deterministic stand-in for adclib.hashpas (real crypto: adclib_hashpas_test + smoke)
    _hashpas_calls[ #_hashpas_calls + 1 ] = { pw = pw, salt = salt }
    return "H:" .. tostring( pw ) .. ":" .. tostring( salt )
end
local _mock_hub = {
    getregusers = function( ) return { }, _mock_regusers_by_nick, { } end,
    escapeto    = function( s ) return s end,   -- identity: test nicks have no spaces
}
local _mock_cfg = {
    get = function( key )
        if key == "http_api_tokens" then return _stub_cfg_tokens end
        if key == "log_api_audit" then return true end
        if key == "http_api_log_reads" then return false end
        if key == "http_api_idempotency_max_entries" then return _stub_cfg_idem_cap end
        return nil
    end,
}
local _mock_out = {
    put       = function() end,
    -- capture so the Fix-B handler-crash test can assert the logged
    -- text carries a Lua traceback (xpcall + debug.traceback), not just
    -- the bare error message. out_error is snapshotted to a local at
    -- module load, so this capturing closure must exist BEFORE loadfile.
    error     = function( ... ) _last_error_args = { ... } end,
    api_audit = function( ... ) _last_audit_args = { ... } end,
}
local _mock_dkjson = {
    encode = function( v )
        -- minimal stub: just stringify with type discrimination.
        -- Real dkjson is bundled and gets exercised by smoke; here
        -- we only verify the router CALLS encode with the right
        -- shape. Returns the table as a sentinel.
        return { _encoded = v }
    end,
    decode = function( s )
        if type( s ) ~= "string" then return nil, nil, "not a string" end
        if s == "BAD" then return nil, nil, "stub: forced bad json" end
        -- the stub accepts the special prefix "OBJ:" + lua syntax
        if s:sub( 1, 4 ) == "OBJ:" then
            local fn, err = loadstring and loadstring( "return " .. s:sub( 5 ) )
                or load( "return " .. s:sub( 5 ) )
            if not fn then return nil, nil, err end
            local ok, t = pcall( fn )
            if not ok then return nil, nil, t end
            return t
        end
        -- "ARR:" mirrors real dkjson tagging a decoded JSON array with the
        -- metatable {__jsontype="array"} - the body-shape guard's signal.
        if s:sub( 1, 4 ) == "ARR:" then
            local fn = loadstring and loadstring( "return " .. s:sub( 5 ) )
                or load( "return " .. s:sub( 5 ) )
            if not fn then return nil, nil, "stub: bad ARR body" end
            local ok, t = pcall( fn )
            if not ok then return nil, nil, t end
            return setmetatable( t, { __jsontype = "array" } )
        end
        return nil, nil, "stub: only OBJ:{...} / ARR:{...} accepted"
    end,
}

-- Phase 1c: http_router now also calls `use "socket"` (idempotency
-- cache TTL) and `use "adclib"` (constant_time_eq C binding).
-- `socket.gettime` is the only field touched at module load; a
-- minimal stub backed by os.time() is enough for unit tests.
-- `adclib` here is a table with only `hashpas` (a deterministic stub)
-- and NO `constant_time_eq`, so http_router's `_adclib_cte` stays nil and
-- the pure-Lua constant_time_eq fallback is still exercised; the real C
-- bindings (hashpas + constant_time_eq) are covered by the adclib_*_test
-- suite + the smoke harness against a real build.
local _mock_socket = { gettime = function( ) return os.time( ) end }

-- dispatch() resolves `use "ratelimit"` at request time for any non-
-- X-Confirm route; a permissive stub lets the body-shape + handler-crash
-- dispatch tests run without a real token bucket. (Bucket behaviour is
-- covered by ratelimit_test.lua + smoke.)
local _mock_ratelimit = {
    http_token             = function( ) return true end,
    http_token_retry_after = function( ) return 60 end,
    http_authverify        = function( ) return _authverify_allow end,
}

local _real = {
    string = string, table = table, os = os, io = io, math = math,
    pairs = pairs, ipairs = ipairs, tostring = tostring, tonumber = tonumber,
    type = type, pcall = pcall, xpcall = xpcall, select = select, error = error,
    getmetatable = getmetatable, debug = debug,
    cfg = _mock_cfg, out = _mock_out, dkjson = _mock_dkjson,
    socket = _mock_socket, adclib = { hashpas = _stub_hashpas },
    ratelimit = _mock_ratelimit, hub = _mock_hub,
}
_G.use = function( name )
    local v = _real[ name ]
    assert( v ~= nil, "http_router_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local router = assert( loadfile( "core/http_router.lua" ) )( )

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-50s got=%q want=%q\n",
            label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- constant_time_eq
----------------------------------------------------------------------

eq( "cte: equal strings",          router._constant_time_eq( "abc", "abc" ), true )
eq( "cte: different strings",      router._constant_time_eq( "abc", "abd" ), false )
eq( "cte: different lengths",      router._constant_time_eq( "abc", "abcd" ), false )
eq( "cte: empty equal",            router._constant_time_eq( "", "" ), true )
eq( "cte: non-string a",           router._constant_time_eq( nil, "x" ), false )
eq( "cte: non-string b",           router._constant_time_eq( "x", 42 ), false )
eq( "cte: byte-precise difference at position 1",
    router._constant_time_eq( "abc", "abx" ), false )

----------------------------------------------------------------------
-- validate_schema
----------------------------------------------------------------------

do
    local schema = {
        target = { type = "string", required = true, max_length = 64 },
        duration_minutes = { type = "integer", min = 1, max = 525600 },
        scope = { type = "string", enum = { "all", "hub", "level" } },
    }
    local ok, err
    ok = router._validate_schema( schema, { target = "x", scope = "all" } )
    eq( "schema: minimum valid", ok, true )

    ok, err = router._validate_schema( schema, { } )
    eq( "schema: missing required", ok, false )

    ok, err = router._validate_schema( schema, { target = 42 } )
    eq( "schema: wrong type", ok, false )

    ok = router._validate_schema( schema,
        { target = "x", duration_minutes = 60 } )
    eq( "schema: integer ok", ok, true )

    ok, err = router._validate_schema( schema,
        { target = "x", duration_minutes = 1.5 } )
    eq( "schema: integer rejects float", ok, false )

    ok, err = router._validate_schema( schema,
        { target = "x", scope = "everyone" } )
    eq( "schema: enum mismatch", ok, false )

    ok, err = router._validate_schema( schema,
        { target = string.rep( "x", 65 ) } )
    eq( "schema: max_length exceeded", ok, false )

    ok, err = router._validate_schema( schema,
        { target = "x", duration_minutes = 0 } )
    eq( "schema: below min", ok, false )

    eq( "schema: nil schema -> ok",
        router._validate_schema( nil, { } ), true )
end

----------------------------------------------------------------------
-- envelope helpers
----------------------------------------------------------------------

do
    local e = router._envelope_success( { x = 1 } )
    -- mock dkjson.encode returns { _encoded = v }; we assert the
    -- shape the router built.
    eq( "envelope: success ok flag", e._encoded.ok, true )
    eq( "envelope: success data x", e._encoded.data.x, 1 )

    local f = router._envelope_error( "E_BAD_INPUT", "bad field" )
    eq( "envelope: error ok flag", f._encoded.ok, false )
    eq( "envelope: error code", f._encoded.error.code, "E_BAD_INPUT" )
    eq( "envelope: error message", f._encoded.error.message, "bad field" )
end

----------------------------------------------------------------------
-- resolve_token
----------------------------------------------------------------------

do
    _stub_cfg_tokens = {
        [ "admin-tokens-here-which-is-long-enough" ] = { scope = "admin", comment = "ops cli" },
        [ "readonlytoken99-also-long-enough" ]       = { scope = "read",  comment = "grafana" },
        [ "shorty7" ]                                = { scope = "read",  comment = "tiny" },
    }
    local label, scope, bid = router._resolve_token( "Bearer admin-tokens-here-which-is-long-enough" )
    eq( "resolve: admin scope", scope, "admin" )
    eq( "resolve: admin label has comment", label:find( "ops cli", 1, true ) ~= nil, true )
    eq( "resolve: admin label NO full secret",
        label:find( "tokens-here-which-is", 1, true ), nil )
    eq( "resolve: bucket_id is 16 chars for long token", #bid, 16 )
    eq( "resolve: bucket_id is non-empty", #bid > 0, true )

    -- Two distinct tokens with the same comment + same first4 +
    -- same last4 would have collided in the PR-B label-as-bucket
    -- scheme. Confirm their bucket_ids differ here.
    _stub_cfg_tokens = {
        [ "abcd-XXXX-aaaaaaaa-wxyz" ] = { scope = "read", comment = "dup" },
        [ "abcd-YYYY-bbbbbbbb-wxyz" ] = { scope = "read", comment = "dup" },
    }
    local lbl1, _, bid1 = router._resolve_token( "Bearer abcd-XXXX-aaaaaaaa-wxyz" )
    local lbl2, _, bid2 = router._resolve_token( "Bearer abcd-YYYY-bbbbbbbb-wxyz" )
    eq( "resolve: label collides (audit only)", lbl1, lbl2 )
    eq( "resolve: bucket_id does NOT collide", bid1 == bid2, false )

    -- Short token (< 16 chars): bucket_id falls back to full token
    _stub_cfg_tokens = {
        [ "shorty7" ] = { scope = "read", comment = "tiny" },
    }
    local _, _, bid_s = router._resolve_token( "Bearer shorty7" )
    eq( "resolve: short token bucket_id == full token", bid_s, "shorty7" )

    -- restore for the unknown-token tests below
    _stub_cfg_tokens = { }
    local nil_l, err = router._resolve_token( "Bearer nope-not-a-token" )
    eq( "resolve: unknown -> nil", nil_l, nil )
    eq( "resolve: unknown -> error code", err, "unknown" )

    nil_l, err = router._resolve_token( "MalformedHeader" )
    eq( "resolve: no Bearer -> malformed", err, "malformed" )

    nil_l, err = router._resolve_token( nil )
    eq( "resolve: missing -> missing", err, "missing" )
end

----------------------------------------------------------------------
-- generate_request_id shape (8-4-4-4-12 hex)
----------------------------------------------------------------------

do
    local id = router._generate_request_id( )
    eq( "req-id: length",
        #id, 36 )
    eq( "req-id: pattern matches UUIDv4-shape",
        id:match( "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-4%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$" ) ~= nil,
        true )
end

----------------------------------------------------------------------
-- register + unregister_all + duplicate rejection
----------------------------------------------------------------------

do
    router.unregister_all( )

    -- Register fresh; succeeds.
    local handler = function( ) return { status = 200, data = { } } end
    local ok = pcall( router.register, "GET", "/v1/foo", "read", handler )
    eq( "register: fresh route ok", ok, true )

    -- Duplicate same method+path rejects.
    local ok2 = pcall( router.register, "GET", "/v1/foo", "read", handler )
    eq( "register: duplicate route rejected", ok2, false )

    -- Different method on same path: ok.
    local ok3 = pcall( router.register, "POST", "/v1/foo", "admin", handler )
    eq( "register: same path different method ok", ok3, true )

    -- Lowercase method rejected.
    local ok4 = pcall( router.register, "get", "/v1/bar", "read", handler )
    eq( "register: lowercase method rejected", ok4, false )

    -- Invalid scope rejected.
    local ok5 = pcall( router.register, "GET", "/v1/bar", "guest", handler )
    eq( "register: invalid scope rejected", ok5, false )

    -- Path must start with /
    local ok6 = pcall( router.register, "GET", "v1/baz", "read", handler )
    eq( "register: path without / rejected", ok6, false )

    -- Non-function handler rejected.
    local ok7 = pcall( router.register, "GET", "/v1/qux", "read", "not-a-function" )
    eq( "register: non-function handler rejected", ok7, false )

    router.unregister_all( )
end

----------------------------------------------------------------------
-- idempotency cache (FIFO + TTL + replace-in-place + clear)
----------------------------------------------------------------------

do
    -- Cache key shape is (bucket_id, method, path, idem_key) per #275
    -- SEC-5 path-scoping: a shared idempotency key must NOT collide
    -- across (method, path) pairs.
    local M, P = "POST", "/v1/x"
    router._idem_clear( )

    -- miss on cold cache
    local status, body, headers = router._idem_lookup( "label", M, P, "k1" )
    eq( "idem: cold miss", status, nil )

    -- store + hit
    router._idem_store( "label", M, P, "k1", 201, "BODY1", { foo = "bar" } )
    local st, bd, hd = router._idem_lookup( "label", M, P, "k1" )
    eq( "idem: hit status", st, 201 )
    eq( "idem: hit body",   bd, "BODY1" )
    eq( "idem: hit header keeps foo", hd and hd.foo, "bar" )

    -- different label, same key -> miss (per-token isolation)
    local st2 = router._idem_lookup( "other_label", M, P, "k1" )
    eq( "idem: per-token isolation", st2, nil )

    -- #275 SEC-5: same (label, key) but different method or path -> miss
    local stMm = router._idem_lookup( "label", "DELETE", P, "k1" )
    eq( "idem: method-scoped (DELETE same path same key)", stMm, nil )
    local stPp = router._idem_lookup( "label", M, "/v1/y", "k1" )
    eq( "idem: path-scoped (same method other path same key)", stPp, nil )

    -- replace in place (same key)
    router._idem_store( "label", M, P, "k1", 409, "CONFLICT", { } )
    local st3, bd3 = router._idem_lookup( "label", M, P, "k1" )
    eq( "idem: replace status", st3, 409 )
    eq( "idem: replace body",   bd3, "CONFLICT" )

    -- empty / missing key -> no-op (not cached, not looked up)
    router._idem_store( "label", M, P, "", 200, "X", { } )
    local stN = router._idem_lookup( "label", M, P, "" )
    eq( "idem: empty key never hits", stN, nil )
    local stN2 = router._idem_lookup( "label", M, P, nil )
    eq( "idem: nil key never hits", stN2, nil )

    -- clear
    router._idem_clear( )
    local stC = router._idem_lookup( "label", M, P, "k1" )
    eq( "idem: cleared", stC, nil )

    -- Cap-eviction: shrink cap to 2 via mock cfg, store 3 entries,
    -- confirm oldest insert was evicted FIFO. Also confirms the
    -- replace-in-place + ord-bump path: replacing k1 between k2
    -- and k3 stores does NOT evict the live k1 when k3 trips cap.
    _stub_cfg_idem_cap = 2
    router._idem_clear( )
    router._idem_store( "L", M, P, "k1", 200, "B1", { } )
    router._idem_store( "L", M, P, "k2", 200, "B2", { } )
    eq( "idem-cap: pre-evict k1 alive", router._idem_lookup( "L", M, P, "k1" ), 200 )
    eq( "idem-cap: pre-evict k2 alive", router._idem_lookup( "L", M, P, "k2" ), 200 )
    router._idem_store( "L", M, P, "k3", 200, "B3", { } )
    eq( "idem-cap: oldest k1 evicted", router._idem_lookup( "L", M, P, "k1" ), nil )
    eq( "idem-cap: k2 survives", router._idem_lookup( "L", M, P, "k2" ), 200 )
    eq( "idem-cap: k3 alive", router._idem_lookup( "L", M, P, "k3" ), 200 )

    -- Replace-in-place + cap: store k1+k2, then replace k1, then
    -- store k3 (would trigger 1 eviction). The replaced k1 must
    -- survive because its ord is the NEWEST; k2 should be evicted.
    router._idem_clear( )
    router._idem_store( "L", M, P, "k1", 200, "B1-old", { } )
    router._idem_store( "L", M, P, "k2", 200, "B2",     { } )
    router._idem_store( "L", M, P, "k1", 200, "B1-new", { } )    -- replace; k1.ord becomes newest
    router._idem_store( "L", M, P, "k3", 200, "B3",     { } )    -- evict cycle: pops k1-stale, sees ord mismatch, keeps live k1; pops k2 next, evicts.
    local k1_st, k1_bd = router._idem_lookup( "L", M, P, "k1" )
    eq( "idem-cap-replace: replaced k1 alive", k1_st, 200 )
    eq( "idem-cap-replace: replaced k1 body is NEW", k1_bd, "B1-new" )
    eq( "idem-cap-replace: k2 evicted (older ord)", router._idem_lookup( "L", M, P, "k2" ), nil )
    eq( "idem-cap-replace: k3 alive", router._idem_lookup( "L", M, P, "k3" ), 200 )

    -- restore default cap (other tests don't care, but be tidy)
    _stub_cfg_idem_cap = nil
end

----------------------------------------------------------------------
-- dispatch: OPTIONS introspection must not be an unauthenticated
-- path-existence oracle (Part of #533). The normal 405/404 outcomes
-- only reveal path existence to an authenticated caller, so anonymous
-- OPTIONS on an auth-gated path must 401 just like a GET would; only a
-- scope="none" (public) path or an authenticated caller gets 204+Allow.
-- RED pre-fix: anonymous OPTIONS on an auth-gated path returned
-- 204+Allow (introspection ran before auth).
----------------------------------------------------------------------

do
    router.unregister_all( )
    local h = function( ) return { status = 200, data = { } } end
    router.register( "GET",  "/v1/probe", "read",  h )   -- auth-gated path
    router.register( "POST", "/v1/probe", "admin", h )
    router.register( "GET",  "/v1/pub",   "none",  h )   -- public path
    _stub_cfg_tokens = { [ "VALIDREADTOKEN0001" ] = { scope = "read" } }

    local function opt( path, token )
        local headers = { }
        if token then headers[ "authorization" ] = "Bearer " .. token end
        return router.dispatch(
            { method = "OPTIONS", target = path, headers = headers, body = nil },
            "127.0.0.1" )
    end
    local function allows( hdrs, m )
        return hdrs and hdrs[ "Allow" ] and hdrs[ "Allow" ]:find( m, 1, true ) ~= nil
    end

    -- anonymous OPTIONS on the auth-gated path: 401, no Allow leak.
    local st, _b, hdrs = opt( "/v1/probe", nil )
    eq( "OPTIONS anon auth-gated path -> 401", st, 401 )
    eq( "OPTIONS anon auth-gated: no Allow leak", hdrs and hdrs[ "Allow" ], nil )

    -- authenticated OPTIONS on the same path: 204 + Allow(GET,HEAD,OPTIONS).
    local st2, _b2, hdrs2 = opt( "/v1/probe", "VALIDREADTOKEN0001" )
    eq( "OPTIONS authed auth-gated path -> 204", st2, 204 )
    eq( "OPTIONS authed: Allow lists GET",     allows( hdrs2, "GET" ),     true )
    eq( "OPTIONS authed: Allow lists HEAD",    allows( hdrs2, "HEAD" ),    true )
    eq( "OPTIONS authed: Allow lists OPTIONS", allows( hdrs2, "OPTIONS" ), true )

    -- anonymous OPTIONS on a public (scope="none") path: still 204.
    local st3, _b3, hdrs3 = opt( "/v1/pub", nil )
    eq( "OPTIONS anon public path -> 204", st3, 204 )
    eq( "OPTIONS anon public: Allow present", allows( hdrs3, "GET" ), true )

    -- anonymous OPTIONS on an unknown path: 401 (unchanged).
    eq( "OPTIONS anon unknown path -> 401", ( opt( "/v1/unknown", nil ) ), 401 )

    router.unregister_all( )
    _stub_cfg_tokens = { }
end

----------------------------------------------------------------------
-- dispatch body-shape guard (§6.1): a top-level JSON *array* must be
-- rejected, not silently accepted as a body whose named fields all read
-- nil. Real dkjson tags a decoded array with metatable
-- {__jsontype="array"}; the router rejects on that tag (the mock mirrors
-- the tag via its "ARR:" prefix; the real tag is pinned below).
-- RED pre-fix: the array body reached the handler and returned 200.
----------------------------------------------------------------------

do
    router.unregister_all( )
    local seen_body
    local h = function( req )
        seen_body = req.body
        return { status = 200, data = { got = "ok" } }
    end
    router.register( "POST", "/v1/body", "admin", h )
    _stub_cfg_tokens = { [ "ADMINTOKEN00000001" ] = { scope = "admin" } }

    local function post( raw )
        return router.dispatch( {
            method  = "POST",
            target  = "/v1/body",
            headers = {
                [ "authorization" ] = "Bearer ADMINTOKEN00000001",
                [ "content-type" ]  = "application/json; charset=utf-8",
            },
            body = raw,
        }, "127.0.0.1" )
    end

    -- object body: accepted, handler runs, body reaches it.
    seen_body = nil
    local st_ok = post( "OBJ:{ topic = 'hello' }" )
    eq( "body-guard: object body -> 200", st_ok, 200 )
    eq( "body-guard: object body reaches handler", seen_body and seen_body.topic, "hello" )

    -- array body: rejected 400 BEFORE the handler; distinct message.
    seen_body = nil
    local st_arr, body_arr = post( "ARR:{ 1, 2, 3 }" )
    eq( "body-guard: array body -> 400", st_arr, 400 )
    local arr_err = body_arr and body_arr._encoded and body_arr._encoded.error
    eq( "body-guard: array body code E_BAD_JSON", arr_err and arr_err.code, "E_BAD_JSON" )
    eq( "body-guard: array body message names array",
        arr_err and arr_err.message, "body must be a JSON object, not a JSON array" )
    eq( "body-guard: array body never reached handler", seen_body, nil )

    router.unregister_all( )
    _stub_cfg_tokens = { }
end

----------------------------------------------------------------------
-- Pin the external assumption Fix A relies on: the BUNDLED dkjson tags a
-- decoded top-level array with __jsontype="array" and an object with
-- "object". If a future dkjson bump drops the tag, the body-shape guard
-- above silently stops rejecting arrays; catch that here, not in prod.
----------------------------------------------------------------------

do
    local realdk = assert( loadfile( "dkjson/dkjson.lua" ) )( )
    local arr = realdk.decode( "[1,2,3]" )
    local obj = realdk.decode( "{\"a\":1}" )
    eq( "dkjson: decoded array tagged __jsontype=array",
        getmetatable( arr ) and getmetatable( arr ).__jsontype, "array" )
    eq( "dkjson: decoded object tagged __jsontype=object",
        getmetatable( obj ) and getmetatable( obj ).__jsontype, "object" )
end

----------------------------------------------------------------------
-- dispatch handler-crash logging (Fix B): an uncaught handler error is
-- caught (500 E_INTERNAL) AND logged WITH its Lua traceback (xpcall +
-- debug.traceback), not just the bare message (pcall).
-- RED pre-fix (pcall): the logged text carried the message but no
-- "stack traceback:" section.
----------------------------------------------------------------------

do
    router.unregister_all( )
    router.register( "GET", "/v1/boom", "read", function( ) error( "kaboom" ) end )
    _stub_cfg_tokens = { [ "READTOKEN000000001" ] = { scope = "read" } }
    _last_error_args = nil
    local st = router.dispatch( {
        method  = "GET",
        target  = "/v1/boom",
        headers = { [ "authorization" ] = "Bearer READTOKEN000000001" },
        body    = nil,
    }, "127.0.0.1" )
    eq( "handler-crash: 500 E_INTERNAL", st, 500 )
    local logged = _last_error_args and table.concat( _last_error_args, "" ) or ""
    eq( "handler-crash: message logged", logged:find( "kaboom", 1, true ) ~= nil, true )
    eq( "handler-crash: traceback logged", logged:find( "stack traceback", 1, true ) ~= nil, true )
    router.unregister_all( )
    _stub_cfg_tokens = { }
end

----------------------------------------------------------------------
-- POST /v1/auth/verify handler (WebUI operator login via ADC challenge-
-- response). The deterministic _stub_hashpas lets this exercise the
-- HANDLER logic - reguser lookup, per-nick/IP throttle, constant-time
-- compare, ok/level, timing-equalization - while the real Tiger crypto
-- is covered by adclib_hashpas_test + smoke. RED pre-feature:
-- _auth_verify_handler does not exist (nil), so every call below errors.
----------------------------------------------------------------------

do
    local SALT = string.rep( "A", 39 )   -- valid RFC4648 base32, 39 chars
    _mock_regusers_by_nick = {
        [ "alice" ]   = { password = "secret", level = 60 },
        [ "bob" ]     = { password = "pw2" },          -- no level -> default 20
        [ "emptypw" ] = { password = "", level = 100 },-- corrupt user.tbl edge (LOW-1)
    }
    _authverify_allow = true
    local function verify( nickv, respv, ip )
        return router._auth_verify_handler( {
            body      = { nick = nickv, salt = SALT, response = respv },
            source_ip = ip or "127.0.0.1",
        } )
    end

    -- correct credential -> 200 { ok = true, level }
    local r1 = verify( "alice", _stub_hashpas( "secret", SALT ) )
    eq( "authverify: correct -> 200",      r1.status,                200 )
    eq( "authverify: correct -> ok true",  r1.data and r1.data.ok,   true )
    eq( "authverify: correct -> level 60", r1.data and r1.data.level, 60 )

    -- wrong password -> ok false, NO level leaked
    local r2 = verify( "alice", "H:wrong:" .. SALT )
    eq( "authverify: wrong pw -> ok false", r2.data and r2.data.ok,    false )
    eq( "authverify: wrong pw -> no level", r2.data and r2.data.level, nil )

    -- wrong password of the SAME LENGTH as the expected hash: exercises
    -- the equal-length byte compare, not the length short-circuit (NIT-5).
    local r2b = verify( "alice", _stub_hashpas( "secre7", SALT ) )   -- 6 chars like "secret"
    eq( "authverify: same-length wrong pw -> ok false", r2b.data and r2b.data.ok, false )

    -- empty STORED password must never authenticate, even with the
    -- "correct" hash of "" (LOW-1: empty is treated as absent -> DUMMY).
    local r_empty = verify( "emptypw", _stub_hashpas( "", SALT ) )
    eq( "authverify: empty stored pw -> ok false", r_empty.data and r_empty.data.ok, false )

    -- unknown nick -> ok false, but hashpas STILL called (timing-equalized)
    local before = #_hashpas_calls
    local r3 = verify( "nobody", "whatever" )
    eq( "authverify: unknown nick -> ok false", r3.data and r3.data.ok, false )
    eq( "authverify: unknown nick still hashes (timing-equalized)",
        #_hashpas_calls > before, true )

    -- reguser with no level field -> default 20
    local r4 = verify( "bob", _stub_hashpas( "pw2", SALT ) )
    eq( "authverify: missing level -> default 20", r4.data and r4.data.level, 20 )

    -- rate-limited (per-nick/IP bucket empty) -> 429
    _authverify_allow = false
    local r5 = verify( "alice", _stub_hashpas( "secret", SALT ) )
    eq( "authverify: rate-limited -> 429", r5.status, 429 )
    _authverify_allow = true

    -- malformed salt -> 400 (clean, not a hashpas crash)
    local r6 = router._auth_verify_handler( {
        body = { nick = "alice", salt = "not*base32!", response = "x" },
        source_ip = "127.0.0.1",
    } )
    eq( "authverify: bad salt -> 400", r6.status, 400 )
    eq( "authverify: bad salt -> E_BAD_INPUT", r6.error and r6.error.code, "E_BAD_INPUT" )

    -- missing fields -> 400
    local r7 = router._auth_verify_handler( { body = { }, source_ip = "127.0.0.1" } )
    eq( "authverify: missing fields -> 400", r7.status, 400 )
end

----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
