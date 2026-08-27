--[[

    tests/unit/etc_webhook_test.lua

    Unit tests for scripts/etc_webhook.lua (inbound webhook receiver, #398).

    Uses the REAL core/hmac.lua (loaded via a use-shim) so the HMAC-SHA256
    signature verification is genuinely exercised - a valid request is
    signed the same way the plugin verifies it. Everything else is a
    sandbox-global stub (plugins get NO `use`). The plugin's captured
    HTTP handler + listeners are driven by hand over a controlled clock.

    Covers: HMAC pass / wrong-sig / missing-sig, sha256= prefix strip,
    event filter (allowed / unlisted / ping), dedup, template rendering
    ({dotted.path}, {event}, missing path), control-byte strip +
    truncation, global flood cap, min_level gating (per-user reply vs
    broadcast), missing-secret endpoint skipped, activate=false inert,
    body-field conditions (equals / not_equals).

    Run: lua5.4 tests/unit/etc_webhook_test.lua

]]--

----------------------------------------------------------------------
-- real hmac (needs sha256) via a use-shim, BEFORE installing sandbox globals
----------------------------------------------------------------------
local _real_os = os
local _shim = { type = type, string = string, table = table, error = error, tostring = tostring, io = io }
_G.use = function( n ) return _shim[ n ] end
local sha256 = assert( loadfile( "core/sha256.lua" ) )( )
_shim.sha256 = sha256
local hmac = assert( loadfile( "core/hmac.lua" ) )( )
_G.use = nil

----------------------------------------------------------------------
-- tiny harness
----------------------------------------------------------------------
local checks, failures = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then failures = failures + 1
        io.write( string.format( "FAIL %-56s got=%s want=%s\n", label, tostring( got ), tostring( want ) ) )
    else io.write( "ok   " .. label .. "\n" ) end
end
local function truthy( label, v )
    checks = checks + 1
    if not v then failures = failures + 1; io.write( "FAIL " .. label .. " (got " .. tostring( v ) .. ")\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- mutable state the stubs close over
----------------------------------------------------------------------
local CONFIG_FILE = "cfg/webhooks.tbl"
local DEDUP_FILE  = "scripts/data/etc_webhook.tbl"
local _now, _activate, _config, _dedup, _users
local _listeners, _routes, _announced
local _written, _chmod_called          -- mgmt writer round-trip capture (v0.04)

local SECRET = "s3cr3t-webhook-key"

----------------------------------------------------------------------
-- sandbox-global stubs
----------------------------------------------------------------------
_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs; _G.next = next
_G.tonumber = tonumber; _G.tostring = tostring
_G.string = string; _G.table = table; _G.math = math
_G.PROCESSED = "PROCESSED"
_G.hmac = hmac
_G.adclib = { constant_time_eq = function( a, b ) return a == b end, sanitize_utf8 = function( s ) return s end }
_G.utf = {
    len = function( s ) return #s end,
    sub = function( s, i, j ) return string.sub( s, i, j ) end,
}
local _real_io = io
_G.os = setmetatable( { time = function( ) return _now end }, { __index = _real_os } )
-- io.open returns a handle only when the corresponding state exists, so
-- the plugin's first-run-silent probes see "file present" iff we set the
-- state (CONFIG_FILE <-> _config, DEDUP_FILE <-> _dedup). Mirrors on-disk
-- reality: io.open succeeds iff the file exists.
_G.io = setmetatable( { open = function( p )
    if p == CONFIG_FILE and _config then return { close = function( ) end } end
    if p == DEDUP_FILE  and _dedup  then return { close = function( ) end } end
    return nil
end }, { __index = _real_io } )

_G.cfg = {
    get = function( k )
        if k == "etc_webhook_activate" then return _activate end
        if k == "language" then return "en" end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
local _dedup_loadtable_called = false
_G.util = {
    loadtable = function( p )
        if p == CONFIG_FILE then return _config end
        if p == DEDUP_FILE then _dedup_loadtable_called = true; return _dedup end
        return nil
    end,
    savetable = function( t, _name, p ) if p == DEDUP_FILE then _dedup = t end end,
    strip_control_bytes = function( s ) if type( s ) ~= "string" then return "" end return ( s:gsub( "%c", "?" ) ) end,
    -- mgmt writer (v0.04): tabletostring captures the raw table it is asked
    -- to serialise; atomic_write "commits" it back to _config so a write
    -- then a read round-trips (mirrors the on-disk file). The real
    -- util.tabletostring output is exercised by the smoke test.
    tabletostring = function( tbl, _name ) _written = tbl; return "SERIALISED\n" end,
    atomic_write  = function( p, _content ) if p == CONFIG_FILE then _config = _written end return true end,
    chmod_secret  = function( _p ) _chmod_called = true end,
}
-- secrets.lookup returns an env/cfg override for a key iff seeded in
-- _overrides (default: none -> inline-secret path). Lets a test exercise
-- secret_source = "external".
local _overrides = { }
_G.secrets = { register = function( ) end, lookup = function( k ) return _overrides[ k ] end }

-- audit stub: capture fired events so a test can assert the endpoint name
-- reaches audit as a flat-table target (a bare-string target is dropped to
-- nil by the real audit.build - the v0.04 bug this guards).
local _audit_events = { }
_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, actor = actor, target = target, reason = reason, meta = meta }
    end,
    fire  = function( ev ) _audit_events[ #_audit_events + 1 ] = ev end,
}
local function last_audit( ) return _audit_events[ #_audit_events ] end

_G.hub = {
    setlistener   = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    -- key by "METHOD path": v0.04 registers GET/POST/PUT on the same
    -- /v1/webhooks path, so a path-only key would clobber siblings.
    http_register = function( method, path, scope, handler, meta )
        _routes[ method .. " " .. path ] = { method = method, scope = scope, handler = handler, meta = meta }
    end,
    regbot   = function( p ) return { nick = function( ) return p.nick end } end,
    getbot   = function( ) return { hubbot = true } end,
    getusers = function( ) return _users end,
    import   = function( ) return nil end,
    debug    = function( ) end,
    broadcast = function( msg, from ) _announced[ #_announced + 1 ] = { msg = msg, from = from, kind = "broadcast" } end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( )
    _listeners, _routes, _announced = { }, { }, { }
    assert( loadfile( "scripts/etc_webhook.lua" ) )( )
    if _listeners.onStart then _listeners.onStart( ) end   -- hub fires onStart after load
end

local function make_user( nick, level )
    return {
        level = function( ) return level end,
        reply = function( _self, msg, from ) _announced[ #_announced + 1 ] = { msg = msg, from = from, kind = "reply", to = nick } end,
    }
end

-- sign the body the way the plugin verifies it
local function sig_for( body ) return "sha256=" .. hmac.sha256( SECRET, body ) end

local function route( method, path ) return _routes[ method .. " " .. path ] end

-- invoke a management handler with a synthetic admin request
local function call( method, path, body, path_vars )
    local r = route( method, path )
    if not r then return nil end
    return r.handler( { body = body, path_vars = path_vars, token_label = "op1" } )
end

-- convenience: a Discourse-style post_created request with a decoded body
local function discourse_req( id, event, sig, body_str, body_tbl )
    return {
        headers = {
            [ "x-discourse-event-signature" ] = sig,
            [ "x-discourse-event" ]           = event,   -- the SPECIFIC event (matches base_config event_header)
            [ "x-discourse-event-type" ]      = "topic",  -- the category; present but not what we key on
            [ "x-discourse-event-id" ]        = id,
        },
        raw_body = body_str,
        body     = body_tbl,
    }
end

local function base_config( )
    return {
        max_per_minute = 3,
        dedup_max      = 100,
        field_maxlen   = 20,
        endpoints = {
            {
                name = "discourse", path = "/v1/webhook/discourse",
                signature_header = "x-discourse-event-signature", signature_prefix = "sha256=",
                event_header = "x-discourse-event", events = { "post_created" },
                id_header = "x-discourse-event-id", bot_nick = "Forum", min_level = 0,
                templates = { post_created = "New post by {post.username}: {post.topic_title}" },
                secret = SECRET,
            },
        },
    }
end

local function fire_handler( req )
    return route( "POST", "/v1/webhook/discourse" ).handler( req )
end

----------------------------------------------------------------------
-- setup: active, one Discourse endpoint
----------------------------------------------------------------------
_now = 1000; _activate = true; _dedup = nil; _users = { }
_config = base_config( )
load_plugin( )

truthy( "route registered for the discourse endpoint", route( "POST", "/v1/webhook/discourse" ) ~= nil )
eq( "route is POST",  route( "POST", "/v1/webhook/discourse" ).method, "POST" )
eq( "route scope is none", route( "POST", "/v1/webhook/discourse" ).scope, "none" )
-- v0.04: management routes register alongside the receiver
truthy( "mgmt GET /v1/webhooks registered",    route( "GET", "/v1/webhooks" ) ~= nil )
eq( "mgmt GET scope is read",                  route( "GET", "/v1/webhooks" ).scope, "read" )
eq( "mgmt POST scope is admin",                route( "POST", "/v1/webhooks" ).scope, "admin" )
eq( "mgmt PUT {name} scope is admin",          route( "PUT", "/v1/webhooks/{name}" ).scope, "admin" )
eq( "mgmt DELETE {name} scope is admin",       route( "DELETE", "/v1/webhooks/{name}" ).scope, "admin" )

local BODY = '{"post":{"username":"alice","topic_title":"Hello"}}'
local BTBL = { post = { username = "alice", topic_title = "Hello" } }

----------------------------------------------------------------------
-- 1. valid signed post_created -> 200 + one rendered announce
----------------------------------------------------------------------
local r = fire_handler( discourse_req( "1", "post_created", sig_for( BODY ), BODY, BTBL ) )
eq( "valid: status 200", r.status, 200 )
eq( "valid: one announce", #_announced, 1 )
eq( "valid: rendered template", _announced[ 1 ] and _announced[ 1 ].msg, "New post by alice: Hello" )
eq( "valid: broadcast (min_level 0)", _announced[ 1 ] and _announced[ 1 ].kind, "broadcast" )

----------------------------------------------------------------------
-- 2. wrong signature -> 401, no announce
----------------------------------------------------------------------
_announced = { }
r = fire_handler( discourse_req( "2", "post_created", "sha256=deadbeef", BODY, BTBL ) )
eq( "wrong sig: 401", r.status, 401 )
eq( "wrong sig: no announce", #_announced, 0 )

----------------------------------------------------------------------
-- 3. missing signature header -> 401
----------------------------------------------------------------------
_announced = { }
r = fire_handler( { headers = { [ "x-discourse-event-type" ] = "post_created" }, raw_body = BODY, body = BTBL } )
eq( "missing sig: 401", r.status, 401 )

----------------------------------------------------------------------
-- 4. correctly signed but UNLISTED event -> 200, no announce
----------------------------------------------------------------------
_announced = { }
r = fire_handler( discourse_req( "4", "user_updated", sig_for( BODY ), BODY, BTBL ) )
eq( "unlisted event: 200", r.status, 200 )
eq( "unlisted event: no announce", #_announced, 0 )

----------------------------------------------------------------------
-- 5. ping (signed, not in events) -> 200, no announce (test-delivery ok)
----------------------------------------------------------------------
_announced = { }
r = fire_handler( discourse_req( "5", "ping", sig_for( BODY ), BODY, BTBL ) )
eq( "ping: 200 (secret validated, nothing announced)", r.status, 200 )
eq( "ping: no announce", #_announced, 0 )

----------------------------------------------------------------------
-- 6. dedup: same id twice -> second is a no-op
----------------------------------------------------------------------
_announced = { }
fire_handler( discourse_req( "dup", "post_created", sig_for( BODY ), BODY, BTBL ) )
fire_handler( discourse_req( "dup", "post_created", sig_for( BODY ), BODY, BTBL ) )
eq( "dedup: only first delivery announced", #_announced, 1 )

----------------------------------------------------------------------
-- 7. template: missing path -> empty; {event} resolves
----------------------------------------------------------------------
_announced = { }
_config = base_config( )
_config.endpoints[ 1 ].templates.post_created = "[{event}] {post.username} / {post.missing.deep}"
load_plugin( )
fire_handler( discourse_req( "7", "post_created", sig_for( BODY ), BODY, BTBL ) )
eq( "template: {event} + missing path -> empty", _announced[ 1 ] and _announced[ 1 ].msg, "[post_created] alice / " )

----------------------------------------------------------------------
-- 7b. non-scalar path (a signed sender sends an object where a scalar
--     was expected) renders empty - no "table: 0x..." heap-pointer leak
----------------------------------------------------------------------
_announced = { }
_config = base_config( )
_config.endpoints[ 1 ].templates.post_created = "by {post.username}"
load_plugin( )
local OBJBODY = '{"post":{"username":{"nested":"x"}}}'
fire_handler( discourse_req( "7b", "post_created", sig_for( OBJBODY ), OBJBODY, { post = { username = { nested = "x" } } } ) )
eq( "non-scalar field renders empty (no heap pointer)", _announced[ 1 ] and _announced[ 1 ].msg, "by " )

----------------------------------------------------------------------
-- 8. truncation (field_maxlen=20) + control-byte strip
----------------------------------------------------------------------
_announced = { }
_config = base_config( )
_config.endpoints[ 1 ].templates.post_created = "{post.topic_title}"
load_plugin( )
local LONGBODY = '{"post":{"topic_title":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'   -- 30 a's
fire_handler( discourse_req( "8", "post_created", sig_for( LONGBODY ), LONGBODY, { post = { topic_title = string.rep( "a", 30 ) } } ) )
eq( "truncation: value cut to field_maxlen + ellipsis", _announced[ 1 ].msg, string.rep( "a", 20 ) .. "..." )

_announced = { }
local CTRLBODY = '{"post":{"topic_title":"a\\tb"}}'
local ctrl_tbl = { post = { topic_title = "a\tb" } }
-- sign the exact raw bytes we send
local ctrl_raw = '{"post":{"topic_title":"a\tb"}}'
load_plugin( )
fire_handler( discourse_req( "9", "post_created", sig_for( ctrl_raw ), ctrl_raw, ctrl_tbl ) )
eq( "control byte stripped from value", _announced[ 1 ].msg, "a?b" )

----------------------------------------------------------------------
-- 9. flood cap: max_per_minute=3 -> 4th announce dropped (same clock)
----------------------------------------------------------------------
_announced = { }
_config = base_config( )   -- max_per_minute = 3
load_plugin( )
for i = 1, 4 do
    fire_handler( discourse_req( "f" .. i, "post_created", sig_for( BODY ), BODY, BTBL ) )
end
eq( "flood cap: only 3 of 4 announced", #_announced, 3 )

----------------------------------------------------------------------
-- 10. min_level gating: only users >= min_level get a per-user reply,
--     hub.broadcast is NOT used
----------------------------------------------------------------------
_announced = { }
_config = base_config( )
_config.endpoints[ 1 ].min_level = 50
load_plugin( )
_users = { make_user( "op", 60 ), make_user( "reg", 20 ), make_user( "op2", 50 ) }
fire_handler( discourse_req( "10", "post_created", sig_for( BODY ), BODY, BTBL ) )
local replies, broadcasts = 0, 0
for _, a in ipairs( _announced ) do
    if a.kind == "reply" then replies = replies + 1 end
    if a.kind == "broadcast" then broadcasts = broadcasts + 1 end
end
eq( "min_level: 2 users >= 50 get a reply", replies, 2 )
eq( "min_level: no broadcast used", broadcasts, 0 )
_users = { }

----------------------------------------------------------------------
-- 11. endpoint with NO resolvable secret is skipped (no route)
----------------------------------------------------------------------
_config = base_config( )
_config.endpoints[ 1 ].secret = nil    -- no inline; secrets.lookup returns nil
load_plugin( )
truthy( "no-secret endpoint: receiver route NOT registered", route( "POST", "/v1/webhook/discourse" ) == nil )
truthy( "no-secret endpoint: mgmt API still registered", route( "GET", "/v1/webhooks" ) ~= nil )

----------------------------------------------------------------------
-- 12. activate = false -> receiver inert, but mgmt API still present
--     (v0.04: the WebUI tab must be reachable to flip the switch on)
----------------------------------------------------------------------
_activate = false
_config = base_config( )
load_plugin( )
truthy( "activate=false: receiver route NOT registered", route( "POST", "/v1/webhook/discourse" ) == nil )
truthy( "activate=false: mgmt GET still registered",     route( "GET", "/v1/webhooks" ) ~= nil )
r = call( "GET", "/v1/webhooks" )
eq( "activate=false: GET reports activate=false", r.data.activate, false )
_activate = true

----------------------------------------------------------------------
-- 13. first-run dedup state (#398 follow-up, v0.02): with no dedup file
--     yet, dedup_load must probe io.open and NOT call util.loadtable -
--     util.loadtable -> checkfile logs an error.log line the HubSecurity
--     bot relays to ops on every fresh start.
----------------------------------------------------------------------
_config = base_config( )
_dedup = nil                          -- dedup file absent (first run)
_dedup_loadtable_called = false
load_plugin( )                        -- fires onStart -> dedup_load
eq( "first-run: dedup_load skips util.loadtable (no checkfile noise)", _dedup_loadtable_called, false )

-- complement: an existing dedup file IS loaded, so an id persisted from a
-- prior run is treated as a duplicate on the very first delivery. The
-- stored key is namespaced by endpoint name (see the handler:
-- entry.name .. ":" .. id), so seed the "discourse:" form.
_config = base_config( )
_dedup = { seen = { [ "discourse:persisted" ] = 1 } }
_dedup_loadtable_called = false
load_plugin( )
eq( "existing dedup file loaded via util.loadtable", _dedup_loadtable_called, true )
fire_handler( discourse_req( "persisted", "post_created", sig_for( BODY ), BODY, BTBL ) )
eq( "pre-seen id from disk is deduped (no announce)", #_announced, 0 )
_dedup = nil

----------------------------------------------------------------------
-- 14. body-field conditions (v0.03). Fail pre-fix: without the feature
--     every one of these would announce (the conditions field is ignored).
----------------------------------------------------------------------
-- 14a. not_equals: skip a Discourse topic's opening post (post_number == 1),
--      but still announce real replies (>= 2) and payloads lacking the field.
_config = base_config( )
_config.max_per_minute = 100   -- decouple from the flood cap: suppression is the only variable
_config.endpoints[ 1 ].templates.post_created = "post {post.post_number}"
_config.endpoints[ 1 ].conditions = { { path = "post.post_number", not_equals = 1 } }
load_plugin( )

_announced = { }
local B_OPEN = '{"post":{"post_number":1}}'
fire_handler( discourse_req( "c1", "post_created", sig_for( B_OPEN ), B_OPEN, { post = { post_number = 1 } } ) )
eq( "conditions not_equals: opening post (post_number=1) suppressed", #_announced, 0 )

-- numeric compare: JSON 1.0 decodes to a Lua float; it must still match the
-- integer config 1 (a plain string compare would see "1.0" != "1" and leak).
_announced = { }
local B_OPENF = '{"post":{"post_number":1.0}}'
fire_handler( discourse_req( "c1f", "post_created", sig_for( B_OPENF ), B_OPENF, { post = { post_number = 1.0 } } ) )
eq( "conditions not_equals: float opening post (1.0) also suppressed", #_announced, 0 )

_announced = { }
local B_REPLY = '{"post":{"post_number":2}}'
fire_handler( discourse_req( "c2", "post_created", sig_for( B_REPLY ), B_REPLY, { post = { post_number = 2 } } ) )
eq( "conditions not_equals: reply (post_number=2) announced", #_announced, 1 )

_announced = { }
local B_NOFIELD = '{"post":{}}'   -- field absent (like a topic_created payload) -> nil passes not_equals
fire_handler( discourse_req( "c3", "post_created", sig_for( B_NOFIELD ), B_NOFIELD, { post = { } } ) )
eq( "conditions not_equals: absent field (nil) still announces", #_announced, 1 )

-- 14b. equals: GitHub-style action filter - announce only action == "released"
--      (all release actions share event=release; only the body field differs).
_config = base_config( )
_config.max_per_minute = 100
_config.endpoints[ 1 ].templates.post_created = "release {action}"
_config.endpoints[ 1 ].conditions = { { path = "action", equals = "released" } }
load_plugin( )

_announced = { }
local B_CREATED = '{"action":"created"}'
fire_handler( discourse_req( "e1", "post_created", sig_for( B_CREATED ), B_CREATED, { action = "created" } ) )
eq( "conditions equals: action=created suppressed", #_announced, 0 )

_announced = { }
local B_RELEASED = '{"action":"released"}'
fire_handler( discourse_req( "e2", "post_created", sig_for( B_RELEASED ), B_RELEASED, { action = "released" } ) )
eq( "conditions equals: action=released announced", #_announced, 1 )

----------------------------------------------------------------------
-- 15. HTTP management API (v0.04). The routes are net-new (absent on
--     v0.03), and the enabled-skip case (20) is a provable RED on v0.03:
--     normalise ignored `enabled`, so a disabled endpoint still got a
--     receiver route.
----------------------------------------------------------------------
local NEWEP = {
    name = "ci", signature_header = "x-ci-signature", signature_prefix = "sha256=",
    event_header = "x-ci-event", events = { "build" }, id_header = "x-ci-id",
    bot_nick = "CI", min_level = 0,
    templates = { build = "build {status}" },
    conditions = { { path = "branch", equals = "main" } },
    secret = "ci-secret",
}

-- 15. GET: shape + secret redaction (inline source)
_overrides = { }
_config = base_config( ); _activate = true; _dedup = nil; _users = { }
load_plugin( )
r = call( "GET", "/v1/webhooks" )
eq( "GET: status 200", r.status, 200 )
eq( "GET: one endpoint listed", #r.data.endpoints, 1 )
local d = r.data.endpoints[ 1 ]
eq( "GET: endpoint name", d.name, "discourse" )
eq( "GET: secret value NOT present", d.secret, nil )
eq( "GET: has_secret true (inline)", d.has_secret, true )
eq( "GET: secret_source = inline", d.secret_source, "inline" )
eq( "GET: enabled defaults true", d.enabled, true )
eq( "GET: valid true", d.valid, true )
eq( "GET: tuning max_per_minute from file", r.data.tuning.max_per_minute, 3 )
eq( "GET: activate reported true", r.data.activate, true )

-- 15b. GET: secret_source=external when an env/cfg override exists
_overrides = { [ "etc_webhook_discourse_secret" ] = "env-value" }
r = call( "GET", "/v1/webhooks" )
eq( "GET: secret_source = external with env/cfg override", r.data.endpoints[ 1 ].secret_source, "external" )
_overrides = { }

-- 16. POST create -> 200 reload_required, chmod 600 on write, then listed
_config = base_config( ); load_plugin( )
_chmod_called = false
r = call( "POST", "/v1/webhooks", NEWEP )
eq( "POST: status 200", r.status, 200 )
eq( "POST: apply_status reload_required", r.data.apply_status, "reload_required" )
eq( "POST: action label", r.data.action, "webhook-created" )
eq( "POST: writer chmod 600 called", _chmod_called, true )
eq( "POST: audit action webhook.create", last_audit() and last_audit().action, "webhook.create" )
eq( "POST: audit target is endpoint name (flat table, not dropped)",
    last_audit() and last_audit().target and last_audit().target.nick, "ci" )
r = call( "GET", "/v1/webhooks" )
eq( "POST: endpoint count now 2", #r.data.endpoints, 2 )
local ci
for _, e in ipairs( r.data.endpoints ) do if e.name == "ci" then ci = e end end
truthy( "POST: created endpoint present in GET", ci ~= nil )
eq( "POST: created has_secret", ci and ci.has_secret, true )
eq( "POST: created events preserved", ci and ci.events and ci.events[ 1 ], "build" )
eq( "POST: created path defaulted", ci and ci.path, "/v1/webhook/ci" )

-- 16b. POST duplicate name -> 400
_config = base_config( ); load_plugin( )
r = call( "POST", "/v1/webhooks", { name = "discourse", signature_header = "x", secret = "k" } )
eq( "POST dup name: 400", r.status, 400 )
eq( "POST dup name: E_BAD_INPUT", r.error.code, "E_BAD_INPUT" )

-- 16c. POST invalid name -> 400 (bad chars, and overlong)
r = call( "POST", "/v1/webhooks", { name = "bad name!", signature_header = "x", secret = "k" } )
eq( "POST bad name: 400", r.status, 400 )
r = call( "POST", "/v1/webhooks", { name = string.rep( "a", 65 ), signature_header = "x", secret = "k" } )
eq( "POST overlong name (>64): 400", r.status, 400 )
r = call( "POST", "/v1/webhooks", { name = "numsec", signature_header = "x", secret = 12345 } )
eq( "POST non-string secret: 400", r.status, 400 )

-- 16d. POST no resolvable secret -> 400 (never a silently-inert endpoint)
_overrides = { }
r = call( "POST", "/v1/webhooks", { name = "nosec", signature_header = "x-sig" } )
eq( "POST no secret: 400", r.status, 400 )

-- 17. PUT full-replace, blank secret keeps the current inline secret
_config = base_config( ); load_plugin( )
r = call( "PUT", "/v1/webhooks/{name}",
    { name = "discourse", signature_header = "x-new-sig", min_level = 50 }, { name = "discourse" } )
eq( "PUT: status 200", r.status, 200 )
eq( "PUT keep-secret: inline secret unchanged", _config.endpoints[ 1 ].secret, SECRET )
r = call( "GET", "/v1/webhooks" )
local pu = r.data.endpoints[ 1 ]
eq( "PUT: signature_header updated", pu.signature_header, "x-new-sig" )
eq( "PUT: min_level updated", pu.min_level, 50 )
eq( "PUT: still has_secret", pu.has_secret, true )
eq( "PUT full-replace: events dropped (not in body)", pu.events, nil )

-- 17b. PUT with a secret rotates the inline secret
_config = base_config( ); load_plugin( )
r = call( "PUT", "/v1/webhooks/{name}",
    { name = "discourse", signature_header = "x", secret = "rotated-key" }, { name = "discourse" } )
eq( "PUT rotate: 200", r.status, 200 )
eq( "PUT rotate: new inline secret stored", _config.endpoints[ 1 ].secret, "rotated-key" )

-- 17c. PUT unknown name -> 404
r = call( "PUT", "/v1/webhooks/{name}",
    { name = "ghost", signature_header = "x", secret = "k" }, { name = "ghost" } )
eq( "PUT unknown: 404", r.status, 404 )
eq( "PUT unknown: E_NOT_FOUND", r.error.code, "E_NOT_FOUND" )

-- 18. DELETE -> gone from GET
_config = base_config( ); load_plugin( )
r = call( "DELETE", "/v1/webhooks/{name}", nil, { name = "discourse" } )
eq( "DELETE: 200", r.status, 200 )
eq( "DELETE: audit target name", last_audit() and last_audit().target and last_audit().target.nick, "discourse" )
r = call( "GET", "/v1/webhooks" )
eq( "DELETE: endpoint removed", #r.data.endpoints, 0 )

-- 18b. DELETE unknown -> 404
r = call( "DELETE", "/v1/webhooks/{name}", nil, { name = "ghost" } )
eq( "DELETE unknown: 404", r.status, 404 )

-- 19. PUT /v1/webhooks (global tuning)
_config = base_config( ); load_plugin( )
r = call( "PUT", "/v1/webhooks", { max_per_minute = 42, dedup_max = 999 } )
eq( "settings: 200", r.status, 200 )
eq( "settings: reload_required", r.data.apply_status, "reload_required" )
eq( "settings: audit action", last_audit() and last_audit().action, "webhook.tune" )
truthy( "settings: audit target nil (no endpoint)", last_audit() and last_audit().target == nil )
r = call( "GET", "/v1/webhooks" )
eq( "settings: max_per_minute updated", r.data.tuning.max_per_minute, 42 )
eq( "settings: dedup_max updated", r.data.tuning.dedup_max, 999 )
eq( "settings: field_maxlen untouched", r.data.tuning.field_maxlen, 20 )
r = call( "PUT", "/v1/webhooks", { max_per_minute = 0 } )
eq( "settings: reject <= 0", r.status, 400 )

-- 20. enabled=false: receiver route skipped, but still listed in GET.
--     RED on v0.03 (enabled ignored -> receiver route WAS registered).
_config = base_config( )
_config.endpoints[ 1 ].enabled = false
load_plugin( )
truthy( "enabled=false: receiver route NOT registered", route( "POST", "/v1/webhook/discourse" ) == nil )
r = call( "GET", "/v1/webhooks" )
eq( "enabled=false: still listed in GET", #r.data.endpoints, 1 )
eq( "enabled=false: GET reports enabled=false", r.data.endpoints[ 1 ].enabled, false )

-- 21. GET view is scalar-safe: a hand-edited file with non-scalar junk in
--     events/templates/conditions is FILTERED (the GET data is dkjson-
--     encoded outside the handler guard, so raw passthrough of a function/
--     cycle would crash the hub loop). RED pre-fix (raw passthrough).
_overrides = { }
_config = base_config( )
_config.endpoints[ 1 ].events     = { "ok", function() end, { nested = 1 } }
_config.endpoints[ 1 ].templates  = { good = "hi", bad = function() end }
_config.endpoints[ 1 ].conditions = { { path = "p", equals = "v" }, { path = "q", equals = function() end } }
load_plugin( )
r = call( "GET", "/v1/webhooks" )
local sv = r.data.endpoints[ 1 ]
eq( "scalar-safe: only string events kept", sv.events and #sv.events, 1 )
eq( "scalar-safe: string event value", sv.events and sv.events[ 1 ], "ok" )
eq( "scalar-safe: string template kept", sv.templates and sv.templates.good, "hi" )
truthy( "scalar-safe: function template dropped", sv.templates and sv.templates.bad == nil )
eq( "scalar-safe: only scalar-valued conditions kept", sv.conditions and #sv.conditions, 1 )
eq( "scalar-safe: kept condition path", sv.conditions and sv.conditions[ 1 ].path, "p" )

-- 22. path guard: an INVALID endpoint (norm=nil because it has no name) with
--     a function `path` must NOT leak the function into the wire view - the
--     raw-path fallback is scalar-guarded (else dkjson.encode crashes the loop).
_config = { endpoints = { { signature_header = "h", path = function() end } } }
load_plugin( )
r = call( "GET", "/v1/webhooks" )
local iv = r.data.endpoints[ 1 ]
truthy( "path guard: view.path is a string, not the raw function", type( iv.path ) == "string" )
eq( "path guard: invalid endpoint flagged valid=false", iv.valid, false )

----------------------------------------------------------------------
if failures > 0 then
    io.write( string.format( "\n%d passed, %d failed\n", checks - failures, failures ) )
    os.exit( 1 )
end
io.write( string.format( "\n%d passed, 0 failed\n", checks ) )
