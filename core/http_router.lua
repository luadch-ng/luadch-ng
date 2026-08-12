--[[

    http_router.lua - the HTTP API router (Phase 1b of #82).

    Owns the route table, auth, scope check, idempotency-key cache,
    envelope formatting, JSON marshalling (via dkjson), schema mini-
    validation, audit-log emission, and first-boot token bootstrap.

    core/http.lua is the transport-level interface to server.lua's
    listener wiring; this module is the API logic on top of that.
    The two are intentionally separate so transport hardening (the
    framer caps, the response builder) stays small and testable
    while the route surface grows over phase 1c + later.

    Authoritative design: docs/HTTP_API.md. This file is the
    implementation of §3-§9 of that spec.

    Plugin entrypoint: hub.http_register( method, path, scope,
    handler, meta ) - wired in core/hub.lua. The router itself
    exposes register() / unregister_all() / dispatch() for the
    transport layer and core/hub.lua to call.

    Out of scope for phase 1b (lands in phase 1c):
      - token-bucket + failed-auth + prefix rate-limiting (§4.8, §6.3)
      - idempotency-key cache eviction policy (the data structure is
        here; size cap + eviction lands with the cap cfg key in 1c)
      - adclib.constant_time_eq C binding (pure-Lua fallback ships
        here; C version lands in 1c)
      - the bulk of the core endpoints (/v1/version, /v1/stats,
        /v1/users, /v1/log/api) - 1b registers only /health (special-
        case, unauthenticated) and /v1/endpoints (proves the
        registry + scope filtering work end-to-end). 1c adds the
        rest.

]]--

----------------------------------// DECLARATION //--

local use = use

local pairs = use "pairs"
local ipairs = use "ipairs"
local tostring = use "tostring"
local tonumber = use "tonumber"
local type = use "type"
local xpcall = use "xpcall"
local error = use "error"
local getmetatable = use "getmetatable"
local debug = use "debug"

local string = use "string"
local table = use "table"
local os = use "os"
local io = use "io"
local math = use "math"

local string_sub = string.sub
local string_len = string.len
local string_find = string.find
local string_match = string.match
local string_gmatch = string.gmatch
local string_lower = string.lower
local string_byte = string.byte
local table_concat = table.concat
local table_insert = table.insert
local table_remove = table.remove
local table_sort = table.sort
local math_floor = math.floor

local cfg = use "cfg"
local out = use "out"

local cfg_get = cfg.get
local out_error = out.error
local out_api_audit = out.api_audit

-- socket.gettime for idempotency-cache TTL (monotonic-enough; same
-- source as ratelimit.lua's bucket timestamps).
local socket = use "socket"
local socket_gettime = socket.gettime

-- forward declarations
local register
local unregister_all
local dispatch
local list_endpoints
local resolve_token
local constant_time_eq
local json_encode
local json_decode
local envelope_success
local envelope_error
local validate_schema
local audit_log
local match_path
local generate_request_id
local bootstrap_first_token
local register_core_endpoints
local parse_query
local status_reason
local idem_lookup
local idem_store
local idem_clear

-- module state
local _routes      = { }    -- _routes[method][path_pattern] = { handler, scope, plugin, meta, path_template }
local _routes_flat = { }    -- flat list for /v1/endpoints; populated alongside _routes
local _initialized = false

-- Idempotency-key cache (#82 §6.2). Per-token map keyed by the
-- non-secret token label + the client-supplied X-Idempotency-Key.
-- Bounded by both 5-min TTL AND `http_api_idempotency_max_entries`
-- (FIFO eviction, oldest insert evicted first; we don't track LRU
-- because the cap+TTL combo bounds memory regardless of order).
-- Cleared on +reload because the handler closures producing the
-- cached responses may no longer exist.
--
-- The cache uses a monotonically-increasing `ord` field per entry
-- so the FIFO order array can carry stale slots safely: replace-
-- in-place bumps the entry's ord and pushes a new {k, ord} to the
-- order array; eviction pops the head and only deletes the map
-- entry if its current ord matches the popped slot's ord (i.e. it
-- has not been replaced since). Stale order slots are silently
-- skipped. This keeps replace-in-place correct without an O(n)
-- order-list shift.
local _IDEM_TTL = 300    -- seconds; spec §6.2 fixed at 5 minutes
local _idem_map = { }    -- map: key -> { status, body, headers, ts, ord }
local _idem_order = { }  -- FIFO array of {k, ord} pairs, oldest first
local _idem_ord_next = 1 -- next ordinal to hand out
local _idem_size = 0     -- live entry count (matches #{k for k,_ in pairs(_idem_map)})

----------------------------------// DEFINITION //--

-- Constant-time string equality. Lua's `==` short-circuits at the
-- first mismatching byte which leaks length + prefix-match timing
-- for token comparisons. Phase 1c wires the C implementation
-- (adclib.constant_time_eq) which runs at C speed; if adclib is
-- absent (e.g. a stripped build), fall through to the pure-Lua
-- XOR-accumulate equivalent. Both implementations share the same
-- contract: returns true iff #a == #b AND every byte matches.
-- The length itself is not secret in our use case (the operator
-- picked the token), so we bail out fast on length mismatch.
local _adclib = use "adclib"
local _adclib_cte = _adclib and _adclib.constant_time_eq
constant_time_eq = function( a, b )
    if type( a ) ~= "string" or type( b ) ~= "string" then
        return false
    end
    if _adclib_cte then
        return _adclib_cte( a, b )
    end
    -- Pure-Lua fallback (never used when adclib loaded). Algorithm
    -- must match the C version above byte-for-byte.
    local len_a = string_len( a )
    if len_a ~= string_len( b ) then
        return false
    end
    local diff = 0
    for i = 1, len_a do
        diff = diff | ( string_byte( a, i ) ~ string_byte( b, i ) )
    end
    return diff == 0
end

-- JSON encode + decode via the bundled dkjson 2.10. The `use` is
-- lazy because dkjson is in init.lua's _optional list (the HTTP
-- API itself is opt-in); failure to load is surfaced at first call
-- as a 500 with a logged error. The HTTP listener won't bind in
-- the first place if dkjson didn't load - this is purely defence
-- in depth.
json_encode = function( v )
    local dkjson = use "dkjson"
    if not dkjson then
        error( "http_router: dkjson did not load; cannot encode JSON" )
    end
    return dkjson.encode( v )
end
json_decode = function( s )
    local dkjson = use "dkjson"
    if not dkjson then
        error( "http_router: dkjson did not load; cannot decode JSON" )
    end
    -- dkjson returns (value, position, errmsg) on failure (value=nil,
    -- pos<0). Wrap that into a single (value, errmsg) shape.
    local v, _, err = dkjson.decode( s, 1, nil )
    if v == nil then
        return nil, err or "invalid json"
    end
    return v
end

envelope_success = function( data )
    return json_encode( { ok = true, data = data } )
end

envelope_error = function( code, message )
    return json_encode( {
        ok    = false,
        error = { code = code, message = message },
    } )
end

-- Schema mini-validator (docs/HTTP_API.md §5.5). Top-level only;
-- nested validation is the handler's job per the spec contract.
-- Returns (true, nil) on pass or (false, "field 'x': ...") on fail.
validate_schema = function( schema, body )
    if not schema then return true end
    if type( body ) ~= "table" then
        return false, "body must be a JSON object"
    end
    for field, spec in pairs( schema ) do
        local v = body[ field ]
        local present = ( v ~= nil )
        if spec.required and not present then
            return false, "field '" .. field .. "': required"
        end
        if present then
            if spec.type then
                local actual = type( v )
                local expected = spec.type
                local ok
                if expected == "integer" then
                    ok = ( actual == "number" and v % 1 == 0 )
                elseif expected == "array" or expected == "object" then
                    -- both are Lua tables; distinguishing them
                    -- precisely needs a key-scan (an empty {} is
                    -- ambiguous and accepted as either). The spec
                    -- says top-level only, so a coarse check is OK.
                    ok = ( actual == "table" )
                else
                    ok = ( actual == expected )
                end
                if not ok then
                    return false, "field '" .. field .. "': expected " .. expected
                end
            end
            if spec.enum then
                local match = false
                for _, allowed in ipairs( spec.enum ) do
                    if v == allowed then match = true break end
                end
                if not match then
                    return false, "field '" .. field .. "': not in enum"
                end
            end
            -- min / max apply only to numeric values. Pre-#275 the
            -- check was guarded by `type(v) == "number"` which silently
            -- passed any non-numeric value the schema put through min/
            -- max bounds - a schema-author footgun. Now: if min/max is
            -- set on a field whose runtime value is non-numeric, fail
            -- loudly so the misconfiguration surfaces in CI / first
            -- smoke run instead of silently bypassing the bound.
            if spec.min or spec.max then
                if type( v ) ~= "number" then
                    return false, "field '" .. field .. "': min/max only valid for numeric values"
                end
                if spec.min and v < spec.min then
                    return false, "field '" .. field .. "': below min"
                end
                if spec.max and v > spec.max then
                    return false, "field '" .. field .. "': above max"
                end
            end
            if spec.min_length and type( v ) == "string" and string_len( v ) < spec.min_length then
                return false, "field '" .. field .. "': too short"
            end
            if spec.max_length and type( v ) == "string" and string_len( v ) > spec.max_length then
                return false, "field '" .. field .. "': too long"
            end
            if spec.pattern and type( v ) == "string"
               and not string_match( v, spec.pattern ) then
                return false, "field '" .. field .. "': pattern mismatch"
            end
        end
    end
    return true
end

-- Path-template match. Converts e.g. "/v1/users/{sid}" into the Lua
-- pattern "^/v1/users/([^/]+)$" and captures path-var values. Cached
-- per route at register time so dispatch is O(routes per method).
local function compile_path_pattern( template )
    local vars = { }
    local pattern = "^" .. ( template:gsub( "%-", "%%-" ):gsub( "{([^}]+)}", function( name )
        table_insert( vars, name )
        return "([^/]+)"
    end ) ) .. "$"
    return pattern, vars
end

match_path = function( route, path )
    local matches = { string_match( path, route.pattern ) }
    if matches[ 1 ] == nil then return nil end
    local path_vars = { }
    for i, name in ipairs( route.vars ) do
        path_vars[ name ] = matches[ i ]
    end
    return path_vars
end

register = function( method, path, scope, handler, meta )
    if type( method ) ~= "string" or string_match( method, "[a-z]" ) then
        error( "http_router.register: method must be an uppercase string" )
    end
    if type( path ) ~= "string" or string_sub( path, 1, 1 ) ~= "/" then
        error( "http_router.register: path must start with /" )
    end
    if scope ~= "read" and scope ~= "admin" and scope ~= "none" then
        error( "http_router.register: scope must be 'read', 'admin' or 'none'" )
    end
    if type( handler ) ~= "function" then
        error( "http_router.register: handler must be a function" )
    end
    local pattern, vars = compile_path_pattern( path )
    _routes[ method ] = _routes[ method ] or { }
    if _routes[ method ][ path ] then
        error( "http_router.register: duplicate route '" .. method .. " " .. path .. "'" )
    end
    local route = {
        handler  = handler,
        scope    = scope,
        plugin   = ( meta and meta.plugin ) or "core",
        meta     = meta or { },
        template = path,
        pattern  = pattern,
        vars     = vars,
    }
    _routes[ method ][ path ] = route
    table_insert( _routes_flat, { method = method, route = route } )
end

unregister_all = function( )
    _routes      = { }
    _routes_flat = { }
    _initialized = false
    -- §6.2: idempotency cache MUST be cleared on +reload (handler
    -- closures the cached responses came from may no longer exist
    -- in the new route table).
    idem_clear( )
end

-- Idempotency cache: lookup. Returns (status, body, headers) on
-- cache hit or nil on miss. Lazily drops a TTL-expired entry it
-- finds during the lookup so the cache size remains bounded even
-- if no write happens for a long time. (The stale order slot is
-- skipped by the ord-mismatch check at eviction time.)
--
-- Key includes method+path so a client that reuses the same
-- Idempotency-Key across two different write endpoints (e.g. a
-- shared request-correlation id) does NOT get the first action's
-- cached reply replayed for the second. Spec §6.2.
idem_lookup = function( bucket_id, method, path, idem_key )
    if not bucket_id or not idem_key or idem_key == "" then return nil end
    local k = bucket_id .. "\0" .. method .. " " .. path .. "\0" .. idem_key
    local entry = _idem_map[ k ]
    if not entry then return nil end
    if ( socket_gettime( ) - entry.ts ) >= _IDEM_TTL then
        _idem_map[ k ] = nil
        _idem_size = _idem_size - 1
        return nil
    end
    return entry.status, entry.body, entry.headers
end

-- Idempotency cache: store. Adds the (status, body, headers) tuple
-- under (bucket_id, method, path, idem_key). FIFO-evicts oldest
-- INSERTION order entry (by ordinal) to keep size <= cap. Stores
-- replace in place but still push a fresh order slot; the prior
-- slot becomes stale and is skipped on eviction.
idem_store = function( bucket_id, method, path, idem_key, status, body, headers )
    if not bucket_id or not idem_key or idem_key == "" then return end
    local k = bucket_id .. "\0" .. method .. " " .. path .. "\0" .. idem_key
    local now = socket_gettime( )
    local ord = _idem_ord_next
    _idem_ord_next = _idem_ord_next + 1
    if _idem_map[ k ] then
        -- Replace in place: bump ord so an in-flight eviction
        -- looking for the OLD ord skips this slot. The old
        -- _idem_order slot {k, old_ord} is now stale and gets
        -- discarded harmlessly on its turn.
        _idem_map[ k ] = { status = status, body = body, headers = headers, ts = now, ord = ord }
        table_insert( _idem_order, { k = k, ord = ord } )
        return
    end
    -- Fresh insert: track size, evict if at cap.
    local cap = cfg_get "http_api_idempotency_max_entries" or 1024
    while _idem_size >= cap do
        local head = _idem_order[ 1 ]
        if not head then break end    -- defence: order empty but size says full -> bail
        table_remove( _idem_order, 1 )
        local m = _idem_map[ head.k ]
        if m and m.ord == head.ord then
            -- live entry; delete
            _idem_map[ head.k ] = nil
            _idem_size = _idem_size - 1
        end
        -- ord mismatch / map miss = stale slot, just drop it and keep looping
    end
    _idem_map[ k ] = { status = status, body = body, headers = headers, ts = now, ord = ord }
    _idem_size = _idem_size + 1
    table_insert( _idem_order, { k = k, ord = ord } )
end

idem_clear = function( )
    _idem_map = { }
    _idem_order = { }
    _idem_ord_next = 1
    _idem_size = 0
end

-- /v1/endpoints discovery: scope-filtered live route registry.
-- The endpoint registers itself - the registry is self-describing.
list_endpoints = function( req )
    local out_list = { }
    local can_see_admin = ( req.token_scope == "admin" )
    for _, entry in ipairs( _routes_flat ) do
        local r = entry.route
        -- scope="none" routes (e.g. /health) are public and listed
        -- to every token holder. read-scoped routes are listed to
        -- everyone with auth. admin-scoped routes only to admin
        -- tokens. (/v1/endpoints requires read scope to call so
        -- we never hit this code for an anonymous caller.)
        if r.scope == "none" or r.scope == "read" or can_see_admin then
            table_insert( out_list, {
                method      = entry.method,
                path        = r.template,
                scope       = r.scope,
                plugin      = r.plugin,
                description = r.meta.description,
                request_schema  = r.meta.request_schema,
                response_schema = r.meta.response_schema,
            } )
        end
    end
    return { status = 200, data = { endpoints = out_list } }
end

-- Resolve `Authorization: Bearer <token>` against cfg.http_api_tokens.
-- Returns (label, scope, bucket_id) on success or (nil, error_code)
-- on failure.
--
-- `label` is the loggable, intentionally-obfuscated identifier
-- (comment + first4...last4). It goes to the audit log and to
-- operator-visible error messages.
--
-- `bucket_id` is an INTERNAL stable identifier for rate-limit and
-- idempotency-cache keying. It MUST be unique per cfg-token even
-- when two tokens share a comment + first4 + last4 (e.g. an
-- operator rotated a 52-char base32 token and kept the comment).
-- The full cfg_token would collide-proof but lives only in
-- ratelimit's _buckets table (never logged); we use first8 + last8
-- which is collision-proof for any realistic deployment (32^16 ≈
-- 1.2e24 possibilities) AND tolerates very short tokens by
-- gracefully falling back to the full token below 16 chars.
resolve_token = function( authz_header )
    if type( authz_header ) ~= "string" then
        return nil, "missing"
    end
    local token = string_match( authz_header, "^Bearer (.+)$" )
    if not token then return nil, "malformed" end
    local tokens = cfg_get "http_api_tokens" or { }
    for cfg_token, spec in pairs( tokens ) do
        if constant_time_eq( token, cfg_token ) then
            local first4 = string_sub( cfg_token, 1, 4 )
            local last4  = string_sub( cfg_token, -4 )
            local comment = ( spec.comment and spec.comment ~= "" )
                and ( spec.comment .. " " ) or ""
            local label = comment .. "(" .. first4 .. "..." .. last4 .. ")"
            local bucket_id
            if string_len( cfg_token ) >= 16 then
                bucket_id = string_sub( cfg_token, 1, 8 ) .. string_sub( cfg_token, -8 )
            else
                bucket_id = cfg_token    -- tiny token; uniqueness == identity
            end
            return label, spec.scope, bucket_id
        end
    end
    return nil, "unknown"
end

-- Audit-log line, one per non-GET request (or per any request if
-- http_api_log_reads = true). Body field is JSON-serialised, max
-- 512 bytes, control bytes replaced with `?`. Log-injection defence
-- only - NOT a secret-redaction primitive (a 256-byte token + a
-- 30-byte password both fit well under the 512 cap and land verbatim
-- on disk). Per-route redaction is enforced by audit_log() via the
-- `audit_redact_body` route-meta flag.
local function logsafe_body( raw_body )
    if not raw_body or raw_body == "" then return "-" end
    local s = raw_body
    if string_len( s ) > 512 then
        s = string_sub( s, 1, 509 ) .. "..."
    end
    return ( s:gsub( "%c", "?" ) )
end

-- Per-route audit-body redaction (§6.8). Routes that ingest secrets
-- (password rotation, reguser POST) declare `audit_redact_body =
-- true` in their meta; dispatch sets req._audit_redact_body after
-- route resolution. Unauthenticated / unmatched paths set
-- req._audit_skip_body so attacker-chosen bytes do not land in the
-- audit file via 401 / 404 / 405 / 415 probes.
audit_log = function( req, status )
    if not cfg_get "log_api_audit" then return end
    if req.method == "GET" and not cfg_get "http_api_log_reads" then return end
    local body_field
    if req._audit_skip_body then
        body_field = "[skipped]"
    elseif req._audit_redact_body then
        body_field = "[redacted]"
    else
        body_field = logsafe_body( req.raw_body )
    end
    out_api_audit(
        req.method, " ", req.path, " ", tostring( status ),
        " token=", ( req.token_label or "-" ),
        " src=", ( req.source_ip or "-" ),
        " idem=", ( req.idempotency_key or "-" ),
        " req_id=", ( req.request_id or "-" ),
        " body=", body_field
    )
end

generate_request_id = function( )
    -- UUIDv4-SHAPED opaque hex (8-4-4-4-12 with the version nibble
    -- pinned to 4). NOT a real UUIDv4 - the variant nibble is
    -- unconstrained and math.random is not CSPRNG. Purely for log
    -- correlation; clients can supply their own X-Request-ID if
    -- they need stronger uniqueness or RFC4122-conformant IDs.
    local random = math.random
    local hex = "0123456789abcdef"
    local function block( n )
        local out_b = { }
        for i = 1, n do
            local idx = random( 1, 16 )
            out_b[ i ] = string_sub( hex, idx, idx )
        end
        return table_concat( out_b )
    end
    return block( 8 ) .. "-" .. block( 4 ) .. "-4" .. block( 3 )
        .. "-" .. block( 4 ) .. "-" .. block( 12 )
end

-- The X-Confirm-required endpoints (docs/HTTP_API.md §4.6). Lookup
-- by "METHOD path-template" - cheap and explicit.
local _xconfirm_required = {
    [ "POST /v1/reload" ]   = true,
    [ "POST /v1/restart" ]  = true,
    [ "POST /v1/shutdown" ] = true,
    [ "DELETE /v1/registered/{nick}" ] = true,
    [ "DELETE /v1/usercleaner/expired" ] = true,
    [ "DELETE /v1/usercleaner/ghosts" ]  = true,
    [ "DELETE /v1/usercleaner/orphan-comments" ] = true,
}

parse_query = function( s )
    local q = { }
    if not s or s == "" then return q end
    for pair in string_gmatch( s, "([^&]+)" ) do
        local k, v = string_match( pair, "^([^=]+)=(.*)$" )
        if k then
            q[ k ] = v
        else
            q[ pair ] = ""
        end
    end
    return q
end

status_reason = function( code )
    -- minimal local table, full table is in core/http.lua. Used
    -- only for framer-reject responses where we emit text/plain.
    local m = {
        [400] = "Bad Request",
        [404] = "Not Found",
        [413] = "Payload Too Large",
        [414] = "URI Too Long",
        [431] = "Request Header Fields Too Large",
        [505] = "HTTP Version Not Supported",
    }
    return m[ code ]
end

-- Main dispatch path. Called by core/http.lua's incoming with the
-- framer's parsed unit; the handler returns a Lua table that we
-- envelope, serialize and hand back to the transport layer.
--
-- Returns (status, response_body_string, headers_table) so
-- core/http.lua can build the wire response.
dispatch = function( framer_unit, source_ip )
    -- Reject units from the framer (4xx / 5xx surfaced as plain
    -- text + the canned status reason; the API envelope is for
    -- routed-through-the-API responses, not transport-level
    -- rejections that never reached an auth handler).
    if framer_unit.reject then
        local code = framer_unit.reject
        return code, code .. " " .. ( status_reason( code ) or "error" ) .. "\n",
            { [ "Content-Type" ] = "text/plain; charset=utf-8" }
    end

    local method = framer_unit.method
    local target = framer_unit.target
    -- split off query string
    local path, query_str
    local q = string_find( target, "?", 1, true )
    if q then
        path = string_sub( target, 1, q - 1 )
        query_str = string_sub( target, q + 1 )
    else
        path = target
    end

    -- Build the req struct that handlers see.
    local req = {
        method     = method,
        path       = path,
        target     = target,
        query      = parse_query( query_str ),
        headers    = framer_unit.headers,
        raw_body   = framer_unit.body,
        body       = nil,    -- parsed JSON, filled after auth/CL check
        source_ip  = source_ip,
        request_id = framer_unit.headers[ "x-request-id" ]
                     or generate_request_id( ),
        idempotency_key = framer_unit.headers[ "x-idempotency-key" ],
        confirm    = ( framer_unit.headers[ "x-confirm" ] == "yes" ),
    }

    -- Headers we always echo regardless of outcome.
    local resp_headers = { [ "X-Request-ID" ] = req.request_id }

    -- Lookup the route FIRST (we need to know if scope=="none" -
    -- the unauthenticated routes like /health - to decide whether
    -- to enforce auth). Supports HEAD -> GET fallback per §6.6.
    local lookup_method = method == "HEAD" and "GET" or method
    local methods_for_path = { }
    local matched_route, matched_vars
    -- A path is "public" if it carries any scope="none" route (e.g.
    -- /health, the webhook receiver). Anonymous OPTIONS introspection
    -- is allowed on such a path; on an auth-gated path it is not (it
    -- would leak path existence - see the OPTIONS block below). This is
    -- keyed on the concrete request path, and every scope="none" route
    -- today is an EXACT template (no wildcard), so a public route can
    -- never over-match an auth-gated concrete path. If a wildcard/
    -- templated scope="none" route is ever added, revisit: it could
    -- mark an auth-gated path public and expose its methods to anon.
    local path_has_public_route = false
    for m, paths in pairs( _routes ) do
        for _, r in pairs( paths ) do
            local vars = match_path( r, path )
            if vars then
                table_insert( methods_for_path, m )
                if r.scope == "none" then path_has_public_route = true end
                if m == lookup_method then
                    matched_route = r
                    matched_vars  = vars
                end
            end
        end
    end

    -- Auth resolution (label = nil means anonymous / bad token).
    -- Resolved BEFORE the OPTIONS introspection below so that
    -- introspection on an auth-gated path cannot serve as an
    -- unauthenticated path-existence + method oracle.
    local authz_header = framer_unit.headers[ "authorization" ]
    local label, scope_or_err, bucket_id = resolve_token( authz_header )

    -- Per-prefix failed-auth bucket (§4.8 second line of defence).
    -- Only consumed when a Bearer token IS present but does NOT
    -- match: that is the brute-force walk-the-token-space surface.
    -- An absent header is just an anonymous probe (cheap) and a
    -- malformed header is filtered into the same anonymous bucket.
    -- See note in §4.8 of the spec: the per-connection counter is
    -- moot under our `Connection: close` transport (one HTTP
    -- request per TCP conn), so the prefix bucket carries the
    -- abuse defence on its own.
    if label == nil and scope_or_err == "unknown" then
        local ratelimit = use "ratelimit"
        local bearer = authz_header and string_match( authz_header, "^Bearer (.+)$" )
        local prefix = bearer and string_sub( bearer, 1, 4 ) or ""
        if not ratelimit.http_authfail_prefix( prefix ) then
            -- Prefix bucket exhausted. Treat the same as a normal
            -- 401 from the caller's perspective (no leak about
            -- whether the prefix is hot) but emit a different
            -- audit entry so operators can see brute-force noise.
            -- Surface the prefix in the audit token field (not the
            -- full token bytes - the prefix is already a §4.8
            -- length-leak-limited identifier) so brute-force
            -- attribution shows up in api_audit.log rather than as
            -- token=-. Defensive %c strip on the prefix bytes - the
            -- framer rejects control bytes in header values but
            -- belt-and-suspenders against any future framer relax.
            req.token_label = "prefix(" .. ( prefix:gsub( "%c", "?" ) ) .. ")"
            req._audit_skip_body = true
            audit_log( req, 429 )
            resp_headers[ "Retry-After" ] = "60"
            return 429, envelope_error( "E_RATE_LIMITED",
                "too many failed authentications; back off" ), resp_headers
        end
    end

    -- OPTIONS auto-introspection per §6.6: returns 204 + Allow header
    -- listing the registered methods. Gated on auth for an auth-gated
    -- path: the normal 405/404 outcomes below only reveal path
    -- existence to an AUTHENTICATED caller, so serving 204+Allow to an
    -- anonymous caller here would be exactly the path-existence +
    -- method oracle the rest of the router withholds. A path carrying a
    -- scope="none" route (/health, the webhook receiver) is public, so
    -- anonymous OPTIONS on it stays allowed. Skipped if the path is not
    -- registered at all (falls through to the 401/404 path below).
    if method == "OPTIONS" and #methods_for_path > 0
       and ( label or path_has_public_route ) then
        -- HEAD is implicit for any GET route per §6.6; surface it.
        local has_get = false
        for _, m in ipairs( methods_for_path ) do
            if m == "GET" then has_get = true break end
        end
        if has_get then
            local has_head = false
            for _, m in ipairs( methods_for_path ) do
                if m == "HEAD" then has_head = true break end
            end
            if not has_head then
                table_insert( methods_for_path, "HEAD" )
            end
        end
        table_insert( methods_for_path, "OPTIONS" )
        resp_headers[ "Allow" ] = table_concat( methods_for_path, ", " )
        return 204, "", resp_headers
    end

    -- Method/path resolution outcomes - all require auth except
    -- the OPTIONS introspection above. Path-existence is not
    -- leaked to anonymous callers (admin API posture; loopback-
    -- only listener; reverse proxy handles non-loopback discovery
    -- via its own auth surface).
    if not matched_route then
        -- No route resolution = no audit_redact_body policy known;
        -- default to skipping the body so attacker-chosen bytes
        -- from 401/404/405 probes do not land in api_audit.log.
        req._audit_skip_body = true
        if not label then
            audit_log( req, 401 )
            return 401, envelope_error( "E_UNAUTHENTICATED", "missing or invalid bearer token" ), resp_headers
        end
        req.token_label = label
        req.token_scope = scope_or_err

        if #methods_for_path > 0 then
            -- Path exists for some other method - 405 + Allow header.
            local allowed = table_concat( methods_for_path, ", " )
            resp_headers[ "Allow" ] = allowed
            audit_log( req, 405 )
            return 405, envelope_error( "E_METHOD_NOT_ALLOWED",
                "method " .. method .. " not allowed; see Allow header" ), resp_headers
        end
        audit_log( req, 404 )
        return 404, envelope_error( "E_NOT_FOUND", "no such endpoint" ), resp_headers
    end

    req.path_vars = matched_vars
    -- §6.8: per-route audit-body redaction policy. Looked up once
    -- here so every audit_log() call from this dispatch sees a
    -- consistent flag (some happen post-handler with errors).
    req._audit_redact_body = matched_route.meta.audit_redact_body and true or false

    -- Auth enforcement: scope=="none" routes (e.g. /health) skip
    -- auth entirely. Everything else requires a valid token.
    if matched_route.scope ~= "none" then
        if not label then
            req._audit_skip_body = true
            audit_log( req, 401 )
            return 401, envelope_error( "E_UNAUTHENTICATED", "missing or invalid bearer token" ), resp_headers
        end
        req.token_label = label
        req.token_scope = scope_or_err
        req.token_bucket_id = bucket_id

        -- Scope check.
        if matched_route.scope == "admin" and req.token_scope ~= "admin" then
            audit_log( req, 403 )
            return 403, envelope_error( "E_FORBIDDEN", "endpoint requires admin scope" ), resp_headers
        end

        -- Per-token-bucket rate-limit (§6.3). X-Confirm endpoints
        -- exempt (§6.3 carve-out: operator recovery actions must
        -- always succeed). Checked AFTER scope (a 403 should not
        -- consume bucket budget either - that is the same operator-
        -- mistake-recovery argument).
        local xconfirm_key = method .. " " .. matched_route.template
        if not _xconfirm_required[ xconfirm_key ] then
            local ratelimit = use "ratelimit"
            if not ratelimit.http_token( bucket_id, req.token_scope ) then
                local secs = ratelimit.http_token_retry_after( bucket_id, req.token_scope )
                resp_headers[ "Retry-After" ] = tostring( secs )
                audit_log( req, 429 )
                return 429, envelope_error( "E_RATE_LIMITED",
                    "per-token rate limit exceeded; see Retry-After" ), resp_headers
            end
        end
    end

    -- X-Confirm for destructive ops (§4.6).
    if _xconfirm_required[ method .. " " .. matched_route.template ] and not req.confirm then
        audit_log( req, 400 )
        return 400, envelope_error( "E_CONFIRMATION_REQUIRED",
            "endpoint requires header 'X-Confirm: yes'" ), resp_headers
    end

    -- Idempotency cache lookup (§6.2). WRITE methods only; GETs
    -- are not cached because they have no side-effects worth
    -- deduplicating. Cache hit returns the prior (status, body,
    -- headers) immediately, handler is NOT invoked, audit log is
    -- NOT re-emitted. We DO still echo the current X-Request-ID so
    -- the client sees this turn's correlation id, not the cached one.
    local _is_write = ( method ~= "GET" and method ~= "HEAD" and method ~= "OPTIONS" )
    if _is_write and req.idempotency_key and req.token_bucket_id then
        local cstatus, cbody, cheaders = idem_lookup(
            req.token_bucket_id, method, matched_route.template, req.idempotency_key )
        if cstatus then
            -- Replay cached response. cheaders is the original
            -- handler-time set; overlay this turn's X-Request-ID on
            -- top so the wire reply carries the current request id.
            local replay = { }
            if cheaders then
                for k, v in pairs( cheaders ) do replay[ k ] = v end
            end
            replay[ "X-Request-ID" ] = req.request_id
            return cstatus, cbody, replay
        end
    end

    -- Body parse (only for methods that accept a body and only when
    -- CL > 0; the framer already enforced Content-Type-irrelevant
    -- transport rules).
    if req.raw_body and req.raw_body ~= "" then
        local ct = framer_unit.headers[ "content-type" ] or ""
        -- minimum check: starts with application/json. Charset
        -- parameters and case-insensitive media types are out of
        -- scope for phase 1b.
        local ct_lower = string_lower( ct )
        if not string_find( ct_lower, "^application/json", 1, false ) then
            audit_log( req, 415 )
            return 415, envelope_error( "E_UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json" ), resp_headers
        end
        local parsed, err = json_decode( req.raw_body )
        if not parsed then
            audit_log( req, 400 )
            return 400, envelope_error( "E_BAD_JSON", err or "invalid json" ), resp_headers
        end
        if type( parsed ) ~= "table" then
            audit_log( req, 400 )
            return 400, envelope_error( "E_BAD_JSON", "body must be a JSON object" ), resp_headers
        end
        -- Top-level MUST be a JSON object, never an array (§6.1). dkjson
        -- tags a decoded array with a metatable {__jsontype="array"} and
        -- an object with {__jsontype="object"}. Without this check a bare
        -- array passes the type()=="table" test above and reaches the
        -- handler as a body whose every named-field lookup silently reads
        -- nil - so a client sending `[...]` gets misleading validation
        -- errors instead of "not an object". Reject it explicitly.
        local pmeta = getmetatable( parsed )
        if pmeta and pmeta.__jsontype == "array" then
            audit_log( req, 400 )
            return 400, envelope_error( "E_BAD_JSON", "body must be a JSON object, not a JSON array" ), resp_headers
        end
        req.body = parsed

        -- Schema validation, if the route declared one.
        if matched_route.meta.request_schema then
            local ok, schema_err = validate_schema( matched_route.meta.request_schema, parsed )
            if not ok then
                audit_log( req, 400 )
                return 400, envelope_error( "E_BAD_INPUT", schema_err ), resp_headers
            end
        end
    end

    -- Dispatch. xpcall (not pcall) so an uncaught handler error carries
    -- its Lua traceback into error.log - a bare pcall discards the stack,
    -- leaving only the message with no line to look at. `debug` is a core
    -- import (never handed to the plugin sandbox); the message handler
    -- runs at the point of the error, so the traceback is meaningful.
    local ok, result_or_err = xpcall( matched_route.handler, function( err )
        return debug.traceback( tostring( err ), 2 )
    end, req )
    if not ok then
        out_error( "http_router.dispatch: handler raised on ",
            method, " ", path, ": ", tostring( result_or_err ) )
        audit_log( req, 500 )
        return 500, envelope_error( "E_INTERNAL", "handler error" ), resp_headers
    end
    if type( result_or_err ) ~= "table" then
        out_error( "http_router.dispatch: handler for ",
            method, " ", path, " returned non-table: ", tostring( result_or_err ) )
        audit_log( req, 500 )
        return 500, envelope_error( "E_INTERNAL", "handler contract violated" ), resp_headers
    end

    -- #263 PR-B: a handler may return a deferred response when it
    -- wants to long-poll. Status sentinel "deferred" + a `defer`
    -- function gets forwarded verbatim through to http_incoming;
    -- the function is invoked with the connection handler so the
    -- handler can register itself as a waiter and write the
    -- response later (on timer expiry OR event arrival).
    if result_or_err.status == "deferred" and type( result_or_err.defer ) == "function" then
        audit_log( req, 202 )    -- "Accepted" audit marker; real status will be 200 on resolve
        return "deferred", result_or_err.defer, resp_headers
    end

    local status = result_or_err.status or 200
    local body
    if result_or_err.raw_body ~= nil then
        -- Escape hatch for non-JSON responses (e.g. /health returns
        -- text/plain "ok"). Handler controls the body bytes + the
        -- Content-Type via `content_type`; the envelope is skipped.
        body = result_or_err.raw_body
        if result_or_err.content_type then
            resp_headers[ "Content-Type" ] = result_or_err.content_type
        end
    elseif result_or_err.error then
        body = envelope_error( result_or_err.error.code or "E_INTERNAL",
                               result_or_err.error.message or "error" )
    else
        body = envelope_success( result_or_err.data )
    end

    -- HEAD: handler returned a unit; the router measured the body
    -- length for Content-Length but discards the bytes themselves
    -- (§6.6 contract).
    if method == "HEAD" then
        resp_headers[ "Content-Length-Override" ] = tostring( string_len( body ) )
        body = ""
    end

    -- Idempotency cache store (§6.2). Write methods only; stash the
    -- (status, body, headers) tuple under (label, idem_key). A
    -- retry within the 5-min TTL replays this without re-invoking
    -- the handler. We deliberately store the FULL handler response
    -- (incl. status) so error responses are also cached - a retry
    -- of a request that failed validation deterministically gets
    -- the same 400, not a re-run that might race differently.
    if _is_write and req.idempotency_key and req.token_bucket_id then
        idem_store( req.token_bucket_id, req.method, matched_route.template,
                    req.idempotency_key, status, body, resp_headers )
    end

    audit_log( req, status )
    return status, body, resp_headers
end


-- First-boot token bootstrap (§4.7). Called by core/hub.lua BEFORE
-- binding the http_port. Returns (true) if cfg.tbl already has a
-- token (listener should bind); returns (nil, err) if no tokens
-- are configured (listener will NOT bind). The "no tokens" case
-- is not a failure - it is the documented opt-in gate: a sample
-- token is written to cfg/api_token.first as a convenience for
-- the operator to copy into cfg.tbl, but is NOT activated
-- in-memory. The operator must explicitly populate
-- http_api_tokens in cfg.tbl + restart (or +reload after the
-- listener was bound on a previous boot) for the API to come up.
--
-- Rationale (#231): the previous design activated the bootstrap
-- token via cfg.set(..., nosave=true), which made the API "just
-- work" on first boot. But +reload (or POST /v1/reload) reads
-- cfg.tbl fresh and silently wipes the in-memory bootstrap
-- token - operator gets 401 on every subsequent call until a
-- full process restart (which then generates a NEW random
-- token, overwriting api_token.first). Explicit opt-in via
-- cfg.tbl makes cfg.tbl the single source of truth and removes
-- this footgun.
bootstrap_first_token = function( cfg_path )
    local tokens = cfg_get "http_api_tokens" or { }
    -- Lua tables have no `next` shortcut we can rely on for "is
    -- empty" without a pairs scan - one iteration tells us.
    local any = false
    for _ in pairs( tokens ) do any = true break end
    if any then return true end    -- operator already provisioned a token

    local adclib = use "adclib"
    if not adclib then
        return nil, "adclib not loaded - cannot generate sample token"
    end
    -- 32 bytes from RAND_bytes -> base32 = 52 chars. Operator can
    -- shorten or rotate via cfg+reload as they please; we just
    -- want enough entropy that brute-force is moot.
    local raw = adclib.createsalt( 32 )
    if not raw then
        return nil, "adclib.createsalt returned nil"
    end
    local basexx = use "basexx"
    if not basexx then
        return nil, "basexx not loaded - cannot encode sample token"
    end
    local token = basexx.to_base32( raw ):gsub( "=", "" )

    local path = cfg_path .. "api_token.first"
    local f, err = io.open( path, "w" )
    if not f then
        out_error( "http_router.bootstrap_first_token: cannot write ",
            path, ": ", tostring( err ) )
        return nil, err
    end
    f:write( "# Sample admin token generated for convenience.\n" )
    f:write( "# The HTTP API is NOT active until you copy this value\n" )
    f:write( "# into cfg.tbl http_api_tokens and restart the hub (or\n" )
    f:write( "# +reload). Delete this file once you have done so.\n" )
    f:write( "# See docs/HTTP_API.md section 4.7.\n" )
    f:write( "#\n" )
    f:write( token .. "\n" )
    f:close( )

    -- chmod 600 if the platform supports it (POSIX). On Windows
    -- the call is skipped; the operator's ACLs / file-system perms
    -- apply instead. Same heuristic as cfg_secret.lua's _is_windows.
    -- Failure to chmod on POSIX is fail-loud (chmod-or-die, per
    -- Phase 7 SECURITY guidance) - a world-readable token file is
    -- worse than no token file.
    if not ( os.getenv "COMSPEC" and os.getenv "WINDIR" ) then
        local escaped = "'" .. ( path:gsub( "'", "'\\''" ) ) .. "'"
        local chmod_ok = os.execute( "chmod 600 " .. escaped )
        if chmod_ok ~= true and chmod_ok ~= 0 then
            -- os.execute returns true (Lua 5.4) or 0 (legacy) on
            -- success. Anything else = chmod failed.
            out_error( "http_router.bootstrap_first_token: chmod 600 ", path,
                " failed (rc=", tostring( chmod_ok ), "); refusing to bring up the HTTP listener" )
            return nil, "chmod 600 failed on sample token file"
        end
    end

    out_error( "hub.lua: http_port is set but cfg.tbl http_api_tokens is empty; ",
        "wrote sample token to ", path, " (chmod 600). Copy it into cfg.tbl ",
        "and restart (or +reload) to activate the HTTP API. Listener was NOT bound." )
    -- The third return value is a stable sentinel callers (core/hub.lua)
    -- check to distinguish "documented opt-in gate, do not re-log as
    -- failure" from genuine bootstrap errors (e.g. chmod failure, no
    -- adclib). Don't replace this with substring-matching against the
    -- err string - the message wording is operator-facing and may
    -- evolve, the sentinel string must not.
    return nil, "no http_api_tokens configured; sample written to " .. path, "OPT_IN_GATE"
end

-- /health: unversioned, unauthenticated, plain text. Registered as
-- a normal route with scope = "none" so it appears in
-- /v1/endpoints and follows the same dispatch path as everything
-- else; the special case for it in earlier drafts is gone.
local function health_handler( )
    return {
        status = 200,
        raw_body = "ok\n",
        content_type = "text/plain; charset=utf-8",
    }
end

-- ISO 8601 UTC second-precision timestamp (§7.4). Always trailing Z.
local function iso8601_utc( t )
    return os.date( "!%Y-%m-%dT%H:%M:%SZ", t )
end

-- /v1/version: hub identity + uptime. Read-scoped.
local function version_handler( )
    local const = use "const"
    local start = ( use "signal" ).get( "start" ) or os.time( )
    local now = os.time( )
    return { status = 200, data = {
        name           = const.PROGRAM_NAME,
        version        = const.VERSION,
        copyright      = const.COPYRIGHT,
        fork           = const.FORK,
        hub_name       = cfg_get "hub_name",
        hub_description = cfg_get "hub_description",
        start_time     = iso8601_utc( start ),
        server_time    = iso8601_utc( now ),
        uptime_seconds = now - start,
    } }
end

-- /v1/stats: hub-wide counters. Read-scoped. Returns what is
-- natively tracked by the hub (online user count, share, files,
-- by-level breakdown). Byte-traffic counters are NOT exposed -
-- the hub does not natively track them; that surface lives in
-- etc_trafficmanager plugin and is out of scope for the core API
-- in Phase 1. A future Phase-N could add a `traffic` block once
-- the hub gains native byte counters.
local function stats_handler( )
    local hub_obj = ( use "hub" ).object( )
    -- 1st return value is _nobot_normalstatesids (humans only); bots
    -- do not implement the full user-object surface (no :files() /
    -- :share()) so iterating the bot-inclusive table crashes the
    -- handler. The headline "online users" stat is also more
    -- meaningful without bots inflating the count.
    local nobots = hub_obj.getusers( )
    local online_count = 0
    local share_total = 0
    local files_total = 0
    local by_level = { }
    for _, user in pairs( nobots ) do
        online_count = online_count + 1
        local s = user:share( ) or 0
        share_total = share_total + s
        local f = user:files( ) or 0
        files_total = files_total + f
        local lvl = user:level( ) or 0
        by_level[ tostring( lvl ) ] = ( by_level[ tostring( lvl ) ] or 0 ) + 1
    end
    return { status = 200, data = {
        online_count       = online_count,
        share_total_bytes  = share_total,
        files_total        = files_total,
        by_level           = by_level,
    } }
end

-- Build the JSON-safe representation of a user object. Used by
-- both /v1/users (list) and /v1/users/{sid} (detail). Pulls the
-- subset of INF fields the API documents publicly.
local function _user_to_json( user )
    -- user.hubs returns (HN, HR, HO); guard the unpack so a user
    -- without an INF doesn't crash the serializer.
    local hn, hr, ho = user.hubs( user )
    return {
        sid            = user:sid( ),
        nick           = user:nick( ),
        cid            = user:cid( ),
        description    = user:description( ),
        email          = user:email( ),
        level          = user:level( ),
        share_bytes    = user:share( ),
        share_files    = user:files( ),
        slots          = user:slots( ),
        features       = user:features( ),
        hubs_normal    = hn,
        hubs_regged    = hr,
        hubs_op        = ho,
        version        = user:version( ),
    }
end

-- #264 field spec for /v1/users. Getters read the live user object;
-- string fields are substring-matched, integer fields support exact +
-- _min / _max range, default sort is by SID (stable for pagination).
local _users_filter_spec = {
    string_fields = {
        nick        = function( u ) return u:nick( )        end,
        description = function( u ) return u:description( ) end,
    },
    integer_fields = {
        level       = function( u ) return u:level( )       end,
        share_bytes = function( u ) return u:share( )       end,
    },
    sortable_fields = {
        nick        = function( u ) return u:nick( )        end,
        level       = function( u ) return tonumber( u:level( ) ) or 0 end,
        share_bytes = function( u ) return tonumber( u:share( ) ) or 0 end,
        files       = function( u ) return tonumber( u:files( ) ) or 0 end,
    },
    default_sort_field      = nil,    -- nil = let users_list_handler stable-order by SID before passing in
    default_sort_descending = false,
}

-- /v1/users: paginated list (§6.4). limit/offset clamped to
-- [1, 1000] / [0, total]. Read-scoped. Filter/sort via #264 helper.
local function users_list_handler( req )
    local hub_obj = ( use "hub" ).object( )
    -- 1st return value is _nobot_normalstatesids - humans only.
    -- /v1/users is for connected human clients; bot listing belongs
    -- to a future /v1/bots endpoint (not Phase 1).
    local nobots = hub_obj.getusers( )
    -- Pre-sort by SID so default order (no ?sort=) is stable across
    -- pagination requests. The filter helper preserves this order
    -- when default_sort_field is nil (no re-sort happens).
    local users_list = { }
    for sid, user in pairs( nobots ) do
        table_insert( users_list, user )
    end
    table_sort( users_list, function( a, b )
        return ( a:sid( ) or "" ) < ( b:sid( ) or "" )
    end )

    local http_filter = use "http_filter"
    local ok, rows_or_status, code, msg = http_filter.apply(
        req.query, _users_filter_spec, users_list
    )
    if not ok then
        return { status = rows_or_status,
            error = { code = code, message = msg } }
    end
    local rows       = rows_or_status
    local pagination = code

    -- Render the page via _user_to_json AFTER filter/sort/paginate so
    -- the JSON serialisation cost scales with page size, not total.
    local page = { }
    for i, user in ipairs( rows ) do
        page[ i ] = _user_to_json( user )
    end

    -- The envelope helper produces `{ok, data}`. /v1/users wants
    -- `pagination` as a SIBLING of `data` (spec §6.4). We bypass
    -- envelope_success and ship a custom raw_body via dkjson.encode
    -- so the envelope's sibling field can land.
    local wire = json_encode( {
        ok         = true,
        data       = { users = page },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- /v1/users/{sid}: full INF + session metadata for one user.
-- 404 if SID not online. Read-scoped.
local function users_detail_handler( req )
    local sid = req.path_vars and req.path_vars[ "sid" ]
    if not sid or sid == "" then
        return { status = 400, error = { code = "E_BAD_INPUT", message = "missing sid" } }
    end
    local hub_obj = ( use "hub" ).object( )
    -- Detail endpoint also restricts to humans (matches /v1/users).
    local nobots = hub_obj.getusers( )
    local user = nobots[ sid ]
    if not user then
        return { status = 404, error = { code = "E_NOT_FOUND", message = "no such online sid" } }
    end
    return { status = 200, data = _user_to_json( user ) }
end

-- /v1/log/api: tail the api_audit log file. Admin-scoped.
-- ?lines=N (default 200, max 1000) follows the §6.4 tail convention.
-- Response shape `{ lines, returned, total_lines }` matches the
-- sibling tail endpoints (/v1/log/error, /v1/log/cmd, /v1/chatlog)
-- so generic admin / WebUI clients can render any tail endpoint
-- with one shape (#275 CON-1). Missing-file returns 200 with an
-- empty `lines` array.
--
-- The absolute on-disk path is NOT echoed (#275 CON-1: pre-fix
-- the response leaked `cfg.log_path` to any admin token; the
-- response now exposes counts only, never paths).
local function log_api_handler( req )
    local lines_q = tonumber( req.query.lines ) or 200
    if lines_q < 1 then lines_q = 1 end
    if lines_q > 1000 then lines_q = 1000 end
    lines_q = math_floor( lines_q )

    local log_path = cfg_get "log_path" or "././log/"
    local path = log_path .. "api_audit.log"
    local f = io.open( path, "rb" )
    if not f then
        -- Missing-file is normal in a hub that never recorded an
        -- audit-worthy event (the createlog only creates the file
        -- on first write, which gates on log_api_audit cfg).
        return { status = 200, data = { lines = { }, returned = 0, total_lines = 0 } }
    end
    -- Stream line-by-line, counting total and keeping a rolling
    -- window of the last `lines_q + WINDOW_SLACK` lines. The window
    -- bounds memory to O(lines_q) regardless of file size - critical
    -- because audit_log.api has no rotation hook (#275 CON-1
    -- post-review: a long-running unrotated hub had this handler
    -- materialise the whole file into a Lua array).
    local WINDOW_SLACK = 1024    -- trim only every N excess lines (amortise the copy)
    local window_cap = lines_q + WINDOW_SLACK
    local total = 0
    local window = { }
    for line in f:lines( ) do
        total = total + 1
        window[ #window + 1 ] = line
        if #window > window_cap then
            -- Shrink to last lines_q. Amortised O(1) per appended
            -- line (one copy every WINDOW_SLACK lines).
            local fresh = { }
            local start_i = #window - lines_q + 1
            for i = start_i, #window do
                fresh[ #fresh + 1 ] = window[ i ]
            end
            window = fresh
        end
    end
    f:close( )
    -- Final trim to exactly lines_q (window may carry up to
    -- WINDOW_SLACK extra at this point).
    local out_lines
    if #window <= lines_q then
        out_lines = window
    else
        out_lines = { }
        local start_i = #window - lines_q + 1
        for i = start_i, #window do
            table_insert( out_lines, window[ i ] )
        end
    end
    return { status = 200, data = {
        lines       = out_lines,
        returned    = #out_lines,
        total_lines = total,
    } }
end

-- #261 GET /v1/plugins: read-scoped. Returns a snapshot of every
-- entry in cfg.scripts plus runtime state (loaded? listeners?
-- registered HTTP routes?). The data shape is documented in
-- docs/HTTP_API.md §10.2 / footnote for /v1/plugins.
local function plugins_list_handler( req )
    local scripts_mod = use "scripts"
    if type( scripts_mod.list_plugins ) ~= "function" then
        return { status = 500, error = { code = "E_INTERNAL",
            message = "scripts.list_plugins not available" } }
    end
    local plugins = scripts_mod.list_plugins( )
    -- Decorate each plugin with the HTTP routes it registered.
    -- _routes_flat is the same data the /v1/endpoints catalog uses;
    -- entries have shape { method, route = { template, scope, plugin, ... } }.
    local routes_by_plugin = { }
    for _, entry in ipairs( _routes_flat ) do
        local owner = entry.route.plugin
        if owner then
            routes_by_plugin[ owner ] = routes_by_plugin[ owner ] or { }
            table_insert( routes_by_plugin[ owner ], {
                method = entry.method,
                path   = entry.route.template,
                scope  = entry.route.scope,
            } )
        end
    end
    for _, p in ipairs( plugins ) do
        p.http_routes = routes_by_plugin[ p.name ] or { }
    end
    return { status = 200, data = { plugins = plugins } }
end

-- #261 PUT /v1/plugins/{name}/enabled: admin-scoped. Body is
-- `{ "enabled": bool }`. Mutates cfg.scripts via cfg.set, does
-- NOT trigger reload. Response carries reload_required = true so
-- the client can chain POST /v1/reload after a batch of toggles.
local function plugins_toggle_handler( req )
    local name = req.path_vars and req.path_vars[ "name" ]
    if not name or name == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing plugin name in path" } }
    end
    local body = req.body or { }
    if body.enabled == nil then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing required field: enabled (boolean)" } }
    end
    if type( body.enabled ) ~= "boolean" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "field 'enabled' must be a boolean (got " ..
                type( body.enabled ) .. ")" } }
    end
    local scripts_mod = use "scripts"
    if type( scripts_mod.set_plugin_enabled ) ~= "function" then
        return { status = 500, error = { code = "E_INTERNAL",
            message = "scripts.set_plugin_enabled not available" } }
    end
    local ok, code, msg = scripts_mod.set_plugin_enabled( name, body.enabled )
    if not ok then
        local status
        if code == "E_FORBIDDEN" then status = 403
        elseif code == "E_NOT_FOUND" then status = 404
        else status = 400 end
        return { status = status, error = { code = code, message = msg } }
    end
    return { status = 200, data = {
        action          = "plugin-toggle-set",
        name            = name,
        enabled         = body.enabled,
        reload_required = true,
    } }
end

-- #262 / Precursor 0c of #78 arc: cfg keys whose value MUST NOT
-- leak through the HTTP API are masked as the string "<redacted>"
-- on GET and rejected with 403 on PUT. The registry lives in
-- core/secrets.lua (single source of truth across +showcfg, GET
-- /v1/config, audit-body redaction). Future plugins register their
-- own sensitive keys at onStart via `secrets.register(cfg_key)` -
-- no edit to this file required.

-- #262: apply-status classification - which keys take effect
-- immediately on cfg.set vs need POST /v1/reload vs need a full
-- hub restart. Anything not in either bucket defaults to "live".
-- Listed sparingly: only keys whose runtime caching / module-load
-- semantics make a hot cfg.set ineffective until the operator
-- explicitly applies.
local _config_reload_required = {
    scripts            = true,    -- #261 plugin list; needs +reload to apply
    language           = true,    -- language tables loaded at startup
    -- Path keys consumed at module-load / reload time (file handles
    -- + table caches refresh on the next +reload cycle).
    user_path          = true,
    script_path        = true,
    scripts_cfg_path   = true,
    scripts_lang_path  = true,
    core_lang_path     = true,
    -- ratelimit.init() caches its full cfg surface at module-load
    -- time into local state (see `init()` in core/ratelimit.lua). A
    -- hot cfg.set() on any of these keys returns "live" misleadingly;
    -- the new values only take effect at +reload. The list mirrors
    -- the `cfg_get` calls in ratelimit.init() one-to-one so adding a
    -- new ratelimit key in the future is a one-line append both
    -- there and here. Sweep done as part of #275 SEC-6.
    ratelimit_activate              = true,
    ratelimit_bypass_level          = true,
    ratelimit_perip_max_conns       = true,
    ratelimit_perip_conn_rate       = true,
    ratelimit_perip_conn_burst      = true,
    ratelimit_handshake_timeout     = true,
    ratelimit_perip_authfail_rate   = true,
    ratelimit_perip_authfail_burst  = true,
    ratelimit_authfail_lockout      = true,
    ratelimit_user_msg_rate         = true,
    ratelimit_user_msg_burst        = true,
    ratelimit_user_pm_rate          = true,
    ratelimit_user_pm_burst         = true,
    ratelimit_user_inf_rate         = true,
    ratelimit_user_inf_burst        = true,
    ratelimit_user_ctm_rate         = true,
    ratelimit_user_ctm_burst        = true,
    ratelimit_user_search_period    = true,
    ratelimit_user_search_burst     = true,
    ratelimit_tiers                 = true,
    ratelimit_tier_for_level        = true,
    -- HTTP API rate-limit knobs (subset of the same ratelimit module
    -- state):
    http_api_rate_read              = true,
    http_api_rate_admin             = true,
    http_api_burst                  = true,
    http_api_authfail_prefix_rate   = true,
    http_api_authfail_prefix_burst  = true,
}
local _config_restart_required = {
    tcp_ports        = true,
    ssl_ports        = true,
    tcp_ports_ipv6   = true,
    ssl_ports_ipv6   = true,
    http_port        = true,
    hub_listen       = true,
    master_key_path  = true,    -- also in secrets registry; PUT 403 before this is reached
    log_path         = true,    -- log file handles opened at startup
    -- TLS context is constructed once when the SSL listener binds.
    -- Changing ssl_params / use_ssl after startup has no effect
    -- until the listener is re-created at process restart.
    ssl_params       = true,
    use_ssl          = true,
}

local _classify_apply_status = function( key )
    if _config_restart_required[ key ] then return "restart_required" end
    if _config_reload_required[ key ]  then return "reload_required"  end
    return "live"
end

-- #262 GET /v1/config: read-scoped. Returns the full cfg snapshot
-- (every key registered in cfg_defaults.lua) with sensitive keys
-- masked as "<redacted>". The sensitive-key list lives in
-- core/secrets.lua (Precursor 0c of #78 arc).
local function config_get_handler( req )
    local cfg_mod = use "cfg"
    if type( cfg_mod.list_keys ) ~= "function" then
        return { status = 500, error = { code = "E_INTERNAL",
            message = "cfg.list_keys not available" } }
    end
    local secrets_mod = use "secrets"
    local snapshot = { }
    for _, key in ipairs( cfg_mod.list_keys( ) ) do
        if secrets_mod.is_secret_key( key ) then
            snapshot[ key ] = "<redacted>"
        else
            snapshot[ key ] = cfg_mod.get( key )
        end
    end
    return { status = 200, data = { config = snapshot } }
end

-- #262 PUT /v1/config/{key}: admin-scoped. Body `{ "value": <any
-- JSON type> }`. Denylisted keys -> 403. Unknown keys -> 404.
-- Validator-rejected values -> 400 with the validator's err_msg.
-- Success -> 200 with apply_status (live / reload_required /
-- restart_required) so the operator knows the next step.
local function config_put_handler( req )
    local key = req.path_vars and req.path_vars[ "key" ]
    if not key or key == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {key} path variable" } }
    end
    local secrets_mod = use "secrets"
    if secrets_mod.is_secret_key( key ) then
        return { status = 403, error = { code = "E_FORBIDDEN",
            message = "cfg key '" .. key .. "' is sensitive (in secrets registry); " ..
                "rotate / relocate via direct cfg.tbl edit + hub restart" } }
    end
    local cfg_mod = use "cfg"
    if not cfg_mod.is_known( key ) then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "unknown cfg key '" .. key .. "' (not in cfg_defaults.lua)" } }
    end
    local body = req.body
    if type( body ) ~= "table" or body.value == nil then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing required body field: value" } }
    end
    local ok, err = cfg_mod.set( key, body.value )
    if not ok then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = err or "cfg.set rejected the value" } }
    end
    return { status = 200, data = {
        action       = "config-set",
        key          = key,
        apply_status = _classify_apply_status( key ),
    } }
end

-- #263 PR-A GET /v1/events: read-scoped event stream. PR-B adds
-- the `?wait=<seconds>` long-poll path - when the immediate poll
-- finds zero matching events AND wait > 0, the handler returns a
-- deferred response that registers the connection as a waiter in
-- http_events. Server resumes the response on event arrival
-- (sub-second) OR deadline expiry (up to wait seconds).
local function events_get_handler( req )
    local q = req.query or { }
    local events_mod = use "http_events"
    if type( events_mod.poll ) ~= "function" then
        return { status = 500, error = { code = "E_INTERNAL",
            message = "http_events.poll not available" } }
    end
    -- Scope-based event filter: strips `pm` (user content) and
    -- `audit` (staff-action trail with target IPs / CIDs) from the
    -- read-scope stream. Admin tokens see everything. Used on
    -- both the immediate-return path AND the deferred render
    -- closure passed through to http_events.register_waiter.
    -- #84: audit events carry target IPs / CIDs and the actor's
    -- session metadata; gating them admin-only matches the
    -- plugin trust contract in SECURITY.md §2.
    local is_admin = ( req.token_scope == "admin" )
    local function filter_for_scope( rows )
        if is_admin then return rows end
        local out = { }
        for _, ev in ipairs( rows ) do
            if ev.type ~= "pm" and ev.type ~= "audit" then
                out[ #out + 1 ] = ev
            end
        end
        return out
    end

    local rows, cursor, cursor_lost = events_mod.poll( q.since, q.types )
    rows = filter_for_scope( rows )

    -- Parse wait. Default 0 (immediate). Max 60s per spec.
    local wait_secs = tonumber( q.wait ) or 0
    if wait_secs < 0 then wait_secs = 0 end
    if wait_secs > 60 then wait_secs = 60 end

    if #rows > 0 or wait_secs == 0 or cursor_lost then
        -- Immediate return: events available OR no wait requested
        -- OR cursor_lost (don't long-poll on a stale cursor -
        -- client must catch up first).
        local data = { events = rows, cursor = cursor }
        if cursor_lost then data.cursor_lost = true end
        return { status = 200, data = data }
    end

    -- Long-poll path: register the connection as a waiter.
    -- http_events.emit / tick will resolve it.
    if type( events_mod.register_waiter ) ~= "function" then
        -- PR-A fallback path; should not happen post-PR-B.
        return { status = 200, data = { events = { }, cursor = cursor } }
    end
    -- Build the render closure - this runs at resolve time with
    -- the final (rows, cursor, cursor_lost) tuple. It owns the
    -- pm-scope filter so http_events stays scope-agnostic. Echoes
    -- the request's X-Request-ID so audit-log correlation works
    -- on the deferred path same as the immediate path (§6.5).
    local request_id = req.request_id
    local render_fn = function( final_rows, final_cursor, final_cursor_lost )
        final_rows = filter_for_scope( final_rows or { } )
        local data = { events = final_rows, cursor = final_cursor }
        if final_cursor_lost then data.cursor_lost = true end
        local body = json_encode( { ok = true, data = data } )
        local http = use "http"
        local extra = { [ "X-Request-ID" ] = request_id }
        return http.response( 200, body, "application/json; charset=utf-8", extra, false )
    end

    return {
        status = "deferred",
        defer  = function( handler )
            events_mod.register_waiter( handler, q.since, q.types, wait_secs, render_fn )
        end,
    }
end

-- Fixed non-matching password used to equalize the timing of an
-- unknown-nick verify against a known-nick one: we compute hashpas +
-- a constant-time compare in BOTH cases, so response time does not
-- reveal whether a nick is registered. Never a valid stored password.
local _AUTHVERIFY_DUMMY_PW = "\0no-such-account\0"

-- POST /v1/auth/verify - verify an operator's hub credential via the
-- ADC challenge-response, for the WebUI login (BFF) flow. The caller
-- (a token-bearing BFF) mints a fresh base32 salt, the browser returns
-- adclib.hashpas(password, salt); we recompute from the stored password
-- and compare in CONSTANT TIME. Returns { ok = true, level } on success,
-- { ok = false } otherwise (no level leaked). scope=read keeps this
-- password oracle behind the bearer (never unauthenticated); the body is
-- audit-redacted (auth material). Mirrors core/hub_dispatch.lua's HPAS
-- recompute (:644) but, unlike the native `~=` there, is constant-time.
local function auth_verify_handler( req )
    local body = req.body or { }
    local nick, salt, response = body.nick, body.salt, body.response
    if type( nick ) ~= "string" or nick == ""
        or type( salt ) ~= "string" or type( response ) ~= "string" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "nick, salt, response are required strings" } }
    end
    -- Password-oracle throttle: per-nick AND per-IP (both gate).
    local ratelimit = use "ratelimit"
    if not ratelimit.http_authverify( nick, req.source_ip ) then
        return { status = 429, error = { code = "E_RATE_LIMITED",
            message = "auth-verify rate limit exceeded" } }
    end
    -- Salt must be RFC4648 base32 (upper, no padding) within the length
    -- adclib.hashpas accepts (saltBytes = len*5/8 in (0, 64]); reject a
    -- malformed salt as a clean 400 rather than letting hashpas raise.
    if #salt < 16 or #salt > 102 or string_find( salt, "[^A-Z2-7]" ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "salt must be RFC4648 base32 (A-Z2-7), 16..102 chars" } }
    end
    -- Reguser lookup. Nicks with spaces are stored escaped, so escape the
    -- incoming nick exactly as the ADC login path does before indexing.
    local hub = use "hub"
    local _, regs_by_nick = hub.getregusers( )
    local profile = regs_by_nick[ hub.escapeto( nick ) ]
    -- Treat an empty stored password as ABSENT: the reg/setpass paths
    -- reject "", but a corrupt or hand-edited user.tbl could carry
    -- password="", and hashpas("", salt) must never become a valid login.
    -- An empty password falls through to the DUMMY -> ok=false.
    local stored = ( profile and type( profile.password ) == "string"
        and profile.password ~= "" ) and profile.password or nil
    -- Timing-equalized: always compute hashpas + a constant-time compare,
    -- even for an unknown nick (dummy password). `not stored` still
    -- forces ok=false regardless of the compare result.
    local expected = _adclib.hashpas( stored or _AUTHVERIFY_DUMMY_PW, salt )
    local matched  = constant_time_eq( response, expected )
    if not ( stored and matched ) then
        return { status = 200, data = { ok = false } }
    end
    return { status = 200, data = { ok = true, level = tonumber( profile.level ) or 20 } }
end

-- /v1/endpoints + /health registration. Called from
-- register_core_endpoints below at module-init time so the discovery
-- surface is always available (no plugin owns it).
register_core_endpoints = function( )
    register( "GET", "/health", "none", health_handler, {
        plugin = "core",
        description = "load-balancer health probe (plain text, unauthenticated)",
        response_schema = nil,
    } )
    register( "GET", "/v1/endpoints", "read", list_endpoints, {
        plugin = "core",
        description = "list all registered endpoints (scope-filtered to the caller's token)",
        response_schema = { endpoints = { type = "array", required = true } },
    } )
    register( "GET", "/v1/version", "read", version_handler, {
        plugin = "core",
        description = "hub identity, version, and uptime",
    } )
    register( "GET", "/v1/stats", "read", stats_handler, {
        plugin = "core",
        description = "hub-wide counters: online users, share total, by-level breakdown",
    } )
    register( "GET", "/v1/users", "read", users_list_handler, {
        plugin = "core",
        description = "online users (paginated; ?limit=200&offset=0)",
    } )
    register( "GET", "/v1/users/{sid}", "read", users_detail_handler, {
        plugin = "core",
        description = "full session metadata for one online user (by SID)",
    } )
    register( "GET", "/v1/log/api", "admin", log_api_handler, {
        plugin = "core",
        description = "tail of api_audit.log (admin-scoped; ?lines=N default 200 max 1000); response {lines, returned, total_lines} matches sibling tail endpoints",
    } )
    -- #261 plugin-management endpoints.
    register( "GET", "/v1/plugins", "read", plugins_list_handler, {
        plugin = "core",
        description = "list plugins in cfg.scripts + runtime state (loaded / listeners / http_routes)",
    } )
    register( "PUT", "/v1/plugins/{name}/enabled", "admin", plugins_toggle_handler, {
        plugin = "core",
        description = "toggle a manageable (table-form) plugin's enabled flag; mutates cfg.tbl, requires POST /v1/reload to apply",
        request_schema = {
            enabled = { type = "boolean", required = true },
        },
    } )
    -- #262 config management endpoints.
    register( "GET", "/v1/config", "read", config_get_handler, {
        plugin = "core",
        description = "full cfg snapshot; keys in the secrets registry (see core/secrets.lua) masked as <redacted>",
    } )
    register( "PUT", "/v1/config/{key}", "admin", config_put_handler, {
        plugin = "core",
        description = "update one cfg key; response carries apply_status (live / reload_required / restart_required)",
    } )
    -- #263 PR-A event stream (immediate-return polling).
    register( "GET", "/v1/events", "read", events_get_handler, {
        plugin = "core",
        description = "polled event stream; ?since=<id>&types=<csv>; PR-A immediate-return (PR-B adds long-poll)",
    } )
    -- WebUI operator login: verify a hub credential via ADC challenge-
    -- response. scope=read keeps the password oracle behind a bearer;
    -- the body carries auth material, so it is audit-redacted.
    register( "POST", "/v1/auth/verify", "read", auth_verify_handler, {
        plugin = "core",
        description = "verify an operator's hub credential via ADC challenge-response (WebUI login); body {nick, salt, response} -> {ok, level}",
        request_schema = {
            nick     = { type = "string", required = true, max_length = 64 },
            salt     = { type = "string", required = true, max_length = 128 },
            response = { type = "string", required = true, max_length = 128 },
        },
        response_schema = {
            ok    = { type = "boolean", required = true },
            level = { type = "integer", required = false },
        },
        audit_redact_body = true,
    } )
end

-- init() is called by core/hub.lua after cfg has loaded and before
-- the HTTP listener binds. Re-callable: +reload calls unregister_all
-- + init() again to repopulate routes.
local init = function( )
    if _initialized then return end
    register_core_endpoints( )
    _initialized = true
end

----------------------------------// PUBLIC INTERFACE //--

return {

    register              = register,
    unregister_all        = unregister_all,
    dispatch              = dispatch,
    bootstrap_first_token = bootstrap_first_token,
    init                  = init,

    -- exposed for unit tests (NOT for plugin use):
    _constant_time_eq     = constant_time_eq,
    _validate_schema      = validate_schema,
    _envelope_success     = envelope_success,
    _envelope_error       = envelope_error,
    _resolve_token        = resolve_token,
    _generate_request_id  = generate_request_id,
    _auth_verify_handler  = auth_verify_handler,
    _idem_lookup          = function( ... ) return idem_lookup( ... ) end,
    _idem_store           = function( ... ) return idem_store( ... ) end,
    _idem_clear           = function( ... ) return idem_clear( ... ) end,

}
