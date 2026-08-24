--[[

    core/ratelimit.lua - DoS hardening rate limiter

    Phase 7c. Token-bucket counters keyed by IP or by user-CID,
    cfg-tunable, op-level bypass. Hooks:

    - server.lua  : accept_ip / release_ip / handshake_started /
                    handshake_finished / expired_handshakes
    - hub_dispatch: user_msg / user_search / record_authfail

    Storage:

        _perip_count[ip]   = active socket count
        _buckets[id][kind] = { tokens, ts }
        _hs_started[h]     = handshake start ts

    IDs:
        "ip:1.2.3.4"   for per-IP buckets
        "user:CID"     for per-user buckets (CID is stable per session)

    Cleanup:
        tick() walks _buckets and drops entries idle > 5 min. Per-IP
        counts drop to zero on release_ip; handshake table is cleaned
        explicitly on handshake_finished or via the periodic walk
        triggered by expired_handshakes.

]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local pairs = use "pairs"
local tostring = use "tostring"
local type = use "type"

--// lua libs //--

local math = use "math"

--// lua lib methods //--

local math_min = math.min

--// extern libs //--

local socket = use "socket"

--// extern lib methods //--

local socket_gettime = socket.gettime

--// core modules //--

local cfg = use "cfg"

--// core methods //--

local cfg_get = cfg.get

--// functions //--

local init
local accept_ip
local release_ip
local handshake_started
local handshake_finished
local expired_handshakes
local user_msg
local user_pm
local user_inf
local user_ctm
local user_search
local record_authfail
local http_token
local http_token_retry_after
local http_authfail_prefix
local http_authverify
local tick

--// tables //--

local _perip_count
local _buckets
local _hs_started
local _ip_blocks    -- ip -> expiry-ts; F-AUTH-3 sticky lockout
local _tier_buckets -- level -> tier-table from cfg (#80 per-userlevel overlay)

--// scalars //--

local _activate
local _bypass_level
local _perip_max_conns
local _perip_conn_rate
local _perip_conn_burst
local _hs_timeout
local _authfail_rate_per_sec
local _authfail_burst
local _authfail_lockout
local _http_rate_read           -- HTTP API per-token rate (read scope), per-second
local _http_rate_admin          -- HTTP API per-token rate (admin scope), per-second
local _http_burst               -- HTTP API per-token burst (shared across scopes)
local _http_authfail_prefix_rate    -- HTTP per-prefix failed-auth bucket, per-second
local _http_authfail_prefix_burst   -- HTTP per-prefix failed-auth bucket, burst
local _http_authverify_rate         -- HTTP /v1/auth/verify oracle bucket, per-second
local _http_authverify_burst        -- HTTP /v1/auth/verify oracle bucket, burst
local _msg_rate
local _msg_burst
local _pm_rate
local _pm_burst
local _inf_rate
local _inf_burst
local _ctm_rate
local _ctm_burst
local _search_rate_per_sec
local _search_burst

local _last_cleanup
local _cleanup_interval
local _bucket_idle_max

----------------------------------// DEFINITION //--

_perip_count = { }
_buckets = { }
_hs_started = { }
_ip_blocks = { }
_tier_buckets = { }

_last_cleanup = 0
_cleanup_interval = 60
_bucket_idle_max = 300

local function _bucket( id, kind, capacity )
    local b = _buckets[ id ]
    if not b then
        b = { }
        _buckets[ id ] = b
    end
    local tk = b[ kind ]
    if not tk then
        tk = { tokens = capacity, ts = socket_gettime( ) }
        b[ kind ] = tk
    end
    return tk
end

local function _consume( id, kind, capacity, fill_per_sec )
    local now = socket_gettime( )
    local tk = _bucket( id, kind, capacity )
    local elapsed = now - tk.ts
    if elapsed > 0 then
        tk.tokens = math_min( capacity, tk.tokens + elapsed * fill_per_sec )
        tk.ts = now
    end
    if tk.tokens >= 1 then
        tk.tokens = tk.tokens - 1
        return true
    end
    return false
end

local function _ip_blocked( ip )
    local until_ts = _ip_blocks[ ip ]
    if not until_ts then return false end
    if socket_gettime( ) >= until_ts then
        _ip_blocks[ ip ] = nil
        return false
    end
    return true
end

accept_ip = function( ip )
    if not _activate then return true end
    -- Defence in depth: server.lua drops a nil peer IP before calling
    -- us, but never let a nil crash the accept loop here (mirror
    -- release_ip's guard below). A peer we cannot identify cannot be
    -- per-IP limited; allow and let the caller close the dead socket.
    if not ip then return true end
    -- Sticky F-AUTH-3 IP block from prior bad-auth abuse.
    if _ip_blocked( ip ) then
        return false, "IP locked out due to repeated auth failures: " .. tostring( ip )
    end
    -- Parallel-socket cap (F-NET-1, parallel slot count)
    local count = _perip_count[ ip ] or 0
    if count >= _perip_max_conns then
        return false, "too many connections from " .. tostring( ip )
    end
    -- Connection-rate (F-NET-1, rate)
    if not _consume( "ip:" .. ip, "conn", _perip_conn_burst, _perip_conn_rate ) then
        return false, "connection rate exceeded for " .. tostring( ip )
    end
    _perip_count[ ip ] = count + 1
    return true
end

release_ip = function( ip )
    if not ip then return end
    local count = _perip_count[ ip ]
    if not count then return end
    if count <= 1 then
        _perip_count[ ip ] = nil
    else
        _perip_count[ ip ] = count - 1
    end
end

handshake_started = function( handler )
    if not _activate or _hs_timeout <= 0 then return end
    _hs_started[ handler ] = socket_gettime( )
end

handshake_finished = function( handler )
    _hs_started[ handler ] = nil
end

-- Returns array of handlers whose TLS handshake has been pending
-- longer than _hs_timeout. Caller (server.lua periodic timer) is
-- responsible for closing them.
expired_handshakes = function( )
    if not _activate or _hs_timeout <= 0 then return nil end
    local now = socket_gettime( )
    local result
    for h, ts in pairs( _hs_started ) do
        if ( now - ts ) >= _hs_timeout then
            result = result or { }
            result[ #result + 1 ] = h
        end
    end
    return result
end

-- #80 PR 4/4: tier-overlay helper. Looks up a per-userlevel tier for
-- the caller; if a tier exists and has the requested rate/burst fields
-- the tier values override the global scalars, otherwise the scalars
-- apply unchanged. Tier fields are optional and additive - a tier may
-- override only a subset of the five bucket families, the rest still
-- fall back to global scalars. Returns (rate, burst).
local function _tier_or_scalar( level, rate_key, burst_key, default_rate, default_burst )
    local tier = level and _tier_buckets[ level ]
    if not tier then return default_rate, default_burst end
    local rate = tier[ rate_key ] or default_rate
    local burst = tier[ burst_key ] or default_burst
    return rate, burst
end

-- Per-user mainchat-rate (F-RL-1). level >= bypass_level skips the check.
-- Gates BMSG only - the PM types (DMSG/EMSG) used to share this bucket
-- but have their own user_pm bucket since #80 so operators can tune them
-- independently.
user_msg = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    local rate, burst = _tier_or_scalar( level, "msg_rate", "msg_burst", _msg_rate, _msg_burst )
    return _consume( "user:" .. cid, "msg", burst, rate )
end

-- Per-user PM-rate (#80, PM-Flood split). Gates DMSG/EMSG. level >=
-- bypass_level skips the check. Defaults are the same as user_msg for
-- behaviour-equivalence with the pre-split v3.1.7 release; operators
-- can tune them tighter independently of the mainchat bucket.
user_pm = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    local rate, burst = _tier_or_scalar( level, "pm_rate", "pm_burst", _pm_rate, _pm_burst )
    return _consume( "user:" .. cid, "pm", burst, rate )
end

-- Per-user BINF-update rate (#80, INF-Update flood). Gates post-login
-- BINFs only - the login BINF runs through the IDENTIFY/VERIFY state
-- machine before normal-state dispatch, so a tight bucket here cannot
-- block legitimate logins. Defaults are deliberately lenient (2/s,
-- burst 20) to tolerate legitimate share-state churn: watch-folders
-- emit a BINF whenever the share size changes, and a user starting
-- ten parallel downloads emits ten quick slot-count updates. Operators
-- on quiet hubs can tighten. level >= bypass_level skips the check.
user_inf = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    local rate, burst = _tier_or_scalar( level, "inf_rate", "inf_burst", _inf_rate, _inf_burst )
    return _consume( "user:" .. cid, "inf", burst, rate )
end

-- Per-user connection-setup rate (#80, CTM/RCM-Flood). Gates DCTM
-- and DRCM (both directions of the peer-connection initiation
-- handshake) through the same bucket - semantically a user picks one
-- or the other per peer based on NAT/routing, so abusing them
-- separately makes no sense and a shared limit keeps the cfg surface
-- small. Defaults (2/s, burst 30) tolerate the explicit use case
-- called out in #80: a user firing 20-30 connection attempts when
-- their search results page resolves to many peers, or starting many
-- parallel downloads from a download queue. Sustained 2/s caps a
-- malicious crawler at ~120 connection attempts per minute after the
-- burst is exhausted. level >= bypass_level skips the check.
user_ctm = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    local rate, burst = _tier_or_scalar( level, "ctm_rate", "ctm_burst", _ctm_rate, _ctm_burst )
    return _consume( "user:" .. cid, "ctm", burst, rate )
end

-- Per-user search-rate (F-RL-2). level >= bypass_level skips the check.
-- The tier-overlay uses `search_period` (matches the scalar cfg key
-- name) and converts to rate-per-second at lookup time. Pass 0 / nil
-- to skip the override and fall through to the global rate.
user_search = function( cid, level )
    if not _activate then return true end
    if level and level >= _bypass_level then return true end
    if not cid or cid == "" then return true end
    local burst = _search_burst
    local rate = _search_rate_per_sec
    local tier = _tier_buckets[ level ]
    if tier then
        if tier.search_burst then burst = tier.search_burst end
        local period = tier.search_period
        if period and period > 0 then rate = 1 / period end
    end
    return _consume( "user:" .. cid, "search", burst, rate )
end

-- Per-IP failed-auth tracking (F-AUTH-3). Consumes a token from the
-- per-IP authfail bucket; if the rate has been exceeded the IP is
-- added to the sticky lockout list for `_authfail_lockout` seconds.
-- accept_ip will refuse new connections from that IP for the duration.
-- Returns true if still under the rate, false if just locked out.
record_authfail = function( ip )
    if not _activate then return true end
    if not ip or ip == "" then return true end
    local ok = _consume( "ip:" .. ip, "authfail", _authfail_burst, _authfail_rate_per_sec )
    if not ok then
        _ip_blocks[ ip ] = socket_gettime( ) + _authfail_lockout
    end
    return ok
end

--// HTTP API rate-limit (#82 §6.3 + §4.8) //--

-- HTTP API per-token-bucket (#82 §6.3). Returns true if a token is
-- available (request may proceed) and false if the bucket is empty.
-- `label` is the non-secret token label produced by resolve_token
-- (comment + first4...last4); we key the bucket on it so the per-
-- token-prefix accounting is stable across both `read` and `admin`
-- tokens with the same label. `scope` selects the per-second fill
-- rate; both scopes share `_http_burst` so a quiet WebUI does not
-- block a sudden admin batch.
--
-- Always returns true if the rate limiter is globally disabled
-- (cfg `ratelimit_activate = false`) - matches the per-user
-- functions' semantics. The HTTP API has no level-bypass; even an
-- admin token is subject to the bucket (operator-recovery
-- endpoints carve out via X-Confirm, see http_router.lua).
http_token = function( label, scope )
    if not _activate then return true end
    if not label or label == "" then return true end
    local rate = ( scope == "admin" ) and _http_rate_admin or _http_rate_read
    return _consume( "http:" .. label, "token", _http_burst, rate )
end

-- Retry-After helper for http_token: returns the integer number of
-- seconds the caller should wait before re-trying. Reads the bucket
-- state without consuming; if the bucket is full or non-existent
-- returns 1 (a safe floor - clients should not hammer in tight
-- loops). The token-bucket fill rate is per-second, so the wait is
-- approximately `(1 - tokens) / fill_per_sec` ceiling'd to integer
-- seconds.
http_token_retry_after = function( label, scope )
    if not _activate then return 1 end
    local rate = ( scope == "admin" ) and _http_rate_admin or _http_rate_read
    if rate <= 0 then return 1 end
    local b = _buckets[ "http:" .. label ]
    local tk = b and b[ "token" ]
    if not tk then return 1 end
    local now = socket_gettime( )
    local elapsed = now - tk.ts
    local current = math_min( _http_burst, tk.tokens + elapsed * rate )
    if current >= 1 then return 1 end
    local needed = 1 - current
    local wait = needed / rate
    -- ceil to integer second; never return < 1
    local secs = wait - ( wait % 1 )
    if wait > secs then secs = secs + 1 end
    if secs < 1 then secs = 1 end
    return secs
end

-- HTTP per-prefix failed-auth bucket (#82 §4.8). Second line of
-- defence behind the per-connection counter: an attacker walking
-- the token space across many short connections (one request per
-- TCP conn, our transport) hits this bucket keyed on the first 4
-- chars of the Bearer token. Defaults 10/min/prefix, burst 5.
-- Returns true if the request may proceed, false if the prefix
-- bucket is empty.
--
-- `prefix` is the first 4 chars of the Bearer payload (length-leak
-- limited; we never log the full token). Caller passes "" if no
-- Authorization header is present - that case is not throttled
-- here (the missing-token codepath is cheap and not a prefix).
http_authfail_prefix = function( prefix )
    if not _activate then return true end
    if not prefix or prefix == "" then return true end
    return _consume( "httpprefix:" .. prefix, "authfail",
        _http_authfail_prefix_burst, _http_authfail_prefix_rate )
end

-- HTTP /v1/auth/verify password-oracle bucket (WebUI operator login).
-- The verify endpoint checks a hub password via ADC challenge-response,
-- so it is a password oracle - throttle hard. Consume BOTH a per-nick
-- and a per-IP bucket: the per-nick bucket bounds brute-forcing one
-- account, the per-IP bucket bounds spraying across many accounts from
-- one host. Both are consumed when present and the request is allowed
-- only if neither bucket was empty - an attack request pays both
-- tokens, which is intended. Returns true if the request may proceed.
http_authverify = function( nick, ip )
    if not _activate then return true end
    local ok = true
    if nick and nick ~= "" then
        if not _consume( "authverifynick:" .. nick, "authverify",
            _http_authverify_burst, _http_authverify_rate ) then
            ok = false
        end
    end
    if ip and ip ~= "" then
        if not _consume( "authverifyip:" .. ip, "authverify",
            _http_authverify_burst, _http_authverify_rate ) then
            ok = false
        end
    end
    return ok
end

tick = function( )
    local now = socket_gettime( )
    if ( now - _last_cleanup ) < _cleanup_interval then return end
    _last_cleanup = now
    local stale_before = now - _bucket_idle_max
    for id, kinds in pairs( _buckets ) do
        local newest = 0
        for _, tk in pairs( kinds ) do
            if tk.ts > newest then newest = tk.ts end
        end
        if newest < stale_before then
            _buckets[ id ] = nil
        end
    end
    -- Drop expired IP locks so the table does not grow unboundedly.
    for ip, until_ts in pairs( _ip_blocks ) do
        if now >= until_ts then _ip_blocks[ ip ] = nil end
    end
end

-- Re-reads the full ratelimit cfg surface into the module scalars and
-- rebuilds the tier overlay. Also drops the live token buckets so a
-- changed capacity/rate takes effect immediately (restart-equivalent)
-- instead of the boot-time limits bleeding through until each bucket
-- refills. The live tables that are NOT rate budgets are preserved:
-- _perip_count (active socket count), _ip_blocks (sticky F-AUTH-3
-- lockouts) and _hs_started (in-flight handshake deadlines) - dropping
-- those on an operator +reload would miscount live sockets, forgive a
-- locked-out abuser, and lose handshake tracking. Runs at boot (from
-- init) and on every +reload / POST /v1/reload (as the cfg-reload
-- listener registered by init, #648).
local function _apply_cfg( )
    _activate = cfg_get "ratelimit_activate"
    _bypass_level = cfg_get "ratelimit_bypass_level"
    _perip_max_conns = cfg_get "ratelimit_perip_max_conns"
    _perip_conn_rate = cfg_get "ratelimit_perip_conn_rate"
    _perip_conn_burst = cfg_get "ratelimit_perip_conn_burst"
    _hs_timeout = cfg_get "ratelimit_handshake_timeout"
    -- authfail rate is configured per-minute for human-friendly tuning.
    _authfail_rate_per_sec = cfg_get "ratelimit_perip_authfail_rate" / 60
    _authfail_burst = cfg_get "ratelimit_perip_authfail_burst"
    _authfail_lockout = cfg_get "ratelimit_authfail_lockout"
    _msg_rate = cfg_get "ratelimit_user_msg_rate"
    _msg_burst = cfg_get "ratelimit_user_msg_burst"
    _pm_rate = cfg_get "ratelimit_user_pm_rate"
    _pm_burst = cfg_get "ratelimit_user_pm_burst"
    _inf_rate = cfg_get "ratelimit_user_inf_rate"
    _inf_burst = cfg_get "ratelimit_user_inf_burst"
    _ctm_rate = cfg_get "ratelimit_user_ctm_rate"
    _ctm_burst = cfg_get "ratelimit_user_ctm_burst"
    -- search is configured as "one per N seconds" for legibility; convert
    -- to fill-rate per second.
    local search_period = cfg_get "ratelimit_user_search_period"
    if not search_period or search_period <= 0 then search_period = 1 end
    _search_rate_per_sec = 1 / search_period
    _search_burst = cfg_get "ratelimit_user_search_burst"
    -- #80 PR 4/4: per-userlevel tier overlay. Build a fast lookup
    -- _tier_buckets[level] -> tier-table once at init; runtime path is
    -- a single table indexing per call. Both cfg keys default to empty
    -- so a hub that does not configure tiers sees zero overhead and
    -- behaviour-identical to the pre-tier release.
    _tier_buckets = { }
    local tiers = cfg_get "ratelimit_tiers"
    local level_map = cfg_get "ratelimit_tier_for_level"
    if type( tiers ) == "table" and type( level_map ) == "table" then
        for level, tier_name in pairs( level_map ) do
            local tier = tiers[ tier_name ]
            if type( tier ) == "table" then
                _tier_buckets[ level ] = tier
            end
        end
    end
    -- HTTP API rate-limit defaults are cfg'd as requests-per-minute
    -- for human legibility; convert to per-second fill rate.
    local r_read = cfg_get "http_api_rate_read"
    local r_admin = cfg_get "http_api_rate_admin"
    _http_rate_read  = ( r_read  and r_read  > 0 ) and ( r_read  / 60 ) or ( 120 / 60 )
    _http_rate_admin = ( r_admin and r_admin > 0 ) and ( r_admin / 60 ) or (  60 / 60 )
    _http_burst = cfg_get "http_api_burst" or 10
    -- HTTP per-prefix failed-auth bucket (§4.8). Cfg'd as
    -- per-minute for symmetry with the perip authfail key. Defaults
    -- match the spec (10/min, burst 5).
    local pf_rate = cfg_get "http_api_authfail_prefix_rate"
    _http_authfail_prefix_rate = ( pf_rate and pf_rate > 0 )
        and ( pf_rate / 60 ) or ( 10 / 60 )
    _http_authfail_prefix_burst = cfg_get "http_api_authfail_prefix_burst" or 5
    -- HTTP /v1/auth/verify password-oracle bucket (WebUI login). Cfg'd
    -- per-minute; deliberately low - this is a password oracle, not a
    -- normal read endpoint. Keyed per-nick AND per-IP (both gate).
    local av_rate = cfg_get "http_api_authverify_rate"
    _http_authverify_rate = ( av_rate and av_rate > 0 ) and ( av_rate / 60 ) or ( 6 / 60 )
    _http_authverify_burst = cfg_get "http_api_authverify_burst" or 3
    -- #648: reset the token buckets so a changed capacity/rate applies
    -- at once (see the _apply_cfg header for what is preserved).
    _buckets = { }
    _last_cleanup = socket_gettime( )
end

init = function( )
    _apply_cfg( )
    -- #648: PUT /v1/config reports the ratelimit_* / http_api_* keys as
    -- "reload_required", but nothing re-ran the cfg read on reload, so a
    -- change only took effect at the next full restart. Subscribe the
    -- re-read to the cfg-reload event (fired by cfg.reload() on both
    -- +reload and POST /v1/reload). Registered here in init (which runs
    -- once at boot via init.lua's _core loop), NOT in _apply_cfg (which
    -- re-runs on every reload) so the listener list cannot grow per
    -- reload. Mirrors blocklist/whitelist; guarded for unit tests that
    -- stub cfg without registerevent.
    if type( cfg.registerevent ) == "function" then
        cfg.registerevent( "reload", _apply_cfg )
    end
end

----------------------------------// PUBLIC INTERFACE //--

return {

    init = init,

    accept_ip = accept_ip,
    release_ip = release_ip,
    handshake_started = handshake_started,
    handshake_finished = handshake_finished,
    expired_handshakes = expired_handshakes,
    user_msg = user_msg,
    user_pm = user_pm,
    user_inf = user_inf,
    user_ctm = user_ctm,
    user_search = user_search,
    record_authfail = record_authfail,
    http_token = http_token,
    http_token_retry_after = http_token_retry_after,
    http_authfail_prefix = http_authfail_prefix,
    http_authverify = http_authverify,
    tick = tick,

}
