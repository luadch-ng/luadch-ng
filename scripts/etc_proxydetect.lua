--[[

    etc_proxydetect.lua v0.01 by Aybo

    Phase F of the unified-blocklist arc (#78, closes #352). Live
    proxy / VPN / Tor detection: on connect the client IP is looked up
    against an external provider API and, if it is a proxy/VPN/Tor exit
    of a type the operator blocks, the connection is kicked
    (`etc_proxydetect_action = "block"`) or just logged
    (`= "log_only"`, the default - observe before you enforce).

    ============================ DESIGN ============================

    - PROVIDER lookup is a NON-BLOCKING outbound HTTPS request
      (core/http_client.lua). The verdict therefore arrives LATER, in
      a callback - so unlike the SYNCHRONOUS connect filters
      (etc_geoip / etc_clientblocker, which decide inside the listener
      and `return PROCESSED`) this plugin STRUCTURALLY lets the
      connection through first and kicks later from the callback. That
      "default-allow, kick-later" flow has no other precedent in the
      hub; the callback re-resolves the user from the SID captured at
      connect (`hub.issidonline`) and guards SID-reuse via the CID -
      it NEVER calls a method on the user object closed over from the
      listener (which may be stale / freed by the time the reply lands).

    - STORE-PUSH HYBRID (vs a plain per-connection kick): on a positive
      verdict in `block` mode the plugin BOTH kicks the live user AND
      pushes the IP into core/blocklist.lua with a TTL and
      source=<provider>. The pre-handshake accept-hook
      (blocklist.check_ip) then STEALTH-DROPS the NEXT connection from
      that IP before onConnect even fires - no second API call, no
      handshake cost, and it survives +reload / restart because the
      blocklist store is persisted. So the blocklist store doubles as
      the persistent, cross-reload, pre-handshake POSITIVE cache.
      `log_only` mode does NOT push (it must not block anything).

    - A local `scripts/data/etc_proxydetect.tbl` caches verdicts (mainly
      CLEAN ones, which the store does not hold) so a reconnecting
      legitimate user does not burn a provider query every time. The
      cache stores the raw detected TYPES; the block decision is
      re-evaluated against the live `etc_proxydetect_block_types` on
      every hit, so changing the policy takes effect without waiting
      for a cache entry to expire.

    - FAIL-OPEN by default (`etc_proxydetect_fail_open = true`): a
      provider outage / timeout / quota exhaustion lets the connection
      IN rather than locking every joining user out behind a broken
      external dependency in the connect path. Operators who want
      strictness set it false (kick on provider error) - documented as
      the riskier mode.

    - A daily query cap (`etc_proxydetect_max_queries_per_day`) is a
      quota / cost safety valve: a flood of DISTINCT IPs (each a cache
      miss) could otherwise exhaust the free tier or run up a paid bill.
      Over the cap -> skip the query and fail-open.

    - SSRF: the client IP is the only untrusted value that reaches the
      request URL. It is strictly validated (v4 octet range / v6
      hex+colon charset, length-capped) BEFORE interpolation, and the
      endpoint host is a fixed per-adapter constant - never operator-
      or client-supplied. core/ipmatch is not in the plugin sandbox, so
      the validator is local.

    - CONCURRENCY LIMIT (best-effort, by design): while one IP's lookup
      is in flight, further connections from the same IP are deduped to
      that single query (for quota), so when the verdict lands only the
      connection that TRIGGERED the query is kicked. Other sessions that
      arrived from that IP during the ~query window stay for their
      session; they are caught on their NEXT connection by the
      pre-handshake store block (block mode). log_only is the default, so
      this is acceptable (best-effort); a kick-all-same-IP pass (enumerating
      online users) is a possible follow-up once the getusers()-at-connect
      timing is verified.

    - operators are exempt by default via `etc_proxydetect_check_levels`
      (mirrors etc_geoip / etc_clientblocker) so a provider false
      positive cannot lock staff out.

    - PROVIDER T&C (surfaced to the operator at load + in docs/BLOCKLIST.md):
        proxycheck.io   - 1000/day free (100 keyless); commercial use on
                          the free tier is NOT explicitly granted.
        VPNAPI.io       - 1000/day free, but PERSONAL / NON-COMMERCIAL only.
        IPQualityScore  - 1000/MONTH free (35/day), EVALUATION only.
      A run of provider failures fires one op-chat alert
      (etc_proxydetect_fail_alert_threshold) so a down provider / bad key
      does not degrade detection silently.

    Public surface (getters, NOT direct exports, to survive +reload
    rebinds - the #239 / #238 hazard):

        get_status() -> table
            snapshot for `+proxydetect` / GET /v1/proxydetect / tests.

        classify(parsed) -> types_table
            adapter interpretation of a decoded provider body (nil when
            no adapter is active); primary use is the unit test.

    Listener-chain note: place AFTER `hub_inf_manager.lua` in
    cfg.scripts, like etc_geoip / etc_clientblocker - structural INF
    validation is a precondition for any connect-time policy filter.

    v0.01: by Aybo
        - initial implementation, Part of #78 (Phase F1: framework +
          proxycheck.io adapter).
    v0.02: by Aybo
        - Phase F2 (closes #352): VPNAPI.io + IPQualityScore adapters
          (key kept out of the failure log via http_client `log_url`) +
          op-chat alert on a run of provider failures.
    v0.03: by Aybo
        - #504: the op-chat report + audit now carry the connect-time
          nick as a fallback. The async verdict re-resolves the user by
          SID; a connection that dropped before the reply landed (common
          for short-lived hosting/proxy IPs) resolved to nil, so the
          report rendered "The user ? with IP ...". The nick is now
          captured at connect and threaded through as a fallback.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_proxydetect"
local scriptversion = "0.03"

local cmd_status = "proxydetect"

local cache_file = "scripts/data/etc_proxydetect.tbl"

-- How often (seconds) the dirty verdict cache is flushed to disk +
-- swept of expired rows. Keeps a connect-heavy hub from writing the
-- cache on every new verdict.
local CACHE_FLUSH_INTERVAL = 60

-- Hard ceiling on cached verdicts. With a non-zero daily query cap the
-- cache self-bounds (a verdict only lands after a capped query), but
-- max_queries_per_day = 0 (unlimited) removes that bound - a distinct-IP
-- flood would otherwise grow the cache without limit. At the ceiling a
-- new verdict evicts one arbitrary existing entry (O(1), best-effort,
-- like core/blocklist.lua's rollup LRU cap).
local MAX_CACHE_ENTRIES = 20000

-- Rolling window for the daily query cap.
local QUERY_WINDOW_SEC = 86400

-- Rolling window (seconds) for the provider-failure alert: this many
-- failures within the window fires ONE op-chat alert (debounced until a
-- success), so ops learn the provider is down / the key is bad.
local FAIL_ALERT_WINDOW = 60


--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }
local _ = lang_err and hub.debug( lang_err )

local enabled          = cfg.get( "etc_proxydetect_enabled" )
local provider_name    = cfg.get( "etc_proxydetect_provider" ) or "proxycheck"
local action           = cfg.get( "etc_proxydetect_action" ) or "log_only"
local block_types_cfg  = cfg.get( "etc_proxydetect_block_types" ) or { }
local check_levels     = cfg.get( "etc_proxydetect_check_levels" ) or { }
local cache_ttl        = cfg.get( "etc_proxydetect_cache_ttl_sec" ) or 86400
local query_timeout    = cfg.get( "etc_proxydetect_query_timeout_sec" ) or 5
local fail_open        = cfg.get( "etc_proxydetect_fail_open" )
local stealth          = cfg.get( "etc_proxydetect_stealth" )
local max_per_day      = cfg.get( "etc_proxydetect_max_queries_per_day" ) or 1000
local fail_alert_threshold = cfg.get( "etc_proxydetect_fail_alert_threshold" ) or 10
local oplevel          = cfg.get( "etc_proxydetect_oplevel" ) or 80

local report_activate  = cfg.get( "etc_proxydetect_report" )
local report_hubbot    = cfg.get( "etc_proxydetect_report_hubbot" )
local report_opchat    = cfg.get( "etc_proxydetect_report_opchat" )
local report_llevel    = cfg.get( "etc_proxydetect_llevel" ) or 60

local report = hub.import( "etc_report" )


--// table lookups
local hub_escapeto    = hub.escapeto
local hub_getbot      = hub.getbot
local hub_import      = hub.import
local hub_debug       = hub.debug
local hub_issidonline = hub.issidonline
local utf_format      = utf.format
local socket_gettime  = socket.gettime
local table_concat    = table.concat
local table_sort      = table.sort
local dkjson_decode   = dkjson.decode
local util_loadtable  = util.loadtable
local util_savetable  = util.savetable
local io_open         = io.open


--// lang
local msg_denied      = lang.msg_denied or "You are not allowed to use this command."
-- Kick text is operator POLICY, so cfg is the single source of truth
-- (mirrors etc_geoip / etc_clientblocker); a lang key would silently
-- shadow the cfg value.
local kick_reason     = cfg.get( "etc_proxydetect_kick_reason" )
                        or "Proxy / VPN / Tor connections are not permitted on this hub."
local msg_report      = lang.msg_report      or "[ PROXYDETECT ]--> The user %s with IP %s is a %s (%s). Action: %s."
local msg_provider_bad = lang.msg_provider_bad or "etc_proxydetect.lua: unknown provider '%s' - the plugin is inert. Set etc_proxydetect_provider to one of: %s."
local msg_key_missing = lang.msg_key_missing  or "etc_proxydetect.lua: provider '%s' needs an API key (etc_proxydetect_api_key or LUADCH_ETC_PROXYDETECT_API_KEY) - the plugin is inert."
local msg_tos_note    = lang.msg_tos_note     or "etc_proxydetect.lua: provider '%s' - review its free-tier terms (see docs/BLOCKLIST.md): %s."
local msg_quota       = lang.msg_quota        or "etc_proxydetect.lua: daily query cap (%d) reached - skipping lookups (fail-open) until the window resets."
local msg_fail_alert  = lang.msg_fail_alert   or "[ PROXYDETECT ]--> provider '%s' lookups failing: %d errors in %ds - detection is degraded (fail-%s)."

-- +proxydetect status lines
local msg_status_header   = lang.msg_status_header   or "\n=== PROXYDETECT STATUS ==="
local msg_status_footer   = lang.msg_status_footer   or "=== END ===\n"
local msg_status_enabled  = lang.msg_status_enabled  or "  enabled:          %s"
local msg_status_provider = lang.msg_status_provider or "  provider:         %s"
local msg_status_action   = lang.msg_status_action   or "  action:           %s"
local msg_status_btypes   = lang.msg_status_btypes   or "  blocked types:    %s"
local msg_status_failopen = lang.msg_status_failopen or "  fail-open:        %s"
local msg_status_cache    = lang.msg_status_cache    or "  cached verdicts:  %d"
local msg_status_queries  = lang.msg_status_queries  or "  queries today:    %d / %s"


----------
--[CODE]--
----------

-- Live blocked-type set, rebuilt at onStart from cfg. A detected type
-- matches only if it is present + true here.
local block_types = { }    -- ["proxy"]=true / ["vpn"]=true / ["tor"]=true

-- Verdict cache: [ip] = { expires_at = <socket.gettime deadline>, types = { proxy=true, ... } }.
-- An empty `types` table means CLEAN. Held as a file-scope upvalue,
-- reassigned at onStart, exposed only through the accessor helpers -
-- never returned by reference (the #239 / #238 rebind hazard).
local cache = { }
local cache_n = 0                        -- live entry count, kept in sync (avoids O(n) size checks)
local cache_cap = MAX_CACHE_ENTRIES      -- overridable in the unit test
local cache_dirty = false
local next_flush = 0

-- In-flight guard: an IP whose query is outstanding, so a burst of
-- connections from the same IP fires exactly one provider query.
local inflight = { }       -- ["1.2.3.4"] = true

-- Daily query cap bookkeeping.
local query_count = 0
local query_window_start = 0
local quota_warned = false

-- Provider-failure alert bookkeeping (see FAIL_ALERT_WINDOW).
local fail_count = 0
local fail_window_start = 0
local fail_alerted = false


------------------------------
--[ PROVIDER ADAPTERS ]--
------------------------------

-- Each adapter owns its endpoint (fixed host - NOT operator-supplied,
-- for SSRF), whether it needs a key, and how to turn a decoded JSON
-- body into a set of detected types.
--
--   build_request(ip, key) -> { url, method, headers, body, log_url }
--       ip is already SSRF-validated. `log_url` is a KEY-FREE url that
--       http_client logs in place of `url` on failure (Precursor F0), for
--       providers that must carry the key in the url (vpnapi query string /
--       ipqs path); proxycheck omits it (its key goes in the POST body).
--   interpret(parsed, ip) -> types_table | nil, err
--       types_table: { proxy=true, vpn=true, tor=true, ... } (empty = clean)
--       nil + err:   the provider reported an error (bad key / quota /
--                    denied) - treated as a query failure, not "clean".

local function _first_ip_record( parsed, ip )
    -- proxycheck v2 keys the per-IP object by the queried IP string;
    -- fall back to the first table-valued, non-meta entry in case the
    -- provider normalised the key (e.g. a v6 form).
    local rec = parsed[ ip ]
    if type( rec ) == "table" then return rec end
    for k, v in pairs( parsed ) do
        if type( v ) == "table" and k ~= "block" then return v end
    end
    return nil
end

local PROVIDERS = {

    proxycheck = {
        source   = "proxycheck",
        needs_key = false,    -- works keyless at 100/day; a key raises it to 1000/day
        tos      = "1000/day free (100 keyless); commercial use on the free tier not explicitly granted",
        -- Returns the http_client request fragment { url, method, headers,
        -- body }. v2 endpoint: stable + unambiguous flat response. vpn=1
        -- adds VPN/Tor discrimination; risk=1 adds a risk score. The API
        -- KEY is sent in the POST body, NOT the query string: http_client
        -- logs req.url (not req.body) on a request crash / failure
        -- (out.error/out.put), so a query-param key would leak into
        -- error.log. proxycheck accepts the key as a POST field.
        build_request = function( ip, key )
            local req = {
                url     = "https://proxycheck.io/v2/" .. ip .. "?vpn=1&risk=1",
                method  = "GET",
                headers = { [ "Accept" ] = "application/json" },
            }
            if key and key ~= "" then
                req.method = "POST"
                req.headers[ "Content-Type" ] = "application/x-www-form-urlencoded"
                req.body = "key=" .. key
            end
            return req
        end,
        interpret = function( parsed, ip )
            local status = parsed.status
            -- "ok"/"warning" carry data; "denied"/"error" mean bad key
            -- or quota -> a provider error, NOT a clean verdict.
            if status ~= "ok" and status ~= "warning" then
                return nil, tostring( status or "no status" )
            end
            local rec = _first_ip_record( parsed, ip )
            if type( rec ) ~= "table" then return { } end    -- no data = clean
            local types = { }
            if rec.proxy == "yes" then types.proxy = true end
            local t = type( rec.type ) == "string" and rec.type:lower( ) or ""
            if t == "vpn" then types.vpn = true end
            if t == "tor" then types.tor = true end
            return types
        end,
    },

    vpnapi = {
        source   = "vpnapi",
        needs_key = true,     -- no keyless tier
        tos      = "1000/day free, but the free tier is PERSONAL / NON-COMMERCIAL only - a public/community hub needs a paid plan",
        -- Key is a query param; log_url drops it so it never reaches the
        -- failure log (F0). Response: booleans under `security`.
        build_request = function( ip, key )
            return {
                url     = "https://vpnapi.io/api/" .. ip .. "?key=" .. ( key or "" ),
                log_url = "https://vpnapi.io/api/" .. ip,
                method  = "GET",
                headers = { [ "Accept" ] = "application/json" },
            }
        end,
        interpret = function( parsed, ip )
            local sec = parsed.security
            if type( sec ) ~= "table" then
                -- a valid reply always carries `security`; its absence is an
                -- error response (e.g. invalid key -> { message = ... }).
                return nil, tostring( parsed.message or "no security block" )
            end
            local types = { }
            if sec.vpn   == true then types.vpn = true end
            if sec.proxy == true then types.proxy = true end
            if sec.tor   == true then types.tor = true end
            -- `relay` (e.g. iCloud Private Relay) is its OWN type, NOT proxy.
            -- Private Relay is a privacy feature used by millions of ordinary
            -- Apple users, so it is NOT in the default block_types - an
            -- operator opts in by adding relay=true. See docs/BLOCKLIST.md.
            if sec.relay == true then types.relay = true end
            return types
        end,
    },

    ipqs = {
        source   = "ipqs",
        needs_key = true,     -- no keyless tier
        tos      = "1000/MONTH free (35/day cap); the free tier is EVALUATION only - production / commercial use needs a paid plan",
        -- Key is in the URL PATH; log_url redacts that path segment (F0).
        build_request = function( ip, key )
            return {
                url     = "https://www.ipqualityscore.com/api/json/ip/" .. ( key or "" ) .. "/" .. ip,
                log_url = "https://www.ipqualityscore.com/api/json/ip/REDACTED/" .. ip,
                method  = "GET",
                headers = { [ "Accept" ] = "application/json" },
            }
        end,
        interpret = function( parsed, ip )
            if parsed.success ~= true then
                return nil, tostring( parsed.message or "success=false" )
            end
            local types = { }
            if parsed.proxy == true then types.proxy = true end
            if parsed.vpn   == true then types.vpn = true end
            if parsed.tor   == true then types.tor = true end
            return types
        end,
    },

}

local adapter = PROVIDERS[ provider_name ]
local api_key = nil    -- resolved at onStart via secrets (env-var-first)


---------------------------
--[ IP VALIDATION (SSRF) ]--
---------------------------

local function _valid_v4( ip )
    local a, b, c, d = ip:match( "^(%d+)%.(%d+)%.(%d+)%.(%d+)$" )
    if not a then return false end
    for _, o in ipairs( { a, b, c, d } ) do
        if #o > 3 or tonumber( o ) > 255 then return false end
    end
    return true
end

local function _valid_v6( ip )
    if not ip:find( ":" ) then return false end
    if #ip > 45 then return false end
    -- hex digits + colons only; blocks every URL-structural metachar
    -- (/ ? # @ & space ...) so the IP cannot alter the request URL.
    if ip:find( "[^%x:]" ) then return false end
    return true
end

-- Normalise + validate the connecting IP for a provider query.
-- Returns (query_ip, family) or nil. v4-mapped-v6 (`::ffff:a.b.c.d`)
-- is reduced to the bare v4 so the provider looks up the real address.
local function query_ip( ip )
    if type( ip ) ~= "string" or ip == "" then return nil end
    local mapped = ip:lower( ):match( "^::ffff:(%d+%.%d+%.%d+%.%d+)$" )
    if mapped then ip = mapped end
    if _valid_v4( ip ) then return ip, 4 end
    if _valid_v6( ip ) then return ip, 6 end
    return nil
end


-----------------
--[ CACHE ]--
-----------------

local function load_cache( )
    -- Peek before util.loadtable so a fresh install / first run does
    -- not trip util.checkfile's error.log line (the #359 pattern).
    local f = io_open( cache_file, "r" )
    if not f then return { } end
    f:close( )
    local t = util_loadtable( cache_file )
    if type( t ) ~= "table" then return { } end
    -- Drop already-expired rows on load so a long downtime doesn't
    -- resurrect stale verdicts.
    local now = socket_gettime( )
    local kept = { }
    for ip, v in pairs( t ) do
        if type( v ) == "table" and type( v.expires_at ) == "number"
           and v.expires_at > now and type( v.types ) == "table" then
            kept[ ip ] = { expires_at = v.expires_at, types = v.types }
        end
    end
    return kept
end

local function cache_get( ip )
    local v = cache[ ip ]
    if not v then return nil end
    if v.expires_at <= socket_gettime( ) then
        cache[ ip ] = nil
        cache_n = cache_n - 1
        cache_dirty = true
        return nil
    end
    return v
end

local function cache_set( ip, types )
    if cache[ ip ] == nil then
        -- New key: enforce the hard ceiling before inserting so an
        -- unlimited-quota hub can't grow the cache without bound. Evict
        -- one arbitrary entry (best-effort, O(1)).
        if cache_cap > 0 and cache_n >= cache_cap then
            local k = next( cache )
            if k then cache[ k ] = nil; cache_n = cache_n - 1 end
        end
        cache_n = cache_n + 1
    end
    cache[ ip ] = { expires_at = socket_gettime( ) + cache_ttl, types = types or { } }
    cache_dirty = true
end

local function flush_cache( )
    -- Purge expired rows regardless of the dirty flag (entries can expire
    -- during an idle period with no set/get to mark the cache dirty), then
    -- persist only if something actually changed.
    local now = socket_gettime( )
    local kept, n, purged = { }, 0, false
    for ip, v in pairs( cache ) do
        if v.expires_at > now then kept[ ip ] = v; n = n + 1
        else purged = true end
    end
    cache = kept
    cache_n = n
    if cache_dirty or purged then
        util_savetable( cache, "cache", cache_file )
        cache_dirty = false
    end
end

local function cache_count( )
    return cache_n
end


-----------------
--[ QUOTA ]--
-----------------

-- Consume one query slot. Returns true if a query may run, false if
-- the daily cap is reached (0 = unlimited). Rolling 24 h window.
local function quota_allow( )
    if max_per_day <= 0 then return true end
    local now = socket_gettime( )
    if now - query_window_start >= QUERY_WINDOW_SEC then
        query_window_start = now
        query_count = 0
        quota_warned = false
    end
    if query_count >= max_per_day then
        if not quota_warned then
            quota_warned = true
            hub_debug( utf_format( msg_quota, max_per_day ) )
        end
        return false
    end
    query_count = query_count + 1
    return true
end


---------------------------
--[ VERDICT / ENFORCE ]--
---------------------------

-- Which detected types the operator actually blocks. Returns a sorted
-- list of matched type names (empty = nothing to act on).
local function matched_types( types )
    local out = { }
    for t in pairs( types ) do
        if block_types[ t ] then out[ #out + 1 ] = t end
    end
    table_sort( out )
    return out
end

-- Push a positive IP into the pre-handshake blocklist store so repeat
-- connections are dropped at accept (block mode only). Called ONLY for a
-- fresh detection - a cache hit skips it, because the original detection
-- already pushed the entry and blocklist.add does not dedup by CIDR, so
-- re-pushing would accumulate duplicate rows + a full-store disk rewrite
-- each time.
local function store_push( ip, family, matched, provider )
    local cidr = ip .. ( family == 6 and "/128" or "/32" )
    blocklist.add( cidr, {
        source     = provider,
        reason     = "proxy/VPN detected (" .. provider .. ")",
        stealth    = stealth and true or false,
        expires_at = socket_gettime( ) + cache_ttl,
        meta       = { provider = provider, type = matched[ 1 ] },
    } )
end

-- Act on a positive verdict. `user` may be nil (the connection already
-- left by the time an async lookup returned) - we still audit / report
-- / cache / store-push for observability + future pre-handshake blocks;
-- we only KICK when the user is still live.
local function apply_positive( user, ip, family, types, matched, cached, last_nick )
    local matched_str = table_concat( matched, "," )
    -- `user` is nil when the connection dropped before the async verdict
    -- returned (the SID re-resolve found nobody). `last_nick` is the nick
    -- captured at connect time, used as a fallback so the report + audit
    -- still name who was flagged instead of rendering "?" (#504). Stored
    -- in `meta.nick` too so log consumers have an always-present nick even
    -- when the audit target snapshot is absent (the dropped-user case);
    -- it intentionally overlaps the target snapshot for a live user.
    local nick = ( user and user:nick( ) ) or last_nick or "?"
    if audit then
        audit.fire( audit.build( "proxydetect.block", scriptname, user, kick_reason,
            { ip = ip, provider = adapter.source, types = matched_str,
              action = action, cached = cached and true or false, nick = nick } ) )
    end
    if report then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel,
            utf_format( msg_report, nick, ip, matched_str,
                adapter.source, action ) )
    end
    if action == "block" then
        if not cached then store_push( ip, family, matched, adapter.source ) end
        if user then
            user:kill( "ISTA 231 " .. hub_escapeto( kick_reason ) .. " TL-1\n" )
        end
    end
end

-- A run of failures within FAIL_ALERT_WINDOW fires ONE op-chat alert so
-- ops notice a down provider / bad key instead of silent degradation.
-- A single success resets the counter (recovery).
local function note_success( )
    fail_count = 0
    fail_alerted = false
end

local function note_failure( provider )
    if fail_alert_threshold <= 0 then return end
    local now = socket_gettime( )
    if now - fail_window_start >= FAIL_ALERT_WINDOW then
        fail_window_start = now
        fail_count = 0
        -- fail_alerted is intentionally NOT reset here: a window rollover
        -- restarts the count but must not re-arm the alert, or a sustained
        -- outage would spam op-chat once per window. Only note_success (a
        -- recovered lookup) clears it, so an outage yields exactly ONE alert.
    end
    fail_count = fail_count + 1
    if fail_count >= fail_alert_threshold and not fail_alerted then
        fail_alerted = true
        if report then
            report.send( report_activate, report_hubbot, report_opchat, report_llevel,
                utf_format( msg_fail_alert, provider, fail_count, FAIL_ALERT_WINDOW,
                    fail_open and "open" or "closed" ) )
        end
        if audit then
            audit.fire( audit.build( "proxydetect.provider.down", scriptname, nil, nil,
                { provider = provider, failures = fail_count, window = FAIL_ALERT_WINDOW } ) )
        end
    end
end

-- A provider error / timeout. Fail-open (allow) by default; fail-closed
-- kicks the still-live user (but does NOT store-push - we have no
-- verdict, only a broken provider).
local function apply_failure( sid, cid, ip, err )
    if audit then
        audit.fire( audit.build( "proxydetect.query.fail", scriptname, nil, nil,
            { ip = ip, provider = adapter and adapter.source or provider_name,
              err = tostring( err ), fail_open = fail_open and true or false } ) )
    end
    note_failure( adapter and adapter.source or provider_name )
    if fail_open then return end
    local u = hub_issidonline( sid )
    if u and u:cid( ) == cid then
        u:kill( "ISTA 231 " .. hub_escapeto( kick_reason ) .. " TL-1\n" )
    end
end


-- Adapter interpretation exposed for the unit test.
local function classify( parsed, ip )
    if not adapter then return nil end
    return adapter.interpret( parsed, ip or "" )
end


-- The async response handler. Re-resolves the user from the SID (never
-- the closed-over listener object) and guards SID reuse via the CID.
local function handle_response( res, ip, family, sid, cid, nick )
    inflight[ ip ] = nil
    if res.status ~= 200 then
        return apply_failure( sid, cid, ip, "HTTP status " .. tostring( res.status ) )
    end
    local body = res.body or ""
    -- dkjson.decode RETURNS nil on ordinary malformed input but THROWS
    -- on pathological nesting - pcall so a hostile / broken body
    -- degrades to a query failure instead of a swallowed callback error.
    local pok, parsed = pcall( dkjson_decode, body )
    if not pok or type( parsed ) ~= "table" then
        return apply_failure( sid, cid, ip, "JSON decode failed" )
    end
    -- pcall the adapter interpret too: the proxycheck/vpnapi/ipqs parsers
    -- are throw-safe today, but a provider adapter parsing untrusted JSON
    -- could throw - degrade to a query failure rather than a swallowed
    -- callback error (the untrusted-input-parser contract).
    local pok2, types, ierr = pcall( adapter.interpret, parsed, ip )
    if not pok2 then
        return apply_failure( sid, cid, ip, "interpret error: " .. tostring( types ) )
    end
    if not types then
        return apply_failure( sid, cid, ip, ierr or "provider error" )
    end

    local matched = matched_types( types )
    cache_set( ip, types )
    note_success( )    -- a good verdict clears the provider-failure alert
    if #matched == 0 then return end    -- detected-but-not-blocked, or clean

    local u = hub_issidonline( sid )
    if u and u:cid( ) ~= cid then u = nil end    -- SID reused by another client
    apply_positive( u, ip, family, types, matched, false, nick )
end


-- The onConnect check. Synchronous cache hits kick inline (return
-- PROCESSED); a cache miss fires an async query and lets the
-- connection through (kick-later from the callback).
local check_proxydetect = function( user )
    if not enabled then return end
    if not adapter then return end
    if adapter.needs_key and ( not api_key or api_key == "" ) then return end

    if not check_levels[ user:level( ) ] then return end

    local ip, family = query_ip( user:ip( ) )
    if not ip then return end    -- unparseable IP -> skip (fail-open)

    -- #78 allowlist: a whitelisted IP (trusted infra / hublist pinger)
    -- is never sent to the provider (saves the paid query), cached, or
    -- kicked. Checked before the cache + quota so a trusted IP costs
    -- nothing.
    if whitelist.is_whitelisted( ip ) then return end

    -- Cache hit: decide against the LIVE block_types (policy changes
    -- take effect without waiting for expiry).
    local c = cache_get( ip )
    if c then
        local matched = matched_types( c.types )
        if #matched == 0 then return end
        apply_positive( user, ip, family, c.types, matched, true )
        return ( action == "block" ) and PROCESSED or nil
    end

    if inflight[ ip ] then return end
    if not quota_allow( ) then return end    -- over cap -> fail-open

    inflight[ ip ] = true
    local sid, cid = user:sid( ), user:cid( )
    -- Capture the nick now, while the user is live: the async callback
    -- may re-resolve to nil if the connection drops first (#504). Empty
    -- -> nil so the "?" fallback still applies for a nickless login.
    local nick = user:nick( )
    if nick == "" then nick = nil end
    local rq = adapter.build_request( ip, api_key )
    local ok, rerr = http_client.request{
        url          = rq.url,
        method       = rq.method,
        headers      = rq.headers,
        body         = rq.body,
        log_url      = rq.log_url,    -- key-free url for the failure log (vpnapi/ipqs put the key in the url)
        timeout      = query_timeout,
        max_response = 65536,    -- provider JSON is a few KiB; bound a misbehaving one
        on_complete  = function( res ) handle_response( res, ip, family, sid, cid, nick ) end,
        on_error     = function( err )
            inflight[ ip ] = nil
            apply_failure( sid, cid, ip, err )
        end,
    }
    if not ok then
        inflight[ ip ] = nil
        -- The query never reached the provider (bad url / in-flight cap) -
        -- refund the quota slot quota_allow() consumed above.
        if max_per_day > 0 and query_count > 0 then query_count = query_count - 1 end
        apply_failure( sid, cid, ip, rerr or "request rejected" )
    end
    return nil    -- allow-pending
end


-----------------
--[ STATUS ]--
-----------------

local function get_status( )
    local btypes = { }
    for t in pairs( block_types ) do btypes[ #btypes + 1 ] = t end
    table_sort( btypes )
    return {
        enabled       = enabled and true or false,
        provider      = provider_name,
        provider_ok   = adapter and true or false,
        action        = action,
        blocked_types = btypes,
        fail_open     = fail_open and true or false,
        cached        = cache_count( ),
        queries_today = query_count,
        max_per_day   = max_per_day,
    }
end

local function format_status( )
    local s = get_status( )
    local lines = { msg_status_header, "" }
    lines[ #lines + 1 ] = utf_format( msg_status_enabled,  tostring( s.enabled ) )
    lines[ #lines + 1 ] = utf_format( msg_status_provider,
        s.provider .. ( s.provider_ok and "" or " (UNKNOWN - inert)" ) )
    lines[ #lines + 1 ] = utf_format( msg_status_action,   s.action )
    lines[ #lines + 1 ] = utf_format( msg_status_btypes,
        #s.blocked_types > 0 and table_concat( s.blocked_types, ", " ) or "(none)" )
    lines[ #lines + 1 ] = utf_format( msg_status_failopen, tostring( s.fail_open ) )
    lines[ #lines + 1 ] = utf_format( msg_status_cache,    s.cached )
    lines[ #lines + 1 ] = utf_format( msg_status_queries,  s.queries_today,
        s.max_per_day > 0 and tostring( s.max_per_day ) or "unlimited" )
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_status_footer
    return table_concat( lines, "\n" )
end


------------------
--[ADC HANDLERS]--
------------------

local on_proxydetect = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    -- 3-arg reply -> DMSG so the multi-line status shows in the
    -- operator's PM window (AirDC++ renders multi-line DMSG where BMSG
    -- appeared empty; same choice as +geoip / +blocker).
    user:reply( format_status( ), hub_getbot( ), hub_getbot( ) )
    return PROCESSED
end


-------------------
--[HTTP HANDLERS]--
-------------------

local http_get_status = function( req )
    return { status = 200, data = get_status( ) }
end


-----------------
--[LIFECYCLE ]--
-----------------

local function _build_block_types( )
    block_types = { }
    for t, on in pairs( block_types_cfg ) do
        if type( t ) == "string" and on == true then
            block_types[ t:lower( ) ] = true
        end
    end
end


hub.setlistener( "onConnect", { }, check_proxydetect )

hub.setlistener( "onTimer", { },
    function( )
        if not enabled then return end
        local now = socket_gettime( )
        if now >= next_flush then
            next_flush = now + CACHE_FLUSH_INTERVAL
            flush_cache( )
        end
    end
)

hub.setlistener( "onExit", { },
    function( )
        flush_cache( )
    end
)

hub.setlistener( "onStart", { },
    function( )
        _build_block_types( )
        cache = load_cache( )
        cache_n = 0
        for _ in pairs( cache ) do cache_n = cache_n + 1 end
        cache_dirty = false
        next_flush = socket_gettime( ) + CACHE_FLUSH_INTERVAL
        query_window_start = socket_gettime( )
        query_count = 0

        -- Register the API-key cfg key as secret so GET /v1/config
        -- redacts it + PUT /v1/config/{key} refuses it. Then resolve
        -- it env-var-first (Docker) / cfg.tbl (bare-metal).
        -- api_writable: a third-party proxy-detection provider key the operator may set
        -- from the WebUI (masked write, #178) - not the hub's own auth/crypto material.
        if secrets.register then secrets.register( "etc_proxydetect_api_key", { api_writable = true } ) end
        api_key = secrets.lookup( "etc_proxydetect_api_key" )

        -- Operator guidance at load: unknown provider / missing key /
        -- free-tier terms. Inert (no crash) when misconfigured.
        if not adapter then
            local names = { }
            for k in pairs( PROVIDERS ) do names[ #names + 1 ] = k end
            table_sort( names )
            hub_debug( utf_format( msg_provider_bad, tostring( provider_name ),
                table_concat( names, ", " ) ) )
        else
            if adapter.needs_key and ( not api_key or api_key == "" ) then
                hub_debug( utf_format( msg_key_missing, provider_name ) )
            end
            if enabled then
                hub_debug( utf_format( msg_tos_note, provider_name, adapter.tos ) )
            end
        end

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( lang.help_title or "etc_proxydetect.lua - proxy/VPN detection",
                lang.help_usage or "[+!#]proxydetect",
                lang.help_desc or "Show proxy-detection status: provider, action mode, blocked types, cache + query count.",
                oplevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( lang.ucmd_menu or { "Hub", "Proxydetect", "status" }, cmd_status, { }, { "CT1" }, oplevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_status, on_proxydetect, oplevel ) )

        -- Read-only HTTP status mirror. No write endpoint: the policy is
        -- cfg-driven (edit cfg.tbl + reload), not a mutable store. Raw
        -- hub.http_register because there is no SID target.
        if hub.http_register then
            hub.http_register( "GET", "/v1/proxydetect", "read", http_get_status, {
                plugin = scriptname,
                description = "Proxy-detection status: provider, action mode, blocked types, cache + query count (= ADC `+proxydetect`)",
                response_schema = {
                    enabled       = { type = "boolean", required = true },
                    provider      = { type = "string",  required = true },
                    provider_ok   = { type = "boolean", required = true },
                    action        = { type = "string",  required = true },
                    blocked_types = { type = "array",   required = true },
                    fail_open     = { type = "boolean", required = true },
                    cached        = { type = "number",  required = true },
                    queries_today = { type = "number",  required = true },
                    max_per_day   = { type = "number",  required = true },
                },
            } )
        end
        return nil
    end
)


hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )


--// public //--

return {

    get_status = get_status,
    classify   = classify,

    -- exposed for the unit test
    _query_ip       = query_ip,
    _matched_types  = matched_types,
    _set_cache_cap  = function( n ) cache_cap = n end,

}
