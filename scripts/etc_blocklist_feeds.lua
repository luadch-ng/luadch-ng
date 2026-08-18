--[[

    etc_blocklist_feeds.lua v0.01 by Aybo (#78 Phase E)

    External IP/CIDR blocklist feed puller. Fetches known-bad-IP lists
    over HTTPS on a per-feed timer and pushes them into the unified
    pre-handshake blocklist (core/blocklist.lua) with source="external"
    and meta.feed=<name>, so the engine drops those IPs at TCP-accept
    before they cost a handshake.

    Built-in feeds (each independently opt-in, all OFF by default):
      - tor         : Tor exit-node list (plain IPv4, one per line)
                      https://check.torproject.org/torbulkexitlist
      - spamhaus    : Spamhaus DROP v4 (JSONL {"cidr","sblid"} per line)
                      https://www.spamhaus.org/drop/drop_v4.json
      - spamhaus_v6 : Spamhaus DROP v6 (same JSONL, drop_v6.json)
      - abuseipdb   : AbuseIPDB blacklist (top-N reported IPs, plaintext).
                      Needs an API key (Key header, env-var-first via
                      secrets); free-tier blacklist download is 5/day so
                      the interval floor is 6 h.
      - generic     : operator-supplied line-list URL (IP/CIDR per line,
                      #/; comments) - no key, no default URL.

    Design:
      - Non-blocking fetch via core/http_client (verify=peer against the
        bundled CA bundle by default). A feed's whole set is ingested in
        ONE atomic disk write via blocklist.bulk_replace - the per-CIDR
        add() would be O(N^2) and freeze the single hub thread on a real
        feed.
      - Each successful refresh REPLACES the feed's prior entries, so a
        shrinking feed leaves no stale rows. Entries carry a TTL of 2x
        the refresh interval as a backstop: a few missed refreshes do not
        instantly unblock, but a permanently-dead feed eventually expires
        out.
      - Per-feed refresh interval, clamped up to an adapter minimum (Tor
        30 min, Spamhaus 1 h - their published auto-fetch floors;
        aggressive polling gets the hub's IP firewalled by the feed).
      - Self-healing: a fetch / parse / HTTP failure leaves the last-good
        entries in place (bulk_replace refuses to wipe a feed with an
        all-invalid parse) and fires a feed.refresh.fail audit.

    Listener-chain note: this plugin is a store WRITER, not a connect-
    time filter (the engine blocks pre-handshake), so it does NOT
    register onConnect and its position in cfg.scripts is not load-bearing
    beyond needing etc_report / the command cores loaded first. Ships
    alongside the #78 cluster (after etc_geoip).

    Public surface (getters, NOT direct exports - survive +reload):
      get_status()  -> feed status table (used by +blfeeds + the HTTP API)

    Operator control:
      +blfeeds                show each feed's state + last refresh
      GET /v1/blocklist/feeds same, read-only (policy is cfg-driven)

    v0.02:
      - +reload no longer re-pulls a feed that was fetched less than its
        interval ago. The last-fetch time is now persisted to
        scripts/data/etc_blocklist_feeds.tbl, and onStart schedules the
        next pull at last_fetch + interval instead of a few seconds after
        boot - so an operator making several config edits + reloading each
        time can no longer hammer the provider into an IP ban.

    v0.01:
      - initial: tor + spamhaus(+v6) + abuseipdb (API key via secrets) +
        generic operator-URL adapters, RAM-mode fetch, bulk_replace
        ingest, TTL backstop, +blfeeds status + HTTP mirror.

]]--

--------------
--[SETTINGS]--
--------------

local scriptname = "etc_blocklist_feeds"
local scriptversion = "0.02"

local cmd_status = "blfeeds"

--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }
local _ = lang_err and hub.debug( lang_err )

local enabled = cfg.get( "etc_blocklist_feeds_enabled" )

local oplevel = cfg.get( "etc_blocklist_feeds_oplevel" ) or 80

local report_activate = cfg.get( "etc_blocklist_feeds_report" )
local report_hubbot   = cfg.get( "etc_blocklist_feeds_report_hubbot" )
local report_opchat   = cfg.get( "etc_blocklist_feeds_report_opchat" )
local report_llevel   = cfg.get( "etc_blocklist_feeds_llevel" ) or 80

local report = hub.import( "etc_report" )

--// table lookups
local hub_import   = hub.import
local hub_debug    = hub.debug
local hub_getbot   = hub.getbot
local utf_format   = utf.format
local os_time      = os.time
local table_concat = table.concat
local math_max     = math.max
local math_min     = math.min
local math_floor   = math.floor
local util_savetable = util.savetable
local util_loadtable = util.loadtable
local io_open      = io.open

--// lang
local msg_denied       = lang.msg_denied       or "You are not allowed to use this command."
local msg_refresh_ok   = lang.msg_refresh_ok   or "etc_blocklist_feeds.lua: feed '%s' refreshed: +%d / -%d entries (%d skipped)."
local msg_refresh_fail = lang.msg_refresh_fail  or "etc_blocklist_feeds.lua: feed '%s' refresh FAILED: %s (keeping last-good entries)."
local msg_clamped      = lang.msg_clamped      or "etc_blocklist_feeds.lua: feed '%s' refresh interval raised to the %ds minimum (feed policy)."
local msg_abuseipdb_no_key = lang.msg_abuseipdb_no_key or "etc_blocklist_feeds.lua: abuseipdb feed is enabled but no API key is set (cfg '%s' or the LUADCH_* env var) - the feed is disabled."
local msg_report_ok    = lang.msg_report_ok    or "[ FEEDS ]--> Feed '%s' updated: %d entries now active."
local msg_report_fail  = lang.msg_report_fail  or "[ FEEDS ]--> Feed '%s' refresh FAILED: %s"

local msg_status_header = lang.msg_status_header or "\n=== BLOCKLIST FEEDS STATUS ==="
local msg_status_footer = lang.msg_status_footer or "=== END ===\n"
local msg_status_master = lang.msg_status_master or "  plugin enabled:  %s"
local msg_status_feed   = lang.msg_status_feed   or "  [%s] enabled=%s  interval=%ds  entries=%d  last=%s"

-- +blfeeds / etc_usercommands / cmd_help texts
local help_title = lang.help_title or "etc_blocklist_feeds.lua - external blocklist feeds"
local help_usage = lang.help_usage or "[+!#]blfeeds"
local help_desc  = lang.help_desc  or "Show external-feed status: per-feed enabled state, interval, entry count, last refresh."
local ucmd_menu  = lang.ucmd_menu  or { "Hub", "Blocklist", "Feeds status" }


----------
--[CODE]--
----------

-- Feed runtime state, built at load from the per-adapter cfg keys. Each:
-- name, enabled, url, interval (clamped), stealth, parse fn, max_response,
-- next_refresh (os.time deadline), in_flight, last (last-refresh status).
local feeds = { }

-- Persisted per-feed last-fetch timestamp (unix epoch). The in-memory
-- next_refresh is wiped on +reload, so WITHOUT this a reload would re-pull
-- every feed a few seconds after boot - and an operator making several
-- config edits + reloading each time would hammer the provider (Spamhaus
-- firewalls IPs that fetch more than once per 12 h; AbuseIPDB has a daily
-- quota). This small table survives reload so onStart can schedule the
-- NEXT pull at last_fetch + interval instead of re-pulling now.
local STATE_FILE = "scripts/data/etc_blocklist_feeds.tbl"
local fetched_at = { }    -- { [feedname] = epoch }, (re)loaded in onStart

local function load_fetched_at( )
    -- peek with io.open first to avoid a first-run checkfile log line
    -- (mirrors etc_geoip's load_update_state)
    local f = io_open( STATE_FILE, "r" )
    if not f then return { } end
    f:close( )
    local t = util_loadtable( STATE_FILE )
    return ( type( t ) == "table" ) and t or { }
end

local function mark_fetched( name )
    fetched_at[ name ] = os_time( )
    util_savetable( fetched_at, "fetched_at", STATE_FILE )
end


------------------
--[FEED PARSERS]--
------------------

-- Parse a plain-text IP/CIDR list (Tor exit list, generic feeds) into an
-- array of CIDR strings. Byte-oriented (string methods, not the utf
-- shim): CRLF-tolerant, skips blank + whole-line #/; comment lines, and
-- strips an inline trailing "; ..." / "# ..." comment (legacy Spamhaus
-- TXT style "1.2.3.0/24 ; SBL123"). No IPv6 line uses # or ; so this is
-- safe for v6 too. bulk_replace validates + caps each CIDR downstream.
local function parse_line_list( body )
    local out = { }
    for raw in body:gmatch( "[^\r\n]+" ) do
        local line = raw:gsub( "%s*[#;].*$", "" ):gsub( "^%s+", "" ):gsub( "%s+$", "" )
        -- A valid IP/CIDR is <= 43 chars (max v6 /128); anything longer is
        -- not a CIDR, so skip it rather than hand junk to the store parser
        -- (bounds the value explicitly per DEVELOPMENT.md s5).
        if line ~= "" and #line <= 64 then out[ #out + 1 ] = line end
    end
    return out
end

-- Parse Spamhaus drop_v4.json / drop_v6.json. These are JSONL: one JSON
-- object per line, {"cidr":"1.2.3.0/24","sblid":"SBL123","rir":"..."},
-- plus a trailing {"type":"metadata",...} line. Extract .cidr, keep the
-- .sblid in meta. A line that fails to decode or has no .cidr (the
-- metadata line, a truncated line) is silently skipped - bulk_replace's
-- refuse-on-all-invalid guard catches a wholesale parse failure.
local function parse_spamhaus_json( body )
    local out = { }
    for raw in body:gmatch( "[^\r\n]+" ) do
        -- pcall the decode: dkjson RETURNS (nil, err) on ordinary malformed
        -- lines (skipped), but THROWS on a deep-nesting stack overflow. An
        -- unguarded throw would abort the whole feed AND skip the _fail
        -- path (per DEVELOPMENT.md s5: degrade to a skip at the parser).
        local ok, obj = pcall( dkjson.decode, raw )
        -- cidr bounded to <= 64 chars (a valid CIDR is <= 43); a longer
        -- value is not a CIDR - skip rather than store/parse junk.
        if ok and type( obj ) == "table" and type( obj.cidr ) == "string" and #obj.cidr <= 64 then
            -- sblid is untrusted feed content. Keep ONLY a bounded scalar
            -- string: bulk_replace's contract is "meta must be flat scalars"
            -- (a nested/large table would be serialized into the shared
            -- store .tbl and can make it unloadable on the next reload,
            -- wiping every entry incl. manual pins). Real SBL ids are ~10
            -- chars; 64 is generous headroom.
            local sblid = ( type( obj.sblid ) == "string" ) and obj.sblid:sub( 1, 64 ) or nil
            out[ #out + 1 ] = { cidr = obj.cidr, meta = { sblid = sblid } }
        end
    end
    return out
end


---------------------
--[REFRESH MACHINE]--
---------------------

local function _fail( f, err )
    -- Alert opchat only on the first failure and on an ok->fail
    -- transition, so a persistently-dead feed does not spam the op chat
    -- every interval. The debug log + audit fire on every failure (they
    -- are logs; the interval is >= 30 min so they are not noisy).
    local was_ok = ( f.last == nil ) or ( f.last.ok == true )
    f.last = { ok = false, at = os_time( ), err = tostring( err ) }
    hub_debug( utf_format( msg_refresh_fail, f.name, tostring( err ) ) )
    if audit then
        audit.fire( audit.build( "feed.refresh.fail", scriptname, nil, nil,
            { feed = f.name, url = f.url, err = tostring( err ) } ) )
    end
    if report and report_activate and was_ok then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel,
            utf_format( msg_report_fail, f.name, tostring( err ) ) )
    end
end

-- Push a freshly-fetched entry set into the store (one atomic write) and
-- record the result. TTL = 2x the refresh interval (unix-epoch absolute,
-- comparable to socket.gettime() which the engine uses), so a couple of
-- missed refreshes do not instantly unblock but a dead feed ages out.
local function _apply( f, entries )
    -- An empty parse from a 200 is a SOFT FAILURE, not an intended clear:
    -- empty body, all-comment body, a mid-transfer close, or a feed FORMAT
    -- change (e.g. Spamhaus shipping one JSON array instead of JSONL) all
    -- yield zero entries. bulk_replace's refuse-to-wipe guard only fires
    -- when the input was non-empty-but-all-invalid, so it would treat
    -- n_entries==0 as a deliberate wipe and fail-open the feed. Keep the
    -- last-good entries instead (they TTL-expire if the feed stays dead).
    if #entries == 0 then
        _fail( f, "fetched 0 valid entries (empty body or feed format change?)" )
        return
    end
    local now = os_time( )
    local ok, stats, err = blocklist.bulk_replace( "external", f.name, entries, {
        stealth    = f.stealth,
        expires_at = now + 2 * f.interval,
    } )
    if not ok then
        _fail( f, err or "bulk_replace failed" )
        return
    end
    local was_failing = ( f.last == nil ) or ( f.last.ok == false )
    f.last = { ok = true, at = now, added = stats.added, removed = stats.removed, skipped = stats.skipped }
    hub_debug( utf_format( msg_refresh_ok, f.name, stats.added, stats.removed, stats.skipped ) )
    if audit then
        audit.fire( audit.build( "feed.refresh.success", scriptname, nil, nil, {
            feed = f.name, url = f.url, added = stats.added, removed = stats.removed,
            skipped = stats.skipped, too_broad = stats.too_broad,
        } ) )
    end
    -- Debounce the op-chat report like _fail does: only on the first
    -- refresh and on recovery (fail->ok). bulk_replace replaces the whole
    -- set every time, so added/removed are always nonzero and cannot
    -- signal a real change - reporting every steady-state refresh would
    -- spam op-chat (~48 lines/day for a 30-min feed).
    if report and report_activate and was_failing then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel,
            utf_format( msg_report_ok, f.name, stats.added ) )
    end
end

-- Kick off one non-blocking fetch for a feed. The in_flight guard stops
-- a slow refresh from overlapping the next timer tick. A synchronous
-- request() rejection (bad url / in-flight cap) is handled too, else the
-- feed would stay in_flight forever.
local function refresh_feed( f )
    if f.in_flight then return end
    f.in_flight = true
    local ok, rerr = http_client.request{
        url          = f.url,
        headers      = f.headers,      -- e.g. AbuseIPDB's Key + Accept
        max_response = f.max_response,
        timeout      = 30,
        on_complete  = function( res )
            f.in_flight = false
            if res.status ~= 200 then
                _fail( f, "HTTP status " .. tostring( res.status ) )
                return
            end
            local body = res.body or ""
            -- RAM mode (unlike http_client's download_to_file path) has no
            -- built-in short-read guard: a mid-transfer close returns a 200
            -- with a truncated body. If the server declared a Content-Length,
            -- verify we got it all, else a truncated set would replace the
            -- good feed. Mismatch -> soft failure, keep last-good.
            local cl = tonumber( res.headers and res.headers[ "content-length" ] )
            if cl and #body ~= cl then
                _fail( f, "truncated response (" .. #body .. " of " .. cl .. " bytes)" )
                return
            end
            -- pcall the parse: a parser throw would otherwise be swallowed
            -- by http_client's callback pcall WITHOUT firing _fail.
            local pok, entries = pcall( f.parse, body )
            if not pok then
                _fail( f, "parse error: " .. tostring( entries ) )
                return
            end
            _apply( f, entries )
        end,
        on_error     = function( err )
            f.in_flight = false
            _fail( f, tostring( err ) )
        end,
    }
    if not ok then
        f.in_flight = false
        _fail( f, tostring( rerr or "request rejected" ) )
    else
        -- a request actually went out to the provider; record the time so
        -- a +reload within the interval reschedules instead of re-pulling.
        -- The synchronous-rejection branch above sent nothing to the
        -- provider, so it does NOT mark - a reload then re-pulls promptly
        -- (there was no real fetch to throttle). Note this marks on a
        -- FAILED fetch too (429/500/timeout still hit the provider), which
        -- is deliberate: those are exactly who a reload-loop must not hammer.
        mark_fetched( f.name )
    end
end


-----------------
--[FEED SETUP]--
-----------------

-- Register one built-in feed from its per-adapter cfg keys. The refresh
-- interval is clamped UP to the adapter minimum (the feed provider's
-- published auto-fetch floor) regardless of the operator value - polling
-- faster gets the hub's IP firewalled by the provider.
local function add_feed( name, cfg_enabled, url, interval_cfg, min_interval, stealth, parse_fn, max_resp, headers )
    if type( url ) ~= "string" or url == "" then return end
    local raw = tonumber( interval_cfg ) or min_interval
    local interval = math_max( math_floor( raw ), min_interval )
    if raw < min_interval then
        hub_debug( utf_format( msg_clamped, name, min_interval ) )
    end
    feeds[ #feeds + 1 ] = {
        name = name, enabled = cfg_enabled and true or false, url = url,
        interval = interval, stealth = stealth and true or false,
        parse = parse_fn, max_response = max_resp, headers = headers,
        next_refresh = 0, in_flight = false, last = nil,
    }
end

add_feed( "tor",
    cfg.get( "etc_blocklist_feeds_tor_enabled" ),
    cfg.get( "etc_blocklist_feeds_tor_url" ) or "https://check.torproject.org/torbulkexitlist",
    cfg.get( "etc_blocklist_feeds_tor_refresh_interval_sec" ), 1800,
    cfg.get( "etc_blocklist_feeds_tor_stealth" ),
    parse_line_list, 256 * 1024 )

add_feed( "spamhaus",
    cfg.get( "etc_blocklist_feeds_spamhaus_enabled" ),
    cfg.get( "etc_blocklist_feeds_spamhaus_url" ) or "https://www.spamhaus.org/drop/drop_v4.json",
    cfg.get( "etc_blocklist_feeds_spamhaus_refresh_interval_sec" ), 3600,
    cfg.get( "etc_blocklist_feeds_spamhaus_stealth" ),
    parse_spamhaus_json, 1024 * 1024 )

add_feed( "spamhaus_v6",
    cfg.get( "etc_blocklist_feeds_spamhaus_v6_enabled" ),
    cfg.get( "etc_blocklist_feeds_spamhaus_v6_url" ) or "https://www.spamhaus.org/drop/drop_v6.json",
    cfg.get( "etc_blocklist_feeds_spamhaus_refresh_interval_sec" ), 3600,   -- shares spamhaus interval
    cfg.get( "etc_blocklist_feeds_spamhaus_stealth" ),                       -- shares spamhaus stealth
    parse_spamhaus_json, 1024 * 1024 )

-- AbuseIPDB blacklist (top-N most-reported IPs, free tier = 10k, plain
-- text one IP per line via ?plaintext). Needs an API key sent in the
-- `Key` header - env-var-first via secrets.lookup (Docker-friendly), cfg
-- fallback. If the feed is enabled but no key is set, do NOT schedule it
-- (it would 401 every interval) - warn once. The blacklist DOWNLOAD
-- endpoint is capped at 5 requests/day on the free tier (a separate limit
-- from the 1000 check/report + 100 check-block quotas), so the interval
-- floor is 6 h (= 4 pulls/day, safely under 5).
local abuseipdb_key     = secrets.lookup( "etc_blocklist_feeds_abuseipdb_key" )
local abuseipdb_enabled = cfg.get( "etc_blocklist_feeds_abuseipdb_enabled" ) and true or false
if abuseipdb_enabled and not abuseipdb_key then
    hub_debug( utf_format( msg_abuseipdb_no_key, "etc_blocklist_feeds_abuseipdb_key" ) )
    abuseipdb_enabled = false
end
add_feed( "abuseipdb",
    abuseipdb_enabled,
    cfg.get( "etc_blocklist_feeds_abuseipdb_url" ) or "https://api.abuseipdb.com/api/v2/blacklist?plaintext",
    cfg.get( "etc_blocklist_feeds_abuseipdb_refresh_interval_sec" ), 21600,
    cfg.get( "etc_blocklist_feeds_abuseipdb_stealth" ),
    parse_line_list, 1024 * 1024,
    abuseipdb_key and { Key = abuseipdb_key, Accept = "text/plain" } or nil )

-- Generic operator-supplied line list (one IP/CIDR per line, #/; comments
-- tolerated). No default URL - an operator who enables it must set one;
-- add_feed skips a feed with an empty url. No API key.
add_feed( "generic",
    cfg.get( "etc_blocklist_feeds_generic_enabled" ),
    cfg.get( "etc_blocklist_feeds_generic_url" ) or "",
    cfg.get( "etc_blocklist_feeds_generic_refresh_interval_sec" ), 300,
    cfg.get( "etc_blocklist_feeds_generic_stealth" ),
    parse_line_list, 1024 * 1024 )


------------
--[STATUS]--
------------

-- Count entries per feed in a SINGLE store scan (list() has no meta
-- filter, so group source="external" rows by meta.feed client-side). One
-- pass for all feeds, not one list() call per feed.
local function feed_counts( )
    local counts = { }
    for _, r in ipairs( blocklist.list{ source = "external" } ) do
        local fn = r.meta and r.meta.feed
        if fn then counts[ fn ] = ( counts[ fn ] or 0 ) + 1 end
    end
    return counts
end

local function get_status( )
    local counts = feed_counts( )
    local out = { enabled = enabled and true or false, feeds = { } }
    for _, f in ipairs( feeds ) do
        local last
        if f.last then
            last = { ok = f.last.ok, at = f.last.at, added = f.last.added,
                     removed = f.last.removed, skipped = f.last.skipped, err = f.last.err }
        end
        out.feeds[ #out.feeds + 1 ] = {
            name = f.name, enabled = f.enabled, url = f.url,
            interval_sec = f.interval, stealth = f.stealth,
            entries = counts[ f.name ] or 0, last = last,
        }
    end
    return out
end

local function format_status( )
    local s = get_status( )
    local lines = { msg_status_header, "" }
    lines[ #lines + 1 ] = utf_format( msg_status_master, tostring( s.enabled ) )
    for _, f in ipairs( s.feeds ) do
        local last_str = "never"
        if f.last then
            if f.last.ok then
                last_str = "ok +" .. tostring( f.last.added ) .. " / -" .. tostring( f.last.removed )
            else
                last_str = "FAIL: " .. tostring( f.last.err )
            end
        end
        lines[ #lines + 1 ] = utf_format( msg_status_feed, f.name,
            tostring( f.enabled ), f.interval_sec, f.entries, last_str )
    end
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_status_footer
    return table_concat( lines, "\n" )
end


------------------
--[ADC HANDLERS]--
------------------

local on_blfeeds = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    -- 3-arg reply -> DMSG so the multi-line status lands in the operator's
    -- PM window (AirDC++ renders multi-line DMSG where BMSG shows empty).
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
--[LISTENERS]--
-----------------

hub.setlistener( "onTimer", { },
    function( )
        if not enabled then return end
        local now = os_time( )
        for _, f in ipairs( feeds ) do
            if f.enabled and now >= f.next_refresh then
                f.next_refresh = now + f.interval
                refresh_feed( f )
            end
        end
    end
)

hub.setlistener( "onStart", { },
    function( )
        -- Register the AbuseIPDB API key as a secret so GET /v1/config
        -- redacts it (idempotent). Redaction is active only once this
        -- plugin is loaded; the LUADCH_* env var is never dumped either
        -- way, so it is the safer place for the key.
        -- api_writable: a third-party AbuseIPDB credential the operator may set from the
        -- WebUI (masked write, #178) - not the hub's own auth/crypto material.
        if secrets.register then secrets.register( "etc_blocklist_feeds_abuseipdb_key", { api_writable = true } ) end

        -- Seed each enabled feed's next refresh. Honour the PERSISTED last
        -- fetch across +reload: a feed pulled less than its interval ago is
        -- scheduled at last_fetch + interval (in the future) rather than
        -- re-pulled now, so repeated reloads never hammer the provider. A
        -- feed never fetched, overdue, or carrying a bogus future timestamp
        -- (clock skew / a corrupt state file) is staggered a few seconds
        -- after boot - the min() caps a future value to one interval so it
        -- can never freeze the feed indefinitely.
        fetched_at = load_fetched_at( )
        local now = os_time( )
        local stagger = 0
        for _, f in ipairs( feeds ) do
            if f.enabled then
                local last = tonumber( fetched_at[ f.name ] )
                if last and last + f.interval > now then
                    f.next_refresh = math_min( last + f.interval, now + f.interval )
                else
                    stagger = stagger + 3
                    f.next_refresh = now + stagger
                end
            end
        end

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd_status, { }, { "CT1" }, oplevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_status, on_blfeeds, oplevel ) )

        -- Read-only HTTP status mirror. No write endpoint: which feeds run
        -- is cfg-driven (edited in cfg.tbl + reload), not a mutable store.
        -- Raw hub.http_register because there is no SID target.
        if hub.http_register then
            hub.http_register( "GET", "/v1/blocklist/feeds", "read", http_get_status, {
                plugin = scriptname,
                description = "External blocklist feed status: per-feed enabled state, interval, entry count, last refresh (= ADC `+blfeeds`)",
                response_schema = {
                    enabled = { type = "boolean", required = true },
                    feeds   = { type = "array",   required = true },
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

    -- exposed for unit tests
    _parse_line_list     = parse_line_list,
    _parse_spamhaus_json = parse_spamhaus_json,

}
