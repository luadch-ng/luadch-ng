--[[

    etc_geoip.lua v0.01 by Aybo

    Phase D2 of the unified-blocklist arc (#78). Country / ASN policy
    blocking driven by a MaxMind GeoLite2 database.

        - on every connect (post-handshake `onConnect`) the plugin
          resolves the client IP to its country (ISO-3166-1 alpha-2)
          and, if an ASN DB is configured, its autonomous-system
          number, via core/mmdb.lua. If the country is in
          `etc_geoip_blocked_countries` OR the ASN is in
          `etc_geoip_blocked_asns`, the connection is either kicked
          (`etc_geoip_action = "block"`) or just logged
          (`= "log_only"`, the default - observe before you enforce).

        - PER-CONNECTION lookup, NOT store pre-population. The mmdb
          lookup is depth-bounded (<= 128 node reads, ~tens of us) and
          runs post-handshake, so it adds nothing to the pre-handshake
          accept hot-path and never bloats the blocklist store with
          the ~6k-14k CIDRs a single country spans. Country blocking is
          policy, not DoS mitigation (that is what the pre-handshake IP
          blocklist + rate limiter are for), so a post-handshake kick -
          exactly how cmd_ban / etc_clientblocker block - is the right
          layer and gives a kick reason the user can actually see.

        - operators are exempt by default via
          `etc_geoip_check_levels` (mirrors etc_clientblocker) so a
          misconfigured country list cannot lock staff out.

        - the hub boots fine WITHOUT a database: a missing / corrupt
          `.mmdb` logs a single warning and leaves the plugin inert.
          The operator installs + refreshes the DB out-of-band with
          MaxMind's `geoipupdate` tool (see docs/BLOCKLIST.md); the
          plugin re-reads it every `etc_geoip_recheck_interval_sec`.

        - audit-fires `geoip.block` on every match (both block and
          log_only), `geoip.db.missing` once when a configured DB is
          absent, and `geoip.db.stale` once when the DB build is older
          than 30 days.

        Public surface (getters, NOT direct exports, to survive
        +reload rebinds - the #239 / #238 hazard):

            resolve(country, asn) -> reason_string | nil
                pure policy decision against the live blocked sets;
                primary use is the unit test + `+geoip` diagnostics.

            classify(ip) -> country, asn, org
                run the live readers against an IP (nil fields when a
                DB is absent or the IP is not found).

            get_status() -> table
                snapshot for `+geoip` / GET /v1/geoip / tests.

        Listener-chain note: place AFTER `hub_inf_manager.lua` in
        cfg.scripts, like etc_clientblocker - structural INF
        validation is a precondition for any connect-time policy
        filter.

        v0.02: by Aybo
            - persist the auto-update check time (scripts/data/etc_geoip.tbl)
              and schedule the next check from it across +reload, so a
              reload no longer re-checks MaxMind ~30s after boot every time
              (mirrors etc_blocklist_feeds #386).
        v0.01: by Aybo
            - initial implementation, Part of #78 (Phase D2)

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_geoip"
local scriptversion = "0.02"

local cmd_status = "geoip"

local STALE_AFTER_SEC = 30 * 24 * 3600    -- warn if the DB build is older than 30 days


--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }
local _ = lang_err and hub.debug( lang_err )

local enabled          = cfg.get( "etc_geoip_enabled" )
local country_db_path  = cfg.get( "etc_geoip_country_db_path" )
local asn_db_path      = cfg.get( "etc_geoip_asn_db_path" )
local blocked_countries_cfg = cfg.get( "etc_geoip_blocked_countries" ) or { }
local blocked_asns_cfg = cfg.get( "etc_geoip_blocked_asns" ) or { }
local action           = cfg.get( "etc_geoip_action" ) or "log_only"
local check_levels     = cfg.get( "etc_geoip_check_levels" ) or { }
local recheck_interval = cfg.get( "etc_geoip_recheck_interval_sec" ) or 3600
local oplevel          = cfg.get( "etc_geoip_oplevel" ) or 80

-- In-hub DB auto-update (#78 Phase D3). Off by default. The license key is
-- resolved env-var-first via core/secrets at onStart (not read here).
local auto_update      = cfg.get( "etc_geoip_auto_update" )
local account_id       = cfg.get( "etc_geoip_account_id" ) or ""
local edition_ids      = cfg.get( "etc_geoip_edition_ids" ) or { "GeoLite2-Country", "GeoLite2-ASN" }
local update_interval  = cfg.get( "etc_geoip_update_interval_sec" ) or 86400
local license_key      = nil    -- resolved in onStart via secrets.lookup

local report_activate  = cfg.get( "etc_geoip_report" )
local report_hubbot    = cfg.get( "etc_geoip_report_hubbot" )
local report_opchat    = cfg.get( "etc_geoip_report_opchat" )
local report_llevel    = cfg.get( "etc_geoip_llevel" ) or 80

local report = hub.import( "etc_report" )


--// table lookups
local hub_escapeto = hub.escapeto
local hub_getbot   = hub.getbot
local hub_import   = hub.import
local hub_debug    = hub.debug
local utf_format   = utf.format
local os_time      = os.time
local table_concat = table.concat
local table_sort   = table.sort
local util_loadtable = util.loadtable
local util_savetable = util.savetable
local io_open      = io.open
local out_put      = out.put


--// lang
local msg_denied      = lang.msg_denied      or "You are not allowed to use this command."
-- Kick text is operator POLICY, so cfg is the single source of truth
-- (a message the operator sets in cfg.tbl must actually take effect) -
-- not a lang key that would silently shadow it. Mirrors
-- etc_clientblocker's cfg-driven reason.
local kick_reason     = cfg.get( "etc_geoip_kick_reason" )
                        or "Your region is not permitted on this hub."
local msg_report      = lang.msg_report      or "[ GEOIP ]--> The user %s with IP %s (%s) is not permitted (%s). Action: %s."
local msg_db_missing  = lang.msg_db_missing  or "etc_geoip.lua: %s database not found at '%s' - GeoIP checks for it are disabled. Run geoipupdate (see docs/BLOCKLIST.md)."
local msg_db_stale    = lang.msg_db_stale    or "etc_geoip.lua: %s database is older than 30 days (built %s) - run geoipupdate to refresh."
local msg_db_loaded   = lang.msg_db_loaded   or "etc_geoip.lua: loaded %s database (%s, built %s)."
local msg_update_ok   = lang.msg_update_ok   or "[ GEOIP ]--> %d database(s) auto-updated from MaxMind."
local msg_update_fail = lang.msg_update_fail or "[ GEOIP ]--> database auto-update failed: %s (keeping the last-good database)."
local msg_update_recovered = lang.msg_update_recovered or "[ GEOIP ]--> database auto-update recovered."
local msg_update_missing_key = lang.msg_update_missing_key or "etc_geoip.lua: auto-update is on but no MaxMind account_id / license_key is set - see docs/BLOCKLIST.md."
local msg_update_start = lang.msg_update_start or "[ GEOIP ]--> auto-update: checking %s for updates at MaxMind..."

-- +geoip status lines
local msg_status_header   = lang.msg_status_header   or "\n=== GEOIP STATUS ==="
local msg_status_footer   = lang.msg_status_footer   or "=== END ===\n"
local msg_status_enabled  = lang.msg_status_enabled  or "  enabled:            %s"
local msg_status_action   = lang.msg_status_action   or "  action:             %s"
local msg_status_country  = lang.msg_status_country  or "  country DB:         %s"
local msg_status_asn      = lang.msg_status_asn      or "  ASN DB:             %s"
local msg_status_bcountry = lang.msg_status_bcountry or "  blocked countries:  %s"
local msg_status_basn     = lang.msg_status_basn     or "  blocked ASNs:       %s"


----------
--[CODE]--
----------

-- Live policy sets, rebuilt at onStart. Country codes are upper-cased
-- + format-validated so a lower-case cfg entry ("cn") still matches
-- the DB's upper-case iso_code.
local blocked_countries = { }    -- ["CN"] = true
local blocked_asns      = { }    -- [4134] = true

-- Live readers (nil when the DB is absent / corrupt). Rebound on
-- reopen; the public getters read them through closures so a +reload
-- never leaves a caller on a stale reader.
local country_reader = nil
local asn_reader     = nil

-- Debounce flags so a missing DB warns once per (re)load, not on every
-- onConnect / onTimer tick.
local warned_missing = { }       -- ["country"]=true / ["asn"]=true

local next_recheck = 0           -- os.time() deadline for the DB reopen


local function _build_sets( )
    blocked_countries = { }
    for _, c in ipairs( blocked_countries_cfg ) do
        if type( c ) == "string" then
            local up = c:upper( )
            if up:match( "^%u%u$" ) then blocked_countries[ up ] = true end
        end
    end
    blocked_asns = { }
    for _, a in ipairs( blocked_asns_cfg ) do
        local n = tonumber( a )
        if n and n == math.floor( n ) and n >= 0 then blocked_asns[ n ] = true end
    end
end


-- (Re)open one DB path, given the reader currently in use for it.
--   - success:        close the old reader (mmdb contract) + return the new one.
--   - open failure:   RETAIN `current` and warn once. A transient failure
--                     (e.g. a non-atomic DB replace mid-write, a brief
--                     permission blip) must NOT null a working reader and
--                     silently disable enforcement until the next recheck.
--                     First open (current == nil) therefore just stays nil
--                     (inert) - identical to the old behaviour.
-- On a successful open, emit a one-time staleness warning if the DB
-- build_epoch is older than 30 days.
local function _reopen( which, path, current )
    if type( path ) ~= "string" or path == "" then return current end
    local reader, err = mmdb.open( path )
    if not reader then
        if not warned_missing[ which ] then
            warned_missing[ which ] = true
            hub_debug( utf_format( msg_db_missing, which, tostring( path ) ) )
            if audit then
                audit.fire( audit.build( "geoip.db.missing", scriptname, nil, nil,
                    { db = which, path = path, err = tostring( err ) } ) )
            end
        end
        return current    -- keep the last-good reader (or nil on first open)
    end
    warned_missing[ which ] = nil
    if current and current ~= reader and current.close then current:close( ) end
    local meta = reader.metadata or { }
    local built = tonumber( meta.build_epoch )
    local built_str = built and os.date( "!%Y-%m-%d", built ) or "?"
    hub_debug( utf_format( msg_db_loaded, which, tostring( meta.database_type or "?" ), built_str ) )
    if built and ( os_time( ) - built ) > STALE_AFTER_SEC then
        hub_debug( utf_format( msg_db_stale, which, built_str ) )
        if audit then
            audit.fire( audit.build( "geoip.db.stale", scriptname, nil, nil,
                { db = which, build_epoch = built } ) )
        end
    end
    return reader
end


-- Open / refresh both DBs. No-op when the feature is disabled so a
-- loaded-but-off plugin does zero DB I/O (the onConnect check is
-- likewise gated on `enabled`).
local function _open_all( )
    if not enabled then return end
    country_reader = _reopen( "country", country_db_path, country_reader )
    asn_reader     = _reopen( "asn", asn_db_path, asn_reader )
end


-- Pure policy decision. Returns a short match string ("country=CN" /
-- "ASN=4134") or nil. Country checked before ASN so the audit reason
-- is deterministic when both match.
local function resolve( country, asn )
    if country and blocked_countries[ country ] then
        return "country=" .. country
    end
    if asn and blocked_asns[ asn ] then
        return "ASN=" .. asn
    end
    return nil
end


-- Run the live readers against an IP. Any field is nil when its DB is
-- absent or the IP is not in it. Lookups are pcall-guarded inside
-- mmdb, so a corrupt record degrades to nil rather than throwing.
local function classify( ip )
    local country, asn, org
    if country_reader and type( ip ) == "string" then
        local rec = country_reader:lookup( ip )
        country = rec and rec.country and rec.country.iso_code
    end
    if asn_reader and type( ip ) == "string" then
        local rec = asn_reader:lookup( ip )
        if rec then
            asn = rec.autonomous_system_number
            org = rec.autonomous_system_organization
        end
    end
    return country, asn, org
end


-- The onConnect check. Returns PROCESSED when it kicks, nil otherwise.
local check_geoip = function( user )
    if not enabled then return end
    if not ( country_reader or asn_reader ) then return end

    local user_level = user:level( )
    if not check_levels[ user_level ] then return end

    local ip = user:ip( )
    if not ip or ip == "" then return end

    -- #78 allowlist: a whitelisted IP (trusted infra / hublist pinger)
    -- is exempt from the country/ASN block and its report + audit.
    if whitelist.is_whitelisted( ip ) then return end

    local country, asn, org = classify( ip )
    local matched = resolve( country, asn )
    if not matched then return end    -- allowed

    -- Always audit + report the match (both block and log_only) so an
    -- operator running log_only sees exactly what a block WOULD drop.
    if audit then
        audit.fire( audit.build( "geoip.block", scriptname, user, kick_reason,
            { country = country, asn = asn, org = org, matched = matched, action = action } ) )
    end
    if report then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel,
            utf_format( msg_report, user:nick( ) or "?", ip, matched, tostring( org or "?" ), action ) )
    end

    if action == "block" then
        user:kill( "ISTA 231 " .. hub_escapeto( kick_reason ) .. " TL-1\n" )
        return PROCESSED
    end
    return nil    -- log_only: let the connection through
end


-- Status snapshot for +geoip / GET /v1/geoip / the unit test.
local function _reader_status( reader, path )
    if not reader then
        return { loaded = false, path = path }
    end
    local meta = reader.metadata or { }
    local built = tonumber( meta.build_epoch )
    return {
        loaded       = true,
        path         = path,
        db_type      = meta.database_type,
        build_epoch  = built,
        build_date   = built and os.date( "!%Y-%m-%d", built ) or nil,
        stale        = built and ( os_time( ) - built ) > STALE_AFTER_SEC or false,
    }
end

local function get_status( )
    local countries, asns = { }, { }
    for c in pairs( blocked_countries ) do countries[ #countries + 1 ] = c end
    for a in pairs( blocked_asns ) do asns[ #asns + 1 ] = a end
    table_sort( countries )
    table_sort( asns )
    return {
        enabled           = enabled and true or false,
        action            = action,
        blocked_countries = countries,
        blocked_asns      = asns,
        country_db        = _reader_status( country_reader, country_db_path ),
        asn_db            = _reader_status( asn_reader, asn_db_path ),
    }
end


local function format_status( )
    local s = get_status( )
    local function dbline( d )
        if not d.loaded then return "not loaded (" .. tostring( d.path ) .. ")" end
        return string.format( "%s (%s, built %s%s)", tostring( d.path ),
            tostring( d.db_type or "?" ), tostring( d.build_date or "?" ),
            d.stale and ", STALE" or "" )
    end
    local lines = { msg_status_header, "" }
    lines[ #lines + 1 ] = utf_format( msg_status_enabled, tostring( s.enabled ) )
    lines[ #lines + 1 ] = utf_format( msg_status_action,  s.action )
    lines[ #lines + 1 ] = utf_format( msg_status_country, dbline( s.country_db ) )
    lines[ #lines + 1 ] = utf_format( msg_status_asn,     dbline( s.asn_db ) )
    lines[ #lines + 1 ] = utf_format( msg_status_bcountry,
        #s.blocked_countries > 0 and table_concat( s.blocked_countries, ", " ) or "(none)" )
    lines[ #lines + 1 ] = utf_format( msg_status_basn,
        #s.blocked_asns > 0 and table_concat( s.blocked_asns, ", " ) or "(none)" )
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_status_footer
    return table_concat( lines, "\n" )
end


------------------
--[ADC HANDLERS]--
------------------

local on_geoip = function( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    -- 3-arg reply -> DMSG so the multi-line status shows in the
    -- operator's PM window (same choice as +blocker / cmd_help;
    -- AirDC++ renders multi-line DMSG where BMSG appeared empty).
    user:reply( format_status( ), hub_getbot( ), hub_getbot( ) )
    return PROCESSED
end


-------------------
--[HTTP HANDLERS]--
-------------------

local http_get_status = function( req )
    return { status = 200, data = get_status( ) }
end


------------------
--[AUTO-UPDATE ]--
------------------

-- Persisted per-edition sha256 of the last successfully-installed tar.gz,
-- so a cycle skips the big download when MaxMind's file is unchanged.
local update_state_file = "scripts/data/etc_geoip.tbl"
local update_in_flight = false
local next_update = 0
local update_was_failing = false    -- report debounce (ok->fail edge + recovery)

local function load_update_state( )
    local f = io_open( update_state_file, "r" )    -- peek: avoid a first-run checkfile log
    if not f then return { } end
    f:close( )
    return util_loadtable( update_state_file ) or { }
end

local function _update_report( msg )
    if report then
        report.send( report_activate, report_hubbot, report_opchat, report_llevel, msg )
    end
end

-- Only Country + ASN map to the two reader paths; other editions have no
-- destination and are skipped.
local function edition_dest( edition )
    if edition == "GeoLite2-Country" then return country_db_path end
    if edition == "GeoLite2-ASN" then return asn_db_path end
    return nil
end

-- Run one update cycle: fetch each configured edition SEQUENTIALLY (a
-- callback chain, so N editions never fan out into N concurrent downloads),
-- persist the new sha256, and swap the live reader(s) on success. The
-- in-flight guard stops the next timer tick from overlapping a running cycle.
local function run_update( )
    if update_in_flight then return end
    if account_id == "" or not license_key or license_key == "" then return end
    update_in_flight = true

    local state = load_update_state( )
    local queue = { }
    for _, ed in ipairs( edition_ids ) do
        local dest = edition_dest( ed )
        if type( dest ) == "string" and dest ~= "" then
            queue[ #queue + 1 ] = { edition = ed, dest = dest }
        end
    end

    -- Announce the cycle start to event.log (out.put, gated on log_events)
    -- so the operator sees the fetch kick off, not just the result.
    if #queue > 0 then
        local names = { }
        for _, it in ipairs( queue ) do names[ #names + 1 ] = it.edition end
        out_put( utf_format( msg_update_start, table_concat( names, ", " ) ) )
        -- Persist the check time NOW, before the fetch, so a MaxMind
        -- rate-limit / failure still counts (those are exactly who a
        -- reload-loop must not re-hammer) and onStart schedules the next
        -- check from it across +reload. "unchanged" editions save no state
        -- (no sha256 change), so on an all-unchanged cycle this is the only
        -- write. Mirrors etc_blocklist_feeds mark_fetched (#386).
        state.last_update = os_time( )
        util_savetable( state, "state", update_state_file )
    end

    local i, updated_count, last_err = 0, 0, nil
    local function step( )
        i = i + 1
        local item = queue[ i ]
        if not item then
            update_in_flight = false
            -- Report + debounce. A mixed cycle (something updated AND
            -- something failed) surfaces BOTH and keeps the failing edge so
            -- the next clean cycle still reports recovery.
            if updated_count > 0 then
                _open_all( )                    -- swap the live reader(s) to the new DB now
                _update_report( utf_format( msg_update_ok, updated_count ) )
                if last_err then
                    if not update_was_failing then
                        update_was_failing = true
                        _update_report( utf_format( msg_update_fail, last_err ) )
                    end
                else
                    update_was_failing = false
                end
            elseif last_err then
                if not update_was_failing then
                    update_was_failing = true
                    _update_report( utf_format( msg_update_fail, last_err ) )
                end
            elseif update_was_failing then      -- all unchanged after a prior failing run
                update_was_failing = false
                _update_report( msg_update_recovered )
            end
            return
        end
        -- Apply one edition's result. pcall-guarded at the call site below so
        -- a throw here (e.g. an audit-subsystem error) can never stop step()
        -- from advancing / clearing the in-flight guard (would jam
        -- auto-update until +reload).
        local function on_result( result )
            if result.status == "updated" then
                updated_count = updated_count + 1
                state[ item.edition ] = result.sha256
                util_savetable( state, "state", update_state_file )
                if audit then
                    audit.fire( audit.build( "geoip.update.success", scriptname, nil, nil,
                        { edition = item.edition, bytes = result.bytes } ) )
                end
            elseif result.status == "failed" then
                last_err = item.edition .. ": " .. tostring( result.err )
                if audit then
                    audit.fire( audit.build( "geoip.update.fail", scriptname, nil, nil,
                        { edition = item.edition, err = tostring( result.err ) } ) )
                end
            end    -- "unchanged" -> nothing
        end
        -- update() invokes on_done exactly once and does not throw after it,
        -- so if the call itself throws (never with these fixed args) on_done
        -- did NOT run -> advancing step() here is safe, not a double-step.
        local uok, uerr = pcall( geoip_update.update, {
            edition = item.edition, dest = item.dest,
            account_id = account_id, license_key = license_key,
            known_sha256 = state[ item.edition ], verify = "peer",
        }, function( result )
            local hok, herr = pcall( on_result, result )
            if not hok then hub_debug( "etc_geoip: update result handler error: " .. tostring( herr ) ) end
            step( )
        end )
        if not uok then
            last_err = item.edition .. ": " .. tostring( uerr )
            step( )
        end
    end
    step( )
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onConnect", { }, check_geoip )

hub.setlistener( "onTimer", { },
    function( )
        -- Re-read the DB on a deadline so a `geoipupdate` cron write is
        -- picked up without a manual +reload. Reopen into fresh locals;
        -- the swap is atomic (single-threaded, no yield mid-open).
        if not enabled then return end
        local now = os_time( )
        if now >= next_recheck then
            next_recheck = now + recheck_interval
            _open_all( )
        end
        -- Auto-update deadline: download + refresh the .mmdb, then swap the
        -- live reader on success. Separate deadline from the passive recheck
        -- above; both converge on the idempotent reopen-retain _open_all().
        if auto_update and now >= next_update then
            next_update = now + update_interval
            run_update( )
        end
    end
)

hub.setlistener( "onStart", { },
    function( )
        _build_sets( )
        warned_missing = { }
        _open_all( )
        next_recheck = os_time( ) + recheck_interval

        -- Auto-update: register the license key as a secret (so GET
        -- /v1/config redacts it) + resolve it env-var-first, then stagger
        -- the first update shortly after boot. Requires etc_geoip_enabled
        -- (the onTimer returns early when the check is off).
        -- api_writable: a third-party MaxMind credential the operator may set from the
        -- WebUI (masked write, #178) - not the hub's own auth/crypto material.
        if secrets and secrets.register then secrets.register( "etc_geoip_license_key", { api_writable = true } ) end
        license_key = secrets and secrets.lookup( "etc_geoip_license_key" ) or nil
        if auto_update then
            if account_id == "" or not license_key or license_key == "" then
                hub_debug( msg_update_missing_key )
            end
            -- Honour the PERSISTED last-update time across +reload. onStart
            -- fires on every reload (a full Lua restart) and next_update is
            -- RAM-only - without this a reload would re-check MaxMind ~30s
            -- after boot EVERY time, so an operator reloading several times a
            -- day hits MaxMind's rate-limited download endpoint each time (the
            -- DB only changes twice weekly). Schedule the next check at
            -- last_update + interval instead; never-checked / overdue is
            -- staggered shortly after boot. min() caps a bogus future
            -- timestamp (clock skew / corrupt state) to one interval so it
            -- can never freeze the updater. Mirrors etc_blocklist_feeds (#386).
            local last = tonumber( load_update_state( ).last_update )
            local now = os_time( )
            if last and last + update_interval > now then
                next_update = math.min( last + update_interval, now + update_interval )
            else
                next_update = now + 30
            end
        end

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( "etc_geoip.lua - geoip",
                lang.help_usage or "[+!#]geoip",
                lang.help_desc or "Show GeoIP status: DB load state, action mode, blocked countries / ASNs.",
                oplevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( lang.ucmd_menu or { "Hub", "GeoIP", "status" }, cmd_status, { }, { "CT1" }, oplevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_status, on_geoip, oplevel ) )

        -- Read-only HTTP status mirror. No write endpoint: the policy
        -- (blocked countries / ASNs) is cfg-driven, edited in cfg.tbl +
        -- reload, not a mutable store. Raw hub.http_register because
        -- there is no SID target.
        if hub.http_register then
            hub.http_register( "GET", "/v1/geoip", "read", http_get_status, {
                plugin = scriptname,
                description = "GeoIP status: DB load state, action mode, blocked countries / ASNs (= ADC `+geoip`)",
                response_schema = {
                    enabled           = { type = "boolean", required = true },
                    action            = { type = "string",  required = true },
                    blocked_countries = { type = "array",   required = true },
                    blocked_asns      = { type = "array",   required = true },
                    country_db        = { type = "object",  required = true },
                    asn_db            = { type = "object",  required = true },
                },
            } )
        end
        return nil
    end
)


hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )


--// public //--

return {

    resolve    = resolve,
    classify   = classify,
    get_status = get_status,

}
