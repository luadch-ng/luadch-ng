--[[

    tests/unit/etc_geoip_test.lua

    Unit tests for scripts/etc_geoip.lua (#78 Phase D2). Exercises:
      - resolve(country, asn) pure policy decision (both hit paths + miss)
      - classify(ip) against the REAL GeoLite2-Country test fixture via
        the real core/mmdb.lua reader (v4 + v6 + v4-mapped + miss)
      - the onConnect check via a stubbed user object: block-mode kick,
        log_only-mode pass-through (+ audit either way), operator-level
        exemption, disabled-toggle short-circuit, no-DB inertness
      - get_status() snapshot shape
      - graceful missing-DB handling (open a bad path -> no crash)

    Run: lua5.4 tests/unit/etc_geoip_test.lua   (exit 0 = pass, 1 = fail)

]]--

local FIX = "tests/unit/fixtures/mmdb/GeoLite2-Country-Test.mmdb"

----------------------------------------------------------------------
-- Load the REAL core/mmdb.lua + core/ipmatch.lua (via a use-stub, as
-- mmdb_test does) so the plugin's classify() runs against genuine
-- lookups, then expose mmdb as the sandbox global the plugin reads.
----------------------------------------------------------------------

local _real = { type=type, tostring=tostring, tonumber=tonumber, error=error,
    pcall=pcall, setmetatable=setmetatable, string=string, table=table,
    io=io, ipairs=ipairs, os=os }
local _loaded_ipmatch
local function core_use( name )
    if name == "ipmatch" then return _loaded_ipmatch end
    local v = _real[ name ]; if v ~= nil then return v end
    error( "core_use: missing dep " .. tostring( name ) )
end
_G.use = core_use
_loaded_ipmatch = assert( loadfile( "core/ipmatch.lua" ) )( )
local mmdb = assert( loadfile( "core/mmdb.lua" ) )( )
_G.use = nil   -- plugins do NOT get `use`; drop it before loading the plugin

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------

local _pass, _fail = 0, 0
local function eq( what, got, want )
    if got == want then _pass = _pass + 1
    else _fail = _fail + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) ) end
end
local function truthy( what, v ) if v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end
local function falsy( what, v ) if not v then _pass = _pass + 1
    else _fail = _fail + 1; io.stderr:write( "FAIL: " .. what .. " got=" .. tostring( v ) .. "\n" ) end end

----------------------------------------------------------------------
-- Sandbox-global stubs the plugin reads. cfg values are mutable so a
-- test can flip enabled/action/db-path and reload the plugin.
----------------------------------------------------------------------

local _cfg = {
    language = "en",
    etc_geoip_enabled = true,
    etc_geoip_country_db_path = FIX,
    etc_geoip_asn_db_path = "tests/unit/fixtures/mmdb/does-not-exist.mmdb",
    etc_geoip_blocked_countries = { "GB", "se" },   -- lower-case tolerated
    etc_geoip_blocked_asns = { 4134 },
    etc_geoip_action = "block",
    etc_geoip_check_levels = { [0]=true, [10]=true, [20]=true, [50]=true, [60]=false, [80]=false, [100]=true },
    etc_geoip_recheck_interval_sec = 3600,
    etc_geoip_oplevel = 80,
    etc_geoip_kick_reason = "region blocked",
    etc_geoip_report = false,
    etc_geoip_report_hubbot = false,
    etc_geoip_report_opchat = false,
    etc_geoip_llevel = 60,
}

local _listeners, _audit, _kicks
local function fresh_capture( )
    _listeners = { }; _audit = { }; _kicks = { }
end
fresh_capture( )

_G.PROCESSED = "PROCESSED"
_G.os = os
_G.math = math
_G.table = table
_G.string = string
_G.type = type
_G.pairs = pairs
_G.ipairs = ipairs
_G.tonumber = tonumber
_G.tostring = tostring

_G.cfg = {
    get = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
    -- #707: etc_geoip declares its cfg keys reload-required at load; the plugin only
    -- needs the call to succeed here (the classifier behaviour is covered in
    -- http_router_test).
    mark_reload_required = function( ) end,
}
_G.utf = {
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}
_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, meta = meta or { } }
    end,
    fire = function( ev ) _audit[ #_audit + 1 ] = ev end,
}
_G.mmdb = mmdb

-- Auto-update (#78 Phase D3) sandbox stubs, driven by the control vars below.
local _geoip_state = { }          -- persisted per-edition sha256 (util.loadtable/savetable)
local _license = ""               -- what secrets.lookup returns
local _registered = { }           -- secret keys the plugin registered
local _update_cb = nil            -- function(opts) -> result; drives geoip_update.update
local _updates = { }              -- captured update() opts
_G.util = {
    loadtable = function( ) return _geoip_state end,
    savetable = function( t ) _geoip_state = t end,
}
_G.secrets = {
    register = function( k ) _registered[ k ] = true end,
    lookup   = function( ) return _license end,
}
_G.geoip_update = {
    update = function( opts, on_done )
        _updates[ #_updates + 1 ] = opts
        on_done( _update_cb and _update_cb( opts ) or { status = "unchanged" } )
    end,
}
local _out_puts = { }             -- captured out.put(event.log) lines
_G.out = { put = function( m ) _out_puts[ #_out_puts + 1 ] = m end }
-- io.open must succeed for the state-file peek so util.loadtable is consulted;
-- everything else (io.stderr / io.write in the harness) falls through to real io.
local _real_io = io
_G.io = setmetatable( { open = function( path, mode )
    if path == "scripts/data/etc_geoip.tbl" then return { close = function( ) end } end
    return _real_io.open( path, mode )
end }, { __index = _real_io } )

_G.hub = {
    setlistener   = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    debug         = function( ) end,
    import        = function( ) return nil end,   -- no etc_report / cmd_help / etc_hubcommands
    escapeto      = function( s ) return s end,
    getbot        = function( ) return "bot" end,
    http_register = function( ) end,
}

-- etc_hubcommands is asserted non-nil in onStart, so provide it.
local _orig_import = _G.hub.import
_G.hub.import = function( name )
    if name == "etc_hubcommands" then
        return { add = function( ) return true end, has = function( ) return false end }
    end
    return nil
end

-- #78 allowlist stub: the plugin's whitelist guard. Default: nothing
-- whitelisted (existing tests unaffected). A test flips an entry on
-- via `_wl[ip] = true`.
local _wl = { }
_G.whitelist = { is_whitelisted = function( ip ) return _wl[ ip ] == true end }

----------------------------------------------------------------------
-- Load helper + stub user
----------------------------------------------------------------------

local function load_plugin( )
    fresh_capture( )
    local plugin = assert( loadfile( "scripts/etc_geoip.lua" ) )( )
    if _listeners.onStart then _listeners.onStart( ) end
    -- onStart legitimately fires geoip.db.stale / geoip.db.missing
    -- audits (the fixture is an old build + the ASN path is absent by
    -- design). Clear the capture so the onConnect assertions below see
    -- only their own events.
    _audit = { }; _kicks = { }
    return plugin
end

local function make_user( opts )
    return {
        _lvl = opts.level, _ip = opts.ip, _nick = opts.nick or "tester",
        level = function( s ) return s._lvl end,
        ip    = function( s ) return s._ip end,
        nick  = function( s ) return s._nick end,
        kill  = function( s, msg ) _kicks[ #_kicks + 1 ] = msg end,
    }
end

----------------------------------------------------------------------
-- resolve(): pure policy decision
----------------------------------------------------------------------

do
    local p = load_plugin( )
    eq( "resolve blocked country",      p.resolve( "GB", nil ), "country=GB" )
    eq( "resolve lower-case cfg matched", p.resolve( "SE", nil ), "country=SE" )
    falsy( "resolve allowed country",   p.resolve( "JP", nil ) )
    eq( "resolve blocked asn",          p.resolve( "JP", 4134 ), "ASN=4134" )
    falsy( "resolve allowed asn",       p.resolve( "JP", 9999 ) )
    eq( "resolve country wins over asn", p.resolve( "GB", 4134 ), "country=GB" )
    falsy( "resolve nil/nil",           p.resolve( nil, nil ) )
end

----------------------------------------------------------------------
-- classify(): real reader against the fixture
----------------------------------------------------------------------

do
    local p = load_plugin( )
    local c1 = select( 1, p.classify( "81.2.69.160" ) )        -- v4 -> GB
    eq( "classify v4 -> GB", c1, "GB" )
    local c2 = select( 1, p.classify( "::ffff:81.2.69.160" ) ) -- v4-mapped (dual-stack) -> GB
    eq( "classify v4-mapped -> GB", c2, "GB" )
    local c3 = select( 1, p.classify( "2001:218::1" ) )        -- v6 -> JP
    eq( "classify v6 -> JP", c3, "JP" )
    local c4 = select( 1, p.classify( "10.0.0.1" ) )           -- unmapped -> nil
    falsy( "classify miss -> nil country", c4 )
end

----------------------------------------------------------------------
-- ASN path end-to-end: real GeoLite2-ASN fixture -> classify -> block
----------------------------------------------------------------------

do
    local ASN_FIX = "tests/unit/fixtures/mmdb/GeoLite2-ASN-Test.mmdb"
    _cfg.etc_geoip_asn_db_path = ASN_FIX
    _cfg.etc_geoip_blocked_countries = { }        -- isolate the ASN path
    _cfg.etc_geoip_blocked_asns = { 15169 }       -- Google, = 1.0.0.0/24 in the fixture
    _cfg.etc_geoip_action = "block"
    local p = load_plugin( )

    local _c, asn, org = p.classify( "1.0.0.1" )
    eq( "classify asn number", asn, 15169 )
    eq( "classify asn org", org, "Google Inc." )
    eq( "resolve blocked asn (live)", p.resolve( nil, asn ), "ASN=15169" )

    local check = _listeners.onConnect
    local r = check( make_user{ level = 20, ip = "1.0.0.1" } )     -- AS15169, blocked
    eq( "asn block: PROCESSED", r, "PROCESSED" )
    eq( "asn block: kill emitted", #_kicks, 1 )
    eq( "asn block: audit meta asn", _audit[ 1 ] and _audit[ 1 ].meta.asn, 15169 )
    eq( "asn block: audit matched", _audit[ 1 ] and _audit[ 1 ].meta.matched, "ASN=15169" )

    -- restore the country-path config for the tests below
    _cfg.etc_geoip_asn_db_path = "tests/unit/fixtures/mmdb/does-not-exist.mmdb"
    _cfg.etc_geoip_blocked_countries = { "GB", "se" }
    _cfg.etc_geoip_blocked_asns = { 4134 }
end

----------------------------------------------------------------------
-- onConnect: block mode kicks a blocked-country user
----------------------------------------------------------------------

do
    _cfg.etc_geoip_action = "block"
    load_plugin( )
    local check = _listeners.onConnect
    truthy( "onConnect listener registered", check )

    local r = check( make_user{ level = 20, ip = "81.2.69.160" } )  -- GB, blocked
    eq( "block: returns PROCESSED", r, "PROCESSED" )
    eq( "block: kill emitted", #_kicks, 1 )
    truthy( "block: kill carries ISTA", _kicks[ 1 ] and _kicks[ 1 ]:find( "ISTA 231" ) )
    eq( "block: audit fired", #_audit, 1 )
    eq( "block: audit action", _audit[ 1 ] and _audit[ 1 ].action, "geoip.block" )
    eq( "block: audit meta country", _audit[ 1 ] and _audit[ 1 ].meta.country, "GB" )
    eq( "block: audit meta action", _audit[ 1 ] and _audit[ 1 ].meta.action, "block" )
end

do
    _cfg.etc_geoip_action = "block"
    load_plugin( )
    local check = _listeners.onConnect
    local r = check( make_user{ level = 20, ip = "2001:218::1" } )  -- JP, allowed
    falsy( "allowed user: no PROCESSED", r )
    eq( "allowed user: no kick", #_kicks, 0 )
    eq( "allowed user: no audit", #_audit, 0 )
end

----------------------------------------------------------------------
-- #78 allowlist: a whitelisted IP is exempt from the geoip block.
-- Provably FAILS pre-fix (without the guard the GB IP is kicked).
----------------------------------------------------------------------

do
    _cfg.etc_geoip_action = "block"
    load_plugin( )
    local check = _listeners.onConnect

    -- baseline: GB blocked when NOT whitelisted
    _wl = { }
    local r1 = check( make_user{ level = 20, ip = "81.2.69.160" } )
    eq( "geoip wl baseline: GB blocked", r1, "PROCESSED" )
    eq( "geoip wl baseline: kicked", #_kicks, 1 )

    -- whitelist that IP -> exempt (no kick, no audit, allowed)
    _kicks = { }; _audit = { }
    _wl = { [ "81.2.69.160" ] = true }
    local r2 = check( make_user{ level = 20, ip = "81.2.69.160" } )
    falsy( "geoip whitelisted -> not blocked", r2 )
    eq( "geoip whitelisted -> no kick", #_kicks, 0 )
    eq( "geoip whitelisted -> no audit", #_audit, 0 )
    _wl = { }
end

----------------------------------------------------------------------
-- onConnect: log_only audits + reports but does NOT kick
----------------------------------------------------------------------

do
    _cfg.etc_geoip_action = "log_only"
    load_plugin( )
    local check = _listeners.onConnect
    local r = check( make_user{ level = 20, ip = "81.2.69.160" } )  -- GB, blocked
    falsy( "log_only: no PROCESSED", r )
    eq( "log_only: no kick", #_kicks, 0 )
    eq( "log_only: audit still fired", #_audit, 1 )
    eq( "log_only: audit meta action", _audit[ 1 ] and _audit[ 1 ].meta.action, "log_only" )
    _cfg.etc_geoip_action = "block"
end

----------------------------------------------------------------------
-- onConnect: operator level is exempt; disabled toggle short-circuits
----------------------------------------------------------------------

do
    load_plugin( )
    local check = _listeners.onConnect
    local r = check( make_user{ level = 80, ip = "81.2.69.160" } )  -- op, exempt
    falsy( "op exempt: no PROCESSED", r )
    eq( "op exempt: no kick", #_kicks, 0 )
end

do
    _cfg.etc_geoip_enabled = false
    load_plugin( )
    local check = _listeners.onConnect
    local r = check( make_user{ level = 20, ip = "81.2.69.160" } )  -- would block, but disabled
    falsy( "disabled: no PROCESSED", r )
    eq( "disabled: no kick", #_kicks, 0 )
    _cfg.etc_geoip_enabled = true
end

----------------------------------------------------------------------
-- get_status snapshot + graceful missing-DB
----------------------------------------------------------------------

do
    local p = load_plugin( )
    local s = p.get_status( )
    eq( "status enabled", s.enabled, true )
    eq( "status action", s.action, "block" )
    truthy( "status country DB loaded", s.country_db.loaded )
    eq( "status country db_type", s.country_db.db_type, "GeoLite2-Country" )
    falsy( "status asn DB not loaded (bad path)", s.asn_db.loaded )
    -- blocked_countries normalised to upper-case + sorted
    eq( "status blocked count", #s.blocked_countries, 2 )
    eq( "status blocked[1]", s.blocked_countries[ 1 ], "GB" )
    eq( "status blocked[2]", s.blocked_countries[ 2 ], "SE" )
end

do
    -- both DBs missing -> plugin loads, onConnect is inert, no crash
    _cfg.etc_geoip_country_db_path = "tests/unit/fixtures/mmdb/nope.mmdb"
    local p = load_plugin( )
    local check = _listeners.onConnect
    local r = check( make_user{ level = 20, ip = "81.2.69.160" } )
    falsy( "no DB: onConnect inert", r )
    eq( "no DB: no kick", #_kicks, 0 )
    falsy( "no DB: country reader absent", p.get_status( ).country_db.loaded )
    _cfg.etc_geoip_country_db_path = FIX
end

----------------------------------------------------------------------
-- SEC-1: a FAILED onTimer reopen must RETAIN the last-good reader (a
-- transient DB failure, e.g. a non-atomic replace mid-write, must not
-- silently disable enforcement). Uses a fake clock to force the reopen.
----------------------------------------------------------------------

do
    local real_os = _real.os
    local clock = { t = 1000000 }
    _G.os = { time = function( ) return clock.t end,
              date = real_os.date, difftime = real_os.difftime, clock = real_os.clock }
    _cfg.etc_geoip_country_db_path = FIX
    local p = load_plugin( )                      -- onStart opens the good DB
    truthy( "retain: reader loaded at start", p.get_status( ).country_db.loaded )

    _cfg.etc_geoip_country_db_path = "tests/unit/fixtures/mmdb/gone.mmdb"  -- now bad
    clock.t = clock.t + 3601                       -- past next_recheck
    _listeners.onTimer( )                          -- reopen ATTEMPT fails
    truthy( "retain: reader kept after failed reopen (SEC-1)", p.get_status( ).country_db.loaded )
    eq( "retain: classify still works", ( select( 1, p.classify( "81.2.69.160" ) ) ), "GB" )

    _G.os = real_os
    _cfg.etc_geoip_country_db_path = FIX
end

----------------------------------------------------------------------
-- Phase D3: in-hub auto-update integration (run_update cycle)
----------------------------------------------------------------------

local function _has_audit( action )
    for _, a in ipairs( _audit ) do if a.action == action then return true end end
    return false
end

do
    local real_os = _real.os
    local clock = { t = 1000000 }
    _G.os = { time = function( ) return clock.t end,
              date = real_os.date, difftime = real_os.difftime, clock = real_os.clock }

    _cfg.etc_geoip_country_db_path = FIX
    _cfg.etc_geoip_auto_update = true
    _cfg.etc_geoip_account_id = "12345"
    _cfg.etc_geoip_edition_ids = { "GeoLite2-Country" }
    _cfg.etc_geoip_update_interval_sec = 86400
    _license = "LICKEY"; _geoip_state = { }; _update_cb = nil

    load_plugin( )
    truthy( "autoupdate: license secret registered", _registered.etc_geoip_license_key )

    _updates = { }; _out_puts = { }
    _listeners.onTimer( )                          -- clock < next_update (onStart set now+30)
    eq( "autoupdate: no update before deadline", #_updates, 0 )

    _update_cb = function( ) return { status = "updated", sha256 = string.rep( "e", 64 ), bytes = 4321 } end
    clock.t = clock.t + 31
    _listeners.onTimer( )
    eq( "autoupdate: update() fired past deadline", #_updates, 1 )
    truthy( "autoupdate: fetch-start logged to event.log (names the edition)",
        _out_puts[ 1 ] and _out_puts[ 1 ]:find( "GeoLite2-Country", 1, true ) ~= nil )
    eq( "autoupdate: edition", _updates[ 1 ].edition, "GeoLite2-Country" )
    eq( "autoupdate: dest = country_db_path", _updates[ 1 ].dest, FIX )
    eq( "autoupdate: account_id passed", _updates[ 1 ].account_id, "12345" )
    eq( "autoupdate: license passed", _updates[ 1 ].license_key, "LICKEY" )
    falsy( "autoupdate: known_sha256 nil on first run", _updates[ 1 ].known_sha256 )
    eq( "autoupdate: new sha256 persisted", _geoip_state[ "GeoLite2-Country" ], string.rep( "e", 64 ) )
    truthy( "autoupdate: geoip.update.success audited", _has_audit( "geoip.update.success" ) )

    _updates = { }
    _update_cb = function( ) return { status = "unchanged", sha256 = string.rep( "e", 64 ) } end
    clock.t = clock.t + 86401
    _listeners.onTimer( )
    eq( "autoupdate: next cycle sends the stored sha256", _updates[ 1 ] and _updates[ 1 ].known_sha256, string.rep( "e", 64 ) )

    _updates = { }; _audit = { }
    _update_cb = function( ) return { status = "failed", err = "download 500" } end
    clock.t = clock.t + 86401
    _listeners.onTimer( )
    truthy( "autoupdate: geoip.update.fail audited", _has_audit( "geoip.update.fail" ) )

    -- no credentials -> run_update is a no-op
    _license = ""
    load_plugin( )
    _updates = { }
    clock.t = clock.t + 86401
    _listeners.onTimer( )
    eq( "autoupdate: no license -> no update fired", #_updates, 0 )

    _G.os = real_os
    _cfg.etc_geoip_auto_update = nil
    _cfg.etc_geoip_account_id = nil
    _cfg.etc_geoip_edition_ids = nil
end

----------------------------------------------------------------------
-- Phase D3 follow-up (#386 mirror): +reload must NOT re-check MaxMind
-- ~30s after boot when the last check is recent. next_update is RAM-only,
-- so onStart persists/reads the last-check time across reload.
----------------------------------------------------------------------

do
    local real_os = _real.os
    local clock = { t = 2000000 }
    _G.os = { time = function( ) return clock.t end,
              date = real_os.date, difftime = real_os.difftime, clock = real_os.clock }

    _cfg.etc_geoip_country_db_path = FIX
    _cfg.etc_geoip_enabled = true
    _cfg.etc_geoip_auto_update = true
    _cfg.etc_geoip_account_id = "12345"
    _cfg.etc_geoip_edition_ids = { "GeoLite2-Country" }
    _cfg.etc_geoip_update_interval_sec = 86400
    _license = "LICKEY"; _update_cb = nil

    -- A check happened 100s ago (far inside the 1-day interval), persisted.
    _geoip_state = { last_update = clock.t - 100 }

    load_plugin( )    -- onStart must schedule from last_update, NOT now+30

    -- A reload right after a recent check must not re-check ~30s later.
    _updates = { }
    clock.t = clock.t + 31          -- past the pre-fix now+30 window
    _listeners.onTimer( )
    eq( "reload-throttle: no MaxMind re-check ~30s after reload when last check is recent", #_updates, 0 )

    -- ...but once the interval elapses FROM the persisted last check, it fires.
    _updates = { }
    clock.t = ( 2000000 - 100 ) + 86400 + 1
    _listeners.onTimer( )
    eq( "reload-throttle: re-check fires once the interval elapses from last_update", #_updates, 1 )

    _G.os = real_os
    _cfg.etc_geoip_auto_update = nil
    _cfg.etc_geoip_account_id = nil
    _cfg.etc_geoip_edition_ids = nil
end

----------------------------------------------------------------------

io.stderr:write( string.format( "\netc_geoip_test: %d passed, %d failed\n", _pass, _fail ) )
os.exit( _fail == 0 and 0 or 1 )
