--[[

    tests/unit/etc_clientblocker_test.lua

    Unit tests for scripts/etc_clientblocker.lua (#81).

    Exercises every branch of do_add_pattern / do_del_pattern via
    the HTTP API surface (pure-function shape: req -> response),
    the check_clients onConnect listener via a stubbed user
    object, and the +addblocker / +delblocker / +blocker ADC
    handlers via captured etc_hubcommands registrations.

    Run: lua5.4 tests/unit/etc_clientblocker_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- stub layer: sandbox globals the plugin reads at file scope
----------------------------------------------------------------------

local _registered = { onStart = nil, onConnect = nil, hub = { }, http = { } }
local _saved_table = nil
local _next_loaded = nil
local _audit_fired = { }
local _reports_sent = { }

local stub_hub = {
    setlistener = function( event, opts, fn )
        _registered[ event ] = fn
    end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( cmd, fn )
                    _registered.hub[ cmd ] = fn
                    return true
                end,
                has = function( ) return false end,
                list = function( ) return { } end,
            }
        end
        if name == "etc_report" then
            return {
                send = function( activate, hubbot, opchat, llevel, msg )
                    _reports_sent[ #_reports_sent + 1 ] = {
                        activate = activate, hubbot = hubbot, opchat = opchat,
                        llevel = llevel, msg = msg,
                    }
                end,
            }
        end
        if name == "etc_usercommands"  then return nil end
        if name == "cmd_help"          then return nil end
        if name == "bot_opchat"        then return nil end
        return nil
    end,
    escapefrom = function( s ) return s end,
    escapeto   = function( s ) return s end,
    http_register = function( method, path, scope, handler, meta )
        _registered.http[ method .. " " .. path ] = handler
    end,
}

_G.hub = stub_hub
_G.cfg = {
    get = function( key )
        if key == "language" then return "en" end
        if key == "etc_clientblocker_oplevel" then return 80 end
        if key == "etc_clientblocker_default_reason" then return "blocked default" end
        if key == "etc_clientblocker_max_pattern_len" then return 200 end
        if key == "etc_clientblocker_check_levels" then
            return {
                [ 0 ]   = true,  [ 10 ]  = true,  [ 20 ]  = true,
                [ 30 ]  = true,  [ 40 ]  = true,  [ 50 ]  = true,
                [ 55 ]  = false,
                [ 60 ]  = false, [ 70 ]  = false, [ 80 ]  = false,
                [ 100 ] = true,
            }
        end
        if key == "etc_clientblocker_report"        then return true  end
        if key == "etc_clientblocker_report_hubbot" then return false end
        if key == "etc_clientblocker_report_opchat" then return true  end
        if key == "etc_clientblocker_llevel"        then return 60    end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}
_G.util = {
    loadtable = function( )
        local r = _next_loaded
        _next_loaded = nil
        return r
    end,
    savetable = function( tbl )
        _saved_table = tbl
        return true
    end,
    -- REAL util.spairs impl from core/util.lua (intentional copy:
    -- the test must exercise the same mutate-orderedIndex behaviour
    -- so the R1 regression test catches early-return leaks). The
    -- only difference from the core impl is the `k ~= "orderedIndex"`
    -- guard in genOrderedIndex to avoid recursive re-indexing if a
    -- prior leak left the field in place (same as core does in #266
    -- variants but written explicitly here so the test stays
    -- self-contained).
    spairs = ( function( )
        local function genOrderedIndex( tbl )
            local idx = { }
            for k in pairs( tbl ) do
                if k ~= "orderedIndex" then idx[ #idx + 1 ] = k end
            end
            table.sort( idx )
            return idx
        end
        local function orderedNext( tbl, state )
            local key
            if state == nil then
                tbl.orderedIndex = genOrderedIndex( tbl )
                key = tbl.orderedIndex[ 1 ]
            else
                for i = 1, #tbl.orderedIndex do
                    if tbl.orderedIndex[ i ] == state then key = tbl.orderedIndex[ i + 1 ] end
                end
            end
            if key then return key, tbl[ key ] end
            tbl.orderedIndex = nil
            return
        end
        return function( tbl ) return orderedNext, tbl, nil end
    end )( ),
    strip_control_bytes = function( s ) return s end,
}
_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1

_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, actor = actor, target = target,
                 reason = reason, meta = meta }
    end,
    fire = function( ev ) _audit_fired[ #_audit_fired + 1 ] = ev end,
}

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-65s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

----------------------------------------------------------------------
-- load plugin + onStart so handlers + patterns_tbl are live
--
-- Pre-populate _next_loaded with a sentinel so the v0.10 seed-on-
-- empty logic (introduced for the testhub-sync bug) does NOT fire
-- and inject BUNDLED_DEFAULTS into patterns_tbl - those would
-- inflate the entry counts the rest of the test asserts against.
-- We clear the sentinel from patterns_tbl right after onStart so
-- the existing test cases run against a clean empty map.
----------------------------------------------------------------------

_next_loaded = { [ "__test_sentinel__" ] = "skip-seed" }
local plugin = assert( loadfile( "scripts/etc_clientblocker.lua" ) )( )
assert( _registered.onStart, "onStart not registered" )
assert( _registered.onConnect, "onConnect not registered" )
_registered.onStart( )
plugin.get_patterns_tbl( )[ "__test_sentinel__" ] = nil

local POST   = _registered.http[ "POST /v1/clientblocker" ];               assert( POST,   "POST not registered" )
local GET    = _registered.http[ "GET /v1/clientblocker" ];                assert( GET,    "GET not registered" )
local DELETE = _registered.http[ "DELETE /v1/clientblocker/{pattern}" ];   assert( DELETE, "DELETE not registered" )
local add_h  = _registered.hub.addblocker;                                 assert( add_h,  "+addblocker not registered" )
local del_h  = _registered.hub.delblocker;                                 assert( del_h,  "+delblocker not registered" )
local list_h = _registered.hub.blocker;                                    assert( list_h, "+blocker not registered" )

local function fresh_user( opts )
    opts = opts or { }
    local killed = nil
    local replied = nil
    local function noop( ) end
    return {
        level   = function( ) return opts.level   or 20 end,
        nick    = function( ) return opts.nick    or "tester" end,
        ip      = function( ) return opts.ip      or "1.2.3.4" end,
        version = function( ) return opts.version end,
        reply   = function( _, msg, _ ) replied = msg end,
        kill    = function( _, msg )    killed  = msg end,
    }, function( ) return killed end, function( ) return replied end
end

----------------------------------------------------------------------
-- 1. POST happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local r = POST{ body = { pattern = "badclient", reason = "stay out" }, token_label = "alice" }
    eq( "POST happy: status 201",     r.status,         201 )
    eq( "POST happy: action",         r.data.action,    "added" )
    eq( "POST happy: pattern echoed", r.data.pattern,   "badclient" )
    eq( "POST happy: reason echoed",  r.data.reason,    "stay out" )
    eq( "POST happy: resolve hits",   plugin.resolve( "badclient/1.0" ), "stay out" )
    eq( "POST happy: persisted",      _saved_table and _saved_table.badclient, "stay out" )
    eq( "POST happy: audit fired",    #_audit_fired, 1 )
    eq( "POST happy: audit action",   _audit_fired[ 1 ].action, "client.block.add" )
end

----------------------------------------------------------------------
-- 2. POST default reason when omitted
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "uglycli" }, token_label = "alice" }
    eq( "POST default reason: status",      r.status,       201 )
    eq( "POST default reason: stored",      plugin.resolve( "uglycli" ), "blocked default" )
    eq( "POST default reason: echo in resp", r.data.reason, "blocked default" )
end

----------------------------------------------------------------------
-- 3. POST reject: bad_pattern (empty)
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "" }, token_label = "alice" }
    eq( "bad_pattern empty: status", r.status,     400 )
    eq( "bad_pattern empty: code",   r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 4. POST reject: bad_pattern (too long)
----------------------------------------------------------------------

do
    -- 250 chars - over the 200 cap but pcall-safe. Mix in `%a`
    -- character classes so the body is a realistic-looking
    -- pattern, not just `aaaaa...`, so the long-cap branch is
    -- exercised independently of the compile-probe branch.
    local long_pat = string.rep( "x%a", 100 )    -- 300 chars
    local r = POST{ body = { pattern = long_pat }, token_label = "alice" }
    eq( "bad_pattern long: status",  r.status,     400 )
    eq( "bad_pattern long: code",    r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 5. POST reject: bad_pattern (fails compile probe)
----------------------------------------------------------------------

do
    -- Unbalanced bracket - Lua matcher will error on first run.
    local r = POST{ body = { pattern = "[abc" }, token_label = "alice" }
    eq( "bad_pattern compile: status", r.status,     400 )
    eq( "bad_pattern compile: code",   r.error.code, "bad_pattern" )
end

----------------------------------------------------------------------
-- 5b. POST reject: bad_pattern (URL-unsafe chars)
----------------------------------------------------------------------

do
    -- The DELETE endpoint uses the pattern as a path-var; the router
    -- captures with ([^/]+) and does not percent-decode. Patterns
    -- containing any of /?#& must be rejected at POST time so they
    -- never end up un-deletable.
    for _, ch in ipairs( { "/", "?", "#", "&" } ) do
        local r = POST{ body = { pattern = "pat" .. ch .. "x" }, token_label = "alice" }
        eq( "url-unsafe " .. ch .. ": status", r.status,     400 )
        eq( "url-unsafe " .. ch .. ": code",   r.error.code, "bad_pattern" )
    end
end

----------------------------------------------------------------------
-- 5c. POST reject: bad_pattern (dot-segment "." / "..", #617)
--     A bare "." or ".." is collapsed by URL path normalization so
--     DELETE /v1/clientblocker/{pattern} can never reach the route -
--     the entry would be un-removable via HTTP. Reject at POST time.
--     Regression per CLAUDE.md 1a.7: on the unpatched validate_pattern
--     these POSTs returned 201 (accepted); they now return 400. The
--     "a.b" case guards that we reject ONLY the exact dot-segments,
--     not every pattern containing a dot (real VE tags carry dots).
----------------------------------------------------------------------

do
    for _, seg in ipairs( { ".", ".." } ) do
        local r = POST{ body = { pattern = seg }, token_label = "alice" }
        eq( "dot-segment " .. seg .. ": status", r.status,     400 )
        eq( "dot-segment " .. seg .. ": code",   r.error.code, "bad_pattern" )
    end
    -- a dot elsewhere is still a legitimate pattern (must be accepted)
    local ok = POST{ body = { pattern = "a.b", reason = "x" }, token_label = "alice" }
    eq( "dotted pattern a.b: accepted", ok.status, 201 )
    -- cleanup so later count-based assertions are unaffected
    DELETE{ path_vars = { pattern = "a.b" }, token_label = "alice" }
end

----------------------------------------------------------------------
-- 6. POST reject: exists
----------------------------------------------------------------------

do
    local r = POST{ body = { pattern = "badclient", reason = "x" }, token_label = "alice" }
    eq( "exists: status", r.status,     409 )
    eq( "exists: code",   r.error.code, "exists" )
    eq( "exists: did not overwrite", plugin.resolve( "badclient" ), "stay out" )
end

----------------------------------------------------------------------
-- 7. GET list
----------------------------------------------------------------------

do
    local r = GET{ }
    eq( "GET: status", r.status,     200 )
    eq( "GET: count",  r.data.count, 2 )
    -- Sorted alphabetically by util.spairs stub.
    eq( "GET: row 1 pattern", r.data.patterns[ 1 ].pattern, "badclient" )
    eq( "GET: row 2 pattern", r.data.patterns[ 2 ].pattern, "uglycli" )
end

----------------------------------------------------------------------
-- 8. DELETE happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local r = DELETE{ path_vars = { pattern = "badclient" }, token_label = "alice" }
    eq( "DELETE happy: status",            r.status,         200 )
    eq( "DELETE happy: action",            r.data.action,    "deleted" )
    eq( "DELETE happy: previous reason",   r.data.previous,  "stay out" )
    eq( "DELETE happy: resolve nil",       plugin.resolve( "badclient" ), nil )
    eq( "DELETE happy: audit fired",       #_audit_fired,    1 )
    eq( "DELETE happy: audit action",      _audit_fired[ 1 ].action, "client.block.remove" )
end

----------------------------------------------------------------------
-- 9. DELETE reject: not_found
----------------------------------------------------------------------

do
    local r = DELETE{ path_vars = { pattern = "ghost" }, token_label = "alice" }
    eq( "not_found: status", r.status,     404 )
    eq( "not_found: code",   r.error.code, "not_found" )
end

----------------------------------------------------------------------
-- 10. check_clients onConnect - matching VE on covered level
----------------------------------------------------------------------

do
    -- Add "AirDC%+%+%s2" pattern, then clear the audit log so we
    -- only observe the .kick event from check_clients (the POST
    -- itself fires .add which would otherwise count toward
    -- #_audit_fired).
    POST{ body = { pattern = "AirDC%+%+%s2", reason = "old AirDC" }, token_label = "alice" }
    _audit_fired = { }
    _reports_sent = { }
    local user, killed_of = fresh_user{ level = 20, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "check covered level: PROCESSED", r,            1 )
    eq( "check covered level: kill issued", killed_of( ) and true or false, true )
    eq( "check covered level: ISTA prefix", killed_of( ) and killed_of( ):sub( 1, 9 ) or "", "ISTA 231 " )
    eq( "check covered level: audit fired", #_audit_fired,                  1 )
    eq( "check covered level: audit action", _audit_fired[ 1 ].action,      "client.block.kick" )
    -- Actor on the kick event is the plugin name (string shorthand
    -- supported by core/audit.lua's _snapshot_actor); the test stub
    -- just forwards the raw value so we assert the string directly.
    eq( "check covered level: audit actor", _audit_fired[ 1 ].actor,        "etc_clientblocker" )
    -- Opchat report fires too (Sopor-imported v0.10 feature).
    eq( "check covered level: report fired",   #_reports_sent,              1 )
    eq( "check covered level: report opchat",  _reports_sent[ 1 ].opchat,   true )
    eq( "check covered level: report hubbot",  _reports_sent[ 1 ].hubbot,   false )
    eq( "check covered level: report contains nick",    ( _reports_sent[ 1 ].msg or "" ):find( "tester", 1, true ) ~= nil, true )
    eq( "check covered level: report contains pattern", ( _reports_sent[ 1 ].msg or "" ):find( "AirDC%+%+%s2", 1, true ) ~= nil, true )
end

----------------------------------------------------------------------
-- 10c. check_clients level-exempt path does NOT fire the report
--      (SBOT level 55 is exempt by default - added in the Sopor
--      import). Regression for the "report fires even on exempt
--      level" hazard.
----------------------------------------------------------------------

do
    _reports_sent = { }
    _audit_fired = { }
    local user, killed_of = fresh_user{ level = 55, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "SBOT exempt: returns nil",  r,            nil )
    eq( "SBOT exempt: no kill",      killed_of( ), nil )
    eq( "SBOT exempt: no report",    #_reports_sent, 0 )
    eq( "SBOT exempt: no audit",     #_audit_fired,  0 )
end

----------------------------------------------------------------------
-- 10d. examples/data/etc_clientblocker.tbl.example Sopor-isms:
--      `%w` was normalised to literal `w` because Lua's `%w` matches
--      ANY word char (the original pattern silently over-blocked any
--      "AirDC++X 0.5" not just "AirDC++w 0.5"). `%n` is left as-is
--      (Lua 5.4 treats `%X` for non-class X as literal X). The two
--      assertions below are regression tests per CLAUDE.md §1a.7:
--      they would FAIL on the original Sopor pattern `^AirDC%+%+%w%s`
--      because the over-permissive class would let "AirDC++Q 0.5"
--      match, and they PASS on the normalised `^AirDC%+%+w%s`.
----------------------------------------------------------------------

do
    local pat = "^AirDC%+%+w%s"
    eq( "%w->w fix: AirDC++w 0.5 matches", ( "AirDC++w 0.5" ):find( pat ) ~= nil, true )
    eq( "%w->w fix: AirDC++Q 0.5 does NOT match", ( "AirDC++Q 0.5" ):find( pat ) ~= nil, false )
end

----------------------------------------------------------------------
-- 10e. examples/data/etc_clientblocker.tbl.example AirDC++ fork
--      catchall: `^AirDC%+%+[^%snw]` must MATCH unauthorised forks
--      (any AP-suffix that is not "w" / "n" / whitespace) and must
--      NOT match the three legitimate AirDC++ flavours (plain, Web,
--      nano).
----------------------------------------------------------------------

do
    local pat = "^AirDC%+%+[^%snw]"
    -- Legitimate (must NOT match):
    eq( "fork catchall: plain AirDC++ legit", ( "AirDC++ 4.30" ):find( pat ) ~= nil, false )
    eq( "fork catchall: AirDC++w legit",      ( "AirDC++w 2.14.0" ):find( pat ) ~= nil, false )
    eq( "fork catchall: AirDC++n legit",      ( "AirDC++n 1.2" ):find( pat ) ~= nil, false )
    -- Forks (MUST match):
    eq( "fork catchall: AirDC++Q",       ( "AirDC++Q 1.0" ):find( pat ) ~= nil, true )
    eq( "fork catchall: AirDC++X",       ( "AirDC++X 0.99" ):find( pat ) ~= nil, true )
    eq( "fork catchall: AirDC++3",       ( "AirDC++3 0.5" ):find( pat ) ~= nil, true )
    eq( "fork catchall: AirDC++Z-mod",   ( "AirDC++Z-mod 2.0" ):find( pat ) ~= nil, true )
    eq( "fork catchall: AirDC++pirate",  ( "AirDC++pirate 1.0" ):find( pat ) ~= nil, true )
end

----------------------------------------------------------------------
-- 10b. check_clients does NOT leak util.spairs `orderedIndex` field
--      into patterns_tbl after the kick early-returns. Regression
--      test for the security review R1 finding. The pre-fix code
--      ran `util_spairs(patterns_tbl)` and `return PROCESSED` mid-
--      iteration, leaving the internal `orderedIndex` array
--      attached to patterns_tbl. The test stub's util.spairs IS
--      the real impl (lifted from core/util.lua) so the leak is
--      observable here.
----------------------------------------------------------------------

do
    -- patterns_tbl currently has "AirDC%+%+%s2" (from test 10). A
    -- match + kick triggers the early-return; we then assert the
    -- internal util.spairs `orderedIndex` artifact did NOT leak
    -- through. Pre-fix code used `util_spairs(patterns_tbl)` +
    -- `return PROCESSED` mid-iteration, which leaked. The fix
    -- snapshot+sort+ipairs sidesteps it.
    local user, _killed_of = fresh_user{ level = 20, version = "AirDC++ 2.5.0" }
    _registered.onConnect( user )
    eq( "orderedIndex leak: not present", plugin.get_patterns_tbl( ).orderedIndex, nil )
end

----------------------------------------------------------------------
-- 11. check_clients onConnect - matching VE on exempt level (OP)
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 60, version = "AirDC++ 2.5.0" }
    local r = _registered.onConnect( user )
    eq( "check exempt level: returns nil", r,             nil )
    eq( "check exempt level: no kill",     killed_of( ),  nil )
end

----------------------------------------------------------------------
-- 12. check_clients onConnect - non-matching VE
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 20, version = "AirDC++ 4.10" }
    local r = _registered.onConnect( user )
    eq( "check non-match: returns nil", r,            nil )
    eq( "check non-match: no kill",     killed_of( ), nil )
end

----------------------------------------------------------------------
-- 13. check_clients onConnect - nil VE (F-INF-1d guard)
----------------------------------------------------------------------

do
    local user, killed_of = fresh_user{ level = 20, version = nil }
    local r = _registered.onConnect( user )
    eq( "check nil VE: returns nil", r,            nil )
    eq( "check nil VE: no kill",     killed_of( ), nil )
end

----------------------------------------------------------------------
-- 14. ADC: +addblocker happy path
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 80, nick = "admin" }
    add_h( user, "addblocker", "newpattern\\s\\d a kick reason here" )
    -- utf.match (string.match in stubs) splits on first whitespace, so
    -- pattern = "newpattern\\s\\d", reason = "a kick reason here"
    eq( "+addblocker: persisted",  plugin.resolve( "newpattern\\s\\d/1.0" ) ~= nil
                                   or plugin.get_patterns_tbl( )[ "newpattern\\s\\d" ] ~= nil, true )
    eq( "+addblocker: audit",      #_audit_fired, 1 )
    eq( "+addblocker: audit action", _audit_fired[ 1 ].action, "client.block.add" )
    eq( "+addblocker: reply set",  type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 15. ADC: +addblocker denied (low level)
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 20, nick = "joe" }
    add_h( user, "addblocker", "denypat reason" )
    eq( "+addblocker denied: no persist", plugin.get_patterns_tbl( )[ "denypat" ], nil )
    eq( "+addblocker denied: no audit",   #_audit_fired,    0 )
    eq( "+addblocker denied: reply set",  type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 16. ADC: +addblocker missing args
----------------------------------------------------------------------

do
    local user, _, replied_of = fresh_user{ level = 80 }
    add_h( user, "addblocker", "" )
    eq( "+addblocker empty: reply set", type( replied_of( ) ), "string" )
end

----------------------------------------------------------------------
-- 17. ADC: +delblocker happy
----------------------------------------------------------------------

do
    _audit_fired = { }
    local user, _, replied_of = fresh_user{ level = 80, nick = "admin" }
    del_h( user, "delblocker", "uglycli" )
    eq( "+delblocker: removed",    plugin.get_patterns_tbl( )[ "uglycli" ], nil )
    eq( "+delblocker: audit",      #_audit_fired, 1 )
    eq( "+delblocker: audit action", _audit_fired[ 1 ].action, "client.block.remove" )
end

----------------------------------------------------------------------
-- 18. ADC: +blocker list reply
----------------------------------------------------------------------

do
    local user, _, replied_of = fresh_user{ level = 80 }
    list_h( user, "blocker", "" )
    eq( "+blocker list: reply set",          type( replied_of( ) ), "string" )
    eq( "+blocker list: contains a pattern", ( replied_of( ) or "" ):find( "AirDC" ) ~= nil, true )
end

----------------------------------------------------------------------
-- 19. resolve() input handling
----------------------------------------------------------------------

eq( "resolve: nil input",    plugin.resolve( nil ),    nil )
eq( "resolve: number input", plugin.resolve( 42 ),     nil )
eq( "resolve: empty string", plugin.resolve( "" ),     nil )

----------------------------------------------------------------------
-- 20. +reload semantic: re-running onStart loads fresh from disk
----------------------------------------------------------------------

do
    -- Simulate operator hand-editing the file between reloads.
    _next_loaded = { manualpat = "from disk" }
    _registered.onStart( )
    eq( "reload: old in-memory map gone", plugin.get_patterns_tbl( )[ "AirDC%+%+%s2" ], nil )
    eq( "reload: new in-memory map live", plugin.get_patterns_tbl( )[ "manualpat" ],    "from disk" )
end

----------------------------------------------------------------------
-- 21. Seed-on-missing: when scripts/data/etc_clientblocker.tbl does
--     NOT exist on disk (util.loadtable returns nil), onStart seeds
--     the 6 bundled defaults into the in-memory map and persists
--     them. This is the canonical "first run" / fresh install path.
----------------------------------------------------------------------

do
    _saved_table = nil
    _next_loaded = nil    -- file missing (util_load returns nil)
    _registered.onStart( )
    local live = plugin.get_patterns_tbl( )
    local count = 0
    for _ in pairs( live ) do count = count + 1 end
    eq( "seed-on-missing: bundled count == 6", count, 6 )
    eq( "seed-on-missing: CleanDC default seeded",
        live[ "^CleanDC%+%+.+" ] ~= nil, true )
    eq( "seed-on-missing: FearDC default seeded",
        live[ "^FearDC.+" ] ~= nil, true )
    eq( "seed-on-missing: persisted to disk",
        _saved_table and _saved_table[ "^FearDC.+" ] ~= nil, true )
end

----------------------------------------------------------------------
-- 21b. NO seed-on-empty: when the .tbl EXISTS on disk but contains
--      an empty patterns table, that is the operator's deliberate
--      "I want zero patterns" state (e.g. they +delblocker'd all 6
--      bundled defaults). onStart must leave it alone - silently
--      re-seeding would undo the operator's intent. Per #81 follow-
--      up feedback from Aybo.
----------------------------------------------------------------------

do
    _saved_table = nil
    _next_loaded = { }    -- file EXISTS, parses to empty table
    _registered.onStart( )
    local live = plugin.get_patterns_tbl( )
    local count = 0
    for _ in pairs( live ) do count = count + 1 end
    eq( "empty .tbl exists: count stays at 0",        count,        0 )
    eq( "empty .tbl exists: FearDC NOT re-injected",  live[ "^FearDC.+" ], nil )
    eq( "empty .tbl exists: NOT persisted (no save)", _saved_table, nil )
end

----------------------------------------------------------------------
-- 22. Seed-on-non-empty: when the .tbl has any operator entries,
--     onStart MUST leave them alone (no merge with bundled defaults).
--     This is what protects an operator who has +delblocker'd a
--     bundled default from having it come back on reload.
----------------------------------------------------------------------

do
    _saved_table = nil
    _next_loaded = { [ "operator_only_pattern" ] = "kept" }
    _registered.onStart( )
    local live = plugin.get_patterns_tbl( )
    local count = 0
    for _ in pairs( live ) do count = count + 1 end
    eq( "non-empty .tbl: count stays at 1",                    count, 1 )
    eq( "non-empty .tbl: operator entry preserved",            live[ "operator_only_pattern" ], "kept" )
    eq( "non-empty .tbl: bundled NOT injected",                live[ "^FearDC.+" ], nil )
    eq( "non-empty .tbl: NOT re-persisted (no save call)",     _saved_table, nil )
end

----------------------------------------------------------------------
-- 22b. +delblocker by 1-based index from +blocker output. Operator
--      should not need to retype `^FearDC.+` (with the easy-to-miss
--      `^` anchor on the bundled defaults) - typing the row number
--      from the +blocker list works just as well.
----------------------------------------------------------------------

do
    -- Reset to a known state with 3 patterns. spairs sorts alpha so
    -- the order is: "aaa" -> 1, "mmm" -> 2, "zzz" -> 3.
    local tbl = plugin.get_patterns_tbl( )
    for k in pairs( tbl ) do tbl[ k ] = nil end
    tbl[ "aaa" ] = "aaa-reason"
    tbl[ "mmm" ] = "mmm-reason"
    tbl[ "zzz" ] = "zzz-reason"

    local user, _, replied_of = fresh_user{ level = 80, nick = "op" }

    -- Delete row 2 ("mmm") via index.
    del_h( user, "delblocker", "2" )
    eq( "delblocker by index 2: removed mmm", plugin.get_patterns_tbl( )[ "mmm" ], nil )
    eq( "delblocker by index 2: aaa still there", plugin.get_patterns_tbl( )[ "aaa" ], "aaa-reason" )
    eq( "delblocker by index 2: zzz still there", plugin.get_patterns_tbl( )[ "zzz" ], "zzz-reason" )

    -- After delete, indices re-shift: 1 = aaa, 2 = zzz. Delete row 1.
    del_h( user, "delblocker", "1" )
    eq( "delblocker by index 1: removed aaa", plugin.get_patterns_tbl( )[ "aaa" ], nil )
    eq( "delblocker by index 1: zzz still there", plugin.get_patterns_tbl( )[ "zzz" ], "zzz-reason" )

    -- Out-of-range index falls through to literal-pattern not_found.
    del_h( user, "delblocker", "99" )
    eq( "delblocker by index 99: literal-fallback not_found in reply",
        ( replied_of( ) or "" ):find( "No such pattern" ) ~= nil
        or ( replied_of( ) or "" ):find( "99" ) ~= nil, true )

    -- Literal pattern still works (post-fix, pattern "zzz" remains).
    del_h( user, "delblocker", "zzz" )
    eq( "delblocker literal: removed zzz", plugin.get_patterns_tbl( )[ "zzz" ], nil )
end

----------------------------------------------------------------------
-- 23. +blocker uses DMSG (3-arg reply) so multi-line list output
--     renders correctly across DC clients incl. AirDC++ (testhub
--     feedback: BMSG path appeared empty in AirDC++).
----------------------------------------------------------------------

do
    -- Need a fresh_user variant that captures the reply ARITY.
    local last_reply
    local op_user = {
        level = function( ) return 100 end,
        nick  = function( ) return "op" end,
        ip    = function( ) return "1.2.3.4" end,
        reply = function( _, msg, from, to )
            last_reply = { msg = msg, from = from, to = to }
        end,
        kill  = function( ) end,
    }
    list_h( op_user, "blocker", "" )
    eq( "+blocker: reply got a message",
        type( last_reply ) == "table" and type( last_reply.msg ) == "string", true )
    eq( "+blocker: reply is DMSG (3rd arg present)",
        last_reply.to ~= nil, true )
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
