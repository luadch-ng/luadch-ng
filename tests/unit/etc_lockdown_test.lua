--[[

    tests/unit/etc_lockdown_test.lua

    Unit tests for scripts/etc_lockdown.lua (#501 maintenance-mode gate).
    Exercises:
      - parse_time_reason: minutes-vs-reason split (cmd_ban grammar),
        notint / badtime rejects, no-arg, non-numeric-first -> reason
      - command minlevel guard + self-lockout guard (level > invoker)
      - enable: state shape, ABSOLUTE expiry timestamp, kick-online-below
        count (humans-only, staff untouched), persisted once
      - onConnect veto: below-level -> ISTA 226 + IQUI TL + PROCESSED;
        at/above-level -> nil, not killed
      - whitelist exemption (toggle on) + no exemption (toggle off)
      - TL: indefinite -> default_retry; timed -> remaining seconds
      - off / already-off / status (on + off)
      - auto-expiry via onTimer + boot-expiry clear
      - persisted lockdown reloads on plugin load

    Plugins get NO `use`; every dependency is a sandbox-global stub.
    Run: lua5.4 tests/unit/etc_lockdown_test.lua

]]--

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
local function contains( what, hay, needle )
    truthy( what, type( hay ) == "string" and hay:find( needle, 1, true ) ~= nil )
end

----------------------------------------------------------------------
-- Controllable clock + capture state
----------------------------------------------------------------------
local _now = 1000000
local _cfg, _persisted, _saved, _save_count, _reports, _audit, _online, _wl, _loadtable_called

local function reset_cfg( )
    _cfg = {
        language = "en",
        etc_lockdown_command_minlevel = 60,
        etc_lockdown_default_retry    = 120,
        etc_lockdown_exempt_whitelist = true,
        etc_lockdown_report        = true,
        etc_lockdown_report_hubbot = false,
        etc_lockdown_report_opchat = true,
        etc_lockdown_llevel        = 60,
    }
end
local function fresh( )
    _saved = nil; _save_count = 0; _reports = { }; _audit = { }
    _online = { }; _wl = { }
    _loadtable_called = false
end

----------------------------------------------------------------------
-- Sandbox globals
----------------------------------------------------------------------
_G.use = nil
_G.PROCESSED = "PROCESSED"
_G.table, _G.string, _G.math = table, string, math
_G.type, _G.pairs, _G.ipairs, _G.next = type, pairs, ipairs, next
_G.tonumber, _G.tostring, _G.pcall = tonumber, tostring, pcall

local _real_os = os
_G.os = setmetatable( { time = function( ) return _now end }, { __index = _real_os } )

-- io stub: override open() to simulate the store file's existence - it exists
-- iff there is persisted state to load (mirrors reality; the .tbl is written
-- only on the first state change), so the fresh-hub path exercises the plugin's
-- io.open peek. Everything else (stderr, write) falls through to the real io.
local _real_io = io
_G.io = setmetatable( {
    open = function( path )
        if _persisted ~= nil then return { close = function( ) end } end
        return nil, tostring( path ) .. ": No such file or directory"
    end,
}, { __index = _real_io } )

_G.util = {
    loadtable = function( ) _loadtable_called = true; return _persisted end,
    savetable = function( t, name, path ) _saved = t; _save_count = _save_count + 1 end,
    strip_control_bytes = function( s ) return s end,
}
-- The HTTP actor-label helper ( core/util_http ) is a sandbox global; the
-- handlers use it for by_nick + audit. Stub the X-Actor -> token-label -> default
-- fallback it implements.
_G.util_http = {
    operator_label = function( req )
        if req and type( req.actor ) == "string" and req.actor ~= "" then return req.actor end
        return ( req and req.token_label ) or "http-api"
    end,
}
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
    match  = function( s, pat ) return string.match( s, pat ) end,
}
_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, meta = meta or { } }
    end,
    fire = function( ev ) _audit[ #_audit + 1 ] = ev end,
}
_G.whitelist = { is_whitelisted = function( ip ) return _wl[ ip ] == true end }
_G.hub = {
    setlistener = function( ev, _opts, fn ) _G._listeners[ ev ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "bot" end,
    getusers    = function( ) return _online end,
    escapeto    = function( s ) return s end,
    http_register = function( method, path, _scope, handler ) _G._http[ method .. " " .. path ] = handler end,
    import      = function( name )
        if name == "etc_hubcommands" then return { add = function( ) return true end } end
        if name == "cmd_help" then return { reg = function( ) end } end
        if name == "etc_usercommands" then return { add = function( ) end } end
        if name == "etc_report" then
            return { send = function( _a, _h, _o, _l, msg ) _reports[ #_reports + 1 ] = msg end }
        end
        return nil
    end,
}

local function mkuser( level, ip, sid, nick )
    local u
    u = {
        level     = function( ) return level end,
        ip        = function( ) return ip end,
        sid       = function( ) return sid end,
        nick      = function( ) return nick or ( "u" .. tostring( sid ) ) end,
        firstnick = function( ) return nick or ( "u" .. tostring( sid ) ) end,
        kill      = function( _, adc, q1 ) u._killed = adc; u._killtl = q1 end,
        reply     = function( _, msg ) u._reply = msg end,
    }
    return u
end

local function load_plugin( overrides, persisted )
    reset_cfg( )
    if overrides then for k, v in pairs( overrides ) do _cfg[ k ] = v end end
    fresh( )
    _persisted = persisted
    _G._listeners = { }
    _G._http = { }
    local p = assert( loadfile( "scripts/etc_lockdown.lua" ) )( )
    if _G._listeners.onStart then _G._listeners.onStart( ) end
    return p, _G._listeners
end

----------------------------------------------------------------------
-- parse_time_reason (minutes-vs-reason split)
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local function pr( s ) return p._parse_time_reason( s ) end

    local m, r, e = pr( "30 maintenance" )
    eq( "parse: '30 maintenance' minutes", m, 30 ); eq( "parse: reason", r, "maintenance" ); eq( "parse: no err", e, nil )

    m, r, e = pr( "5" )
    eq( "parse: '5' minutes", m, 5 ); eq( "parse: '5' no reason", r, nil ); eq( "parse: '5' no err", e, nil )

    m, r, e = pr( "maintenance in progress" )
    eq( "parse: non-numeric -> no minutes", m, nil ); eq( "parse: whole tail is reason", r, "maintenance in progress" )

    m, r, e = pr( "" )
    eq( "parse: empty -> no minutes", m, nil ); eq( "parse: empty -> no reason", r, nil )

    m, r, e = pr( "1.5 x" )
    eq( "parse: decimal rejected", e, "notint" ); eq( "parse: decimal no minutes", m, nil )

    m, r, e = pr( "0 x" )
    eq( "parse: zero rejected", e, "badtime" )

    m, r, e = pr( "-3 x" )
    eq( "parse: negative rejected", e, "badtime" )

    -- hardening: integer-valued floats and inf must NOT slip through as
    -- minutes (would give a float expires_at or a never-expiring "timed"
    -- lockdown + a malformed "TL inf" reconnect hint)
    m, r, e = pr( "1e3 x" )                          -- 1000.0, a float
    eq( "parse: integer-valued float rejected", e, "notint" )
    m, r, e = pr( "1e999 x" )                        -- math.huge
    eq( "parse: inf rejected", e, "notint" )
    m, r, e = pr( "525601 x" )                       -- over the 1-year cap
    eq( "parse: over-cap rejected", e, "badtime" )
    m, r, e = pr( "525600" )                         -- exactly the cap
    eq( "parse: at-cap accepted", m, 525600 )

    -- cmd_ban-style ambiguity: a reason that starts with a number is read
    -- as minutes, exactly like +ban. Documented, operator-known behaviour.
    m, r = pr( "2 hours downtime" )
    eq( "parse: numeric-first taken as minutes", m, 2 ); eq( "parse: rest is reason", r, "hours downtime" )
end

----------------------------------------------------------------------
-- command guards: minlevel + self-lockout
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local low = mkuser( 40, "1.1.1.1", "S1" )      -- below command_minlevel 60
    local r = p._on_lockdown( low, "lockdown", "60" )
    eq( "guard: below minlevel -> PROCESSED", r, "PROCESSED" )
    falsy( "guard: below minlevel did NOT enable", p._state( ).active )

    local op = mkuser( 60, "2.2.2.2", "S2" )       -- level 60 op
    p._on_lockdown( op, "lockdown", "80" )          -- tries to lock above own level
    falsy( "self-lockout: level>own rejected -> not active", p._state( ).active )

    p._on_lockdown( op, "lockdown", "60" )          -- own level is allowed
    truthy( "self-lockout: level==own allowed", p._state( ).active )
    eq( "self-lockout: level set", p._state( ).level, 60 )
end

----------------------------------------------------------------------
-- enable: state, absolute expiry, kick-online-below, persist
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    _online = {
        A = mkuser( 20, "10.0.0.1", "A" ),   -- kicked
        B = mkuser( 30, "10.0.0.2", "B" ),   -- kicked
        C = mkuser( 80, "10.0.0.3", "C" ),   -- staff, untouched
    }
    local owner = mkuser( 100, "9.9.9.9", "OWN", "owner" )
    p._on_lockdown( owner, "lockdown", "60 5 scheduled maintenance" )

    truthy( "enable: active", p._state( ).active )
    eq( "enable: level", p._state( ).level, 60 )
    eq( "enable: message", p._state( ).message, "scheduled maintenance" )
    eq( "enable: ABSOLUTE expiry = now + 5min", p._state( ).expires_at, _now + 300 )
    eq( "enable: by_nick", p._state( ).by_nick, "owner" )
    truthy( "enable: persisted", _save_count >= 1 )
    eq( "enable: persisted absolute expiry", _saved.expires_at, _now + 300 )

    truthy( "enable: A (l20) kicked", _online.A._killed ~= nil )
    truthy( "enable: B (l30) kicked", _online.B._killed ~= nil )
    falsy( "enable: C (l80 staff) NOT kicked", _online.C._killed )
    contains( "enable: kick uses ISTA 226", _online.A._killed, "ISTA 226" )
    contains( "enable: reason in kick", _online.A._killed, "scheduled maintenance" )
    contains( "enable: TL is remaining (~300)", _online.A._killtl, "TL30" ) -- "TL300" starts with TL30
    truthy( "enable: audit fired", #_audit >= 1 )
    eq( "enable: audit action", _audit[ #_audit ].action, "lockdown.enable" )
end

----------------------------------------------------------------------
-- onConnect veto
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    local owner = mkuser( 100, "9.9.9.9", "OWN", "owner" )
    p._on_lockdown( owner, "lockdown", "60" )      -- indefinite lockdown at 60

    local below = mkuser( 20, "3.3.3.3", "X" )
    local r = L.onConnect( below )
    eq( "connect: below-level refused (PROCESSED)", r, "PROCESSED" )
    truthy( "connect: below-level killed", below._killed ~= nil )
    contains( "connect: ISTA 226", below._killed, "ISTA 226" )
    contains( "connect: indefinite TL = default_retry 120", below._killtl, "TL120" )

    local at = mkuser( 60, "4.4.4.4", "Y" )
    eq( "connect: at-level admitted (nil)", L.onConnect( at ), nil )
    falsy( "connect: at-level not killed", at._killed )

    local above = mkuser( 80, "5.5.5.5", "Z" )
    eq( "connect: above-level admitted (nil)", L.onConnect( above ), nil )
    falsy( "connect: above-level not killed", above._killed )
end

----------------------------------------------------------------------
-- whitelist exemption
----------------------------------------------------------------------
do
    local p, L = load_plugin( )                    -- exempt_whitelist defaults true
    p._on_lockdown( mkuser( 100, "9.9.9.9", "OWN" ), "lockdown", "60" )
    _wl[ "7.7.7.7" ] = true
    local pinger = mkuser( 10, "7.7.7.7", "P" )
    eq( "whitelist: exempt IP admitted (nil)", L.onConnect( pinger ), nil )
    falsy( "whitelist: exempt IP not killed", pinger._killed )

    local other = mkuser( 10, "8.8.8.8", "Q" )     -- not whitelisted
    eq( "whitelist: non-exempt low-level refused", L.onConnect( other ), "PROCESSED" )
end

do
    -- toggle OFF: a whitelisted low-level user IS kicked
    local p, L = load_plugin( { etc_lockdown_exempt_whitelist = false } )
    p._on_lockdown( mkuser( 100, "9.9.9.9", "OWN" ), "lockdown", "60" )
    _wl[ "7.7.7.7" ] = true
    local pinger = mkuser( 10, "7.7.7.7", "P" )
    eq( "whitelist-off: whitelisted low-level refused", L.onConnect( pinger ), "PROCESSED" )
end

----------------------------------------------------------------------
-- off / already-off / status
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    local owner = mkuser( 100, "9.9.9.9", "OWN", "owner" )

    p._on_lockdown( owner, "lockdown", "status" )
    contains( "status: OFF before enable", owner._reply, "OFF" )

    p._on_lockdown( owner, "lockdown", "60 nachtwartung" )
    p._on_lockdown( owner, "lockdown", "status" )
    contains( "status: ON after enable", owner._reply, "ON" )
    contains( "status: shows message", owner._reply, "nachtwartung" )

    p._on_lockdown( owner, "lockdown", "off" )
    falsy( "off: not active", p._state( ).active )
    local below = mkuser( 20, "3.3.3.3", "X" )
    eq( "off: below-level now admitted", L.onConnect( below ), nil )

    p._on_lockdown( owner, "lockdown", "off" )     -- already off
    contains( "already-off: informs", owner._reply, "not active" )
end

----------------------------------------------------------------------
-- auto-expiry via onTimer
----------------------------------------------------------------------
do
    local p, L = load_plugin( )
    local owner = mkuser( 100, "9.9.9.9", "OWN", "owner" )
    p._on_lockdown( owner, "lockdown", "60 5" )    -- 5 minutes
    truthy( "expiry: active before deadline", p._state( ).active )

    -- Before deadline, onTimer is a no-op and the gate still refuses.
    L.onTimer( )
    truthy( "expiry: still active pre-deadline", p._state( ).active )
    eq( "expiry: refuses pre-deadline", L.onConnect( mkuser( 20, "1.2.3.4", "X" ) ), "PROCESSED" )

    _now = _now + 301                               -- past the deadline
    L.onTimer( )
    falsy( "expiry: cleared post-deadline", p._state( ).active )
    eq( "expiry: admits post-deadline", L.onConnect( mkuser( 20, "1.2.3.4", "X" ) ), nil )
    truthy( "expiry: audit fired", ( function( )
        for _, e in ipairs( _audit ) do if e.action == "lockdown.expire" then return true end end
    end )( ) )
    _now = 1000000
end

----------------------------------------------------------------------
-- persisted lockdown reloads on plugin load
----------------------------------------------------------------------
do
    -- a still-valid persisted lockdown survives a reload
    local p, L = load_plugin( nil, { active = true, level = 60, message = "persisted",
        expires_at = _now + 600, by_nick = "op", by_level = 60, started_at = _now } )
    truthy( "reload: persisted lockdown active", p._state( ).active )
    eq( "reload: refuses below-level", L.onConnect( mkuser( 20, "1.2.3.4", "X" ) ), "PROCESSED" )
end

do
    -- a persisted lockdown that already expired while the hub was down is
    -- cleared on boot (onStart)
    local p, L = load_plugin( nil, { active = true, level = 60, message = "stale",
        expires_at = _now - 10, by_nick = "op", by_level = 60, started_at = _now - 100 } )
    falsy( "reload: expired-while-down cleared on boot", p._state( ).active )
    eq( "reload: admits after boot-clear", L.onConnect( mkuser( 20, "1.2.3.4", "X" ) ), nil )
end

do
    -- HARDENING (review finding): a corrupt / hand-edited store with
    -- active=true but NO numeric level must degrade to inactive, not
    -- crash every onConnect (a level comparison against nil = hub-wide
    -- login block).
    local p, L = load_plugin( nil, { active = true, message = "corrupt" } )
    falsy( "corrupt: active-without-level coerced to inactive", p._state( ).active )
    eq( "corrupt: onConnect admits, no crash", L.onConnect( mkuser( 20, "1.2.3.4", "X" ) ), nil )

    -- non-numeric expires_at is likewise coerced
    local p2, L2 = load_plugin( nil, { active = true, level = 60, expires_at = "soon" } )
    falsy( "corrupt: bad expires_at coerced to inactive", p2._state( ).active )
end

----------------------------------------------------------------------
-- fresh hub ( no store file ): the io.open peek short-circuits so
-- util.loadtable ( and thus util.checkfile ) is NOT called, and no
-- "No such file" checkfile line is logged on every boot / +reload.
-- Proven RED on the pre-fix load that called util.loadtable directly.
----------------------------------------------------------------------
do
    local p = load_plugin( )                        -- persisted nil -> store "missing"
    falsy( "fresh-hub: util.loadtable NOT called ( no checkfile noise )", _loadtable_called )
    falsy( "fresh-hub: state inactive", p._state( ).active )
end

do
    -- when the store DOES exist, loadtable is still consulted and the
    -- persisted lockdown loads ( the peek only skips the missing-file case )
    local p = load_plugin( nil, { active = true, level = 60, expires_at = _now + 600,
        by_nick = "op", by_level = 60, started_at = _now } )
    truthy( "existing-store: util.loadtable consulted", _loadtable_called )
    truthy( "existing-store: persisted lockdown active", p._state( ).active )
end

----------------------------------------------------------------------
-- HTTP API ( v0.03, #699 ): GET status + POST engage ( 0-99 cap ) +
-- DELETE lift. Handlers captured from hub.http_register in onStart; RED
-- pre-fix ( the three routes are unregistered on v0.02 ).
----------------------------------------------------------------------
do
    local p = load_plugin( )
    local GET  = _G._http[ "GET /v1/lockdown" ]
    local POST = _G._http[ "POST /v1/lockdown" ]
    local DEL  = _G._http[ "DELETE /v1/lockdown" ]
    truthy( "http: GET /v1/lockdown registered",    GET ~= nil )
    truthy( "http: POST /v1/lockdown registered",   POST ~= nil )
    truthy( "http: DELETE /v1/lockdown registered", DEL ~= nil )

    -- GET while off
    local r = GET( { } )
    eq( "http GET off: status 200", r.status, 200 )
    eq( "http GET off: active false", r.data.active, false )

    -- POST engage: level 60, 5 min, message; one online below is kicked, staff not
    _online = { A = mkuser( 20, "10.0.0.1", "A" ), C = mkuser( 80, "10.0.0.3", "C" ) }
    r = POST( { body = { level = 60, minutes = 5, message = "webui maint" }, token_label = "tok", actor = "adminop" } )
    eq( "http POST: status 200", r.status, 200 )
    eq( "http POST: active", r.data.active, true )
    eq( "http POST: level", r.data.level, 60 )
    eq( "http POST: message", r.data.message, "webui maint" )
    eq( "http POST: kicked = 1 ( A l20; C l80 staff exempt )", r.data.kicked, 1 )
    truthy( "http POST: A kicked", _online.A._killed ~= nil )
    falsy(  "http POST: C staff not kicked", _online.C._killed )
    eq( "http POST: expires_at absolute", r.data.expires_at, _now + 300 )
    eq( "http POST: remaining_seconds = 300", r.data.remaining_seconds, 300 )
    eq( "http POST: indefinite false", r.data.indefinite, false )
    eq( "http POST: by_nick = X-Actor label", r.data.by_nick, "adminop" )
    truthy( "http POST: state active", p._state( ).active )
    eq( "http POST: audit action lockdown.enable", _audit[ #_audit ].action, "lockdown.enable" )

    -- GET reflects the live state
    r = GET( { } )
    eq( "http GET on: active", r.data.active, true )
    eq( "http GET on: level", r.data.level, 60 )

    -- DELETE lift
    r = DEL( { token_label = "tok" } )
    eq( "http DELETE: status 200", r.status, 200 )
    eq( "http DELETE: active false", r.data.active, false )
    eq( "http DELETE: was_active true", r.data.was_active, true )
    falsy( "http DELETE: state inactive", p._state( ).active )
    eq( "http DELETE: audit lockdown.disable", _audit[ #_audit ].action, "lockdown.disable" )

    -- DELETE when already off -> was_active false, no new audit
    local n_before = #_audit
    r = DEL( { token_label = "tok" } )
    eq( "http DELETE off: was_active false", r.data.was_active, false )
    eq( "http DELETE off: no audit fired", #_audit, n_before )

    -- by_nick falls back to token_label when X-Actor absent
    r = POST( { body = { level = 50 }, token_label = "onlytoken" } )
    eq( "http POST: by_nick falls back to token_label", r.data.by_nick, "onlytoken" )
    DEL( { token_label = "tok" } )
end

do
    -- POST validation: HTTP level cap 0-99, integer + range; minutes int/range;
    -- message must be a string. Every bad body -> 400 and NOTHING engages.
    local p = load_plugin( )
    local POST = _G._http[ "POST /v1/lockdown" ]

    local function bad( label, body )
        local r = POST( { body = body, token_label = "tok" } )
        eq( label .. ": status 400", r.status, 400 )
        falsy( label .. ": stays off", p._state( ).active )
    end
    bad( "level 100 ( HTTP cap )", { level = 100 } )
    bad( "level -1",               { level = -1 } )
    bad( "level 60.5 ( non-int )", { level = 60.5 } )
    bad( "level missing",          { } )
    bad( "level string",           { level = "60" } )
    bad( "minutes 0",              { level = 60, minutes = 0 } )
    bad( "minutes 1.5",            { level = 60, minutes = 1.5 } )
    bad( "minutes over cap",       { level = 60, minutes = 525601 } )
    bad( "message non-string",     { level = 60, message = 5 } )
    bad( "message over 256",       { level = 60, message = string.rep( "x", 257 ) } )
    falsy( "validation: nothing engaged after all bad inputs", p._state( ).active )

    -- boundary: level 99 ( the cap ) and level 0 are accepted
    local r = POST( { body = { level = 99 }, token_label = "tok" } )
    eq( "level 99 ( cap boundary ) accepted", r.data.active, true )
    eq( "level 99: indefinite ( no minutes )", r.data.indefinite, true )
    falsy( "level 99: no expires_at", r.data.expires_at )

    -- The design invariant the 0-99 cap exists for: a level-99 HTTP engage
    -- must NEVER lock out a level-100 owner. Prove it at the onConnect gate
    -- ( is_exempt: 100 >= 99 ), and that a level-98 user IS refused.
    local L = _G._listeners
    local owner = mkuser( 100, "1.1.1.1", "O" )
    eq(    "cap: level-100 owner admitted under a level-99 lockdown", L.onConnect( owner ), nil )
    falsy( "cap: level-100 owner not killed", owner._killed )
    eq(    "cap: level-98 refused under a level-99 lockdown", L.onConnect( mkuser( 98, "2.2.2.2", "Lo" ) ), "PROCESSED" )
end

----------------------------------------------------------------------
io.write( string.format( "\netc_lockdown: %d passed, %d failed\n", _pass, _fail ) )
os.exit( _fail == 0 and 0 or 1 )
