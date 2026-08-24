--[[

    tests/unit/ratelimit_test.lua

    Regression + sanity tests for core/ratelimit.lua's per-IP accept
    guard (Phase 7c F-NET-1).

    Primary regression: accept_ip(nil) must NOT crash. server.lua calls
    ratelimit_accept_ip(clientip) where clientip comes from
    client:getpeername(), which returns nil when the peer resets the
    connection between accept() and the getpeername() call (trivially
    remote-triggerable). Pre-fix, accept_ip built the token-bucket key
    as `"ip:" .. ip`, so a nil ip raised "attempt to concatenate a nil
    value (local 'ip')" INSIDE the accept loop and took the whole
    listener down - the hub stopped accepting connections and dropped
    users (reported by Sopor on 3.1.11, present on all lines). release_ip
    already guarded nil; accept_ip did not.

    Run: lua5.4 tests/unit/ratelimit_test.lua   (or C:\lua-5.4.8_Win64_bin\lua54.exe)
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim. ratelimit.lua pulls stdlib + socket + cfg via use("X")
-- under init.lua's restricted env. socket.gettime and cfg.get are
-- stubbed; init() reads the ratelimit_* cfg keys (some with unguarded
-- arithmetic, so they must resolve to numbers).
----------------------------------------------------------------------

local _now = 1000.0

-- #648: cfg-reload listeners registered by ratelimit.init() land here so
-- the test can fire them the way cfg.lua's reload() does.
local _reload_listeners = { }

local _cfg = {
    ratelimit_activate            = true,
    ratelimit_bypass_level        = 60,
    ratelimit_perip_max_conns     = 5,
    ratelimit_perip_conn_rate     = 1,
    ratelimit_perip_conn_burst    = 3,
    ratelimit_handshake_timeout   = 10,
    ratelimit_perip_authfail_rate = 6,
    ratelimit_perip_authfail_burst= 3,
    ratelimit_authfail_lockout    = 300,
    ratelimit_user_msg_rate       = 1, ratelimit_user_msg_burst    = 5,
    ratelimit_user_pm_rate        = 1, ratelimit_user_pm_burst     = 5,
    ratelimit_user_inf_rate       = 1, ratelimit_user_inf_burst    = 5,
    ratelimit_user_ctm_rate       = 1, ratelimit_user_ctm_burst    = 5,
    ratelimit_user_search_period  = 5, ratelimit_user_search_burst = 3,
    -- ratelimit_tiers / ratelimit_tier_for_level left nil (type-guarded)
    -- http_api_* left nil (all guarded with in-code defaults)
}

local _real = {
    pairs    = pairs,
    ipairs   = ipairs,
    tostring = tostring,
    type     = type,
    math     = math,
    socket   = { gettime = function( ) return _now end },
    cfg      = {
        get = function( k ) return _cfg[ k ] end,
        -- #648: capture cfg-reload listeners so the test can simulate
        -- cfg.reload() firing them (the real cfg.lua does exactly this).
        registerevent = function( what, fn )
            if what == "reload" then
                _reload_listeners[ #_reload_listeners + 1 ] = fn
            end
        end,
    },
}

_G.use = function( name )
    local m = _real[ name ]
    if m == nil then
        error( "ratelimit_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return m
end

local rl = assert( loadfile( "core/ratelimit.lua" ) )( )
rl.init( )

----------------------------------------------------------------------
-- Tiny test harness.
----------------------------------------------------------------------

local _passes, _fails = 0, 0

local function eq( what, got, expected )
    if got == expected then
        _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format(
            "FAIL: %s\n  got:      %s\n  expected: %s\n",
            what, tostring( got ), tostring( expected )
        ) )
    end
end

----------------------------------------------------------------------
-- PRIMARY REGRESSION: accept_ip(nil) must not crash.
-- Pre-fix this raises at `"ip:" .. ip`; pcall returns ok=false.
----------------------------------------------------------------------

local ok, res = pcall( rl.accept_ip, nil )
eq( "accept_ip(nil) does not crash (getpeername raced with a reset)", ok, true )
eq( "accept_ip(nil) returns true (allow; caller drops the dead socket)", res, true )

-- release_ip(nil) has always been guarded; lock that in for symmetry.
local ok_rel = pcall( rl.release_ip, nil )
eq( "release_ip(nil) does not crash", ok_rel, true )

----------------------------------------------------------------------
-- SANITY: the limiter still functions for a real IP, so the nil guard
-- did not neuter it. burst = 3 at a fixed clock, so the 4th accept in
-- the same instant is rate-refused.
----------------------------------------------------------------------

eq( "accept_ip(valid) allows 1st", ( rl.accept_ip( "8.8.8.8" ) ), true )
eq( "accept_ip(valid) allows 2nd", ( rl.accept_ip( "8.8.8.8" ) ), true )
eq( "accept_ip(valid) allows 3rd", ( rl.accept_ip( "8.8.8.8" ) ), true )
eq( "accept_ip(valid) refuses 4th (conn-rate burst exhausted)",
    ( rl.accept_ip( "8.8.8.8" ) ), false )

-- A different IP is independent (its own bucket).
eq( "accept_ip(other IP) unaffected", ( rl.accept_ip( "9.9.9.9" ) ), true )

----------------------------------------------------------------------
-- HTTP /v1/auth/verify password-oracle bucket: per-nick AND per-IP,
-- BOTH must have budget. Defaults (nil cfg) -> burst 3; fixed clock so
-- no refill. Uses the "authverify*" key namespace, distinct from the
-- accept_ip "ip:" buckets above (no cross-talk).
----------------------------------------------------------------------

-- per-nick exhaustion (brute one account): burst 3, 4th refused.
eq( "authverify: alice allow 1", ( rl.http_authverify( "alice", "1.1.1.1" ) ), true )
eq( "authverify: alice allow 2", ( rl.http_authverify( "alice", "1.1.1.1" ) ), true )
eq( "authverify: alice allow 3", ( rl.http_authverify( "alice", "1.1.1.1" ) ), true )
eq( "authverify: alice refuse 4 (bucket empty)", ( rl.http_authverify( "alice", "1.1.1.1" ) ), false )

-- per-IP gates spraying a DIFFERENT nick from the same IP (1.1.1.1's
-- IP bucket was drained by alice, so bob is refused despite a fresh nick).
eq( "authverify: bob/1.1.1.1 refused (per-IP bucket drained)",
    ( rl.http_authverify( "bob", "1.1.1.1" ) ), false )

-- per-nick gates a DISTRIBUTED brute-force of one account across fresh
-- IPs (dave's nick bucket empties regardless of the source IP).
eq( "authverify: dave/ip-a allow", ( rl.http_authverify( "dave", "10.0.0.1" ) ), true )
eq( "authverify: dave/ip-b allow", ( rl.http_authverify( "dave", "10.0.0.2" ) ), true )
eq( "authverify: dave/ip-c allow", ( rl.http_authverify( "dave", "10.0.0.3" ) ), true )
eq( "authverify: dave/ip-d refused (per-nick empty, fresh IP)",
    ( rl.http_authverify( "dave", "10.0.0.4" ) ), false )

-- a fresh nick + fresh IP is independent.
eq( "authverify: carol/fresh -> allow", ( rl.http_authverify( "carol", "203.0.113.7" ) ), true )

----------------------------------------------------------------------
-- #648 REGRESSION: a ratelimit cfg change must take effect on
-- cfg.reload(), not only at a full restart. Pre-fix, init() registered
-- no cfg-reload listener, so the cached _http_burst kept its boot value
-- and PUT /v1/config + POST /v1/reload silently no-op'd until restart
-- despite reporting apply_status "reload_required". Post-fix init()
-- subscribes _apply_cfg, which re-reads the cfg AND clears the buckets
-- so a raised burst applies at once (restart-equivalent).
--
-- fire_reload() replays what cfg.reload() does: mutate _cfg, then call
-- every registered "reload" listener. Fixed clock => buckets never
-- refill, so token counts are exact.
----------------------------------------------------------------------

local function fire_reload( )
    for _, fn in ipairs( _reload_listeners ) do fn( ) end
end

-- The no-growth safety argument rests on init() registering the reload
-- listener exactly once (in init, not in the re-run _apply_cfg). init()
-- ran once at load (line ~78); lock the invariant before any second init.
eq( "init registered exactly one cfg-reload listener", #_reload_listeners, 1 )

-- Establish a small admin burst and drain it.
_cfg.http_api_burst      = 4
_cfg.http_api_rate_admin = 60      -- >0; fixed clock => no refill
fire_reload( )
for i = 1, 4 do
    eq( "http_token admin allow " .. i .. " (burst 4)", ( rl.http_token( "op", "admin" ) ), true )
end
eq( "http_token admin refuse 5 (burst 4 exhausted)", ( rl.http_token( "op", "admin" ) ), false )

-- Operator raises the burst and reloads. The SAME token must immediately
-- see the new capacity. Pre-fix _http_burst never refreshed (and the old
-- bucket was never cleared), so this stayed throttled at 4 -> RED.
_cfg.http_api_burst = 12
fire_reload( )
for i = 1, 12 do
    eq( "http_token admin allow " .. i .. " after reload (burst 12)", ( rl.http_token( "op", "admin" ) ), true )
end
eq( "http_token admin refuse 13 after reload (new burst 12 exhausted)",
    ( rl.http_token( "op", "admin" ) ), false )

-- A LOWERED limit must apply on reload too: cut the burst, reload, and a
-- fresh token gets only the new (smaller) capacity.
_cfg.http_api_burst = 2
fire_reload( )
eq( "http_token admin allow 1 after lowering reload (burst 2)", ( rl.http_token( "op2", "admin" ) ), true )
eq( "http_token admin allow 2 after lowering reload (burst 2)", ( rl.http_token( "op2", "admin" ) ), true )
eq( "http_token admin refuse 3 after lowering reload (burst 2 exhausted)",
    ( rl.http_token( "op2", "admin" ) ), false )

----------------------------------------------------------------------
-- Disabled limiter: accept_ip returns true for any input incl. nil,
-- without touching the bucket machinery.
----------------------------------------------------------------------

_cfg.ratelimit_activate = false
rl.init( )
eq( "disabled: accept_ip(nil) true",   ( rl.accept_ip( nil ) ),       true )
eq( "disabled: accept_ip(valid) true", ( rl.accept_ip( "1.2.3.4" ) ), true )
eq( "disabled: http_authverify true",  ( rl.http_authverify( "x", "1.2.3.4" ) ), true )

----------------------------------------------------------------------
-- Output
----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format(
        "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails
    ) )
    os.exit( 1 )
end

print( string.format( "OK: %d checks passed", _passes ) )
