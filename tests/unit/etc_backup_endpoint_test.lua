--[[

    tests/unit/etc_backup_endpoint_test.lua

    Regression test for scripts/etc_backup.lua HTTP API (v0.02, #701):
      GET  /v1/backups  - status + artifact list
      POST /v1/backups  - run a backup now (409 not-ready / 500 fail / 200 ok)

    Provably fails pre-fix (per CLAUDE.md 1a.7): on v0.01 the plugin registers
    no HTTP routes, so the two "registered" asserts go RED; they pass on v0.02.

    The backup ENGINE (core/backup, sandbox global `backup`) is stubbed so the
    handler logic is tested in isolation - readiness / run success / run failure
    / list rows are all controllable. Plugins get NO `use`; every dependency is
    a sandbox-global stub. Run: lua5.4 tests/unit/etc_backup_endpoint_test.lua

]]--

local checks, failures = 0, 0
local function ok( label, cond, extra )
    checks = checks + 1
    if not cond then failures = failures + 1
        io.write( "FAIL " .. label .. ( extra and ( " - " .. tostring( extra ) ) or "" ) .. "\n" )
    else io.write( "ok   " .. label .. "\n" ) end
end

----------------------------------------------------------------------
-- mutable state the stubs close over
----------------------------------------------------------------------
local _listeners, _http, _saved, _audit
local _cfg, _ready, _runRes, _runErr, _list, _runCalled

_G.type = type; _G.pairs = pairs; _G.ipairs = ipairs
_G.tonumber = tonumber; _G.tostring = tostring
_G.table = table; _G.string = string
_G.setmetatable = setmetatable; _G.getmetatable = getmetatable
_G.PROCESSED = "PROCESSED"
_G.os = os   -- real clock; onStart's schedule math reads os.time / os.date

-- load_state() peeks with io.open before util.loadtable; return "no file" so a
-- fresh test hub takes the no-persisted-state path. Real io underneath for write.
local _real_io = io
_G.io = setmetatable( { open = function( ) return nil end }, { __index = _real_io } )

_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { }, nil end,
}
_G.util = {
    loadtable = function( ) return nil end,
    savetable = function( t ) _saved = t end,
}
_G.util_http = {
    operator_label = function( req )
        if req and type( req.actor ) == "string" and req.actor ~= "" then return req.actor end
        return ( req and req.token_label ) or "http-api"
    end,
}
_G.secrets = { register = function( ) end }
_G.audit = {
    build = function( action, actor, target, reason, meta ) return { action = action, meta = meta or { } } end,
    fire  = function( ev ) _audit[ #_audit + 1 ] = ev end,
}
-- The engine: readiness / run / list all read the controllable test state.
_G.backup = {
    readiness = function( ) return _ready end,
    run       = function( ) _runCalled = true; return _runRes, _runErr end,
    list      = function( ) return _list end,
}
_G.hub = {
    debug         = function( ) end,
    getbot        = function( ) return { } end,
    getusers      = function( ) return { } end,
    setlistener   = function( ev, _o, fn ) _listeners[ ev ] = fn end,
    import        = function( ) return nil end,
    http_register = function( method, path, _scope, handler ) _http[ method .. " " .. path ] = handler end,
}

----------------------------------------------------------------------
-- helpers
----------------------------------------------------------------------
local function load_plugin( cfg_overrides )
    _listeners = { }; _http = { }; _saved = nil; _audit = { }
    _cfg = { language = "en", etc_backup_enabled = true, etc_backup_dir = "cfg/backups" }
    if cfg_overrides then for k, v in pairs( cfg_overrides ) do _cfg[ k ] = v end end
    _ready = { ok = true, issues = { } }
    _runRes = nil; _runErr = nil; _list = { }; _runCalled = false
    assert( loadfile( "scripts/etc_backup.lua" ) )( )
    if _listeners.onStart then _listeners.onStart( ) end
    return _http[ "GET /v1/backups" ], _http[ "POST /v1/backups" ]
end

----------------------------------------------------------------------
-- Case 1: registration + GET status (ready, daily schedule, 2 artifacts)
----------------------------------------------------------------------
local GET, POST = load_plugin( { etc_backup_daily_at = "04:00" } )
ok( "GET /v1/backups registered (v0.02)",  GET ~= nil )
ok( "POST /v1/backups registered (v0.02)", POST ~= nil )
if GET then
    _list = { { name = "luadch-backup-2026-09-22.ldbk1", bytes = 100 },
              { name = "luadch-backup-2026-09-21.ldbk1", bytes = 90 } }
    local r = GET( { } )
    ok( "GET status 200", r.status == 200 )
    ok( "GET enabled true", r.data.enabled == true )
    ok( "GET ready true", r.data.ready == true )
    ok( "GET dir", r.data.dir == "cfg/backups", r.data.dir )
    ok( "GET daily_at", r.data.daily_at == "04:00", r.data.daily_at )
    ok( "GET no interval_hours in daily mode", r.data.interval_hours == nil )
    ok( "GET next_backup_at is set (daily)", type( r.data.next_backup_at ) == "number" )
    ok( "GET backups count 2", #r.data.backups == 2, #r.data.backups )
    ok( "GET backups[1] name (newest first from engine)", r.data.backups[ 1 ].name == "luadch-backup-2026-09-22.ldbk1" )
    ok( "GET backups[1] bytes", r.data.backups[ 1 ].bytes == 100 )
end

----------------------------------------------------------------------
-- Case 2: empty list -> backups is a JSON array ([] not {})
----------------------------------------------------------------------
do
    local G = load_plugin( )
    _list = { }
    local r = G( { } )
    ok( "GET empty: backups length 0", #r.data.backups == 0 )
    ok( "GET empty: backups tagged json-array ([])", ( getmetatable( r.data.backups ) or { } ).__jsontype == "array" )
end

----------------------------------------------------------------------
-- Case 3: not ready -> ready=false + issues present
----------------------------------------------------------------------
do
    local G = load_plugin( )
    _ready = { ok = false, issues = { "no_passphrase", "backup_dir_unwritable" } }
    local r = G( { } )
    ok( "GET not-ready: ready false", r.data.ready == false )
    ok( "GET not-ready: issues present", r.data.issues ~= nil and #r.data.issues == 2 )
    ok( "GET not-ready: issues[1]", r.data.issues and r.data.issues[ 1 ] == "no_passphrase" )
    ok( "GET not-ready: issues tagged json-array", ( getmetatable( r.data.issues ) or { } ).__jsontype == "array" )
end

----------------------------------------------------------------------
-- Case 4: interval mode (no daily) -> interval_hours, no daily_at
----------------------------------------------------------------------
do
    local G = load_plugin( { etc_backup_interval_hours = 6 } )
    local r = G( { } )
    ok( "GET interval mode: interval_hours 6", r.data.interval_hours == 6, r.data.interval_hours )
    ok( "GET interval mode: no daily_at", r.data.daily_at == nil )
end

----------------------------------------------------------------------
-- Case 5: POST success -> 200 + result + audit backup.success + persist
----------------------------------------------------------------------
do
    local _, P = load_plugin( )
    _ready  = { ok = true, issues = { } }
    _runRes = { path = "cfg/backups/luadch-backup-X.ldbk1", bytes = 2048, files = 12, skipped = 1 }
    local r = P( { token_label = "tok", actor = "adminop" } )
    ok( "POST success: status 200", r.status == 200 )
    ok( "POST success: engine run() called", _runCalled == true )
    ok( "POST success: path", r.data.path == "cfg/backups/luadch-backup-X.ldbk1" )
    ok( "POST success: bytes", r.data.bytes == 2048 )
    ok( "POST success: files", r.data.files == 12 )
    ok( "POST success: skipped", r.data.skipped == 1 )
    ok( "POST success: next_backup_at absent (no schedule configured)", r.data.next_backup_at == nil )
    ok( "POST success: audit backup.success", _audit[ #_audit ] and _audit[ #_audit ].action == "backup.success" )
    ok( "POST success: persisted state", _saved ~= nil )
end

----------------------------------------------------------------------
-- Case 6: POST not-ready -> 409, engine run() NOT called
----------------------------------------------------------------------
do
    local _, P = load_plugin( )
    _ready = { ok = false, issues = { "no_passphrase" } }
    local r = P( { token_label = "tok" } )
    ok( "POST not-ready: status 409", r.status == 409 )
    ok( "POST not-ready: code", r.error and r.error.code == "E_BACKUP_NOT_READY" )
    ok( "POST not-ready: message lists issues", r.error and r.error.message:find( "no_passphrase", 1, true ) ~= nil )
    ok( "POST not-ready: engine run() NOT called", _runCalled == false )
    ok( "POST not-ready: nothing persisted", _saved == nil )
end

----------------------------------------------------------------------
-- Case 7: POST run failure (ready but run returns nil,err) -> 500
----------------------------------------------------------------------
do
    local _, P = load_plugin( )
    _ready  = { ok = true, issues = { } }
    _runRes = nil; _runErr = "backup: nothing to back up (no state files found)"
    local r = P( { token_label = "tok" } )
    ok( "POST run-fail: status 500", r.status == 500 )
    ok( "POST run-fail: code", r.error and r.error.code == "E_BACKUP_FAILED" )
    ok( "POST run-fail: message carries engine err", r.error and r.error.message:find( "nothing to back up", 1, true ) ~= nil )
    ok( "POST run-fail: audit backup.fail", _audit[ #_audit ] and _audit[ #_audit ].action == "backup.fail" )
end

----------------------------------------------------------------------
-- Case 8: feature disabled -> POST 409 (not a misleading 500), run() not called
----------------------------------------------------------------------
do
    local _, P = load_plugin( { etc_backup_enabled = false } )
    _ready = { ok = true, issues = { } }   -- otherwise ready, but disabled
    local r = P( { token_label = "tok" } )
    ok( "POST disabled: status 409", r.status == 409 )
    ok( "POST disabled: code E_BACKUP_NOT_READY", r.error and r.error.code == "E_BACKUP_NOT_READY" )
    ok( "POST disabled: message mentions disabled", r.error and r.error.message:find( "disabled", 1, true ) ~= nil )
    ok( "POST disabled: engine run() NOT called", _runCalled == false )
end

----------------------------------------------------------------------
-- Case 9: an artifact whose size could not be stat'd -> bytes key absent
----------------------------------------------------------------------
do
    local G = load_plugin( )
    _list = { { name = "luadch-backup-x.ldbk1" } }   -- no bytes (stat failed)
    local r = G( { } )
    ok( "GET nil-bytes: name present", r.data.backups[ 1 ].name == "luadch-backup-x.ldbk1" )
    ok( "GET nil-bytes: bytes key absent", r.data.backups[ 1 ].bytes == nil )
end

----------------------------------------------------------------------
-- Case 10: POST success WITH a schedule -> next_backup_at present
----------------------------------------------------------------------
do
    local _, P = load_plugin( { etc_backup_daily_at = "04:00" } )
    _ready  = { ok = true, issues = { } }
    _runRes = { path = "cfg/backups/y.ldbk1", bytes = 10, files = 2, skipped = 0 }
    local r = P( { token_label = "tok" } )
    ok( "POST scheduled: status 200", r.status == 200 )
    ok( "POST scheduled: next_backup_at present", type( r.data.next_backup_at ) == "number" )
end

----------------------------------------------------------------------
io.write( string.format( "\n%d/%d checks passed\n", checks - failures, checks ) )
if failures > 0 then io.write( "FAIL etc_backup_endpoint_test\n" ); os.exit( 1 ) end
io.write( "OK etc_backup_endpoint_test\n" )
