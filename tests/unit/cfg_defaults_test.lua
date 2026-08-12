--[[

    tests/unit/cfg_defaults_test.lua

    Regression test for the missing-cfg_defaults-registration crash.

    A bundled plugin that reads a cfg key at module scope
    (`local x = cfg.get("some_key")`) crashes at plugin load if that
    key is registered in NEITHER the operator's cfg.tbl NOR
    core/cfg_defaults.lua: core/cfg.lua's get() does

        get = function( target )
            if _settings[ target ] == nil then
                return _defaultsettings[ target ][ 1 ]   -- nil[1] -> error
            end
            return _settings[ target ]
        end

    so an unregistered key with no cfg.tbl override indexes
    `_defaultsettings[target]` (nil) at `[1]` and throws. This hit
    etc_prometheus.lua, whose `etc_prometheus_activate` toggle shipped
    only in examples/cfg/cfg.tbl and was missing from cfg_defaults.lua:
    a fresh install (example cfg carries the key) and CI smoke both
    passed, but an operator who whitelisted the plugin on an older
    cfg.tbl crashed on load.

    This test loads the REAL cfg_defaults.lua settings table and
    reproduces cfg.get()'s exact lookup for a key the operator did NOT
    set, proving the default resolves instead of crashing. It fails on
    the unpatched cfg_defaults (key absent) and passes patched.

    Run:  C:\lua-5.4.8_Win64_bin\lua54.exe tests/unit/cfg_defaults_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim. cfg_defaults.lua is a core module: every dep comes via
-- use("X") under init.lua's restricted env. Loading it standalone only
-- runs the top-level `local X = use "Y"` bindings and builds the data
-- table of { default, validator } pairs - no validator is INVOKED at
-- load, so type/const/types stubs suffice.
----------------------------------------------------------------------

local _real = {
    type   = type,
    pairs  = pairs,
    ipairs = ipairs,
    -- const.CONFIG_PATH is read into an upvalue at load; any string is fine.
    const  = { CONFIG_PATH = "cfg/" },
    -- types.utf8 + types.get "<name>" are captured into upvalues at load.
    -- The identity stub (always true) is exercised by the http_api_tokens
    -- validator test below (it calls types_table(value)); returning true
    -- lets that test drive the per-entry filter path.
    types  = {
        utf8 = function() return true end,
        get  = function() return function() return true end end,
    },
    -- http_api_tokens validator resolves `use "out"` lazily to log dropped
    -- entries; a no-op error sink keeps that path silent under test.
    out    = { error = function() end },
}

_G.use = function( name )
    local m = _real[ name ]
    if m == nil then
        error( "cfg_defaults_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return m
end

local mod = assert( loadfile( "core/cfg_defaults.lua" ) )( )
local settings = mod.settings

----------------------------------------------------------------------
-- Tiny test harness.
----------------------------------------------------------------------

local _passes, _fails = 0, 0

local function assert_eq( what, got, expected )
    if got == expected then
        _passes = _passes + 1
    else
        _fails = _fails + 1
        io.stderr:write( string.format(
            "FAIL: %s\n  got: %s\n  expected: %s\n",
            what, tostring( got ), tostring( expected )
        ) )
    end
end

local function assert_true( what, got )
    assert_eq( what, not not got, true )
end

----------------------------------------------------------------------
-- Faithful reproduction of core/cfg.lua get() for a key the operator
-- did NOT set in cfg.tbl (so _settings[key] == nil and the default
-- path is taken). This is the exact code that crashed.
----------------------------------------------------------------------

local function make_cfg_get( defaultsettings, operator_settings )
    return function( target )
        if operator_settings[ target ] == nil then
            return defaultsettings[ target ][ 1 ]
        end
        return operator_settings[ target ]
    end
end

-- Operator cfg.tbl WITHOUT etc_prometheus_activate (the crash scenario).
local cfg_get = make_cfg_get( settings, { } )

----------------------------------------------------------------------
-- The regression: etc_prometheus_activate must be registered so
-- cfg.get resolves the default instead of throwing on nil[1].
----------------------------------------------------------------------

assert_true( "etc_prometheus_activate is registered in cfg_defaults",
    settings.etc_prometheus_activate ~= nil )

local ok, val = pcall( cfg_get, "etc_prometheus_activate" )
assert_true( "cfg.get(etc_prometheus_activate) does not crash on an omitting cfg.tbl", ok )
assert_eq( "etc_prometheus_activate default resolves to false", val, false )

-- Guard the sibling _activate toggles the observability plugins read at
-- module scope, so the same class of bug cannot silently regress into a
-- neighbour. Each must resolve to a boolean default, not crash.
for _, key in ipairs( {
    "etc_status_push_activate",
    "etc_regserver_announce_activate",
    "etc_webhook_activate",
} ) do
    local sok, sval = pcall( cfg_get, key )
    assert_true( key .. ": registered + resolves without crash", sok )
    assert_true( key .. ": default is a boolean", type( sval ) == "boolean" )
end

----------------------------------------------------------------------
-- http_api_tokens validator: per-entry (NOT whole-table) validation.
-- A single malformed entry must not invalidate the whole map - that
-- path returned false, the cfg loader reset the key to {}, and the HTTP
-- listener then refused to bind: one scope typo locked the operator out.
-- The validator now drops only the bad entries, keeps the valid tokens,
-- and returns true.
-- RED pre-fix: a mixed good/bad map returned false (whole-table reject)
-- and left the map unmutated.
----------------------------------------------------------------------

do
    local validator = settings.http_api_tokens[ 2 ]

    -- mixed: one valid admin token + one bad-scope typo.
    local mixed = {
        [ "goodtoken-long-enough-000001" ] = { scope = "admin", comment = "ops" },
        [ "typoscope-long-enough-000002" ] = { scope = "administrator" },   -- bad
    }
    assert_eq( "http_api_tokens: mixed map validates true (per-entry)",
        validator( mixed ), true )
    assert_true( "http_api_tokens: valid token survives",
        mixed[ "goodtoken-long-enough-000001" ] ~= nil )
    assert_eq( "http_api_tokens: valid token scope intact",
        mixed[ "goodtoken-long-enough-000001" ]
            and mixed[ "goodtoken-long-enough-000001" ].scope, "admin" )
    assert_true( "http_api_tokens: bad-scope entry dropped",
        mixed[ "typoscope-long-enough-000002" ] == nil )

    -- all-valid: unchanged, true.
    local allgood = {
        [ "aaaa-long-enough-token-0001" ] = { scope = "read" },
        [ "bbbb-long-enough-token-0002" ] = { scope = "admin", comment = "x" },
    }
    assert_eq( "http_api_tokens: all-valid validates true",
        validator( allgood ), true )
    assert_true( "http_api_tokens: all-valid keeps both",
        allgood[ "aaaa-long-enough-token-0001" ] ~= nil
        and allgood[ "bbbb-long-enough-token-0002" ] ~= nil )

    -- all-bad: everything dropped, still true (empty map -> listener
    -- simply won't bind, same as no tokens; NOT a hard reject).
    local allbad = { [ "onlytoken-long-enough-0003" ] = { scope = "nope" } }
    assert_eq( "http_api_tokens: all-bad validates true",
        validator( allbad ), true )
    assert_true( "http_api_tokens: all-bad map emptied", next( allbad ) == nil )
end

----------------------------------------------------------------------
-- Result
----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format(
        "\nFAIL: %d/%d checks failed\n",
        _fails, _passes + _fails
    ) )
    os.exit( 1 )
end

print( string.format( "OK: %d checks passed", _passes ) )
