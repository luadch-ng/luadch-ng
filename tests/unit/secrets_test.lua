--[[

    tests/unit/secrets_test.lua

    Unit tests for core/secrets.lua (#78 Precursor 0c). Covers:
      - registry: register / is_secret_key / list_secret_keys
      - baseline registrations after init()
      - _derive_env_name shape (prefix + uppercase)
      - lookup: env-var precedence over cfg.get
      - lookup: cfg.get fallback when env var unset / empty
      - lookup: empty cfg returns nil (not the empty string)
      - lookup: nil / non-string input -> nil
      - re-registration is idempotent
      - register rejects non-string / empty input

    Run:  C:\lua-5.4.8_Win64_bin\lua54.exe tests/unit/secrets_test.lua
    Exit 0 = all pass, 1 = a failure.

]]--

----------------------------------------------------------------------
-- `use` shim. secrets.lua follows the core-module pattern: every
-- stdlib / library it touches comes via use("X") under init.lua's
-- restricted env. The shim hands back the real stdlib values for
-- type / pairs / tostring / string / table / os; cfg is mocked.
----------------------------------------------------------------------

local _cfg_store = { }

local _real = {
    type     = type,
    pairs    = pairs,
    tostring = tostring,
    string   = string,
    table    = table,
    os       = os,
    pcall    = pcall,
    cfg      = {
        get = function( key )
            return _cfg_store[ key ]
        end,
    },
}

_G.use = function( name )
    local m = _real[ name ]
    if m == nil then
        error( "secrets_test shim missing dep: use \"" .. tostring( name ) .. "\"" )
    end
    return m
end

local secrets = assert( loadfile( "core/secrets.lua" ) )( )

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

local function assert_false( what, got )
    assert_eq( what, not got, true )
end

----------------------------------------------------------------------
-- _derive_env_name
----------------------------------------------------------------------

assert_eq( "_derive_env_name: simple cfg key",
    secrets._derive_env_name( "etc_geoip_license_key" ),
    "LUADCH_ETC_GEOIP_LICENSE_KEY" )

assert_eq( "_derive_env_name: short key",
    secrets._derive_env_name( "api_token" ),
    "LUADCH_API_TOKEN" )

assert_eq( "_derive_env_name: nil input -> nil",
    secrets._derive_env_name( nil ), nil )

assert_eq( "_derive_env_name: empty string -> nil",
    secrets._derive_env_name( "" ), nil )

assert_eq( "_derive_env_name: non-string -> nil",
    secrets._derive_env_name( 42 ), nil )

-- Fail-loud guard: any cfg key with chars outside [A-Za-z0-9_] gets
-- nil rather than an unreliable env-var name. POSIX shells accept
-- only [A-Z0-9_] in env-var names; producing `LUADCH_FOO-BAR`
-- silently would create shell-dependent lookup behaviour.
assert_eq( "_derive_env_name: dash rejected",
    secrets._derive_env_name( "foo-bar" ), nil )

assert_eq( "_derive_env_name: dot rejected",
    secrets._derive_env_name( "foo.bar" ), nil )

assert_eq( "_derive_env_name: space rejected",
    secrets._derive_env_name( "foo bar" ), nil )

assert_eq( "_derive_env_name: slash rejected",
    secrets._derive_env_name( "foo/bar" ), nil )

----------------------------------------------------------------------
-- register / is_secret_key / list_secret_keys (fresh registry)
----------------------------------------------------------------------

assert_false( "is_secret_key: unknown key pre-init",
    secrets.is_secret_key( "etc_geoip_license_key" ) )

assert_true( "register: returns true on success",
    secrets.register( "etc_geoip_license_key" ) )

assert_true( "is_secret_key: registered key -> true",
    secrets.is_secret_key( "etc_geoip_license_key" ) )

assert_false( "is_secret_key: still-unknown key -> false",
    secrets.is_secret_key( "etc_proxydetect_api_key" ) )

assert_true( "register: re-registration is idempotent",
    secrets.register( "etc_geoip_license_key" ) )

assert_false( "register: nil input rejected",
    secrets.register( nil ) )

assert_false( "register: empty string rejected",
    secrets.register( "" ) )

assert_false( "register: non-string rejected",
    secrets.register( 42 ) )

local list = secrets.list_secret_keys( )
assert_eq( "list_secret_keys: count = 1 after one register",
    #list, 1 )
assert_eq( "list_secret_keys: contains registered key",
    list[ 1 ], "etc_geoip_license_key" )

----------------------------------------------------------------------
-- is_api_writable / list_api_writable (#178 default-deny opt-in)
----------------------------------------------------------------------

-- A secret registered WITHOUT the flag is not API-writable (default-deny).
assert_false( "is_api_writable: plain-registered secret is NOT writable",
    secrets.is_api_writable( "etc_geoip_license_key" ) )

-- Opt a key in explicitly.
assert_true( "register: opt-in with api_writable returns true",
    secrets.register( "test_writable_key", { api_writable = true } ) )
assert_true( "is_secret_key: opted-in key is a secret",
    secrets.is_secret_key( "test_writable_key" ) )
assert_true( "is_api_writable: opted-in key -> true",
    secrets.is_api_writable( "test_writable_key" ) )

-- A plain re-register must NOT downgrade an already-writable key.
assert_true( "register: plain re-register returns true",
    secrets.register( "test_writable_key" ) )
assert_true( "is_api_writable: still writable after plain re-register (no downgrade)",
    secrets.is_api_writable( "test_writable_key" ) )

-- Empty / flagless opts does not opt in; unknown key is not writable.
assert_true( "register: with empty opts table",
    secrets.register( "test_plain_key", { } ) )
assert_false( "is_api_writable: empty-opts key is not writable",
    secrets.is_api_writable( "test_plain_key" ) )
assert_false( "is_api_writable: never-registered key -> false",
    secrets.is_api_writable( "never_registered" ) )

local wlist = secrets.list_api_writable( )
assert_eq( "list_api_writable: exactly the one opted-in key",
    #wlist, 1 )
assert_eq( "list_api_writable: contains the opted-in key",
    wlist[ 1 ], "test_writable_key" )

----------------------------------------------------------------------
-- init() seeds the baseline registry
----------------------------------------------------------------------

secrets.init( )

assert_true( "init: http_api_tokens registered",
    secrets.is_secret_key( "http_api_tokens" ) )

assert_true( "init: master_key_path registered",
    secrets.is_secret_key( "master_key_path" ) )

-- The baseline auth/crypto secrets must NOT be API-writable (default-deny; they never
-- opt in) - this is the core of #178's write-protection.
assert_false( "init: http_api_tokens is a secret but NOT api-writable",
    secrets.is_api_writable( "http_api_tokens" ) )
assert_false( "init: master_key_path is a secret but NOT api-writable",
    secrets.is_api_writable( "master_key_path" ) )

-- Structural guard: an explicit api_writable opt-in on a core auth/crypto secret is
-- ignored at both register() and is_api_writable() - the guarantee does not rely on
-- "nobody opts them in" (defense-in-depth against a future internal mistake).
secrets.register( "http_api_tokens", { api_writable = true } )
assert_false( "structural: http_api_tokens stays protected despite an api_writable opt-in",
    secrets.is_api_writable( "http_api_tokens" ) )
secrets.register( "master_key_path", { api_writable = true } )
assert_false( "structural: master_key_path stays protected despite an api_writable opt-in",
    secrets.is_api_writable( "master_key_path" ) )
-- And such a key never leaks into the writable list.
for _, k in ipairs( secrets.list_api_writable( ) ) do
    assert_true( "structural: list_api_writable excludes core secrets (" .. k .. ")",
        k ~= "http_api_tokens" and k ~= "master_key_path" )
end

local list_after = secrets.list_secret_keys( )
assert_true( "list_secret_keys: returns sorted array",
    list_after[ 1 ] <= list_after[ #list_after ] )

----------------------------------------------------------------------
-- lookup: env-var precedence (mock os.getenv via _G replacement)
----------------------------------------------------------------------

-- Stash + replace os.getenv with a controllable mock. The module
-- captured `os` at load time via `local os = os`, so we mutate the
-- shared `os` table's `getenv` field instead of rebinding the local.
local _real_getenv = os.getenv
local _env = { }
os.getenv = function( name ) return _env[ name ] end

-- Case 1: env var set + cfg unset -> env wins
_env[ "LUADCH_TESTKEY_ALPHA" ] = "from-env"
_cfg_store[ "testkey_alpha" ] = nil
assert_eq( "lookup: env-var precedence over unset cfg",
    secrets.lookup( "testkey_alpha" ),
    "from-env" )

-- Case 2: env var set + cfg also set -> env still wins
_env[ "LUADCH_TESTKEY_BETA" ] = "from-env"
_cfg_store[ "testkey_beta" ] = "from-cfg"
assert_eq( "lookup: env wins over populated cfg",
    secrets.lookup( "testkey_beta" ),
    "from-env" )

-- Case 3: env unset + cfg set -> cfg fallback
_env[ "LUADCH_TESTKEY_GAMMA" ] = nil
_cfg_store[ "testkey_gamma" ] = "from-cfg"
assert_eq( "lookup: cfg fallback when env unset",
    secrets.lookup( "testkey_gamma" ),
    "from-cfg" )

-- Case 4: env set to empty + cfg set -> cfg wins (empty env != set)
_env[ "LUADCH_TESTKEY_DELTA" ] = ""
_cfg_store[ "testkey_delta" ] = "from-cfg"
assert_eq( "lookup: empty env does NOT mask populated cfg",
    secrets.lookup( "testkey_delta" ),
    "from-cfg" )

-- Case 5: both unset -> nil
_env[ "LUADCH_TESTKEY_EPSILON" ] = nil
_cfg_store[ "testkey_epsilon" ] = nil
assert_eq( "lookup: both unset -> nil",
    secrets.lookup( "testkey_epsilon" ),
    nil )

-- Case 6: cfg has empty string -> nil (treated as unset)
_env[ "LUADCH_TESTKEY_ZETA" ] = nil
_cfg_store[ "testkey_zeta" ] = ""
assert_eq( "lookup: cfg empty string treated as unset",
    secrets.lookup( "testkey_zeta" ),
    nil )

-- Case 7: cfg has non-string value (e.g. table) -> nil
_env[ "LUADCH_TESTKEY_ETA" ] = nil
_cfg_store[ "testkey_eta" ] = { "not", "a", "string" }
assert_eq( "lookup: cfg non-string treated as unset",
    secrets.lookup( "testkey_eta" ),
    nil )

-- Case 8: lookup() with bad input
assert_eq( "lookup: nil input -> nil",
    secrets.lookup( nil ), nil )

assert_eq( "lookup: empty string input -> nil",
    secrets.lookup( "" ), nil )

assert_eq( "lookup: non-string input -> nil",
    secrets.lookup( 42 ), nil )

-- Case 9 (regression): a cfg key that is unknown to BOTH cfg_defaults
-- and cfg.tbl makes the REAL cfg.get raise - it indexes the nil
-- default entry (`_defaultsettings[target][1]`, cfg.lua get()). The
-- earlier cases use a mock get() that quietly returns nil for unknown
-- keys, so they do NOT exercise that path; model the raise explicitly
-- here. lookup() must swallow it and return nil, because dynamically
-- named secret keys - e.g. the etc_webhook plugin's per-endpoint
-- `etc_webhook_<name>_secret` - are not cfg_defaults keys and must not
-- crash the caller's onStart on a miss. Provably fails pre-fix: without
-- the pcall guard, secrets.lookup propagates the raise and the pcall
-- below returns ok=false.
local _plain_get = _real.cfg.get
_real.cfg.get = function( key )
    if key == "etc_webhook_unknown_secret" then
        error( "cfg.lua: function 'get': unknown target (simulated)" )
    end
    return _plain_get( key )
end
_env[ "LUADCH_ETC_WEBHOOK_UNKNOWN_SECRET" ] = nil
local _ok, _res = pcall( secrets.lookup, "etc_webhook_unknown_secret" )
assert_true( "lookup: unknown cfg key does not propagate cfg.get crash", _ok )
assert_eq( "lookup: unknown cfg key returns nil", _res, nil )
_real.cfg.get = _plain_get

----------------------------------------------------------------------
-- env_is_set (#178: warn when an env var would shadow a cfg write)
----------------------------------------------------------------------

_env[ "LUADCH_SHADOWED_KEY" ] = "from-env"
assert_true( "env_is_set: non-empty env var present -> true",
    secrets.env_is_set( "shadowed_key" ) )

_env[ "LUADCH_UNSHADOWED_KEY" ] = nil
assert_false( "env_is_set: env var absent -> false",
    secrets.env_is_set( "unshadowed_key" ) )

_env[ "LUADCH_EMPTY_KEY" ] = ""
assert_false( "env_is_set: empty env var does NOT shadow -> false",
    secrets.env_is_set( "empty_key" ) )

assert_false( "env_is_set: non-derivable key name -> false",
    secrets.env_is_set( "foo-bar" ) )

-- Restore os.getenv
os.getenv = _real_getenv

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
