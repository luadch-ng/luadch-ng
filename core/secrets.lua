--[[

    core/secrets.lua - sensitive-key registry + env-var-first lookup.

    Two responsibilities, both pre-requisites for the unified
    blocklist arc (#78 Precursor 0c) - Phase D (etc_geoip) needs a
    MaxMind license-key lookup that survives both Docker (env var)
    and bare-metal (cfg.tbl) deployments; Phase F (etc_proxydetect)
    needs the same shape for proxycheck.io / VPNAPI.io / IPQS API
    keys. The redaction registry is also used today by
    GET /v1/config (#262) which previously hardcoded its denylist.

    1. Registry of cfg keys that are "secrets" (API tokens, license
       keys, encryption-master-key paths). Consumers consult
       `is_secret_key(cfg_key)` before displaying / logging /
       exporting a cfg value. Single source of truth - GET /v1/config
       redaction, future +showcfg, audit-body redaction all consult
       this module instead of carrying their own denylist copies.

    2. Env-var-first lookup helper (`lookup`): for API-keyed plugins
       and any cfg key that should travel via Docker env section
       instead of cfg.tbl. Checks `LUADCH_<UPPER_CFG_KEY>` env var
       first; falls back to cfg.get on miss. Empty string in either
       location counts as "unset" so an empty env var does NOT mask
       a populated cfg value.

    Lazy-binds cfg via `use "cfg"` at call time so module load order
    in init.lua is straightforward (cfg -> secrets -> rest of core).

    Baseline registry (pre-loaded by init()):
      - http_api_tokens (HTTP API auth tokens; existed pre-arc)
      - master_key_path (cfg_secret encryption key path; existed pre-arc)

    Plugins / other modules register additional keys at onStart /
    init time:

        local secrets = use "secrets"
        secrets.register( "etc_geoip_license_key" )

    Re-registration is idempotent. No unregister() - sensitive keys
    stay sensitive for the process lifetime.

]]--

local use = use

-- Core modules run under init.lua's restricted env (only `use` is
-- in scope). Everything else - stdlib functions, libraries - must
-- be pulled in via `use`. Same pattern as core/util.lua + core/audit.lua.
local type        = use "type"
local pairs       = use "pairs"
local string      = use "string"
local table       = use "table"
local os          = use "os"
local pcall       = use "pcall"

local _registry = { }

-- Subset of _registry opted into API-writability (masked write via PUT /v1/config, #178).
-- Default-deny: a secret is NOT here unless its register() call passed api_writable=true,
-- so the hub's own auth/crypto secrets (http_api_tokens, master_key_path) and any future
-- or un-opted plugin secret stay write-protected without having to be named.
local _api_writable = { }

-- Structurally NEVER API-writable, regardless of any api_writable opt-in: the hub's own
-- auth-token store and the at-rest crypto master-key path. Belt-and-suspenders over
-- default-deny - even a future internal bug that passed api_writable=true for one of these
-- is ignored at BOTH register() and is_api_writable(), so the guarantee is structural, not
-- merely "nothing happens to opt them in".
local _never_api_writable = {
    http_api_tokens = true,
    master_key_path = true,
}

local _env_prefix = "LUADCH_"

local _derive_env_name = function( cfg_key )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return nil end
    -- cfg keys in this repo are [a-z0-9_]+ (per cfg_defaults.lua
    -- convention); a plain upper() suffices and the POSIX / Windows
    -- env-var name charset accepts all of [A-Z0-9_]. Fail-loud on
    -- any future cfg key that contains chars outside that set
    -- rather than silently producing an unreliable env-var name
    -- (e.g. `LUADCH_FOO-BAR` reads differ across shells).
    if cfg_key:find( "[^%a%d_]" ) then return nil end
    return _env_prefix .. string.upper( cfg_key )
end

-- register( cfg_key [, opts ] ) - mark cfg_key as a secret (redacted on GET, rejected on
-- PUT). opts.api_writable = true additionally opts the key into a masked write via
-- PUT /v1/config (#178) - use it only for third-party plugin credentials (license / API
-- keys, outbound tokens), never the hub's own auth/crypto material. Idempotent; a later
-- plain register() never DOWNGRADES a key already opted writable.
local register = function( cfg_key, opts )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return false end
    _registry[ cfg_key ] = true
    if type( opts ) == "table" and opts.api_writable == true and not _never_api_writable[ cfg_key ] then
        _api_writable[ cfg_key ] = true
    end
    return true
end

local is_secret_key = function( cfg_key )
    return _registry[ cfg_key ] == true
end

-- True only for a secret explicitly opted into API-writability (default-deny) that is not
-- on the structural never-writable list.
local is_api_writable = function( cfg_key )
    return _api_writable[ cfg_key ] == true and not _never_api_writable[ cfg_key ]
end

local lookup = function( cfg_key )
    if type( cfg_key ) ~= "string" or cfg_key == "" then return nil end

    -- 1. Env var first (Docker-friendly).
    local env_name = _derive_env_name( cfg_key )
    if env_name then
        local v = os.getenv( env_name )
        if type( v ) == "string" and v ~= "" then
            return v
        end
    end

    -- 2. cfg.tbl fallback (bare-metal friendly; chmod 600 by Phase
    -- 7c hardening).
    --
    -- cfg.get RAISES on a key that is in neither cfg_defaults nor
    -- cfg.tbl (it indexes the nil default entry, cfg.lua get()). That
    -- path is reachable for dynamically-named secret keys - e.g. the
    -- etc_webhook plugin resolves a per-endpoint
    -- `etc_webhook_<name>_secret` that need not be a cfg_defaults key.
    -- pcall-guard so an unknown key degrades to "unset" (nil) instead
    -- of taking down the caller's onStart; a genuine cfg.tbl value
    -- still returns normally.
    local cfg_mod = use "cfg"
    if cfg_mod and type( cfg_mod.get ) == "function" then
        local ok, v = pcall( cfg_mod.get, cfg_key )
        if ok and type( v ) == "string" and v ~= "" then
            return v
        end
    end

    return nil
end

local list_secret_keys = function( )
    local out = { }
    for k in pairs( _registry ) do
        out[ #out + 1 ] = k
    end
    table.sort( out )
    return out
end

-- The api-writable secret keys, sorted. GET /v1/config returns this so the WebUI can
-- offer a masked editor for exactly those redacted keys and keep the rest read-only (#178).
local list_api_writable = function( )
    local out = { }
    for k in pairs( _api_writable ) do
        out[ #out + 1 ] = k
    end
    table.sort( out )
    return out
end

-- True if an env var (LUADCH_<KEY>) currently holds a non-empty value for this key: then
-- lookup() takes the env value and a cfg.tbl write is shadowed until the env is cleared.
-- The PUT /v1/config handler surfaces this so a masked write does not silently no-op (#178).
local env_is_set = function( cfg_key )
    local env_name = _derive_env_name( cfg_key )
    if not env_name then return false end
    local v = os.getenv( env_name )
    return type( v ) == "string" and v ~= ""
end

local init = function( )
    -- Baseline registry - sensitive keys that existed before this
    -- module landed. Migrated from the hardcoded denylist at
    -- core/http_router.lua _config_denylist (#262 / #272).
    register( "http_api_tokens" )
    register( "master_key_path" )
end

return {
    register          = register,
    is_secret_key     = is_secret_key,
    is_api_writable   = is_api_writable,
    lookup            = lookup,
    list_secret_keys  = list_secret_keys,
    list_api_writable = list_api_writable,
    env_is_set        = env_is_set,
    _derive_env_name  = _derive_env_name,    -- exposed for tests
    init              = init,
}
