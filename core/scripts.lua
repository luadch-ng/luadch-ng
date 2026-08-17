--[[

        scripts.lua by blastbeat

        - this script manages custom user scripts

]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local type = use "type"
local error = use "error"
local pairs = use "pairs"
local pcall = use "pcall"
local ipairs = use "ipairs"
local loadfile = use "loadfile"
local tostring = use "tostring"
local setmetatable = use "setmetatable"

--// lua libs //--

local io = use "io"
local os = use "os"
local table = use "table"
local _G = use "_G"

--// extern libs //--

local adclib = use "adclib"
local unicode = use "unicode"

--// extern lib methods //--

local utf = unicode.utf8

local utf_sub = utf.sub

--// core scripts //--

local adc = use "adc"
local cfg = use "cfg"
local out = use "out"
local mem = use "mem"
local util = use "util"

--// core methods //--

local cfg_get = cfg.get
local mem_free = mem.free
local out_error = out.error
local checkfile = util.checkfile

--// functions //--

local init
local index
local newindex

local import
local setenv
local killscripts
local firelistener
local startscripts
local listenermethod

-- #261 forward declarations
local list_plugins
local set_plugin_enabled

--// tables //--

local _code
local _loaded
local _scripts
local _listeners
local _plugin_meta    -- #261: per-plugin metadata for GET /v1/plugins

local _
local _len    -- len of listeners array

----------------------------------// DEFINITION //--

_len = 0

_loaded = { }
_scripts = { }    -- script names
_listeners = { }    -- array auf listeners tables of scripts
_plugin_meta = { }    -- #261: scriptname -> { name, filename, version, manageable, enabled, loaded, order_index, scriptid }

-- #263: core-side taps into scripts.firelistener. Each tap is a
-- function( ltype, a1, a2, a3, a4, a5 ) called BEFORE the plugin
-- listener iteration. Wrapped in pcall so a bad tap can't cascade
-- into the listener-chain's contract. Used by core/http_events.lua
-- to capture every event the hub fires (without requiring plugin
-- changes) into the GET /v1/events ringbuffer.
local _firelistener_taps = { }

_code = {    -- mhh...

    hubbypass = 2,
    hubdispatch = 1,
    scriptsbypass = 8,
    scriptsdispatch = 4,

}

-- Plugin sandbox whitelist (Tier 1 of #206). Each plugin loaded
-- via `startscripts()` gets an _ENV table seeded with ONLY the
-- globals listed below; everything else in `_G` (the hub's runtime
-- namespace) is unreachable from plugin code.
--
-- Notably EXCLUDED (the genuinely-dangerous Lua VM primitives):
--   debug      VM introspection, getlocal/setlocal of other funcs,
--              metatable poking via debug.setmetatable
--   load       compile-arbitrary-string-to-callable
--   loadfile   compile-arbitrary-file-to-callable
--   dofile    load + immediately invoke arbitrary file
--   rawget    bypass __index trap (defeats strict-mode write detect)
--   rawset    bypass __newindex trap
--   rawlen    bypass __len trap
--   rawequal  bypass __eq trap
--   _G        the underlying global env (would re-expose everything)
--   _ENV      escape to parent env
--
-- Removed across Tier-2 sub-PRs (cumulative):
--   require    Sub-PR-1: plugins now reach modules through
--              whitelisted globals (`ssl`, `basexx`); ssl submodules
--              like `ssl.x509` are pre-attached in core/init.lua so
--              `local x509 = ssl.x509` replaces `require "ssl.x509"`
--   package    Sub-PR-1: cmd_hubinfo's old `package.config:sub(1,1)`
--              is replaced by `util.path_sep()` so the whole
--              `package` library no longer leaks into the sandbox
--   os         Sub-PR-2: replaced by a curated `_os_safe` shim
--              exposing ONLY os.time / os.date / os.difftime /
--              os.clock (read-only time-accessor family). Blocks
--              os.execute / os.remove / os.rename / os.exit /
--              os.setlocale / os.tmpname / os.tmpfile / os.getenv
--              reachability from plugin code.
--   io         Sub-PR-3: replaced by a curated `_io_safe` shim
--              exposing ONLY io.open with path-restriction (no
--              absolute paths, no parent-dir traversal). Blocks
--              io.popen entirely; cmd_hubinfo's old system-info
--              io.popen calls migrated to the new
--              `core/sysinfo.lua` core module (whitelisted as
--              `sysinfo`). Closes the last major sandbox-escape
--              vector identified in #206.

-- Curated `os` shim for the plugin sandbox (#206 Tier-2 Sub-PR-2).
-- Plugin code that needs current-time / date-format / time-arithmetic
-- reaches the same Lua-stdlib functions, but the dangerous siblings
-- on the os table (execute / remove / rename / exit / tmpname /
-- tmpfile / setlocale / getenv) are not in this table - access to
-- env.os.execute returns nil + the next `.execute(...)` errors
-- with "attempt to call a nil value (method 'execute')". Adding a
-- method here requires a security review of every plugin that
-- gets exposed to it (Tier-2 Sub-PR-3 follows the same pattern
-- for `io`).
local _os_safe = {
    time     = os.time,
    date     = os.date,
    difftime = os.difftime,
    clock    = os.clock,
}

-- Curated `io` shim for the plugin sandbox (#206 Tier-2 Sub-PR-3).
-- `io.popen` is no longer in the shim - the only legitimate caller
-- (`cmd_hubinfo` for system-info detection) now reaches the curated
-- core helper `sysinfo` instead. `io.open` is path-restricted:
-- absolute paths and parent-dir traversal are rejected so a
-- compromised plugin can't read `/etc/shadow`, `C:\Windows\…`,
-- or escape its working dir via `../../`. Bundled plugins write
-- to relative paths under `log/`, `cfg/`, `certs/`, `scripts/data/`
-- - all permitted.
--
-- NOT in the shim (left absent on purpose):
--   io.popen        shell-arbitrary-command via pipe
--   io.input        replaces the process-global stdin handle
--   io.output       replaces the process-global stdout handle
--   io.read         reads from the current process-global input
--   io.write        writes to the current process-global output
--   io.stdin / stdout / stderr   plugin should not touch the
--                                 hub's tty handles
--   io.lines        relies on io.input / io.open semantics
--   io.tmpfile      tempfile handle
--   io.close        no-op without io.open's matching handle
--   io.type         introspection of file handles
--
-- The file handle returned by `_io_safe.open` IS the real Lua
-- file handle (same userdata) - its methods (`:read`, `:write`,
-- `:close`, `:lines`, `:seek`, `:setvbuf`) work normally. The
-- shim only narrows the entry point.
-- Path-safety check is owned by util.safe_path (added in #266 so the
-- check is shared between this shim AND the plugin-callable util I/O
-- functions like checkfile / atomic_write / maketable - previously
-- util captured the unsandboxed io.open at module load and bypassed
-- this gate). The shim still owns the final io.open call so the
-- returned handle remains a real Lua file userdata.
local _io_safe = {
    open = function( path, mode )
        local ok, err = util.safe_path( path )
        if not ok then
            return nil, "io_safe: " .. err
        end
        return io.open( path, mode )
    end,
}
--
-- `hub`, `utf`, `string`, and `PROCESSED` are NOT in the whitelist
-- because they are written into env explicitly later (see lines
-- ~200-205 below) - `hub` gets a curated copy of the public hub
-- API (underscore-prefixed methods filtered out), `utf` is the
-- unicode shim, `string` is REPLACED with `utf` so plugins get
-- UTF-aware string functions instead of the byte-oriented standard
-- library, and `PROCESSED` is the listener-return constant.
local SANDBOX_GLOBALS = {
    -- Lua language basics (safe by spec)
    "assert", "error", "ipairs", "next", "pairs", "pcall", "print",
    "select", "tonumber", "tostring", "type", "xpcall",
    "setmetatable", "getmetatable", "collectgarbage",
    -- Standard libraries (safe)
    "table", "math", "coroutine",
    -- `os` and `io` were here until Tier-2 Sub-PR-2 / Sub-PR-3
    -- replaced them with curated `_os_safe` / `_io_safe` shims
    -- (assigned to env.os / env.io explicitly after the
    -- SANDBOX_GLOBALS loop runs).
    -- `sysinfo` is the new core module that owns the host-OS /
    -- CPU / RAM detection - cmd_hubinfo calls into it instead of
    -- shelling out via io.popen directly.
    "sysinfo",
    -- luadch core modules (always present in _G after init.lua)
    "cfg", "util", "util_http", "http_filter", "http_events", "http_client", "adc", "adclib", "signal", "out",
    "audit",
    -- core/secrets.lua (#78 Precursor 0c): sensitive-key registry
    -- + env-var-first cfg lookup. Future API-keyed plugins
    -- (etc_geoip MaxMind license, etc_proxydetect provider keys,
    -- webhook tokens) call `secrets.lookup(cfg_key)` so Docker
    -- operators can set keys via env vars instead of cfg.tbl.
    "secrets",
    -- core/whitelist.lua (#78 allowlist): global IP/CIDR allowlist.
    -- Every IP-blocking plugin (etc_geoip / etc_proxydetect / usr_hubs
    -- / ...) calls whitelist.is_whitelisted(ip) before its own block so
    -- trusted infrastructure (hublist pingers etc.) is exempt from the
    -- automated blockers. Phase B's etc_whitelist.lua manages entries.
    "whitelist",
    -- core/blocklist.lua (#78 Phase A): unified pre-handshake
    -- IP/CIDR blocklist engine. Phase B's etc_blocklist.lua and
    -- Phase D/E/F's auto-feed plugins call blocklist.add /
    -- .remove / .list / .count to manage entries; plugins NEVER
    -- hold a direct reference to the engine's _entries array
    -- (trust contract documented in the engine header).
    "blocklist",
    -- core/mmdb.lua (#78 Phase D1): pure-Lua MaxMind DB reader.
    -- Phase D2's etc_geoip.lua calls mmdb.open(path) + reader:lookup(ip)
    -- to resolve a connecting IP to its country / ASN. Read-only; the
    -- reader degrades to (nil, err) on a missing / corrupt DB so a
    -- plugin never crashes the hub on a bad operator drop.
    "mmdb",
    -- core/geoip_update.lua (#78 Phase D3): in-hub MaxMind GeoLite2 DB
    -- auto-update. etc_geoip.lua calls geoip_update.update{...} on its
    -- update timer to fetch + refresh the .mmdb the reader reads.
    "geoip_update",
    -- core/hmac.lua: HMAC-SHA256 (RFC 2104) built on core/sha256.lua.
    -- Exposed for plugins that authenticate signed inbound webhooks
    -- (etc_webhook: Discourse / GitHub sign the request body with
    -- HMAC-SHA256). Raw sha256 deliberately stays OUT of the sandbox -
    -- plugins get the MAC primitive, not the underlying hash.
    "hmac",
    -- core/backup.lua (#480 PR-A): automatic-backup engine. The thin
    -- scheduler/CLI plugin etc_backup.lua calls backup.run / .readiness /
    -- .list. The engine reads its own policy (dir / keep / passphrase /
    -- include_master_key) from cfg + secrets, NOT from caller args, so a
    -- plugin can only trigger a backup to the operator-configured
    -- destination - it cannot redirect the artifact or pick the key.
    "backup",
    "unicode",
    -- read-only program constants (PROGRAM_NAME / VERSION / FORK /
    -- COPYRIGHT / CONFIG_PATH). Static strings, no capability; lets
    -- plugins report the hub's app name + version (e.g. the regserver
    -- announcer's AP/VE fields) without hardcoding.
    "const",
    -- Extern + optional libs (some are `false` if their require()
    -- in init.lua failed - guarded by `or false` in the iterator below)
    "ssl", "socket", "basexx", "zlib_stream", "dkjson",
}

index = function( tbl, key )
    error( "attempt to read undeclared var: '" .. tostring( key ) .. "'", 2 )
end

newindex = function( tbl, key, value )
    error( "attempt to write undeclared var: '" .. tostring( key ) .. " = " .. tostring( value ) .. "'", 2 )
end

setenv = function( tbl )
    local mtbl = { }
    mtbl.__index = index
    mtbl.__newindex = newindex
    return setmetatable( tbl, mtbl )
end

listenermethod = function( arg, scriptid )
    if arg == "set" then
        local listeners = { }
        _listeners[ scriptid ] = listeners
        _len = _len + 1
        return function( ltype, id, func )
            listeners[ ltype ] = listeners[ ltype ] or { }
            listeners[ ltype ][ id ] = func
        end
    elseif arg == "get" then
        return function( ltype )
            local listeners = _listeners[ scriptid ]
            return listeners and listeners[ ltype ]
        end
    end
    -- removeListener counterpart tracked in issue #48
end

firelistener = function( ltype, a1, a2, a3, a4, a5 )
    -- #263: invoke core-side taps before plugin listeners. The
    -- order is intentional - taps see EVERY firelistener call,
    -- including ones a plugin listener would have short-circuited
    -- via PROCESSED. The /v1/events stream should reflect what
    -- the hub OBSERVED, not what was ultimately dispatched.
    for _, tap in ipairs( _firelistener_taps ) do
        pcall( tap, ltype, a1, a2, a3, a4, a5 )
    end
    local ret, dispatch
    for k = 1, _len do
        local listeners = _listeners[ k ][ ltype ]
        if listeners then
            for i, func in pairs( listeners ) do
                local bol, sret = pcall( func, a1, a2, a3, a4, a5 )
                if bol then
                    ret = ret or sret
                elseif ltype ~= "onError" then    -- no endless loops ^^
                    out_error( "scripts.lua: script error: ", sret, " (listener: ", ltype, "; script: '", _scripts[ k ], "')" )
                end
            end

            --// ugly shit //--

            --[[if ret == 6 or ret == 10 then
                dispatch = dispatch or 0
            end
            if ret == 5 or ret == 9 then
                dispatch = dispatch or 1
            end
            if ret == 9 or ret == 10 then
                break
            end]]

            if ret == 10 then    -- PROCESSED should be enough
                return true
            end
        end
    end
    --return ( dispatch == 0 )
    return false
end

-- #261: extract `local scriptversion = "X.Y"` from the script source
-- via simple grep. Plugins follow this convention across the bundled
-- 66-plugin set; the function is a best-effort lookup, returns
-- "unknown" if the pattern doesn't match. Opt-in override via a
-- plugin's `return { _version = "0.5" }` is applied at load time
-- AFTER pcall in startscripts and takes precedence.
local function _extract_version( source )
    if type( source ) ~= "string" then return "unknown" end
    local v = source:match( "[\r\n]%s*local%s+scriptversion%s*=%s*[\"']([^\"']+)[\"']" )
              or source:match( "^%s*local%s+scriptversion%s*=%s*[\"']([^\"']+)[\"']" )
    return v or "unknown"
end

startscripts = function( hub )
    _plugin_meta = { }    -- rebuild on every startscripts (covers +reload)
    for cfg_index, entry in ipairs( cfg_get "scripts" ) do
        -- #261: entries are EITHER plain strings (operator-managed,
        -- API-protected) OR `{ "name.lua", enabled = bool }` tables
        -- (API-toggleable). The semantic split is documented in the
        -- spec and in examples/cfg/cfg.tbl; here we just normalise to
        -- (scriptname, enabled, manageable) for the existing loader.
        local scriptname, enabled, manageable
        if type( entry ) == "string" then
            scriptname, enabled, manageable = entry, true, false
        elseif type( entry ) == "table" then
            scriptname  = entry[ 1 ]
            enabled     = entry.enabled ~= false    -- nil/true -> true; only literal false disables
            manageable  = true
        end
        if not scriptname then
            out_error( "scripts.lua: invalid entry in cfg.scripts at index ", cfg_index )
        elseif not enabled then
            -- #635: read the source so a disabled plugin still reports its real
            -- version (registry / +scripts / WebUI) instead of a bare "unknown".
            -- checkfile is path-guarded + UTF-8-checked + READ-ONLY - the plugin is
            -- NOT loaded or executed (that only happens in the enabled branch below).
            -- A genuinely missing / unreadable file falls back to "unknown"
            -- (_extract_version returns "unknown" on a nil source).
            local src = checkfile( cfg_get( "script_path" ) .. scriptname )
            _plugin_meta[ scriptname ] = {
                name          = scriptname:gsub( "%.lua$", "" ),
                filename      = scriptname,
                version       = _extract_version( src ),
                manageable    = manageable,
                enabled       = false,
                loaded        = false,
                order_index   = cfg_index,
                scriptid      = nil,
            }
        else
        local path = cfg_get( "script_path" ) .. scriptname
        local ret, err = checkfile( path )
        if not ret then
            out_error( "scripts.lua: format error in script '", scriptname, "': ", err )
        else
            -- Build the script's _ENV table BEFORE loadfile, so we can pass it
            -- as the 3rd loadfile argument (Lua 5.4 idiom; setfenv is gone).
            local hubobject = { }
            for name, method in pairs( hub ) do
                if utf_sub( name, 1, 1 ) ~= "_" then    -- no "hidden" functions...
                    hubobject[ name ] = method
                end
            end
            local key = _len + 1
            hubobject.setlistener = listenermethod( "set", key )    -- this is needed to execute listeners in script order
            hubobject.getlistener = listenermethod( "get", key )
            local env =  { }

            --// useful constants //--

            --env.DISPATCH_HUB = _code.hubdispatch
            --env.DISCARD_HUB = _code.hubbypass
            --env.DISPATCH_SCRIPTS = _code.scriptsdispatch
            --env.DISCARD_SCRIPTS = _code.scriptsbypass

            env.PROCESSED = _code.scriptsbypass + _code.hubbypass    -- should be enough

            -- Sandbox whitelist (Tier 1 of #206). Replaces the
            -- previous verbatim `for k,v in pairs(_G) do env[k]=v end`
            -- which exposed `debug`, `loadfile`, `dofile`, `load`,
            -- `rawget/rawset` etc. to every plugin. The new
            -- behaviour: ONLY names in `SANDBOX_GLOBALS` are
            -- imported from _G; everything else is unreachable
            -- (`env.debug` is nil, indexing it raises
            -- "attempt to index nil value" or - with the optional
            -- `setenv` trap below - the explicit "undeclared var"
            -- error). Curated `hub` / `utf` / `string` overrides
            -- happen after this loop.
            for _, name in ipairs( SANDBOX_GLOBALS ) do
                env[ name ] = _G[ name ]
            end
            -- Curated `os` shim (#206 Tier-2 Sub-PR-2). Replaces
            -- the full `os` library so plugin code reaches only
            -- the three methods the bundled-plugin audit found in
            -- use (time / date / difftime). See `_os_safe`
            -- definition near the SANDBOX_GLOBALS block above.
            env.os = _os_safe
            -- Curated `io` shim (#206 Tier-2 Sub-PR-3). io.popen
            -- is gone; io.open is path-restricted. See `_io_safe`.
            env.io = _io_safe
            env.hub = hubobject
            env.utf = utf
            env.string = utf
            -- `no_global_scripting` cfg key (default true): with the
            -- explicit whitelist above, accessing a forbidden global
            -- like `debug` already raises "attempt to index nil
            -- value" at the plugin's first dereference. The setenv()
            -- wrapper merely UPGRADES the error to the more explicit
            -- "attempt to read undeclared var: 'debug'" via __index,
            -- AND adds an __newindex trap that blocks
            -- plugin-created globals (`myvar = 5` outside a `local`
            -- binding). The cfg key remains for the __newindex
            -- behaviour - legacy plugins that create globals
            -- unintentionally rely on the lax mode. Operators who
            -- want maximum strictness leave the default true.
            -- Candidate for deprecation alongside the Tier 2 os/io
            -- curation pass for #206.
            if cfg_get "no_global_scripting" then
                setenv( env )
            end

            -- #261: capture version BEFORE pcall (source-grep on the
            -- source string that checkfile() already read). The
            -- plugin's return value can override via
            -- `return { _version = "..." }`.
            local _meta_version = _extract_version( ret )
            ret, err = loadfile( path, "t", env )
            if not ret then
                out_error( "scripts.lua: syntax error in script '", scriptname, "': ", err )
            else
                local bol, ret = pcall( ret )
                if not bol then
                    out_error( "scripts.lua: lua error in script '", scriptname, "': ", ret )
                else
                    _loaded[ scriptname ] = ret
                    _scripts[ key ] = scriptname
                    if type( ret ) == "table" and type( ret._version ) == "string" then
                        _meta_version = ret._version
                    end
                    _plugin_meta[ scriptname ] = {
                        name          = scriptname:gsub( "%.lua$", "" ),
                        filename      = scriptname,
                        version       = _meta_version,
                        manageable    = manageable,
                        enabled       = true,
                        loaded        = true,
                        order_index   = cfg_index,
                        scriptid      = key,    -- inner-shadowed `key` (set just above by `local key = _len + 1`)
                    }
                end
            end
        end
        end    -- #261: close the `else` of the enabled-gate
    end
    firelistener "onStart"
end

killscripts = function( )
    firelistener "onExit"
    _loaded = { }
    _scripts = { }
    _listeners = { }
    _len = 0
    mem_free( )
end

import = function( script )
    script = tostring( script )
    local tbl = _loaded[ script ] or _loaded[ script .. ".lua" ]
    if type( tbl ) == "table" then
        local ctbl = { }
        for i, k in pairs( tbl ) do
            ctbl[ i ] = k
        end
        return setmetatable( ctbl, { __mode = "v" } )
    else
        return tbl
    end
end

init = function( )
    out.setlistener( "error", function( msg ) firelistener( "onError", tostring( msg ) ) end )
end

-- #263: register a core-side tap into the firelistener chain.
-- Called by core/http_events.lua.init. Idempotent on the same
-- function reference (re-register does NOT duplicate).
local register_tap = function( fn )
    if type( fn ) ~= "function" then return end
    for _, existing in ipairs( _firelistener_taps ) do
        if existing == fn then return end
    end
    table.insert( _firelistener_taps, fn )
end

-- #261 helpers, exported for core/http_router.lua's /v1/plugins endpoints.

-- Return the listener types a plugin has registered. Walks the
-- _listeners table for the plugin's scriptid and collects the keys
-- (onLogin / onBroadcast / ...). Returns an array (deterministic
-- order = ipairs of a sorted snapshot).
local function _listener_types_for( scriptid )
    if type( scriptid ) ~= "number" then return { } end
    local tbl = _listeners[ scriptid ]
    if type( tbl ) ~= "table" then return { } end
    local out = { }
    for ltype in pairs( tbl ) do
        out[ #out + 1 ] = ltype
    end
    table.sort( out )
    return out
end

-- Snapshot of all plugins currently registered in cfg.scripts plus
-- their runtime state. The `enabled` / `manageable` / `order_index`
-- fields reflect the LIVE cfg.scripts table (not the snapshot from
-- startscripts time) - so a PUT-driven cfg.scripts mutation is
-- immediately visible to a follow-up GET, without requiring a
-- reload. The `loaded` / `version` / `listeners` fields come from
-- _plugin_meta (built at startscripts time) so they reflect what
-- is actually running in memory - those flip after POST /v1/reload.
list_plugins = function( )
    local out = { }
    local scripts = cfg.get( "scripts" )
    if type( scripts ) ~= "table" then return out end
    for cfg_index, entry in ipairs( scripts ) do
        local scriptname, enabled, manageable
        if type( entry ) == "string" then
            scriptname, enabled, manageable = entry, true, false
        elseif type( entry ) == "table" then
            scriptname  = entry[ 1 ]
            enabled     = entry.enabled ~= false
            manageable  = true
        end
        if scriptname then
            local meta = _plugin_meta[ scriptname ]
            out[ #out + 1 ] = {
                name          = scriptname:gsub( "%.lua$", "" ),
                filename      = scriptname,
                version       = ( meta and meta.version ) or "unknown",
                manageable    = manageable,
                enabled       = enabled,
                loaded        = ( meta and meta.loaded ) or false,
                order_index   = cfg_index,
                listeners     = _listener_types_for( meta and meta.scriptid ),
            }
        end
    end
    return out
end

-- Persist a new enabled-state for a plugin entry by rewriting the
-- cfg.scripts array via cfg.set. Only operates on table-form
-- (manageable) entries; string-form entries are operator-protected.
-- Returns ( true ) on success, or ( false, code, msg ) on failure
-- where code is one of:
--   "E_NOT_FOUND" - plugin name not in cfg.scripts
--   "E_FORBIDDEN" - entry exists but in string-form
--   "E_INVALID"   - cfg.set rejected the new value
-- The change does NOT trigger a reload; the caller surfaces
-- reload_required = true to the API client.
set_plugin_enabled = function( name, new_enabled )
    if type( name ) ~= "string" or type( new_enabled ) ~= "boolean" then
        return false, "E_BAD_INPUT", "name (string) and enabled (boolean) required"
    end
    local scripts = cfg.get( "scripts" )
    if type( scripts ) ~= "table" then
        return false, "E_INVALID", "cfg.scripts not an array"
    end
    local filename_a = name
    local filename_b = name:match( "%.lua$" ) and name or ( name .. ".lua" )
    -- find the entry: match by full filename (with or without .lua).
    -- If a duplicate exists in cfg.scripts (same name twice - e.g. one
    -- string-form + one table-form), this picks the FIRST match.
    -- Duplicates are an operator misconfiguration; the GET listing
    -- would already show both rows. Documented edge case, not handled
    -- specially here.
    local found_index, found_is_string
    for i, entry in ipairs( scripts ) do
        local entry_name
        if type( entry ) == "string" then
            entry_name = entry
            if entry_name == filename_a or entry_name == filename_b then
                found_index, found_is_string = i, true
                break
            end
        elseif type( entry ) == "table" then
            entry_name = entry[ 1 ]
            if entry_name == filename_a or entry_name == filename_b then
                found_index, found_is_string = i, false
                break
            end
        end
    end
    if not found_index then
        return false, "E_NOT_FOUND", "plugin '" .. name .. "' not in cfg.scripts"
    end
    if found_is_string then
        return false, "E_FORBIDDEN",
            "plugin '" .. name .. "' is in string-form (operator-protected). " ..
            "Convert to table-form in cfg.scripts to enable API toggling."
    end
    -- mutate in place: keep table identity, just update enabled flag
    scripts[ found_index ].enabled = new_enabled
    -- cfg.set returns (true) on full success, (false, err_msg) on any
    -- failure path (validator reject / unknown key / savetable error) -
    -- see core/cfg.lua. Surfaces the validator's err_msg through to
    -- the API client for actionable 400s.
    local ok, err = cfg.set( "scripts", scripts )
    if not ok then
        return false, "E_INVALID", "cfg.set failed: " .. tostring( err )
    end
    return true
end

----------------------------------// BEGIN //--

----------------------------------// PUBLIC INTERFACE //--

return {

    init = init,

    kill = killscripts,
    start = startscripts,
    import = import,
    firelistener = firelistener,

    -- #261 plugin-management surface used by core/http_router.lua's
    -- GET /v1/plugins + PUT /v1/plugins/{name}/enabled endpoints.
    list_plugins       = list_plugins,
    set_plugin_enabled = set_plugin_enabled,

    -- #263 core-side tap registration; core/http_events.lua uses
    -- this to observe every event the hub fires via the existing
    -- listener-chain machinery.
    register_tap       = register_tap,

}
