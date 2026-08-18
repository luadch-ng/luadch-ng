--[[

        init.lua by blastbeat

        - this scipt starts the whole program
        - the main task is importing all extern libs and core scripts
        - every core script gets a "nacked" _G; globals are not allowed
        - benefits:
            - "mistyped var name" - bugs are gone
            - you are forced to use faster locals
            - no problems with lua modules which export global names ( because the main _G remains untouched )

]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local error = error
local pcall = pcall
local ipairs = ipairs
local assert = assert
local require = require
local loadfile = loadfile
local tostring = tostring
local setmetatable = setmetatable

--// lua libs //--

local os = os
local io = io
local package = package

--// lua lib methods //--

local write = io.write

--// functions //--

local use
local init
local import
local setenv
local loadscript

--// tables //--

local _env    -- replacement for _G in core scripts
local _core    -- array with names of core scripts
local _global    -- link to _G, could change in future
local _module    -- array with names of extern libs
local _optional    -- array with names of extern optional libs

--// simple data types //--

local _    -- dummy var
local _path    -- path to core scripts ( string )
local _filetype    -- extension of shared libraries ( string )

----------------------------------// DEFINITION //--

_path = "././core/"

_filetype = (    -- unix or windows libs?
    os.getenv "COMSPEC" and os.getenv "WINDIR" and ".dll"
) or ".so"

_global = _G

_core = {    -- luadch core, order is important

    "const",
    "mem",
    "signal",
    "util",
    -- ensuredirs is deliberately NOT in _core: import() loads it
    -- manually and calls ensure() BEFORE this load loop, so the runtime
    -- dirs (log/ cfg/ certs/ scripts/data/ cfg/geoip/) exist before any
    -- core module inits into them.
    -- cfg_secret is not in _core because its init() needs cfg_get
    -- (master_key_path). cfg.lua does `use "cfg_secret"` and calls
    -- secret.init() from cfg.init() after _settings is loaded so
    -- the cfg-side path override works on first boot.
    -- cfg_write (#644, comment-preserving cfg.tbl writer) is likewise NOT
    -- in _core: cfg.lua's file-scope `use "cfg_write"` pulls it in when cfg
    -- loads (so a restricted-env fault still surfaces at boot), it is
    -- passive at load, and it has no init() to order.
    "cfg",
    -- core/secrets.lua (Precursor 0c of #78 arc): sensitive-key
    -- registry + env-var-first cfg lookup. Loaded AFTER cfg so the
    -- init() baseline registrations and the lookup fallback can
    -- consult cfg.get; loaded BEFORE everything that holds
    -- sensitive cfg keys (http_router /v1/config redaction, future
    -- etc_geoip / etc_proxydetect plugins).
    "secrets",
    "out",
    -- cert_bootstrap MUST come after cfg + out (it reads cfg.get and
    -- writes via out.put) and BEFORE hub (hub.init() binds the TLS
    -- listener, which would fail with "missing cert" if the cert was
    -- not yet generated). Closes #77.
    "cert_bootstrap",
    -- core/sha256.lua (Precursor 0d of #78 arc): pure-Lua FIPS 180-4
    -- SHA-256. Used by cacert_bootstrap below to compare runtime
    -- ca-bundle.pem against the bundled source-of-truth. Self-test
    -- runs at module load against NIST CAVP vectors; load failure
    -- here aborts the boot LOUD which is exactly what we want for a
    -- silent-corruption-class bug.
    "sha256",
    -- core/hmac.lua: HMAC-SHA256 (RFC 2104) on top of core/sha256.lua.
    -- Load AFTER sha256 (its only dep; used at load-time self-test
    -- against RFC 4231 vectors) and BEFORE scripts so it is in _G when
    -- the plugin sandbox iterates the whitelist. Consumed by the
    -- etc_webhook plugin to authenticate signed inbound webhook bodies;
    -- sha256 itself stays OUT of the sandbox, plugins get only the MAC.
    "hmac",
    -- core/cacert_bootstrap.lua (Precursor 0d of #78 arc): reconcile
    -- certs/ca-bundle.pem against lib/luadch/ca-bundle.pem on every
    -- boot (install missing, warn on outdated, opt-in auto-update).
    -- MUST come after cfg + out + sha256 (uses all three at init
    -- time); ordering vs hub is irrelevant because the reconcile
    -- runs at init-time, not at hub-loop time.
    "cacert_bootstrap",
    -- core/ipmatch.lua (Phase A of #78 arc): pure-Lua IPv4/IPv6
    -- + CIDR parse + prefix-match primitives. No deps beyond
    -- stdlib; load order is just before its consumer blocklist.
    "ipmatch",
    -- core/whitelist.lua (#78 allowlist): global IP/CIDR allowlist
    -- consulted by blocklist.check_ip and the IP-blocking plugins.
    -- Loaded AFTER ipmatch (uses its parse/match primitives) and
    -- BEFORE blocklist, which captures whitelist.is_whitelisted in
    -- its init() to apply the "whitelist overrides an automated block"
    -- precedence. Same passive-at-load / init()-reads-cfg contract.
    "whitelist",
    -- core/blocklist.lua (Phase A of #78 arc): unified pre-handshake
    -- IP/CIDR blocklist (in-memory bucketed cache + scripts/data/etc_blocklist.tbl
    -- persistent store + decision API). Loaded BEFORE ratelimit +
    -- server because server.lua captures `blocklist.check_ip` at
    -- module load for the accept-time stealth hook. init() reads
    -- cfg + reloads the store + registers a cfg-reload listener.
    "blocklist",
    -- core/mmdb.lua (Phase D1 of #78 arc): pure-Lua MaxMind DB reader
    -- (GeoLite2 Country / ASN). Passive library - no init(), opens no
    -- files at load. Loaded AFTER ipmatch (uses it to parse lookup
    -- addresses); position among the post-ipmatch modules is otherwise
    -- irrelevant. The Phase D2 plugin (etc_geoip) is its only
    -- consumer; registered here so it loads under the restricted env
    -- and is reachable as a core module.
    "mmdb",
    "ratelimit",
    "server",
    "adc",
    "hub",
    -- core/util_http.lua: HTTP-API-specific plugin helpers (#82
    -- Phase 2 PR-B). Loaded AFTER hub.lua because the helper does
    -- a lazy `use "hub"` at registration time, not at module-load
    -- time, but kept ordered alongside the other HTTP-API
    -- machinery (core/http.lua / core/http_router.lua are loaded
    -- on demand via `use`, not from _core).
    "util_http",
    -- core/http_filter.lua: shared filter+sort+paginate helper for
    -- HTTP API list endpoints (#264). Loaded after util_http for
    -- symmetry; pure-Lua, no runtime dependency on hub state.
    "http_filter",
    -- core/audit.lua (#84): canonical audit-event builder + fire
    -- helper. Loaded BEFORE scripts so the module is in _G when
    -- the plugin sandbox iterates the whitelist (admin plugins
    -- call `audit.fire(audit.build(...))`). Late-binds scripts +
    -- cfg + out via `use` at first call to avoid a load-order
    -- cycle with scripts.lua.
    "audit",
    -- core/http_client.lua: non-blocking OUTBOUND HTTP(S) client for
    -- plugins (hublist announce, webhooks). Loaded after server is
    -- available (it lazy-`use`s server.addtimer) and BEFORE scripts
    -- so the module is in _G when the plugin sandbox iterates the
    -- whitelist. Touches no server.lua internals - drives a
    -- non-blocking socket on the existing ~1s timer so the
    -- single-threaded hub never blocks on an outbound request.
    "http_client",
    -- core/geoip_update.lua: in-hub MaxMind GeoLite2 auto-update
    -- (download .tar.gz -> verify sha256 -> gunzip -> untar -> atomic
    -- place). Infrastructure the etc_geoip plugin drives by import - it
    -- needs sha256 (not in the plugin sandbox), full os.rename and
    -- server.addtimer, so it cannot live in the plugin. Loaded AFTER
    -- http_client / sha256 / mmdb (its top-level use deps) and BEFORE
    -- scripts so it is in _G when the plugin sandbox iterates the whitelist.
    "geoip_update",
    -- #206 Tier-2 Sub-PR-3: host OS / CPU / RAM detection
    -- helpers. Lives in core (not in a plugin) so the bundled
    -- `cmd_hubinfo` plugin can use `sysinfo.os_name()` etc. via
    -- the whitelisted `sysinfo` global without needing `io.popen`
    -- in the plugin sandbox. Loaded BEFORE scripts.lua so the
    -- module is in _G when the plugin sandbox iterates the
    -- whitelist.
    "sysinfo",
    -- core/backup.lua (#480 PR-A): automatic-backup engine - collects the
    -- restore-minimum state set, seals it via core/backup_archive.lua, writes
    -- + rotates the .ldbk artifact. Needs full os.rename/remove + raw
    -- makedir/listdir + secrets, so it lives in core, not the plugin sandbox.
    -- Loaded AFTER its file-scope use deps (cfg / out / const / secrets;
    -- backup_archive loads on demand) and BEFORE scripts so it is in _G when
    -- the plugin sandbox iterates the whitelist (scripts/etc_backup.lua calls
    -- backup.run / .readiness / .list). Passive at load - no init(), no I/O.
    "backup",
    "scripts",
    -- #263: HTTP API event ringbuffer. Loaded AFTER scripts so its
    -- init() can register a core-side tap into scripts.firelistener;
    -- captures every event the hub fires (onLogin / onBroadcast /
    -- onReg / ...) for the GET /v1/events stream without requiring
    -- plugin changes.
    "http_events",
    "types",

}

_module = {    -- extern libs

    "adclib",
    "unicode",
    "socket",

}

_optional = {    -- optional extern libs

    "ssl",
    "basexx",
    -- Phase 8 S4b: zlib stream binding for ADC-EXT ZLIF (stream
    -- compression). Optional so the hub still runs if the binary
    -- failed to build / is missing; cfg validates `zlif_enabled =
    -- true` against load success and refuses to advertise ZLIF if
    -- the binding is not available.
    "zlib_stream",
    -- Phase 1 of #82: pure-Lua JSON encoder/decoder for the HTTP
    -- API. Optional because the API itself is opt-in via cfg
    -- `http_port`; the hub stays runnable on installs that
    -- omitted the dkjson drop. The HTTP router refuses to bind
    -- if `http_port` is set but dkjson did not load.
    "dkjson",

}

loadscript = function( name )    -- this function loads a certain core script
    name = tostring( name )
    if _global[ name ] == false then    -- optional lib
        return nil
    end
    assert( not _global[ name ], "fatal error: namespace '" .. name .. "' already exists" )    -- UNSAFE: program termination
    -- Lua 5.4: pass env as the 3rd loadfile arg; it becomes _ENV in the chunk.
    local script, err = loadfile( _path .. name .. ".lua", "t", _env )
    assert( script, err )    -- UNSAFE: program termination
    _global[ name ] = script( )
    write( "\ninit.lua: loaded '" .. name .. "'" )
    return _global[ name ]
end

import = function( )    -- this function loads all extern libs and the core
    write "init.lua: import libs"
    for i, lib in ipairs( _module ) do
        _global[ lib ] = _global[ lib ] or require( lib )
        write( "\ninit.lua: loaded '" .. lib .. "'" )
    end
    write "\ninit.lua: import optional libs"
    local succ
    for i, lib in ipairs( _optional ) do
        succ, ret = pcall( require, lib )
        _global[ lib ] = ( succ and ret ) or false
        _ = succ and write( "\ninit.lua: loaded '" .. lib .. "'" )
    end
    -- Pre-load common ssl submodules so plugins can reach them
    -- through the already-whitelisted `ssl` global (cert / keyprint
    -- handling) without needing `require` in the plugin sandbox
    -- (#206 Tier 2). Plugins use `ssl.x509.load(...)`; the
    -- submodule is attached as a field of the parent ssl table.
    if _global.ssl then
        succ, ret = pcall( require, "ssl.x509" )
        if succ then _global.ssl.x509 = ret end
    end
    write "\ninit.lua: import core"
    -- Self-heal the runtime directories the hub writes into (log/, cfg/,
    -- certs/, scripts/data/, cfg/geoip/) BEFORE any core module inits
    -- into them: a bare-metal / wiped-bind-mount install may lack them,
    -- and cfg/geoip/ is created by nothing else. Best-effort - makedir is
    -- EEXIST-tolerant and absent under a standalone lua; a genuine
    -- failure still surfaces later as a clear write error.
    local ensuredirs = use "ensuredirs"
    _ = ensuredirs and ensuredirs.ensure and ensuredirs.ensure( )
    for i, script in ipairs( _core ) do
        _ = _global[ script ] or loadscript( script )
    end
    write "\ninit.lua: init core modules"
    for i, script in ipairs( _core ) do
        _ = _global[ script ].init and _global[ script ].init( )
        _ = _global[ script ].init and write( "\ninit.lua: initialized '" .. script .. "'" )
    end
end

use = function( name )    -- this function imports any global var/namespace
    return nil
    or _global[ name ]
    or loadscript( name )
end

setenv = function( tbl )    -- this function creates a new env
    return setmetatable(
        tbl or {

            use = use,    -- the only global method a script can access

        },
        {    -- global vars are not allowed

            __index = function( tbl, key )
                error( "attempt to read undeclared var: '" .. tostring( key ) .. "'", 2 )
            end,

            __newindex = function( tbl, key, value )
                error( "attempt to write undeclared var: '" .. tostring( key ) .. " = " .. tostring( value ) .. "'", 2 )
            end,

        }
    )
end

init = function( )    -- this function is the start point
    _env = _env or setenv{ use = use }
    import( )
    write( "\n\n"
        .. const.PROGRAM_NAME
        .. " "
        .. const.VERSION
        .. " by Aybo (fork of Luadch "
        .. const.COPYRIGHT
        .. ") (2007-" .. os.date( "%Y" ) .. ")"
        .. "\n\n"
    )
    signal.set( "start", os.time( ) )
    mem.free( )
    local bol, err = pcall( hub.loop )
    if not bol and err then
        out.error( err )
    elseif err == "restart" then
        restartluadch( )
    end
    os.exit( )
end

----------------------------------// BEGIN //--

package.path = package.path .. ";"
    .. "././core/?.lua;"
    .. "././lib/?/?.lua;"
    .. "././lib/luasocket/lua/?.lua;"
    .. "././lib/luasec/lua/?.lua;"

package.cpath = package.cpath .. ";"
    .. "././lib/?/?" .. _filetype .. ";"
    .. "././lib/luasocket/?/?" .. _filetype .. ";"
    .. "././lib/luasec/?/?" .. _filetype .. ";"

init( )
