--[[

    hub_runtime.lua by pulsar

        description: this script saves the hub runtime and adds a command to show/reset the hub runtime

        usage: [+!#]runtime show|reset

        v0.11:
            - fix (#445 follow-up): migrate_or_init read core/hci.lua on
              every boot, even once the new scripts/data/hub_runtime.tbl
              store already held a value. util.loadtable logs a "checkfile:
              No such file" error for a missing legacy file, and Docker
              never ships core/hci.lua, so the error log gained one such
              line on every single boot. Now the legacy file is consulted
              only when the new store is absent/corrupt, and its existence
              is probed with io.open first, so a missing one logs nothing.

        v0.10:
            - fix #445: move the persisted runtime store from
              `core/hci.lua` to `scripts/data/hub_runtime.tbl`.
              `core/` is a SHIPPED directory (CMake install +
              baked into the Docker image), so every upgrade wrote
              a pristine `hubruntime = 0` over the operator's
              accumulated value; `scripts/data/` is the
              operator-owned (Docker-mounted) plugin-state dir that
              upgrades never clobber. Migrates once on load: if the
              new store is absent, adopt the value from a legacy
              `core/hci.lua`. That adoption only recovers a value if
              the legacy file still holds it at boot - so
              CMakeLists.txt excludes `core/hci.lua` from the
              install (`PATTERN "hci.lua" EXCLUDE`), leaving the
              operator's on-disk value in place for a source
              (`cmake --install`) upgrade to migrate. Docker cannot
              migrate (the old counter lived in the ephemeral
              container layer, discarded on recreate) but gains a
              persistent counter going forward. `core/hci.lua` is
              never written now; a future release removes it. This
              plugin is the sole writer; cmd_uptime / cmd_hubinfo
              became pure readers of the new path in their v-bumps.

        v0.9:
            - HTTP API: GET /v1/runtime (read), PUT /v1/runtime (admin)
              #82 Phase 4 PR-4

        v0.8: by pulsar
            - removed precaching of hci.lua on scriptstart

        v0.7: by pulsar
            - added "years" to util.formatseconds
                - changed get_hubuptime(), get_hubruntime()

        v0.6: by pulsar
            - changed check_hci() function

        v0.5: by pulsar
            - removed table lookups
            - show session runtime too
            - fix #67 -> https://github.com/luadch/luadch/issues/67
                - added check_hci()

        v0.4: by pulsar
            - added "get_hubruntime()" function
            - added "reset_hubruntime()" function
            - added help, ucmd
            - added report

        v0.3: by pulsar
            - small fix

        v0.2: by pulsar
            - using new luadch date style

        v0.1: by pulsar
            - saves the hub runtime

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "hub_runtime"
local scriptversion = "0.11"

local cmd = "runtime"
local cmd_p1 = "show"
local cmd_p2 = "reset"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local minlevel = cfg.get( "hub_runtime_minlevel" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "hub_runtime_report" )
local report_opchat = cfg.get( "hub_runtime_report_opchat" )
local report_hubbot = cfg.get( "hub_runtime_report_hubbot" )
local llevel = cfg.get( "hub_runtime_llevel" )
-- #445: the persisted store now lives under scripts/data/ (operator-
-- owned, Docker-mounted, upgrade-safe), NOT core/ (shipped, clobbered
-- on every install / image update). `legacy_hci_file` is the old
-- location, read once at load as the migration source and never written.
local hci_file = "scripts/data/hub_runtime.tbl"
local legacy_hci_file = "core/hci.lua"

--// msgs
local help_title = "hub_runtime.lua"
local help_usage = lang.help_usage or "[+!#]runtime show|reset"
local help_desc = lang.help_desc or "Show/reset the hub runtime"

local msg_runtime = lang.msg_runtime or [[


=== RUNTIME ============================================================

               Hub runtime - Session:   %s
               Hub runtime - Complete: %s

============================================================ RUNTIME ===
  ]]

local msg_reset_1 = lang.msg_reset_1 or "Hub runtime was reset."
local msg_reset_2 = lang.msg_reset_2 or "Hub runtime has been reset by: %s"
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]runtime show|reset"

local msg_years = lang.msg_years or " years, "
local msg_days = lang.msg_days or " days, "
local msg_hours = lang.msg_hours or " hours, "
local msg_minutes = lang.msg_minutes or " minutes, "
local msg_seconds = lang.msg_seconds or " seconds"

local ucmd_menu_show = lang.ucmd_menu_show or { "Hub", "Core", "Hub runtime", "show" }
local ucmd_menu_reset = lang.ucmd_menu_reset or { "Hub", "Core", "Hub runtime", "reset", "OK" }

local msg_unknown = lang.msg_unknown or "<UNKNOWN>"

--// functions
local get_hubuptime, get_hubruntime, set_hubruntime, reset_hubruntime, onbmsg


----------
--[CODE]--
----------

local minutes = 1
local delay = minutes * 60
local start = os.time()

-- #445 migration decision (pure; unit-tested via the _runtime_seed
-- export). Given the current new-store table and the legacy core/hci.lua
-- table (either may be nil / non-table on a missing / corrupt file),
-- returns the seed to write to the new store, or nil when the new store
-- already holds a valid value and must be left untouched.
--   - new store already valid  -> nil (no-op; do NOT re-adopt legacy)
--   - new store absent, legacy has a value -> adopt it (upgrade path)
--   - neither present           -> zeros (fresh hub)
-- Adopting the legacy value is what stops the fix from zeroing every
-- operator's counter on the release that introduces it.
local function runtime_seed( existing, legacy )
    if type( existing ) == "table" and type( existing.hubruntime ) == "number" then
        return nil
    end
    local seed = { hubruntime = 0, hubruntime_last_check = 0 }
    if type( legacy ) == "table" and type( legacy.hubruntime ) == "number" then
        seed.hubruntime = legacy.hubruntime
        seed.hubruntime_last_check = legacy.hubruntime_last_check or 0
    end
    return seed
end

local function migrate_or_init()
    local existing = util.loadtable( hci_file )
    if type( existing ) == "table" and type( existing.hubruntime ) == "number" then
        -- New store already holds a value: migration is done. Do NOT read
        -- the legacy core/hci.lua - util.loadtable logs a scary "checkfile:
        -- No such file" error for a missing one, and on Docker (core/ is
        -- baked, never migratable) it is never there, so re-reading it on
        -- every boot only spams the error log (#445 follow-up).
        return
    end
    -- New store absent / corrupt: consult the legacy core/hci.lua ONCE,
    -- but probe its existence with io.open first so a missing legacy file
    -- (the normal case now, and always on Docker) logs nothing.
    local legacy
    local f = io.open( legacy_hci_file, "r" )
    if f then f:close(); legacy = util.loadtable( legacy_hci_file ) end
    local seed = runtime_seed( existing, legacy )
    if seed then util.savetable( seed, "hub_runtime", hci_file ) end
end

migrate_or_init()

get_hubuptime = function()
    local hubuptime
    local start = signal.get( "start" ) or os.time()
    if not start then
        hubuptime = msg_unknown
    else
        local y, d, h, m, s = util.formatseconds( os.difftime( os.time(), start ) )
        hubuptime = y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    end
    return hubuptime
end

-- F-PLG-2 (#133): defensive `or {}` plus `.field or default` so a
-- mid-run loadtable failure (file deleted, permission flip, fs error)
-- doesn't crash these listeners. migrate_or_init() at script load
-- already creates the store with zero defaults; in steady state these
-- reads succeed.
get_hubruntime = function()
    local hci_tbl = util.loadtable( hci_file ) or {}
    local hrt = hci_tbl.hubruntime or 0
    local y, d, h, m, s = util.formatseconds( hrt )
    hrt = y .. msg_years .. d .. msg_days .. h .. msg_hours .. m .. msg_minutes .. s .. msg_seconds
    return hrt
end

set_hubruntime = function()
    local hci_tbl = util.loadtable( hci_file ) or {}
    local hrt = hci_tbl.hubruntime or 0
    local hrt_lc = hci_tbl.hubruntime_last_check or 0
    if hrt_lc == 0 then hrt_lc = util.date() end
    local hrt_lc_str = tostring( hrt_lc )
    if #hrt_lc_str ~= 14 then hrt_lc = util.convertepochdate( hrt_lc ) end
    local sec, y, d, h, m, s = util.difftime( util.date(), hrt_lc )
    local new_time = hrt + sec
    hci_tbl.hubruntime = new_time
    hci_tbl.hubruntime_last_check = util.date()
    util.savetable( hci_tbl, "hub_runtime", hci_file )
end

reset_hubruntime = function()
    local hci_tbl = util.loadtable( hci_file ) or {}
    hci_tbl.hubruntime = 0
    util.savetable( hci_tbl, "hub_runtime", hci_file )
end

-- Helpers for raw-seconds access to the persisted runtime counter.
-- The ADC path's `get_hubuptime` / `get_hubruntime` return formatted
-- strings (`X years, Y days, ...`); the HTTP path returns raw integer
-- seconds and lets the client format. Matches /v1/version uptime-as-
-- seconds and /v1/records raw-bytes conventions.
--
-- The two-line load-and-parse duplication with `get_hubruntime` /
-- `get_hubuptime` above is deliberate: the format-vs-raw split is
-- the API surface contract, not coincidence. Extracting a shared
-- helper would force the ADC functions to take a "raw or
-- formatted" mode flag, which adds a worse coupling than the
-- 2-line duplication.
local get_session_seconds = function()
    local start_ts = signal.get( "start" ) or os.time()
    return math.floor( os.difftime( os.time(), start_ts ) )
end

local get_total_seconds = function()
    local hci_tbl = util.loadtable( hci_file ) or {}
    return math.floor( tonumber( hci_tbl.hubruntime ) or 0 )
end

-- HTTP handler: GET /v1/runtime (#82 Phase 4 PR-4). Read scope.
-- Returns raw integer seconds for both session (this process's
-- uptime, from `signal.get("start")`) and total (the persisted
-- accumulator written to `scripts/data/hub_runtime.tbl` by the
-- 60s onTimer).
--
-- The ADC `+runtime show` cmd formats both as human-readable
-- strings via `util.formatseconds`; the HTTP path returns raw
-- seconds (consistent with `/v1/version`'s `uptime` and the
-- raw-bytes convention of `/v1/records`). Clients format.
--
-- The ADC-side `hub_runtime_minlevel` gate does NOT apply on the
-- HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
local http_handler_get_runtime = function( req )
    return { status = 200, data = {
        session_seconds = get_session_seconds(),
        total_seconds   = get_total_seconds(),
    } }
end

-- HTTP handler: PUT /v1/runtime (#82 Phase 4 PR-4). Admin scope.
-- Body `{hubruntime: integer (>= 0) required}`. Sets the
-- persisted runtime accumulator and rewrites
-- `hubruntime_last_check` to `util.date()` so the next 60s
-- `set_hubruntime` tick computes the diff from now and adds
-- ~60s to the supplied value (rather than racing the
-- accumulator forward by whatever sat in the file pre-PUT).
--
-- Family-consistent with the #236 registered-users PUTs (all
-- require a typed body). The only ADC operation in this plugin
-- is "reset to zero"; PUT generalises to "set runtime to N"
-- because the underlying `scripts/data/hub_runtime.tbl` storage is a plain
-- integer count - a future ops workflow that needs to seed
-- runtime from a backup uses the same endpoint without a new
-- verb.
--
-- Returns 200 with `data: {action: "runtime-set", hubruntime}`
-- per §7.1.1 (hub-control variant: no sid/nick). Returns
-- **400 E_BAD_INPUT** if `hubruntime` is missing, non-integer,
-- or negative.
--
-- The ADC-side `hub_runtime_minlevel` gate does NOT apply on
-- the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate.
local http_handler_put_runtime = function( req )
    local body = req.body or {}
    local hrt = body.hubruntime
    if type( hrt ) ~= "number" or hrt < 0 or hrt ~= math.floor( hrt ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "hubruntime must be a non-negative integer" } }
    end
    local hrt_int = math.floor( hrt )
    local hci_tbl = util.loadtable( hci_file ) or {}
    hci_tbl.hubruntime = hrt_int
    hci_tbl.hubruntime_last_check = util.date()
    util.savetable( hci_tbl, "hub_runtime", hci_file )
    return { status = 200, data = {
        action     = "runtime-set",
        hubruntime = hrt_int,
    } }
end

hub.setlistener( "onTimer", {},
    function()
        if os.time() - start >= delay then
            set_hubruntime()
            start = os.time()
        end
        return nil
    end
)

onbmsg = function( user, command, parameters )
    local user_level = user:level()
    local user_firstnick = user:firstnick()
    if user_level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    local param = utf.match( parameters, "^(%S+)$" )
    if param == cmd_p1 then
        user:reply( utf.format( msg_runtime, get_hubuptime(), get_hubruntime() ), hub.getbot() )
        return PROCESSED
    end
    if param == cmd_p2 then
        reset_hubruntime()
        user:reply( msg_reset_1, hub.getbot() )
        local msg = utf.format( msg_reset_2, user_firstnick )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
        return PROCESSED
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

hub.setlistener( "onStart", {},
    function()
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_show, cmd, { cmd_p1 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_reset, cmd, { cmd_p2 }, { "CT1" }, minlevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoints (#82 Phase 4 PR-4).
        if hub.http_register then
            hub.http_register( "GET", "/v1/runtime", "read", http_handler_get_runtime, {
                plugin = scriptname,
                description = "hub runtime counters in raw seconds (= ADC `+runtime show`, raw-int format): session_seconds + total_seconds",
                response_schema = {
                    session_seconds = { type = "integer", required = true },
                    total_seconds   = { type = "integer", required = true },
                },
            } )
            hub.http_register( "PUT", "/v1/runtime", "admin", http_handler_put_runtime, {
                plugin = scriptname,
                description = "set persisted hub runtime accumulator (= ADC `+runtime reset` generalised; PUT { hubruntime: 0 } is the reset shape)",
                request_schema = {
                    hubruntime = { type = "integer", required = true, min = 0 },
                },
                response_schema = {
                    action     = { type = "string",  required = true },
                    hubruntime = { type = "integer", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {

    -- Internal test seam (#445): the pure migration decision. `_`-prefixed
    -- per the repo convention for a non-contract, test-only export.
    _runtime_seed = runtime_seed,

}