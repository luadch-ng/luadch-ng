--[[

    etc_auditlog.lua by Aybo (#84)

        Persistent JSONL audit trail for staff actions.

        - Subscribes to onAudit events (fired by admin command
          plugins via the core/audit.lua helper).
        - Serializes each event to a single JSON object per line.
        - Writes to log/audit-YYYY-MM-DD.jsonl (configurable via
          cfg.etc_auditlog_dir + _prefix).
        - Rolls over at first write past UTC midnight and unlinks
          files older than cfg.etc_auditlog_retention_days.
        - Append-only on disk: io.open mode is "ab"; no code path
          opens the file in write/truncate mode.
        - HTTP read endpoint: GET /v1/log/audit?lines=N (admin
          scope). Reads the CURRENT day's file only - multi-day
          queries are filesystem-side (jq, grep) by design.

        Toggles via cfg.tbl:
          etc_auditlog_activate           kill-switch (default true)
          etc_auditlog_dir                "log/"
          etc_auditlog_prefix             "audit-"
          etc_auditlog_retention_days     90
          etc_auditlog_http_lines_default 200
          etc_auditlog_http_lines_max     1000

        Threat model + plugin-trust caveats in docs/SECURITY.md.

        v0.01: initial release (#84)

]]--

----------------------
--[ SETTINGS / DECL ]--
----------------------

local scriptname = "etc_auditlog"
local scriptversion = "0.01"

local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_import = hub.import
local hub_debug = hub.debug
local hub_getbot = hub.getbot()
local utf_format = utf.format
local utf_match = utf.match
local os_date = os.date
local os_time = os.time
local os_remove = os.remove
local io_open = io.open

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )

--// dkjson: optional dep (Phase 1 of #82 made it optional in the
-- build). If missing the plugin loads as a no-op so a partial
-- install doesn't break the hub.
local dkjson = dkjson

--// cfg snapshot at onStart - re-read on +reload via the standard
-- hub-restart-loaded fresh-snapshot pattern.
local cfg_activate
local cfg_dir
local cfg_prefix
local cfg_retention_days
local cfg_http_lines_default
local cfg_http_lines_max

local _refresh_cfg_snapshot = function( )
    cfg_activate           = cfg_get "etc_auditlog_activate"
    cfg_dir                = cfg_get "etc_auditlog_dir"                or "log/"
    cfg_prefix             = cfg_get "etc_auditlog_prefix"             or "audit-"
    cfg_retention_days     = tonumber( cfg_get "etc_auditlog_retention_days" ) or 90
    cfg_http_lines_default = tonumber( cfg_get "etc_auditlog_http_lines_default" ) or 200
    cfg_http_lines_max     = tonumber( cfg_get "etc_auditlog_http_lines_max" )     or 1000
end

--// msgs
local help_title = "etc_auditlog.lua"
local help_usage = lang.help_usage or "[+!#]auditlog show"
local help_desc  = lang.help_desc  or "Shows the audit log (today's file)."
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_nofile = lang.msg_nofile or "No audit log entries for today yet."
local msg_usage  = lang.msg_usage  or "Usage: [+!#]auditlog show"
local msg_out    = lang.msg_out    or [[


=== AUDIT LOG (today) ====================================================================================

%s
==================================================================================== AUDIT LOG (today) ===

      ]]

local ucmd_menu = lang.ucmd_menu or { "Hub", "Logs", "show", "audit.log (today)" }

local minlevel = 80
local cmd_name = "auditlog"
local cmd_p = "show"

----------
--[CODE]--
----------

-- Current-day file path. Uses UTC so daily rollover is unaffected
-- by host timezone + DST shifts (audit trails want stable cadence).
local _current_date_path = function( )
    local d = os_date( "!%Y-%m-%d", os_time( ) )
    return cfg_dir .. cfg_prefix .. d .. ".jsonl", d
end

-- Per-process set of files we have already chmod'd 600 since
-- start, so the chmod_secret syscall fires once per file (on the
-- first write to a new daily path) rather than on every event.
-- Cleared implicitly on +reload (plugin re-loads with a fresh
-- empty table); the chmod is idempotent so re-running is safe.
local _chmodded = {}

-- Open today's file in APPEND-BINARY mode + chmod 600 on POSIX
-- the first time we touch a given path. The "ab" flag is the
-- only mode this plugin ever uses - no truncation surface. Caller
-- closes the handle (we don't hold it open between writes; the
-- append cost is one syscall per event and avoids "stale handle
-- across rollover" bugs at midnight). chmod via util.chmod_secret
-- = no-op on Windows, POSIX gets 0600 (matches user.tbl baseline
-- from docs/SECURITY.md F-AUTH-1 +  cmd_secret + cert_bootstrap).
local _open_append = function( path )
    local f, oerr = io_open( path, "ab" )
    if not f then
        hub_debug( scriptname .. ": cannot open '" .. tostring( path ) .. "' for append: " .. tostring( oerr ) )
        return nil
    end
    if not _chmodded[ path ] then
        util.chmod_secret( path )
        _chmodded[ path ] = true
    end
    return f
end

-- Unlink any audit-*.jsonl whose embedded date is older than the
-- configured retention. Probes candidate dates backwards by a
-- one-year window past the retention cutoff (operators who shrink
-- retention_days still get the now-stale historical files cleaned
-- up). Sandboxed plugins can't shell out to `ls`/`dir`, so we
-- enumerate by reconstructing the known filename pattern day by
-- day instead. ~365 io.open syscalls per rollover (once per day)
-- which is negligible.
local _retention_sweep = function( )
    if not cfg_retention_days or cfg_retention_days <= 0 then return end
    local now = os_time( )
    local check_window_days = 365
    for back = 1, check_window_days do
        -- Skip the first cfg_retention_days (= retained); unlink everything older.
        local candidate_date = os_date( "!%Y-%m-%d", now - ( ( cfg_retention_days + back ) * 86400 ) )
        local path = cfg_dir .. cfg_prefix .. candidate_date .. ".jsonl"
        local f = io_open( path, "rb" )
        if f then
            f:close( )
            local ok, rerr = os_remove( path )
            if not ok then
                hub_debug( scriptname .. ": retention sweep: cannot unlink '" .. path .. "': " .. tostring( rerr ) )
            end
        end
    end
end

-- Tracks last-known date so we trigger retention_sweep exactly
-- once per UTC day rollover (first write past midnight).
local _last_seen_date

local _maybe_rollover = function( today )
    if _last_seen_date ~= nil and _last_seen_date ~= today then
        _retention_sweep( )
    end
    _last_seen_date = today
end

-- Build the JSONL line bytes for an event. Drops nil sub-fields
-- (target / reason / meta) so the on-disk shape is compact when
-- the plugin only set the required keys.
local _serialize_event = function( event )
    if not dkjson then return nil end
    local wire = {
        ts     = os_date( "!%Y-%m-%dT%H:%M:%SZ", os_time( ) ),
        action = event.action,
        actor  = event.actor,
    }
    if event.target then wire.target = event.target end
    if event.reason and event.reason ~= "" then wire.reason = event.reason end
    if event.meta   then wire.meta   = event.meta   end
    local s, jerr = dkjson.encode( wire )
    if not s then
        hub_debug( scriptname .. ": dkjson.encode failed: " .. tostring( jerr ) )
        return nil
    end
    return s
end

local _write_event = function( event )
    if not cfg_activate then return end
    if not dkjson then return end    -- silent no-op if dep missing
    local line = _serialize_event( event )
    if not line then return end
    local path, today = _current_date_path( )
    _maybe_rollover( today )
    local f = _open_append( path )
    if not f then return end
    f:write( line, "\n" )
    f:close( )
end

-- onAudit listener: tap registered into scripts.firelistener chain
-- via the standard hub.setlistener pattern. Re-entered for every
-- staff action fire site across cmd_ban / cmd_reg / cmd_disconnect /
-- etc. Errors swallowed (audit must not break the hub).
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" then return nil end
        local ok, werr = pcall( _write_event, event )
        if not ok then
            hub_debug( scriptname .. ": write failed (caught): " .. tostring( werr ) )
        end
        return nil
    end
)

-- Tail-read the CURRENT day's file. Returns (lines_table,
-- total_lines). Pattern matches etc_cmdlog.lua's read_log_tail.
-- Multi-day queries are out of scope for v1 - operators with
-- compliance needs go to the filesystem (jq / cat).
local _read_today_tail = function( n )
    local path = _current_date_path( )
    local file = io_open( path, "rb" )
    if not file then return { }, 0 end
    local all = { }
    for line in file:lines( ) do
        all[ #all + 1 ] = line
    end
    file:close( )
    local total = #all
    if n and total > n then
        local out = { }
        for i = total - n + 1, total do
            out[ #out + 1 ] = all[ i ]
        end
        return out, total
    end
    return all, total
end

-- ADC command handler: +auditlog show. Dumps today's file as one
-- big banner in the chat reply, same pattern as +cmdlog show.
local onbmsg = function( user, adccmd, parameters, txt )
    if user:level( ) < minlevel then
        user:reply( msg_denied, hub_getbot )
        return PROCESSED
    end
    local id = utf_match( parameters or "", "^(%S+)$" )
    if id ~= cmd_p then
        user:reply( msg_usage, hub_getbot )
        return PROCESSED
    end
    local path = _current_date_path( )
    local file = io_open( path, "rb" )
    if not file then
        user:reply( msg_nofile, hub_getbot )
        return PROCESSED
    end
    local msg = file:read( "*a" )
    file:close( )
    user:reply( utf_format( msg_out, msg or "" ), hub_getbot, hub_getbot )
    return PROCESSED
end

-- HTTP API handler: GET /v1/log/audit?lines=N. Same envelope
-- shape as /v1/log/cmd and /v1/errors (#82 §6.4): {lines, returned,
-- total_lines}. Admin scope.
local http_handler_log_audit = function( req )
    local n = tonumber( req.query and req.query.lines ) or cfg_http_lines_default
    if n < 1 then n = cfg_http_lines_default end
    if n > cfg_http_lines_max then n = cfg_http_lines_max end
    local lines, total = _read_today_tail( n )
    return { status = 200, data = {
        lines       = lines,
        returned    = #lines,
        total_lines = total,
    } }
end

hub.setlistener( "onStart", {},
    function( )
        _refresh_cfg_snapshot( )
        if not dkjson then
            hub_debug( scriptname .. ": dkjson optional dep missing; plugin is a no-op." )
        end
        -- One-shot retention sweep at boot. Without this a hub
        -- that restarts every day before the first event of the
        -- new day fires the daily rollover detection would never
        -- unlink stale files - the operator-facing surprise is
        -- "retention 7 days configured but log/ still has month-old
        -- files". Idempotent, cheap (max 365 io.open probes).
        _retention_sweep( )
        -- Seed the rollover tracker so the FIRST write today does
        -- not trigger a second sweep on top of the boot one.
        _last_seen_date = os_date( "!%Y-%m-%d", os_time( ) )
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd_name, { cmd_p }, { "CT1" }, minlevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_name, onbmsg, minlevel ) )
        if hub.http_register then
            hub.http_register( "GET", "/v1/log/audit", "admin", http_handler_log_audit, {
                plugin = scriptname,
                description = "tail today's audit log (= ADC `+auditlog show`); query ?lines=N (default 200, max 1000)",
                response_schema = {
                    lines       = { type = "array",   required = true },
                    returned    = { type = "integer", required = true },
                    total_lines = { type = "integer", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
