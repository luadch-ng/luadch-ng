--[[

    etc_backup.lua - automatic encrypted hub backups (#480, PR-A)

    The thin scheduler / CLI / owner-nag layer on top of the core engine
    (core/backup.lua, exposed as the sandbox global `backup`). This plugin
    owns WHEN a backup runs and HOW the operator is told about it; the engine
    owns the actual collect -> seal -> write -> rotate work and reads its own
    policy (dir / keep / passphrase / include_master_key) straight from cfg +
    core/secrets. See docs/BACKUP.md.

    Schedule (persisted across +reload in scripts/data/etc_backup.tbl):
      - etc_backup_daily_at "HH:MM" (server-local) is the primary mode.
      - etc_backup_interval_hours > 0 is the fallback when daily_at is empty.
    Commands (level etc_backup_oplevel, default 80):
      +backup now | list | status
    Owner nag (level etc_backup_notify_level, default 100): when the feature
    is enabled but not ready (no passphrase / backup dir not writable /
    master.key unreadable), the hubbot PMs the owner on start + on login,
    enumerating exactly what is missing.

    License: GPLv3

]]--

local scriptname    = "etc_backup"
local scriptversion = "0.01"

--// sandbox globals //--
local cfg     = cfg
local hub     = hub
local backup  = backup
local audit   = audit
local secrets = secrets
local util    = util
local type     = type
local tonumber = tonumber
local tostring = tostring
local pairs    = pairs
local ipairs   = ipairs
local table_concat = table.concat
local os_time = os.time
local os_date = os.date
local io_open = io.open
local PROCESSED = PROCESSED

local hub_debug      = hub.debug
local hub_getbot     = hub.getbot
local hub_getusers   = hub.getusers
local hub_setlistener = hub.setlistener
local hub_import     = hub.import

--// i18n //--
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname )
lang = lang or { }
if lang_err then hub_debug( lang_err ) end

local msg_denied    = lang.msg_denied    or "You are not allowed to use this command."
local msg_usage     = lang.msg_usage     or "Usage: +backup now|list|status"
local msg_now_ok    = lang.msg_now_ok    or "Backup written: "
local msg_now_fail  = lang.msg_now_fail  or "Backup failed: "
local msg_list_head = lang.msg_list_head or "Backups in "
local msg_list_none = lang.msg_list_none or "  (none yet)"
local msg_bytes     = lang.msg_bytes     or " bytes"
local msg_files     = lang.msg_files     or " files"
local msg_st_enabled  = lang.msg_st_enabled  or "enabled: "
local msg_st_schedule = lang.msg_st_schedule or "schedule: "
local msg_st_daily    = lang.msg_st_daily    or "daily at "
local msg_st_every    = lang.msg_st_every    or "every "
local msg_st_none     = lang.msg_st_none     or "none"
local msg_st_next     = lang.msg_st_next     or "next: "
local msg_st_last     = lang.msg_st_last     or "last: "
local msg_st_ready    = lang.msg_st_ready    or "ready: "
local msg_st_yes      = lang.msg_st_yes      or "yes"
local msg_st_no       = lang.msg_st_no       or "no"
local msg_nag_head    = lang.msg_nag_head    or "Backup is ENABLED but not fully configured:"
local msg_iss_pass    = lang.msg_iss_pass    or "  - no passphrase set (etc_backup_passphrase / env LUADCH_ETC_BACKUP_PASSPHRASE)"
local msg_iss_dir     = lang.msg_iss_dir     or "  - the backup directory is not writable (etc_backup_dir)"
local msg_iss_mk      = lang.msg_iss_mk      or "  - master.key is not readable (etc_backup_include_master_key)"

local help_title = "etc_backup.lua - backup"
local help_usage = lang.help_usage or "+backup now|list|status"
local help_desc  = lang.help_desc  or "Automatic encrypted backups: run one now, list artifacts, show status."
local ucmd_now    = lang.ucmd_now    or { "Backup", "Run now" }
local ucmd_list   = lang.ucmd_list   or { "Backup", "List" }
local ucmd_status = lang.ucmd_status or { "Backup", "Status" }

--// constants + runtime state //--
local cmd_main   = "backup"
local STATE_FILE = "scripts/data/etc_backup.tbl"

local enabled, daily_at, interval_sec, notify_level, oplevel
local last_backup_at, next_backup_at
local in_flight = false

local passphrase_key = "etc_backup_passphrase"

----------------------------------// SCHEDULE (pure helpers) //--

-- Next occurrence of a server-local HH:MM strictly after `now`, or nil if
-- the string is not a valid HH:MM (caller falls back to the interval).
local function _next_daily( now, hhmm )
    if type( hhmm ) ~= "string" then return nil end
    local h, m = hhmm:match( "^(%d%d?):(%d%d)$" )
    h, m = tonumber( h ), tonumber( m )
    if not h or not m or h < 0 or h > 23 or m < 0 or m > 59 then return nil end
    local t = os_date( "*t", now )
    local cand = os_time{ year = t.year, month = t.month, day = t.day, hour = h, min = m, sec = 0 }
    -- A spring-forward-gap HH:MM makes os.time return nil; the caller then
    -- falls back to the interval. Accepted (once-a-year, narrow).
    if not cand then return nil end
    -- Flat +24h: across a DST change the slot is 1h off for that one day and
    -- self-corrects on the next recompute. Accepted for a backup schedule.
    if cand <= now then cand = cand + 86400 end   -- today's slot passed -> tomorrow
    return cand
end

-- The next scheduled time after `now`. daily_at wins; else interval from
-- `anchor` (last run at start, `now` after a run). Overdue interval fires
-- this tick (n = now) instead of hammering. nil = no schedule configured.
local function _compute_next( now, anchor, daily, ivl )
    if daily and daily ~= "" then
        local n = _next_daily( now, daily )
        if n then return n end
    end
    if ivl and ivl > 0 then
        local n = ( anchor or now ) + ivl
        if n <= now then n = now end
        return n
    end
    return nil
end

local function _schedule_next( now, anchor )
    return _compute_next( now, anchor, daily_at, interval_sec )
end

----------------------------------// STATE PERSISTENCE //--

local function load_state( )
    local f = io_open( STATE_FILE, "r" )   -- peek so loadtable doesn't log "no such file"
    if not f then return end
    f:close( )
    local st = util.loadtable( STATE_FILE )
    if type( st ) == "table" then
        last_backup_at = tonumber( st.last_backup_at )
        next_backup_at = tonumber( st.next_backup_at )
    end
end

local function persist_state( )
    util.savetable( { last_backup_at = last_backup_at, next_backup_at = next_backup_at },
        "etc_backup_state", STATE_FILE )
end

----------------------------------// OWNER NAG //--

local function build_nag( issues )
    local lines = { msg_nag_head }
    for _, code in ipairs( issues ) do
        if code == "no_passphrase" then lines[ #lines + 1 ] = msg_iss_pass
        elseif code == "backup_dir_unwritable" then lines[ #lines + 1 ] = msg_iss_dir
        elseif code == "master_key_unreadable" then lines[ #lines + 1 ] = msg_iss_mk
        else lines[ #lines + 1 ] = "  - " .. code end
    end
    return table_concat( lines, "\n" )
end

-- PM the readiness checklist. `target` = one user (on login) or nil = every
-- online user at/above notify_level (on start / after a failed run).
local function notify_if_unready( target )
    if not enabled then return end
    local r = backup.readiness( )
    if r.ok then return end
    local msg = build_nag( r.issues )
    local bot = hub_getbot( )
    if target then
        target:reply( msg, bot, bot )   -- 3-arg = private DMSG
    else
        for _, user in pairs( hub_getusers( ) ) do   -- first table = humans only
            if not user:isbot( ) and user:level( ) >= notify_level then
                user:reply( msg, bot, bot )
            end
        end
    end
end

----------------------------------// BACKUP DRIVER //--

-- Run one backup, audit the outcome, update last_backup_at on success. Does
-- NOT recompute next / persist - the caller (timer or +backup now) does.
local function do_backup( trigger, actor )
    local res, err = backup.run( )
    if res then
        last_backup_at = os_time( )
        audit.fire( audit.build( "backup.success", actor, nil, nil, {
            path = res.path, bytes = res.bytes, files = res.files, trigger = trigger } ) )
        return res
    end
    audit.fire( audit.build( "backup.fail", actor, nil, err, { trigger = trigger } ) )
    notify_if_unready( nil )   -- a config-class failure is explained to owners
    return nil, err
end

----------------------------------// COMMAND: +backup //--

local function cmd_now( user )
    local res, err = do_backup( "manual", user )
    local now = os_time( )
    next_backup_at = _schedule_next( now, now )
    persist_state( )
    if res then
        user:reply( msg_now_ok .. res.path .. " (" .. tostring( res.bytes ) .. msg_bytes
            .. ", " .. tostring( res.files ) .. msg_files .. ")", hub_getbot( ) )
    else
        user:reply( msg_now_fail .. tostring( err ), hub_getbot( ) )
    end
end

local function cmd_list( user )
    local rows = backup.list( )
    local dir = cfg.get( "etc_backup_dir" ) or "cfg/backups"
    local lines = { msg_list_head .. dir .. ":" }
    if not rows or #rows == 0 then
        lines[ #lines + 1 ] = msg_list_none
    else
        for _, r in ipairs( rows ) do
            lines[ #lines + 1 ] = "  " .. r.name .. "  (" .. tostring( r.bytes or "?" ) .. msg_bytes .. ")"
        end
    end
    user:reply( table_concat( lines, "\n" ), hub_getbot( ) )
end

local function cmd_status( user )
    local r = backup.readiness( )
    local sched
    if daily_at and daily_at ~= "" then sched = msg_st_daily .. daily_at
    elseif interval_sec and interval_sec > 0 then sched = msg_st_every .. tostring( interval_sec // 3600 ) .. "h"
    else sched = msg_st_none end
    local ready = r.ok and msg_st_yes or ( msg_st_no .. " (" .. table_concat( r.issues, ", " ) .. ")" )
    local parts = {
        msg_st_enabled  .. tostring( enabled ),
        msg_st_schedule .. sched,
        msg_st_next     .. ( next_backup_at and os_date( "%Y-%m-%d %H:%M", next_backup_at ) or "-" ),
        msg_st_last     .. ( last_backup_at and os_date( "%Y-%m-%d %H:%M", last_backup_at ) or "-" ),
        msg_st_ready    .. ready,
    }
    user:reply( table_concat( parts, "\n" ), hub_getbot( ) )
end

local function on_backup( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    local sub = parameters and parameters:match( "^%s*(%S+)" )
    if sub == "now" then cmd_now( user )
    elseif sub == "list" then cmd_list( user )
    elseif sub == "status" then cmd_status( user )
    else user:reply( msg_usage, hub_getbot( ) ) end
    return PROCESSED
end

----------------------------------// LISTENERS //--

hub_setlistener( "onStart", { },
    function( )
        in_flight = false

        enabled = cfg.get( "etc_backup_enabled" )
        if enabled == nil then enabled = true end
        daily_at = cfg.get( "etc_backup_daily_at" ) or ""
        interval_sec = ( tonumber( cfg.get( "etc_backup_interval_hours" ) ) or 0 ) * 3600
        notify_level = tonumber( cfg.get( "etc_backup_notify_level" ) ) or 100
        oplevel      = tonumber( cfg.get( "etc_backup_oplevel" ) ) or 80

        -- Register the passphrase key as a secret whenever loaded, so a
        -- value in cfg.tbl is redacted from /v1/config even while inactive.
        if secrets and secrets.register then secrets.register( passphrase_key ) end

        load_state( )
        local now = os_time( )
        -- Honor the persisted deadline across +reload / restart so an interval
        -- countdown is not reset on every boot (the #386/#414 anti-pattern)
        -- and a slot missed while the hub was down still fires on boot. Only
        -- recompute when there is no persisted deadline (first run).
        if enabled then
            next_backup_at = next_backup_at or _schedule_next( now, last_backup_at )
        else
            next_backup_at = nil
        end

        -- command trio (help / right-click menu / +cmd dispatcher)
        local help = hub_import( "cmd_help" )
        if help then help.reg( help_title, help_usage, help_desc, oplevel ) end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_now,    cmd_main .. " now",    { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_list,   cmd_main .. " list",   { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_status, cmd_main .. " status", { }, { "CT1" }, oplevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )
        if hubcmd then hubcmd.add( cmd_main, on_backup, oplevel ) end

        notify_if_unready( nil )   -- nag owners already online (e.g. after +reload)
        return nil
    end
)

hub_setlistener( "onTimer", { },
    function( )
        if not enabled then return nil end
        if in_flight then return nil end
        if not next_backup_at then return nil end
        local now = os_time( )
        if now >= next_backup_at then
            in_flight = true
            -- Guard the run: a raise deep inside (audit / reply) must not
            -- wedge the scheduler with in_flight stuck true and next_backup_at
            -- past-due, which would silently stop all future backups until a
            -- +reload. next_backup_at is always advanced afterwards.
            pcall( do_backup, "scheduled", nil )
            next_backup_at = _schedule_next( now, now )
            persist_state( )
            in_flight = false
        end
        return nil
    end
)

hub_setlistener( "onLogin", { },
    function( user )
        if not enabled then return nil end
        if user:isbot( ) then return nil end
        if user:level( ) >= notify_level then
            notify_if_unready( user )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- test seams (pure schedule math)
return {
    _next_daily   = _next_daily,
    _compute_next = _compute_next,
}
