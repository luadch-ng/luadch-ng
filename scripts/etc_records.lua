--[[

    etc_records.lua by Motnahp

        v0.11: by Aybo (#647)
            - two new all-time peak records, mirroring the two share-based
              ones: peak hub filecount (sum of SF across users, partner to
              hub_share) and top file-sharer (biggest single-user SF,
              partner to top_sharer). Both are SILENT (endpoint + `+records
              show` + WebUI only, no chat broadcast on a new peak) to avoid
              main-chat noise; the three legacy records keep their
              broadcasts.
            - the record store migrates from the fragile positional 8-slot
              table to a named-key table ({ hub_share={bytes,date,time},
              max_users={count,date,time}, top_sharer={nick,bytes},
              hub_files={count,date,time}, top_file_sharer={nick,count},
              _fmt=2 }).
              load_records() detects the legacy positional format and
              migrates it once, preserving every existing value, so a
              3.1.x operator keeps their records across the 3.1 -> 3.2
              upgrade (etc_records.tbl lives in scripts/data/, upgrade-safe).
              Persistence switched from util.savearray to util.savetable.
            - GET /v1/records gains hub_files {count, recorded_at} and
              top_file_sharer {nick, file_count}; `+records show` gains the
              two matching lines (msg_rmsg template extended, en/de lang).

        v0.9:
            - fix #465: seed the positional records table's slots at load
              so a missing / empty / corrupt etc_records.tbl no longer
              crashes the onLogin + onTimer max-tracking comparisons
              (`> tonumber(records[3|6|8])` -> "compare nil with number"
              on every login). The `or { }` on load only guarded a nil
              table, not nil slots. Degrades gracefully now
              (DEVELOPMENT.md §5); existing values preserved.

        v0.8:
            - HTTP API: GET /v1/records (read), DELETE /v1/records (admin)
              #82 Phase 4 PR-2

        v0.7: by pulsar
            - change date style, old: DD.MM.YY  new: YYYY-MM-DD
        
        v0.6: by pulsar
            - small fix
        
        v0.5: by pulsar
            - changes in hubshare() and topshare() to prevent possible doublepostings  / thx Kaas

        v0.4: by Motnahp
            - added some missing declarations
            - fix help output for owners

        v0.3: by pulsar
            - script is now a part of Luadch
            - export scriptsettings to "cfg/cfg.tbl"
            - add lang feature
            - caching some new table lookups
            - rewriting some code

        v0.2: by Motnahp
            - checks on login and on timer if the user have the biggest share
            - adds cmd reset

        v0.1: by Motnahp
            - checks if hubshare/useramount record was outbid by timer and everytime if a user logs in
            - adds cmd show

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_records"
local scriptversion = "0.11"

local cmd = "records"
local prm1 = "show"
local prm2 = "reset"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_debug = hub.debug
local hub_getbot = hub.getbot( )
local hub_import = hub.import
local hub_getusers = hub.getusers
local util_loadtable = util.loadtable
local util_savetable = util.savetable
local util_formatbytes = util.formatbytes
local utf_match = utf.match
local utf_format = utf.format
local os_date = os.date
local os_time = os.time
local os_difftime = os.difftime
local math_floor = math.floor

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg_get( "language" )
local delay = cfg_get( "etc_records_delay" )
local sendPM = cfg_get( "etc_records_sendPM" )
local sendMain = cfg_get( "etc_records_sendMain" )
local reportlvl = cfg_get( "etc_records_reportlvl" )
local whereto_main = cfg_get( "etc_records_whereto_main" )
local whereto_pm = cfg_get( "etc_records_whereto_pm" )
local min_level = cfg_get( "etc_records_min_level" )
local min_level_reset = cfg_get( "etc_records_min_level_reset" )

--// functions
local shareoptimize
local hubshare
local onliners
local buildrecords
local bcSharerecord
local bcUserrecord
local sendItTo
local reset
local topshare
local bcTopshare
local tryagain

--// msgs
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )

local help_title = "etc_records.lua - Users"  -- regs
local help_titleo = "etc_records.lua - Owners"  -- regs
local help_usage = lang.help_usage or "[+!#]records show"
local help_desc = lang.help_desc or "sends the hub records to user"
local help_usageo = lang.help_usageo or "[+!#]records show|reset"
local help_desco = lang.help_desco or "sends the hub records to user|reset records database"

local help_err = lang.help_err or "You are not allowed to use this command."
local help_err_wrong_id_reg = lang.help_err_wrong_id_reg or "\n\t\t Wrong input, please try it again with: \n\n\t\t %s \n\t\t %s "
local help_err_wrong_id_o = lang.help_err_wrong_id_o or "\n\t\t Wrong input, please try it again with: \n\n\t\t %s \n\t\t %s \n\n\t\t %s \n\t\t %s "

local msg_reseted = lang.msg_reseted or "Hub Records: successfully reset database"
local msg_hmsg = lang.msg_hmsg or "Hub Records: New hub share record: %s %s"
local msg_umsg = lang.msg_umsg or "Hub Records: New user amount record: %s"
local msg_tmsg = lang.msg_tmsg or "Hub Records: User %s has broken the user share record with: %s %s"

local msg_rmsg = lang.msg_rmsg or [[


=== RECORDS ==========================================

    Hub record statistic:

    Max users:  %s User, Date: %s, Time: %s
    Max hub share:  %s %s, Date: %s, Time: %s
    Max hub files:  %s files, Date: %s, Time: %s
    Topsharer:  %s with %s %s
    Top file-sharer:  %s with %s files

========================================== RECORDS ===

   ]]

local ucmd_menu = lang.ucmd_menu or { "General", "Hub Records" }
local ucmd_menu_reset = lang.ucmd_menu_reset or { "Hub", "etc", "Hub Records", "reset database" }


----------
--[CODE]--
----------

local start = os_time( )
local records_path = "scripts/data/etc_records.tbl"

-- v0.11 (#647): the record store is a NAMED-KEY table. The three legacy
-- records keep their meaning; two new silent peaks (hub_files, top_file_sharer)
-- are added. `_fmt = 2` marks the named format so load_records() can tell
-- it apart from the legacy positional 8-slot table and migrate once.
--
--   hub_share       = { bytes, date, time }  -- peak total share (broadcast)
--   max_users       = { count, date, time }  -- peak online humans (broadcast)
--   top_sharer      = { nick, bytes }         -- biggest single share (broadcast)
--   hub_files       = { count, date, time }  -- peak total filecount (silent)
--   top_file_sharer = { nick, count }         -- biggest single filecount (silent)
-- Each store key maps 1:1 to the wire object of the same name in GET
-- /v1/records; the wire field names differ only where the legacy contract
-- already did (top_sharer.bytes -> share_bytes, top_file_sharer.count ->
-- file_count), see http_handler_get_records.
local function default_records( )
    return {
        _fmt            = 2,
        hub_share       = { bytes = 0, date = os_date( "%Y-%m-%d" ), time = os_date( "%H:%M:%S" ) },
        max_users       = { count = 0, date = os_date( "%Y-%m-%d" ), time = os_date( "%H:%M:%S" ) },
        top_sharer      = { nick = "none", bytes = 0 },
        hub_files       = { count = 0, date = os_date( "%Y-%m-%d" ), time = os_date( "%H:%M:%S" ) },
        top_file_sharer = { nick = "none", count = 0 },
    }
end

-- Migrate the legacy positional 8-slot table (v<=0.10) to the named
-- format, PRESERVING every existing value so a 3.1.x operator keeps
-- their records across the 3.1 -> 3.2 upgrade. The legacy layout was:
--   [1] share_date  [2] share_time  [3] hub_share_bytes
--   [4] users_date  [5] users_time  [6] users_count
--   [7] top_nick    [8] top_share_bytes
-- The two new records seed to their default (0 / "none") - no backfill
-- is possible from the old file. `tonumber(...) or 0` also repairs a
-- numeric slot that persisted as a non-numeric string (the #465 case).
local function migrate_positional( old )
    local r = default_records( )
    r.hub_share.date   = old[ 1 ] or r.hub_share.date
    r.hub_share.time   = old[ 2 ] or r.hub_share.time
    r.hub_share.bytes  = tonumber( old[ 3 ] ) or 0
    r.max_users.date   = old[ 4 ] or r.max_users.date
    r.max_users.time   = old[ 5 ] or r.max_users.time
    r.max_users.count  = tonumber( old[ 6 ] ) or 0
    r.top_sharer.nick  = old[ 7 ] or "none"
    r.top_sharer.bytes = tonumber( old[ 8 ] ) or 0
    return r
end

-- Coerce a loaded value to the same shape as its default: a numeric
-- field falls back to its default when missing / non-numeric, a string
-- field when missing / non-string. Keeps a corrupt slot from crashing a
-- later max-comparison (the #465 lesson, generalised to the named store).
local function coerce_like( val, default )
    if type( default ) == "number" then return tonumber( val ) or default end
    if type( default ) == "string" then
        if type( val ) == "string" then return val end
        return default
    end
    return val
end

-- Fill any missing / mistyped key in `t` from `d` (one level of nested
-- tables, which is all the store uses). So a store written by an older
-- named-format version that lacks a newer key gets it seeded.
local function seed_missing( t, d )
    for k, dv in pairs( d ) do
        if type( dv ) == "table" then
            if type( t[ k ] ) ~= "table" then t[ k ] = { } end
            for kk, dvv in pairs( dv ) do
                t[ k ][ kk ] = coerce_like( t[ k ][ kk ], dvv )
            end
        else
            t[ k ] = coerce_like( t[ k ], dv )
        end
    end
end

-- True if `t` carries any legacy positional slot. A named store has no
-- integer keys at all, so probing ALL of 1..8 (not just the numeric
-- max-slots) also catches a pathologically truncated pre-v0.9 file whose
-- only survivor is a date / nick slot - it still migrates rather than
-- silently degrading to fresh defaults with the stray slot left as cruft.
local function looks_positional( t )
    for i = 1, 8 do
        if t[ i ] ~= nil then return true end
    end
    return false
end

-- Load the persisted store defensively: a missing / corrupt file
-- degrades to fresh defaults; a legacy positional file migrates once;
-- a named file gets any absent key seeded. Always returns a well-formed
-- named table so no downstream max-comparison can hit a nil.
local function load_records( )
    local t = util_loadtable( records_path )
    if type( t ) ~= "table" then
        return default_records( )
    end
    if t._fmt == nil and looks_positional( t ) then
        -- legacy positional format: migrate once, preserving values.
        t = migrate_positional( t )
    end
    seed_missing( t, default_records( ) )
    t._fmt = 2
    return t
end

local records = load_records( )

local function save_records( )
    util_savetable( records, scriptname, records_path )
end

local onbmsg = function( user, adccmd, parameters )
    local id = utf_match( parameters, "^(%S+)$" )
    local user_level = user:level( )

    if id == prm1 then  -- show
        if user_level >= min_level then
            if whereto_main then
                user:reply( buildrecords( ), hub_getbot )
            end
            if whereto_pm then
                user:reply( buildrecords( ), hub_getbot, hub_getbot )
            end
        else
            user:reply( help_err, hub_getbot )
        end
        return PROCESSED
    end

    if id == prm2 then  -- reset
        if user_level == min_level_reset then  -- owners only
            sendItTo( reportlvl, msg_reseted )
            reset( )
            audit.fire( audit.build( "records.reset", user, nil, nil, nil ) )
        else
            user:reply( help_err, hub_getbot)
        end
        return PROCESSED
    end

    user:reply( tryagain( user_level ), hub_getbot )  -- if no id hittes
    return PROCESSED
end

-- Join `YYYY-MM-DD` + `HH:MM:SS` into the wire `recorded_at` form,
-- collapsing to `""` when both halves are missing so a never-
-- sampled hub does not surface a stray `" / "` separator.
local format_recorded_at = function( date, time )
    if ( date == nil or date == "" ) and ( time == nil or time == "" ) then
        return ""
    end
    return ( date or "" ) .. " / " .. ( time or "" )
end

-- HTTP handler: GET /v1/records (#82 Phase 4 PR-2, extended #647).
-- Read scope. Returns the current hub records snapshot as named
-- objects. Raw byte / file counts are returned (no `shareoptimize`
-- formatting) so the API caller decides display units.
--
-- `records` is the named store (see default_records above); the wire
-- objects are a stable API contract independent of the persistence
-- shape. `recorded_at` strings are `YYYY-MM-DD / HH:MM:SS` (hub local
-- time), collapsed to `""` when both halves are missing. On a fresh
-- hub before any sample every counter is 0 and every nick is "none"
-- (#618: 0 unambiguously means "no record yet"; the `>` max-trackers
-- increment identically from a 0 seed).
--
-- #647 added hub_files {count, recorded_at} (peak total filecount,
-- partner to hub_share) and top_file_sharer {nick, file_count}
-- (biggest single filecount, partner to top_sharer).
--
-- The ADC-side `etc_records_min_level` gate does NOT apply on
-- the HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
local http_handler_get_records = function( req )
    return { status = 200, data = {
        hub_share = {
            total_bytes = records.hub_share.bytes,
            recorded_at = format_recorded_at( records.hub_share.date, records.hub_share.time ),
        },
        max_users = {
            count       = records.max_users.count,
            recorded_at = format_recorded_at( records.max_users.date, records.max_users.time ),
        },
        top_sharer = {
            nick        = records.top_sharer.nick,
            share_bytes = records.top_sharer.bytes,
        },
        hub_files = {
            count       = records.hub_files.count,
            recorded_at = format_recorded_at( records.hub_files.date, records.hub_files.time ),
        },
        top_file_sharer = {
            nick        = records.top_file_sharer.nick,
            file_count  = records.top_file_sharer.count,
        },
    } }
end

-- HTTP handler: DELETE /v1/records (#82 Phase 4 PR-2). Admin scope.
-- Resets the records to a fresh snapshot (zero counters + today's
-- date/time) and immediately re-samples via `hubshare()` +
-- `onliners()` so a follow-up GET returns the current live state
-- rather than a transient zero. Same code path as ADC `+records
-- reset`. The reset is intentionally not gated by X-Confirm:
-- records are recomputed continuously from live hub state, so
-- the lost data is bounded (just the historical max-share /
-- max-users date stamps) - destructive but recoverable on a
-- timescale of seconds.
--
-- Note on table identity: the legacy `reset()` rebinds the
-- file-local `records = { ... }`. All closures over `records`
-- in this file (helpers + listeners + the GET handler above)
-- capture the SAME upvalue, so they transparently see the new
-- table after reset. The plugin does not `return { records = ... }`
-- so no importer holds a stale reference (mirrors the
-- reference_lua_plugin_exports rebind-safety analysis).
--
-- The ADC-side `etc_records_min_level_reset` gate (typically
-- owner-only) does NOT apply on the HTTP path: the bearer
-- token's `admin` scope IS the authorisation gate.
local http_handler_reset_records = function( req )
    reset()
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "records.reset",
        { nick = actor_label, sid = "<http>" }, nil, nil, nil ) )
    return { status = 200, data = {
        action = "records-reset",
    } }
end

hub.setlistener( "onStart", { },
    function( )
        help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, min_level )  -- reg help
            help.reg( help_titleo, help_usageo, help_desco, min_level_reset)  -- reg help
        end
        ucmd = hub_import( "etc_usercommands" )  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { prm1} , { "CT1" }, min_level )  -- show
            ucmd.add( ucmd_menu_reset, cmd, { prm2 } , { "CT1" }, min_level_reset )  -- reset
        end
        hubcmd = hub_import( "etc_hubcommands" )  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, min_level ) )
        -- HTTP API endpoints (#82 Phase 4 PR-2). Read snapshot +
        -- admin-scoped destructive reset.
        if hub.http_register then
            hub.http_register( "GET", "/v1/records", "read", http_handler_get_records, {
                plugin = scriptname,
                description = "hub records snapshot (= ADC `+records show`): hub_share, max_users, top_sharer, hub_files, top_file_sharer",
                response_schema = {
                    hub_share       = { type = "object", required = true },
                    max_users       = { type = "object", required = true },
                    top_sharer      = { type = "object", required = true },
                    hub_files       = { type = "object", required = true },
                    top_file_sharer = { type = "object", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/records", "admin", http_handler_reset_records, {
                plugin = scriptname,
                description = "reset hub records to zero (= ADC `+records reset`); re-samples live state on success",
                response_schema = {
                    action = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

hub.setlistener( "onLogin", {},
    function( user, nick)
        hubshare( )
        onliners( )
        topshare( user, nick )
    end
)

hub.setlistener( "onTimer", { },
    function( )
        if os_time( ) - start >= delay then
           hubshare( )
           start = os_time( )
        end
        return nil
    end
)

hub.setlistener( "onExit", { },
    function( )
        save_records( )
    end
)

function shareoptimize( share )  -- optimizes the share and shareunit for the output
    local ushare = share
    local uunit = "B"
    if ( ( ushare/1024 ) > 1 ) then
        ushare = ushare / 1024
        uunit = "KB"
        if ( ( ushare/1024 ) > 1 ) then
            ushare = ushare / 1024
            uunit = "MB"
            if ( ( ushare/1024 ) > 1 ) then
                ushare = ushare / 1024
                uunit = "GB"
                if ( ( ushare/1024 ) > 1 ) then
                    ushare = ushare / 1024
                    uunit = "TB"
                    if ( ( ushare/1024 ) > 1 ) then
                        ushare = ushare / 1024
                        uunit = "PB"
                    end
                end
            end
        end
    end
    ushare = math_floor( ( ushare+0.005 ) * 100 ) / 100
    return ushare, uunit
end

function hubshare( )  -- checks for a bigger total hubshare / total filecount
    local new_hubshare = 0  -- summed share (bytes)
    local new_hubfiles = 0  -- summed filecount (SF)
    for sid, user in pairs( hub_getusers( ) ) do
        if not user:isbot( ) then
            -- Phase 8a F-INF-1: user:share() / user:files() are nil for
            -- clients that did not send SS / SF in BINF. Treat missing as
            -- zero contribution.
            new_hubshare = new_hubshare + ( user:share( ) or 0 )
            new_hubfiles = new_hubfiles + ( user:files( ) or 0 )
        end
    end
    local dirty = false
    -- peak total share: broadcast on a new record (legacy behaviour).
    if new_hubshare > records.hub_share.bytes then
        local old = util_formatbytes( records.hub_share.bytes )
        local new = util_formatbytes( new_hubshare )
        if new ~= old then
            local share, unit = shareoptimize( new_hubshare )
            bcSharerecord( share, unit )
        end
        records.hub_share.bytes = new_hubshare
        records.hub_share.time  = os_date( "%H:%M:%S" )
        records.hub_share.date  = os_date( "%Y-%m-%d" )
        dirty = true
    end
    -- #647 peak total filecount: silent (endpoint / show only, no broadcast).
    if new_hubfiles > records.hub_files.count then
        records.hub_files.count = new_hubfiles
        records.hub_files.time  = os_date( "%H:%M:%S" )
        records.hub_files.date  = os_date( "%Y-%m-%d" )
        dirty = true
    end
    if dirty then save_records( ) end  -- one write even if both peaks fire
end

function onliners( )  -- checks if there are more users online then ever
    local onlineusers = 0  -- users online
    for sid, user in pairs( hub_getusers( ) ) do
        if not user:isbot( ) then
            onlineusers = onlineusers + 1
        end
    end
    if onlineusers > records.max_users.count then
        --put the new details in--
        records.max_users.count = onlineusers
        records.max_users.time  = os_date( "%H:%M:%S" )
        records.max_users.date  = os_date( "%Y-%m-%d" )
        --save and broadcast--
        save_records( )
        bcUserrecord( onlineusers )
    end
end

function topshare( user )  -- checks if the target user has the most share / files in the hub ( ever )
    local target_nick = user:firstnick( )
    -- Phase 8a F-INF-1: user:share() / user:files() are nil for clients
    -- that did not send SS / SF in BINF. Treat missing as 0 - they cannot
    -- win a top record with nothing declared, but the listener must not
    -- crash either.
    local target_usershare = user:share( ) or 0
    local target_userfiles = user:files( ) or 0

    local dirty = false
    -- biggest single share: broadcast on a new record (legacy behaviour).
    if target_usershare > records.top_sharer.bytes then
        local old = util_formatbytes( records.top_sharer.bytes )
        local new = util_formatbytes( target_usershare )
        if new ~= old then
            local share, unit = shareoptimize( target_usershare )
            bcTopshare( target_nick, share, unit )
        end
        records.top_sharer.nick  = target_nick
        records.top_sharer.bytes = target_usershare
        dirty = true
    end
    -- #647 biggest single filecount: silent (endpoint / show only).
    if target_userfiles > records.top_file_sharer.count then
        records.top_file_sharer.nick  = target_nick
        records.top_file_sharer.count = target_userfiles
        dirty = true
    end
    if dirty then save_records( ) end  -- one write even if both peaks fire
end

function buildrecords( )  -- builds msg for command show
    -- getting all informations of table --
    --sharestats--
    local share, shareunit = shareoptimize( records.hub_share.bytes )
    local sharedate = records.hub_share.date
    local sharetime = records.hub_share.time
    --userstats--
    local users = records.max_users.count
    local usersdate = records.max_users.date
    local userstime = records.max_users.time
    --filestats (#647)--
    local hubfiles = records.hub_files.count
    local hubfilesdate = records.hub_files.date
    local hubfilestime = records.hub_files.time
    --topuser (share)--
    local topuser = records.top_sharer.nick
    local topuser_share, topuser_shareunit = shareoptimize( records.top_sharer.bytes )
    --topuser (files, #647)--
    local topfiles_nick = records.top_file_sharer.nick
    local topfiles_count = records.top_file_sharer.count

    -- Argument order must match msg_rmsg's %s order (see the lang files):
    -- users(3), share(4), hub files(3), top sharer(3), top file-sharer(2).
    local rmsg = utf_format( msg_rmsg,
                       users, usersdate, userstime,
                       share, shareunit, sharedate, sharetime,
                       hubfiles, hubfilesdate, hubfilestime,
                       topuser, topuser_share, topuser_shareunit,
                       topfiles_nick, topfiles_count )

    return rmsg
end

-- functions to send/broadcast --
function bcSharerecord( share, shareunit )
    local hmsg = utf_format( msg_hmsg, share, shareunit )
    sendItTo( reportlvl, hmsg )
end

function bcUserrecord( users )
    local umsg = utf_format( msg_umsg, users )
    sendItTo( reportlvl, umsg )
end

function bcTopshare( nick, share, shareunit )
    local tmsg = utf_format( msg_tmsg, nick, share, shareunit )
    sendItTo( reportlvl, tmsg )
end

function sendItTo( lvl, msg )  -- send methode depending on lvl and setting main or pm
    for sid, user in pairs( hub_getusers( ) ) do
        local targetuser = user:level( )
        if targetuser >= lvl then
            if sendPM then
                user:reply( msg, hub_getbot, hub_getbot )
            end
            if sendMain then
                user:reply( msg, hub_getbot )
            end
        end
    end
end

tryagain = function( user_level )  -- sends the cmd-using-user the alternativ commands
    local msg = ""
    if user_level >= min_level_reset then  -- for owners
        help_err_wrong_id_o = utf_format( help_err_wrong_id_o, help_usage, help_desc, help_usageo, help_desco )
        msg = help_err_wrong_id_o
    else  -- for regs
        help_err_wrong_id_reg = utf_format( help_err_wrong_id_reg, help_usage, help_desc )
        msg = help_err_wrong_id_reg
    end
    return msg
end

function reset( )
    -- new 'init': rebind `records` to a fresh named store. Every closure
    -- in this file captures `records` as an upvalue, so they all see the
    -- new table after the reset (the GET handler included - the plugin
    -- exports no direct table ref, so no importer holds a stale one).
    records = default_records( )
    -- fill up with live state - hubshare() re-samples share AND filecount,
    -- onliners() the user count. topshare() needs a login user, so the two
    -- top-* records stay "none" until the next login (legacy behaviour).
    hubshare( )
    onliners( )
    save_records( )
end

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
