--[[

    etc_records.lua by Motnahp

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
local scriptversion = "0.10"

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
local util_savearray = util.savearray
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
    Topsharer:  %s with %s %s

========================================== RECORDS ===

   ]]

local ucmd_menu = lang.ucmd_menu or { "General", "Hub Records" }
local ucmd_menu_reset = lang.ucmd_menu_reset or { "Hub", "etc", "Hub Records", "reset database" }


----------
--[CODE]--
----------

local start = os_time( )
local records_path = "scripts/data/etc_records.tbl"
local records = util_loadtable( records_path ) or { }  -- load the left ones

-- #465: `records` is a positional 8-slot table. A missing / empty /
-- truncated / corrupt file leaves the numeric max-slots nil, and the
-- onLogin + onTimer max-tracking comparisons (`> tonumber(records[3|6|8])`
-- in hubshare / onliners / topshare) then crash with "attempt to compare
-- nil with number" on EVERY login until the file is restored. `or { }`
-- above only guards a nil TABLE, not nil slots. Seed any absent / non-
-- numeric slot to the same default shape reset() builds, so the plugin
-- degrades gracefully on a missing / corrupt file (DEVELOPMENT.md §5).
-- Existing values are preserved; `tonumber(...) or N` also repairs a slot
-- that somehow persisted as a non-numeric string. The date / time / nick
-- reads are already nil-tolerant downstream (format_recorded_at, `or
-- "none"`) but are defaulted here too so the table is always well-formed.
records[ 1 ] = records[ 1 ] or os_date( "%Y-%m-%d" )  -- share record date
records[ 2 ] = records[ 2 ] or os_date( "%H:%M:%S" )  -- share record time
records[ 3 ] = tonumber( records[ 3 ] ) or 0          -- max total hubshare (bytes); #618 seed 0, not 1
records[ 4 ] = records[ 4 ] or os_date( "%Y-%m-%d" )  -- user-count record date
records[ 5 ] = records[ 5 ] or os_date( "%H:%M:%S" )  -- user-count record time
records[ 6 ] = tonumber( records[ 6 ] ) or 0          -- max online users
records[ 7 ] = records[ 7 ] or "none"                 -- top-share nick
records[ 8 ] = tonumber( records[ 8 ] ) or 0          -- max single-user share (bytes)

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

-- HTTP handler: GET /v1/records (#82 Phase 4 PR-2). Read scope.
-- Returns the current hub records snapshot as structured rows.
-- Raw byte counts are returned (no `shareoptimize` formatting)
-- so the API caller decides display units.
--
-- `records` is an 8-key flat table persisted by the legacy ADC
-- path. The fields are:
--   [1] share_date  [2] share_time  [3] hub_share_bytes
--   [4] users_date  [5] users_time  [6] users_count
--   [7] top_nick    [8] top_share_bytes
-- These are wrapped in named objects on the wire; clients should
-- NOT rely on the array shape (which is a persistence-format
-- detail, not the API contract).
--
-- `recorded_at` strings are `YYYY-MM-DD / HH:MM:SS` (hub local
-- time, matches `cmd_reg`'s persistence format), collapsed to
-- `""` when both halves are missing. On a fresh hub before any
-- sample has been taken all three seed to 0: `hub_share.total_bytes`
-- = 0, `max_users.count` = 0, `top_sharer.share_bytes` = 0
-- (`top_sharer.nick` = "none"). #618 normalised the hub_share seed
-- from a vestigial `1` to `0` so a value of 0 unambiguously means
-- "no record yet"; the `> records[3]` max-tracker in `hubshare()`
-- increments identically from a 0 seed (no real hub totals 1 byte).
--
-- The ADC-side `etc_records_min_level` gate does NOT apply on
-- the HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
local http_handler_get_records = function( req )
    return { status = 200, data = {
        hub_share = {
            total_bytes = tonumber( records[ 3 ] ) or 0,
            recorded_at = format_recorded_at( records[ 1 ], records[ 2 ] ),
        },
        max_users = {
            count       = tonumber( records[ 6 ] ) or 0,
            recorded_at = format_recorded_at( records[ 4 ], records[ 5 ] ),
        },
        top_sharer = {
            nick        = records[ 7 ] or "none",
            share_bytes = tonumber( records[ 8 ] ) or 0,
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
                description = "hub records snapshot (= ADC `+records show`): hub_share, max_users, top_sharer",
                response_schema = {
                    hub_share  = { type = "object", required = true },
                    max_users  = { type = "object", required = true },
                    top_sharer = { type = "object", required = true },
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
        util_savearray( records, records_path )
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

function hubshare( )  -- checks if there is a bigger total hubshare
    local new_hubshare = 0  -- hubshare
    local new_hubshareunit  -- unit of hubshare
    for sid, user in pairs( hub_getusers( ) ) do
        if not user:isbot( ) then
            -- Phase 8a F-INF-1: user:share() is nil for clients that
            -- did not send SS in BINF. Treat missing as zero contribution.
            new_hubshare = new_hubshare + ( user:share( ) or 0 )
        end
    end
    if new_hubshare > tonumber( records[3] ) then
        local old = util_formatbytes( tonumber( records[3] ) )
        local new = util_formatbytes( new_hubshare )
        if new ~= old then
            local share, unit = shareoptimize( new_hubshare )
            bcSharerecord( share, unit )
        end

        --put the new details in--
        records[3] = new_hubshare
        records[2] = os_date( "%H:%M:%S" )
        records[1] = os_date( "%Y-%m-%d" )
        --save and broadcast--
        util_savearray( records, records_path )
        
        --new_hubshare, new_hubshareunit = shareoptimize( new_hubshare )
        --bcSharerecord( new_hubshare, new_hubshareunit )
    end
end

function onliners( )  -- checks if there are more users online then ever
    local onlineusers = 0  -- users online
    for sid, user in pairs( hub_getusers( ) ) do
        if not user:isbot( ) then
            onlineusers = onlineusers + 1
        end
    end
    if onlineusers > tonumber( records[6] ) then
        --put the new details in--
        records[6] = onlineusers
        records[5] = os_date( "%H:%M:%S" )
        records[4] = os_date( "%Y-%m-%d" )
        --save and broadcast--
        util_savearray( records, records_path )
        bcUserrecord( onlineusers )
    end
end

function topshare( user )  -- checks if the target user gots the most share in the hub ( ever )
    local target_nick = user:firstnick( )
    local tbl_nick = records[7]
    -- Phase 8a F-INF-1: user:share() is nil for clients that did not
    -- send SS in BINF. Treat missing as 0 - they cannot win the
    -- top-share record with no declared share, but the listener must
    -- not crash either.
    local target_usershare = user:share( ) or 0
    local target_shareunit  -- targets share unit

    if target_usershare > tonumber( records[8] ) then
        local old = util_formatbytes( tonumber( records[8] ) )
        local new = util_formatbytes( target_usershare )
        if new ~= old then
            local share, unit = shareoptimize( target_usershare )
            bcTopshare( target_nick, share, unit )
        end

        --put the new details in--
        records[7] = target_nick
        records[8] = target_usershare
        --save and broadcast--
        util_savearray( records, records_path )
        
        --target_usershare, target_shareunit = shareoptimize( target_usershare )
        --bcTopshare( target_nick, target_usershare, target_shareunit )
    end
end

function buildrecords( )  -- builds msg for command show
    local rmsg = ""

    -- getting all informations of table --
    --sharestats--
    local s = records[3] or 0  -- total-share-amount (#618: 0 = no record; never fires post-init)
    local share, shareunit = shareoptimize( s )
    local sharedate = records[1] or os_date( "%Y-%m-%d" )  -- date
    local sharetime = records[2] or os_date( "%H:%M:%S" )  -- time
    --userstats--
    local users = records[6] or 0  -- user-amount (never fires post-init)
    local usersdate = records[4] or os_date( "%Y-%m-%d" )  -- date
    local userstime = records[5] or os_date( "%H:%M:%S" )  -- time
    --topuser--
    local topuser = records[7] or "none"  -- nick
    local tus = records[8] or 0  -- share-amount (never fires post-init)
    local topuser_share, topuser_shareunit = shareoptimize( tus )

    local rmsg = utf_format( msg_rmsg,
                       users, usersdate, userstime,
                       share, shareunit, sharedate, sharetime,
                       topuser, topuser_share, topuser_shareunit )

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
    -- new 'init' --
    records = {
        -- sharestats --
        [1] = os_date( "%Y-%m-%d" ),  -- date
        [2] = os_date( "%H:%M:%S" ),  -- time
        [3] = 0,  -- total-share-amount (#618: 0 = no record yet, matches [6]/[8])
        -- userstats --
        [4] = os_date( "%Y-%m-%d" ),  -- date
        [5] = os_date( "%H:%M:%S" ),  -- time
        [6] = 0,  -- user-amount
        -- topuser --
        [7] = "none",  -- nick
        [8] = 0  -- share-amount
    }
    -- fill up with new items --
    hubshare( )
    onliners( )
    util_savearray( records, records_path )
end

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
