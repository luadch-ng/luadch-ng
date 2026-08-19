--[[

	cmd_usercleaner.lua by pulsar

        - This script shows and removes no longer used and never used accounts from "cfg/users.tbl"

        usage:

            [+!#]usercleaner showall               -- List of all offline users, sorted by offline time in days (used accounts)
            [+!#]usercleaner showexpired           -- List of all expired offline users, sorted by offline time in days (used accounts)
            [+!#]usercleaner showghosts            -- List of all expired offline users, sorted by reg time in days (unused accounts)
            [+!#]usercleaner delexpired            -- Delete all expired offline users (ghosts excludet, with nick and level protection)
            [+!#]usercleaner delghosts             -- Delete all expired accounts who never been used (with nick protection, but without level protection)
            [+!#]usercleaner addexception <NICK>   -- Add user account to exception list
            [+!#]usercleaner delexception <NICK>   -- Delete user account from exceptions list
            [+!#]usercleaner delexceptionall       -- Delete all user accounts from exceptions list
            [+!#]usercleaner showexceptions        -- Show nick exceptions and level exceptions
            [+!#]usercleaner setdays <DAYS>        -- Change the expired days (default = 365)


        v0.9:
            - carry a nick exception over to the new nick on +nickchange /
              HTTP rename. exception_tbl is keyed by nick; a rename only
              updated user.tbl, so the exception was silently orphaned -
              the renamed account then looked "unused" and could be
              auto-deleted (delghosts / delexpired). An onAudit tap on
              reg.nickchange now re-keys exception_tbl (covers the ADC
              self / othernick / othernicku paths AND the HTTP API).

        v0.8:
            - route the showall / showexpired / showghosts / showexceptions
              status-column "true" / "false" booleans through lang
              (msg_yes / msg_no). Part of #301 i18n cleanup.

        v0.6:
            - HTTP API: GET + DELETE /v1/usercleaner/expired, GET + DELETE
              /v1/usercleaner/ghosts (admin DELETEs require X-Confirm)
              #82 Phase 4 PR-6

        v0.5:
            - remove reg description if it exists (cmd_reg_descriptions.tbl)
            - remove ban if it exists (cmd_ban_bans.tbl)
            - remove block if it exists (etc_trafficmanager.tbl)
               - fix #188 / thx Sopor

        v0.4:
            - show level protection info on ghost users  / requested by Sopor

        v0.3:
            - changed "help_title"
            - changed "msg_exceptions_level"

        v0.2:
            - small optical adjustment

        v0.1:
            - first checkout

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_usercleaner"
local scriptversion = "0.9"

--// command
local cmd = "usercleaner"

--// command parameters
local cmd_p1 = "showall"
local cmd_p2 = "showexpired"
local cmd_p3 = "showghosts"
local cmd_p4 = "delexpired"
local cmd_p5 = "delghosts"
local cmd_p6 = "addexception"
local cmd_p7 = "delexception"
local cmd_p8 = "delexceptionall"
local cmd_p9 = "showexceptions"
local cmd_p10 = "setdays"
local cmd_p11 = "cleancomment"

--// imports
local help, ucmd, hubcmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local report = hub.import( "etc_report" )
local cfg_levels = cfg.get( "levels" )

local report_activate = cfg.get( "cmd_usercleaner_report" )
local report_level = cfg.get( "cmd_usercleaner_report_llevel" )
local report_hubbot = cfg.get( "cmd_usercleaner_report_hubbot" )
local report_opchat = cfg.get( "cmd_usercleaner_report_opchat" )

local exception_file = "scripts/data/cmd_usercleaner_exceptions.tbl"
local settings_file = "scripts/data/cmd_usercleaner_settings.tbl"
local exception_tbl = util.loadtable( exception_file ) or {}
local settings_tbl = util.loadtable( settings_file ) or {}

local activate = cfg.get( "cmd_usercleaner_activate" )
local permission = cfg.get( "cmd_usercleaner_permission" )
local minlevel = util.getlowestlevel( permission )
local expired_days = settings_tbl[ "expired_days" ] or 365
local protected_levels = cfg.get( "cmd_usercleaner_protected_levels" )

local block = hub.import( "etc_trafficmanager" )
local ban = hub.import( "cmd_ban")
local description_file = "scripts/data/cmd_reg_descriptions.tbl"

--// msgs
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]usercleaner showall | showexpired | showghosts | delexpired | delghosts | addexception <NICK> | delexception <NICK> | delexceptionall | showexceptions | setdays <DAYS> | cleancomment"
local msg_nousers = lang.msg_nousers or "[ No users found ]"

local help_title = "cmd_usercleaner.lua"
local help_usage = lang.help_usage or "[+!#]usercleaner showall | showexpired | showghosts | delexpired | delghosts | addexception <NICK> | delexception <NICK> | delexceptionall | showexceptions | setdays <DAYS> | cleancomment"
local help_desc = lang.help_desc or "Shows and removes used and unused offline accounts"

local msg_delreg_expired = lang.msg_delreg_expired or "[ Usercleaner ]--> User:  %s  was delregged because: expired offline time:  %s  days"
local msg_delreg_unused = lang.msg_delreg_unused or "[ Usercleaner ]--> User:  %s  was delregged because: unused since  %s  days"
local msg_delreg_exception = lang.msg_delreg_exception or "[ Usercleaner ]--> The following user is on the exception list and cannot be deleted: "
local msg_delreg_exception_level = lang.msg_delreg_exception_level or "[ Usercleaner ]--> The following user has a protected level and cannot be deleted: %s | protected level: %s"
local msg_orphan_comments_cleaned = lang.msg_orphan_comments_cleaned or "[ Usercleaner ]--> Removed %d orphaned comments (nicks no longer registered)"
local msg_orphan_comments_none = lang.msg_orphan_comments_none or "[ Usercleaner ]--> No orphaned comments found"

local msg_exceptions_add = lang.msg_exceptions_add or "[ Usercleaner ]--> Nick was added to exceptions: "
local msg_exceptions_add_taken = lang.msg_exceptions_add_taken or "[ Usercleaner ]--> Nick has already been added: "
local msg_exceptions_level = lang.msg_exceptions_level or "[ Usercleaner ]--> The following user has already a protected level and cannot be added: %s | protected level: %s"
local msg_exceptions_del = lang.msg_exceptions_del or "[ Usercleaner ]--> Nick was removed from exceptions: "
local msg_exceptions_delall = lang.msg_exceptions_delall or "[ Usercleaner ]--> The exception list was cleared by: "
local msg_exceptions_del_notfound = lang.msg_exceptions_del_notfound or "[ Usercleaner ]--> Nick was not found: "
local msg_exceptions_show = lang.msg_exceptions_show or "[ No exceptions found ]"

local msg_settings_setdays = lang.msg_settings_setdays or "[ Usercleaner ]--> Change the expired days to: "

local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "User", "Control", "Usercleaner", "Show", "Offline accounts (used)" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or { "User", "Control", "Usercleaner", "Show", "Expired offline accounts (used)" }
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or { "User", "Control", "Usercleaner", "Show", "Expired offline accounts (unused)" }
local ucmd_menu_ct1_4 = lang.ucmd_menu_ct1_4 or { "User", "Control", "Usercleaner", "Delete", "Expired offline accounts (used)", "OK" }
local ucmd_menu_ct1_5 = lang.ucmd_menu_ct1_5 or { "User", "Control", "Usercleaner", "Delete", "Expired offline accounts (unused)", "OK" }
local ucmd_menu_ct1_6 = lang.ucmd_menu_ct1_6 or { "User", "Control", "Usercleaner", "Exceptions", "Add user" }
local ucmd_menu_ct1_7 = lang.ucmd_menu_ct1_7 or { "User", "Control", "Usercleaner", "Exceptions", "Del user" }
local ucmd_menu_ct1_8 = lang.ucmd_menu_ct1_8 or { "User", "Control", "Usercleaner", "Exceptions", "Del all users" }
local ucmd_menu_ct1_9 = lang.ucmd_menu_ct1_9 or { "User", "Control", "Usercleaner", "Exceptions", "Show" }
local ucmd_menu_ct1_10 = lang.ucmd_menu_ct1_10 or { "User", "Control", "Usercleaner", "Settings", "Change expiring time in days (default=365)" }
local ucmd_menu_ct1_11 = lang.ucmd_menu_ct1_11 or { "User", "Control", "Usercleaner", "Clean orphaned comments" }

local ucmd_nick = lang.ucmd_nick or "Nickname:"
local ucmd_days = lang.ucmd_days or "Days:"

-- #301 PR-3: status-column booleans routed through lang. The msg_yes /
-- msg_no literals are rendered in the showall / showexpired / showghosts
-- tables; pre-fix they bypassed the lang file entirely.
local msg_yes = lang.msg_yes or "true"
local msg_no  = lang.msg_no  or "false"

local msg_out_all = lang.msg_out_all or [[


=== USERCLEANER ===================================================================================

   [ List of all offline users, sorted by offline time in days ]

               Days offline              Nick protected         Level protected        Nickname
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------

%s
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------
               Days offline              Nick protected         Level protected        Nickname

   [ List of all offline users, sorted by offline time in days ]

=================================================================================== USERCLEANER ===

  ]]

local msg_out_expired = lang.msg_out_expired or [[


=== USERCLEANER ===================================================================================

   [ List of all expired offline users, sorted by offline time in days ]

   Expired time in days:  %s

               Days offline              Nick protected         Level protected        Nickname
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------

%s
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------
               Days offline              Nick protected         Level protected        Nickname

   Expired time in days:  %s

   [ List of all expired offline users, sorted by offline time in days ]

=================================================================================== USERCLEANER ===

  ]]

local msg_out_ghosts = lang.msg_out_ghosts or [[


=== USERCLEANER ===================================================================================

   [ List of all unused expired offline users, sorted by reg time in days ]

   Expired time in days:  %s

                  Days since registration          Nick protected         Level protected        Nickname
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------

%s
        -------------------------------------------------------------------------------------------------------------------------------------------------------------------
                  Days since registration          Nick protected         Level protected        Nickname

   Expired time in days:  %s

   [ List of all unused expired offline users, sorted by reg time in days ]

=================================================================================== USERCLEANER ===

  ]]

local msg_out_exceptions = lang.msg_out_exceptions or [[


=== USERCLEANER ======================================================

   [ List of Nick exceptions ]

                               Nickname
                  -------------------------------------------------------------------------------------------

%s

   [ List of Level exceptions ]

                               Protected                  Level
                  -------------------------------------------------------------------------------------------

%s
====================================================== USERCLEANER ===

  ]]


----------
--[CODE]--
----------

if not activate then
   hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
   return
end

--// check if table key exists
local keyExists = function( tbl, key )
    return tbl[ key ] ~= nil
end

--// check if table is empty
local isEmpty = function( tbl )
    if next( tbl ) == nil then return true else return false end
end

--// sort table by value if key is a string and value is a number
local vPairs = function( tbl, mode )
    local t, i = {}, 0
    for k, v in pairs( tbl ) do t[ #t + 1 ] = k end
    if mode then
        table.sort( t, function( a, b ) return mode( tbl, a, b ) end )
    else
        table.sort( t )
    end
    return function()
        i = i + 1
        if t[ i ] then return t[ i ], tbl[ t[ i ] ] end
    end
end

--// remove register description if exists
local description_del = function( targetnick )
    local description_tbl = util.loadtable( description_file ) or {}
    for k, v in pairs( description_tbl ) do
        if k == targetnick then
            description_tbl[ k ] = nil
            util.savetable( description_tbl, "description_tbl", description_file )
            break
        end
    end
end

--// #311: sweep cmd_reg_descriptions.tbl for entries whose nick is no
--// longer in user.tbl. Historical leftovers from pre-Aug-2022
--// usercleaner runs (before commit f87c861 added per-user
--// description_del) accumulate forever otherwise; a fresh +reg with
--// a recycled old nick then resurrects the stale comment. Called at
--// the end of each delete-batch (delUsers, _classify_and_delete) so
--// every usercleaner run self-heals, and exposed as a standalone
--// +usercleaner cleandesc subcommand for explicit one-shot use.
--// Returns the count removed; non-destructive (only removes entries
--// with no matching reg-user, which by definition are unreachable).
local sweep_orphan_descriptions = function()
    local description_tbl = util.loadtable( description_file ) or {}
    local user_tbl = hub.getregusers()
    local valid_nicks = {}
    for _, u in ipairs( user_tbl ) do
        if u.nick then valid_nicks[ u.nick ] = true end
    end
    --// collect first, then mutate - safer than modifying during iterate.
    local orphans = {}
    for nick in pairs( description_tbl ) do
        if not valid_nicks[ nick ] then orphans[ #orphans + 1 ] = nick end
    end
    if #orphans == 0 then return 0 end
    for _, nick in ipairs( orphans ) do description_tbl[ nick ] = nil end
    util.savetable( description_tbl, "description_tbl", description_file )
    return #orphans
end

--// get time in days
local getTime = function( nTime, sDate )
    if nTime and string.len( tostring( nTime ) ) == 14 then
        local sec, y, d, h, m, s = util.difftime( util.date(), nTime )
        d = d + ( y * 365 )
        return d
    end
    if nTime and string.len( tostring( nTime ) ) ~= 14 then
        local lastconnect = util.convertepochdate( nTime )
        local sec, y, d, h, m, s = util.difftime( util.date(), lastconnect )
        d = d + ( y * 365 )
        return d
    end
    if sDate then --> that will be really ugly but we have to go through that
        local Y, M, D, h, m, s
        if string.find( sDate, "-" ) then --> new style, e.g.: "2017-12-27 / 17:13:01"
            Y = string.sub( sDate,  1,  4 ); M = string.sub( sDate,  6,  7 ); D = string.sub( sDate,  9, 10 )
            h = string.sub( sDate, 14, 15 ); m = string.sub( sDate, 17, 18 ); s = string.sub( sDate, 20, 21 )
        elseif string.len( sDate ) == 21 then --> older style, e.g.: "27.12.2017 / 17:13:01"
            Y = string.sub( sDate,  7, 10 ); M = string.sub( sDate,  4,  5 ); D = string.sub( sDate,  1,  2 )
            h = string.sub( sDate, 14, 15 ); m = string.sub( sDate, 17, 18 ); s = string.sub( sDate, 20, 21 )
        elseif string.len( sDate ) == 10 then --> oldest style, e.g.: "27.12.2017"
            Y = string.sub( sDate,  7, 10 ); M = string.sub( sDate,  4,  5 ); D = string.sub( sDate,  1,  2 )
            h = "00"; m = "00"; s = "00"
        else
            return 0
        end
        local regdate = tonumber( Y .. M .. D .. h .. m .. s )
        local sec, y, d, h, m, s = util.difftime( util.date(), regdate )
        d = d + ( y * 365 )
        return d
    end
    return false
end

local checkUsers = function( all, expired, ghosts, level )
    local users = {}
    local user_tbl = hub.getregusers()
    for i, v in ipairs( user_tbl ) do
        if ( user_tbl[ i ].is_bot ~= 1 ) and ( user_tbl[ i ].is_online ~= 1 ) then
            local reg_date = getTime( false, user_tbl[ i ].date )
            local user_lastseen = getTime( user_tbl[ i ].lastseen, false )
            local user_lastconnect = getTime( user_tbl[ i ].lastconnect, false )

            if all then --> List of all offline users, sorted by offline time in days (ghosts excludet)
                if user_lastseen then users[ user_tbl[ i ].nick ] = user_lastseen end
                if ( not user_lastseen ) and user_lastconnect then users[ user_tbl[ i ].nick ] = user_lastconnect end
            end
            if expired then --> List of all expired offline users, sorted by offline time in days
                if user_lastseen and ( user_lastseen >= expired_days ) then users[ user_tbl[ i ].nick ] = user_lastseen end
                if ( not user_lastseen ) and user_lastconnect and ( user_lastconnect >= expired_days ) then users[ user_tbl[ i ].nick ] = user_lastconnect end
            end
            if ghosts then --> List of all expired offline accounts who never been used, sorted by reg time in days
                if ( not user_lastseen ) and ( not user_lastconnect ) and reg_date and ( reg_date >= expired_days ) then users[ user_tbl[ i ].nick ] = reg_date end
            end
            if level then
                users[ user_tbl[ i ].nick ] = user_tbl[ i ].level
            end
        end
    end
    return users
end

local showUsers = function( all, expired, ghosts )
    local msg = ""
    local tbl_users_level = checkUsers( false, false, false, true )
    if all then --> List of all offline users, sorted by offline time in days (ghosts excludet)
        local tbl_users_all = checkUsers( true, false, false, false )
        for nick, days in vPairs( tbl_users_all, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                msg = msg .. "\t" .. days .. "\t\t" .. msg_yes .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            elseif protected_levels[ tbl_users_level[ nick ] ] then
                msg = msg .. "\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_yes .. "\t\t" .. nick .. "\n"
            else
                msg = msg .. "\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            end
        end
        if msg == "" then msg = "\t" .. msg_nousers .. "\n" end
        return utf.format( msg_out_all, msg )
    end
    if expired then --> List of all expired offline users, sorted by offline time in days
        local tbl_users_expired = checkUsers( false, true, false, false )
        for nick, days in vPairs( tbl_users_expired, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                msg = msg .. "\t" .. days .. "\t\t" .. msg_yes .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            elseif protected_levels[ tbl_users_level[ nick ] ] then
                msg = msg .. "\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_yes .. "\t\t" .. nick .. "\n"
            else
                msg = msg .. "\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            end
        end
        if msg == "" then msg = "\t" .. msg_nousers .. "\n" end
        return utf.format( msg_out_expired, expired_days, msg, expired_days )
    end
    if ghosts then --> List of all expired offline accounts who never been used, sorted by reg time in days
        local tbl_users_ghosts = checkUsers( false, false, true, false )
        for nick, days in vPairs( tbl_users_ghosts, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                msg = msg .. "\t\t" .. days .. "\t\t" .. msg_yes .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            elseif protected_levels[ tbl_users_level[ nick ] ] then
                msg = msg .. "\t\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_yes .. "\t\t" .. nick .. "\n"
            else
                msg = msg .. "\t\t" .. days .. "\t\t" .. msg_no .. "\t\t" .. msg_no .. "\t\t" .. nick .. "\n"
            end
        end
        if msg == "" then msg = "\t" .. msg_nousers .. "\n" end
        return utf.format( msg_out_ghosts, expired_days, msg, expired_days )
    end
    --[[
    if ghosts then --> List of all expired offline accounts who never been used, sorted by reg time in days
        local tbl_users_ghosts = checkUsers( false, false, true, false )
        for nick, days in vPairs( tbl_users_ghosts, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                msg = msg .. "\t\t" .. days .. "\t\t" .. "true" .. "\t\t" .. nick .. "\n"
            else
                msg = msg .. "\t\t" .. days .. "\t\t" .. "false" .. "\t\t" .. nick .. "\n"
            end
        end
        if msg == "" then msg = "\t" .. msg_nousers .. "\n" end
        return utf.format( msg_out_ghosts, expired_days, msg, expired_days )
    end
    ]]
end

-- HTTP API helpers (#82 Phase 4 PR-6).
--
-- The ADC `delUsers` above writes operator-facing chat banners
-- via `user:reply(...)` for every nick it processes, which would
-- make a CT2 right-click `+usercleaner delexpired` against a hub
-- with hundreds of expired regs spam the operator's main chat.
-- The HTTP variants below collect structured rows (a 1-line
-- record per nick describing what happened) and return them all
-- in the response, instead of writing to chat.
--
-- Categories per row: "deleted" (delreg succeeded + cascade
-- cleanups), "skipped:exception" (nick on the protected
-- exceptions table), "skipped:protected_level" (target level in
-- `cmd_usercleaner_protected_levels`; only applies to expired,
-- not ghosts - matches the ADC delUsers asymmetry which skips
-- the level guard on ghosts).
local _classify_and_delete = function( mode )
    -- mode = "expired" or "ghosts"
    local tbl_users_level = checkUsers( false, false, false, true )
    local tbl_users
    -- Per-mode field name aligned with the GET endpoint so the
    -- operator audit trail uses one stable semantic key:
    --   expired -> days_offline   (matches GET /v1/usercleaner/expired)
    --   ghosts  -> days_since_reg (matches GET /v1/usercleaner/ghosts)
    local days_field
    if mode == "expired" then
        tbl_users  = checkUsers( false, true, false, false )
        days_field = "days_offline"
    else
        tbl_users  = checkUsers( false, false, true, false )
        days_field = "days_since_reg"
    end
    local out = {
        deleted                  = {},
        skipped_exception        = {},
        skipped_protected_level  = {},
    }
    for nick, days in vPairs( tbl_users, function( t, a, b ) return t[ b ] < t[ a ] end ) do
        if exception_tbl[ nick ] then
            local row = { nick = nick }
            row[ days_field ] = days
            out.skipped_exception[ #out.skipped_exception + 1 ] = row
        elseif mode == "expired" and protected_levels[ tbl_users_level[ nick ] ] then
            local row = { nick = nick, protected_level = tbl_users_level[ nick ] }
            row[ days_field ] = days
            out.skipped_protected_level[ #out.skipped_protected_level + 1 ] = row
        else
            hub.delreguser( nick )
            description_del( nick )
            if ban then ban.del( nick ) end
            if block then block.del( nick ) end
            local row = { nick = nick }
            row[ days_field ] = days
            out.deleted[ #out.deleted + 1 ] = row
            -- Report to opchat / hubbot (matches ADC delUsers'
            -- report.send call so the operator audit trail is
            -- identical regardless of the trigger surface).
            local msg_template = mode == "expired"
                and msg_delreg_expired or msg_delreg_unused
            report.send( report_activate, report_hubbot, report_opchat,
                         report_level, utf.format( msg_template, nick, days ) )
        end
    end
    --// #311: same orphan sweep as the chat-cmd path; emit count
    --// through opchat report so the HTTP-triggered run leaves the
    --// same audit trail. Field added to `out` for the response body.
    local removed = sweep_orphan_descriptions()
    out.orphan_comments_removed = removed
    if removed > 0 then
        report.send( report_activate, report_hubbot, report_opchat,
                     report_level, utf.format( msg_orphan_comments_cleaned, removed ) )
    end
    return out
end

-- HTTP handler: GET /v1/usercleaner/expired (#82 Phase 4 PR-6).
-- Read scope. Lists offline regged accounts whose `lastseen`
-- (or `lastconnect` fallback) is older than cfg `expired_days`.
-- Each entry includes the per-nick exception + protected-level
-- flags so the operator can preview which rows a subsequent
-- DELETE would skip.
-- #264 PR-B filter/sort spec for /v1/usercleaner/expired.
-- `days_offline` is an integer (range filter via _min/_max);
-- `nick_protected` / `level_protected` are boolean flags.
local _expired_filter_spec = {
    string_fields = {
        nick = function( e ) return e.nick or "" end,
    },
    integer_fields = {
        level        = function( e ) return tonumber( e.level )        or 0 end,
        days_offline = function( e ) return tonumber( e.days_offline ) or 0 end,
    },
    boolean_fields = {
        nick_protected  = function( e ) return e.nick_protected  end,
        level_protected = function( e ) return e.level_protected end,
    },
    sortable_fields = {
        nick         = function( e ) return e.nick                    or "" end,
        level        = function( e ) return tonumber( e.level )        or 0  end,
        days_offline = function( e ) return tonumber( e.days_offline ) or 0  end,
    },
    -- Default sort = days_offline DESC (oldest first) - matches the
    -- existing pre-#264 behaviour from the vPairs reverse-comparator
    -- so the operator's "show me the most expired first" workflow
    -- stays preserved when no explicit ?sort= is supplied.
    default_sort_field      = "days_offline",
    default_sort_descending = true,
}

local http_handler_list_expired = function( req )
    local tbl_users_level    = checkUsers( false, false, false, true )
    local tbl_users_expired  = checkUsers( false, true, false, false )
    local entries = {}
    for nick, days in pairs( tbl_users_expired ) do
        entries[ #entries + 1 ] = {
            nick               = nick,
            days_offline       = days,
            level              = tbl_users_level[ nick ] or 0,
            nick_protected     = exception_tbl[ nick ] and true or false,
            level_protected    = protected_levels[ tbl_users_level[ nick ] ] and true or false,
        }
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _expired_filter_spec, entries
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = {
            expired_days = expired_days,
            entries      = rows,
        },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- HTTP handler: DELETE /v1/usercleaner/expired (#82 Phase 4 PR-6).
-- Admin scope. Router-enforced X-Confirm: yes (§4.6) - bulk
-- delreg is destructive enough that the operator should confirm
-- via header (matches the cmd_delreg `DELETE /v1/registered/
-- {nick}` precedent, scaled up to "everyone past expiry").
--
-- Returns `data: {action: "users-cleaned", mode: "expired",
-- deleted, skipped_exception, skipped_protected_level,
-- expired_days, orphan_comments_removed}` per §7.1.1; the three
-- arrays mirror the categories from the ADC delUsers loop so the
-- operator gets the full audit trail in one response (vs the
-- ADC chat-stream variant that prints one banner per nick - the
-- API folds those into a structured response). #311 added
-- `orphan_comments_removed` to surface the side-effect sweep
-- count (always >= 0, often 0 on routine runs).
local http_handler_delete_expired = function( req )
    local result = _classify_and_delete( "expired" )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "user.cleanup",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { mode = "delexpired",
          deleted = #( result.deleted or {} ),
          orphan_comments_removed = result.orphan_comments_removed or 0 } ) )
    return { status = 200, data = {
        action                   = "users-cleaned",
        mode                     = "expired",
        expired_days             = expired_days,
        deleted                  = result.deleted,
        skipped_exception        = result.skipped_exception,
        skipped_protected_level  = result.skipped_protected_level,
        orphan_comments_removed  = result.orphan_comments_removed or 0,
    } }
end

-- HTTP handler: GET /v1/usercleaner/ghosts (#82 Phase 4 PR-6).
-- Read scope. Lists offline regged accounts that have never
-- logged in (no `lastseen` AND no `lastconnect`) AND whose reg
-- date is older than `expired_days`. The level-protection flag
-- is included for surface symmetry but ghosts are DELETEd
-- regardless of level (matches the ADC delUsers asymmetry -
-- never-used accounts are presumed throwaways).
-- #264 PR-B filter/sort spec for /v1/usercleaner/ghosts. Same shape
-- as expired but the per-mode field is `days_since_reg` instead of
-- `days_offline`.
local _ghosts_filter_spec = {
    string_fields = {
        nick = function( e ) return e.nick or "" end,
    },
    integer_fields = {
        level          = function( e ) return tonumber( e.level )          or 0 end,
        days_since_reg = function( e ) return tonumber( e.days_since_reg ) or 0 end,
    },
    boolean_fields = {
        nick_protected  = function( e ) return e.nick_protected  end,
        level_protected = function( e ) return e.level_protected end,
    },
    sortable_fields = {
        nick           = function( e ) return e.nick                      or "" end,
        level          = function( e ) return tonumber( e.level )          or 0  end,
        days_since_reg = function( e ) return tonumber( e.days_since_reg ) or 0  end,
    },
    default_sort_field      = "days_since_reg",
    default_sort_descending = true,
}

local http_handler_list_ghosts = function( req )
    local tbl_users_level    = checkUsers( false, false, false, true )
    local tbl_users_ghosts   = checkUsers( false, false, true, false )
    local entries = {}
    for nick, days in pairs( tbl_users_ghosts ) do
        entries[ #entries + 1 ] = {
            nick               = nick,
            days_since_reg     = days,
            level              = tbl_users_level[ nick ] or 0,
            nick_protected     = exception_tbl[ nick ] and true or false,
            level_protected    = protected_levels[ tbl_users_level[ nick ] ] and true or false,
        }
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _ghosts_filter_spec, entries
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = {
            expired_days = expired_days,
            entries      = rows,
        },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- HTTP handler: DELETE /v1/usercleaner/ghosts (#82 Phase 4 PR-6).
-- Admin scope. Router-enforced X-Confirm: yes (§4.6). Same
-- shape as the expired DELETE; `skipped_protected_level` is
-- always empty because ghosts ignore the level guard - the
-- field is present for response-shape symmetry. #311 added
-- `orphan_comments_removed` for the same reason it's on the
-- expired variant.
local http_handler_delete_ghosts = function( req )
    local result = _classify_and_delete( "ghosts" )
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    audit.fire( audit.build( "user.cleanup",
        { nick = actor_label, sid = "<http>" }, nil, nil,
        { mode = "delghosts",
          deleted = #( result.deleted or {} ),
          orphan_comments_removed = result.orphan_comments_removed or 0 } ) )
    return { status = 200, data = {
        action                   = "users-cleaned",
        mode                     = "ghosts",
        expired_days             = expired_days,
        deleted                  = result.deleted,
        skipped_exception        = result.skipped_exception,
        skipped_protected_level  = result.skipped_protected_level,
        orphan_comments_removed  = result.orphan_comments_removed or 0,
    } }
end

-- HTTP handler: DELETE /v1/usercleaner/orphan-comments (#311).
-- Admin scope. Router-enforced X-Confirm: yes (§4.6). Sweeps
-- `cmd_reg_descriptions.tbl` for entries whose nick is no longer
-- in user.tbl - historical leftovers from pre-Aug-2022 hub
-- versions whose usercleaner did not call description_del on
-- delete. No-op when the file is clean. Same effect as the ADC
-- chat command `+usercleaner cleancomment`.
local http_handler_clean_orphan_comments = function( req )
    local removed = sweep_orphan_descriptions()
    if removed > 0 then
        local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
        audit.fire( audit.build( "user.cleanup.orphan_comments",
            { nick = actor_label, sid = "<http>" }, nil, nil, { removed = removed } ) )
    end
    return { status = 200, data = {
        action                   = "orphan-comments-cleaned",
        orphan_comments_removed  = removed,
    } }
end

-- Returns (deleted_count, orphan_comments_removed_count) so the
-- caller can include the totals in the audit-event meta. Matches
-- the HTTP twin's response shape (#84 review followup - removes
-- the ADC-vs-HTTP audit asymmetry).
local delUsers = function( expired, ghosts, user )
    local tbl_users_level = checkUsers( false, false, false, true )
    local deleted = 0
    if expired then --> Delete all expired offline users (ghosts excludet)
        local tbl_users_expired = checkUsers( false, true, false )
        for nick, days in vPairs( tbl_users_expired, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                user:reply( msg_delreg_exception .. nick, hub.getbot() )
            elseif protected_levels[ tbl_users_level[ nick ] ] then
                user:reply( utf.format( msg_delreg_exception_level, nick, tbl_users_level[ nick ] ), hub.getbot() )
            else
                hub.delreguser( nick ) -- delreg user
                description_del( nick ) -- remove reg description if it exists (cmd_reg_descriptions.tbl)
                if ban then ban.del( nick ) end -- remove ban if it exists (cmd_ban_bans.tbl)
                if block then block.del( nick ) end -- remove block if it exists (etc_trafficmanager.tbl)
                user:reply( utf.format( msg_delreg_expired, nick, days ), hub.getbot() )
                report.send( report_activate, report_hubbot, report_opchat, report_level, utf.format( msg_delreg_expired, nick, days ) )
                deleted = deleted + 1
            end
        end
    end
    if ghosts then --> Delete all expired offline users, never been used
        local tbl_users_ghosts = checkUsers( false, false, true, false )
        for nick, days in vPairs( tbl_users_ghosts, function( t, a, b ) return t[ b ] < t[ a ] end ) do
            if exception_tbl[ nick ] then
                user:reply( msg_delreg_exception .. nick, hub.getbot() )
            else
                hub.delreguser( nick ) -- delreg user
                description_del( nick ) -- remove reg description if it exists (cmd_reg_descriptions.tbl)
                if ban then ban.del( nick ) end -- remove ban if it exists (cmd_ban_bans.tbl)
                if block then block.del( nick ) end -- remove block if it exists (etc_trafficmanager.tbl)
                user:reply( utf.format( msg_delreg_unused, nick, days ), hub.getbot() )
                report.send( report_activate, report_hubbot, report_opchat, report_level, utf.format( msg_delreg_unused, nick, days ) )
                deleted = deleted + 1
            end
        end
    end
    --// #311: after each delete-batch, sweep historical orphans whose
    --// user.tbl entry was removed in a prior session before
    --// description_del was wired up. Silent when nothing to clean.
    local removed = sweep_orphan_descriptions()
    if removed > 0 then
        local msg = utf.format( msg_orphan_comments_cleaned, removed )
        user:reply( msg, hub.getbot() )
        report.send( report_activate, report_hubbot, report_opchat, report_level, msg )
    end
    return deleted, removed
end

local userExceptions = function( add, del, delall, show, user, nick )
    if add then --> addexception
        local tbl_users_level = checkUsers( false, false, false, true )
        if keyExists( exception_tbl, nick ) then
            user:reply( msg_exceptions_add_taken .. nick, hub.getbot() )
        elseif protected_levels[ tbl_users_level[ nick ] ] then
            user:reply( utf.format( msg_exceptions_level, nick, tbl_users_level[ nick ] ), hub.getbot() )
        else
            exception_tbl[ nick ] = user:firstnick()
            util.savetable( exception_tbl, "exception_tbl", exception_file )
            user:reply( msg_exceptions_add .. nick, hub.getbot() )
        end
    end
    if del then --> delexception
        if keyExists( exception_tbl, nick ) then
            exception_tbl[ nick ] = nil
            util.savetable( exception_tbl, "exception_tbl", exception_file )
            user:reply( msg_exceptions_del .. nick, hub.getbot() )
        else
            user:reply( msg_exceptions_del_notfound .. nick, hub.getbot() )
        end
    end
    if delall then --> delexceptionall
        exception_tbl = {}
        util.savetable( exception_tbl, "exception_tbl", exception_file )
        user:reply( msg_exceptions_delall .. user:nick(), hub.getbot() )
    end
    if show then --> showexceptions
        local msg_exc, msg_lvl, l = "", "", 0
        if isEmpty( exception_tbl ) then
            msg_exc = "\t\t" .. msg_exceptions_show .. "\n"
        else
            for k, v in util.spairs( exception_tbl ) do
                msg_exc = msg_exc .. "\t\t" .. k .. "\n"
            end
        end
        for i = 1, 100, 1 do
            if keyExists( protected_levels, i ) then
                if protected_levels[ i ] then l = msg_yes else l = msg_no end
                msg_lvl = msg_lvl .. "\t\t" .. l .. "\t\t" .. i .. "  [ " .. cfg_levels[ i ] .. " ]" .. "\n"
            end
        end
        user:reply( utf.format( msg_out_exceptions, msg_exc, msg_lvl ), hub.getbot(), hub.getbot() )
    end
end

local changeSettings = function( days, user )
    if days then --> setdays
        expired_days = tonumber( days )
        settings_tbl[ "expired_days" ] = expired_days
        util.savetable( settings_tbl, "settings_tbl", settings_file )
        user:reply( msg_settings_setdays .. expired_days, hub.getbot() )
    end
end

local onbmsg = function( user, command, parameters )
    if not permission[ user:level() ] then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end

    local param = utf.match( parameters, "^(%S+)" )
    local nick = utf.match( parameters, "^%S+ (%S+)" )
    local days = utf.match( parameters, "^%S+ (%d+)" )

    if ( param == cmd_p1 ) then --> showall
        user:reply( showUsers( true, false, false ), hub.getbot(), hub.getbot() )
        return PROCESSED
    end
    if ( param == cmd_p2 ) then --> showexpired
        user:reply( showUsers( false, true, false ), hub.getbot(), hub.getbot() )
        return PROCESSED
    end
    if ( param == cmd_p3 ) then --> showghosts
        user:reply( showUsers( false, false, true ), hub.getbot(), hub.getbot() )
        return PROCESSED
    end
    if ( param == cmd_p4 ) then --> delexpired
        local _deleted, _orphans = delUsers( true, false, user )
        audit.fire( audit.build( "user.cleanup", user, nil, nil,
            { mode = "delexpired",
              deleted = _deleted,
              orphan_comments_removed = _orphans } ) )
        return PROCESSED
    end
    if ( param == cmd_p5 ) then --> delghosts
        local _deleted, _orphans = delUsers( false, true, user )
        audit.fire( audit.build( "user.cleanup", user, nil, nil,
            { mode = "delghosts",
              deleted = _deleted,
              orphan_comments_removed = _orphans } ) )
        return PROCESSED
    end
    if ( param == cmd_p6 ) and nick then --> addexception
        userExceptions( true, false, false, false, user, nick )
        audit.fire( audit.build( "user.cleanup.exception.add", user,
            { nick = nick }, nil, nil ) )
        return PROCESSED
    end
    if ( param == cmd_p7 ) and nick then --> delexception
        userExceptions( false, true, false, false, user, nick )
        audit.fire( audit.build( "user.cleanup.exception.remove", user,
            { nick = nick }, nil, nil ) )
        return PROCESSED
    end
    if ( param == cmd_p8 ) then --> delexceptionall
        userExceptions( false, false, true, false, user, false )
        audit.fire( audit.build( "user.cleanup.exception.clear", user, nil, nil, nil ) )
        return PROCESSED
    end
    if ( param == cmd_p9 ) then --> showexceptions
        userExceptions( false, false, false, true, user, false )
        return PROCESSED
    end
    if ( param == cmd_p10 ) and days then --> setdays
        changeSettings( days, user )
        audit.fire( audit.build( "user.cleanup.setdays", user, nil, nil,
            { days = tonumber( days ) } ) )
        return PROCESSED
    end
    if ( param == cmd_p11 ) then --> cleancomment (#311: explicit one-shot orphan sweep)
        local removed = sweep_orphan_descriptions()
        if removed > 0 then
            local msg = utf.format( msg_orphan_comments_cleaned, removed )
            user:reply( msg, hub.getbot() )
            report.send( report_activate, report_hubbot, report_opchat, report_level, msg )
            audit.fire( audit.build( "user.cleanup.orphan_comments", user, nil, nil,
                { removed = removed } ) )
        else
            user:reply( msg_orphan_comments_none, hub.getbot() )
        end
        return PROCESSED
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

--// keep a nick exception attached to its user across a rename.
-- exception_tbl is keyed by nick; +nickchange (and the HTTP rename)
-- renames the user in user.tbl but not here, so without this the
-- protection was silently orphaned on rename - the renamed account
-- then looked "unused" and could be auto-deleted (delghosts /
-- delexpired). audit.fire is unconditional (core/audit.lua), so one
-- onAudit tap catches every reg.nickchange - the ADC self / othernick
-- / othernicku paths AND the HTTP API. Returns nil (never PROCESSED)
-- so the etc_auditlog / http_events onAudit taps still receive it.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        if old_nick == new_nick or exception_tbl[ old_nick ] == nil then return nil end
        -- If a stale entry already sits under the new nick, the renamed
        -- user's own exception wins - overwrite keeps it intact.
        exception_tbl[ new_nick ] = exception_tbl[ old_nick ]
        exception_tbl[ old_nick ] = nil
        util.savetable( exception_tbl, "exception_tbl", exception_file )
        return nil
    end
)

hub.setlistener( "onStart", {},
    function()
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct1_1, cmd, { cmd_p1 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_2, cmd, { cmd_p2 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_3, cmd, { cmd_p3 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_4, cmd, { cmd_p4 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_5, cmd, { cmd_p5 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_6, cmd, { cmd_p6, "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_7, cmd, { cmd_p7, "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_8, cmd, { cmd_p8 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_9, cmd, { cmd_p9 }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_10, cmd, { cmd_p10, "%[line:" .. ucmd_days .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu_ct1_11, cmd, { cmd_p11 }, { "CT1" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( { cmd }, onbmsg, minlevel ) )
        -- HTTP API endpoints (#82 Phase 4 PR-6). Only registered
        -- when the plugin is `activate=true` (early-return at top
        -- of file already short-circuits the entire module otherwise).
        if hub.http_register then
            hub.http_register( "GET", "/v1/usercleaner/expired", "read", http_handler_list_expired, {
                plugin = scriptname,
                description = "list offline regs older than cfg expired_days (= ADC `+usercleaner showexpired`)",
                response_schema = {
                    expired_days = { type = "integer", required = true },
                    entries      = { type = "array",   required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/usercleaner/expired", "admin", http_handler_delete_expired, {
                plugin = scriptname,
                description = "delreg all expired offline regs (= ADC `+usercleaner delexpired`); requires X-Confirm",
                response_schema = {
                    action                   = { type = "string",  required = true },
                    mode                     = { type = "string",  required = true },
                    expired_days             = { type = "integer", required = true },
                    deleted                  = { type = "array",   required = true },
                    skipped_exception        = { type = "array",   required = true },
                    skipped_protected_level  = { type = "array",   required = true },
                    orphan_comments_removed  = { type = "integer", required = true },
                },
            } )
            hub.http_register( "GET", "/v1/usercleaner/ghosts", "read", http_handler_list_ghosts, {
                plugin = scriptname,
                description = "list ghost regs (never logged in + reg date older than expired_days; = ADC `+usercleaner showghosts`)",
                response_schema = {
                    expired_days = { type = "integer", required = true },
                    entries      = { type = "array",   required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/usercleaner/ghosts", "admin", http_handler_delete_ghosts, {
                plugin = scriptname,
                description = "delreg all ghost regs (= ADC `+usercleaner delghosts`); requires X-Confirm",
                response_schema = {
                    action                   = { type = "string",  required = true },
                    mode                     = { type = "string",  required = true },
                    expired_days             = { type = "integer", required = true },
                    deleted                  = { type = "array",   required = true },
                    skipped_exception        = { type = "array",   required = true },
                    skipped_protected_level  = { type = "array",   required = true },
                    orphan_comments_removed  = { type = "integer", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/usercleaner/orphan-comments", "admin", http_handler_clean_orphan_comments, {
                plugin = scriptname,
                description = "sweep orphan comments in cmd_reg_descriptions.tbl whose nick is no longer registered (= ADC `+usercleaner cleancomment`); requires X-Confirm",
                response_schema = {
                    action                   = { type = "string",  required = true },
                    orphan_comments_removed  = { type = "integer", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )