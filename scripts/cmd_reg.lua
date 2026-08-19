--[[

    cmd_reg.lua by blastbeat

        - usage: [+!#]reg nick <NICK> <LEVEL> [<COMMENT>] / [+!#]reg desc <NICK> <COMMENT> (an empty comment removes an existing comment)

        - this script adds a command "reg" to reg users
        - note: be careful when using the nick prefix script: you should reg user nicks always WITHOUT prefix

        v0.36: by Aybo
            - doc (#612): the GET /v1/registered `lastseen` filter is a
              packed-decimal YYYYMMDDHHMMSS integer (hub local time), not
              epoch. Corrected the filter-spec comment and the bad-input
              error string ("expected packed YYYYMMDDHHMMSS integer"). No
              behaviour change - the value was always the packed form.

        v0.35:
            - audit_redact_body = true on POST /v1/registered so the
              optional `password` body field does not land verbatim in
              api_audit.log. Body field logs as `[redacted]` for this
              route; the response still echoes nick/level/outcome.

        v0.34: by Aybo
            - HTTP API (#82 #264 PR-A): filter+sort spec on
              GET /v1/registered.

        v0.33:
            - HTTP API (#82 registered-users family PR-1, #236):
                - GET    /v1/registered           (read,  paginated; humans only)
                - POST   /v1/registered           (admin; = ADC `+reg nick`)
                - PATCH  /v1/registered/{nick}    (admin; = ADC `+reg desc`)
            - Coexist with ADC `+reg`; ADC path unchanged.

        v0.32: by pulsar
            - refresh "cfg/user.tbl.bak" if a new user gets regged

        v0.31: by pulsar
            - added "hub_email" to output msg
                - request by Sopor / fix #185 -> https://github.com/luadch/luadch/issues/185
            - added "msg_unknown"

        v0.30: by pulsar
            - fix typo  / thx Sopor
            - changed visuals / fix #174 -> https://github.com/luadch/luadch/issues/174

        v0.29: by pulsar
            - script adapted to the global style
            - remove UTF8 BOM from script/langfiles
            - added tcp_ports_ipv6, ssl_ports_ipv6

        v0.28: by pulsar
            - changed visuals
            - removed table lookups

        v0.27: by pulsar
            - fix #47 -> https://github.com/luadch/luadch/issues/47
                - show comment from the registered user as default if exists

        v0.26: by pulsar
            - fix #83 -> https://github.com/luadch/luadch/issues/83
            - the script now sends the registration information to the user

        v0.25: by HypoManiac
            - fixed so comment can not be set on user of same or higher level
            - fixed so comment can not be set on unknown user

        v0.24: by pulsar
            - added min_length/max_length restrictions

        v0.23: by pulsar
            - usage/help msg improvement  / thx Sopor
            - small improvements with output msg  / thx Sopor

        v0.22: by pulsar
            - some typo fixes  / thx Sopor
            - removed send_report() function, using report import functionality now
            - added comment feature to add/change a comment to existing regusers

        v0.21: by pulsar
            - added possibility to add a description  / request by DerWahre

        v0.20: by pulsar
            - removed "cmd_reg_minlevel" import
                - using util.getlowestlevel( tbl ) instead of "cmd_ban_minlevel"

        v0.19: by pulsar
            - check if opchat is activated

        v0.18: by pulsar
            - using "user:firstnick()" for "registered by" for "user.tbl"
            - add "deleted by" info to blacklist msg
            - fix CT2 RC doublereg bug if hub uses nicktags  / thx Motnahp

        v0.17: by pulsar
            - added some new table lookups
            - added possibility to send report as feed to opchat

        v0.16: by pulsar
            - now using auto generated passwords for regs
            - add some new table lookups and clean some parts of code

        v0.15: by pulsar
            - added levelname to output message

        v0.14: by pulsar
            - changed visual output style

        v0.13: by pulsar
            - show sorted levelnames in rightclick

        v0.12: by pulsar
            - changed rightclick style

        v0.11: by pulsar
            - changed database path and filename
            - from now on all scripts uses the same database folder

        v0.10: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.09: by pulsar
            - show user level

        v0.08: by pulsar
            - checks user whether blacklistet before registering or not

        v0.07: by pulsar
            - fix output style

        v0.06: by pulsar
          - add keyprint feature

        v0.05: by blastbeat
          - small fix in language files and ucmd

        v0.04: by blastbeat
          - updated script api
          - renamed command
          - regged hubcommand

        v0.03: by blastbeat
          - added accinfo, language files, ucmd

        v0.02: by blastbeat
          - updated script api

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_reg"
local scriptversion = "0.36"

local cmd = "reg"

--// imports
local hubcmd, help, ucmd
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local permission = cfg.get( "cmd_reg_permission" )
local tcp = cfg.get( "tcp_ports" )
local ssl = cfg.get( "ssl_ports" )
local tcp_ipv6 = cfg.get( "tcp_ports_ipv6" )
local ssl_ipv6 = cfg.get( "ssl_ports_ipv6" )
local host = cfg.get( "hub_hostaddress" )
local hname = cfg.get( "hub_name" )
local hmail = cfg.get( "hub_email" )
local use_keyprint = cfg.get( "use_keyprint" )
local keyprint_type = cfg.get( "keyprint_type" )
local keyprint_hash = cfg.get( "keyprint_hash" )
local min_length = cfg.get( "min_nickname_length" )
local max_length = cfg.get( "max_nickname_length" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "cmd_reg_report" )
local llevel = cfg.get( "cmd_reg_llevel" )
local report_hubbot = cfg.get( "cmd_reg_report_hubbot" )
local report_opchat = cfg.get( "cmd_reg_report_opchat" )

--// msgs
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_report = lang.msg_report or "[ REG ]--> User: %s  |  registered new User: %s  |  Level: %d [ %s ]  |  Comment: %s"
local msg_nocomment = lang.msg_nocomment or "no comment defined"
local msg_level = lang.msg_level or "You are not allowed to reg this level."
local msg_usage = lang.msg_usage or "Usage: [+!#]reg nick <NICK> <LEVEL> [<COMMENT>] / [+!#]reg desc <NICK> <COMMENT> (an empty comment removes an existing comment)"
local msg_error = lang.msg_error or "An error occurred: "
local msg_ok = lang.msg_ok or "[ REG ]--> User regged with following parameters: Nickname: %s  |  Password: %s  |  Level: %s [ %s ]  |  Comment: %s"
local msg_desc = lang.msg_desc or "[ REG ]--> User: %s  |  added/changed a comment to/from Reguser: %s  |  Comment: %s"
local msg_length = lang.msg_length or "Nickname restrictions, min/max length: %s/%s"
local msg_keyprint = lang.msg_keyprint or "  (with Keyprint)"
local msg_unknown = lang.msg_unknown or "<UNKNOWN>"
local msg_accinfo = lang.msg_accinfo or [[


=== ACCOUNT ==================================================================================================================

    Nickname: %s
    Password: %s

    Level: %s  [ %s ]

    Hubname: %s
    Hubmail: %s

    Hubaddress: %s
================================================================================================================== ACCOUNT ===

        ]]

local help_title = "cmd_reg.lua"
local help_usage = lang.help_usage or "[+!#]reg nick <NICK> <LEVEL> [<COMMENT>] / [+!#]reg desc <NICK> <COMMENT> (an empty comment removes an existing comment)"
local help_desc = lang.help_desc or "Regs a new user / add a comment to an existing user"

local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or "User"
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or "Control"
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or "Reg"
local ucmd_menu_ct2 = lang.ucmd_menu_ct2 or { "Reg" }
local ucmd_menu_ct3 = lang.ucmd_menu_ct3 or { "User", "Control", "Change", "Comment", "add//change comment of a reguser" }
local ucmd_menu_ct4 = lang.ucmd_menu_ct4 or { "Change", "Comment", "add//change comment of a reguser" }

local ucmd_level = lang.ucmd_level or "Level:"
local ucmd_nick = lang.ucmd_nick or "Nick:"
local ucmd_desc = lang.ucmd_desc or "Comment (optional):"
local ucmd_desc2 = lang.ucmd_desc2 or "Comment:"

local msg_blacklist1 = lang.msg_blacklist1 or "Error: This User is blacklisted!"
local msg_blacklist2 = lang.msg_blacklist2 or "Reason: "
local msg_blacklist3 = lang.msg_blacklist3 or "Deleted on: "
local msg_blacklist4 = lang.msg_blacklist4 or "Deleted by: "

--// database
local blacklist_file = "scripts/data/cmd_delreg_blacklist.tbl"
local description_file = "scripts/data/cmd_reg_descriptions.tbl"


----------
--[CODE]--
----------

local minlevel = util.getlowestlevel( permission )
local blacklist_tbl, description_tbl

local addy = "\n"

local tbl_isEmpty = function( tbl )
    if next( tbl ) == nil then return true else return false end
end

local get_keyprint = function( str )
    if use_keyprint then
        return "\n\t" .. str .. keyprint_type .. keyprint_hash .. msg_keyprint .. "\n"
    else
        return "\n"
    end
end

--// tcp_ports
if not tbl_isEmpty( tcp ) and ( tcp[ 1 ] > 0 ) then
    addy = addy .. "\n\t[ IPv4 ]\n\n"
    if #tcp > 1 then
        for i, port in ipairs( tcp ) do
            addy = addy .. "\tadc://" .. host .. ":" .. port .. "\n"
        end
    else
        addy = addy .. "\tadc://" .. host .. ":" .. tcp[ 1 ] .. "\n"
    end
end
--// ssl_ports
if not tbl_isEmpty( ssl ) and ( ssl[ 1 ] > 0 ) then
    if #ssl > 1 then
        addy = addy .. "\n\t[ IPv4 SSL ]\n\n"
        for i, port in ipairs( ssl ) do
            addy = addy .. "\tadcs://" .. host .. ":" .. port .. get_keyprint( "adcs://" .. host .. ":" .. port )
        end
    else
        addy = addy .. "\n\t[ IPv4 SSL ]\n\n"
        addy = addy .. "\tadcs://" .. host .. ":" .. ssl[ 1 ] .. get_keyprint( "adcs://" .. host .. ":" .. ssl[ 1 ] )
    end
end
--// tcp_ports_ipv6
if not tbl_isEmpty( tcp_ipv6 ) and ( tcp_ipv6[ 1 ] > 0 ) then
    addy = addy .. "\n\t[ IPv6 ]\n\n"
    if #tcp_ipv6 > 1 then
        for i, port in ipairs( tcp_ipv6 ) do
            addy = addy .. "\tadc://" .. host .. ":" .. port .. "\n"
        end
    else
        addy = addy .. "\tadc://" .. host .. ":" .. tcp_ipv6[ 1 ] .. "\n"
    end
end
--// ssl_ports_ipv6
if not tbl_isEmpty( ssl_ipv6 ) and ( ssl_ipv6[ 1 ] > 0 ) then
    if #ssl_ipv6 > 1 then
        addy = addy .. "\n\t[ IPv6 SSL ]\n\n"
        for i, port in ipairs( ssl_ipv6 ) do
            addy = addy .. "\tadcs://" .. host .. ":" .. port .. get_keyprint( "adcs://" .. host .. ":" .. port )
        end
    else
        addy = addy .. "\n\t[ IPv6 SSL ]\n\n"
        addy = addy .. "\tadcs://" .. host .. ":" .. ssl_ipv6[ 1 ] .. get_keyprint( "adcs://" .. host .. ":" .. ssl_ipv6[ 1 ] )
    end
end

local description_add = function( targetnick, nick, reason )
    description_tbl = util.loadtable( description_file ) or {}
    description_tbl[ targetnick ] = {}
    description_tbl[ targetnick ][ "tBy" ] = nick
    description_tbl[ targetnick ][ "tReason" ] = reason
    util.savetable( description_tbl, "description_tbl", description_file )
end

-- Mirror of description_add for the empty-comment case on the
-- HTTP PATCH path: removes the entry entirely so the GET list
-- shows comment="" via the `desc and desc.tReason or ""` fallback,
-- rather than persisting an empty-reason record forever.
local description_del = function( targetnick )
    description_tbl = util.loadtable( description_file ) or {}
    if description_tbl[ targetnick ] then
        description_tbl[ targetnick ] = nil
        util.savetable( description_tbl, "description_tbl", description_file )
    end
end

local onbmsg = function( user, command, parameters )
    local user_nick = user:nick()
    local user_firstnick = user:firstnick()
    local user_level = user:level( )
    blacklist_tbl = util.loadtable( blacklist_file ) or {}
    if user_level < minlevel then
        user:reply( msg_denied, hub.getbot() )
        return PROCESSED
    end
    local password = util.generatepass()
    local by, id, level, desc = utf.match( parameters, "^(%S+) (%S+) (%d+) ?(.*)" )
    local by2, id2, desc2 = utf.match( parameters, "^(%S+) (%S+) (.*)" )
    level = tonumber( level )
    if not ( ( by == "nick" and id ) or ( by2 == "desc" ) ) or not ( ( password and level ) or ( id2 and desc2 ) ) then
        user:reply( msg_usage, hub.getbot() )
        return PROCESSED
    end
    local levels = cfg.get( "levels" ) or { }
    if by == "nick" then
        if not levels[ level ] or ( permission[ user_level ] < level ) then
            user:reply( msg_level, hub.getbot() )
            return PROCESSED
        end
    end
    local target_firstnick
    local target_level = tonumber( level ) or "unknown"
    local target_levelname = cfg.get( "levels" )[ target_level ] or "Unreg"
    local target = hub.isnickonline( id ) or hub.isnickonline( id2 )
    if target then
        target_firstnick = target:firstnick()
    else
        target_firstnick = id or id2
    end
    if string.len( target_firstnick ) < min_length or string.len( target_firstnick ) > max_length then
        user:reply( utf.format( msg_length, min_length, max_length ), hub.getbot() )
        return PROCESSED
    end
    if blacklist_tbl[ target_firstnick ] then
        local date = blacklist_tbl[ target_firstnick ]["tDate"] or ""
        local by = blacklist_tbl[ target_firstnick ]["tBy"] or ""
        local reason = blacklist_tbl[ target_firstnick ]["tReason"] or ""
        user:reply( msg_blacklist1, hub.getbot() )
        user:reply( msg_blacklist2 .. reason, hub.getbot() )
        user:reply( msg_blacklist3 .. date, hub.getbot() )
        user:reply( msg_blacklist4 .. by, hub.getbot() )
        return PROCESSED
    end
    if ( by2 == "desc" and id2 and desc2 ) then
        local _, regnicks, _ = hub.getregusers()
        local target = regnicks[ target_firstnick ]
        if target then
            local target_level = target.level
            if ( target_level < user_level or user_level == 100 ) then
                description_add( target_firstnick, user_firstnick, desc2 )
                local msg = utf.format( msg_desc, user_firstnick, target_firstnick, desc2 )
                user:reply( msg, hub.getbot() )
                report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
                audit.fire( audit.build( "reg.desc.set", user,
                    { nick = target_firstnick, level = target_level }, nil, { comment = desc2 } ) )
            else
                user:reply( msg_denied, hub.getbot() )
            end
        else
            user:reply( msg_usage, hub.getbot() )
        end
        return PROCESSED
    end
    if not blacklist_tbl[ target_firstnick ] then
        local bol, err = hub.reguser{ nick = target_firstnick, password = password, level = target_level, by = user:firstnick() }
        if not bol then
            user:reply( msg_error .. ( err or "" ), hub.getbot() )
        else
            local comment = desc
            if comment == "" then comment = msg_nocomment end
            local message = utf.format( msg_report, user_nick, target_firstnick, target_level, target_levelname, comment )
            report.send( report_activate, report_hubbot, report_opchat, llevel, message )
            local message2 = utf.format( msg_ok, target_firstnick, password, target_level, target_levelname, comment )
            user:reply( message2, hub.getbot() )
            local accinfo = utf.format(
                msg_accinfo,
                target_firstnick or msg_unknown,
                password or msg_unknown,
                target_level or msg_unknown,
                target_levelname or msg_unknown,
                hname or msg_unknown,
                hmail or msg_unknown,
                addy  or msg_unknown
            )
            user:reply( accinfo, hub.getbot(), hub.getbot() )
            if target then
                target:reply( accinfo, hub.getbot(), hub.getbot() )
            end
            if desc ~= "" then
                description_add( target_firstnick, user_firstnick, desc )
            end
            --// refresh "cfg/user.tbl.bak"
            cfg.checkusers()
            audit.fire( audit.build( "reg.add", user,
                { nick = target_firstnick, level = target_level },
                nil,
                { comment = ( desc ~= "" and desc or nil ) } ) )
        end
    end
    return PROCESSED
end

-- HTTP API endpoints (#82 registered-users family PR-1, #236).
-- Coexist with the ADC `+reg` chat-cmd above. Registered via raw
-- `hub.http_register` (NOT util_http.http_register_user_action)
-- because /v1/registered is not a SID-target resource - nick is
-- the natural primary key (§7.4 / §10.2). Pattern mirrors cmd_ban
-- PR-4 (#209).
--
-- The ADC-side `cmd_reg_permission` level-ladder does NOT apply
-- on the HTTP path: the bearer token's `admin` scope IS the
-- authorisation gate (consistent with all prior #82 phases).

local format_reguser_entry = function( profile, desc_tbl )
    local level = tonumber( profile.level ) or 0
    local levels = cfg.get( "levels" ) or {}
    local desc = desc_tbl[ profile.nick ]
    return {
        nick       = profile.nick or "",
        level      = level,
        level_name = levels[ level ] or "Unreg",
        by         = profile.by or "",
        regged_at  = profile.date or "",
        lastseen   = tonumber( profile.lastseen ) or 0,
        comment    = ( desc and desc.tReason ) or "",
    }
end

-- #264 filter/sort spec for /v1/registered. Operates on the raw
-- `profile` records returned by hub.getregusers; rendering via
-- format_reguser_entry happens AFTER filter/sort/paginate so the
-- (potentially expensive) cfg.levels lookup and desc_tbl join run
-- only on the page-size subset.
local _registered_filter_spec = {
    string_fields = {
        nick    = function( p ) return p.nick or "" end,
        by      = function( p ) return p.by or ""   end,
        comment = function( p, ctx ) return ctx.desc_tbl[ p.nick ] and ctx.desc_tbl[ p.nick ].tReason or "" end,
    },
    integer_fields = {
        level   = function( p ) return tonumber( p.level ) or 0 end,
    },
    date_fields = {
        -- regged_at is the raw "YYYY-MM-DD / HH:MM:SS" string the hub
        -- persists; the format sorts lexicographically same as
        -- chronological. Query string passes through unchanged.
        regged_at = {
            get         = function( p ) return p.date or "" end,
            parse_query = function( q ) return q end,
        },
        -- lastseen is stored as a packed-decimal YYYYMMDDHHMMSS integer (hub
        -- local time, util.date()'s "new luadch date style"; 0 = never seen).
        -- Operator passes that same 14-digit form as the query value - a
        -- numeric compare on the packed form is chronological. Conversion from
        -- ISO 8601 / wall-clock dates is left to the caller for this phase
        -- (matches the stored format and avoids a locale-sensitive date parser
        -- in core).
        lastseen = {
            get         = function( p ) return tonumber( p.lastseen ) or 0 end,
            parse_query = function( q )
                local v = tonumber( q )
                if not v then return nil, "expected packed YYYYMMDDHHMMSS integer (got '" .. tostring( q ) .. "')" end
                return v
            end,
        },
    },
    sortable_fields = {
        nick      = function( p ) return p.nick or "" end,
        level     = function( p ) return tonumber( p.level ) or 0 end,
        by        = function( p ) return p.by or "" end,
        regged_at = function( p ) return p.date or "" end,
        lastseen  = function( p ) return tonumber( p.lastseen ) or 0 end,
    },
    default_sort_field      = "nick",
    default_sort_descending = false,
}

-- Wrap the comment getter so it can read desc_tbl from the request
-- context (`desc_tbl` is per-request, not module-global, so it can't
-- be closed over at module-load time).
local function _registered_spec_with_ctx( desc_tbl )
    local spec = {
        string_fields   = {},
        integer_fields  = _registered_filter_spec.integer_fields,
        date_fields     = _registered_filter_spec.date_fields,
        sortable_fields = _registered_filter_spec.sortable_fields,
        default_sort_field      = _registered_filter_spec.default_sort_field,
        default_sort_descending = _registered_filter_spec.default_sort_descending,
    }
    -- copy string getters, rebind `comment` with the captured desc_tbl
    for name, fn in pairs( _registered_filter_spec.string_fields ) do
        if name == "comment" then
            spec.string_fields[ name ] = function( p ) return desc_tbl[ p.nick ] and desc_tbl[ p.nick ].tReason or "" end
        else
            spec.string_fields[ name ] = fn
        end
    end
    return spec
end

local http_handler_list_regusers = function( req )
    local regusers = hub.getregusers()
    -- Per-request snapshot of the description side-table; consistent
    -- within one paginated response, freshly re-read on the next call.
    local desc_tbl = util.loadtable( description_file ) or {}
    -- Exclude bots (matches /v1/users humans-only semantics; bot
    -- listing belongs to a future /v1/bots endpoint, not Phase 8).
    local humans = {}
    for _, profile in ipairs( regusers ) do
        if profile.is_bot ~= 1 and profile.nick then
            humans[ #humans + 1 ] = profile
        end
    end

    local spec = _registered_spec_with_ctx( desc_tbl )
    local ok, rows_or_status, code, msg = http_filter.apply(
        req.query or {}, spec, humans
    )
    if not ok then
        return { status = rows_or_status,
            error = { code = code, message = msg } }
    end
    local rows       = rows_or_status
    local pagination = code

    local page = {}
    for i, profile in ipairs( rows ) do
        page[ i ] = format_reguser_entry( profile, desc_tbl )
    end

    -- §6.4 wants `pagination` as a sibling of `data` - the envelope
    -- helper carries only `data`, so we encode the wire body
    -- ourselves and return it as raw_body. Mirrors /v1/users.
    local wire = dkjson.encode( {
        ok         = true,
        data       = { registered = page },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- POST /v1/registered: register a new user.
-- Body: { nick, level, password?, comment? }. Absent password =>
-- auto-generated server-side (matches ADC behaviour) and returned
-- in the response so the admin can communicate it to the user.
-- `level` must be a valid level in cfg.levels. Blacklisted nicks
-- (from cmd_delreg) return 409 to make the operator clear the
-- blacklist deliberately rather than silently re-reg.
local http_handler_create_reguser = function( req )
    local body = req.body or {}
    local nick = body.nick
    local level = tonumber( body.level )
    if type( nick ) ~= "string" or nick == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty `nick` field" } }
    end
    if not level or level ~= math.floor( level ) or level < 0 then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or invalid `level` field (expected non-negative integer)" } }
    end
    -- Coerce to a Lua integer: math.floor returns an integer in 5.4,
    -- so `tostring(level)` is "20" not "20.0" - the latter would
    -- fail hub.reguser's `^%d+$` regex on the `level` field.
    level = math.floor( level )
    local clean_nick = util.strip_control_bytes( nick )
    if clean_nick:find( " " ) or clean_nick:find( "\n" ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "`nick` may not contain whitespace" } }
    end
    if #clean_nick < min_length or #clean_nick > max_length then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = utf.format( "nick length must be between %s and %s characters", min_length, max_length ) } }
    end
    local levels = cfg.get( "levels" ) or {}
    if not levels[ level ] then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "unknown level " .. level .. " (not present in cfg.levels)" } }
    end

    local blacklist_tbl_local = util.loadtable( blacklist_file ) or {}
    if blacklist_tbl_local[ clean_nick ] then
        local entry = blacklist_tbl_local[ clean_nick ]
        return { status = 409, error = { code = "E_CONFLICT",
            message = "nick is on the cmd_delreg blacklist (deleted " .. ( entry.tDate or "?" ) .. " by " .. ( entry.tBy or "?" ) .. ")" } }
    end

    local password
    if body.password ~= nil and body.password ~= "" then
        if type( body.password ) ~= "string" then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "`password` must be a string" } }
        end
        password = util.strip_control_bytes( body.password )
        if password:find( "%s" ) then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "`password` may not contain whitespace" } }
        end
    else
        password = util.generatepass()
    end

    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    -- `by` field is persisted into user.tbl and matched against
    -- `_regex.reguser.by = "^[^ \n]+$"` by hub.reguser; the router
    -- builds token_label as `<comment> (first4...last4)` which has
    -- spaces, so strip whitespace to a single underscore before
    -- handing it to hub.reguser. Empty-string actor (very unusual,
    -- caller built it that way) falls back to a fixed sentinel so
    -- the regex never sees `""`. Audit log keeps the raw label.
    local by_label = ( actor_label:gsub( "[%s]+", "_" ) )
    if by_label == "" then by_label = "http-api" end
    local ok, err = hub.reguser{
        nick = clean_nick, password = password, level = level, by = by_label,
    }
    if not ok then
        if err == "nick already regged" then
            return { status = 409, error = { code = "E_CONFLICT",
                message = "nick already regged" } }
        end
        return { status = 500, error = { code = "E_INTERNAL",
            message = "hub.reguser failed: " .. ( err or "unknown" ) } }
    end

    local clean_comment = ""
    if body.comment ~= nil and body.comment ~= "" then
        if type( body.comment ) ~= "string" then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "`comment` must be a string" } }
        end
        clean_comment = util.strip_control_bytes( body.comment )
        description_add( clean_nick, actor_label, clean_comment )
    end

    cfg.checkusers()

    local levelname = levels[ level ] or "Unreg"
    local msg = utf.format( msg_report, actor_label, clean_nick, level, levelname,
                            ( clean_comment ~= "" and clean_comment or msg_nocomment ) )
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    audit.fire( audit.build( "reg.add",
        { nick = actor_label, sid = "<http>" },
        { nick = clean_nick, level = level },
        nil,
        { comment = ( clean_comment ~= "" and clean_comment or nil ) } ) )

    return { status = 200, data = {
        action     = "register",
        nick       = clean_nick,
        level      = level,
        level_name = levelname,
        password   = password,
        comment    = clean_comment,
    } }
end

-- PATCH /v1/registered/{nick}: update free-form fields. Currently
-- only `comment` is supported (mirrors ADC `+reg desc`). The
-- structured fields (password, nick, level) have dedicated PUT
-- subresources per spec §10.2. Empty-string comment clears the
-- description entry; absent comment field => 400 (no-op PATCH is
-- a usage error, not an idempotent success).
local http_handler_patch_reguser = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    -- Router does not URL-decode or control-byte-strip path vars;
    -- a request line with raw control bytes the framer let through
    -- would otherwise reach the audit log + side-table key unclean.
    local nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    if body.comment == nil then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "no patchable fields in body (supported: `comment`)" } }
    end
    if type( body.comment ) ~= "string" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "`comment` must be a string" } }
    end
    local _, regnicks, _ = hub.getregusers()
    local profile = regnicks[ nick ]
    if not profile then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "'" } }
    end
    -- Bots are excluded from GET /v1/registered for uniformity;
    -- reject PATCH on bots so the surface contract stays consistent.
    if profile.is_bot == 1 then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "no registered user with nick '" .. nick .. "' (bots are not addressable via /v1/registered)" } }
    end
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local clean_comment = util.strip_control_bytes( body.comment )
    -- Empty-string comment clears the description entry entirely
    -- (matches the doc'd semantics; the ADC `+reg desc <nick> ""`
    -- path silently no-ops, but the HTTP surface treats this as
    -- an explicit "remove" so subsequent GET shows comment="").
    if clean_comment == "" then
        description_del( nick )
    else
        description_add( nick, actor_label, clean_comment )
    end

    local msg = utf.format( msg_desc, actor_label, nick,
                            ( clean_comment ~= "" and clean_comment or msg_nocomment ) )
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    audit.fire( audit.build( "reg.desc.set",
        { nick = actor_label, sid = "<http>" },
        { nick = nick, level = tonumber( profile.level ) or 0 },
        nil,
        { comment = clean_comment } ) )

    return { status = 200, data = {
        action  = "patch-registered",
        nick    = nick,
        comment = clean_comment,
    } }
end

hub.setlistener( "onStart", {},
    function()
        help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_ct3, cmd, { "desc", "%[line:" .. ucmd_nick .. "]", "%[line:" .. ucmd_desc2 .. "]" }, { "CT1" }, minlevel )
            local levels = cfg.get( "levels" ) or { }
            local tbl = {}
            local i = 1
            for k, v in pairs( levels ) do
                if k > 0 then
                    tbl[ i ] = k
                    i = i + 1
                end
            end
            table.sort( tbl )
            for _, level in pairs( tbl ) do
                ucmd.add( { ucmd_menu_ct1_1, ucmd_menu_ct1_2, ucmd_menu_ct1_3, levels[ level ] }, cmd, { "nick", "%[line:" .. ucmd_nick .. "]", level, "%[line:" .. ucmd_desc .. "]" }, { "CT1" }, minlevel )
            end
            ucmd.add( ucmd_menu_ct2, cmd, { "nick", "%[userNI]", "%[line:" .. ucmd_level .. "]", "%[line:" .. ucmd_desc .. "]" }, { "CT2" }, minlevel )
            ucmd.add( ucmd_menu_ct4, cmd, { "desc", "%[userNI]", "%[line:" .. ucmd_desc2 .. "]" }, { "CT2" }, minlevel )
        end
        hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )

        if hub.http_register then
            hub.http_register( "GET", "/v1/registered", "read", http_handler_list_regusers, {
                plugin = scriptname,
                description = "list registered users (humans only); paginated per §6.4 (?limit=<1..1000>&offset=<int>)",
                response_schema = {
                    registered = { type = "array", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/registered", "admin", http_handler_create_reguser, {
                plugin = scriptname,
                description = "register a new user (= ADC `+reg nick`). body { nick, level, password?, comment? }; absent/empty password => auto-generated + returned",
                -- Body may carry an operator-supplied password; redact
                -- from api_audit.log per §6.8. Diagnostics still get
                -- the nick + level + outcome via the response shape.
                audit_redact_body = true,
                request_schema = {
                    -- No max_length on nick: the handler enforces the
                    -- cfg-driven `min_nickname_length` / `max_nickname_length`
                    -- range, so an operator who has raised either above
                    -- the schema's hardcoded ceiling is not silently
                    -- shut out of the HTTP path.
                    nick     = { type = "string",  required = true },
                    level    = { type = "integer", required = true },
                    password = { type = "string",  max_length = 256 },
                    comment  = { type = "string",  max_length = 256 },
                },
                response_schema = {
                    action     = { type = "string",  required = true },
                    nick       = { type = "string",  required = true },
                    level      = { type = "integer", required = true },
                    level_name = { type = "string",  required = true },
                    password   = { type = "string",  required = true },
                    comment    = { type = "string",  required = true },
                },
            } )
            hub.http_register( "PATCH", "/v1/registered/{nick}", "admin", http_handler_patch_reguser, {
                plugin = scriptname,
                description = "update free-form fields on a registered user (currently only `comment`; = ADC `+reg desc`). body { comment }; empty string clears the description",
                request_schema = {
                    comment = { type = "string", max_length = 256 },
                },
                response_schema = {
                    action  = { type = "string", required = true },
                    nick    = { type = "string", required = true },
                    comment = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )