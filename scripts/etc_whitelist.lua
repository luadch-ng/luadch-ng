--[[

    etc_whitelist.lua v0.01 by Aybo (#78 allowlist, Phase B)

    Operator-facing chat command for the global IP/CIDR allowlist
    (`core/whitelist.lua`, shipped in Phase A). A whitelisted IP is
    exempt from the AUTOMATED blockers (GeoIP / proxydetect / feeds /
    hub-limit) and from automated blocklist-store entries, but NOT
    from a deliberate manual `+ban` / `+blocklist` (a manual block
    wins - see core/whitelist.lua). Six verbs under one command, plus
    JSONL export / import for backup and cross-hub sync:

        +whitelist show [source]      list active entries (optional
                                      filter by source: manual /
                                      pinger)
        +whitelist add <cidr|ip> [reason="..."] [expires=YYYY-MM-DD]
                                      allow a CIDR (or single IP =
                                      /32 v4 or /128 v6). reason +
                                      expires are key=value pairs
                                      with quoted-string values.
        +whitelist del <id>           remove entry by numeric id
                                      from the +whitelist show output
        +whitelist count              {total, by_source} summary
        +whitelist export             write cfg/whitelist-export-
                                      YYYYMMDD-HHMMSS.jsonl with the
                                      operator-added (source=manual)
                                      entries; the bundled pinger seed
                                      re-seeds itself on a fresh hub,
                                      so it is not exported
        +whitelist import <path>      read JSONL, source="manual"
                                      unless a row sets it; control-
                                      byte stripping on every field

    Bundled pinger seed: on the FIRST run (the store .tbl missing on
    disk) this plugin seeds a small set of known hublist-pinger IPs
    as source="pinger" so they are not flagged by the automated
    blockers out of the box. Seed-on-missing only - once the .tbl
    exists the operator's edits (incl. deletions) are authoritative
    and never re-seeded. Disable the seed entirely with
    `etc_whitelist_seed = false`. The list bit-rots (pinger IPs
    rotate); review + extend via `+whitelist add`.

    Hierarchy guard: a level-N operator cannot remove an entry added
    by a level-(N+) master. The entry's `by_level` field, captured at
    add time, is the comparison source. The bundled seed has no
    by_level (= 0), so any operator can prune it.

    Phase D (v0.02) adds the HTTP API alongside the ADC surface:
    GET /v1/whitelist (list + filter/sort/paginate), GET
    /v1/whitelist/counts (summary), POST /v1/whitelist (add),
    DELETE /v1/whitelist/{id} (remove). HTTP admin tokens bypass the
    ADC hierarchy guard - the token is the trust surface, so a token
    can undo any entry regardless of who added it.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname    = "etc_whitelist"
local scriptversion = "0.04"

local cmd_main = "whitelist"


--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname )
lang = lang or { }
if lang_err then hub.debug( lang_err ) end

local oplevel          = cfg.get( "etc_whitelist_oplevel" ) or 80
local show_limit       = cfg.get( "etc_whitelist_show_limit" ) or 200
local import_min_level = cfg.get( "etc_whitelist_import_min_level" ) or 100
local seed_enabled     = cfg.get( "etc_whitelist_seed" )
if seed_enabled == nil then seed_enabled = true end

local report_activate = cfg.get( "etc_whitelist_report" )
local report_hubbot   = cfg.get( "etc_whitelist_report_hubbot" )
local report_opchat   = cfg.get( "etc_whitelist_report_opchat" )
local report_llevel   = cfg.get( "etc_whitelist_llevel" )

-- Store path: core-owned cfg key. Used to detect first-run (file
-- missing) for the bundled-seed decision, mirroring the engine default.
local store_path = cfg.get( "whitelist_store_path" ) or "scripts/data/etc_whitelist.tbl"

local report = hub.import( "etc_report" )


--// table lookups
local hub_getbot     = hub.getbot
local hub_import     = hub.import
local hub_debug      = hub.debug
local util_strip     = util.strip_control_bytes
local util_safe_path = util.safe_path
local utf_match      = utf.match
local utf_format     = utf.format
local table_concat   = table.concat
local string_format  = string.format

--// dkjson: required for JSONL export/import; the plugin still loads
--// without it and the JSONL verbs degrade to an error reply.
local json = dkjson


--// Bundled hublist-pinger allowlist. Seeded on first run only (see
--// header). v6 pingers use a /64 because the host rotates within the
--// range; v4 pingers use an exact /32. Observed on a live 3.2.x hub
--// 2026-07-13; extend via +whitelist add. These are exempt from the
--// automated blockers, never from a manual +ban.
--//
--// Breadth caveat: a /64 exempts a whole subnet. Each range below is
--// meant to be a per-VPS pinger allocation (OVH etc. hand out a /64
--// per host); if a provider ever shares a /64 across tenants, the
--// co-tenants inherit the automated-blocker exemption too (still never
--// a manual-ban exemption). Narrow a range to /128 via +whitelist, or
--// set etc_whitelist_seed=false to skip the seed entirely.
local BUNDLED_SEED = {
    { cidr = "2001:41d0:a:f8b3::/64",   reason = "DCpinger (hublist)" },
    { cidr = "2607:5300:201:3000::/64", reason = "PingerDC (hublist)" },
    { cidr = "2602:fed2:731b:25::/64",  reason = "[ADC]Proxima (hublist)" },
    { cidr = "78.40.117.229",           reason = "HublistPinger" },
    { cidr = "142.54.190.133",          reason = "PWiAM_Pinger" },
    { cidr = "5.252.102.106",           reason = "TEPinger" },
}


--// lang
local help_title      = "etc_whitelist.lua - allowlist"
local help_usage      = lang.help_usage      or "[+!#]whitelist show|add|del|count|export|import ..."
local help_desc       = lang.help_desc       or "Manage the global IP/CIDR allowlist (exempts trusted IPs from the automated blockers, not from a manual ban). Run `+whitelist show`."

local ucmd_menu_show   = lang.ucmd_menu_show   or { "Hub", "Whitelist", "show" }
local ucmd_menu_add    = lang.ucmd_menu_add    or { "Hub", "Whitelist", "add" }
local ucmd_menu_del    = lang.ucmd_menu_del    or { "Hub", "Whitelist", "remove by id" }
local ucmd_menu_count  = lang.ucmd_menu_count  or { "Hub", "Whitelist", "count by source" }
local ucmd_menu_export = lang.ucmd_menu_export or { "Hub", "Whitelist", "export to JSONL" }

local ucmd_popup_cidr   = lang.ucmd_popup_cidr   or "CIDR or IP (e.g. 192.0.2.0/24):"
local ucmd_popup_reason = lang.ucmd_popup_reason or "Reason (optional):"
local ucmd_popup_id     = lang.ucmd_popup_id     or "Entry id from `+whitelist show`:"

local msg_denied        = lang.msg_denied        or "You are not allowed to use this command."
local msg_usage         = lang.msg_usage         or "Usage: +whitelist show|add|del|count|export|import ..."
local msg_usage_add     = lang.msg_usage_add     or 'Usage: +whitelist add <cidr|ip> [reason="..."] [expires=YYYY-MM-DD]'
local msg_usage_del     = lang.msg_usage_del     or "Usage: +whitelist del <id>"
local msg_usage_import  = lang.msg_usage_import  or "Usage: +whitelist import <path>"
local msg_unknown_verb  = lang.msg_unknown_verb  or "Unknown verb '%s'. Try: show, add, del, count, export, import."
local msg_bad_cidr      = lang.msg_bad_cidr      or "Invalid CIDR / IP: %s"
local msg_bad_expires   = lang.msg_bad_expires   or "Invalid expires date '%s'. Expected YYYY-MM-DD."
local msg_added         = lang.msg_added         or "%s added whitelist entry #%d (%s, source=%s)."
local msg_save_failed   = lang.msg_save_failed   or "Failed to persist whitelist: %s"
local msg_open_failed   = lang.msg_open_failed   or "Could not open the file: %s"
local msg_encode_failed = lang.msg_encode_failed or "JSON encode failed: %s"
local msg_removed       = lang.msg_removed       or "%s removed whitelist entry #%d (%s, source=%s)."
local msg_remove_failed = lang.msg_remove_failed or "whitelist.del failed: %s"
local msg_not_found     = lang.msg_not_found     or "No whitelist entry with id #%d."
local msg_hierarchy     = lang.msg_hierarchy     or "Cannot remove entry #%d: it was added by a higher-level operator (you=%d, by=%d)."
local msg_show_header   = lang.msg_show_header   or "\n=== WHITELIST ==="
local msg_show_footer   = lang.msg_show_footer   or "=== END ===\n"
local msg_show_empty    = lang.msg_show_empty    or "(no entries)"
local msg_show_filter   = lang.msg_show_filter   or "(filtered: source=%s)"
local msg_show_capped   = lang.msg_show_capped   or "(showing %d of %d entries; raise etc_whitelist_show_limit or filter by source)"
local msg_count         = lang.msg_count         or "whitelist: %d entries total"
local msg_no_dkjson     = lang.msg_no_dkjson     or "JSONL export/import requires dkjson, which is not available."
local msg_export_ok     = lang.msg_export_ok     or "%s exported %d whitelist entries to %s."
local msg_import_ok     = lang.msg_import_ok     or "%s imported %d entries from %s (%d skipped, %d errors)."
local msg_unsafe_path   = lang.msg_unsafe_path   or "Path '%s' is unsafe: %s"
local msg_import_level  = lang.msg_import_level  or "Import requires level %d or higher (you are %d)."


----------
--[CODE]--
----------

-- Parse `+whitelist add` args. Grammar:
--     <cidr> [reason="..."] [expires=YYYY-MM-DD]
-- Returns: { cidr, reason, expires } | nil, err_msg
local function parse_add_args( parameters )
    if type( parameters ) ~= "string" or parameters == "" then
        return nil, msg_usage_add
    end
    local cidr, rest = utf_match( parameters, "^(%S+)%s*(.*)$" )
    if not cidr or cidr == "" then
        return nil, msg_usage_add
    end
    rest = rest or ""

    -- Extract QUOTED values first against a working copy that we strip
    -- as we go, so a smuggled `expires=...` literal inside the quoted
    -- reason cannot influence the parsed expires (and vice versa).
    local working = rest
    local reason = utf_match( working, 'reason=%"([^%"]*)%"' )
    if reason then
        working = ( working:gsub( 'reason=%"[^%"]*%"', "" ) )
    end
    local expires = utf_match( working, 'expires=%"([^%"]*)%"' )
    if expires then
        working = ( working:gsub( 'expires=%"[^%"]*%"', "" ) )
    end
    reason  = reason  or utf_match( working, "reason=(%S+)" )
    expires = expires or utf_match( working, "expires=(%S+)" )

    return { cidr = cidr, reason = reason, expires = expires }
end


-- Parse YYYY-MM-DD into an end-of-day (23:59:59 local) unix timestamp
-- so "expires=2026-12-31" means "allowed through end of 2026".
local function parse_expires_date( s )
    if type( s ) ~= "string" or s == "" then return nil end
    local y, m, d = s:match( "^(%d%d%d%d)%-(%d%d)%-(%d%d)$" )
    if not y then return nil end
    return os.time{
        year = tonumber( y ), month = tonumber( m ), day = tonumber( d ),
        hour = 23, min = 59, sec = 59,
    }
end


-- The "add" action. source is always "manual" for an operator add.
-- Returns: ok=true, id, msg  |  ok=false, err_code, msg
local function do_add_entry( cidr, opts, actor_label, actor_level )
    opts = opts or { }
    local reason = opts.reason
    local expires_at = nil
    if opts.expires then
        expires_at = parse_expires_date( opts.expires )
        if not expires_at then
            return false, "bad_expires", utf_format( msg_bad_expires, opts.expires )
        end
    end

    local ok, id, err = whitelist.add( cidr, {
        source     = "manual",
        reason     = reason,
        by_nick    = actor_label,
        by_level   = actor_level,
        expires_at = expires_at,
    } )
    if not ok then
        local err_s = tostring( err or cidr )
        if err_s:find( "^save failed" ) then
            return false, "save_failed", utf_format( msg_save_failed, err_s )
        end
        return false, "bad_cidr", utf_format( msg_bad_cidr, err_s )
    end
    return true, id, utf_format( msg_added, actor_label or "?", id, cidr, "manual" )
end


-- The "del" action. Hierarchy guard applied here.
local function do_del_entry( id, actor_label, actor_level )
    if type( id ) ~= "number" or id < 1 then
        return false, "bad_id", msg_usage_del
    end
    local rows = whitelist.list( )
    local found
    for _, e in ipairs( rows ) do
        if e.id == id then found = e; break end
    end
    if not found then
        return false, "not_found", utf_format( msg_not_found, id )
    end
    local by_level = tonumber( found.by_level ) or 0
    if actor_level and actor_level < by_level then
        return false, "hierarchy", utf_format( msg_hierarchy, id, actor_level, by_level )
    end
    local ok, rerr = whitelist.remove( id )
    if not ok then
        return false, "remove_failed", utf_format( msg_remove_failed, tostring( rerr ) )
    end
    return true, found, utf_format( msg_removed, actor_label or "?", id,
        found.cidr, found.source )
end


local function _export_path_for( now_ts )
    return "cfg/whitelist-export-" .. os.date( "%Y%m%d-%H%M%S", now_ts ) .. ".jsonl"
end


-- Export operator-added (source=manual) entries to JSONL. The bundled
-- pinger seed is deliberately NOT exported: it re-seeds itself on a
-- fresh hub, and exporting it would double the seed on re-import.
-- Returns: ok=true, count, path, msg  |  ok=false, err_msg
local function do_export_jsonl( actor_label )
    if not json then return false, msg_no_dkjson end
    local now_ts = os.time( )
    local path = _export_path_for( now_ts )
    local safe_ok, safe_err = util_safe_path( path )
    if not safe_ok then
        return false, utf_format( msg_unsafe_path, path, tostring( safe_err ) )
    end
    local f, ferr = io.open( path, "w" )
    if not f then
        return false, utf_format( msg_open_failed, tostring( ferr ) )
    end
    local count = 0
    local rows = whitelist.list( { source = "manual" } )
    for _, e in ipairs( rows ) do
        local skip = e.expires_at and e.expires_at <= now_ts
        if not skip then
            local line, jerr = json.encode{
                cidr       = e.cidr,
                source     = e.source,
                reason     = e.reason,
                by_nick    = e.by_nick,
                by_level   = e.by_level,
                expires_at = e.expires_at,
                created_at = e.created_at,
            }
            if not line then
                f:close( )
                return false, utf_format( msg_encode_failed, tostring( jerr ) )
            end
            f:write( line, "\n" )
            count = count + 1
        end
    end
    f:close( )
    return true, count, path, utf_format( msg_export_ok, actor_label or "?", count, path )
end


-- Sanitize an imported row: strip control bytes off every string
-- field. Returns cidr, opts  |  nil, err.
local function _sanitize_import_row( row )
    if type( row ) ~= "table" then return nil, "row is not a table" end
    local cidr = type( row.cidr ) == "string" and util_strip( row.cidr ) or nil
    if not cidr or cidr == "" then return nil, "row.cidr missing" end
    local source = "manual"
    if type( row.source ) == "string" and row.source ~= "" then
        source = util_strip( row.source )
    end
    local opts = {
        source     = source,
        reason     = type( row.reason  ) == "string" and util_strip( row.reason  ) or nil,
        by_nick    = type( row.by_nick ) == "string" and util_strip( row.by_nick ) or nil,
        by_level   = tonumber( row.by_level ),
        expires_at = tonumber( row.expires_at ),
    }
    return cidr, opts
end


-- Import JSONL from a file. Invalid rows are skipped + counted.
-- Every imported row is REATTRIBUTED to the importing operator's
-- nick + level (the engine's add() does not enforce hierarchy on
-- insert); `etc_whitelist_import_min_level` (default 100) gates who
-- may import so a mid-tier op cannot import + own master-tier rows.
-- Returns: ok=true, {added, skipped, errors}, msg  |  ok=false, err_msg
local function do_import_jsonl( path, actor_label, actor_level )
    if not json then return false, msg_no_dkjson end
    if type( path ) ~= "string" or path == "" then
        return false, msg_usage_import
    end
    if ( actor_level or 0 ) < import_min_level then
        return false, utf_format( msg_import_level, import_min_level, actor_level or 0 )
    end
    local safe_ok, safe_err = util_safe_path( path )
    if not safe_ok then
        return false, utf_format( msg_unsafe_path, path, tostring( safe_err ) )
    end
    local f, ferr = io.open( path, "r" )
    if not f then
        return false, utf_format( msg_open_failed, tostring( ferr ) )
    end
    local added, skipped, errors = 0, 0, 0
    local error_log_cap = 5
    local errors_logged = 0
    local function _import_diag( msg )
        if errors_logged < error_log_cap then
            hub_debug( scriptname .. " import: " .. msg )
            errors_logged = errors_logged + 1
        end
    end
    while true do
        local line = f:read( "*l" )
        if not line then break end
        line = line:gsub( "^\239\187\191", "" ):gsub( "^%s+", "" ):gsub( "%s+$", "" )
        if line ~= "" then
            local row, _, jerr = json.decode( line )
            if not row then
                errors = errors + 1
                _import_diag( "json.decode failed: " .. tostring( jerr ) )
            else
                local cidr, opts_or_err = _sanitize_import_row( row )
                if not cidr then
                    skipped = skipped + 1
                    _import_diag( "row skipped: " .. tostring( opts_or_err ) )
                else
                    local opts = opts_or_err
                    opts.by_nick = actor_label
                    opts.by_level = actor_level
                    local ok, _id, aerr = whitelist.add( cidr, opts )
                    if ok then
                        added = added + 1
                    else
                        errors = errors + 1
                        _import_diag( "engine rejected " .. tostring( cidr ) ..
                            ": " .. tostring( aerr ) )
                    end
                end
            end
        end
    end
    f:close( )
    return true, { added = added, skipped = skipped, errors = errors },
        utf_format( msg_import_ok, actor_label or "?", added, path, skipped, errors )
end


-- Build the `+whitelist show` body.
local function format_show( source_filter )
    local filter_spec = { }
    if source_filter and source_filter ~= "" then
        filter_spec.source = source_filter
    end
    local rows = whitelist.list( filter_spec )
    local total = #rows
    local lines = { msg_show_header, "" }
    if source_filter and source_filter ~= "" then
        lines[ #lines + 1 ] = "  " .. utf_format( msg_show_filter, source_filter )
    end
    if total == 0 then
        lines[ #lines + 1 ] = "  " .. msg_show_empty
    else
        local cap = math.min( total, show_limit )
        for i = 1, cap do
            local e = rows[ i ]
            local reason_part = ( e.reason and e.reason ~= "" ) and ( " - " .. e.reason ) or ""
            local exp_part    = e.expires_at
                and ( " (expires " .. tostring( os.date( "%Y-%m-%d", e.expires_at ) ) .. ")" )
                or ""
            lines[ #lines + 1 ] = string_format( "  #%d  %s  [src=%s]  by=%s/L%s%s%s",
                e.id, e.cidr or "?", e.source or "?",
                e.by_nick or "?", tostring( e.by_level or "?" ),
                exp_part, reason_part )
        end
        if total > cap then
            lines[ #lines + 1 ] = ""
            lines[ #lines + 1 ] = "  " .. utf_format( msg_show_capped, cap, total )
        end
    end
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_show_footer
    return table_concat( lines, "\n" )
end


local function format_count( )
    local c = whitelist.count( )
    local lines = { msg_show_header, "" }
    lines[ #lines + 1 ] = "  " .. utf_format( msg_count, c.total )
    local sources = { }
    for s in pairs( c.by_source ) do sources[ #sources + 1 ] = s end
    table.sort( sources )
    for _, s in ipairs( sources ) do
        lines[ #lines + 1 ] = string_format( "    %s: %d", s, c.by_source[ s ] )
    end
    lines[ #lines + 1 ] = ""
    lines[ #lines + 1 ] = msg_show_footer
    return table_concat( lines, "\n" )
end


-- Seed the bundled pingers when the store file is MISSING (first run).
-- Returns the number of entries seeded. Exposed for tests.
local function seed_if_first_run( )
    if not seed_enabled then return 0 end
    local probe = io.open( store_path, "r" )
    if probe then
        probe:close( )
        return 0    -- store exists -> operator-owned, never re-seed
    end
    local seeded = 0
    for _, s in ipairs( BUNDLED_SEED ) do
        local ok = whitelist.add( s.cidr, { source = "pinger", reason = s.reason } )
        if ok then seeded = seeded + 1 end
    end
    if seeded > 0 then
        hub_debug( scriptname .. ": seeded " .. seeded ..
            " bundled hublist-pinger allow entries (first run)" )
    end
    return seeded
end


------------------
--[ADC HANDLERS]--
------------------

local function on_whitelist( user, command, parameters )
    if user:level( ) < oplevel then
        user:reply( msg_denied, hub_getbot( ) )
        return PROCESSED
    end
    local verb, rest = utf_match( parameters or "", "^(%S+)%s*(.*)$" )
    verb = verb and verb:lower( ) or ""
    rest = rest or ""

    if verb == "" then
        user:reply( msg_usage, hub_getbot( ) )
        return PROCESSED
    end

    local user_nick  = user:nick( ) or "?"
    local user_level = user:level( )

    if verb == "show" then
        local source_filter = utf_match( rest, "^(%S+)" )
        user:reply( format_show( source_filter ), hub_getbot( ), hub_getbot( ) )

    elseif verb == "count" then
        user:reply( format_count( ), hub_getbot( ), hub_getbot( ) )

    elseif verb == "add" then
        local args, perr = parse_add_args( rest )
        if not args then
            user:reply( perr, hub_getbot( ) )
            return PROCESSED
        end
        local clean_reason = args.reason and util_strip( args.reason ) or nil
        local ok, _id_or_err, msg = do_add_entry( args.cidr, {
            reason  = clean_reason,
            expires = args.expires,
        }, user_nick, user_level )
        user:reply( msg, hub_getbot( ) )
        if ok then
            if report then
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "whitelist.add", user, nil, args.reason, {
                cidr    = args.cidr,
                source  = "manual",
                expires = args.expires,
                id      = _id_or_err,
            } ) )
        end

    elseif verb == "del" then
        local id_str = utf_match( rest, "^(%S+)" )
        local id = tonumber( id_str )
        if not id then
            user:reply( msg_usage_del, hub_getbot( ) )
            return PROCESSED
        end
        local ok, payload, msg = do_del_entry( id, user_nick, user_level )
        user:reply( msg, hub_getbot( ) )
        if ok then
            local entry = payload
            if report then
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "whitelist.remove", user, nil,
                entry.reason, {
                    id     = id,
                    cidr   = entry.cidr,
                    source = entry.source,
                } ) )
        end

    elseif verb == "export" then
        local ok, count_or_err, _path, msg = do_export_jsonl( user_nick )
        user:reply( msg or tostring( count_or_err ), hub_getbot( ) )
        if ok then
            if report then
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "whitelist.export", user, nil, nil, {
                path  = _path,
                count = count_or_err,
            } ) )
        end

    elseif verb == "import" then
        local path = utf_match( rest, "^(%S+)" )
        if not path then
            user:reply( msg_usage_import, hub_getbot( ) )
            return PROCESSED
        end
        local ok, payload, msg = do_import_jsonl( path, user_nick, user_level )
        user:reply( msg or tostring( payload ), hub_getbot( ) )
        if ok then
            if report then
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "whitelist.import", user, nil, nil, {
                path    = path,
                added   = payload.added,
                skipped = payload.skipped,
                errors  = payload.errors,
            } ) )
        end

    else
        user:reply( utf_format( msg_unknown_verb, verb ), hub_getbot( ) )
    end

    return PROCESSED
end


-------------------
--[HTTP HANDLERS]--
-------------------
-- #78 allowlist, Phase D: HTTP API mirrors the ADC surface. Raw
-- hub.http_register (target is a CIDR / id, not a SID). HTTP
-- admin-token requests carry no operator level; they bypass the ADC
-- hierarchy guard via a synthetic by_level = 100 (the token is the
-- trust surface, per the etc_blocklist HTTP contract).

-- Accepted `source` labels on POST. The whitelist source is a label
-- only (no priority): "manual" for an operator add, "pinger" for the
-- bundled seed.
local _SOURCE_ENUM = { "manual", "pinger" }

-- #264 filter/sort spec for GET /v1/whitelist. All rows are pre-listed
-- via whitelist.list() so http_filter sees a stable shape.
local _list_filter_spec = {
    string_fields = {
        source  = function( e ) return e.source  or "" end,
        by_nick = function( e ) return e.by_nick or "" end,
        reason  = function( e ) return e.reason  or "" end,
        cidr    = function( e ) return e.cidr or "" end,
    },
    integer_fields = {
        by_level   = function( e ) return tonumber( e.by_level ) or 0 end,
        created_at = function( e ) return tonumber( e.created_at ) or 0 end,
        expires_at = function( e ) return tonumber( e.expires_at ) or 0 end,
    },
    sortable_fields = {
        id         = function( e ) return tonumber( e.id ) or 0  end,
        cidr       = function( e ) return e.cidr or ""            end,
        source     = function( e ) return e.source or ""          end,
        created_at = function( e ) return tonumber( e.created_at ) or 0 end,
        expires_at = function( e ) return tonumber( e.expires_at ) or 0 end,
    },
    default_sort_field      = "id",
    default_sort_descending = false,
}

local function _format_entry_for_wire( e )
    return {
        id         = e.id,
        cidr       = e.cidr,
        source     = e.source,
        reason     = e.reason or "",
        by_nick    = e.by_nick or "",
        by_level   = e.by_level,
        expires_at = e.expires_at,
        created_at = e.created_at,
        meta       = e.meta,
    }
end

local http_handler_list_entries = function( req )
    local raw = whitelist.list( )
    local entries = { }
    for _, e in ipairs( raw ) do
        entries[ #entries + 1 ] = _format_entry_for_wire( e )
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or { }, _list_filter_spec, entries )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = json.encode{
        ok         = true,
        data       = { entries = rows },
        pagination = pagination,
    }
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

local http_handler_get_counts = function( req )
    -- Force object shape on an empty by_source (dkjson emits {} not [])
    -- so a typed decoder reading it as an object survives a fresh store.
    local c = whitelist.count( )
    setmetatable( c.by_source, { __jsontype = "object" } )
    return { status = 200, data = c }
end

local http_handler_create_entry = function( req )
    local body = req.body or { }
    local cidr = body.cidr
    if type( cidr ) ~= "string" or cidr == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty `cidr` field" } }
    end
    cidr = util_strip( cidr )
    local reason = body.reason
    if reason then reason = util_strip( reason ) end
    local source = body.source or "manual"
    local expires_at = body.expires_at    -- schema-forced number|nil

    local actor_label = util_strip( req.token_label or "http-api" )

    -- by_level = 100 (master) so a subsequent DELETE by the same token
    -- clears the ADC hierarchy guard - the token is the trust surface.
    local ok, id, engine_err = whitelist.add( cidr, {
        source     = source,
        reason     = reason,
        by_nick    = actor_label,
        by_level   = 100,
        expires_at = expires_at,
    } )
    if not ok then
        local err_s = tostring( engine_err or "" )
        local status, code
        if err_s:find( "^save failed" ) then
            status, code = 500, "E_INTERNAL"
        else
            status, code = 400, "E_BAD_INPUT"
        end
        return { status = status, error = {
            code = code, message = err_s ~= "" and err_s or "add failed",
        } }
    end
    local msg = utf_format( msg_added, actor_label, id, cidr, source )
    if report then
        report.send( report_activate, report_hubbot, report_opchat,
            report_llevel, msg )
    end
    audit.fire( audit.build( "whitelist.add",
        { nick = actor_label, sid = "<http>" }, nil, reason, {
            cidr     = cidr,
            source   = source,
            id       = id,
            by_level = 100,
        } ) )
    return { status = 201, data = {
        action = "added",
        id     = id,
        cidr   = cidr,
        source = source,
    } }
end

local http_handler_delete_entry = function( req )
    local id_str = req.path_vars and req.path_vars.id
    local id = tonumber( id_str )
    if not id or id < 1 or id ~= math.floor( id ) then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "invalid {id} - must be a positive integer" } }
    end
    local actor_label = util_strip( req.token_label or "http-api" )
    -- Level 100 (master) -> hierarchy guard passes for any entry.
    local ok, payload, msg = do_del_entry( id, actor_label, 100 )
    if not ok then
        local err_code = payload
        local status = err_code == "not_found" and 404 or 400
        return { status = status, error = {
            code = err_code == "not_found" and "E_NOT_FOUND" or "E_BAD_INPUT",
            message = msg,
        } }
    end
    local entry = payload
    if report then
        report.send( report_activate, report_hubbot, report_opchat,
            report_llevel, msg )
    end
    audit.fire( audit.build( "whitelist.remove",
        { nick = actor_label, sid = "<http>" }, nil, entry.reason, {
            id     = id,
            cidr   = entry.cidr,
            source = entry.source,
        } ) )
    return { status = 200, data = {
        action  = "removed",
        id      = id,
        removed = {
            cidr    = util_strip( entry.cidr or "" ),
            source  = util_strip( entry.source or "" ),
            reason  = util_strip( entry.reason or "" ),
            by_nick = util_strip( entry.by_nick or "" ),
        },
    } }
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onStart", { },
    function( )
        -- Seed bundled pingers on first run (before registering the
        -- command so a `+whitelist show` immediately after boot shows
        -- them).
        seed_if_first_run( )

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
        end

        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu_show,   cmd_main .. " show",
                { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_add,    cmd_main .. " add %[line:" .. ucmd_popup_cidr .. "] reason=%[line:" .. ucmd_popup_reason .. "]",
                { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_del,    cmd_main .. " del %[line:" .. ucmd_popup_id .. "]",
                { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_count,  cmd_main .. " count",
                { }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_export, cmd_main .. " export",
                { }, { "CT1" }, oplevel )
        end

        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd_main, on_whitelist, oplevel ) )

        -- #78 Phase D HTTP API. Raw hub.http_register (target is a
        -- CIDR / id, not a SID). Schema field names use min/max.
        if hub.http_register then
            hub.http_register( "GET", "/v1/whitelist", "read",
                http_handler_list_entries, {
                    plugin = scriptname,
                    description = "list whitelist entries (= ADC `+whitelist show`); supports filter (source, cidr_contains, reason_contains, by_nick, by_level, created_at, expires_at) + sort + pagination via the standard http_filter convention",
                    response_schema = {
                        entries = { type = "array", required = true },
                    },
                } )
            hub.http_register( "GET", "/v1/whitelist/counts", "read",
                http_handler_get_counts, {
                    plugin = scriptname,
                    description = "counts summary (= ADC `+whitelist count`); prometheus + WebUI dashboard friendly",
                    response_schema = {
                        total     = { type = "integer", required = true },
                        by_source = { type = "object",  required = true },
                    },
                } )
            hub.http_register( "POST", "/v1/whitelist", "admin",
                http_handler_create_entry, {
                    plugin = scriptname,
                    description = "add a whitelist entry (= ADC `+whitelist add`); body `{cidr, source?, reason?, expires_at?}`. source enum {manual, pinger}; expires_at is a unix timestamp (integer). CIDRs with host bits set are rejected (`1.2.3.4/24` -> use `1.2.3.0/24`).",
                    request_schema = {
                        cidr    = { type = "string",  required = true,  max_length = 45 },
                        source  = { type = "string",  required = false, enum = _SOURCE_ENUM },
                        reason  = { type = "string",  required = false, max_length = 256 },
                        expires_at = { type = "integer", required = false,
                            min = 1, max = 2147483647 },
                    },
                    response_schema = {
                        action = { type = "string",  required = true },
                        id     = { type = "integer", required = true },
                        cidr   = { type = "string",  required = true },
                        source = { type = "string",  required = true },
                    },
                } )
            hub.http_register( "DELETE", "/v1/whitelist/{id}", "admin",
                http_handler_delete_entry, {
                    plugin = scriptname,
                    description = "remove a whitelist entry by numeric id (= ADC `+whitelist del <id>`). Ids are stable across the store lifetime; a re-add gets a fresh id. HTTP admin tokens bypass the ADC-side hierarchy guard - the token is the trust surface.",
                    response_schema = {
                        action  = { type = "string",  required = true },
                        id      = { type = "integer", required = true },
                        removed = { type = "object",  required = true },
                    },
                } )
        end

        return nil
    end
)


hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// expose internals for unit tests
return {
    _parse_add_args      = parse_add_args,
    _parse_expires_date  = parse_expires_date,
    _do_add_entry        = do_add_entry,
    _do_del_entry        = do_del_entry,
    _do_export_jsonl     = do_export_jsonl,
    _do_import_jsonl     = do_import_jsonl,
    _sanitize_import_row = _sanitize_import_row,
    _format_show         = format_show,
    _format_count        = format_count,
    _seed_if_first_run   = seed_if_first_run,
    _BUNDLED_SEED        = BUNDLED_SEED,
    _http_handler_list_entries = http_handler_list_entries,
    _http_handler_get_counts   = http_handler_get_counts,
    _http_handler_create_entry = http_handler_create_entry,
    _http_handler_delete_entry = http_handler_delete_entry,
    _list_filter_spec          = _list_filter_spec,
    _SOURCE_ENUM               = _SOURCE_ENUM,
}
