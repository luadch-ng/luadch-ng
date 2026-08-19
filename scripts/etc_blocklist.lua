--[[

    etc_blocklist.lua v0.01 by Aybo (#78 Phase B)

    Operator-facing chat command for the unified pre-handshake
    blocklist (`core/blocklist.lua`, shipped in #78 Phase A). Six
    verbs under one command, plus JSONL export / import for backup
    and cross-hub sync.

        +blocklist show [source]      list active entries (optional
                                      filter by source: manual /
                                      geoip / external / proxycheck
                                      / vpnapi / ipqs)
        +blocklist add <cidr|ip> [stealth] [reason="..."] [expires=YYYY-MM-DD]
                                      add a CIDR (or single IP =
                                      /32 v4 or /128 v6). `stealth`
                                      is a literal positional flag;
                                      reason + expires are key=value
                                      pairs with quoted-string values.
        +blocklist del <id>           remove entry by numeric id
                                      from the +blocklist show output
        +blocklist count              {total, by_source} summary
        +blocklist export             write cfg/blocklist-export-
                                      YYYYMMDD.jsonl with all manual
                                      entries (auto-feeds re-fetch
                                      themselves; no need to back
                                      them up)
        +blocklist import <path>      read JSONL, source="manual"
                                      unless row sets it; control-
                                      byte stripping applied to
                                      every string field

    Phase C shipped in v0.02 adds four HTTP endpoints alongside the
    ADC surface: GET /v1/blocklist (list + filter/sort/paginate),
    GET /v1/blocklist/counts (summary), POST /v1/blocklist (add),
    DELETE /v1/blocklist/{id} (remove). HTTP handlers bypass the
    ADC hierarchy guard - the admin token IS the trust surface, so
    a token can undo any entry regardless of who added it.

    Hierarchy guard: a level-N operator cannot remove an entry
    added by a level-(N+) master. The entry's `by_level` field,
    captured at add time, is the comparison source.

    Auto-feed entries (source != "manual") are operator-removable
    only when the operator is at or above the master level; the
    matching plugin (etc_geoip, etc_blocklist_feeds, etc_proxydetect)
    is the canonical owner and a stray manual remove will be re-
    added on the next refresh cycle anyway.

]]--


--------------
--[SETTINGS]--
--------------

local scriptname    = "etc_blocklist"
local scriptversion = "0.04"

local cmd_main = "blocklist"


--// imports
local scriptlang = cfg.get( "language" )
local lang, lang_err = cfg.loadlanguage( scriptlang, scriptname )
lang = lang or { }
if lang_err then hub.debug( lang_err ) end

local oplevel          = cfg.get( "etc_blocklist_oplevel" ) or 80
local show_limit       = cfg.get( "etc_blocklist_show_limit" ) or 200
local import_min_level = cfg.get( "etc_blocklist_import_min_level" ) or 100

local report_activate = cfg.get( "etc_blocklist_report" )
local report_hubbot   = cfg.get( "etc_blocklist_report_hubbot" )
local report_opchat   = cfg.get( "etc_blocklist_report_opchat" )
local report_llevel   = cfg.get( "etc_blocklist_llevel" )

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

--// dkjson: required for JSONL export/import. The plugin still
--// loads if dkjson is unavailable (e.g. operator stripped the
--// optional lib); the JSONL verbs degrade to error replies.
local json = dkjson

--// http_filter (core/http_filter.lua): shared filter+sort+
--// paginate helper for HTTP list endpoints (#264). Sandbox
--// global; always available at plugin runtime.


--// lang
local help_title      = "etc_blocklist.lua - blocklist"
local help_usage      = lang.help_usage      or "[+!#]blocklist show|add|del|count|export|import ..."
local help_desc       = lang.help_desc       or "Manage the unified pre-handshake IP/CIDR blocklist. Run `+blocklist show` for the active entries."

local ucmd_menu_show   = lang.ucmd_menu_show   or { "Hub", "Blocklist", "show" }
local ucmd_menu_add    = lang.ucmd_menu_add    or { "Hub", "Blocklist", "add" }
local ucmd_menu_del    = lang.ucmd_menu_del    or { "Hub", "Blocklist", "remove by id" }
local ucmd_menu_count  = lang.ucmd_menu_count  or { "Hub", "Blocklist", "count by source" }
local ucmd_menu_export = lang.ucmd_menu_export or { "Hub", "Blocklist", "export to JSONL" }

local ucmd_popup_cidr   = lang.ucmd_popup_cidr   or "CIDR or IP (e.g. 192.0.2.0/24):"
local ucmd_popup_reason = lang.ucmd_popup_reason or "Reason (optional):"
local ucmd_popup_id     = lang.ucmd_popup_id     or "Entry id from `+blocklist show`:"

local msg_denied        = lang.msg_denied        or "You are not allowed to use this command."
local msg_usage         = lang.msg_usage         or "Usage: +blocklist show|add|del|count|export|import ..."
local msg_usage_add     = lang.msg_usage_add     or 'Usage: +blocklist add <cidr|ip> [stealth] [reason="..."] [expires=YYYY-MM-DD]'
local msg_usage_del     = lang.msg_usage_del     or "Usage: +blocklist del <id>"
local msg_usage_import  = lang.msg_usage_import  or "Usage: +blocklist import <path>"
local msg_unknown_verb  = lang.msg_unknown_verb  or "Unknown verb '%s'. Try: show, add, del, count, export, import."
local msg_bad_cidr      = lang.msg_bad_cidr      or "Invalid CIDR / IP: %s"
local msg_bad_expires   = lang.msg_bad_expires   or "Invalid expires date '%s'. Expected YYYY-MM-DD."
local msg_added         = lang.msg_added         or "%s added blocklist entry #%d (%s, source=%s, stealth=%s)."
local msg_removed       = lang.msg_removed       or "%s removed blocklist entry #%d (%s, source=%s)."
local msg_remove_failed = lang.msg_remove_failed or "blocklist.del failed: %s"
local msg_not_found     = lang.msg_not_found     or "No blocklist entry with id #%d."
local msg_hierarchy     = lang.msg_hierarchy     or "Cannot remove entry #%d: it was added by a higher-level operator (you=%d, by=%d)."
local msg_show_header   = lang.msg_show_header   or "\n=== BLOCKLIST ==="
local msg_show_footer   = lang.msg_show_footer   or "=== END ===\n"
local msg_show_empty    = lang.msg_show_empty    or "(no entries)"
local msg_show_filter   = lang.msg_show_filter   or "(filtered: source=%s)"
local msg_show_capped   = lang.msg_show_capped   or "(showing %d of %d entries; raise etc_blocklist_show_limit or filter by source)"
local msg_count         = lang.msg_count         or "blocklist: %d entries total"
local msg_no_dkjson     = lang.msg_no_dkjson     or "JSONL export/import requires dkjson, which is not available."
local msg_export_ok     = lang.msg_export_ok     or "%s exported %d blocklist entries to %s."
local msg_import_ok     = lang.msg_import_ok     or "%s imported %d entries from %s (%d skipped, %d errors)."
local msg_unsafe_path   = lang.msg_unsafe_path   or "Path '%s' is unsafe: %s"
local msg_import_level  = lang.msg_import_level  or "Import requires level %d or higher (you are %d)."
local msg_save_failed   = lang.msg_save_failed   or "Failed to persist blocklist: %s"
local msg_open_failed   = lang.msg_open_failed   or "Could not open the file: %s"
local msg_encode_failed = lang.msg_encode_failed or "JSON encode failed: %s"


----------
--[CODE]--
----------

-- Parse `+blocklist add` args. The grammar is:
--     <cidr> [stealth] [reason="..."] [expires=YYYY-MM-DD]
--             ^ literal flag
--                       ^ quoted-string value
--                                       ^ date, unquoted (no spaces)
--
-- Returns: { cidr, stealth, reason, expires } | nil, err_msg
local function parse_add_args( parameters )
    if type( parameters ) ~= "string" or parameters == "" then
        return nil, msg_usage_add
    end
    local cidr, rest = utf_match( parameters, "^(%S+)%s*(.*)$" )
    if not cidr or cidr == "" then
        return nil, msg_usage_add
    end
    rest = rest or ""

    -- Stealth is the first token after cidr, if literal.
    local stealth = false
    local first, after_first = utf_match( rest, "^(%S+)%s*(.*)$" )
    if first == "stealth" then
        stealth = true
        rest = after_first
    end

    -- Extract QUOTED values first against a working copy that we
    -- strip as we go. The unquoted fallback then runs against the
    -- stripped copy so a smuggled `expires=...` literal inside
    -- the quoted reason cannot influence the parsed expires (and
    -- vice versa).
    local working = rest
    local reason = utf_match( working, 'reason=%"([^%"]*)%"' )
    if reason then
        working = ( working:gsub( 'reason=%"[^%"]*%"', "" ) )
    end
    local expires = utf_match( working, 'expires=%"([^%"]*)%"' )
    if expires then
        working = ( working:gsub( 'expires=%"[^%"]*%"', "" ) )
    end
    -- Unquoted single-token fallback for the common shorthand
    -- (`expires=2026-12-31`); only against the post-strip working
    -- copy so an attacker cannot smuggle key=value via the other
    -- field's quoted body.
    reason  = reason  or utf_match( working, "reason=(%S+)" )
    expires = expires or utf_match( working, "expires=(%S+)" )

    return { cidr = cidr, stealth = stealth, reason = reason, expires = expires }
end


-- Parse a YYYY-MM-DD string into a unix timestamp at end-of-day
-- local time. We deliberately use 23:59:59 so an operator typing
-- "expires=2026-12-31" gets "blocked through end of 2026" semantics
-- rather than "blocked through midnight Dec 30/31".
-- Returns: timestamp | nil
local function parse_expires_date( s )
    if type( s ) ~= "string" or s == "" then return nil end
    local y, m, d = s:match( "^(%d%d%d%d)%-(%d%d)%-(%d%d)$" )
    if not y then return nil end
    local ts = os.time{
        year = tonumber( y ), month = tonumber( m ), day = tonumber( d ),
        hour = 23, min = 59, sec = 59,
    }
    return ts
end


-- The actual "add" action. Shared between ADC chat-cmd path and
-- (Phase C) the HTTP API path. The caller is responsible for
-- access control (oplevel gate); this is the pure mutation +
-- audit + report dispatch.
--
-- Returns:
--   ok=true,  id (int),  msg
--   ok=false, err_code (str), msg
--
-- err_code values: "bad_cidr" / "bad_expires" / "add_failed".
local function do_add_entry( cidr, opts, actor_label, actor_level )
    opts = opts or { }
    local stealth = opts.stealth and true or false
    local reason  = opts.reason
    local expires_at = nil
    if opts.expires then
        expires_at = parse_expires_date( opts.expires )
        if not expires_at then
            return false, "bad_expires", utf_format( msg_bad_expires, opts.expires )
        end
    end

    local ok, id, err = blocklist.add( cidr, {
        source     = "manual",
        stealth    = stealth,
        reason     = reason,
        by_nick    = actor_label,
        by_level   = actor_level,
        expires_at = expires_at,
    } )
    if not ok then
        -- Distinguish save-failed (disk I/O / permission error)
        -- from bad-cidr (parser / engine rejection). The engine's
        -- save-failed path prefixes its err with "save failed:";
        -- everything else is a parse / structural rejection.
        local err_s = tostring( err or cidr )
        if err_s:find( "^save failed" ) then
            return false, "save_failed", utf_format( msg_save_failed, err_s )
        end
        return false, "bad_cidr", utf_format( msg_bad_cidr, err_s )
    end
    local stealth_label = stealth and "yes" or "no"
    return true, id, utf_format( msg_added, actor_label or "?", id, cidr,
        "manual", stealth_label )
end


-- The actual "del" action. Hierarchy guard applied here.
local function do_del_entry( id, actor_label, actor_level )
    if type( id ) ~= "number" or id < 1 then
        return false, "bad_id", msg_usage_del
    end
    -- We need the entry's by_level + cidr + source BEFORE removing
    -- it (a) for the hierarchy check and (b) for the audit + report
    -- payload. The list() snapshot is a copy so this is safe.
    local rows = blocklist.list( )
    local found
    for _, e in ipairs( rows ) do
        if e.id == id then found = e; break end
    end
    if not found then
        return false, "not_found", utf_format( msg_not_found, id )
    end
    -- Hierarchy: a level-N operator cannot remove an entry an even
    -- higher-level operator added. nil by_level (auto-feed entry) is
    -- treated as 0 = always removable by an operator. by_level for
    -- manual entries was set at add time and persists across reload.
    local by_level = tonumber( found.by_level ) or 0
    if actor_level and actor_level < by_level then
        return false, "hierarchy", utf_format( msg_hierarchy, id, actor_level, by_level )
    end

    local ok, rerr = blocklist.remove( id )
    if not ok then
        return false, "remove_failed", utf_format( msg_remove_failed, tostring( rerr ) )
    end
    return true, found, utf_format( msg_removed, actor_label or "?", id,
        found.cidr, found.source )
end


-- Resolve where +blocklist export writes. Date+time stamp so two
-- exports on the same day do not silently overwrite each other -
-- HHMMSS suffix is the difference between "backup behaviour" and
-- "operator burned by clobbering the morning's export with the
-- afternoon's smaller set". The caller (do_export_jsonl) runs the
-- path through util.safe_path before opening.
local function _export_path_for( now_ts )
    local stamp = os.date( "%Y%m%d-%H%M%S", now_ts )
    return "cfg/blocklist-export-" .. stamp .. ".jsonl"
end


-- Export current manual entries to a JSONL file. Each line is one
-- JSON object with the entry fields. We deliberately skip
-- expired entries (no point exporting them) and auto-feed entries
-- (they re-fetch themselves; backing them up just creates an
-- import-time conflict with the live feed).
--
-- Returns: ok=true, count, path  |  ok=false, err_msg
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
    local rows = blocklist.list( { source = "manual" } )
    for _, e in ipairs( rows ) do
        local skip = e.expires_at and e.expires_at <= now_ts
        if not skip then
            -- Pick the operator-meaningful subset; the engine
            -- recomputes internal cache fields (network_b64 / family
            -- / prefix_len) from the cidr string on import.
            local line, jerr = json.encode{
                cidr       = e.cidr,
                source     = e.source,
                stealth    = e.stealth and true or false,
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
    return true, count, path, utf_format( msg_export_ok,
        actor_label or "?", count, path )
end


-- Sanitize an imported row. Returns the cleaned opts table (no
-- control bytes anywhere) plus the cidr, or nil + err.
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
        stealth    = row.stealth and true or false,
        reason     = type( row.reason  ) == "string" and util_strip( row.reason  ) or nil,
        by_nick    = type( row.by_nick ) == "string" and util_strip( row.by_nick ) or nil,
        by_level   = tonumber( row.by_level ),
        expires_at = tonumber( row.expires_at ),
    }
    return cidr, opts
end


-- Import JSONL from a file. Each line is one row; invalid rows
-- are skipped + counted (not fatal). The whole file is read into
-- memory first (operators typically export hundreds, not millions,
-- of entries; if Phase D auto-feeds change that we revisit).
--
-- Hierarchy guard: the import path REATTRIBUTES every imported
-- row to the importing operator's nick + level (the engine's
-- add() does NOT enforce hierarchy on insert, only the plugin's
-- del does on the way out). Without an import-level guard a
-- mid-tier operator could import a file containing master-level
-- entries and effectively take ownership of them. The cfg-keyed
-- `etc_blocklist_import_min_level` (default 100 = master-only)
-- gates this; the cfg-default rationale comment in
-- core/cfg_defaults.lua explains the threat model.
--
-- Returns: ok=true, {added, skipped, errors}, msg | ok=false, err_msg
local function do_import_jsonl( path, actor_label, actor_level )
    if not json then return false, msg_no_dkjson end
    if type( path ) ~= "string" or path == "" then
        return false, msg_usage_import
    end
    if ( actor_level or 0 ) < import_min_level then
        return false, utf_format( msg_import_level,
            import_min_level, actor_level or 0 )
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
    -- Log up to this many distinct import errors via hub_debug so
    -- an operator running `+blocklist import bad.jsonl` can see
    -- WHY rows failed without filling error.log on a worst-case
    -- garbage file. The full counts are returned to the caller.
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
        -- Strip BOM + trim whitespace per import-line defensive
        -- pattern; dkjson is strict about leading whitespace.
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
                    -- All imported entries are attributed to the
                    -- importing operator's level. The original
                    -- by_level / by_nick in the file are kept as
                    -- audit metadata in the row only - the entry
                    -- itself is OWNED by whoever imported it.
                    -- The import-level guard above ensured the
                    -- operator is at the master tier, so this
                    -- attribution is policy-safe.
                    local opts = opts_or_err
                    opts.by_nick = actor_label
                    opts.by_level = actor_level
                    local ok, _id, aerr = blocklist.add( cidr, opts )
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
        utf_format( msg_import_ok, actor_label or "?",
            added, path, skipped, errors )
end


-- Build the `+blocklist show` body. `source_filter` may be nil
-- (= all sources) or one of the priority-table keys (manual /
-- geoip / external / proxycheck / vpnapi / ipqs).
local function format_show( source_filter )
    local filter_spec = { }
    if source_filter and source_filter ~= "" then
        filter_spec.source = source_filter
    end
    local rows = blocklist.list( filter_spec )
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
            local stealth_part = e.stealth and " [STEALTH]" or ""
            local reason_part  = ( e.reason and e.reason ~= "" ) and ( " - " .. e.reason ) or ""
            local exp_part     = e.expires_at
                and ( " (expires " .. tostring( os.date( "%Y-%m-%d", e.expires_at ) ) .. ")" )
                or ""
            lines[ #lines + 1 ] = string_format( "  #%d  %s  [src=%s%s]  by=%s/L%s%s%s",
                e.id, e.cidr or "?", e.source or "?", stealth_part,
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


-- Format the `+blocklist count` body. Two lines: total + by-source
-- breakdown sorted by source name.
local function format_count( )
    local c = blocklist.count( )
    local lines = { msg_show_header, "" }
    lines[ #lines + 1 ] = "  " .. utf_format( msg_count, c.total )
    -- Sorted to give a deterministic display order across runs.
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


------------------
--[ADC HANDLERS]--
------------------

-- Single ADC command + 6 verbs dispatched here. The verb is the
-- first whitespace-token; everything after it is the verb's args.
local function on_blocklist( user, command, parameters )
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
        -- 3-arg reply = DMSG (private hubbot PM); the list can be
        -- long and AirDC++ shows multi-line DMSG correctly, BMSG
        -- truncates with some clients (#81 testhub feedback).
        user:reply( format_show( source_filter ), hub_getbot( ), hub_getbot( ) )

    elseif verb == "count" then
        user:reply( format_count( ), hub_getbot( ), hub_getbot( ) )

    elseif verb == "add" then
        local args, perr = parse_add_args( rest )
        if not args then
            user:reply( perr, hub_getbot( ) )
            return PROCESSED
        end
        -- Strip control bytes from the operator-supplied reason
        -- BEFORE it reaches the engine. Consistency with the
        -- import path's _sanitize_import_row + with sibling
        -- etc_clientblocker; defence-in-depth so a reason
        -- containing literal \r / \n / NUL cannot pollute the
        -- on-disk .tbl or the rolled-back +blocklist show output.
        local clean_reason = args.reason and util_strip( args.reason ) or nil
        local ok, _id_or_err, msg = do_add_entry( args.cidr, {
            stealth = args.stealth,
            reason  = clean_reason,
            expires = args.expires,
        }, user_nick, user_level )
        user:reply( msg, hub_getbot( ) )
        if ok then
            if report then
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "blocklist.add", user, nil, args.reason, {
                cidr    = args.cidr,
                source  = "manual",
                stealth = args.stealth and true or false,
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
            -- The entry's reason (captured at add time) is the
            -- contextual "why" for this remove event - per cmd_ban
            -- audit convention, surface it as the reason field.
            audit.fire( audit.build( "blocklist.remove", user, nil,
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
                -- Same cfg-driven quadruple as add/del so an
                -- operator who disables `etc_blocklist_report`
                -- silences export/import too. Force-on op-chat
                -- on hard-coded args would be a confusing
                -- partial-respect-cfg state.
                report.send( report_activate, report_hubbot, report_opchat,
                    report_llevel, msg )
            end
            audit.fire( audit.build( "blocklist.export", user, nil, nil, {
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
            audit.fire( audit.build( "blocklist.import", user, nil, nil, {
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
-- #78 Phase C: HTTP API mirrors the ADC surface via the four
-- endpoints below. Registered via raw `hub.http_register`
-- (NOT `util_http.http_register_user_action`) because a blocklist
-- entry's identity is a CIDR / integer id, not a user SID -
-- `util_http`'s SID preflight would not apply.
--
-- HTTP admin-token requests do NOT carry an operator level (only
-- a token label). The plan's §1a.6 line "POST source=geoip from
-- admin token: ALLOW (token IS the gate)" locks the trust model:
-- the token is a policy-fully-trusted actor. Concretely, the
-- HTTP path skips Phase B's `do_del_entry` hierarchy guard by
-- passing a synthetic `actor_level = 100` (master) so a token
-- can undo ANY entry regardless of who added it. Operators who
-- want tighter control on HTTP-driven removes gate at the
-- token-scope layer, not the entry-level layer.

-- Precomputed enum-set of accepted `source` values on POST.
-- Kept in sync with core/blocklist.lua's `_SOURCE_PRIORITY`
-- table. Adding a new source (Phase D/E/F) means updating BOTH
-- here (the wire schema) and the priority table (the runtime
-- decision).
local _SOURCE_ENUM = { "manual", "geoip", "external",
    "proxycheck", "ipqs", "vpnapi" }

-- #264 filter/sort spec for GET /v1/blocklist. All rows are
-- pre-listed via blocklist.list() so http_filter sees a stable
-- shape; there's no lazy-projection layer between engine and
-- HTTP wire.
local _list_filter_spec = {
    string_fields = {
        source  = function( e ) return e.source  or "" end,
        by_nick = function( e ) return e.by_nick or "" end,
        reason  = function( e ) return e.reason  or "" end,
        -- cidr as substring-match string field per cmd_ban
        -- convention (bans use `nick`/`cid`/`ip` as string
        -- fields, not `nick_contains` etc). An operator typing
        -- `?cidr=192.0.2` narrows to that subnet family without
        -- reasoning about buckets.
        cidr    = function( e ) return e.cidr or "" end,
    },
    boolean_fields = {
        -- Strict boolean-typed field: query must be literal
        -- "true" / "false" (not substring). Wrong value ->
        -- 400 E_BAD_INPUT from http_filter directly, saving
        -- operator debug cycles vs an empty-200 silent-drop
        -- if we modelled this as a string-substring field.
        stealth = function( e ) return e.stealth and true or false end,
    },
    integer_fields = {
        by_level   = function( e ) return tonumber( e.by_level ) or 0 end,
        created_at = function( e ) return tonumber( e.created_at ) or 0 end,
        -- expires_at as integer supports both point-in-time
        -- filtering (`?expires_at=1735689600`) and range
        -- (`?expires_at_min=...&expires_at_max=...`) per
        -- http_filter's integer-field default.
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

-- Format a blocklist entry for wire output. `list()` already
-- returns a copy of the entry with a shallow-copied meta table -
-- we just rebrand the fields in the wire-canonical order and
-- drop internals (network_bytes, _network_b64, family). meta is
-- forwarded verbatim so future Phase D/E/F sources can surface
-- their per-source metadata (country code, feed name, api
-- provider, ...) through the same envelope.
local function _format_entry_for_wire( e )
    return {
        id         = e.id,
        cidr       = e.cidr,
        source     = e.source,
        stealth    = e.stealth and true or false,
        reason     = e.reason or "",
        by_nick    = e.by_nick or "",
        by_level   = e.by_level,
        expires_at = e.expires_at,
        created_at = e.created_at,
        meta       = e.meta,
    }
end


local http_handler_list_entries = function( req )
    local raw = blocklist.list( )    -- full snapshot; no filter here
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
    -- blocklist.count() returns { total, by_source = {...} }.
    -- Surface as-is; the shape is already prometheus-friendly
    -- (flat integer scalar + per-source integer map).
    --
    -- dkjson would emit an EMPTY Lua table as JSON array `[]`
    -- (its default for tables with no string keys). Callers with
    -- typed decoders reading `by_source` as an object would break
    -- on a fresh install. Force object shape via dkjson's
    -- __jsontype hint so the empty case wires as `{}`.
    local c = blocklist.count( )
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
    local stealth = body.stealth and true or false
    local expires_at = body.expires_at    -- schema-forced number|nil

    local actor_label = util_strip( req.token_label or "http-api" )

    -- Call blocklist.add directly (bypassing the ADC-oriented
    -- `do_add_entry` helper) because HTTP callers supply all
    -- fields we need in one shot - `source`, `stealth`, `reason`,
    -- and a raw `expires_at` unix ts (not the ADC's YYYY-MM-DD
    -- date string). Going straight to the engine avoids a
    -- remove-then-re-add dance to override defaults set by
    -- do_add_entry, and keeps do_add_entry as the ADC-specific
    -- convenience wrapper (source=manual, expires date parsing).
    --
    -- HTTP admin-token trust model: `by_level = 100` (master) so
    -- a subsequent DELETE by the same token bypasses Phase B's
    -- hierarchy guard. Documented in the header block.
    local ok, id, engine_err = blocklist.add( cidr, {
        source     = source,
        stealth    = stealth,
        reason     = reason,
        by_nick    = actor_label,
        by_level   = 100,
        expires_at = expires_at,
    } )
    if not ok then
        local err_s = tostring( engine_err or "" )
        -- Save-failure (disk I/O / permission) is a server-side
        -- condition, not caller input; map to 500 E_INTERNAL per
        -- HTTP_API.md envelope convention. Everything else is a
        -- caller-input rejection (bad CIDR, host-bits-set, etc).
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
    -- Reason may have gone in nil; ADC-path lang literal
    -- surfaces "" for empty. Mirror it on the HTTP `msg` used
    -- for the opchat + audit trail so operator-facing output
    -- stays consistent between the two entry paths.
    local stealth_label = stealth and "yes" or "no"
    local msg = utf_format( msg_added,
        actor_label, id, cidr, source, stealth_label )
    if report then
        report.send( report_activate, report_hubbot, report_opchat,
            report_llevel, msg )
    end
    audit.fire( audit.build( "blocklist.add",
        { nick = actor_label, sid = "<http>" }, nil, reason, {
            cidr     = cidr,
            source   = source,
            stealth  = stealth,
            id       = id,
            -- Record the synthetic master attribution so an
            -- operator reading the audit trail can distinguish
            -- HTTP-token-created entries from ADC-master-created
            -- ones; ADC path fires this same event with no
            -- by_level in meta (the actor's real level lives on
            -- the actor snapshot).
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
    -- Level 100 (master) → hierarchy guard passes for any entry.
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
    audit.fire( audit.build( "blocklist.remove",
        { nick = actor_label, sid = "<http>" }, nil, entry.reason, {
            id     = id,
            cidr   = entry.cidr,
            source = entry.source,
        } ) )
    -- Defence-in-depth control-byte strip on the wire response.
    -- Every ingest path (ADC add, JSONL import) already strips at
    -- insertion time, so entries in the store are clean; the
    -- strip here guards against future ingest paths that skip
    -- the sanitisation.
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
        assert( hubcmd.add( cmd_main, on_blocklist, oplevel ) )

        -- #78 Phase C HTTP API. Raw hub.http_register (target is
        -- CIDR / id, not SID; util_http.http_register_user_action
        -- does not apply). Schema field names use the `min`/`max`
        -- convention (#277 catch, not `minimum`/`maximum`).
        if hub.http_register then
            hub.http_register( "GET", "/v1/blocklist", "read",
                http_handler_list_entries, {
                    plugin = scriptname,
                    description = "list blocklist entries (= ADC `+blocklist show`); supports filter (source, stealth, cidr_contains, reason_contains, by_nick, by_level, created_at, expires_at) + sort + pagination via the standard http_filter convention",
                    response_schema = {
                        entries = { type = "array", required = true },
                    },
                } )
            hub.http_register( "GET", "/v1/blocklist/counts", "read",
                http_handler_get_counts, {
                    plugin = scriptname,
                    description = "counts summary (= ADC `+blocklist count`); prometheus + WebUI dashboard friendly",
                    response_schema = {
                        total     = { type = "integer", required = true },
                        by_source = { type = "object",  required = true },
                    },
                } )
            hub.http_register( "POST", "/v1/blocklist", "admin",
                http_handler_create_entry, {
                    plugin = scriptname,
                    description = "add a blocklist entry (= ADC `+blocklist add`); body `{cidr, stealth?, source?, reason?, expires_at?}`. source enum locks to the Phase-A priority set; expires_at is a unix timestamp (integer). CIDRs with host bits set are rejected (`1.2.3.4/24` -> use `1.2.3.0/24`).",
                    request_schema = {
                        cidr    = { type = "string",  required = true,  max_length = 45 },
                        stealth = { type = "boolean", required = false },
                        source  = { type = "string",  required = false, enum = _SOURCE_ENUM },
                        reason  = { type = "string",  required = false, max_length = 256 },
                        -- 2^31 = 2038-01-19; well beyond current
                        -- cfg horizons and fits in Lua 5.4 int on
                        -- any platform. `min = 1` bans the epoch
                        -- 0 UX trap (immediately-expired entry);
                        -- callers wanting permanent entries omit
                        -- the field.
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
            hub.http_register( "DELETE", "/v1/blocklist/{id}", "admin",
                http_handler_delete_entry, {
                    plugin = scriptname,
                    description = "remove a blocklist entry by numeric id (= ADC `+blocklist del <id>`). Ids are stable across the store lifetime (assigned monotonically); a re-add gets a fresh id. HTTP admin tokens bypass the ADC-side hierarchy guard - the token is the trust surface.",
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
    _parse_add_args             = parse_add_args,
    _parse_expires_date         = parse_expires_date,
    _do_add_entry               = do_add_entry,
    _do_del_entry               = do_del_entry,
    _do_export_jsonl            = do_export_jsonl,
    _do_import_jsonl            = do_import_jsonl,
    _sanitize_import_row        = _sanitize_import_row,
    _format_show                = format_show,
    _format_count               = format_count,
    _http_handler_list_entries  = http_handler_list_entries,
    _http_handler_get_counts    = http_handler_get_counts,
    _http_handler_create_entry  = http_handler_create_entry,
    _http_handler_delete_entry  = http_handler_delete_entry,
    _list_filter_spec           = _list_filter_spec,
    _SOURCE_ENUM                = _SOURCE_ENUM,
}
