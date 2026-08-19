--[[

    tests/unit/etc_whitelist_test.lua

    Unit tests for scripts/etc_whitelist.lua (#78 allowlist, Phase B).

    Coverage:
      - parse_add_args: cidr-only, reason="quoted", expires=YYYY-MM-DD,
                        both options; the quoted/unquoted isolation
      - parse_expires_date: YYYY-MM-DD -> end-of-day ts, bad -> nil
      - do_add_entry: happy, bad cidr surfaces engine err, bad expires
      - do_del_entry: not_found, hierarchy block, happy
      - _sanitize_import_row: control-byte stripping on every field
      - format_show / format_count: basic shape
      - seed_if_first_run: seeds the bundled pingers on a MISSING store,
                           seeds nothing when the store exists, and
                           nothing when etc_whitelist_seed=false
      - export/import JSONL round-trip (manual entries)

    The core whitelist engine is stubbed with an in-memory list so the
    test isolates the plugin's mutation/dispatch logic from the Phase A
    matcher (which has its own test file).

    Run: lua5.4 tests/unit/etc_whitelist_test.lua

]]--

----------------------------------------------------------------------
-- In-memory whitelist-engine stub + virtual FS for the seed probe /
-- export-import round-trip.
----------------------------------------------------------------------

local _entries, _next_id
local _vfs = { }          -- path -> string ("exists" marker or file body)
local _vfs_active = true

local function _reset_engine( )
    _entries, _next_id = { }, 1
end
_reset_engine( )

_G.whitelist = {
    add = function( cidr, opts )
        if type( cidr ) ~= "string" or cidr == "" then return false, nil, "bad cidr" end
        if cidr:find( "INVALID" ) then return false, nil, "synthetic-bad" end
        opts = opts or { }
        local e = {
            id = _next_id, cidr = cidr, source = opts.source or "manual",
            reason = opts.reason or "", by_nick = opts.by_nick,
            by_level = opts.by_level, expires_at = opts.expires_at,
            created_at = 1000,
        }
        _entries[ #_entries + 1 ] = e
        _next_id = _next_id + 1
        return true, e.id
    end,
    remove = function( id )
        for i, e in ipairs( _entries ) do
            if e.id == id then table.remove( _entries, i ); return true end
        end
        return false, "not_found"
    end,
    list = function( filter )
        filter = filter or { }
        local out = { }
        for _, e in ipairs( _entries ) do
            if ( not filter.source ) or e.source == filter.source then
                out[ #out + 1 ] = {
                    id = e.id, cidr = e.cidr, source = e.source,
                    reason = e.reason, by_nick = e.by_nick, by_level = e.by_level,
                    expires_at = e.expires_at, created_at = e.created_at,
                }
            end
        end
        return out
    end,
    count = function( )
        local by_source = { }
        for _, e in ipairs( _entries ) do
            by_source[ e.source ] = ( by_source[ e.source ] or 0 ) + 1
        end
        return { total = #_entries, by_source = by_source }
    end,
}

----------------------------------------------------------------------
-- Sandbox-global stubs.
----------------------------------------------------------------------

local _cfg_overrides = { }
local _listeners = { }         -- captured hub.setlistener callbacks
local _http_routes = { }       -- captured hub.http_register registrations
_G.hub = {
    setlistener = function( ev, _opts, fn ) _listeners[ ev ] = fn end,
    debug = function( ) end,
    getbot = function( ) return "stub-bot" end,
    http_register = function( method, path, scope, handler, meta )
        _http_routes[ method .. " " .. path ] = { scope = scope, handler = handler, meta = meta }
    end,
    import = function( name )
        if name == "etc_hubcommands" then
            return { add = function( ) return true end, has = function( ) return false end,
                     list = function( ) return { } end }
        end
        if name == "etc_report" then
            return { send = function( ) end }
        end
        return nil
    end,
}

-- Minimal http_filter stub: source-filter emulation, pass-through
-- otherwise (real filter/sort/paginate is core/http_filter's own test).
_G.http_filter = {
    apply = function( query, spec, rows )
        if query and query.source and query.source ~= "" then
            local filtered = { }
            for _, e in ipairs( rows ) do
                if e.source == query.source then filtered[ #filtered + 1 ] = e end
            end
            rows = filtered
        end
        return true, rows, { total = #rows, limit = 100, offset = 0 }, nil
    end,
}

-- audit stub: capture fired events for the HTTP create/delete assertions.
local _audit_fired = { }
_G.audit = {
    build = function( action, actor, target, reason, meta )
        return { action = action, actor = actor, reason = reason, meta = meta }
    end,
    fire = function( ev ) _audit_fired[ #_audit_fired + 1 ] = ev end,
}
_G.setmetatable = setmetatable

_G.cfg = {
    get = function( key )
        if _cfg_overrides[ key ] ~= nil then return _cfg_overrides[ key ] end
        if key == "language" then return "en" end
        if key == "etc_whitelist_oplevel" then return 80 end
        if key == "etc_whitelist_show_limit" then return 200 end
        if key == "etc_whitelist_seed" then return true end
        if key == "etc_whitelist_report" then return true end
        if key == "etc_whitelist_report_hubbot" then return false end
        if key == "etc_whitelist_report_opchat" then return true end
        if key == "etc_whitelist_llevel" then return 60 end
        if key == "etc_whitelist_import_min_level" then return 100 end
        if key == "whitelist_store_path" then return "scripts/data/etc_whitelist.tbl" end
        return nil
    end,
    loadlanguage = function( ) return { }, nil end,
}

_G.util = {
    strip_control_bytes = function( s )
        if type( s ) ~= "string" then return s end
        return ( s:gsub( "[%c]", "" ) )
    end,
    safe_path = function( p )
        if type( p ) ~= "string" or p == "" then return false, "empty path" end
        if p:find( "%.%." ) then return false, "parent-dir blocked" end
        return true
    end,
}

_G.utf = { match = string.match, format = string.format }
_G.PROCESSED = 1
_G.dkjson = require and nil    -- resolved below

-- Load the real dkjson if available; else provide a tiny stub so the
-- export/import round-trip test still exercises the plugin logic.
do
    local ok, mod = pcall( dofile, "dkjson/dkjson.lua" )
    if ok and type( mod ) == "table" then
        _G.dkjson = mod
    else
        -- Minimal JSON good enough for the flat rows we encode/decode.
        _G.dkjson = {
            encode = function( t )
                local parts = { }
                for k, v in pairs( t ) do
                    local vs
                    if type( v ) == "string" then vs = string.format( "%q", v )
                    elseif type( v ) == "number" then vs = tostring( v )
                    else vs = "null" end
                    parts[ #parts + 1 ] = string.format( "%q:%s", k, vs )
                end
                return "{" .. table.concat( parts, "," ) .. "}"
            end,
            decode = function( s )
                local t = { }
                for k, v in s:gmatch( '"([^"]-)":"([^"]-)"' ) do t[ k ] = v end
                for k, v in s:gmatch( '"([^"]-)":(%-?%d+)' ) do t[ k ] = tonumber( v ) end
                if next( t ) == nil then return nil, nil, "empty" end
                return t
            end,
        }
    end
end

-- io.open VFS: read-mode succeeds iff the path is in _vfs; write-mode
-- captures bytes into _vfs on close. Used for the seed-probe (store
-- present vs missing) and export/import round-trip.
local _real_io_open = io.open
io.open = function( path, mode )
    if not _vfs_active then return _real_io_open( path, mode ) end
    mode = mode or "r"
    if mode:find( "w" ) then
        local buf = { }
        local handle
        handle = {
            write = function( _self, ... )
                for _, s in ipairs{ ... } do buf[ #buf + 1 ] = tostring( s ) end
                return handle
            end,
            close = function( ) _vfs[ path ] = table.concat( buf ) end,
        }
        return handle
    end
    local content = _vfs[ path ]
    if not content then return nil, "No such file or directory" end
    local pos = 1
    local handle
    handle = {
        read = function( _self, fmt )
            if fmt == "*l" or fmt == "l" then
                if pos > #content then return nil end
                local nl = content:find( "\n", pos, true )
                local line
                if nl then line = content:sub( pos, nl - 1 ); pos = nl + 1
                else line = content:sub( pos ); pos = #content + 1 end
                return line
            end
        end,
        close = function( ) end,
    }
    return handle
end

local function load_plugin( )
    return assert( loadfile( "scripts/etc_whitelist.lua" ) )( )
end
local wl = load_plugin( )

----------------------------------------------------------------------
-- Tiny harness
----------------------------------------------------------------------

local _passes, _fails = 0, 0
local function eq( what, got, want )
    if got == want then _passes = _passes + 1
    else _fails = _fails + 1
        io.stderr:write( string.format( "FAIL: %s\n  got:  %s\n  want: %s\n",
            what, tostring( got ), tostring( want ) ) ) end
end
local function truthy( what, v )
    if v then _passes = _passes + 1
    else _fails = _fails + 1; io.stderr:write( "FAIL: " .. what .. "\n" ) end
end

----------------------------------------------------------------------
-- parse_add_args
----------------------------------------------------------------------

do
    local a = wl._parse_add_args( "1.2.3.0/24" )
    truthy( "parse cidr-only", a )
    eq( "parse cidr", a and a.cidr, "1.2.3.0/24" )
    eq( "parse no reason", a and a.reason, nil )

    local b = wl._parse_add_args( '10.0.0.0/8 reason="trusted vpn"' )
    eq( "parse quoted reason cidr", b and b.cidr, "10.0.0.0/8" )
    eq( "parse quoted reason", b and b.reason, "trusted vpn" )

    local c = wl._parse_add_args( "9.9.9.9 expires=2027-01-01" )
    eq( "parse expires cidr", c and c.cidr, "9.9.9.9" )
    eq( "parse expires", c and c.expires, "2027-01-01" )

    local d = wl._parse_add_args( '5.5.5.5 reason="a b" expires=2027-06-30' )
    eq( "parse both reason", d and d.reason, "a b" )
    eq( "parse both expires", d and d.expires, "2027-06-30" )

    eq( "parse empty -> nil", wl._parse_add_args( "" ), nil )
end

----------------------------------------------------------------------
-- parse_expires_date
----------------------------------------------------------------------

do
    truthy( "expires valid -> ts", wl._parse_expires_date( "2027-12-31" ) )
    eq( "expires bad -> nil", wl._parse_expires_date( "nope" ), nil )
    eq( "expires empty -> nil", wl._parse_expires_date( "" ), nil )
end

----------------------------------------------------------------------
-- do_add_entry
----------------------------------------------------------------------

_reset_engine( )
do
    local ok, id, msg = wl._do_add_entry( "1.2.3.0/24", { reason = "r" }, "opnick", 80 )
    eq( "add ok", ok, true )
    truthy( "add id", id )
    truthy( "add msg mentions manual", msg and msg:find( "manual" ) )

    local ok2, code2 = wl._do_add_entry( "INVALIDcidr", { }, "opnick", 80 )
    eq( "add bad cidr false", ok2, false )
    eq( "add bad cidr code", code2, "bad_cidr" )

    local ok3, code3 = wl._do_add_entry( "1.2.3.4", { expires = "not-a-date" }, "opnick", 80 )
    eq( "add bad expires false", ok3, false )
    eq( "add bad expires code", code3, "bad_expires" )
end

----------------------------------------------------------------------
-- do_del_entry: not_found, hierarchy, happy
----------------------------------------------------------------------

_reset_engine( )
do
    -- entry added by a level-100 master
    wl._do_add_entry( "10.10.0.0/16", { }, "master", 100 )
    local rows = wl._do_add_entry and _entries    -- direct id lookup
    local master_id = _entries[ 1 ].id

    -- level-80 op cannot remove the master's entry
    local ok, code = wl._do_del_entry( master_id, "lowop", 80 )
    eq( "hierarchy blocks lower op", ok, false )
    eq( "hierarchy code", code, "hierarchy" )

    -- not found
    local ok2, code2 = wl._do_del_entry( 99999, "master", 100 )
    eq( "del not_found false", ok2, false )
    eq( "del not_found code", code2, "not_found" )

    -- master can remove
    local ok3 = wl._do_del_entry( master_id, "master", 100 )
    eq( "master removes own entry", ok3, true )
    eq( "count after del", wl._format_count and #_entries, 0 )
end

----------------------------------------------------------------------
-- _sanitize_import_row: control-byte strip
----------------------------------------------------------------------

do
    local cidr, opts = wl._sanitize_import_row{
        cidr = "1.2.3.0/24\r\n", reason = "clean\1reason", source = "pin\2ger",
        by_nick = "op\3", by_level = 80, expires_at = 12345,
    }
    eq( "sanitize cidr stripped", cidr, "1.2.3.0/24" )
    eq( "sanitize reason stripped", opts.reason, "cleanreason" )
    eq( "sanitize source stripped", opts.source, "pinger" )
    eq( "sanitize by_nick stripped", opts.by_nick, "op" )
    eq( "sanitize by_level", opts.by_level, 80 )

    local nilcidr = wl._sanitize_import_row{ reason = "x" }
    eq( "sanitize missing cidr nil", nilcidr, nil )
end

----------------------------------------------------------------------
-- format_show / format_count shape
----------------------------------------------------------------------

_reset_engine( )
do
    wl._do_add_entry( "1.2.3.0/24", { reason = "trusted" }, "op", 80 )
    local show = wl._format_show( nil )
    truthy( "show has header", show:find( "WHITELIST" ) )
    truthy( "show lists the cidr", show:find( "1.2.3.0/24" ) )
    truthy( "show shows source", show:find( "src=manual" ) )

    local empty = wl._format_show( "nosuchsource" )
    truthy( "show filtered-empty", empty:find( "no entries" ) )

    local cnt = wl._format_count( )
    truthy( "count total line", cnt:find( "1 entries total" ) )
    truthy( "count by-source", cnt:find( "manual: 1" ) )
end

----------------------------------------------------------------------
-- seed_if_first_run: missing store -> seeds pingers; existing -> 0;
-- disabled -> 0.
----------------------------------------------------------------------

do
    local SP = "scripts/data/etc_whitelist.tbl"

    -- 1) store MISSING -> seed the bundled pingers
    _reset_engine( )
    _vfs = { }                       -- store file absent
    wl = load_plugin( )              -- re-read cfg (seed=true)
    local n = wl._seed_if_first_run( )
    eq( "seed count == bundled size", n, #wl._BUNDLED_SEED )
    eq( "engine now holds the seed", #_entries, #wl._BUNDLED_SEED )
    local all_pinger = true
    for _, e in ipairs( _entries ) do if e.source ~= "pinger" then all_pinger = false end end
    truthy( "all seeded entries source=pinger", all_pinger )

    -- 2) store EXISTS -> no seed
    _reset_engine( )
    _vfs = { [ SP ] = "x" }          -- store present
    wl = load_plugin( )
    eq( "existing store -> seed 0", wl._seed_if_first_run( ), 0 )
    eq( "existing store -> no entries added", #_entries, 0 )

    -- 3) seed disabled -> no seed even if missing
    _reset_engine( )
    _vfs = { }
    _cfg_overrides = { etc_whitelist_seed = false }
    wl = load_plugin( )
    eq( "seed disabled -> 0", wl._seed_if_first_run( ), 0 )
    _cfg_overrides = { }
    wl = load_plugin( )
end

----------------------------------------------------------------------
-- export / import JSONL round-trip (manual entries only)
----------------------------------------------------------------------

_reset_engine( )
do
    _vfs = { }
    wl = load_plugin( )
    wl._do_add_entry( "1.2.3.0/24", { reason = "op-added" }, "op", 100 )
    wl._do_add_entry( "9.9.9.9",    { }, "op", 100 )
    -- a pinger-sourced entry must NOT be exported
    _G.whitelist.add( "8.8.8.8", { source = "pinger", reason = "seed" } )

    local ok, count, path = wl._do_export_jsonl( "op" )
    eq( "export ok", ok, true )
    eq( "export count = manual only (2)", count, 2 )
    truthy( "export wrote file", _vfs[ path ] ~= nil )

    -- wipe + re-import
    _reset_engine( )
    local iok, stats = wl._do_import_jsonl( path, "master", 100 )
    eq( "import ok", iok, true )
    eq( "import added 2", stats.added, 2 )
    eq( "import 0 errors", stats.errors, 0 )
    eq( "engine holds re-imported entries", #_entries, 2 )

    -- import level guard
    local lok, lcode = wl._do_import_jsonl( path, "lowop", 80 )
    eq( "import below min_level rejected", lok, false )
    truthy( "import level err", lcode and lcode:find( "Import requires" ) )
end

----------------------------------------------------------------------
-- HTTP API (Phase D): registration + scope + schema + handler shapes
----------------------------------------------------------------------

_reset_engine( )
do
    _vfs = { }
    _cfg_overrides = { etc_whitelist_seed = false }   -- boot with an empty store
    wl = load_plugin( )
    assert( _listeners.onStart, "onStart not captured" )
    _listeners.onStart( )    -- register the routes

    -- registration + scope
    truthy( "http GET /v1/whitelist registered", _http_routes[ "GET /v1/whitelist" ] )
    truthy( "http GET counts registered", _http_routes[ "GET /v1/whitelist/counts" ] )
    truthy( "http POST registered", _http_routes[ "POST /v1/whitelist" ] )
    truthy( "http DELETE registered", _http_routes[ "DELETE /v1/whitelist/{id}" ] )
    eq( "http GET scope read", _http_routes[ "GET /v1/whitelist" ].scope, "read" )
    eq( "http POST scope admin", _http_routes[ "POST /v1/whitelist" ].scope, "admin" )
    eq( "http DELETE scope admin", _http_routes[ "DELETE /v1/whitelist/{id}" ].scope, "admin" )

    -- POST schema uses min/max (not minimum/maximum) + no stealth field
    local ps = _http_routes[ "POST /v1/whitelist" ].meta.request_schema
    eq( "http POST cidr required", ps.cidr.required, true )
    eq( "http POST cidr max_length", ps.cidr.max_length, 45 )
    truthy( "http POST source enum", ps.source.enum )
    eq( "http POST expires_at min", ps.expires_at.min, 1 )
    eq( "http POST no stealth field", ps.stealth, nil )

    -- create (happy)
    _reset_engine( )
    local rc = wl._http_handler_create_entry{
        body = { cidr = "203.0.113.0/24", source = "pinger", reason = "api",
                 expires_at = 2000000000 },
        token_label = "tok",
    }
    eq( "http create 201", rc.status, 201 )
    eq( "http create action added", rc.data.action, "added" )
    eq( "http create cidr echoed", rc.data.cidr, "203.0.113.0/24" )
    eq( "http create source echoed", rc.data.source, "pinger" )
    eq( "http create engine by_level 100", _entries[ 1 ].by_level, 100 )
    eq( "http create engine by_nick token", _entries[ 1 ].by_nick, "tok" )
    local la = _audit_fired[ #_audit_fired ]
    eq( "http create audit action", la and la.action, "whitelist.add" )
    eq( "http create audit by_level 100", la and la.meta and la.meta.by_level, 100 )

    -- create bad / missing cidr
    eq( "http create bad cidr 400",
        wl._http_handler_create_entry{ body = { cidr = "INVALIDx" }, token_label = "t" }.status, 400 )
    eq( "http create missing cidr 400",
        wl._http_handler_create_entry{ body = { }, token_label = "t" }.status, 400 )

    -- counts
    local rct = wl._http_handler_get_counts{ }
    eq( "http counts 200", rct.status, 200 )
    eq( "http counts total 1", rct.data.total, 1 )
    eq( "http counts by_source pinger 1", rct.data.by_source.pinger, 1 )

    -- list
    local rl = wl._http_handler_list_entries{ query = { } }
    eq( "http list 200", rl.status, 200 )
    truthy( "http list raw_body string", type( rl.raw_body ) == "string" )
    eq( "http list content_type", rl.content_type, "application/json; charset=utf-8" )

    -- delete (happy + not_found + bad id)
    local rd = wl._http_handler_delete_entry{ path_vars = { id = "1" }, token_label = "tok" }
    eq( "http delete 200", rd.status, 200 )
    eq( "http delete action removed", rd.data.action, "removed" )
    eq( "http delete not_found 404",
        wl._http_handler_delete_entry{ path_vars = { id = "9999" }, token_label = "t" }.status, 404 )
    eq( "http delete bad id 400",
        wl._http_handler_delete_entry{ path_vars = { id = "abc" }, token_label = "t" }.status, 400 )

    _cfg_overrides = { }
end

----------------------------------------------------------------------
-- #456: export/import failure reasons must be localized (rendered
-- through a lang template), not the raw English helper string. Lang is
-- empty here so the English fallbacks apply; the point is that the
-- FAILURE path renders msg_open_failed / msg_encode_failed at all
-- (pre-fix it returned the raw "open failed:" / "json.encode failed:").
----------------------------------------------------------------------

do
    _vfs = { }
    -- import a path not in the vfs -> io.open read returns nil -> the
    -- open-failed branch. Reason must be the template, not the raw one.
    local iok, ireason = wl._do_import_jsonl( "cfg/whitelist-missing.jsonl", "master", 100 )
    truthy( "#456 import open-fail: returns false", not iok )
    truthy( "#456 import open-fail: localized 'Could not open'",
        ireason and ireason:find( "Could not open", 1, true ) )
    truthy( "#456 import open-fail: raw 'open failed:' gone",
        not ( ireason and ireason:find( "open failed:", 1, true ) ) )

    -- export with a failing encoder -> the json-encode branch.
    wl._do_add_entry( "1.2.3.0/24", { reason = "r" }, "op", 100 )
    local saved = _G.dkjson.encode
    _G.dkjson.encode = function( ) return nil, "boom" end
    local eok, ereason = wl._do_export_jsonl( "op" )
    _G.dkjson.encode = saved
    truthy( "#456 export encode-fail: returns false", not eok )
    truthy( "#456 export encode-fail: localized 'JSON encode failed'",
        ereason and ereason:find( "JSON encode failed", 1, true ) )
    truthy( "#456 export encode-fail: raw 'json.encode failed:' gone",
        not ( ereason and ereason:find( "json.encode failed:", 1, true ) ) )
end

----------------------------------------------------------------------

if _fails > 0 then
    io.stderr:write( string.format( "\nFAIL: %d/%d checks failed\n", _fails, _passes + _fails ) )
    os.exit( 1 )
end
print( string.format( "OK: %d checks passed", _passes ) )
