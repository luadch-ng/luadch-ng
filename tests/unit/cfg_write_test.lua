--[==[

    tests/unit/cfg_write_test.lua

    Unit tests for core/cfg_write.lua (#644) - the surgical,
    comment/layout-preserving single-key cfg.tbl writer that cfg.set uses
    in place of the wholesale util.savetable, falling back to it on any
    failure.

    What matters, and why:

      1. A single-key change replaces ONLY that key's value; every comment,
         blank line, other key and the operator's bare-key `key = value`
         format is byte-preserved. This is the entire point of the module
         (an operator who edits one setting via the WebUI must not lose
         their hand-annotated cfg.tbl).
      2. A nested-table value (a level-keyed permission map) is replaced
         correctly and re-indented under its key.
      3. A key ABSENT from the file is appended before the closing brace,
         preserving every existing comment.
      4. The canonical already-rewritten form (`[ "key" ] = v`) is handled
         too, so a second edit of a previously wholesale-saved file still
         works.
      5. A `[[ long string ]]` value, and comments containing braces /
         commas / fake `key = value` text, do NOT fool the lexer - a
         neighbouring edit leaves them intact.
      6. THE SAFETY GATE: the rewritten text is accepted only if it
         re-parses (sandboxed) to a table deep-equal to the authoritative
         settings. A change the splice cannot reproduce, a duplicate
         top-level key (ambiguous), a lexically broken file, and an
         unreadable file each return nil (so cfg.set falls back to the
         proven wholesale save) and write NOTHING.

    Provably fails pre-fix (CLAUDE.md 1a.7): on master core/cfg_write.lua
    does not exist, so loadfile returns nil and the assert aborts - RED.
    Patched, all checks pass - GREEN. The behavioural assertions below
    would also fail a no-op or a mis-splicing implementation.

    Run: lua5.4 tests/unit/cfg_write_test.lua   (from repo root)
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]==]

----------------------------------------------------------------------
-- shim layer 1: load the REAL core/util.lua so serialize_value +
-- loadtable_string are genuine (the module reuses util's serialiser and
-- its sandboxed parser - a fake would not prove round-trip parity).
----------------------------------------------------------------------

local _dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

local _io_stub = {
    open = function( ) return nil, "no such file" end,   -- util never opens in these tests
}
local _adclib_stub = {
    isutf8 = function( ) return true end,
    random_bytes = function( ) return "x" end,
}
local _unicode_stub = {
    ascii = { sub = string.sub, gsub = string.gsub },
    utf8  = { format = string.format },
}
local _out_stub = { put = function( ) end, error = function( ) end }
local _mem_stub = { free = function( ) end }

local _util_deps = {
    type = type, load = load, table = table, pairs = pairs,
    pcall = pcall, select = select, ipairs = ipairs,
    tostring = tostring, tonumber = tonumber, loadfile = loadfile,
    setmetatable = setmetatable, getmetatable = getmetatable,
    io = _io_stub, math = math, string = string, os = os,
    package = package,
    adclib = _adclib_stub, unicode = _unicode_stub,
    out = _out_stub, mem = _mem_stub, dkjson = _dkjson,
}
_G.use = function( name )
    local v = _util_deps[ name ]
    assert( v ~= nil, "cfg_write_test util shim missing dep: use \"" .. name .. "\"" )
    return v
end

local util = assert( loadfile( "core/util.lua" ) )( )
util.init( )

----------------------------------------------------------------------
-- shim layer 2: load core/cfg_write.lua. util is a FACADE - real
-- serialize_value + loadtable_string, but atomic_write is captured and io
-- serves a virtual file - so the whole scan / splice / safety-gate path
-- runs in memory and we assert on the exact text that WOULD be written.
----------------------------------------------------------------------

local captured        -- content the module handed to atomic_write (nil = none)
local virtual_file    -- text the io stub serves as the existing cfg.tbl

local _cfgw_io = {
    open = function( )
        if virtual_file == nil then return nil, "no such file" end
        return {
            read  = function( ) return virtual_file end,
            close = function( ) end,
        }
    end,
}
local _util_facade = {
    serialize_value  = util.serialize_value,
    loadtable_string = util.loadtable_string,
    atomic_write     = function( _path, content ) captured = content; return true end,
}
local _cfgw_deps = {
    type = type, pairs = pairs, pcall = pcall, string = string,
    io = _cfgw_io, util = _util_facade,
}
_G.use = function( name )
    local v = _cfgw_deps[ name ]
    assert( v ~= nil, "cfg_write_test shim missing dep: use \"" .. name .. "\"" )
    return v
end

local cfgw = assert( loadfile( "core/cfg_write.lua" ) )( )

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function report( pass, label, extra )
    checks = checks + 1
    if pass then
        io.write( string.format( "ok   %s\n", label ) )
    else
        failures = failures + 1
        io.write( string.format( "FAIL %-58s %s\n", label, extra or "" ) )
    end
end
local function eq( label, got, want )
    report( got == want, label, "got=" .. tostring( got ) .. " want=" .. tostring( want ) )
end
local function has( label, hay, needle )
    report( type( hay ) == "string" and string.find( hay, needle, 1, true ) ~= nil,
        label, "missing: " .. needle )
end
local function hasnot( label, hay, needle )
    report( type( hay ) == "string" and string.find( hay, needle, 1, true ) == nil,
        label, "unexpectedly present: " .. needle )
end

-- Deep equality for the round-trip assertions (independent of the
-- module's own internal deep_equal).
local function deep_equal( a, b )
    if type( a ) ~= type( b ) then return false end
    if type( a ) ~= "table" then return a == b end
    for k, v in pairs( a ) do if not deep_equal( v, b[ k ] ) then return false end end
    for k in pairs( b ) do if a[ k ] == nil then return false end end
    return true
end

-- A representative operator-style cfg.tbl: bare keys, inline comments, a
-- scalar-array, a level-keyed map, a long-bracket multi-line value, and a
-- nasty comment carrying braces / commas / a fake `key = value`.
local CFG = [==[
return { -- root table, do not touch this line

    ---- Basic ----
    language = "en",  -- your language (string)
    hub_name = "My Hub",  -- name of the hub

    -- danger: a comment with { braces }, commas, and a fake key = value pair
    hub_owner = "me",  -- owner (string)

    ssl_ports = { 5001 },  -- ssl ports (integer array)

    cmd_ban_permission = {

        [ 0 ] = 0,
        [ 60 ] = 50,
        [ 100 ] = 100,

    },  -- ban up to level, by level

    msg_banner = [[
line one
line two
]],

}
]==]

local function parse( text )
    local fn = assert( load( text, "cfg", "t", { } ) )
    return fn( )
end

local function fresh( )    -- an independent parse of CFG per test
    return parse( CFG )
end

local function run( old_text, settings, key )
    virtual_file = old_text
    captured = nil
    local ret = cfgw.save_key( "cfg/cfg.tbl", settings, key )
    return ret, captured
end

----------------------------------------------------------------------
-- 1. change a scalar: only that value changes; comments + format kept
----------------------------------------------------------------------

do
    local s = fresh( )
    s.hub_name = "New Name"
    local ret, out = run( CFG, s, "hub_name" )
    eq( "scalar: save_key returned true", ret, true )
    has( "scalar: new value present",         out or "", 'hub_name = "New Name"' )
    has( "scalar: language comment kept",     out or "", "-- your language (string)" )
    has( "scalar: other key untouched",       out or "", 'language = "en"' )
    has( "scalar: own inline comment kept",   out or "", "-- name of the hub" )
    hasnot( "scalar: stays bare-key (no quoting)", out or "", '[ "hub_name" ]' )
    has( "scalar: root comment preserved",    out or "", "root table, do not touch this line" )
    if out then eq( "scalar: round-trips to settings", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 2. change a nested level-map value
----------------------------------------------------------------------

do
    local s = fresh( )
    s.cmd_ban_permission[ 60 ] = 99
    local ret, out = run( CFG, s, "cmd_ban_permission" )
    eq( "map: save_key returned true", ret, true )
    has( "map: changed entry present",        out or "", "[ 60 ] = 99" )
    has( "map: sibling entry present",        out or "", "[ 100 ] = 100" )
    has( "map: unrelated comment kept",       out or "", "-- your language (string)" )
    has( "map: banner long-string intact",    out or "", "line one\nline two" )
    if out then eq( "map: round-trips to settings", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 3. append an ABSENT key before the closing brace
----------------------------------------------------------------------

do
    local s = fresh( )
    s.max_users = 500
    local ret, out = run( CFG, s, "max_users" )
    eq( "append: save_key returned true", ret, true )
    has( "append: new key present (bare)",    out or "", "max_users = 500" )
    has( "append: existing comment kept",     out or "", "-- owner (string)" )
    has( "append: banner intact",             out or "", "line one\nline two" )
    if out then
        eq( "append: round-trips to settings", deep_equal( parse( out ), s ), true )
        -- the appended key must sit INSIDE the table (before the final brace)
        local body = string.match( out, "return%s*(%b{})" )
        has( "append: key is inside the root table", body or "", "max_users = 500" )
    end
end

----------------------------------------------------------------------
-- 4. canonical already-rewritten form ([ "key" ] = v) is handled
----------------------------------------------------------------------

do
    local CANON = 'local settings\n\nsettings = {\n\n    [ "a" ] = 1,\n    [ "b" ] = "x",\n\n}\n\nreturn settings\n'
    local s = { a = 2, b = "x" }
    local ret, out = run( CANON, s, "a" )
    eq( "canonical: save_key returned true", ret, true )
    has( "canonical: changed value present",  out or "", '[ "a" ] = 2' )
    has( "canonical: sibling preserved",      out or "", '[ "b" ] = "x"' )
    has( "canonical: envelope preserved",     out or "", "return settings" )
    if out then eq( "canonical: round-trips", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 4b. a leading UTF-8 BOM (the SHIPPED cfg.tbl carries one) must NOT
--     defeat the surgical path. The scanner tolerates the BOM; the trap
--     is the safety gate - load() does not skip a BOM, loadfile() does,
--     so util.loadtable_string must strip it or the gate rejects every
--     BOM'd file and silently falls back to the comment-stripping save.
--     Provably RED before that fix (save_key returns nil on BOM'd input).
----------------------------------------------------------------------

do
    local BOM = "\239\187\191"
    local s = fresh( )
    s.hub_name = "Bom Name"
    local ret, out = run( BOM .. CFG, s, "hub_name" )
    eq( "bom: save_key returned true", ret, true )
    has( "bom: new value present",       out or "", 'hub_name = "Bom Name"' )
    has( "bom: comment preserved",       out or "", "-- your language (string)" )
    if out then
        eq( "bom: BOM retained in output", string.sub( out, 1, 3 ), BOM )
        -- the written bytes (BOM included) must load to settings exactly as
        -- the runtime loadfile (which strips the BOM) will.
        local stripped = string.gsub( out, "^\239\187\191", "" )
        eq( "bom: round-trips (BOM-stripped parse)", deep_equal( parse( stripped ), s ), true )
    end
end

----------------------------------------------------------------------
-- 5. lexer robustness: a comment with braces/commas/fake-key does not
--    derail a neighbouring edit
----------------------------------------------------------------------

do
    local s = fresh( )
    s.hub_owner = "someone else"
    local ret, out = run( CFG, s, "hub_owner" )
    eq( "comment-trap: save_key returned true", ret, true )
    has( "comment-trap: value changed",        out or "", 'hub_owner = "someone else"' )
    has( "comment-trap: nasty comment intact", out or "", "a fake key = value pair" )
    if out then eq( "comment-trap: round-trips", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 6. SAFETY GATE: a change the single-key splice cannot reproduce is
--    rejected (deep-equal fails) -> nil, nothing written
----------------------------------------------------------------------

do
    local s = fresh( )
    s.hub_name = "New Name"
    s.language = "de"                 -- a SECOND divergence the splice of hub_name won't reflect
    local ret, out = run( CFG, s, "hub_name" )
    eq( "gate-mismatch: save_key returned nil", ret, nil )
    eq( "gate-mismatch: nothing written",       out, nil )
end

----------------------------------------------------------------------
-- 7. ambiguous: editing a key that appears TWICE at top level -> the
--    scan bails (which value span is authoritative is undecidable) ->
--    nil, nothing written. (Editing a NON-duplicated key in the same
--    file stays fine - the splice is unambiguous and the gate verifies -
--    so ambiguity is only rejected for the TARGET key.)
----------------------------------------------------------------------

do
    local DUP = "return {\n    x = 1,\n    y = 2,\n    x = 3,\n}\n"
    local s = parse( DUP )    -- Lua keeps the last x -> { x = 3, y = 2 }
    s.x = 5
    local ret, out = run( DUP, s, "x" )
    eq( "ambiguous: save_key returned nil", ret, nil )
    eq( "ambiguous: nothing written",       out, nil )
end

----------------------------------------------------------------------
-- 8. lexically broken file (unterminated string) -> nil, nothing written
----------------------------------------------------------------------

do
    local BROKEN = 'return {\n    hub_name = "unterminated,\n    x = 1,\n}\n'
    local ret, out = run( BROKEN, { hub_name = "y", x = 1 }, "x" )
    eq( "broken: save_key returned nil", ret, nil )
    eq( "broken: nothing written",       out, nil )
end

----------------------------------------------------------------------
-- 9. unreadable file -> nil, nothing written
----------------------------------------------------------------------

do
    local ret, out = run( nil, { x = 1 }, "x" )   -- virtual_file nil => io.open returns nil
    eq( "unreadable: save_key returned nil", ret, nil )
    eq( "unreadable: nothing written",       out, nil )
end

----------------------------------------------------------------------
-- 10. append when the LAST field has NO trailing comma: a comma must be
--     added after that field's value (before its inline comment) so the
--     result is valid Lua. Provably RED before the trailing-comma fix
--     (append produced two adjacent fields with no separator -> gate nil).
----------------------------------------------------------------------

do
    local NOCOMMA = "return {\n\n    a = 1,  -- first\n    b = 2  -- last (no trailing comma)\n}\n"
    local s = parse( NOCOMMA )
    s.c = 3
    local ret, out = run( NOCOMMA, s, "c" )
    eq( "nocomma: save_key returned true", ret, true )
    has( "nocomma: comma added after last field", out or "", "b = 2,  -- last (no trailing comma)" )
    has( "nocomma: appended key present",         out or "", "c = 3" )
    has( "nocomma: first comment preserved",      out or "", "-- first" )
    if out then eq( "nocomma: round-trips", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 11. append edge cases: an empty table, and a reserved-word key
--     (must fall back to the bracketed [ "end" ] = ... form)
----------------------------------------------------------------------

do
    local s = { only = 1 }
    local ret, out = run( "return {}\n", s, "only" )
    eq( "empty-table: save_key returned true", ret, true )
    has( "empty-table: key inserted", out or "", "only = 1" )
    if out then eq( "empty-table: round-trips", deep_equal( parse( out ), s ), true ) end
end

do
    local s = fresh( )
    s[ "end" ] = 7            -- a Lua reserved word: bare `end = 7` is illegal
    local ret, out = run( CFG, s, "end" )
    eq( "reserved-key: save_key returned true", ret, true )
    has( "reserved-key: bracketed form used", out or "", '[ "end" ] = 7' )
    if out then eq( "reserved-key: round-trips", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- 12. edit a key in a SEMICOLON-separated table (Lua allows ; as a field
--     separator). Provably RED before the ';' terminator fix (the value
--     span over-ran to the closing brace -> gate mismatch -> nil).
----------------------------------------------------------------------

do
    local SEMI = "return {\n    a = 1;\n    b = 2;\n}\n"
    local s = parse( SEMI )
    s.a = 9
    local ret, out = run( SEMI, s, "a" )
    eq( "semicolon: save_key returned true", ret, true )
    has( "semicolon: value changed",   out or "", "a = 9" )
    has( "semicolon: sibling intact",   out or "", "b = 2" )
    if out then eq( "semicolon: round-trips", deep_equal( parse( out ), s ), true ) end
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
