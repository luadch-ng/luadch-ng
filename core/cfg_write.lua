--[==[

    core/cfg_write.lua - surgical, comment/layout-preserving single-key
    cfg.tbl writer (#644).

    The wholesale save path (cfg.set -> util.savetable -> sortserialize)
    rebuilds the ENTIRE cfg.tbl from the in-memory _settings table on every
    change: it strips the operator's comments, re-sorts the keys, quotes
    bare keys (`key = v` -> `[ "key" ] = v`) and swaps the `return { ... }`
    envelope for `local settings; settings = { ... }; return settings`. An
    operator who edits one setting via the WebUI loses their whole
    hand-annotated file. This module preserves it.

    Mechanism (single-key change):
      1. read the existing cfg.tbl TEXT,
      2. a char-stream scanner (never executes the file - it is a pure
         lexer, cf. the untrusted-config recogniser #531) locates the
         target key's VALUE span in the top-level table, skipping strings,
         comments and nested braces, matching both bare `key =` and
         `[ "key" ] =` forms,
      3. splice the newly serialised value (via util.serialize_value, the
         SAME serialiser the wholesale path uses, so the result round-trips
         identically) into that span; when the key is absent, append
         `    key = value,` before the table's closing brace,
      4. SAFETY GATE: re-parse the spliced text sandboxed (util.loadtable_
         string, env = {}, non-executing) and accept it ONLY if it
         deep-equals the authoritative _settings table,
      5. atomic_write.

    Any failure (unreadable file, lexer bail, key ambiguous, parse
    mismatch, write error) returns nil so the caller (cfg.set) falls back
    to the proven wholesale util.savetable. The accept-gate is what makes
    this safe: a mis-scan can only ever produce text that fails to parse or
    parses to a DIFFERENT table, both of which are rejected. The worst case
    is the current behaviour (comments lost), never a corrupted config.

    Scope: only the cfg.set save path. Other util.savetable users (plugin
    state, user.tbl) are untouched.

    Known limitations (each degrades SAFELY to the wholesale fallback, or is
    a cosmetic-only normalisation of the ONE edited key - never a data risk):
      - a `\z` (skip-whitespace) escape spanning a newline inside a short
        string makes the lexer bail -> wholesale save (no cfg value uses it);
      - inner-table rows are re-indented at 4 spaces, so editing a table
        value in a tab-/2-space-indented file does not match its indent unit;
      - editing a `[[ long-bracket ]]` string value rewrites it to a "%q"
        quoted literal (one serialiser); the value round-trips identically.

    Passive at load (no init(), no file I/O at require time).

]==]

local use = use

local type     = use "type"
local pairs    = use "pairs"
local pcall    = use "pcall"
local string   = use "string"
local io       = use "io"
local util     = use "util"

local string_sub   = string.sub
local string_byte  = string.byte
local string_find  = string.find

local io_open = io.open

local util_serialize_value  = util.serialize_value
local util_loadtable_string = util.loadtable_string
local util_atomic_write     = util.atomic_write

-- Lua reserved words: a cfg key equal to one cannot be written as a bare
-- identifier key (`key = v`) - it must use the bracketed form. cfg keys
-- are never reserved words in practice; this is defence for the append
-- path only.
local RESERVED = {
    ["and"] = true, ["break"] = true, ["do"] = true, ["else"] = true,
    ["elseif"] = true, ["end"] = true, ["false"] = true, ["for"] = true,
    ["function"] = true, ["goto"] = true, ["if"] = true, ["in"] = true,
    ["local"] = true, ["nil"] = true, ["not"] = true, ["or"] = true,
    ["repeat"] = true, ["return"] = true, ["then"] = true, ["true"] = true,
    ["until"] = true, ["while"] = true,
}

----------------------------------// LEXER //--

-- Byte-class helpers over string.byte (avoids per-char string allocations).
local B_SPACE, B_TAB, B_NL, B_CR = 32, 9, 10, 13
local B_MINUS, B_LBRACK, B_RBRACK, B_LBRACE, B_RBRACE = 45, 91, 93, 123, 125
local B_EQ, B_COMMA, B_DQUOTE, B_SQUOTE = 61, 44, 34, 39
local B_0, B_9 = 48, 57
local B_a, B_z, B_A, B_Z, B_UNDER, B_DOT = 97, 122, 65, 90, 95, 46

local function is_ws( b )
    return b == B_SPACE or b == B_TAB or b == B_NL or b == B_CR
end

local function is_digit( b )
    return b and b >= B_0 and b <= B_9
end

local function is_alpha( b )
    return b and ( ( b >= B_a and b <= B_z ) or ( b >= B_A and b <= B_Z ) or b == B_UNDER )
end

local function is_alnum( b )
    return b and ( is_alpha( b ) or is_digit( b ) )
end

-- Long-bracket opener at position i? Returns the level (0 for `[[`, 1 for
-- `[=[`, ...) or nil. Does not consume.
local function long_bracket_level( s, i )
    if string_byte( s, i ) ~= B_LBRACK then return nil end
    local k = 0
    local j = i + 1
    while string_byte( s, j ) == B_EQ do
        k = k + 1
        j = j + 1
    end
    if string_byte( s, j ) == B_LBRACK then return k end
    return nil
end

-- Skip a long bracket (string or comment body) whose opener starts at i
-- with the given level. Returns the index one PAST the closing `]=*]`, or
-- nil if unterminated.
local function skip_long_bracket( s, i, level )
    -- opener is `[` + level `=` + `[`  => 2 + level chars
    local p = i + 2 + level
    local len = #s
    while p <= len do
        if string_byte( s, p ) == B_RBRACK then
            local q = p + 1
            local k = 0
            while string_byte( s, q ) == B_EQ do
                k = k + 1
                q = q + 1
            end
            if k == level and string_byte( s, q ) == B_RBRACK then
                return q + 1
            end
        end
        p = p + 1
    end
    return nil
end

-- Skip a short string opened at i by quote byte q. Returns the index one
-- PAST the closing quote, or nil if unterminated / contains a raw newline.
local function skip_short_string( s, i, q )
    local len = #s
    local p = i + 1
    while p <= len do
        local b = string_byte( s, p )
        if b == 92 then           -- backslash: skip the escaped byte (covers
            p = p + 2             -- \" \' \\ and \<newline> line continuation)
        elseif b == q then
            return p + 1
        elseif b == B_NL then
            return nil            -- raw newline in a short string = invalid
        else
            p = p + 1
        end
    end
    return nil
end

-- Tokenise `s` into a flat list of structural tokens, skipping whitespace
-- and comments. Each token = { t = <type>, i = <start byte>, j = <end byte> }
-- where type is "punct" | "name" | "string" | "number". Returns the token
-- list, or nil on a lexical error (unterminated string / long bracket).
local function tokenize( s )
    local tokens = { }
    local n = 0
    local i = 1
    local len = #s
    while i <= len do
        local b = string_byte( s, i )
        if is_ws( b ) then
            i = i + 1
        elseif b == B_MINUS and string_byte( s, i + 1 ) == B_MINUS then
            -- comment
            local after = i + 2
            local level = long_bracket_level( s, after )
            if level then
                local nx = skip_long_bracket( s, after, level )
                if not nx then return nil end
                i = nx
            else
                -- line comment to end of line (or EOF)
                local nl = string_find( s, "\n", after, true )
                i = nl and ( nl + 1 ) or ( len + 1 )
            end
        elseif b == B_LBRACK then
            local level = long_bracket_level( s, i )
            if level then
                local nx = skip_long_bracket( s, i, level )
                if not nx then return nil end
                n = n + 1
                tokens[ n ] = { t = "string", i = i, j = nx - 1 }
                i = nx
            else
                n = n + 1
                tokens[ n ] = { t = "punct", i = i, j = i, v = "[" }
                i = i + 1
            end
        elseif b == B_DQUOTE or b == B_SQUOTE then
            local nx = skip_short_string( s, i, b )
            if not nx then return nil end
            n = n + 1
            tokens[ n ] = { t = "string", i = i, j = nx - 1 }
            i = nx
        elseif is_digit( b ) or ( b == B_DOT and is_digit( string_byte( s, i + 1 ) ) ) then
            -- number: consume a run of alnum / '.' / sign-after-exponent.
            -- Over-consuming is harmless - number tokens are only matched
            -- structurally (never decoded), and the safety gate validates.
            local j = i + 1
            while j <= len do
                local c = string_byte( s, j )
                if is_alnum( c ) or c == B_DOT
                    or ( ( c == B_MINUS or c == 43 ) and ( string_byte( s, j - 1 ) == 101 or string_byte( s, j - 1 ) == 69 ) ) then
                    j = j + 1
                else
                    break
                end
            end
            n = n + 1
            tokens[ n ] = { t = "number", i = i, j = j - 1 }
            i = j
        elseif is_alpha( b ) then
            local j = i + 1
            while is_alnum( string_byte( s, j ) ) do j = j + 1 end
            n = n + 1
            tokens[ n ] = { t = "name", i = i, j = j - 1 }
            i = j
        elseif b == B_EQ then
            if string_byte( s, i + 1 ) == B_EQ then
                n = n + 1
                tokens[ n ] = { t = "punct", i = i, j = i + 1, v = "==" }
                i = i + 2
            else
                n = n + 1
                tokens[ n ] = { t = "punct", i = i, j = i, v = "=" }
                i = i + 1
            end
        else
            -- single-char punctuation ({ } ] , . : ( ) etc.). Only a small
            -- set is meaningful to the parser; the rest are consumed as
            -- generic punct so depth/entry tracking stays correct.
            local ch = string_sub( s, i, i )
            n = n + 1
            tokens[ n ] = { t = "punct", i = i, j = i, v = ch }
            i = i + 1
        end
    end
    return tokens
end

----------------------------------// PARSER //--

local function is_punct( tk, v )
    return tk ~= nil and tk.t == "punct" and tk.v == v
end

-- The indent (leading whitespace of the line) of the byte at offset `pos`.
local function indent_at( s, pos )
    local ls = pos
    while ls > 1 and string_byte( s, ls - 1 ) ~= B_NL do
        ls = ls - 1
    end
    local e = ls
    while e < pos do
        local b = string_byte( s, e )
        if b == B_SPACE or b == B_TAB then e = e + 1 else break end
    end
    return string_sub( s, ls, e - 1 )
end

-- Decode a simple string-literal token to its key name. Only handles a
-- plain SHORT string (the escape-free case; cfg keys are plain identifiers);
-- returns nil for a long-bracket literal (`[[k]]`) or one with a backslash,
-- since neither can equal a plain target key - a nil just means "not this
-- key" (the gate still guarantees correctness).
local function simple_key_of_string( s, tk )
    local first = string_byte( s, tk.i )
    if first ~= B_DQUOTE and first ~= B_SQUOTE then return nil end
    local raw = string_sub( s, tk.i, tk.j )
    if string_find( raw, "\\", 1, true ) then return nil end
    -- strip the surrounding quote bytes
    return string_sub( raw, 2, #raw - 1 )
end

-- Scan the top-level table of cfg text `s` for `key`. Returns a record:
--   { ok = true, found = true,  value_i, value_j, indent }   key present
--   { ok = true, found = false, close_i, indent }            key absent
--   { ok = false }                                           bail -> fallback
-- value_i..value_j is the inclusive byte span of the key's value; close_i
-- is the byte offset of the config table's closing brace (append anchor).
local function scan_table( s, key )
    local tokens = tokenize( s )
    if not tokens then return { ok = false } end
    local n = #tokens

    -- The config table is the first structural `{`.
    local p = 1
    while p <= n and not is_punct( tokens[ p ], "{" ) do p = p + 1 end
    if p > n then return { ok = false } end
    p = p + 1   -- first token inside the table

    local found_i, found_j, found_indent
    local found_count = 0
    local first_indent

    -- Build the result record for a config table whose closing `}` is at
    -- token index `close_p`. `needs_sep` is true when the last field before
    -- the brace has no trailing separator (`,`/`;`), so the APPEND path must
    -- insert a comma right after that field's value (byte `sep_at`) to keep
    -- the file valid Lua. An empty table (prev token is the opening `{`) or
    -- a trailing separator both leave needs_sep false.
    local function make_rec( close_p )
        local prev = tokens[ close_p - 1 ]
        local sep_present = prev ~= nil and prev.t == "punct"
            and ( prev.v == "," or prev.v == ";" or prev.v == "{" )
        return {
            ok = true,
            found = found_count == 1,
            value_i = found_i,
            value_j = found_j,
            indent = found_indent or first_indent or "    ",
            close_i = tokens[ close_p ].i,
            needs_sep = not sep_present,
            sep_at = ( not sep_present and prev ) and prev.j or nil,
        }
    end

    while p <= n do
        local tk = tokens[ p ]
        if is_punct( tk, "}" ) then
            if found_count > 1 then return { ok = false } end   -- ambiguous
            return make_rec( p )
        elseif is_punct( tk, "," ) or is_punct( tk, ";" ) then
            p = p + 1   -- stray / trailing separator
        else
            -- Parse one entry: optional key, then a value.
            local entry_indent = indent_at( s, tk.i )
            if not first_indent then first_indent = entry_indent end
            local this_key = nil
            if tk.t == "name" and is_punct( tokens[ p + 1 ], "=" ) then
                this_key = string_sub( s, tk.i, tk.j )
                p = p + 2
            elseif is_punct( tk, "[" ) and tokens[ p + 1 ] and tokens[ p + 1 ].t == "string"
                and is_punct( tokens[ p + 2 ], "]" ) and is_punct( tokens[ p + 3 ], "=" ) then
                this_key = simple_key_of_string( s, tokens[ p + 1 ] )
                p = p + 4
            elseif is_punct( tk, "[" ) and tokens[ p + 1 ] and tokens[ p + 1 ].t == "number"
                and is_punct( tokens[ p + 2 ], "]" ) and is_punct( tokens[ p + 3 ], "=" ) then
                this_key = nil   -- numeric key: never a targeted cfg key
                p = p + 4
            end
            -- p now sits at the first token of the VALUE (positional entries
            -- start here directly with this_key == nil).
            local vtk = tokens[ p ]
            if not vtk or is_punct( vtk, "}" ) then return { ok = false } end
            local value_i = vtk.i
            local value_j = nil
            local depth = 0
            local terminator = nil
            while p <= n do
                local t = tokens[ p ]
                if is_punct( t, "{" ) then
                    depth = depth + 1; value_j = t.j; p = p + 1
                elseif is_punct( t, "}" ) then
                    if depth == 0 then terminator = "}"; break end
                    depth = depth - 1; value_j = t.j; p = p + 1
                elseif ( is_punct( t, "," ) or is_punct( t, ";" ) ) and depth == 0 then
                    terminator = t.v; break    -- Lua allows both , and ; as field seps
                else
                    value_j = t.j; p = p + 1
                end
            end
            if not value_j then return { ok = false } end
            if this_key == key then
                found_count = found_count + 1
                found_i, found_j, found_indent = value_i, value_j, entry_indent
            end
            if terminator == "}" then
                if found_count > 1 then return { ok = false } end
                return make_rec( p )
            elseif terminator == "," or terminator == ";" then
                p = p + 1
            else
                return { ok = false }   -- ran off the end without a terminator
            end
        end
    end
    return { ok = false }
end

----------------------------------// SAFETY GATE //--

-- Deep structural equality of two Lua data values (cfg tables: scalars +
-- nested tables). Integer/float key normalisation is handled by Lua (t[0]
-- and t[0.0] are the same slot), and `==` treats 3 == 3.0.
local function deep_equal( a, b )
    if type( a ) ~= type( b ) then return false end
    if type( a ) ~= "table" then return a == b end
    for k, v in pairs( a ) do
        if not deep_equal( v, b[ k ] ) then return false end
    end
    for k in pairs( b ) do
        if a[ k ] == nil then return false end
    end
    return true
end

-- Textual form of `key` as a table-constructor key for the APPEND path:
-- a bare identifier when it is a valid, non-reserved Lua name, else the
-- bracketed quoted form.
local function key_repr( key )
    if type( key ) == "string" and not RESERVED[ key ]
        and string_find( key, "^[%a_][%w_]*$" ) then
        return key
    end
    return "[ " .. util_serialize_value( key ) .. " ]"
end

----------------------------------// PUBLIC //--

local function build_new_text( old_text, settings, key )
    local rec = scan_table( old_text, key )
    if not rec.ok then return nil end
    if rec.found then
        local value_text = util_serialize_value( settings[ key ], rec.indent )
        return string_sub( old_text, 1, rec.value_i - 1 )
            .. value_text
            .. string_sub( old_text, rec.value_j + 1 )
    else
        -- Absent key: append `<indent>key = value,` on its own line just
        -- before the closing brace, preserving every existing comment. A
        -- leading newline is added ONLY when the byte before the brace is
        -- not already one, so the common `...,\n\n}` tail gains no double
        -- blank line yet a one-line `{ }` / `{}` still splits correctly.
        local value_text = util_serialize_value( settings[ key ], rec.indent )
        local lead = ( string_byte( old_text, rec.close_i - 1 ) == B_NL ) and "" or "\n"
        local field = lead .. rec.indent .. key_repr( key ) .. " = " .. value_text .. ",\n"
        if rec.needs_sep and rec.sep_at then
            -- The last existing field has no trailing separator. Add a comma
            -- right after its value (before any inline comment on that line)
            -- so the appended field is a syntactically distinct field.
            return string_sub( old_text, 1, rec.sep_at )
                .. ","
                .. string_sub( old_text, rec.sep_at + 1, rec.close_i - 1 )
                .. field
                .. string_sub( old_text, rec.close_i )
        end
        return string_sub( old_text, 1, rec.close_i - 1 )
            .. field
            .. string_sub( old_text, rec.close_i )
    end
end

-- Attempt a comment-preserving in-place rewrite of a single cfg key.
--   path     - cfg.tbl path
--   settings - the authoritative in-memory settings table (post-set)
--   key      - the single key that changed
-- Returns true when the surgical write succeeded and was verified; returns
-- nil (never raises) on ANY failure, so the caller falls back to the
-- wholesale util.savetable.
local function save_key( path, settings, key )
    local ok, result = pcall( function( )
        local f = io_open( path, "rb" )
        if not f then return nil end
        local old_text = f:read( "*a" )
        f:close( )
        if not old_text or old_text == "" then return nil end

        local new_text = build_new_text( old_text, settings, key )
        if not new_text then return nil end

        -- SAFETY GATE: the surgically rewritten text must parse (sandboxed,
        -- non-executing) to a table deep-equal to the authoritative
        -- settings. This is what makes a scanner bug non-catastrophic - a
        -- bad splice can only fail to parse or parse to a different table,
        -- both rejected here.
        --
        -- INVARIANT: the gate's loader (util.loadtable_string) must read the
        -- written bytes EXACTLY as the runtime loader (util.loadtable ->
        -- loadfile) will, or the proof breaks. The one known divergence -
        -- loadfile skips a leading UTF-8 BOM, load() does not - is closed in
        -- util.loadtable_string (the shipped cfg.tbl is BOM-headed). Any new
        -- divergence would be a real corruption channel: keep the two in sync.
        local parsed = util_loadtable_string( new_text, "cfg_write_verify" )
        if type( parsed ) ~= "table" then return nil end
        if not deep_equal( parsed, settings ) then return nil end

        local wok = util_atomic_write( path, new_text )
        if not wok then return nil end
        return true
    end )
    if ok and result == true then return true end
    return nil
end

return {
    save_key = save_key,
}
