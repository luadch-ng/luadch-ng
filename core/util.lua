--[[

        util.lua by blastbeat and pulsar

            - this script is a collection of useful functions

            v0.15: by pulsar
                - small changes in formatseconds()

            v0.14: by pulsar
                - added "years" to formatseconds()

            v0.13: by pulsar
                - added encode/decode functions
                    - low impact encryption - a lightweight pure Lua cipher / based on a code part on stackoverflow.com

            v0.12: by blastbeat
                - added is_posint function; sortserialize checks now for true arrays to omit keys
                - removed some redundant concatinations

            v0.11: by pulsar
                - added: maketable( tbl, path )
                    - make a new local table file

            v0.10: by pulsar
                - added: spairs( tbl )
                    - sort table by string keys - based on a sample by http://lua-users.org

            v0.09: by pulsar
                - improved out_error messages

            v0.08: by pulsar
                - added: util.getlowestlevel( tbl )
                    - get lowest level with rights from permission table (for help/ucmd)

            v0.07: by pulsar
                - added: util.trimstring( str )
                    - trim whitespaces from both ends of a string
                - changed: util.formatbytes( bytes )
                    - return nil, err if parameter is not valid
                - changed: util.formatseconds( t )
                    - return nil, err if parameter is not valid

            v0.06: by pulsar
                - changed: util.difftime( t1, t2 )
                    - return complete time in seconds as first arg

            v0.05: by pulsar
                - changed: util.generatepass( len )
                    - increase default password length to 20
                - added: util.date( )
                - added: util.difftime( t1, t2 )
                - added: util.convertepochdate( t )

            v0.04: by pulsar
                - removed unneeded loop

            v0.03: by blastbeat
                - small changes in function: formatbytes()
                - small changes in function: generatepass()

            v0.02: by pulsar
                - add function: generatepass( len )  / based on a function by blastbeat
                    - usage: number/nil = util.generatepass( len )
                        - returns a random alphanumerical password with length = len
                        - returns nil if len = nil  or  len > 1000
                - add function: formatbytes( bytes )  / based on a function by Night
                    - usage: string/nil = util.formatbytes( bytes )
                        - returns converted bytes as a sting e.g. "209.81 GB"
                        - returns nil if bytes = nil

            v0.01: by blastbeat

]]--

----------------------------------// DECLARATION //--

--// lua functions //--

local type = use "type"
local load = use "load"
local table = use "table"
local pairs = use "pairs"
local pcall = use "pcall"
local select = use "select"
local ipairs = use "ipairs"
local tostring = use "tostring"
local tonumber = use "tonumber"
local loadfile = use "loadfile"
local getmetatable = use "getmetatable"

--// lua libs //--

local io = use "io"
local math = use "math"
local string = use "string"
local os = use "os"
local package = use "package"

--// lua lib methods //--

local io_open = io.open
local os_time = os.time
local os_difftime = os.difftime
local os_rename = os.rename
local os_remove = os.remove
local math_floor = math.floor
local string_byte = string.byte
local table_sort = table.sort
local table_insert = table.insert
local table_concat = table.concat
local string_format = string.format
local string_find = string.find
local string_match = string.match
local string_sub = string.sub
local string_gmatch = string.gmatch

--// extern libs //--

local adclib = use "adclib"
local unicode = use "unicode"

--// extern lib methods //--

local isutf8 = adclib.isutf8
local adclib_random_bytes = adclib.random_bytes
local ascii_sub = unicode.ascii.sub
local utf_format = unicode.utf8.format

--// core scripts //--

local out


--// core methods //--

local out_error

--// constants //--

--// functions //--

local init

local handlebom
local checkfile
local safe_path
local makedir

local serialize
local sortserialize
local serialize_value

local loadtable
local loadtable_string
local loadjsontable
local savetable
local savearray
local arraytostring
local tabletostring
local atomic_write
local maketable

local formatseconds
local formatbytes
local generatepass

local date
local difftime
local convertepochdate

local trimstring
local strip_control_bytes
local getlowestlevel
local spairs

local is_posint

local chmod_secret

local encode
local decode

--// tables //--

--// simple data types //--

local _
local _bom


----------------------------------// DEFINITION //--

_bom = string.char( 239 ) .. string.char( 187 ) .. string.char( 191 )

is_posint = function( n )
    return ( type( n ) == "number" ) and ( n > 0 ) and ( n % 1 == 0 )
end

init = function( )
    out = use "out"
    out_error = out.error
end

handlebom = function( str )
    if type( str ) == "string" and ascii_sub( str, 1, 3 ) == _bom then
        str = ascii_sub( str, 4, -1 )
        return str, true
    else
        return str, false
    end
end

-- Path-safety guard for plugin-callable file I/O. Mirrors the check
-- previously inlined in core/scripts.lua's _io_safe.open shim (added
-- in #213). Centralised here so both _io_safe.open AND the util
-- exports (checkfile / atomic_write / maketable, and transitively
-- loadtable / savetable / savearray) share one source of truth -
-- closes the bypass reported in #266 where a plugin could call
-- util.checkfile("/etc/passwd") because util captured the unsandboxed
-- io.open at module load time.
--
-- Returns (true) for safe paths, (false, err) for unsafe.
--
-- Safe = relative path, no parent-dir traversal component (".."),
-- not an absolute POSIX / Windows / UNC path. Single-dot components
-- ("./") stay allowed; legitimate filenames containing two
-- consecutive dots ("thesis..v2.tbl") stay allowed because the
-- check is component-wise.
--
-- Core callers of the util I/O functions all use paths anchored at
-- CONFIG_PATH = "././cfg/" or relative under scripts/data/ - none
-- of them pass absolute paths or traversal components, so applying
-- the guard unconditionally does not break core code paths.
safe_path = function( path )
    if type( path ) ~= "string" then
        return false, "path must be a string"
    end
    if path == "" then
        return false, "empty path"
    end
    -- Reject embedded NUL: the C I/O layer (strlen-based) would truncate
    -- at it, so a lexical check here and the byte-level check there would
    -- disagree (e.g. "..\0x" reads as a harmless component here but as
    -- ".." to C). No legitimate path contains a NUL.
    if string_find( path, "\0", 1, true ) then
        return false, "null byte in path"
    end
    local first = string_sub( path, 1, 1 )
    if first == "/" or first == "\\" then
        return false, "absolute paths blocked (got '" .. path .. "')"
    end
    if string_match( path, "^[A-Za-z]:[/\\]" ) then
        return false, "absolute Windows paths blocked (got '" .. path .. "')"
    end
    for component in string_gmatch( path, "[^/\\]+" ) do
        if component == ".." then
            return false, "parent-dir traversal blocked (got '" .. path .. "')"
        end
    end
    return true
end

checkfile = function( path )
    local ok, perr = safe_path( path )
    if not ok then
        out_error( "util.lua: function 'checkfile': unsafe path '", tostring( path ), "': ", perr )
        return nil, perr
    end
    local script, err = io.open( path, "r" )
    if script then
        local content = script:read "*a"
        script:close( )
        content = content or ""
        if not isutf8( content ) then    -- utf check to avoid format errors
            out_error( "util.lua: function 'checkfile': error in ", path, ": no utf8 format (checkfile)" )
            return nil, "no utf8 format"
        end
        return content
    end
    out_error( "util.lua: function 'checkfile': error in ", path, ": ", err, " (checkfile)" )
    return nil, err
end

-- Create `path` and every missing parent (mkdir -p), via the makedir C
-- primitive registered by hub.c. safe_path-gated like the other
-- plugin-callable I/O, so a sandboxed plugin can only create directories
-- INSIDE the hub tree (no absolute / traversal path). Core self-heal that
-- must create an absolute operator-configured dir resolves the raw
-- primitive via `use "makedir"` instead (a core module cannot reference a
-- bare global under the restricted env). The primitive is absent under
-- standalone lua (unit tests / a broken build), so degrade to (nil, err)
-- rather than throw.
makedir = function( path )
    local ok, perr = safe_path( path )
    if not ok then
        out_error( "util.lua: function 'makedir': unsafe path '", tostring( path ), "': ", perr )
        return nil, perr
    end
    local resolved, mkdir = pcall( use, "makedir" )
    if not resolved or type( mkdir ) ~= "function" then
        return nil, "makedir primitive unavailable"
    end
    local made, merr = mkdir( path )
    if not made then
        out_error( "util.lua: function 'makedir': could not create '", path, "': ", tostring( merr ) )
        return nil, merr
    end
    return true
end

serialize = function( tbl, name, file, tab )  -- this function saves a table to a file
    tab = tab or ""
    file:write( tab, name, " = {\n\n" )
    for key, value in pairs( tbl ) do
        local key = type( key ) == "string" and utf_format( "[ %q ]", key ) or utf_format( "[ %d ]", key )
        if type( value ) == "table" then
            serialize( value, key, file, tab .. "    " )
        else
            local value = type( value ) == "string" and utf_format( "%q", value ) or tostring( value )
            file:write( tab, "    ", key, " = ", value )
        end
        file:write( ",\n" )
    end
    file:write( "\n", tab, "}" )
end

sortserialize = function( tbl, name, file, tab, r )
    tab = tab or ""
    local temp = { }
    local keycount, keymax, is_array = 0, 0, true
    for key, k in pairs( tbl ) do
        table_insert( temp, key )
        if is_array then
            if is_posint( key ) then
                if key > keymax then keymax = key end
            else
                is_array = false
            end
            keycount = keycount + 1
        end
    end
    if not ( is_array and ( keycount == keymax ) ) then
        is_array = false
    end
    -- Lua 5.4 errors on `a < b` when a and b are of different types.
    -- Mixed-key tables (e.g. #261's cfg.scripts entries
    -- `{ "name.lua", enabled = bool }` which have BOTH an integer
    -- key 1 AND a string key "enabled") would crash the default
    -- sort. Group by type first (numbers before strings), then sort
    -- within each type with the natural < operator.
    --
    -- NOTE: `util.spairs` (line ~812) has the same bare `table_sort`
    -- and would crash on a mixed-key table iterator. Not exercised
    -- by any bundled caller today; fix when a caller surfaces.
    table_sort( temp, function( a, b )
        local ta, tb = type( a ), type( b )
        if ta == tb then return a < b end
        return ta == "number"
    end )
    if r then
        file:write( tab, name,  "{\n\n" )
    else
        file:write( tab, name,  " = {\n\n" )
    end
    local skey = ""
    local sep = ( is_array and skey ) or " = "
    for k, key in ipairs( temp ) do
        if ( type( tbl[ key ] ) ~= "function" ) then
            if not is_array then
                skey = ( type( key ) == "string" ) and utf_format( "[ %q ]", key ) or utf_format( "[ %d ]", key )
            end
            if type( tbl[ key ] ) == "table" then
                sortserialize( tbl[ key ], skey, file, tab .. "    ", is_array )
                file:write( ",\n" )
            else
                local svalue = ( type( tbl[ key ] ) == "string" ) and utf_format( "%q", tbl[ key ] ) or tostring( tbl[ key ] )
                file:write( tab, "    ", skey, sep, svalue, ",\n" )
            end
        end
    end
    file:write( "\n", tab, "}" )
end

-- Serialize a single Lua VALUE to its cfg.tbl textual form, reusing the
-- exact escaping/sorting of the wholesale savetable path (sortserialize)
-- so a surgical single-key rewrite (core/cfg_write.lua, #644) round-trips
-- through loadtable identically to a full savetable. There is deliberately
-- ONE serializer: a second, divergent value-formatter would be a defect
-- (CLAUDE.md 1a.1).
--
-- `indent` is the run of spaces the CLOSING brace of a TABLE value sits at
-- (= the column of the key being written); nested entries indent one
-- 4-space level deeper. Scalars ignore it. The returned text carries NO
-- leading indent on the opening brace (it follows `<key> = ` inline) and
-- NO trailing comma.
serialize_value = function( value, indent )
    if type( value ) ~= "table" then
        return ( type( value ) == "string" ) and utf_format( "%q", value ) or tostring( value )
    end
    indent = indent or ""
    local sb = { buf = { }, n = 0 }
    function sb:write( ... )
        local n = select( "#", ... )
        for i = 1, n do
            self.n = self.n + 1
            self.buf[ self.n ] = tostring( ( select( i, ... ) ) or "" )
        end
    end
    -- r = true makes sortserialize emit `<indent>{ ... }` (a bare value, no
    -- `name = ` prefix), inner entries at indent + 4, closing brace at indent.
    sortserialize( value, "", sb, indent, true )
    local s = table_concat( sb.buf, "", 1, sb.n )
    -- Strip the leading indent sortserialize wrote before the opening brace
    -- so the brace follows `= ` inline; the inner indentation is untouched.
    return ( s:gsub( "^%s+", "" ) )
end

--// loads a local table from file
-- Phase 7e F-FIO-1: was `loadfile(path)` which loads with the caller's
-- full _ENV - any attacker who tampers a .tbl file gains RCE on the
-- hub host (cfg.tbl / user.tbl / lang/*.lng / dozens of plugin state
-- files all flow through here).
--
-- Hardening:
--   1. mode = "t" rejects compiled bytecode files (text source only).
--   2. env = {} gives the chunk an empty _ENV: no os, io, debug,
--      package, load*, require, dofile, loadfile, ... - effectively
--      a sandbox where the chunk can compute pure data but cannot
--      reach the host. Legitimate .tbl files are
--      "local foo; foo = { ... }; return foo" which uses zero
--      globals and works unchanged.
--   3. pcall wraps the chunk call so a tampered file that errors at
--      runtime (e.g. arithmetic on nil, infinite recursion past the
--      Lua stack guard) cannot crash the hub - we just log and
--      return nil.
--
-- Residual risk: a chunk can still loop indefinitely or allocate
-- large tables. That is a DoS, not RCE, and only reachable by an
-- attacker who already has file-write access (i.e. existing
-- corruption / chmod / disk-fill primitives). Acceptable trade-off
-- vs. a full hand-rolled non-executable parser (~300 LoC).
loadtable = function( path )
    local _, err = checkfile( path )
    if err then
        return nil, err
    end
    local chunk, err = loadfile( path, "t", { } )
    if chunk then
        local ok, ret = pcall( chunk )
        if not ok then
            out_error( "util.lua: function 'loadtable': chunk error in ", path, ": ", ret )
            return nil, ret
        end
        if ret and type( ret ) == "table" then
            return ret, err
        else
            return nil, "invalid table"
        end
    end
    return nil, err
end

-- Sandboxed JSON table loader for Weblate-friendly language files
-- (#301 P3, lang Lua->JSON migration). Same return-shape as loadtable:
-- (table, nil) on success, (nil, err) on any failure.
--
-- Unlike loadtable there is NO _ENV / RCE surface here: dkjson.decode
-- is pure-Lua data parsing that never executes the file, so a tampered
-- .json degrades to a parse error, not code execution.
--
-- A MISSING file returns (nil, "not found") WITHOUT logging. The
-- dual-format language loader (cfg_lang.loadlanguage) probes the .json
-- path first and silently falls back to the legacy .tbl / .lang.X while
-- the migration is incremental, so a not-yet-converted file must not
-- spam error.log on every boot / +reload. This is the same io.open peek
-- several plugins already do (etc_geoip, etc_blocklist_feeds, whitelist)
-- to dodge checkfile's first-run noise. A file that DOES exist but is
-- unreadable-as-utf8 / malformed / not a JSON object is a real fault and
-- IS logged.
--
-- dkjson is captured lazily (`use "dkjson"` at call time, not file
-- scope) because util loads before the dkjson lib is registered; the
-- call runs long after boot so the resolver always has it.
loadjsontable = function( path )
    local ok, perr = safe_path( path )
    if not ok then
        out_error( "util.lua: function 'loadjsontable': unsafe path '", tostring( path ), "': ", perr )
        return nil, perr
    end
    local f = io_open( path, "r" )
    if not f then
        return nil, "not found"    -- silent: caller may fall back (migration)
    end
    local content = f:read "*a" or ""
    f:close( )
    if not isutf8( content ) then
        out_error( "util.lua: function 'loadjsontable': error in ", path, ": no utf8 format" )
        return nil, "no utf8 format"
    end
    -- dkjson is an OPTIONAL lib (core/init.lua): use "dkjson" returns nil on
    -- an install that dropped it. A converted .json is unreadable without it,
    -- so degrade to (nil, err) - loadlanguage then falls back to the legacy
    -- .tbl instead of indexing nil and throwing into the boot / plugin-load
    -- path. Mirrors core/http_router.lua's missing-dkjson guard. Resolved
    -- BEFORE the pcall below because `pcall( use("dkjson").decode, ... )`
    -- would evaluate the index-of-nil while building pcall's arguments, i.e.
    -- outside pcall's protection.
    local dkjson = use "dkjson"
    if not dkjson then
        out_error( "util.lua: function 'loadjsontable': dkjson not loaded, cannot parse ", path )
        return nil, "dkjson unavailable"
    end
    -- dkjson.decode RAISES on some malformed input (empty / whitespace-only
    -- content among them - a truncated write or a migration-tool bug), so it
    -- must be pcall-wrapped: a corrupt .json degrades to (nil, err) instead
    -- of throwing up through loadlanguage into the boot / plugin-load path
    -- (DEVELOPMENT.md §5, untrusted-input parsers).
    local pok, ret, _pos, derr = pcall( dkjson.decode, content, 1, nil )
    if not pok then
        out_error( "util.lua: function 'loadjsontable': JSON parse error in ", path, ": ", ret )
        return nil, "json parse error"
    end
    if derr then
        out_error( "util.lua: function 'loadjsontable': JSON error in ", path, ": ", derr )
        return nil, derr
    end
    if type( ret ) == "table" then
        -- A JSON array root decodes to a Lua table too, but a lang file must
        -- be a JSON object (key -> string). dkjson tags the root type via its
        -- metatable, so reject an array explicitly rather than hand back a
        -- table whose every lang.<key> lookup silently misses. An empty
        -- object "{}" tags as "object" and correctly passes.
        local mt = getmetatable( ret )
        if mt and mt.__jsontype == "array" then
            return nil, "invalid table"
        end
        return ret, nil
    end
    return nil, "invalid table"
end

-- Atomically replace `path` with `content` via tmp + rename
-- (F-PLG-1, issue #133). Pattern mirrors cfg_users.lua's pre-existing
-- helper that closed the F-AUTH-1 / luadch#189 partial-write window
-- for user.tbl; now used by savetable / savearray so every plugin
-- save inherits the same crash-safety.
--
-- POSIX rename(2) is atomic on the same filesystem. Windows rename
-- errors when the target exists; fall back to remove-then-rename
-- which loses the strict atomicity guarantee but still avoids the
-- open(W)+truncate corruption window of the naive write path.
--
-- chmod is intentionally NOT applied here - cfg_users.lua handles
-- the user.tbl chmod 600 via util.chmod_secret separately, and
-- generic plugin .tbl files do not need restrictive perms.
--
-- Returns true on success, (false, err) on failure.
atomic_write = function( path, content )
    local pok, perr = safe_path( path )
    if not pok then
        return false, perr
    end
    local tmp = path .. ".tmp"
    local f, err = io_open( tmp, "wb" )
    if not f then
        return false, err
    end
    local ok, werr = f:write( content )
    f:close( )
    if not ok then
        os_remove( tmp )
        return false, werr
    end
    -- POSIX: succeeds and atomically replaces.
    if os_rename( tmp, path ) then return true end
    -- Windows fallback: remove target first, then rename.
    os_remove( path )
    local rok, rerr = os_rename( tmp, path )
    if rok then return true end
    os_remove( tmp )    -- best-effort cleanup on full failure
    return false, rerr or "rename failed"
end

-- Internal: emit a savetable-shaped serialisation to any writer that
-- accepts :write(...). Used by both savetable (file-backed) and
-- tabletostring (in-memory builder). Wraps sortserialize with the
-- `local <name>` / `return <name>` envelope that loadtable expects.
local _writetable = function( tbl, name, writer )
    writer:write( "local ", name, "\n\n" )
    sortserialize( tbl, name, writer, "" )
    writer:write( "\n\nreturn ", name )
end

-- Memory-buffer mirror of the savetable serialisation. Lets
-- savetable build the full content as a string before handing it to
-- atomic_write, so we never half-write the target file.
tabletostring = function( tbl, name )
    local sb = { buf = { }, n = 0 }
    function sb:write( ... )
        local n = select( "#", ... )
        for i = 1, n do
            self.n = self.n + 1
            self.buf[ self.n ] = tostring( ( select( i, ... ) ) or "" )
        end
    end
    _writetable( tbl, name, sb )
    return table_concat( sb.buf, "", 1, sb.n )
end

--// saves a table to a local file (F-PLG-1: atomic via tmp + rename)
savetable = function( tbl, name, path )
    local content = tabletostring( tbl, name )
    local ok, err = atomic_write( path, content )
    if not ok then
        out_error( "util.lua: function 'savetable': error in ", path, ": ", err, " (savetable)" )
        return false, err
    end
    return true
end

-- Internal: emit a savearray-shaped serialisation to any writer that
-- accepts :write(...). Used by both savearray (file-backed) and
-- arraytostring (in-memory builder, for cfg_secret).
local _writearray = function( array, writer )
    array = array or { }
    local iterate, savetbl
    iterate = function( tbl )
        local tmp = { }
        for key, value in pairs( tbl ) do
            tmp[ #tmp + 1 ] = tostring( key )
        end
        table_sort( tmp )
        for i, key in ipairs( tmp ) do
            key = tonumber( key ) or key
            if type( tbl[ key ] ) == "table" then
                writer:write( ( ( type( key ) ~= "number" ) and tostring( key ) .. " = " ) or " " )
                savetbl( tbl[ key ] )
            else
                writer:write( ( ( type( key ) ~= "number" and tostring( key ) .. " = " ) or "" ) .. ( ( type( tbl[ key ] ) == "string" ) and utf_format( "%q", tbl[ key ] ) or tostring( tbl[ key ] ) ) .. ", " )
            end
        end
    end
    savetbl =  function( tbl )
        local tmp = { }
        for key, value in pairs( tbl ) do
            tmp[ #tmp + 1 ] = tostring( key )
        end
        table_sort( tmp )
        writer:write( "{ " )
        iterate( tbl )
        writer:write( "}, " )
    end
    writer:write( "return {\n\n" )
    for i, tbl in ipairs( array ) do
        if type( tbl ) == "table" then
            writer:write( "    { " )
            iterate( tbl )
            writer:write( "},\n" )
        else
            writer:write( "    ", utf_format( "%q,\n", tostring( tbl ) ) )
        end
    end
    writer:write( "\n}" )
end

-- Same shape as savearray but returns the serialised content as a
-- string. Used by core/cfg_secret.lua so we can encrypt the
-- serialised bytes before they ever touch disk (Phase 7f F-AUTH-1).
arraytostring = function( array )
    local sb = { buf = { }, n = 0 }
    function sb:write( ... )
        local n = select( "#", ... )
        for i = 1, n do
            self.n = self.n + 1
            self.buf[ self.n ] = tostring( ( select( i, ... ) ) or "" )
        end
    end
    _writearray( array, sb )
    return table_concat( sb.buf, "", 1, sb.n )
end

-- Sandboxed string-loader for plaintext .tbl content already in
-- memory (Phase 7f F-AUTH-1: cfg_secret.open returns plaintext bytes
-- of an encrypted user.tbl, and we want the same empty-_ENV protection
-- as loadtable). Same return-shape as loadtable.
loadtable_string = function( content, name )
    -- Lua's load() on a STRING does not skip a leading UTF-8 BOM, unlike
    -- loadfile()/luaL_loadfilex (which loadtable uses). Strip it so this
    -- string-loader interprets bytes exactly as the file-loader does. This
    -- is load-bearing for core/cfg_write.lua's safety gate (#644): the gate
    -- re-parses the surgically rewritten cfg text with this function and
    -- must read it EXACTLY as the runtime loadfile will - the shipped
    -- cfg.tbl carries a BOM, so without this a BOM'd file would fail the
    -- gate and silently fall back to the comment-stripping wholesale save.
    if type( content ) == "string" then
        content = content:gsub( "^\239\187\191", "" )
    end
    local fn, err = load( content, name or "tbl_string", "t", { } )
    if not fn then return nil, err end
    local ok, ret = pcall( fn )
    if not ok then
        out_error( "util.lua: function 'loadtable_string': chunk error: ", ret )
        return nil, ret
    end
    if ret and type( ret ) == "table" then
        return ret
    end
    return nil, "invalid table"
end

--// saves an array to a local file (F-PLG-1: atomic via tmp + rename)
savearray = function( array, path )
    local content = arraytostring( array )
    local ok, err = atomic_write( path, content )
    if not ok then
        out_error( "util.lua: function 'savearray': error in ", path, ": ", err, " (savearray)" )
        return false, err
    end
    return true
end

--// make a new local table file
maketable = function( name, path )
    local t = {}
    if not path or path == "" then
        local err = "util.lua: function 'maketable': missing param: path"
        return false, err
    end
    local pok, perr = safe_path( path )
    if not pok then
        out_error( "util.lua: function 'maketable': unsafe path '", path, "': ", perr )
        return false, perr
    end
    local file, err = io_open( path, "w" )
    if not file then
        out_error( "util.lua: function 'maketable': error in ", path, ": ", err, " (maketable)" )
        return false, err
    else
        if not name or name == "" then
            file:write( "return {\n\n" )
            file:write( "}" )
        else
            file:write( "local ", name, "\n\n", name, " = {\n\n}", "\n\nreturn ", name )
        end
        file:close()
    end
    return true
end

--// converts seconds to: years, days, hours, minutes, seconds
formatseconds = function( t, hubstart )
    local err
    local t = tonumber( t )
    if not t then
        err = "util.lua: error: number expected, got nil"
        return nil, err
    end
    if ( t < 0 ) or ( t == 1 / 0 ) then
        err = "util.lua: error: parameter not valid"
        return nil, err
    end
    if hubstart then
        return
            math_floor( t / ( 60 * 60 * 24 ) ), -- days
            math_floor( t / ( 60 * 60 ) ) % 24, -- hours
            math_floor( t / 60 ) % 60, -- minutes
            t % 60 -- seconds
    else
        return
            math.floor( t / ( 60 * 60 * 24 ) / 365 ), -- years
            math.floor( t / ( 60 * 60 * 24 ) ) % 365, -- days
            math.floor( t / ( 60 * 60 ) ) % 24, -- hours
            math.floor( t / 60 ) % 60, -- minutes
            t % 60 -- seconds
    end
end

--// convert bytes to the right unit  / based on a function by Night
formatbytes = function( bytes )
    local err
    local bytes = tonumber( bytes )
    if not bytes then
        err = "util.lua: error: number expected, got nil"
        return nil, err
    end
    if ( bytes < 0 ) or ( bytes == 1 / 0 ) then
        err = "util.lua: error: parameter not valid"
        return nil, err
    end
    if bytes == 0 then return "0 B" end
    local i, units = 1, { "B", "KB", "MB", "GB", "TB", "PB", "EB", "YB" }
    while bytes >= 1024 do
        bytes = bytes / 1024
        i = i + 1
    end
    local unit = units[ i ] or "?"
    local fstr
    if unit == "B" then
        fstr = "%.0f %s"
    else
        fstr = "%.2f %s"
    end
    return string_format( fstr, bytes, unit )
end

--// returns a random generated alphanumerical password with length = len; if no param is specified then len = 20
-- Random source is OpenSSL RAND_bytes via adclib (Phase 7 F-AUTH-2 fix).
-- Two CSPRNG bytes per output character: one drives the bucket choice,
-- one drives the in-bucket index. The original 40/20/40
-- digit/upper/lower distribution is preserved for backwards compatibility
-- with operators' expectations of generated passwords.
generatepass = function( len )
    local len = tonumber( len )
    if not ( type( len ) == "number" ) or ( len < 0 ) or ( len > 1000 ) then len = 20 end
    local lower = { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                    "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" }
    local upper = { "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" }
    local rng = adclib_random_bytes( len * 2 )
    local pwd = ""
    for i = 1, len do
        local b1 = string_byte( rng, ( i - 1 ) * 2 + 1 )
        local b2 = string_byte( rng, ( i - 1 ) * 2 + 2 )
        local X = b1 % 10
        if X < 4 then
            pwd = pwd .. tostring( b2 % 10 )
        elseif X < 6 then
            pwd = pwd .. upper[ ( b2 % 26 ) + 1 ]
        else
            pwd = pwd .. lower[ ( b2 % 26 ) + 1 ]
        end
    end
    return pwd
end

--// returns current date in new luadch date style: yyyymmddhhmmss (as number)
date = function()
    return convertepochdate( os.time( ) )
end

--// returns difftime between two date values (new luadch date style)
difftime = function( t1, t2 )
    local err
    local t1 = tonumber( t1 )
    local t2 = tonumber( t2 )
    if not t1 then
        err = "util.lua: error in param #1: got nil"
        return nil, err
    end
    if not t2 then
        err = "util.lua: error in param #2: got nil"
        return nil, err
    end
    local t1, t2 = tostring( t1 ), tostring( t2 )
    local y1, m1, d1, h1, M1, s1
    local y2, m2, d2, h2, M2, s2
    local diff, T1, T2
    local y, d, h, m, s
    if #t1 ~= 14 then
        err = "util.lua: error in param #1: not valid"
        return nil, err
    else
        y1 = t1:sub( 1, 4 )
        m1 = t1:sub( 5, 6 )
        d1 = t1:sub( 7, 8 )
        h1 = t1:sub( 9, 10 )
        M1 = t1:sub( 11, 12 )
        s1 = t1:sub( 13, 14 )
    end
    if #t2 ~= 14 then
        err = "util.lua: error in param #2: not valid"
        return nil, err
    else
        y2 = t2:sub( 1, 4 )
        m2 = t2:sub( 5, 6 )
        d2 = t2:sub( 7, 8 )
        h2 = t2:sub( 9, 10 )
        M2 = t2:sub( 11, 12 )
        s2 = t2:sub( 13, 14 )
    end
    T1 = os_time( { year = y1, month = m1, day = d1, hour = h1, min = M1, sec = s1 } )
    T2 = os_time( { year = y2, month = m2, day = d2, hour = h2, min = M2, sec = s2 } )
    diff = os_difftime( T1, T2 )
    y = math_floor( diff / ( 60 * 60 * 24 ) / 365 )
    d = math_floor( diff / ( 60 * 60 * 24 ) ) % 365
    h = math_floor( diff / ( 60 * 60 ) ) % 24
    m = math_floor( diff / 60 ) % 60
    s = diff % 60
    return diff, y, d, h, m, s
end

--// convert os.time() "epoch" date to luadch date style: yyyymmddhhmmss (as number)
convertepochdate = function( t )
    local t = tonumber( t )
    if type( t ) ~= "number" then
        return nil, "util.lua: error: number expected, got " .. type( t )
    end
    return tonumber( os.date( "%Y%m%d%H%M%S", t ) )
end

--// trim whitespaces from both ends of a string
-- Trim surrounding whitespace. Contract (#453): string in, string out;
-- a non-string is a caller error and returns (nil, err) per the util.*
-- convention (PLUGIN_API.md §5.3). The old `local str = tostring( str )`
-- shadow silently stringified anything - trimstring( nil ) returned the
-- literal "nil", a data-corruption footgun for callers that trusted the
-- dead type guard removed in #447. See strip_control_bytes below for the
-- other, deliberately-lenient convention (non-string -> "").
trimstring = function( str )
    if type( str ) ~= "string" then
        return nil, "trimstring: string expected, got " .. type( str )
    end
    return string_find( str, "^%s*$" ) and "" or string_match( str, "^%s*(.*%S)" )
end

-- Replace every Lua-class control byte (\r, \n, \t, NUL, ...) with
-- '?'. Defence in depth around `adclib::escape`, which only handles
-- ' ', '\n', '\\' - a `\r`, `\0` or `\t` smuggled through any
-- free-form operator-supplied or HTTP-body-supplied text field
-- (kick reason, redirect URL, ban comment, gag reason, etc.) would
-- otherwise mis-frame the outbound ADC frame on the wire. Lifted
-- here from cmd_disconnect / cmd_redirect (Phase 2 of #82) so all
-- bundled-plugin write-endpoint migrations share a single source
-- of truth - a future tightening (e.g. also strip DEL/0x7F, or
-- enforce a stricter character set) hits every surface atomically.
-- A stricter `adclib::escape` is orthogonal hardening for a future
-- phase. Non-string inputs return ""; that lets callers feed
-- possibly-nil values without a separate guard.
strip_control_bytes = function( str )
    return ( type( str ) == "string" ) and ( str:gsub( "%c", "?" ) ) or ""
end

-- HTTP API helper `http_register_user_action` was extracted into
-- core/util_http.lua per the PR-B independent review (avoid the
-- util.lua-dumping-ground failure mode as Phase 2 grows). Plugins
-- call it as `util_http.http_register_user_action( ... )`.

--// get lowest level with rights from permission table (for help/ucmd)
getlowestlevel = function( tbl )
    local err
    local lowest = 100
    for k, v in pairs( tbl ) do
        if type( k ) ~= "number" then
            err = "util.lua: error: number expected for key, got " .. type( k )
            return nil, err
        end
        if not ( ( type( v ) == "number" ) or ( type( v ) == "boolean" ) ) then
            err = "util.lua: error: number or boolean expected for value, got " .. type( v )
            return nil, err
        end
        if type( v ) == "number" then if v > 0 then if k < lowest then lowest = k end end end
        if type( v ) == "boolean" then if v then if k < lowest then lowest = k end end end
    end
    return lowest
end

--// sort table by string keys - based on a sample by http://lua-users.org
spairs = function( tbl )
    local err
    if type( tbl ) ~= "table" then
        err = "util.lua: error: table expected, got " .. type( tbl )
        return nil, err
    end
    local genOrderedIndex = function( tbl )
        local orderedIndex = {}
        for key in pairs( tbl ) do table_insert( orderedIndex, key ) end
        table_sort( orderedIndex )
        return orderedIndex
    end
    local orderedNext = function( tbl, state )
        local key = nil
        if state == nil then
            tbl.orderedIndex = genOrderedIndex( tbl )
            key = tbl.orderedIndex[ 1 ]
        else
            for i = 1, #tbl.orderedIndex do
                if tbl.orderedIndex[ i ] == state then key = tbl.orderedIndex[ i + 1 ] end
            end
        end
        if key then return key, tbl[ key ] end
        tbl.orderedIndex = nil
        return
    end
    return orderedNext, tbl, nil
end

--// chmod 600 a freshly-written secret file on POSIX. No-op on Windows
-- (NTFS ACLs are not POSIX mode bits; see docs/BUILDING.md for the
-- icacls recipe). Invoked from secret-writing call sites such as
-- saveusers; should NOT be applied to non-secret .tbl files like
-- bans.tbl or hubstats.tbl. Phase 7 F-SEC-1 mitigation.
do
    local is_windows = os.getenv( "COMSPEC" ) and os.getenv( "WINDIR" )
    chmod_secret = function( path )
        if is_windows then return end
        -- Single-quote-escape to neutralise any path metacharacters; the
        -- only common offender is a literal single quote inside the path,
        -- which we replace with the standard '\'' escape.
        local escaped = "'" .. tostring( path ):gsub( "'", "'\\''" ) .. "'"
        os.execute( "chmod 600 " .. escaped )
    end
end

--// low impact encryption - a lightweight pure Lua cipher / based on a code part on stackoverflow.com
do
    local Key53 = 1529434767825498 -- 67bit
    local Key14 = 4887
    local inv256
    --// encode
    -- Non-cryptographic reversible scramble (PLUGIN_API.md §5.3). The
    -- tostring() coercion is intentional and kept as-is (#453): it has
    -- zero in-tree callers, round-trips cleanly for strings and decimal
    -- numbers, and produces no data-corruption footgun (you decode back
    -- what you encoded). Unlike trimstring above, it is NOT hardened.
    encode = function( str )
        local str = tostring( str )
        if not inv256 then
            inv256 = {}
            for M = 0, 127 do
                local inv = -1
                repeat inv = inv + 2
                until inv * ( 2*M + 1 ) % 256 == 1
                inv256[ M ] = inv
            end
        end
        local K, F = Key53, 16384 + Key14
        return ( str:gsub( '.',
            function( m )
                local L = K % 274877906944  -- 2^38
                local H = ( K - L ) / 274877906944
                local M = H % 128
                m = m:byte()
                local c = ( m * inv256[ M ] - ( H - M ) / 128 ) % 256
                K = L * F + H + c + m
                return ( '%02x' ):format( c )
            end
        ) )
    end
    --// decode
    decode = function( str )
        local str = tostring( str )
        local K, F = Key53, 16384 + Key14
        return ( str:gsub( '%x%x',
            function( c )
                local L = K % 274877906944
                local H = ( K - L ) / 274877906944
                local M = H % 128
                c = tonumber( c, 16 )
                local m = ( c + ( H - M ) / 128 ) * ( 2*M + 1 ) % 256
                K = L * F + H + c + m
                return string.char( m )
            end
        ))
    end
end

-- Path separator helper (#206 Tier 2). Returns "/" on POSIX,
-- "\\" on Windows. Lifted out of cmd_hubinfo where it previously
-- used `package.config:sub(1,1)` directly - that exposes the
-- whole `package` library to the plugin sandbox just to read
-- one character. Pre-computed at module-load (cached); cannot
-- change at runtime.
local _path_sep = ( package and package.config and package.config:sub( 1, 1 ) ) or "/"
local path_sep = function( ) return _path_sep end

----------------------------------// PUBLIC INTERFACE //--

return {

    init = init,

    handlebom = handlebom,
    safe_path = safe_path,
    checkfile = checkfile,
    makedir = makedir,
    savetable = savetable,
    loadtable = loadtable,
    loadtable_string = loadtable_string,
    loadjsontable = loadjsontable,
    serialize = serialize,
    serialize_value = serialize_value,
    savearray = savearray,
    arraytostring = arraytostring,
    tabletostring = tabletostring,
    atomic_write = atomic_write,
    formatseconds = formatseconds,
    formatbytes = formatbytes,
    generatepass = generatepass,
    date = date,
    difftime = difftime,
    convertepochdate = convertepochdate,
    trimstring = trimstring,
    strip_control_bytes = strip_control_bytes,
    getlowestlevel = getlowestlevel,
    spairs = spairs,
    maketable = maketable,
    is_posint = is_posint,
    chmod_secret = chmod_secret,
    encode = encode,
    decode = decode,
    path_sep = path_sep,

}
