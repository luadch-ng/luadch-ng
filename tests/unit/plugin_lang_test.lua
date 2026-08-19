--[[

    tests/unit/plugin_lang_test.lua

    Repo-wide lang-key consistency check for the bundled plugins.

    Every plugin binds its language table as `local lang, err =
    cfg.loadlanguage( scriptlang, scriptname )` and then reads keys with
    the `local msg_x = lang.some_key or "<english fallback>"` idiom. If the
    source reads a key the lang file does not define, the lookup returns
    nil, the `or` fallback fires, and the plugin silently serves the
    hardcoded English literal forever - the translation is dead and no
    error is ever raised. cfg.language makes no difference. That failure is
    invisible at runtime, which is exactly why it needs a test.

    This has now bitten twice:
      - #301 PR-2: scripts/usr_share.lua read `lang.msg_minmax` while the
        lang files defined `msg_sharelimits`.
      - scripts/etc_cmdlog.lua read `lang.failmsg1` / `lang.failmsg2` while
        the lang files defined `msg_denied` / `msg_nofile`.
    The first was fixed with a one-plugin test (usr_share_lang_test.lua),
    and the bug promptly reappeared in a plugin that test did not look at.
    So this supersedes it with a sweep over EVERY bundled plugin - per
    CLAUDE.md §1a.1, fix the pattern everywhere, not just where it was
    noticed. usr_share is one of the plugins scanned here, so coverage is a
    strict superset of the test this replaces.

    The same rot runs the other way. A key the lang files define but no
    plugin ever reads is worse than useless: translators keep maintaining
    it, reviewers keep reading it as live surface, and it fires never. That
    direction is invisible to the check above - which is exactly how 22 of
    them accumulated undetected until #447 PR 6 swept them out.

    Method: enumerate the shipped plugins from `examples/cfg/cfg.tbl`'s
    `scripts` whitelist, and for each one that ships lang files, load both
    the .en and .de table (the JSON `scripts/lang/<lng>/<name>.json` if
    present, else the legacy flat Lua `scripts/lang/<name>.lang.<lng>` -
    dual-format, mirroring the runtime loader since the #301 P3 per-language
    subdir Weblate migration), scan the plugin source for every `lang.X`
    reference, then assert:
      - forward: every X the source reads exists in EN, the source of
        truth (this is the usr_share / etc_cmdlog bug class);
      - reverse: every EN key is read by the source (no dead key); and
      - DE is translator-managed via Weblate, so it may be incomplete - it
        gets NO missing-key check (an untranslated key falls back to EN),
        only that it carries no ORPHAN key (every de key exists in en) and
        that each string it DOES translate keeps en's placeholder
        signature (same conversion types in the same order).

    Four traps this deliberately avoids:
      - Do NOT assert the value is a string. Plenty of legitimate keys are
        TABLES (`ucmd_menu*` right-click menu structures, `month_name`).
        An earlier draft asserted `type(v)=="string"` and produced 149
        false positives out of 151 hits. Existence is the invariant; the
        type is the plugin's business.
      - Comments are stripped first, so a `lang.X` mentioned in a header
        changelog cannot trip a false positive.
      - No shell/`io.popen` globbing. A native Windows Lua routes popen
        through cmd.exe, where `ls` does not exist - the enumeration would
        silently yield nothing and the whole test would pass vacuously.
        Reading the cfg whitelist is pure `loadfile` and works everywhere,
        and it ties this test to the plugin set we actually ship.
      - The scan pattern tolerates whitespace after the dot. Lua accepts
        `lang. msg_notfound` as a field access, and usr_uptime.lua:143 is
        written exactly that way. A strict `lang%.([%w_]+)` skips it, so the
        forward check silently under-scanned that key, and the reverse check
        would have reported a live key as orphaned. Both directions need the
        `%s*`.

    Provably fails pre-fix (CLAUDE.md §1a.7): on the unpatched tree the
    forward direction reports etc_cmdlog lang.failmsg1 / lang.failmsg2 and
    cmd_delreg lang.msg_reason as missing; the reverse direction reports
    cmd_reg ucmd_passwort and etc_userlogininfo msg_ccpm_1/2/3 as unread.

    Run: lua tests/unit/plugin_lang_test.lua   (any Lua 5.4, from repo root)
    Exit code 0 = pass, 1 = failure (CI-friendly).

]]--

local CFG_TBL    = "examples/cfg/cfg.tbl"
local LANG_DIR   = "scripts/lang/"
local PLUGIN_DIR = "scripts/"

-- Vacuity guard. If the cfg whitelist ever fails to load or its shape
-- changes, this test would scan nothing and every assertion below would
-- pass trivially - a green test that checks nothing is worse than no test.
-- The tree ships ~78 plugins, ~68 of them with lang files. Fail loudly if
-- we ever see implausibly few. Lower only alongside a real drop.
local MIN_PLUGINS   = 60
local MIN_WITH_LANG = 50
-- Reverse-direction floor. An all-empty `return {}` lang file is a valid
-- table that would make the reverse loop iterate nothing and pass silently,
-- invisible to the two counts above. The tree carries ~2000 defined keys
-- (en + de), so a plausible floor catches a systemic load failure. Lower
-- only alongside a real drop.
local MIN_REVERSE_KEYS = 1000

local function read_text( path )
    local f = io.open( path, "rb" )
    if not f then return nil end
    local s = f:read( "*a" )
    f:close( )
    return s
end

local function load_table( path )
    local chunk = loadfile( path )
    if not chunk then return nil, "cannot load" end
    local ok, t = pcall( chunk )
    if not ok or type( t ) ~= "table" then return nil, "did not return a table" end
    return t
end

-- Plugin lang files migrated to JSON in a per-language subdir (#301 P3):
-- scripts/lang/<lng>/<name>.json. This test mirrors the dual-format runtime
-- loader (core/cfg_lang.loadlanguage): prefer the JSON file, fall back to the
-- legacy flat Lua table (scripts/lang/<name>.lang.<lng>), so it keeps passing
-- whether a given plugin has migrated yet or not.
local dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )

-- Resolve which lang file ships for (name, lng): the subdir .json first, else
-- the legacy flat Lua table, else nil (plugin ships no lang for that language).
local function lang_path( name, lng )
    local json = LANG_DIR .. lng .. "/" .. name .. ".json"
    if read_text( json ) then return json end
    local lua = LANG_DIR .. name .. ".lang." .. lng
    if read_text( lua ) then return lua end
    return nil
end

-- Load a lang file in whichever format it is. JSON via the same bundled
-- dkjson the hub uses; legacy tables via the sandboxed loader above.
local function load_lang( path )
    if path:sub( -5 ) == ".json" then
        local s = read_text( path )
        if not s then return nil, "cannot read" end
        local t, _, err = dkjson.decode( s, 1, nil )
        if err or type( t ) ~= "table" then return nil, err or "did not return a table" end
        return t
    end
    return load_table( path )
end

-- Strip block comments `--[[ ... ]]` and line comments so a `lang.X` in a
-- header changelog or an explanatory note cannot register as a lookup.
local function strip_comments( s )
    s = s:gsub( "%-%-%[%[.-%]%]", "" )
    s = s:gsub( "%-%-[^\n]*", "" )
    return s
end

-- Ordered signature of printf conversions: the sequence of conversion-type
-- letters (`%s`->"s", `%-20d`->"d") after removing the literal `%%`. Lua
-- string.format fills arguments positionally, so a translated de string
-- must keep en's exact TYPE and ORDER, not just the count - a word-order
-- swap of `"%s ... %d"` into `"%d ... %s"` has the same count but crashes
-- string.format at runtime.
local function fmt_sig( s )
    s = ( s:gsub( "%%%%", "" ) )
    local out = { }
    -- No space in the flag class on purpose: a literal percent in free-form
    -- translator text ("50% der Dateien") would otherwise parse as a phantom
    -- "% d" spec and fail the placeholder check, stalling the funnel. luadch
    -- uses no space-flag conversions; real specs (%s %d %-20s %.2f) are unaffected.
    for spec in s:gmatch( "%%[%-+#0-9.]*([%a])" ) do
        out[ #out + 1 ] = spec
    end
    return table.concat( out )
end

local failures, checks = 0, 0
local function check( label, ok )
    checks = checks + 1
    if not ok then
        failures = failures + 1
        io.write( "FAIL " .. label .. "\n" )
    end
end

-- cfg.scripts entries come in two shapes: a bare "name.lua" string, and a
-- `{ "name.lua", enabled = true }` table (the per-plugin toggle form).
local function entry_name( v )
    local file = ( type( v ) == "table" ) and v[ 1 ] or v
    if type( file ) ~= "string" then return nil end
    return file:match( "^(.+)%.lua$" )
end

local cfg, cfg_err = load_table( CFG_TBL )
check( CFG_TBL .. " loads (" .. tostring( cfg_err ) .. ")", cfg ~= nil )

local names = { }
if cfg and type( cfg.scripts ) == "table" then
    for _, v in ipairs( cfg.scripts ) do
        local n = entry_name( v )
        if n then names[ #names + 1 ] = n end
    end
end
table.sort( names )

check( string.format( "cfg.scripts lists at least %d plugins (found %d)",
                      MIN_PLUGINS, #names ),
       #names >= MIN_PLUGINS )

-- Extra translator-managed languages to gate (the Weblate funnel gate). See
-- lang_test.lua: unset in the normal smoke run (only de is checked, and no
-- directory globbing here keeps the Windows leg portable), set by the funnel
-- workflow to the languages it imports so each gets the same per-plugin orphan
-- + placeholder-signature checks de gets, skipping empty (untranslated) values.
local EXTRA_CODES = { }
do
    local extra = os.getenv( "LANG_TEST_EXTRA_CODES" )
    if extra and extra ~= "" then
        for lng in extra:gmatch( "[^,%s]+" ) do
            if lng ~= "en" and lng ~= "de" then EXTRA_CODES[ #EXTRA_CODES + 1 ] = lng end
        end
    end
end

local scanned, total_refs, reverse_checks = 0, 0, 0

for _, name in ipairs( names ) do
    -- Not every plugin ships lang files; those are simply out of scope
    -- here (nothing to be inconsistent with). Resolve either format.
    local en_path = lang_path( name, "en" )
    if en_path then
        local de_path = lang_path( name, "de" )
        local source = read_text( PLUGIN_DIR .. name .. ".lua" )
        local en, en_err = load_lang( en_path )
        local de, de_err = nil, "no .lang.de"
        if de_path then de, de_err = load_lang( de_path ) end

        check( name .. ": plugin source exists", source ~= nil )
        check( name .. ": .lang.en loads (" .. tostring( en_err ) .. ")", en ~= nil )
        -- The de FILE is required to exist and load: a bundled plugin ships
        -- en + de together (DEVELOPMENT.md "all-or-nothing"), and de is
        -- authored, not created by Weblate. Its CONTENT may be partial (an
        -- empty `{}` de file passes) - only its presence is enforced, so a
        -- plugin author who forgot de is still caught.
        check( name .. ": .lang.de exists and loads (" .. tostring( de_err ) .. ")", de ~= nil )

        if source and en and de then
            scanned = scanned + 1
            local seen = { }
            -- Filenames are not translations (#651). A plugin's `+help` section
            -- header used to live in the lang file as a `help_title*` key whose
            -- VALUE is the script filename ("cmd_gag.lua"), so every en key
            -- surfaced to Weblate as a translatable unit and translators saw
            -- filenames to translate. The header is now a code constant; no
            -- `help_title*` key may exist in a lang file. Guarding EN (the
            -- source) is sufficient - the reverse/orphan checks below already
            -- force de/nl/sv keys to be a subset of en, so none can reappear
            -- in a target language without also being in en.
            for key in pairs( en ) do
                check( name .. ": en key '" .. key .. "' is not a filename title (help_title* -> code constant, #651)",
                       key:sub( 1, 10 ) ~= "help_title" )
            end
            -- Forward: EN is the source of truth. A key the plugin reads
            -- MUST exist in EN (the usr_share / etc_cmdlog bug class: source
            -- reads lang.X, the file defines a differently-named key, the
            -- `or "<english>"` fallback silently fires forever). DE is NOT
            -- checked here - it is translator-managed (Weblate) and may be
            -- incomplete; an untranslated key is absent and the runtime
            -- falls back to EN, which the forward check already guarantees.
            for key in strip_comments( source ):gmatch( "lang%.%s*([%w_]+)" ) do
                if not seen[ key ] then
                    seen[ key ] = true
                    total_refs = total_refs + 1
                    check( name .. ": lang." .. key .. " defined in en (source)", en[ key ] ~= nil )
                end
            end
            -- Reverse (dead EN key). A key no plugin reads is invisible rot:
            -- translators keep maintaining it, reviewers keep reading it as
            -- live, and nothing ever fires. The forward check above cannot
            -- see it, which is how 22 of them accumulated by #447 PR 6.
            --
            -- This assumes every read is a literal `lang.<key>` - that is
            -- what `seen` collected. The tree has no `lang[ "key" ]` and no
            -- `local L = lang` alias today; the day one appears, its keys
            -- will look orphaned here and this loop must learn that access
            -- form, or it will report a live key as dead.
            for key in pairs( en ) do
                reverse_checks = reverse_checks + 1
                check( name .. ": en key '" .. key .. "' is read by the plugin", seen[ key ] == true )
            end
            -- DE is translator-managed: only require it has NO ORPHAN keys
            -- (every de key must exist in en - a key the source dropped is
            -- dead translation), and that every string it DOES translate
            -- keeps en's placeholder signature - same conversion types in
            -- the same order (a reordered or dropped %s breaks
            -- string.format; Weblate flags this too, CI is the backstop).
            for key, v in pairs( de ) do
                reverse_checks = reverse_checks + 1
                check( name .. ": de key '" .. key .. "' exists in en (no orphan)", en[ key ] ~= nil )
                if type( v ) == "string" and v ~= "" and type( en[ key ] ) == "string" then
                    check( name .. ": de." .. key .. " placeholder signature matches en",
                           fmt_sig( v ) == fmt_sig( en[ key ] ) )
                end
            end
            -- Extra translator-managed languages (Weblate funnel gate): the
            -- same orphan + placeholder checks as de, for each language the
            -- funnel imports. A plugin that ships no file for a given language
            -- is skipped (translator-managed, may be incomplete).
            for _, lng in ipairs( EXTRA_CODES ) do
                local xpath = lang_path( name, lng )
                if xpath then
                    local xt, xerr = load_lang( xpath )
                    check( name .. ": ." .. lng .. " loads (" .. tostring( xerr ) .. ")", xt ~= nil )
                    for key, v in pairs( xt or { } ) do
                        reverse_checks = reverse_checks + 1
                        check( name .. ": " .. lng .. " key '" .. key .. "' exists in en (no orphan)", en[ key ] ~= nil )
                        if type( v ) == "string" and v ~= "" and type( en[ key ] ) == "string" then
                            check( name .. ": " .. lng .. "." .. key .. " placeholder signature matches en",
                                   fmt_sig( v ) == fmt_sig( en[ key ] ) )
                        end
                    end
                end
            end
        end
    end
end

check( string.format( "scanned at least %d plugins with lang files (scanned %d)",
                      MIN_WITH_LANG, scanned ),
       scanned >= MIN_WITH_LANG )

check( string.format( "reverse-checked at least %d lang keys (checked %d)",
                      MIN_REVERSE_KEYS, reverse_checks ),
       reverse_checks >= MIN_REVERSE_KEYS )

io.write( string.format( "\n%d/%d checks passed (%d plugins scanned, %d distinct lang.X references)\n",
                         checks - failures, checks, scanned, total_refs ) )
if failures > 0 then
    io.write( "FAIL " .. failures .. " check(s) failed\n" )
    os.exit( 1 )
end
io.write( "OK plugin_lang_test\n" )
