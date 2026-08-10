--[[

    tests/unit/nick_rename_propagation_test.lua

    Regression tests for the nick-rename propagation fix. Several plugins
    keep a per-firstnick persistent store that a +nickchange (or the HTTP
    rename) must carry over to the new nick, else the rename silently
    orphans the entry:

      - etc_msgmanager  : a chat block (map:  store[nick] = mode)
      - cmd_usercleaner : a delete-exception (map: store[nick] = by)
      - usr_hide_share  : a hidden-share flag (map: store[nick] = 1)
      - usr_uptime      : accumulated uptime (map: store[nick] = {...})
      - cmd_gag         : a chat gag (list: record.user_nick = nick)
      - cmd_ban         : a by-nick ban (list: record.nick) + history (map)

    Each now registers an onAudit tap on reg.nickchange that re-keys its
    store. (etc_trafficmanager - the store Sopor originally reported - is
    covered in etc_trafficmanager_test.lua.)

    The real plugin is loaded under a stubbed sandbox: the onAudit
    listener is captured through hub.setlistener, the store(s) seeded
    through util.loadtable, and the re-key observed through
    util.savetable / util.savearray (captured per file).

    Regression contract (CLAUDE.md §1a.7): RED pre-fix - no plugin
    registers onAudit, so the "onAudit registered" check FAILS and the
    guarded move assertions are skipped. GREEN patched. Verified by
    running this file against `git show origin/dev:scripts/<plugin>.lua`.

    Run: lua5.4 tests/unit/nick_rename_propagation_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

]]--

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-66s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

-- copy up to two levels: enough for a list-of-flat-records and a
-- map-of-subtrees (the re-key moves a subtree wholesale by reference).
local function dcopy( t )
    local r = { }
    for k, v in pairs( t ) do
        if type( v ) == "table" then
            local vv = { }
            for k2, v2 in pairs( v ) do vv[ k2 ] = v2 end
            r[ k ] = vv
        else
            r[ k ] = v
        end
    end
    return r
end

----------------------------------------------------------------------
-- verify factories (per store shape)
----------------------------------------------------------------------

local function map_verify( store_file, seed_val )
    return function( saves, case )
        local s = saves[ store_file ]
        eq( case.name .. ": store persisted",   s ~= nil, true )
        eq( case.name .. ": new nick present",  s and s.NewNick ~= nil, true )
        eq( case.name .. ": old nick cleared",  s and s.OldNick == nil, true )
        -- value-equality only for scalar-valued maps; a table value (e.g.
        -- uptime's subtree) or an omitted seed_val skips this check.
        if seed_val ~= nil and type( seed_val ) ~= "table" then
            eq( case.name .. ": new nick keeps value", s and s.NewNick, seed_val )
        end
    end
end

local function list_verify( store_file, keyfield )
    return function( saves, case )
        local s = saves[ store_file ]
        eq( case.name .. ": store persisted", s ~= nil, true )
        local has_new, has_old = false, false
        for _, r in ipairs( s or { } ) do
            if r[ keyfield ] == "NewNick" then has_new = true end
            if r[ keyfield ] == "OldNick" then has_old = true end
        end
        eq( case.name .. ": record now under new nick", has_new, true )
        eq( case.name .. ": no record under old nick",  has_old, false )
    end
end

----------------------------------------------------------------------
-- per-plugin descriptors
----------------------------------------------------------------------

local MSG_FILE  = "scripts/data/etc_msgmanager.tbl"
local EXC_FILE  = "scripts/data/cmd_usercleaner_exceptions.tbl"
local HIDE_FILE = "scripts/data/usr_hide_share.tbl"
local UPT_FILE  = "scripts/data/usr_uptime.tbl"
local GAG_FILE  = "scripts/data/cmd_gag.tbl"
local BAN_FILE  = "scripts/data/cmd_ban_bans.tbl"
local BANH_FILE = "scripts/data/cmd_ban_history.tbl"

local CASES = {
    {
        name = "etc_msgmanager", path = "scripts/etc_msgmanager.lua",
        needs_onstart = true,     -- block_tbl is (re)loaded in onStart
        cfg  = { language = "en", etc_msgmanager_activate = true },
        seed = { [ MSG_FILE ] = { OldNick = "b" } },
        verify = map_verify( MSG_FILE, "b" ),
    },
    {
        name = "cmd_usercleaner", path = "scripts/cmd_usercleaner.lua",
        needs_onstart = false,    -- exception_tbl loaded at module scope
        cfg  = { language = "en", cmd_usercleaner_activate = true },
        seed = { [ EXC_FILE ] = { OldNick = "op" } },
        verify = map_verify( EXC_FILE, "op" ),
    },
    {
        name = "usr_hide_share", path = "scripts/usr_hide_share.lua",
        needs_onstart = false,
        cfg  = {
            language = "en", usr_hide_share_activate = true,
            usr_hide_share_permission = { [ 60 ] = 60 },
            usr_hide_share_restrictions = { },
        },
        seed = { [ HIDE_FILE ] = { OldNick = 1 } },
        verify = map_verify( HIDE_FILE, 1 ),
    },
    {
        name = "usr_uptime", path = "scripts/usr_uptime.lua",
        needs_onstart = false,    -- uptime_tbl loaded at module scope
        cfg  = { language = "en" },
        seed = { [ UPT_FILE ] = { OldNick = { [ "2026" ] = { } } } },
        verify = map_verify( UPT_FILE ),   -- table value: presence only
    },
    {
        name = "cmd_gag", path = "scripts/cmd_gag.lua",
        needs_onstart = false,    -- gag_tbl loaded at module scope
        cfg  = { language = "en" },
        -- the second record is a stale entry already under the new nick;
        -- the reverse-dedup loop must drop it and keep the renamed one.
        seed = { [ GAG_FILE ] = {
            { user_nick = "OldNick", mode = "mute" },
            { user_nick = "NewNick", mode = "shadowmute" },
        } },
        verify = function( saves, case )
            list_verify( GAG_FILE, "user_nick" )( saves, case )
            local n, kept_mode = 0, nil
            for _, r in ipairs( saves[ GAG_FILE ] or { } ) do
                if r.user_nick == "NewNick" then n = n + 1; kept_mode = r.mode end
            end
            eq( case.name .. ": exactly one record under new nick (dedup)", n, 1 )
            eq( case.name .. ": renamed record survived, stale dropped", kept_mode, "mute" )
        end,
    },
    {
        name = "cmd_ban", path = "scripts/cmd_ban.lua",
        needs_onstart = false,    -- bans + history loaded at module scope
        cfg  = { language = "en" },
        seed = {
            -- the second record is a cid/ip-only ban (nick = ""); the
            -- empty-nick guard must leave it untouched on a rename.
            [ BAN_FILE ]  = {
                { nick = "OldNick", ip = "", cid = "" },
                { nick = "", ip = "1.2.3.4", cid = "CIDXYZ" },
            },
            [ BANH_FILE ] = { OldNick = { { date = "x" } } },
        },
        verify = function( saves, case )
            list_verify( BAN_FILE, "nick" )( saves, case )
            local ip_ok = false
            for _, r in ipairs( saves[ BAN_FILE ] or { } ) do
                if r.cid == "CIDXYZ" and r.ip == "1.2.3.4" and r.nick == "" then ip_ok = true end
            end
            eq( case.name .. ": cid/ip-only ban left untouched", ip_ok, true )
            local h = saves[ BANH_FILE ]
            eq( case.name .. ": history persisted",        h ~= nil, true )
            eq( case.name .. ": history new nick present", h and h.NewNick ~= nil, true )
            eq( case.name .. ": history old nick cleared", h and h.OldNick == nil, true )
        end,
    },
}

----------------------------------------------------------------------
-- load a plugin under a stubbed sandbox, capture its onAudit listener,
-- fire a reg.nickchange and observe the store move via save capture.
----------------------------------------------------------------------

local function run( case )
    local registered = { }
    local saves = { }                       -- file -> captured table

    local function capture( t, file ) saves[ file ] = dcopy( t ) end

    _G.PROCESSED = 1
    _G.hub = {
        setlistener  = function( ev, _, fn ) registered[ ev ] = fn end,
        debug        = function( ) end,
        getbot       = function( ) return "stub-bot" end,
        sendtoall    = function( ) end,
        escapeto     = function( s ) return s end,
        escapefrom   = function( s ) return s end,
        getusers     = function( ) return { } end,
        isnickonline = function( ) return nil end,
        find_online_by_firstnick = function( ) return nil end,
        getregusers  = function( ) return { }, { }, { } end,
        import = function( n )
            if n == "etc_hubcommands" then
                return { add = function( ) return true end, has = function( ) return false end, list = function( ) return { } end }
            end
            if n == "etc_report" then return { send = function( ) end } end
            return nil     -- cmd_help / etc_usercommands absent
        end,
        http_register = function( ) end,
    }
    _G.cfg = {
        loadlanguage = function( ) return { }, nil end,
        get = function( k ) return case.cfg[ k ] end,
    }
    _G.util = {
        loadtable = function( f )
            local s = case.seed[ f ]
            if s == nil then return nil end
            return dcopy( s )
        end,
        savetable = function( t, _name, file ) capture( t, file ) end,
        savearray = function( t, file ) capture( t, file ) end,
        date = function( ) return "20260101000000" end,
        strip_control_bytes = function( s ) return s end,
        getlowestlevel = function( ) return 60 end,
        spairs = function( t ) return pairs( t ) end,
    }
    _G.utf = { match = string.match, format = string.format, sub = string.sub, len = string.len }

    assert( loadfile( case.path ) )( )
    eq( case.name .. ": onAudit listener registered", registered.onAudit ~= nil, true )
    if case.needs_onstart and registered.onStart then registered.onStart( ) end
    if not registered.onAudit then return end

    -- the rename must move the store from OldNick -> NewNick and persist
    registered.onAudit( { action = "reg.nickchange",
        target = { nick = "NewNick" }, meta = { previous_nick = "OldNick" } } )
    case.verify( saves, case )

    -- an unrelated audit event must not touch any store (no save)
    saves = { }
    registered.onAudit( { action = "ban.add", target = { nick = "x" }, meta = { } } )
    eq( case.name .. ": unrelated event ignored (no save)", next( saves ), nil )

    -- a rename of a user NOT in the store must be a no-op (no spurious
    -- disk write on every nickchange hub-wide)
    saves = { }
    registered.onAudit( { action = "reg.nickchange",
        target = { nick = "B" }, meta = { previous_nick = "not_in_store" } } )
    eq( case.name .. ": rename of a non-stored user is a no-op", next( saves ), nil )
end

for _, c in ipairs( CASES ) do run( c ) end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
