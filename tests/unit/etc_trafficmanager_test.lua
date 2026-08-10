--[[

    tests/unit/etc_trafficmanager_test.lua

    Unit tests for scripts/etc_trafficmanager.lua `show blocks` /
    `show settings` output (luadch-ng/luadch-ng#502).

    Focus: the v2.7 change that makes `+trafficmanager show blocks`
    also list currently-online users who are auto-blocked by share
    (0 B / below minshare) or by a blocked level. These are runtime
    need_block() classifications never persisted to block_tbl, so the
    pre-v2.7 handler (which only iterated block_tbl) showed nothing
    for them. Also covers the v2.7 `show settings` minshare-check line.

    The plugin is loaded with a stubbed sandbox environment; the
    `+trafficmanager` chat handler (onbmsg) is captured through the
    etc_hubcommands.add stub and invoked directly. hub.getusers() is
    stubbed to return a controllable online set.

    Run: lua5.4 tests/unit/etc_trafficmanager_test.lua
    Exit 0 = all pass, 1 = a failure (CI-friendly).

    Regression contract (CLAUDE.md §1a.7): the positive auto-block
    assertions, the "(none)" placeholder, and the settings minshare
    line (9 checks) FAIL on the pre-v2.7 plugin (no auto-block section;
    msg_users had only two %s) and PASS on v2.7. The negative auto
    assertions (clean/op NOT listed) and the manual-section / permission
    checks are guards that pass on both revisions. Verified by running
    this file against `git show origin/dev:scripts/etc_trafficmanager.lua`
    (9 failures pre-fix, 0 post-fix).

    v2.8 NAT-traversal section (below): the two "onNatTraversal /
    onNatTraversalReply registered" checks FAIL on the pre-v2.8 plugin
    (the listeners are unregistered; the guarded block/pass assertions
    are then skipped) and PASS patched - 2 more RED-pre-fix checks.

    nil-scriptname section (below): external add() with scriptname=nil
    must degrade to msg_unknown, not the literal "nil". 3 checks FAIL on
    the pre-fix plugin (dead `tostring(nil) or msg_unknown` fallback) and
    PASS patched.

    nick-rename section (below): a reg.nickchange onAudit event must
    re-key a manual block to the new nick, else +nickchange silently
    unblocks the user (reported by Sopor). The "onAudit listener
    registered" check FAILS on the pre-fix plugin (no listener) and PASSES
    patched; the guarded show-blocks assertions then confirm the key moved
    (new nick blocked, old nick gone) and that an unrelated audit event is
    ignored.

]]--

local GiB = 1024 * 1024 * 1024

----------------------------------------------------------------------
-- controllable state
----------------------------------------------------------------------

local _registered = { }        -- event/listener name -> fn
local _hubcmds = { }           -- cmd name -> handler (onbmsg)
local _online = { }            -- sid -> stub user (hub.getusers)
local _block_seed = nil        -- what util.loadtable returns for block_tbl
local _last_report = nil       -- last op-report message captured from etc_report.send

----------------------------------------------------------------------
-- stub sandbox globals the plugin reads at file scope + runtime
----------------------------------------------------------------------

_G.PROCESSED = 1

_G.hub = {
    setlistener = function( event, opts, fn ) _registered[ event ] = fn end,
    debug       = function( ) end,
    getbot      = function( ) return "stub-bot" end,
    sendtoall   = function( ) end,
    escapeto    = function( s ) return s end,
    escapefrom  = function( s ) return s end,
    isnickonline = function( ) return nil end,
    getusers    = function( ) return _online end,
    -- Mirrors core/hub.lua's find_online_by_firstnick (#537): the plugin
    -- now delegates to this shared hub helper instead of a local copy.
    find_online_by_firstnick = function( firstnick )
        for _, u in pairs( _online ) do
            if u:firstnick( ) == firstnick then return u end
        end
        return nil
    end,
    getregusers = function( ) return { }, { }, { } end,
    import = function( name )
        if name == "etc_hubcommands" then
            return {
                add = function( cmd, fn ) _hubcmds[ cmd ] = fn; return true end,
                has = function( ) return false end,
                list = function( ) return { } end,
            }
        end
        if name == "etc_report" then
            -- capture the formatted op-report (last positional arg) so a
            -- test can assert on the "User: ... | reason: ..." text.
            return { send = function( _, _, _, _, msg ) _last_report = msg end }
        end
        return nil    -- cmd_help / etc_usercommands absent in the test
    end,
    http_register = function( ) end,
}

_G.cfg = {
    loadlanguage = function( ) return { }, nil end,   -- exercise inline fallbacks
    get = function( key )
        local t = {
            language                        = "en",
            etc_trafficmanager_activate     = true,
            etc_trafficmanager_permission   = { [ 60 ] = 60, [ 70 ] = 70, [ 80 ] = 80, [ 100 ] = 100 },
            etc_trafficmanager_report       = false,
            etc_trafficmanager_report_hubbot = false,
            etc_trafficmanager_report_opchat = false,
            etc_trafficmanager_llevel       = 60,
            etc_trafficmanager_blocklevel_tbl = { [ 10 ] = true },   -- level 10 auto-blocked
            etc_trafficmanager_sharecheck   = true,
            etc_trafficmanager_check_minshare = true,
            min_share                       = { [ 0 ] = 0, [ 10 ] = 0, [ 20 ] = 5, [ 60 ] = 0, [ 100 ] = 0 },
            etc_trafficmanager_oplevel      = 60,
            etc_trafficmanager_login_report = false,
            etc_trafficmanager_report_main  = false,
            etc_trafficmanager_report_pm    = false,
            usr_nick_prefix_activate        = false,
            usr_nick_prefix_permission      = { },
            usr_nick_prefix_prefix_table    = { },
            usr_desc_prefix_activate        = false,
            usr_desc_prefix_permission      = { },
            usr_desc_prefix_prefix_table    = { },
            etc_trafficmanager_send_loop    = false,
            etc_trafficmanager_loop_time    = 1,
            etc_trafficmanager_flag_blocked = "[BLOCKED]",
            levels = { [ 10 ] = "Guest", [ 20 ] = "Reg", [ 60 ] = "Op", [ 100 ] = "Owner" },
        }
        return t[ key ]
    end,
}

_G.util = {
    loadtable = function( ) return _block_seed end,
    savetable = function( ) return true end,
    date      = function( ) return "20260101000000" end,
    strip_control_bytes = function( s ) return s end,
    getlowestlevel = function( ) return 60 end,
    -- real spairs impl (copied from core/util.lua) so the manual-block
    -- section iterates in sorted order deterministically.
    spairs = ( function( )
        local function genOrderedIndex( tbl )
            local idx = { }
            for k in pairs( tbl ) do
                if k ~= "orderedIndex" then idx[ #idx + 1 ] = k end
            end
            table.sort( idx )
            return idx
        end
        local function orderedNext( tbl, state )
            local key
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
        return function( tbl ) return orderedNext, tbl, nil end
    end )( ),
}

_G.utf = {
    match  = string.match,
    format = string.format,
    sub    = string.sub,
    len    = string.len,
}

----------------------------------------------------------------------
-- minimal test framework
----------------------------------------------------------------------

local failures, checks = 0, 0
local function eq( label, got, want )
    checks = checks + 1
    if got ~= want then
        failures = failures + 1
        io.write( string.format( "FAIL %-60s got=%q want=%q\n", label, tostring( got ), tostring( want ) ) )
    else
        io.write( string.format( "ok   %s\n", label ) )
    end
end

local function contains( hay, needle ) return ( hay or "" ):find( needle, 1, true ) ~= nil end
local function count( hay, needle )
    local n, i = 0, 1
    while true do
        local s = ( hay or "" ):find( needle, i, true )
        if not s then break end
        n = n + 1; i = s + #needle
    end
    return n
end

----------------------------------------------------------------------
-- stub user + op factory
----------------------------------------------------------------------

local function stub_user( opts )
    return {
        level     = function( ) return opts.level end,
        share     = function( ) return opts.share end,      -- may be nil
        firstnick = function( ) return opts.firstnick end,
        nick      = function( ) return opts.firstnick end,
        isbot     = function( ) return false end,
    }
end

local function op_user( )
    local replied
    local u = {
        level = function( ) return 100 end,
        nick  = function( ) return "owner" end,
        reply = function( _, msg ) replied = msg end,
    }
    return u, function( ) return replied end
end

----------------------------------------------------------------------
-- load plugin + onStart (empty online set) so onbmsg is captured
----------------------------------------------------------------------

_block_seed = { manual_guy = { "admin", "manual reason", "20260101000000" } }
_online = { }
local tm = assert( loadfile( "scripts/etc_trafficmanager.lua" ) )( )
assert( _registered.onStart, "onStart not registered" )
_registered.onStart( )
local onbmsg = _hubcmds.trafficmanager
assert( onbmsg, "+trafficmanager handler not registered" )

----------------------------------------------------------------------
-- 1. show blocks: auto-blocked online users appear with the right
--    reason, clean/op users do not, manual user appears once.
----------------------------------------------------------------------

do
    _online = {
        s1 = stub_user{ firstnick = "zeroshare_guy", level = 20, share = 0 },
        s2 = stub_user{ firstnick = "small_guy",     level = 20, share = 1 * GiB },
        s3 = stub_user{ firstnick = "level_guy",      level = 10, share = 999 * GiB },
        s4 = stub_user{ firstnick = "clean_guy",      level = 20, share = 10 * GiB },
        s5 = stub_user{ firstnick = "op_guy",         level = 60, share = 0 },
        s6 = stub_user{ firstnick = "manual_guy",     level = 20, share = 0 },  -- also in block_tbl
    }
    local op, replied_of = op_user( )
    local r = onbmsg( op, "trafficmanager", "show blocks" )
    local out = replied_of( )
    eq( "show blocks returns PROCESSED", r, 1 )
    eq( "auto: section header present",  contains( out, "Auto-blocked ( online )" ), true )

    eq( "auto: zeroshare_guy listed",    contains( out, "zeroshare_guy" ), true )
    eq( "auto: zeroshare reason",        contains( out, "0 B share" ),     true )
    eq( "auto: small_guy listed",        contains( out, "small_guy" ),     true )
    eq( "auto: minshare reason",         contains( out, "Below minshare" ), true )
    eq( "auto: level_guy listed",        contains( out, "level_guy" ),     true )
    eq( "auto: level reason + name",     contains( out, "Blocked level [ Guest ]" ), true )

    eq( "auto: clean_guy NOT listed",    contains( out, "clean_guy" ),     false )
    eq( "auto: op_guy NOT listed (>= oplevel)", contains( out, "op_guy" ), false )

    eq( "manual: manual_guy present",    contains( out, "manual_guy" ),    true )
    eq( "manual: manual_guy appears once (not duplicated in auto)", count( out, "manual_guy" ), 1 )
    eq( "manual: block reason present",  contains( out, "manual reason" ), true )
    eq( "manual: blocker present",       contains( out, "admin" ),         true )
end

----------------------------------------------------------------------
-- 2. show blocks: no online auto-blocked user -> "(none)" placeholder.
----------------------------------------------------------------------

do
    _online = {
        s1 = stub_user{ firstnick = "clean_guy", level = 20, share = 10 * GiB },
    }
    local op, replied_of = op_user( )
    onbmsg( op, "trafficmanager", "show blocks" )
    local out = replied_of( )
    eq( "empty auto: (none) placeholder", contains( out, "(none)" ), true )
    eq( "empty auto: clean_guy still not listed", contains( out, "clean_guy" ), false )
end

----------------------------------------------------------------------
-- 3. show settings: minshare-check toggle now reported.
----------------------------------------------------------------------

do
    local op, replied_of = op_user( )
    local r = onbmsg( op, "trafficmanager", "show settings" )
    local out = replied_of( )
    eq( "show settings returns PROCESSED",   r, 1 )
    eq( "settings: 0-B-share line present",  contains( out, "Block users with 0 B share" ), true )
    eq( "settings: minshare line present",   contains( out, "Block users below minshare" ), true )
end

----------------------------------------------------------------------
-- 4. non-op is denied show blocks (permission gate intact).
----------------------------------------------------------------------

do
    local replied
    local low = {
        level = function( ) return 20 end,
        reply = function( _, msg ) replied = msg end,
    }
    _online = { }
    onbmsg( low, "trafficmanager", "show blocks" )
    eq( "denied: low-level got denial reply", contains( replied, "not allowed" ), true )
end

----------------------------------------------------------------------
-- 5. lang-file template placeholder parity. The show-blocks / settings
--    call sites pass a fixed number of args; the bundled lang files
--    MUST carry the matching %s count. Lang files are add-only on
--    upgrade (never overwritten), so a bundled-file edit that drops a
--    %s is a realistic drift. The auto-block %s is intentionally LAST
--    in msg_users so a stale two-%s file degrades gracefully rather
--    than mislabelling the section - this guards the bundled files.
----------------------------------------------------------------------

do
    -- Lang files are per-language JSON now (#301 P3): scripts/lang/<lng>/<name>.json.
    local dkjson = assert( loadfile( "dkjson/dkjson.lua" ) )( )
    local function load_lang_json( path )
        local f = assert( io.open( path, "rb" ) )
        local s = f:read( "*a" )
        f:close( )
        return ( assert( dkjson.decode( s, 1, nil ) ) )
    end
    local function pct( s ) return select( 2, ( s or "" ):gsub( "%%s", "" ) ) end
    for _, lc in ipairs( { "en", "de" } ) do
        local L = load_lang_json( "scripts/lang/" .. lc .. "/etc_trafficmanager.json" )
        eq( "lang " .. lc .. ": msg_users has 3 %s", pct( L.msg_users ), 3 )
        eq( "lang " .. lc .. ": opmsg has 8 %s",     pct( L.opmsg ),     8 )
    end
end

----------------------------------------------------------------------
-- NAT-traversal blocking (CCPM / transfer bypass, reported by Sopor):
-- a blocked user's C2C setup must be dropped on the DNAT / DRNT
-- fallback too, not only on CTM / RCM. Passive / CGNAT peers fall back
-- to NAT traversal, which pre-fix slipped through unblocked.
-- RED pre-fix: onNatTraversal / onNatTraversalReply are unregistered
-- (the two "registered" checks fail; the guarded calls are skipped).
----------------------------------------------------------------------

do
    local blocked = stub_user{ firstnick = "nat_blk", level = 10,  share = 0 }    -- auto-blocked level
    local clean   = stub_user{ firstnick = "nat_cln", level = 20,  share = 10 * GiB }  -- 10 GiB, above min_share[20]=5 GiB
    local owner   = stub_user{ firstnick = "nat_own", level = 100, share = 0 }    -- >= masterlevel, exempt

    -- parity control: CTM / RCM already drop a blocked user's setup
    eq( "CTM blocks a blocked user", _registered.onConnectToMe( blocked, clean, { } ), 1 )
    eq( "RCM blocks a blocked user", _registered.onRevConnectToMe( blocked, clean, { } ), 1 )

    -- the fix: NAT traversal must mirror CTM / RCM
    eq( "onNatTraversal registered",      _registered.onNatTraversal ~= nil, true )
    eq( "onNatTraversalReply registered", _registered.onNatTraversalReply ~= nil, true )

    local nat = _registered.onNatTraversal
    local rnt = _registered.onNatTraversalReply
    if nat then
        eq( "NAT: blocked user   -> PROCESSED",           nat( blocked, clean,   { } ), 1 )
        eq( "NAT: blocked target -> PROCESSED",           nat( clean,   blocked, { } ), 1 )
        eq( "NAT: nobody blocked -> nil",                 nat( clean,   clean,   { } ), nil )
        eq( "NAT: blocked user + nil target -> PROCESSED", nat( blocked, nil, { } ), 1 )
        eq( "NAT: clean user + nil target -> nil",         nat( clean,   nil, { } ), nil )
        eq( "NAT: op (>= masterlevel) exempt -> nil",      nat( owner,   blocked, { } ), nil )
    end
    if rnt then
        eq( "RNT: blocked user   -> PROCESSED", rnt( blocked, clean, { } ), 1 )
        eq( "RNT: nobody blocked -> nil",       rnt( clean,   clean, { } ), nil )
    end
end

----------------------------------------------------------------------
-- external add() with a nil scriptname must degrade to msg_unknown,
-- NOT leak the literal string "nil" into the op report / block_tbl.
-- An operator's script (usr_upload_speed) called add(nick, nil, reason);
-- pre-fix `tostring( scriptname ) or msg_unknown` never fell back because
-- tostring(nil) is the truthy string "nil", so the report showed
-- "User:  nil" and appended "blocked by scriptname: nil".
-- RED pre-fix: the three assertions below FAIL (report shows "nil");
-- PASS patched (report shows msg_unknown = "<UNKNOWN>"). Target offline
-- so add() takes the plain external path (no target reply / desc flag).
----------------------------------------------------------------------

do
    _online = { }                                   -- ScriptProbe is offline
    _last_report = nil
    tm.add( "ScriptProbe", nil, "unit reason" )     -- external path, scriptname = nil
    local r = _last_report or ""
    eq( "nil-scriptname add: report User is not literal 'nil'", contains( r, "User:  nil" ), false )
    eq( "nil-scriptname add: no 'scriptname: nil' appended",    contains( r, "scriptname: nil" ), false )
    eq( "nil-scriptname add: degrades to msg_unknown",          contains( r, "User:  <UNKNOWN>" ), true )
end

----------------------------------------------------------------------
-- nick rename: a reg.nickchange onAudit event re-keys a manual block to
-- the new nick. Without the listener +nickchange (and the HTTP rename)
-- renames the user in user.tbl but leaves the block under the old
-- firstnick, silently unblocking them (reported by Sopor).
-- RED pre-fix: onAudit is unregistered -> the "registered" check fails
-- and the guarded move assertions are skipped.
----------------------------------------------------------------------

do
    eq( "rename: onAudit listener registered", _registered.onAudit ~= nil, true )
    if _registered.onAudit then
        -- manual_guy is in block_tbl from the initial _block_seed.
        _registered.onAudit( { action = "reg.nickchange",
            target = { nick = "renamed_guy" },
            meta   = { previous_nick = "manual_guy" } } )
        local op, replied_of = op_user( )
        _online = { }
        onbmsg( op, "trafficmanager", "show blocks" )
        local out = replied_of( )
        eq( "rename: new nick now listed as blocked", contains( out, "renamed_guy" ), true )
        eq( "rename: old nick no longer blocked",     contains( out, "manual_guy" ),  false )

        -- an unrelated audit event must not disturb the block table
        _registered.onAudit( { action = "ban.add", target = { nick = "x" }, meta = { } } )
        local op2, replied_of2 = op_user( )
        _online = { }
        onbmsg( op2, "trafficmanager", "show blocks" )
        eq( "rename: unrelated event ignored (renamed_guy still blocked)",
            contains( replied_of2( ), "renamed_guy" ), true )
    end
end

----------------------------------------------------------------------
-- summary
----------------------------------------------------------------------

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures > 0 and 1 or 0 )
