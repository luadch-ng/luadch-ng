--[[

    tests/unit/cmd_talk_endpoint_test.lua

    Regression test for webui#177 A (hub side, #669): posting to main
    chat as the hubbot from the HTTP API.

    Two coupled units, tested together (the cmd_talk handler mirrors
    through the REAL etc_chatlog.log_line):

      1. etc_chatlog v1.7 exports `log_line(nick, message)` so
         hub-originated main-chat posts - which go out via
         hub.broadcast and therefore never fire onBroadcast - are
         still recorded into the log buffer (and thus GET /v1/chatlog).
         It builds one entry, trims, control-byte sanitises, and no-ops
         on bad input.

      2. cmd_talk v1.3's POST /v1/chat handler broadcasts the message
         as the hubbot (BMSG: bot as `from`, no `pm`), returns
         {action:"chat", message, sender=<hubbot nick>} (NOT the token
         label - no fingerprint leak), records the real operator
         (req.actor, with token-label / "http-api" fallback) as the
         audit actor, and mirrors the post into etc_chatlog.

    FAIL-PRE-FIX: on the unpatched tree cmd_talk has no
    _http_handler_chat and etc_chatlog has no log_line, so both calls
    are `attempt to call a nil value` - the test is red. The
    assertions pin the behaviour.

    Run: lua5.4 tests/unit/cmd_talk_endpoint_test.lua

]]--

local failures, checks = 0, 0
local function ok( label, cond )
    checks = checks + 1
    if cond then io.write( "ok   " .. label .. "\n" )
    else failures = failures + 1; io.write( "FAIL " .. label .. "\n" ) end
end

-- shared sandbox-global stubs
_G.PROCESSED = "PROCESSED"
_G.os = os; _G.string = string; _G.table = table
_G.tonumber = tonumber; _G.tostring = tostring; _G.type = type
_G.ipairs = ipairs; _G.pairs = pairs

-- Mirror production util.strip_control_bytes EXACTLY (core/util.lua):
-- control chars (incl. 0x7f) are REPLACED with '?', non-strings -> "".
local function strip( s ) return ( type( s ) == "string" ) and ( s:gsub( "%c", "?" ) ) or "" end
_G.util = {
    loadtable            = function( ) return { } end,
    savearray            = function( ) end,
    strip_control_bytes  = function( s ) return strip( s ) end,
    getlowestlevel       = function( t ) local lo; for k in pairs( t ) do if not lo or k < lo then lo = k end end return lo or 0 end,
}

local _cfg = {
    language                        = "en",
    -- etc_chatlog
    etc_chatlog_min_level_adv       = 80,
    etc_chatlog_permission          = { },
    etc_chatlog_max_lines           = 200,
    etc_chatlog_default_lines       = 20,
    etc_msgmanager_permission_main  = { },
    -- cmd_talk
    cmd_talk_minlevel               = 10,
    bot_regchat_nick                = "RegChat",
    bot_regchat_activate            = false,
    bot_regchat_permission          = { },
    bot_opchat_nick                 = "OpChat",
    bot_opchat_permission           = { },
}
_G.cfg = {
    get          = function( k ) return _cfg[ k ] end,
    loadlanguage = function( ) return { } end,
}
_G.utf = {
    match  = function( s, pat ) return string.match( s, pat ) end,
    format = function( fmt, ... ) return string.format( fmt, ... ) end,
}

-- ===== Part 1: etc_chatlog.log_line =====
_G.hub = {
    setlistener   = function( ) end,
    debug         = function( ) end,
    getbot        = function( ) return { nick = function( ) return "HubBot" end } end,
    escapefrom    = function( s ) return s end,
    import        = function( ) return nil end,
    http_register = function( ) end,
}

local cl = assert( loadfile( "scripts/etc_chatlog.lua" ) )( )
ok( "etc_chatlog exports log_line", type( cl.log_line ) == "function" )

cl.log_line( "HubBot", "hello from bot" )
local tail1 = cl._get_log_tail( 1 )
ok( "log_line records one line",         #tail1 == 1 )
ok( "recorded nick is the hubbot",       tail1[ 1 ] and tail1[ 1 ].nick == "HubBot" )
ok( "recorded message body preserved",   tail1[ 1 ] and tail1[ 1 ].message == "hello from bot" )

cl.log_line( "Hub\1Bot", "a\2b" )
local tail2 = cl._get_log_tail( 1 )
ok( "log_line control-byte sanitises (-> '?')", tail2[ 1 ] and tail2[ 1 ].nick == "Hub?Bot" and tail2[ 1 ].message == "a?b" )

local before = #cl._t_log
cl.log_line( nil, "x" ); cl.log_line( "n", 123 ); cl.log_line( nil, nil )
ok( "log_line no-ops on bad input",      #cl._t_log == before )

-- ===== Part 2: cmd_talk POST /v1/chat =====
local bcast    -- last broadcast call
local audited  -- last audit event
local bot = { nick = function( ) return "HubBot" end, sid = function( ) return "AAAA" end }
_G.hub = {
    setlistener   = function( ) end,
    debug         = function( ) end,
    getbot        = function( ) return bot end,
    broadcast     = function( msg, from, pm, me ) bcast = { msg = msg, from = from, pm = pm, me = me } end,
    http_register = function( ) end,
    import        = function( name )
        if name == "etc_chatlog" then return cl end
        if name == "bot_regchat" or name == "bot_opchat" then return { feed = function( ) end } end
        return nil  -- cmd_help / etc_usercommands / etc_hubcommands: only used in onStart, which is not fired here
    end,
}
_G.audit = {
    build = function( action, actor, target, msg, extra ) return { action = action, actor = actor, msg = msg } end,
    fire  = function( ev ) audited = ev end,
}

local p = assert( loadfile( "scripts/cmd_talk.lua" ) )( )
ok( "cmd_talk exports _http_handler_chat", type( p._http_handler_chat ) == "function" )

local logbefore = #cl._t_log
local res = p._http_handler_chat( { body = { message = "hi chat" }, actor = "opNick", token_label = "webui (aB..Yz)" } )
ok( "valid post -> status 200",                     res and res.status == 200 )
ok( "action is chat",                               res and res.data and res.data.action == "chat" )
ok( "message echoed back",                          res and res.data and res.data.message == "hi chat" )
ok( "sender is the hubbot nick (no token leak)",    res and res.data and res.data.sender == "HubBot" )
ok( "broadcast as hubbot (from=bot, no pm -> BMSG)", bcast and bcast.msg == "hi chat" and bcast.from == bot and bcast.pm == nil )
ok( "post mirrored into the chat log",              #cl._t_log == logbefore + 1 )
local lastlog = cl._get_log_tail( 1 )[ 1 ]
ok( "mirrored line attributed to the hubbot",       lastlog and lastlog.nick == "HubBot" and lastlog.message == "hi chat" )
ok( "audit action is hub.chat.post",                audited and audited.action == "hub.chat.post" )
ok( "audit actor is the real operator (req.actor)", audited and audited.actor and audited.actor.nick == "opNick" )

p._http_handler_chat( { body = { message = "x" }, token_label = "tok" } )
ok( "audit falls back to token_label when no actor", audited and audited.actor.nick == "tok" )

p._http_handler_chat( { body = { message = "y" } } )
ok( "audit falls back to http-api when neither present", audited and audited.actor.nick == "http-api" )

p._http_handler_chat( { body = { message = "he\1llo" }, actor = "op" } )
ok( "message control bytes sanitised before broadcast (-> '?')", bcast and bcast.msg == "he?llo" )

local e1 = p._http_handler_chat( { body = { message = "" } } )
ok( "empty message -> 400 E_BAD_INPUT", e1 and e1.status == 400 and e1.error and e1.error.code == "E_BAD_INPUT" )
local e2 = p._http_handler_chat( { body = { } } )
ok( "missing message -> 400", e2 and e2.status == 400 )
local e3 = p._http_handler_chat( { } )
ok( "missing body -> 400", e3 and e3.status == 400 )

-- the shared path used by the ADC `+talk` command directly: broadcasts
-- as the hubbot AND mirrors into the chat log (same as /v1/chat)
local dlog = #cl._t_log
p._post_to_mainchat( "via talk" )
ok( "_post_to_mainchat broadcasts as the hubbot (BMSG)", bcast and bcast.msg == "via talk" and bcast.from == bot and bcast.pm == nil )
ok( "_post_to_mainchat mirrors into the chat log",       #cl._t_log == dlog + 1 )
local tlog = cl._get_log_tail( 1 )[ 1 ]
ok( "+talk mirror attributed to the hubbot",             tlog and tlog.nick == "HubBot" and tlog.message == "via talk" )

io.write( string.format( "\n%d checks, %d failures\n", checks, failures ) )
os.exit( failures == 0 and 0 or 1 )
