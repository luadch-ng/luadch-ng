--[[

    cmd_talk.lua by pulsar

        description: sends your msg without nickname

        usage: [+!#]talk <MSG>

        v1.3:
            - HTTP API: POST /v1/chat - post to main chat as the hubbot (admin scope)  webui#177 A
            - extract post_to_mainchat() shared by +talk and the HTTP handler; mirror
              hubbot posts into etc_chatlog (via its new log_line) so they appear in
              +history / GET /v1/chatlog

        v1.2 by blastbeat:
            - get rid of useless 'bot_opchat_activate' variable

        v1.1:
            - fixed pattern matching  / thx Sopor

        v1.0:
            - small fix  / thx Sopor
            - added description/usage to comment
            - using "onbmsg" function instead of "onBroadcast" listener

        v0.9:
            - added "msg_usage"
            - send "msg_usage" on missing param  / thx Sopor

        v0.8:
            - possibility to 'talk' in regchat and opchat, according with talk and chat permissions
            - add new table lookups and imports
            - code cleaning

        v0.7:
            - changed rightclick style

        v0.6:
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.5:
            - code cleaning

        v0.4:
            - Multilanguage Support
            - includet to rev279

        v0.3:
            - code cleaning
            - added: Help Feature (hub.import "cmd_help")

        v0.2:
            - sends your msg without nickname

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_talk"
local scriptversion = "1.3"

local cmd = "talk"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_debug = hub.debug
local hub_import = hub.import
local hub_broadcast = hub.broadcast
local hub_getbot = hub.getbot()
local hub_getusers = hub.getusers
local utf_match = utf.match

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )
local minlevel = cfg_get( "cmd_talk_minlevel" )
local regchat = hub_import( "bot_regchat" )
local regchat_nick = cfg_get( "bot_regchat_nick" )
local regchat_activate = cfg_get( "bot_regchat_activate" )
local regchat_permission = cfg_get( "bot_regchat_permission" )
local opchat = hub_import( "bot_opchat" )
local opchat_nick = cfg_get( "bot_opchat_nick" )
local opchat_permission = cfg_get( "bot_opchat_permission" )

--// msgs
local help_title = "cmd_talk.lua"
local help_usage = lang.help_usage or "[+!#]talk <MSG>"
local help_desc = lang.help_desc or "Talk without nickname"

local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local ucmd_menu = lang.ucmd_menu or { "User", "Messages", "Talk" }
local ucmd_what = lang.ucmd_what or "Message:"
local msg_usage = lang.msg_usage or "Usage: [+!#]talk <MSG>"


----------
--[CODE]--
----------

-- Post a line into main chat as the hubbot (BMSG via hub.broadcast,
-- bot passed as `from` only). Also mirror it into etc_chatlog so it
-- appears in `+history` and the GET /v1/chatlog feed - hub.broadcast
-- does not fire onBroadcast, so etc_chatlog would otherwise miss
-- hubbot posts. Chat filters / flood rules are bypassed by design
-- (the hubbot is not a normal chat user). Shared by the ADC `+talk`
-- command and the HTTP POST /v1/chat handler (webui#177 A).
local post_to_mainchat = function( msg )
    hub_broadcast( msg, hub_getbot )
    local chatlog = hub_import( "etc_chatlog" )
    if chatlog and chatlog.log_line then
        chatlog.log_line( hub_getbot:nick(), msg )
    end
end

local onbmsg = function( user, command, parameters )
    local user_level = user:level()
    if user_level < minlevel then
        user:reply( msg_denied, hub_getbot )
        return PROCESSED
    end
    local param = utf_match( parameters, "^(.*)" )
    if param then
        post_to_mainchat( param )
        return PROCESSED
    end
    user:reply( msg_usage, hub_getbot )
    return PROCESSED
end

-- HTTP handler: POST /v1/chat. Admin scope. Posts a line into main
-- chat as the hubbot (= ADC `+talk`). Body { message } (max 1024,
-- control-byte sanitised). Per webui#177: end users see the hubbot;
-- the audit actor is the real operator (req.actor / X-Actor) with a
-- token-label / "http-api" fallback. The response `sender` is the
-- hubbot nick, NOT the token label - no token-fingerprint leak.
local http_handler_chat = function( req )
    local body = req.body or { }
    local message = body.message
    if not message or message == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing or empty 'message' field" } }
    end
    local clean_msg = util.strip_control_bytes( message )
    post_to_mainchat( clean_msg )
    local actor = req.actor
    if not actor or actor == "" then actor = req.token_label or "http-api" end
    audit.fire( audit.build( "hub.chat.post", { nick = actor, sid = "<http>" }, nil, clean_msg, nil ) )
    return { status = 200, data = {
        action  = "chat",
        message = clean_msg,
        sender  = hub_getbot:nick(),
    } }
end

hub.setlistener( "onPrivateMessage", {},
    function( user, target, adccmd, msg )
        local cmd1, cmd2 = utf_match( msg, "^[+!#](%a+) (.*)" )
        local user_level = user:level()
        local target_level = target:level()
        local target_nick = target:nick()
        if cmd1 == cmd and cmd2 then
            if target_nick == regchat_nick then
                if regchat_activate then
                    if ( ( user_level >= minlevel ) and regchat_permission[ user_level ] ) then
                        regchat.feed( cmd2 )
                    else
                        user:reply( msg_denied, hub_getbot, target )
                    end
                    return PROCESSED
                end
            end
            if target_nick == opchat_nick then
                if opchat then
                    if ( ( user_level >= minlevel ) and opchat_permission[ user_level ] ) then
                        opchat.feed( cmd2 )
                    else
                        user:reply( msg_denied, hub_getbot, target )
                    end
                    return PROCESSED
                end
            end
        end
        return nil
    end
)

hub.setlistener( "onStart", {},
    function()
        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )
        end
        local ucmd = hub_import( "etc_usercommands" )
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { "%[line:" .. ucmd_what .. "]" }, { "CT1" }, minlevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )
        -- HTTP API endpoint (webui#177 A). Coexists with the ADC
        -- `+talk` chat-cmd above; both go through post_to_mainchat.
        -- Raw hub.http_register (not util_http): hub-control endpoint
        -- with no SID target. admin scope is the authorisation gate.
        if hub.http_register then
            hub.http_register( "POST", "/v1/chat", "admin", http_handler_chat, {
                plugin = scriptname,
                description = "post a message into main chat as the hubbot (= ADC `+talk`); body { message }",
                request_schema = {
                    message = { type = "string", required = true, max_length = 1024 },
                },
                response_schema = {
                    action  = { type = "string", required = true },
                    message = { type = "string", required = true },
                    sender  = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

-- exposed for the unit tests (webui#177 A: POST /v1/chat hubbot post)
return {
    _http_handler_chat = http_handler_chat,
    _post_to_mainchat  = post_to_mainchat,
}
