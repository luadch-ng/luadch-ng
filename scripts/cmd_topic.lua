--[[

    cmd_topic.lua by Night

        - this script adds a command "topic"
        - usage: [+!#]topic <NEW-TOPIC>|default

        v0.04:
            - HTTP API: POST /v1/topic (admin scope)  #82 deferred Phase-2-spec
            - extract do_set_topic / do_reset_topic helpers shared by ADC + HTTP

        v0.03: by pulsar
            - add possibility to reset topic to default  / requested by Sopor
            - using report import functionality now

        v0.02: by pulsar
            - export permission to "/cfg/cfg.tbl"
            - add lang feature
            - add topic database
            - some changes and code cleaning

		v0.01: by Night
            - add topic command

]]--


--// settings begin //--

local scriptname = "cmd_topic"
local scriptversion = "0.05"

local cmd = "topic"

--// settings end //--


--// imports
local help, ucmd, hubcmd

--// table lookups
local hub_getbot = hub.getbot()
local hub_broadcast = hub.broadcast
local hub_escapeto = hub.escapeto
local hub_sendtoall = hub.sendtoall
local hub_import = hub.import
local hub_debug = hub.debug
local util_loadtable = util.loadtable
local util_savetable = util.savetable
local utf_match = utf.match
local utf_format = utf.format
local cfg_get = cfg.get

--// permission
local scriptlang = cfg_get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local minlevel = cfg_get( "cmd_topic_minlevel" )
local report = hub_import( "etc_report" )
local report_activate = cfg_get( "cmd_topic_report" )
local report_hubbot = cfg_get( "cmd_topic_report_hubbot" )
local report_opchat = cfg_get( "cmd_topic_report_opchat" )
local llevel = cfg_get( "cmd_topic_llevel" )

--// database
local topic_file = "scripts/data/cmd_topic.tbl"
local topic_tbl = util_loadtable( topic_file ) or {}
local default_topic = cfg_get( "hub_description" )

--// lang, msgs
local help_title = "etc_topic.lua"
local help_usage = lang.help_usage or "[+!#]topic <NEW-TOPIC>|default"
local help_desc = lang.help_desc or "Sets a new hub topic or resets it to default"

local msg_topic_changed = lang.msg_topic_changed or "%s  changed hub topic to: %s   |   old topic was: %s"
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "Usage: [+!#]topic <NEW-TOPIC>|default"
local msg_topic_reset = lang.msg_topic_reset or "%s  reset hub topic to default: %s"

local ucmd_menu = lang.ucmd_menu or { "Hub", "Core", "Hub topic", "set new topic" }
local ucmd_menu2 = lang.ucmd_menu2 or { "Hub", "Core", "Hub topic", "set to default" }
local ucmd_popup = lang.ucmd_popup or "New Topic:"

--// flags
local old, new = "old", "new"

--// CODE

-- Shared action helpers used by BOTH the ADC `+topic` chat-cmd path
-- AND the HTTP `POST /v1/topic` path (#82). Each helper performs
-- the persistence + IINF broadcast for its operation and returns
-- the formatted report message string for the caller to send via
-- report.send at the right moment for its surface.
--
-- `actor_label` is whatever name the operator uses on their
-- surface: a nick for the ADC path, a non-secret token label for
-- the HTTP path. Caller is responsible for control-byte
-- sanitisation of the inputs (defence in depth around adclib
-- escape, matching Phase 2/3 plugin migrations).
local do_set_topic = function( topic, actor_label )
    local previous = topic_tbl[ new ] or default_topic
    if topic_tbl[ new ] then
        topic_tbl[ old ] = topic_tbl[ new ]
        topic_tbl[ new ] = topic
    else
        topic_tbl[ old ] = default_topic
        topic_tbl[ new ] = topic
    end
    util_savetable( topic_tbl, "topic_tbl", topic_file )
    hub_sendtoall( "IINF DE" .. hub_escapeto( topic ) .. "\n" )
    -- #263 PR-B: surface topic-change into the GET /v1/events stream.
    if http_events and http_events.emit then
        http_events.emit( "topic_changed", {
            topic    = topic or "",
            previous = previous or "",
            by       = actor_label or "",
        } )
    end
    return utf_format( msg_topic_changed, actor_label, topic, topic_tbl[ old ] )
end

local do_reset_topic = function( actor_label )
    local previous = topic_tbl[ new ] or default_topic
    topic_tbl = { }
    util_savetable( topic_tbl, "topic_tbl", topic_file )
    hub_sendtoall( "IINF DE" .. hub_escapeto( default_topic ) .. "\n" )
    -- #263 PR-B: topic-reset is just topic_changed to default.
    if http_events and http_events.emit then
        http_events.emit( "topic_changed", {
            topic    = default_topic or "",
            previous = previous or "",
            by       = actor_label or "",
        } )
    end
    return utf_format( msg_topic_reset, actor_label, default_topic )
end

local ontopic = function( user, command, parameters )
    local user_level = user:level()
    local user_nick = user:nick()
    local topic = parameters
	if user_level < minlevel then
		user:reply( msg_denied, hub_getbot )
		return PROCESSED
	end
    if topic == "" then
        user:reply( msg_usage, hub_getbot )
        return PROCESSED
    end
    local msg
    local action_name = "hub.topic.set"
    if topic == "default" then
        msg = do_reset_topic( user_nick )
        action_name = "hub.topic.reset"
    else
        msg = do_set_topic( topic, user_nick )
    end
    user:reply( msg, hub_getbot )
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    audit.fire( audit.build( action_name, user, nil, nil,
        ( topic ~= "default" and { topic = topic } or nil ) ) )
    return PROCESSED
end

-- HTTP handler: POST /v1/topic (#82). Admin scope.
--
-- Body shape: `{topic?: string}` (max 256 chars, control-byte
-- sanitised). Missing OR empty topic field resets the hub topic
-- to `cfg.hub_description`. Non-empty topic sets it.
--
-- Operators wanting to literally set the hub topic to the word
-- "default" can do so via HTTP (`{"topic": "default"}`) - the
-- magic-keyword pattern from the ADC `+topic default` cmd does
-- NOT apply on the HTTP path because we have a structured body
-- to express "reset" via absence.
--
-- The ADC-side `cmd_topic_minlevel` does NOT apply on the HTTP
-- path: the bearer token's `admin` scope IS the authorisation
-- gate (consistent with the rest of #82).
local http_handler_topic = function( req )
    local body = req.body or { }
    local topic = body.topic
    local actor_label = util.strip_control_bytes( req.token_label or "http-api" )
    local previous = topic_tbl[ new ] or default_topic
    local msg, action, new_topic
    local audit_action_name = "hub.topic.set"
    if not topic or topic == "" then
        msg = do_reset_topic( actor_label )
        action = "topic-reset"
        new_topic = default_topic
        audit_action_name = "hub.topic.reset"
    else
        local clean_topic = util.strip_control_bytes( topic )
        msg = do_set_topic( clean_topic, actor_label )
        action = "topic-set"
        new_topic = clean_topic
    end
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg )
    audit.fire( audit.build( audit_action_name,
        { nick = actor_label, sid = "<http>" }, nil, nil,
        ( audit_action_name == "hub.topic.set" and { topic = new_topic } or nil ) ) )
    return { status = 200, data = {
        action   = action,
        topic    = new_topic,
        previous = previous,
    } }
end

hub.setlistener( "onLogin", { },
    function( user )
        if topic_tbl[ new ] then
            user:send( "IINF DE" .. hub_escapeto( topic_tbl[ new ] ) .. "\n" )
        end
        return nil
    end
)

hub.setlistener( "onStart", { },
    function( )
	    help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )    -- reg help
        end
		ucmd = hub_import( "etc_usercommands" )    -- add usercommand
        if ucmd then
			ucmd.add( ucmd_menu, cmd, { "%[line: " .. ucmd_popup .. "]" }, { "CT1" }, minlevel )
            ucmd.add( ucmd_menu2, cmd, { "default" }, { "CT1" }, minlevel )
        end
        hubcmd = hub_import( "etc_hubcommands" )    -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, ontopic, minlevel ) )
        -- HTTP API endpoint (#82). Coexists with the ADC `+topic`
        -- chat-cmd above. Raw hub.http_register (not util_http)
        -- because this is a hub-control endpoint with no SID target.
        if hub.http_register then
            hub.http_register( "POST", "/v1/topic", "admin", http_handler_topic, {
                plugin = scriptname,
                description = "set or reset the hub topic (= ADC `+topic <text>` or `+topic default`). body { topic?: string }; absent / empty resets to cfg.hub_description, non-empty sets.",
                request_schema = {
                    topic = { type = "string", max_length = 256 },
                },
                response_schema = {
                    action   = { type = "string", required = true },
                    topic    = { type = "string", required = true },
                    previous = { type = "string", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded "..scriptname.." "..scriptversion.." **" )