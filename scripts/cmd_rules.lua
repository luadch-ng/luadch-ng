--[[

    cmd_rules.lua by blastbeat

        - this script adds a command "rules" for hub rules
        - usage: [+!#]rules

        v0.07: by Aybo ( #703, WebUI Wave 3 )
            - the rules text is now operator-owned and upgrade-safe. It used
              to live ONLY in the Weblate-managed lang file
              ( scripts/lang/<lng>/cmd_rules.json ), which every upgrade
              overwrites - so custom rules were clobbered on upgrade and
              could only be changed by hand-editing a translation file. The
              text now lives in scripts/data/cmd_rules.tbl ( operator-owned,
              upgrade-excluded like all plugin state ). The lang string is
              demoted to a one-time SEED: on first load the store is seeded
              from lang.msg_rules and FROZEN ( origin="seed" ), so a later
              lang update never overwrites it. A PUT takes ownership
              ( origin="operator" ) and is never re-seeded.
            - HTTP API:
                GET    /v1/rules  ( read )  -> live text { text, is_default, default }
                PUT    /v1/rules  ( admin ) -> set the text { text: string }
                DELETE /v1/rules  ( admin ) -> reset to the lang default
              Mirrors etc_motd's content endpoints exactly ( one shape, no
              divergence ).

        v0.06: by pulsar
            - removed "cmd_rules_rules" from "/cfg/cfg.tbl"
            - added rules msg to the lang files

        v0.05: by pulsar
            - possibility to set target (main/pm/both)
            - add new table lookups
            - code cleaning

        v0.04: by pulsar
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.03: by blastbeat
            - updated script api
            - regged hubcommand

        v0.02: by blastbeat
            - added language files and ucmd

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "cmd_rules"
local scriptversion = "0.07"

local cmd = "rules"


----------------------------
--[DEFINITION/DECLARATION]--
----------------------------

--// table lookups
local cfg_get = cfg.get
local cfg_loadlanguage = cfg.loadlanguage
local hub_getbot = hub.getbot()
local hub_debug = hub.debug
local hub_import = hub.import
local util_loadtable = util.loadtable
local util_savetable = util.savetable

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg_loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub_debug( err )
local minlevel = cfg_get( "cmd_rules_minlevel" )
local destination_main = cfg_get( "cmd_rules_destination_main" )
local destination_pm = cfg_get( "cmd_rules_destination_pm" )

--// msgs
local help_title = "cmd_rules.lua"
local help_usage = lang.help_usage or "[+!#]rules"
local help_desc = lang.help_desc or "sends the hub rules to user"

local ucmd_menu = lang.ucmd_menu or  { "General", "Rules" }

--// default seed: the lang string is the localized default, demoted to a
--   one-time seed for the operator-owned store below.
local default_rules = lang.msg_rules or ""

--// operator-owned store: { text = <string>, origin = "seed" | "operator" }.
--   scripts/data is upgrade-excluded, so operator rules survive both a
--   software upgrade and a lang update. Probe with io.open FIRST so a fresh
--   hub ( no store yet, until the first onStart seed writes it ) does not log
--   a `checkfile: No such file` line every boot ( hub_runtime #445 / lockdown
--   v0.02 first-run-noise lesson ).
local rules_file = "scripts/data/cmd_rules.tbl"
local function load_store( )
    local f = io.open( rules_file, "r" )
    if not f then return { } end
    f:close( )
    return util_loadtable( rules_file ) or { }
end
local rules_tbl = load_store( )

--// text cap for the PUT path ( the stored text also frames the outbound ADC
--   message ). Generous: a banner of rules is a few hundred bytes; 16 KiB
--   leaves ample room without letting the store or the frame grow unbounded.
local RULES_MAX = 16384


----------
--[CODE]--
----------

-- Normalise CRLF / lone CR to LF, then replace every remaining control byte
-- EXCEPT tab + newline with '?'. The rules text is a multi-line banner, so -
-- unlike util.strip_control_bytes, which strips \n too - newlines (and tabs)
-- must survive: adclib.escape handles '\n' on the wire and the client renders
-- the banner across lines. Windows-pasted text arrives with \r\n; normalise it
-- to \n rather than leaving a '?' per line. Any other control byte ( \0, \v,
-- ... ) would mis-frame the outbound ADC message, so it is scrubbed to '?'.
local function sanitise_text( s )
    return ( s:gsub( "\r\n", "\n" ):gsub( "\r", "\n" ):gsub( "[\0-\8\11-\31\127]", "?" ) )
end

-- The live rules text: the operator override if the store holds one, else the
-- ( seeded ) lang default. Read at delivery time so a PUT applies without a
-- +reload.
local function current_rules( )
    return rules_tbl.text or default_rules
end


-------------------
--[HTTP HANDLERS]--
-------------------

-- GET /v1/rules ( read scope ). Live text, read-only. `is_default` is true while
-- the text is still the ( seeded / reset ) default, false once an operator has
-- set it via PUT. `default` is the current lang default, i.e. what DELETE resets
-- to. Read, not admin: the rules are shown to users via `+rules`, so they are
-- not secret ( same posture as GET /v1/topic ).
local function http_handler_get_rules( req )
    return { status = 200, data = {
        text       = current_rules( ),
        is_default = rules_tbl.origin ~= "operator",
        default    = default_rules,
    } }
end

-- PUT /v1/rules ( admin scope ). Body { text: string }. Sets the operator rules
-- ( control bytes except tab/newline scrubbed, capped at RULES_MAX ) and takes
-- ownership ( origin -> "operator" ), so no later lang update / upgrade seed
-- overwrites it. An empty string is valid ( `+rules` then sends nothing ); use
-- DELETE to reset to the default instead.
local function http_handler_put_rules( req )
    local body = req.body or { }
    local text = body.text
    if type( text ) ~= "string" then
        return { status = 400, error = { code = "E_BAD_INPUT", message = "text must be a string" } }
    end
    if #text > RULES_MAX then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "text too long ( max " .. RULES_MAX .. " bytes )" } }
    end
    local clean = sanitise_text( text )
    rules_tbl = { text = clean, origin = "operator" }
    util_savetable( rules_tbl, "rules_tbl", rules_file )
    local by = util_http.operator_label( req )
    audit.fire( audit.build( "hub.rules.set", { nick = by, sid = "<http>" }, nil, nil, nil ) )
    return { status = 200, data = { text = clean, is_default = false } }
end

-- DELETE /v1/rules ( admin scope ). Resets the rules to the current lang default
-- ( origin -> "seed" ), re-tracking the shipped / translated default. No
-- X-Confirm: a rules reset is not disruptive.
local function http_handler_delete_rules( req )
    rules_tbl = { text = default_rules, origin = "seed" }
    util_savetable( rules_tbl, "rules_tbl", rules_file )
    local by = util_http.operator_label( req )
    audit.fire( audit.build( "hub.rules.reset", { nick = by, sid = "<http>" }, nil, nil, nil ) )
    return { status = 200, data = { text = default_rules, is_default = true } }
end


-----------------
--[LIFECYCLE ]--
-----------------

local onbmsg = function( user )
    local user_level = user:level()
    if user_level >= minlevel then
        -- Text is read live so a PUT applies to the next `+rules` without a +reload.
        local msg = current_rules( )
        if msg ~= "" then
            if destination_main then user:reply( msg, hub_getbot ) end
            if destination_pm then user:reply( msg, hub_getbot, hub_getbot ) end
        end
    end
    return PROCESSED
end

hub.setlistener( "onStart", { },
    function( )
        -- One-time seed: demote the lang default into the operator-owned store
        -- and FREEZE it ( no re-seed on later boots ), so a subsequent lang
        -- update never overwrites the operator's text. Skips an empty default
        -- ( e.g. the untranslated sv lang file ) so we never persist an empty
        -- override that would mask a later non-empty default. Idempotent: runs
        -- only while the store has no origin marker yet.
        if not rules_tbl.origin and default_rules ~= "" then
            rules_tbl = { text = default_rules, origin = "seed" }
            util_savetable( rules_tbl, "rules_tbl", rules_file )
        end

        local help = hub_import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, minlevel )  -- reg help
        end
        local ucmd = hub_import( "etc_usercommands" )  -- add usercommand
        if ucmd then
            ucmd.add( ucmd_menu, cmd, { }, { "CT1" }, minlevel )
        end
        local hubcmd = hub_import( "etc_hubcommands" )  -- add hubcommand
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, minlevel ) )

        -- HTTP API ( #703 ). Coexists with the ADC `+rules` above. Raw
        -- hub.http_register ( hub-control endpoint, no SID target ), same shape
        -- as etc_motd's content endpoints. No X-Confirm: editing hub content is
        -- not disruptive.
        if hub.http_register then
            hub.http_register( "GET", "/v1/rules", "read", http_handler_get_rules, {
                plugin = scriptname,
                description = "read the live hub rules text ( = ADC `+rules` ): the operator override if set, else the lang default seed. response { text, is_default, default }.",
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                    default    = { type = "string", required = true },
                },
            } )
            hub.http_register( "PUT", "/v1/rules", "admin", http_handler_put_rules, {
                plugin = scriptname,
                description = "set the hub rules text. body { text: string } ( <= 16384 bytes; control bytes except tab / newline are scrubbed ); an empty string sends nothing. Takes ownership so a later lang update / upgrade never overwrites it. Use DELETE to reset to the lang default.",
                request_schema = {
                    text = { type = "string", max_length = RULES_MAX, required = true },
                },
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/rules", "admin", http_handler_delete_rules, {
                plugin = scriptname,
                description = "reset the hub rules text to the current lang default ( drops the operator override ). response { text, is_default }.",
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                },
            } )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// expose internals for unit tests
return {
    _sanitise_text = sanitise_text,
    _current_rules = function( ) return current_rules( ) end,
    _store         = function( ) return rules_tbl end,
}
