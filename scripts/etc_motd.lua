--[[

    etc_motd.lua by blastbeat

        - this script sends a message to users after login

        v0.10: by Aybo ( #703, WebUI Wave 3 )
            - the MOTD text is now operator-owned and upgrade-safe. It used
              to live ONLY in the Weblate-managed lang file
              ( scripts/lang/<lng>/etc_motd.json ), which every upgrade
              overwrites - so a custom MOTD was clobbered on upgrade and
              could only be changed by hand-editing a translation file.
              The text now lives in scripts/data/etc_motd.tbl ( operator-
              owned, upgrade-excluded like all plugin state ). The lang
              string is demoted to a one-time SEED: on first load the store
              is seeded from lang.msg_motd and FROZEN ( origin="seed" ), so
              a later lang update never overwrites it. A PUT takes ownership
              ( origin="operator" ) and is never re-seeded.
            - HTTP API:
                GET    /v1/motd  ( read )  -> live text { text, is_default, default }
                PUT    /v1/motd  ( admin ) -> set the text { text: string }
                DELETE /v1/motd  ( admin ) -> reset to the lang default
              The endpoints register even when delivery is deactivated, so
              the text can be prepared before the MOTD is switched on.

        v0.09: by Aybo
            - placeholder substitution is gsub-based instead of
              string.format; both `{nick}` (preferred) and `%s` (legacy)
              are now supported. Any number of placeholders is fine, no
              more "bad argument #N to format" errors when an MOTD uses
              the placeholder twice (e.g. multilingual greetings).

        v0.08: by pulsar
            - removed table lookups

        v0.07: by pulsar
            - removed "etc_motd_motd" from "cfg/cfg.tbl"
            - added lang files
                - added banner msg to the lang files

        v0.06: by pulsar
            - possibility to activate/deactivate the script
            - possibility to use %s in the motd to get users nickname (without nicktag)

        v0.05: by pulsar
            - possibility to set target (main/pm/both)  / request by DerWahre
            - add new table lookups

        v0.04: by pulsar
            - add user permissions
            - export scriptsettings to "/cfg/cfg.tbl"

        v0.03: by blastbeat
            - clean up

        v0.02: by blastbeat
            - updated script api

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_motd"
local scriptversion = "0.10"

--// table lookups
local util_loadtable = util.loadtable
local util_savetable = util.savetable
local cfg_get = cfg.get
local hub_getbot = hub.getbot

--// imports
local scriptlang = cfg_get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local activate = cfg_get( "etc_motd_activate" )
local permission = cfg_get( "etc_motd_permission" )
local destination_main = cfg_get( "etc_motd_destination_main" )
local destination_pm = cfg_get( "etc_motd_destination_pm" )

--// default seed: the lang string is the localized default, demoted to a
--   one-time seed for the operator-owned store below.
local default_motd = lang.msg_motd or ""

--// operator-owned store: { text = <string>, origin = "seed" | "operator" }.
--   scripts/data is upgrade-excluded, so an operator MOTD survives both a
--   software upgrade and a lang update. Probe with io.open FIRST so a fresh
--   hub ( no store yet, until the first onStart seed writes it ) does not log
--   a `checkfile: No such file` line every boot ( hub_runtime #445 / lockdown
--   v0.02 first-run-noise lesson ).
local motd_file = "scripts/data/etc_motd.tbl"
local function load_store( )
    local f = io.open( motd_file, "r" )
    if not f then return { } end
    f:close( )
    return util_loadtable( motd_file ) or { }
end
local motd_tbl = load_store( )

--// text cap for the PUT path ( the stored text also frames the outbound ADC
--   message that delivery builds ). Generous: a banner MOTD is a few hundred
--   bytes; 16 KiB leaves ample room without letting the store or the frame
--   grow unbounded.
local MOTD_MAX = 16384


----------
--[CODE]--
----------

-- Normalise CRLF / lone CR to LF, then replace every remaining control byte
-- EXCEPT tab + newline with '?'. The MOTD is a multi-line banner, so - unlike
-- util.strip_control_bytes, which strips \n too - newlines (and tabs) must
-- survive: adclib.escape handles '\n' on the wire and the client renders the
-- banner across lines. Windows-pasted text arrives with \r\n; normalise it to
-- \n rather than leaving a '?' per line. Any other control byte ( \0, \v, ... )
-- would mis-frame the outbound ADC message, so it is scrubbed to '?'.
local function sanitise_text( s )
    return ( s:gsub( "\r\n", "\n" ):gsub( "\r", "\n" ):gsub( "[\0-\8\11-\31\127]", "?" ) )
end

-- The live MOTD text: the operator override if the store holds one, else the
-- ( seeded ) lang default. Read at delivery time so a PUT applies without a
-- +reload.
local function current_motd( )
    return motd_tbl.text or default_motd
end


-------------------
--[HTTP HANDLERS]--
-------------------

-- GET /v1/motd ( read scope ). Live text, read-only. `is_default` is true while
-- the text is still the ( seeded / reset ) default, false once an operator has
-- set it via PUT. `default` is the current lang default, i.e. what DELETE resets
-- to. Read, not admin: the MOTD is shown to users on login, so it is not secret
-- ( same posture as GET /v1/topic ).
local function http_handler_get_motd( req )
    return { status = 200, data = {
        text       = current_motd( ),
        is_default = motd_tbl.origin ~= "operator",
        default    = default_motd,
    } }
end

-- PUT /v1/motd ( admin scope ). Body { text: string }. Sets the operator MOTD
-- ( control bytes except tab/newline scrubbed, capped at MOTD_MAX ) and takes
-- ownership ( origin -> "operator" ), so no later lang update / upgrade seed
-- overwrites it. An empty string is a valid MOTD ( delivers nothing ); use
-- DELETE to reset to the default instead.
local function http_handler_put_motd( req )
    local body = req.body or { }
    local text = body.text
    if type( text ) ~= "string" then
        return { status = 400, error = { code = "E_BAD_INPUT", message = "text must be a string" } }
    end
    if #text > MOTD_MAX then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "text too long ( max " .. MOTD_MAX .. " bytes )" } }
    end
    local clean = sanitise_text( text )
    motd_tbl = { text = clean, origin = "operator" }
    util_savetable( motd_tbl, "motd_tbl", motd_file )
    local by = util_http.operator_label( req )
    audit.fire( audit.build( "hub.motd.set", { nick = by, sid = "<http>" }, nil, nil, nil ) )
    return { status = 200, data = { text = clean, is_default = false } }
end

-- DELETE /v1/motd ( admin scope ). Resets the MOTD to the current lang default
-- ( origin -> "seed" ), re-tracking the shipped / translated default. No
-- X-Confirm: an MOTD reset is not disruptive.
local function http_handler_delete_motd( req )
    motd_tbl = { text = default_motd, origin = "seed" }
    util_savetable( motd_tbl, "motd_tbl", motd_file )
    local by = util_http.operator_label( req )
    audit.fire( audit.build( "hub.motd.reset", { nick = by, sid = "<http>" }, nil, nil, nil ) )
    return { status = 200, data = { text = default_motd, is_default = true } }
end


-----------------
--[LIFECYCLE ]--
-----------------

hub.setlistener( "onLogin", { },
    function( user )
        if not activate then return nil end
        if permission[ user:level() ] then
            -- v0.09: gsub-based template replacement. Both {nick} and %s expand
            -- to the user's firstnick, any number of times, with no format-style
            -- "wrong argument count" errors. Text is read live so a PUT applies
            -- to the next login without a +reload. FUNCTION replacements ( not a
            -- plain string ): a firstnick containing '%' would otherwise raise
            -- "invalid use of '%' in replacement string" and abort this login's
            -- handler ( a function replacement is inserted verbatim ).
            local nick = user:firstnick()
            local repl = function( ) return nick end
            local msg = ( current_motd():gsub( "{nick}", repl ):gsub( "%%s", repl ) )
            if msg ~= "" then
                if destination_main then user:reply( msg, hub_getbot() ) end
                if destination_pm then user:reply( msg, hub_getbot(), hub_getbot() ) end
            end
        end
        return nil
    end
)

hub.setlistener( "onStart", { },
    function( )
        -- One-time seed: demote the lang default into the operator-owned store
        -- and FREEZE it ( no re-seed on later boots ), so a subsequent lang
        -- update never overwrites the operator's text. Skips an empty default
        -- ( e.g. an untranslated lang file ) so we never persist an empty
        -- override that would mask a later non-empty default. Idempotent: runs
        -- only while the store has no origin marker yet.
        if not motd_tbl.origin and default_motd ~= "" then
            motd_tbl = { text = default_motd, origin = "seed" }
            util_savetable( motd_tbl, "motd_tbl", motd_file )
        end
        -- HTTP API ( #703 ). Registered even when MOTD delivery is deactivated,
        -- so an operator can prepare the text before switching it on. Raw
        -- hub.http_register ( hub-control endpoint, no SID target ), same as
        -- cmd_topic. No X-Confirm: editing hub content is not disruptive.
        if hub.http_register then
            hub.http_register( "GET", "/v1/motd", "read", http_handler_get_motd, {
                plugin = scriptname,
                description = "read the live MOTD text ( the message shown to users after login ): the operator override if set, else the lang default seed. response { text, is_default, default }.",
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                    default    = { type = "string", required = true },
                },
            } )
            hub.http_register( "PUT", "/v1/motd", "admin", http_handler_put_motd, {
                plugin = scriptname,
                description = "set the MOTD text. body { text: string } ( <= " .. MOTD_MAX .. " bytes; control bytes except tab / newline are scrubbed ); an empty string delivers nothing. Takes ownership so a later lang update / upgrade never overwrites it. Use DELETE to reset to the lang default.",
                request_schema = {
                    text = { type = "string", max_length = MOTD_MAX, required = true },
                },
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/motd", "admin", http_handler_delete_motd, {
                plugin = scriptname,
                description = "reset the MOTD text to the current lang default ( drops the operator override ). response { text, is_default }.",
                response_schema = {
                    text       = { type = "string", required = true },
                    is_default = { type = "boolean", required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. ( activate and "" or " ( delivery inactive )" ) .. " **" )

--// expose internals for unit tests
return {
    _sanitise_text = sanitise_text,
    _current_motd  = function( ) return current_motd( ) end,
    _store         = function( ) return motd_tbl end,
}
