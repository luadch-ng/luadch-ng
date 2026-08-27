--[[

    etc_webhook.lua by Aybo

        Generic INBOUND webhook receiver. An external service POSTs a
        signed JSON body to a hub HTTP endpoint; the hub verifies the
        HMAC-SHA256 signature over the raw body, applies an event filter
        + dedup, renders a templated message and announces it in the hub
        chat as a named bot. First consumer: a Discourse forum (new
        topics / posts); the same protocol serves GitHub / GitLab / CI /
        monitoring - anything that signs the request body with
        HMAC-SHA256.

        This is the PUSH-inbound mirror of etc_status_push (outbound) and
        the inbound complement of etc_prometheus (pull /metrics).

        Multi-endpoint: the operator-edited cfg/webhooks.tbl holds an
        array of endpoints, each with its own path, signature/event/id
        headers, event filter, bot nick, min-level and message templates
        ( {dotted.path} placeholders resolved against the decoded body,
        plus {event} ). Secrets are resolved per endpoint env-var-first
        (LUADCH_ETC_WEBHOOK_<NAME>_SECRET, else the etc_webhook_<name>_secret
        cfg key) and finally the inline `secret` in cfg/webhooks.tbl.

        cfg.tbl carries only the master switch etc_webhook_activate; all
        endpoint config lives in cfg/webhooks.tbl (keeps cfg.tbl lean).
        Runtime dedup state lives in scripts/data/etc_webhook.tbl.

        cfg/webhooks.tbl can be hand-edited (plain Lua) OR managed through
        the HTTP API (GET/POST/PUT/DELETE /v1/webhooks*, admin scope for
        writes) - the WebUI's Webhooks tab uses the latter. The plugin
        owns the file either way; a WebUI save regenerates it (comments
        dropped) via an atomic write + chmod 600. Endpoint changes reach
        the live receiver only after a +reload, so the API returns
        apply_status = "reload_required".

        Security: the endpoint registers with scope="none" (the router's
        bearer-token gate is skipped) and does its OWN HMAC auth over
        req.raw_body, constant-time compared (adclib.constant_time_eq).
        The HTTP listener itself is only reachable per the operator's
        http_port + reverse-proxy setup - see docs/WEBHOOKS.md.

        v0.04: by Aybo - HTTP management API + per-endpoint `enabled`
               toggle. GET/POST/PUT/DELETE /v1/webhooks/{name} (+ PUT
               /v1/webhooks for the global tuning) let the WebUI create,
               edit and delete endpoints without shell access; the plugin
               writes cfg/webhooks.tbl itself (atomic tmp+rename, chmod
               600 like user.tbl) and NEVER returns a secret on read (only
               has_secret + secret_source). The management routes register
               whenever the plugin is loaded - independent of
               etc_webhook_activate - so the WebUI tab (gated on the route
               being present) and the receiver gate are decoupled: you can
               prepare endpoints and flip the master switch from the tab.
               New optional `enabled` field (default true; absent = on)
               pauses one endpoint without losing its config or secret.
        v0.03: by Aybo - per-endpoint `conditions` body-field filter
               (equals / not_equals) so a delivery can be filtered on a
               decoded JSON field, not just the event header. Solves two
               real cases: announce only the GitHub release `action` you
               want (all release actions share event=release, only the
               `action` field differs), and skip a Discourse topic's own
               opening post (topic_created + post_created both fire for a
               new topic; post.post_number == 1 is that duplicate).
        v0.02: by Aybo - dedup_load probes with io.open before
               util.loadtable, so a first run (no dedup file yet) no
               longer logs a spurious checkfile error (the sibling
               state-file loaders already did this).
        v0.01: by Aybo - initial release (#398).

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_webhook"
local scriptversion = "0.04"

local config_file = "cfg/webhooks.tbl"
local dedup_file  = "scripts/data/etc_webhook.tbl"


--// table lookups
local hub_debug       = hub.debug
local hub_broadcast   = hub.broadcast
local hub_getbot      = hub.getbot
local hub_getusers    = hub.getusers
local hub_regbot      = hub.regbot
local util_loadtable  = util.loadtable
local util_savetable  = util.savetable
local util_strip      = util.strip_control_bytes
local util_tabletostring = util.tabletostring    -- serialise config for the mgmt writer
local util_atomic_write  = util.atomic_write      -- crash-safe tmp+rename write
local util_chmod_secret  = util.chmod_secret      -- POSIX 0600 (webhooks.tbl may hold inline secrets)
local hmac_sha256     = hmac.sha256
local ct_eq           = adclib.constant_time_eq
local adclib_sanitize = adclib.sanitize_utf8
local os_time         = os.time
local math_floor      = math.floor


-- No lang files / no help entry: this plugin has NO chat command and no
-- operator-facing chat output of its own (it only announces the
-- operator-authored templates). Same shape as its sibling
-- etc_status_push. Diagnostics go to hub.debug (gated on log_scripts).


----------
--[CODE]--
----------

-- Response shapes for the scope="none" handler.
local RESP_OK = { status = 200, raw_body = "", content_type = "text/plain; charset=utf-8" }
local function resp_unauthorized( )
    return { status = 401, error = { code = "unauthorized", message = "invalid or missing signature" } }
end

-- Module state (all reset on +reload, which re-runs this file).
local endpoints      = { }    -- validated, active endpoints
local bots           = { }    -- bot_nick -> bot object (deduped)
local receiver_active = false  -- the RECEIVER gate (activate && >=1 valid endpoint); distinct from per-endpoint `enabled`
local tuning         = { max_per_minute = 10, dedup_max = 500, field_maxlen = 300 }

-- dedup: seen[id] = last-seen epoch. Bounded to tuning.dedup_max.
local seen        = { }
local seen_count  = 0
local seen_dirty  = false    -- persisted by the onTimer throttle, not per-event
local last_save   = 0

-- flood window (global across endpoints)
local flood_count = 0
local flood_start = 0


--// config load (operator-edited Lua table; same trust level as cfg.tbl)
local function load_config( )
    -- first-run-silent: a missing file is the normal not-configured
    -- state, not an error worth a log line.
    local f = io.open( config_file, "r" )
    if not f then return nil end
    f:close()
    local ok, tbl = pcall( util_loadtable, config_file )
    if not ok or type( tbl ) ~= "table" then
        hub_debug( scriptname .. ": " .. config_file .. " missing or unreadable - inert" )
        return nil
    end
    return tbl
end

--// per-endpoint validation + normalisation. Returns a normalised entry
--// or nil + reason. Does NOT resolve the secret (caller does).
local function normalise_endpoint( raw )
    if type( raw ) ~= "table" then return nil, "not a table" end
    local name = raw.name
    if type( name ) ~= "string" or not name:match( "^[%a%d_]+$" ) then
        return nil, "invalid/missing name (need [A-Za-z0-9_])"
    end
    local sig_header = raw.signature_header
    if type( sig_header ) ~= "string" or sig_header == "" then
        return nil, "endpoint '" .. name .. "': missing signature_header"
    end
    local events = { }
    if type( raw.events ) == "table" then
        for _, e in ipairs( raw.events ) do
            if type( e ) == "string" then events[ e ] = true end
        end
    end
    local templates = { }
    if type( raw.templates ) == "table" then
        for k, v in pairs( raw.templates ) do
            if type( k ) == "string" and type( v ) == "string" then templates[ k ] = v end
        end
    end
    -- optional body-field conditions: each { path = "dotted.path", equals = X }
    -- or { path = ..., not_equals = X }. ALL must hold (see conditions_pass).
    local conditions = { }
    if type( raw.conditions ) == "table" then
        for _, c in ipairs( raw.conditions ) do
            if type( c ) == "table" and type( c.path ) == "string" and c.path ~= "" then
                if c.equals ~= nil then
                    conditions[ #conditions + 1 ] = { path = c.path, op = "eq", value = c.equals }
                elseif c.not_equals ~= nil then
                    conditions[ #conditions + 1 ] = { path = c.path, op = "ne", value = c.not_equals }
                else
                    -- a path-only entry (e.g. a typo'd `equal`/`not_equal`)
                    -- would otherwise vanish silently, leaving the endpoint
                    -- with no filter and announcing everything.
                    hub_debug( scriptname .. ": endpoint '" .. name .. "': condition on '" .. c.path .. "' has neither equals nor not_equals - ignored" )
                end
            end
        end
    end
    local path = raw.path
    if type( path ) ~= "string" or path:sub( 1, 1 ) ~= "/" then
        path = "/v1/webhook/" .. name
    end
    local min_level = tonumber( raw.min_level ) or 0
    -- header keys arrive lowercased in req.headers
    local event_header = ( type( raw.event_header ) == "string" and raw.event_header ~= "" and raw.event_header:lower() ) or nil
    if next( events ) ~= nil and not event_header then
        hub_debug( scriptname .. ": endpoint '" .. name .. "': an events filter is set but no event_header - every delivery will be dropped" )
    end
    return {
        name             = name,
        path             = path,
        signature_header = sig_header:lower(),
        signature_prefix = ( type( raw.signature_prefix ) == "string" and raw.signature_prefix ) or "",
        event_header     = event_header,
        events           = events,          -- set; empty = allow all
        has_events       = next( events ) ~= nil,
        id_header        = ( type( raw.id_header ) == "string" and raw.id_header ~= "" and raw.id_header:lower() ) or nil,
        bot_nick         = ( type( raw.bot_nick ) == "string" and raw.bot_nick ~= "" and raw.bot_nick ) or nil,
        min_level        = min_level,
        templates        = templates,
        conditions       = conditions,
        has_conditions   = next( conditions ) ~= nil,
        default_template = ( type( raw.default_template ) == "string" and raw.default_template ) or "",
        enabled          = ( raw.enabled ~= false ),   -- default true; only an explicit `enabled = false` pauses it
        inline_secret    = ( type( raw.secret ) == "string" and raw.secret ~= "" and raw.secret ) or nil,
        secret           = nil,             -- filled by caller
    }
end


--// dedup
local function dedup_load( )
    -- first-run-silent: probe with io.open before util.loadtable, which
    -- otherwise calls checkfile and logs an error.log line for the
    -- absent file - the HubSecurity bot relays that to ops on every
    -- fresh start. A missing dedup file is the normal "nothing seen
    -- yet" state. Mirrors load_config() above + the sibling state
    -- loaders (etc_regserver_announce, etc_blocklist_feeds).
    local f = io.open( dedup_file, "r" )
    if not f then return end
    f:close()
    local ok, tbl = pcall( util_loadtable, dedup_file )
    if ok and type( tbl ) == "table" and type( tbl.seen ) == "table" then
        seen = tbl.seen
        seen_count = 0
        for _ in pairs( seen ) do seen_count = seen_count + 1 end
    end
end

local function dedup_save( )
    util_savetable( { seen = seen }, "webhook", dedup_file )
end

-- true if this id was already processed (duplicate delivery).
local function dedup_hit( id )
    return seen[ id ] ~= nil
end

local function dedup_add( id )
    if seen[ id ] == nil then seen_count = seen_count + 1 end
    seen[ id ] = os_time()
    seen_dirty = true
    -- bound: once over the cap, drop the oldest ~10% in a single sorted
    -- pass (amortised ~O(log n) per add; avoids the O(k*n) repeated scan
    -- a signed flooder could otherwise use to stall the loop).
    if seen_count > tuning.dedup_max then
        local arr = { }
        for k, v in pairs( seen ) do arr[ #arr + 1 ] = { k, v } end
        table.sort( arr, function( a, b ) return a[ 2 ] < b[ 2 ] end )
        local drop = math.max( 1, math.floor( tuning.dedup_max * 0.1 ) )
        for i = 1, drop do
            local e = arr[ i ]
            if e then seen[ e[ 1 ] ] = nil; seen_count = seen_count - 1 end
        end
    end
end


--// flood cap (global)
local function flood_ok( )
    local now = os_time()
    if now - flood_start >= 60 then
        flood_start = now
        flood_count = 0
    end
    if flood_count >= tuning.max_per_minute then
        return false
    end
    flood_count = flood_count + 1
    return true
end


--// template render: {dotted.path} against the decoded body, plus {event}.
local function resolve_path( body, path )
    local cur = body
    for key in path:gmatch( "[^%.]+" ) do
        if type( cur ) ~= "table" then return nil end
        local v = cur[ key ]
        if v == nil then
            -- JSON arrays decode to integer-keyed tables; {items.1.x}
            -- should reach cur[1], not cur["1"].
            local nk = tonumber( key )
            if nk ~= nil then v = cur[ nk ] end
        end
        cur = v
    end
    return cur
end

--// endpoint conditions: body-field predicates that ALL must hold for a
--// delivery to announce. Two numbers compare numerically (so a config `1`
--// matches JSON `1` OR `1.0` - dkjson decodes `1.0` as a float); anything
--// else compares as strings. A path that does not resolve is nil, so
--// `not_equals` passes when the field is absent (a Discourse topic_created
--// carries no post.post_number, so a "post.post_number not_equals 1"
--// endpoint still announces the topic) while `equals` fails (drops it).
--// Conditions apply endpoint-wide (to every event the endpoint accepts).
local function conditions_pass( entry, body )
    for _, c in ipairs( entry.conditions ) do
        local actual = resolve_path( body, c.path )
        local match
        if type( actual ) == "number" and type( c.value ) == "number" then
            match = ( actual == c.value )
        else
            match = ( tostring( actual ) == tostring( c.value ) )
        end
        if c.op == "eq" then
            if not match then return false end
        else
            if match then return false end
        end
    end
    return true
end

local function sanitise_value( v )
    local t = type( v )
    -- only scalars render. A non-leaf path (table / array) would else
    -- tostring() to "table: 0x..." - a heap-pointer info-leak + garbage
    -- into chat (reachable by a signed sender putting an object where a
    -- scalar was expected).
    if t ~= "string" and t ~= "number" and t ~= "boolean" then return "" end
    -- strip control bytes, then coerce to valid UTF-8: a signed sender
    -- could send an invalid-UTF-8 field, which would make the broadcast
    -- path's types_utf8 gate raise and silently drop the announce.
    v = adclib_sanitize( util_strip( tostring( v ) ) )
    if utf.len and utf.len( v ) > tuning.field_maxlen then
        v = utf.sub( v, 1, tuning.field_maxlen ) .. "..."
    elseif #v > tuning.field_maxlen then
        v = v:sub( 1, tuning.field_maxlen ) .. "..."
    end
    return v
end

local function render( template, body, event )
    return ( template:gsub( "{([%w_%.]+)}", function( path )
        if path == "event" then return sanitise_value( event ) end
        return sanitise_value( resolve_path( body, path ) )
    end ) )
end


--// announce
local function announce( text, bot, min_level )
    if min_level and min_level > 0 then
        for _, user in pairs( hub_getusers() ) do
            if user:level() >= min_level then
                user:reply( text, bot )
            end
        end
    else
        hub_broadcast( text, bot )
    end
end


--// build a scope="none" HTTP handler bound to one endpoint.
local function make_handler( entry )
    return function( req )
        -- 1. HMAC auth over the EXACT raw bytes, constant-time compared.
        local sig = req.headers and req.headers[ entry.signature_header ]
        if type( sig ) ~= "string" or sig == "" then return resp_unauthorized() end
        if entry.signature_prefix ~= "" then
            local plen = #entry.signature_prefix
            if sig:sub( 1, plen ) == entry.signature_prefix then
                sig = sig:sub( plen + 1 )
            end
        end
        local computed = hmac_sha256( entry.secret, req.raw_body or "" )
        if not ct_eq( computed, sig:lower() ) then return resp_unauthorized() end

        -- From here the request is authenticated. Everything below
        -- returns 200 (the sender should not retry a well-formed,
        -- correctly-signed delivery we chose not to announce).

        -- 2. event filter (ping / unlisted events are acknowledged, not announced)
        local event = entry.event_header and req.headers[ entry.event_header ] or nil
        if entry.has_events and not ( event and entry.events[ event ] ) then
            return RESP_OK
        end

        -- 2b. body-field conditions (e.g. GitHub action=released; or skip a
        -- Discourse topic's own opening post via post.post_number != 1).
        -- Evaluated against the decoded body; ALL must hold to announce.
        if entry.has_conditions and not conditions_pass( entry, req.body or { } ) then
            return RESP_OK
        end

        -- 3. dedup on the delivery id
        local id = entry.id_header and req.headers[ entry.id_header ] or nil
        if id then
            id = entry.name .. ":" .. util_strip( tostring( id ) ):sub( 1, 128 )
            if dedup_hit( id ) then return RESP_OK end
        end

        -- 4. pick a template; nothing to say -> ack
        local template = ( event and entry.templates[ event ] ) or entry.default_template
        if not template or template == "" then
            if id then dedup_add( id ) end
            return RESP_OK
        end

        -- 5. global flood cap
        if not flood_ok() then
            hub_debug( scriptname .. ": flood cap hit (" .. tuning.max_per_minute .. "/min), dropping announce for '" .. entry.name .. "'" )
            -- do NOT dedup a flood-dropped delivery: it was not delivered,
            -- so a later retry (once the flood clears) should still announce.
            return RESP_OK
        end

        -- 6. render + announce
        local text = render( template, req.body or { }, event )
        if text ~= "" then
            local bot = ( entry.bot_nick and bots[ entry.bot_nick ] ) or hub_getbot()
            announce( text, bot, entry.min_level )
        end
        if id then dedup_add( id ) end
        return RESP_OK
    end
end


--------------------------------
--[HTTP MANAGEMENT API (v0.04)]--
--------------------------------
-- GET/POST/PUT/DELETE /v1/webhooks* let the WebUI (or any admin token)
-- manage cfg/webhooks.tbl without shell access. The plugin OWNS the file:
-- writes go through an atomic tmp+rename + chmod 600 (like user.tbl), and
-- a secret is NEVER returned on read (only has_secret + secret_source).
-- Endpoint config is read once at load, so a change reaches the live
-- receiver only after a +reload; every write therefore returns
-- apply_status = "reload_required" and the caller shows the hub's
-- pending-reload banner. These routes register whenever the plugin is
-- loaded (see onStart), independent of the etc_webhook_activate gate.

-- Static banner kept at the top of a machine-written webhooks.tbl. A
-- `--[==[ ]==]` long-bracket level so a future ]] in the text can never
-- close it early; loadtable ignores the comment and reads the `return`.
local CONFIG_HEADER = "--[==[\n" ..
    "    webhooks.tbl - managed by etc_webhook via the HTTP API / WebUI.\n\n" ..
    "    You CAN still edit this by hand (plain Lua, same as cfg.tbl), but a\n" ..
    "    save through the WebUI regenerates the file: comments and layout are\n" ..
    "    NOT preserved and inline secrets are rewritten. Keep it chmod 600 (it\n" ..
    "    may hold inline secrets). Schema + hand-edit guide:\n" ..
    "    examples/cfg/webhooks.tbl and docs/WEBHOOKS.md.\n" ..
    "]==]\n\n"

local function is_scalar( v )
    local t = type( v )
    return t == "string" or t == "number" or t == "boolean"
end

-- Derived per-endpoint secret key (single source of truth): the cfg.tbl
-- key AND, upper-cased, the env var LUADCH_ETC_WEBHOOK_<NAME>_SECRET.
-- Kept in one place so the module-load resolver and the two mgmt readers
-- cannot drift on the key format.
local function secret_key( name )
    return "etc_webhook_" .. name .. "_secret"
end

local function err_resp( status, code, msg )
    return { status = status, error = { code = code, message = msg } }
end
local function bad_input( msg ) return err_resp( 400, "E_BAD_INPUT", msg ) end
local function not_found( msg ) return err_resp( 404, "E_NOT_FOUND", msg ) end
local function internal( msg )  return err_resp( 500, "E_INTERNAL", "failed to write webhooks.tbl: " .. tostring( msg ) ) end

-- Read the on-disk config as a raw operator table (tunings + endpoints[]),
-- or a fresh scaffold if the file is absent/unreadable. Used for writes
-- (mutate + re-serialise) - it carries inline secrets, so it never leaves
-- the process.
local function read_config_raw( )
    local tbl = load_config()
    if type( tbl ) ~= "table" then
        return { max_per_minute = tuning.max_per_minute, dedup_max = tuning.dedup_max,
                 field_maxlen = tuning.field_maxlen, endpoints = { } }
    end
    if type( tbl.endpoints ) ~= "table" then tbl.endpoints = { } end
    return tbl
end

-- Index of the endpoint named `name` in a raw config table (nil if absent).
local function find_endpoint( raw, name )
    for i, e in ipairs( raw.endpoints ) do
        if type( e ) == "table" and e.name == name then return i, e end
    end
    return nil
end

-- Serialise + persist the raw config: header banner + `return webhooks`,
-- atomic write, then chmod 600 (mirrors core/cfg_users.lua's user.tbl path).
local function write_config_raw( raw )
    local content = CONFIG_HEADER .. util_tabletostring( raw, "webhooks" )
    local ok, werr = util_atomic_write( config_file, content )
    if not ok then return false, werr end
    util_chmod_secret( config_file )   -- POSIX 0600; no-op on Windows
    return true
end

-- True if endpoint `e` has a resolvable secret (inline in the body, or an
-- env/cfg override for its derived key). A secret-less endpoint would load
-- inert, so writes reject it rather than silently creating a dead route.
local function endpoint_has_secret( e )
    if type( e.secret ) == "string" and e.secret ~= "" then return true end
    local override = secrets and secrets.lookup and secrets.lookup( secret_key( e.name ) )
    return type( override ) == "string" and override ~= ""
end

-- Build a clean raw endpoint from an untrusted request body, keeping ONLY
-- known keys with sane types (the security-critical input boundary). On
-- edit, `keep_secret` is the existing inline secret used when the body
-- omits `secret` (blank = keep). Returns (raw_endpoint) or (nil, reason).
local function sanitise_endpoint_body( b, keep_secret )
    if type( b ) ~= "table" then return nil, "body must be a JSON object" end
    local e = { }
    if type( b.name ) ~= "string" or not b.name:match( "^[%a%d_]+$" ) then
        return nil, "invalid or missing 'name' (need [A-Za-z0-9_])"
    end
    if #b.name > 64 then return nil, "'name' too long (max 64)" end
    e.name = b.name
    if type( b.signature_header ) ~= "string" or b.signature_header == "" then
        return nil, "missing 'signature_header'"
    end
    e.signature_header = b.signature_header
    if b.path ~= nil then
        if type( b.path ) ~= "string" or b.path:sub( 1, 1 ) ~= "/" then
            return nil, "'path' must be a string starting with '/'"
        end
        e.path = b.path
    end
    if b.signature_prefix ~= nil then
        if type( b.signature_prefix ) ~= "string" then return nil, "'signature_prefix' must be a string" end
        if b.signature_prefix ~= "" then e.signature_prefix = b.signature_prefix end
    end
    if b.event_header ~= nil then
        if type( b.event_header ) ~= "string" then return nil, "'event_header' must be a string" end
        if b.event_header ~= "" then e.event_header = b.event_header end
    end
    if b.id_header ~= nil then
        if type( b.id_header ) ~= "string" then return nil, "'id_header' must be a string" end
        if b.id_header ~= "" then e.id_header = b.id_header end
    end
    if b.bot_nick ~= nil then
        if type( b.bot_nick ) ~= "string" then return nil, "'bot_nick' must be a string" end
        if b.bot_nick ~= "" then e.bot_nick = b.bot_nick end
    end
    if b.default_template ~= nil then
        if type( b.default_template ) ~= "string" then return nil, "'default_template' must be a string" end
        if b.default_template ~= "" then e.default_template = b.default_template end
    end
    if b.min_level ~= nil then
        local ml = tonumber( b.min_level )
        if not ml or ml < 0 then return nil, "'min_level' must be a number >= 0" end
        e.min_level = math_floor( ml )
    end
    if b.enabled ~= nil then
        if type( b.enabled ) ~= "boolean" then return nil, "'enabled' must be true or false" end
        e.enabled = b.enabled
    end
    if b.events ~= nil then
        if type( b.events ) ~= "table" then return nil, "'events' must be an array of strings" end
        local ev = { }
        for _, v in ipairs( b.events ) do
            if type( v ) ~= "string" then return nil, "'events' must contain only strings" end
            ev[ #ev + 1 ] = v
        end
        if #ev > 0 then e.events = ev end
    end
    if b.templates ~= nil then
        if type( b.templates ) ~= "table" then return nil, "'templates' must be an object of event -> string" end
        local tp, any = { }, false
        for k, v in pairs( b.templates ) do
            if type( k ) ~= "string" or type( v ) ~= "string" then
                return nil, "'templates' keys and values must be strings"
            end
            tp[ k ] = v; any = true
        end
        if any then e.templates = tp end
    end
    if b.conditions ~= nil then
        if type( b.conditions ) ~= "table" then return nil, "'conditions' must be an array" end
        local cs = { }
        for _, c in ipairs( b.conditions ) do
            if type( c ) ~= "table" or type( c.path ) ~= "string" or c.path == "" then
                return nil, "each condition needs a non-empty string 'path'"
            end
            local cc = { path = c.path }
            if c.equals ~= nil then
                if not is_scalar( c.equals ) then return nil, "condition 'equals' must be a string, number or boolean" end
                cc.equals = c.equals
            elseif c.not_equals ~= nil then
                if not is_scalar( c.not_equals ) then return nil, "condition 'not_equals' must be a string, number or boolean" end
                cc.not_equals = c.not_equals
            else
                return nil, "each condition needs 'equals' or 'not_equals'"
            end
            cs[ #cs + 1 ] = cc
        end
        if #cs > 0 then e.conditions = cs end
    end
    if b.secret ~= nil and type( b.secret ) ~= "string" then
        return nil, "'secret' must be a string"
    end
    if type( b.secret ) == "string" and b.secret ~= "" then
        e.secret = b.secret
    elseif keep_secret ~= nil then
        e.secret = keep_secret
    end
    return e
end

-- Redacted, editor-facing view of ONE raw endpoint for GET. Never returns
-- the secret value; only has_secret + secret_source ("inline" = rotatable
-- by writing the file, "external" = env/cfg override wins so a file write
-- would NOT take effect, "none" = unset -> currently inert). Empty
-- arrays/maps are omitted so the wire never carries the {}-vs-[] ambiguity.
local function endpoint_public_view( raw_e )
    local norm, reason = normalise_endpoint( raw_e )
    local name = ( type( raw_e.name ) == "string" ) and raw_e.name or ""
    local inline = ( type( raw_e.secret ) == "string" and raw_e.secret ~= "" ) or false
    local has_secret, secret_source = false, "none"
    if name ~= "" then
        local override = secrets and secrets.lookup and secrets.lookup( secret_key( name ) )
        if type( override ) == "string" and override ~= "" then
            has_secret, secret_source = true, "external"
        elseif inline then
            has_secret, secret_source = true, "inline"
        end
    elseif inline then
        has_secret, secret_source = true, "inline"
    end
    local view = {
        name             = name,
        enabled          = ( raw_e.enabled ~= false ),
        -- path must be scalar-guarded like every other field below: when the
        -- endpoint is invalid (norm=nil), the raw fallback would otherwise
        -- pass a hand-edited function/cycle straight to dkjson.encode.
        path             = ( norm and norm.path ) or ( type( raw_e.path ) == "string" and raw_e.path ) or ( "/v1/webhook/" .. name ),
        signature_header = ( type( raw_e.signature_header ) == "string" and raw_e.signature_header ) or "",
        signature_prefix = ( type( raw_e.signature_prefix ) == "string" and raw_e.signature_prefix ) or "",
        event_header     = ( type( raw_e.event_header ) == "string" and raw_e.event_header ) or "",
        id_header        = ( type( raw_e.id_header ) == "string" and raw_e.id_header ) or "",
        bot_nick         = ( type( raw_e.bot_nick ) == "string" and raw_e.bot_nick ) or "",
        min_level        = tonumber( raw_e.min_level ) or 0,
        default_template = ( type( raw_e.default_template ) == "string" and raw_e.default_template ) or "",
        has_secret       = has_secret,
        secret_source    = secret_source,
        valid            = norm ~= nil,
    }
    if not norm then view.invalid_reason = reason end
    -- Scalar-safe copies (NOT the raw on-disk tables): a hand-edited
    -- webhooks.tbl could hold a function / reference cycle inside these,
    -- and http_get_webhooks' data is dkjson-encoded OUTSIDE the handler's
    -- error guard (envelope_success), so a raise there would crash the hub
    -- loop, not just the request. Filtering to scalars here makes the whole
    -- GET payload encode-safe regardless of file content, and keeps the
    -- operator (equals/not_equals) shape the editor round-trips.
    if type( raw_e.events ) == "table" then
        local ev = { }
        for _, v in ipairs( raw_e.events ) do
            if type( v ) == "string" then ev[ #ev + 1 ] = v end
        end
        if #ev > 0 then view.events = ev end
    end
    if type( raw_e.templates ) == "table" then
        local tp, any = { }, false
        for k, v in pairs( raw_e.templates ) do
            if type( k ) == "string" and type( v ) == "string" then tp[ k ] = v; any = true end
        end
        if any then view.templates = tp end
    end
    if type( raw_e.conditions ) == "table" then
        local cs = { }
        for _, c in ipairs( raw_e.conditions ) do
            if type( c ) == "table" and type( c.path ) == "string" then
                local cc
                if is_scalar( c.equals ) then cc = { path = c.path, equals = c.equals }
                elseif is_scalar( c.not_equals ) then cc = { path = c.path, not_equals = c.not_equals } end
                if cc then cs[ #cs + 1 ] = cc end
            end
        end
        if #cs > 0 then view.conditions = cs end
    end
    return view
end

-- onAudit trail for every mutation (who / which endpoint). Same shape as
-- etc_records' HTTP reset audit: the bearer token's admin scope is the
-- gate, token_label the actor. The endpoint name is the audit `target`
-- and MUST be a flat table ({nick=name}) - audit.build's _snapshot_target
-- drops a bare-string target to nil, which would lose the "which endpoint"
-- the trail exists to record. Tuning changes have no endpoint (nil target).
local function audit_mutation( req, action, name )
    if not ( audit and audit.fire and audit.build ) then return end
    local actor = util_strip( ( req and req.token_label ) or "http-api" )
    local target = ( name and name ~= "-" ) and { nick = name } or nil
    audit.fire( audit.build( action, { nick = actor, sid = "<http>" }, target, nil, nil ) )
end

-- GET /v1/webhooks (read): tunings + endpoints, secrets redacted.
local function http_get_webhooks( req )
    local raw = read_config_raw()
    local eps = setmetatable( { }, { __jsontype = "array" } )   -- force [] when empty
    for _, e in ipairs( raw.endpoints ) do
        if type( e ) == "table" then eps[ #eps + 1 ] = endpoint_public_view( e ) end
    end
    return { status = 200, data = {
        activate  = cfg.get( "etc_webhook_activate" ) and true or false,
        tuning    = {
            max_per_minute = tonumber( raw.max_per_minute ) or tuning.max_per_minute,
            dedup_max      = tonumber( raw.dedup_max ) or tuning.dedup_max,
            field_maxlen   = tonumber( raw.field_maxlen ) or tuning.field_maxlen,
        },
        endpoints = eps,
    } }
end

-- POST /v1/webhooks (admin): create a new endpoint.
local function http_create_webhook( req )
    local e, reason = sanitise_endpoint_body( req.body, nil )
    if not e then return bad_input( reason ) end
    local raw = read_config_raw()
    if find_endpoint( raw, e.name ) then
        return bad_input( "endpoint '" .. e.name .. "' already exists" )
    end
    local norm, nreason = normalise_endpoint( e )   -- parity: must load cleanly
    if not norm then return bad_input( nreason ) end
    if not endpoint_has_secret( e ) then
        return bad_input( "endpoint '" .. e.name .. "' has no secret (set 'secret', or configure an env/cfg key)" )
    end
    raw.endpoints[ #raw.endpoints + 1 ] = e
    local ok, werr = write_config_raw( raw )
    if not ok then return internal( werr ) end
    audit_mutation( req, "webhook.create", e.name )
    return { status = 200, data = { action = "webhook-created", name = e.name, apply_status = "reload_required" } }
end

-- PUT /v1/webhooks/{name} (admin): replace an existing endpoint. A blank
-- or omitted `secret` keeps the current inline secret (rotate-only model).
local function http_update_webhook( req )
    local name = req.path_vars and req.path_vars[ "name" ]
    if type( name ) ~= "string" or name == "" then return bad_input( "missing name" ) end
    local raw = read_config_raw()
    local idx, existing = find_endpoint( raw, name )
    if not idx then return not_found( "no such webhook '" .. name .. "'" ) end
    local body = req.body
    if type( body ) == "table" then body.name = name end   -- path name is authoritative
    local keep = ( type( existing.secret ) == "string" and existing.secret ~= "" ) and existing.secret or nil
    local e, reason = sanitise_endpoint_body( body, keep )
    if not e then return bad_input( reason ) end
    local norm, nreason = normalise_endpoint( e )
    if not norm then return bad_input( nreason ) end
    if not endpoint_has_secret( e ) then
        return bad_input( "endpoint '" .. e.name .. "' would have no secret" )
    end
    raw.endpoints[ idx ] = e
    local ok, werr = write_config_raw( raw )
    if not ok then return internal( werr ) end
    audit_mutation( req, "webhook.update", name )
    return { status = 200, data = { action = "webhook-updated", name = name, apply_status = "reload_required" } }
end

-- DELETE /v1/webhooks/{name} (admin): remove an endpoint.
local function http_delete_webhook( req )
    local name = req.path_vars and req.path_vars[ "name" ]
    if type( name ) ~= "string" or name == "" then return bad_input( "missing name" ) end
    local raw = read_config_raw()
    local idx = find_endpoint( raw, name )
    if not idx then return not_found( "no such webhook '" .. name .. "'" ) end
    table.remove( raw.endpoints, idx )
    local ok, werr = write_config_raw( raw )
    if not ok then return internal( werr ) end
    audit_mutation( req, "webhook.delete", name )
    return { status = 200, data = { action = "webhook-deleted", name = name, apply_status = "reload_required" } }
end

-- PUT /v1/webhooks (admin): update the global tuning (flood cap, dedup
-- size, field truncation). Endpoints are managed via the {name} routes.
local function http_update_settings( req )
    local b = req.body
    if type( b ) ~= "table" then return bad_input( "body must be a JSON object" ) end
    local raw = read_config_raw()
    for _, key in ipairs( { "max_per_minute", "dedup_max", "field_maxlen" } ) do
        if b[ key ] ~= nil then
            local n = tonumber( b[ key ] )
            if not n or n <= 0 then return bad_input( "'" .. key .. "' must be a number > 0" ) end
            raw[ key ] = math_floor( n )
        end
    end
    local ok, werr = write_config_raw( raw )
    if not ok then return internal( werr ) end
    audit_mutation( req, "webhook.tune", "-" )
    return { status = 200, data = { action = "webhook-tuned", apply_status = "reload_required" } }
end


--// module-load init (re-runs on +reload)
local config = load_config()
if type( config ) == "table" then
    if type( config.max_per_minute ) == "number" and config.max_per_minute > 0 then tuning.max_per_minute = config.max_per_minute end
    if type( config.dedup_max ) == "number" and config.dedup_max > 0 then tuning.dedup_max = config.dedup_max end
    if type( config.field_maxlen ) == "number" and config.field_maxlen > 0 then tuning.field_maxlen = config.field_maxlen end
    if type( config.endpoints ) == "table" then
        for _, raw in ipairs( config.endpoints ) do
            local entry, reason = normalise_endpoint( raw )
            if not entry then
                hub_debug( scriptname .. ": skipped endpoint (" .. tostring( reason ) .. ")" )
            elseif not entry.enabled then
                hub_debug( scriptname .. ": endpoint '" .. entry.name .. "' is disabled (enabled = false) - skipped" )
            else
                -- Secret resolution: register the derived cfg key (so a
                -- cfg.tbl-stored secret would be redacted from
                -- GET /v1/config), then env-var-first, then the inline
                -- secret in cfg/webhooks.tbl. Registration happens for
                -- every configured endpoint, before the activate gate.
                local skey = secret_key( entry.name )
                if secrets and secrets.register then secrets.register( skey ) end
                local resolved = ( secrets and secrets.lookup and secrets.lookup( skey ) ) or entry.inline_secret
                if type( resolved ) ~= "string" or resolved == "" then
                    hub_debug( scriptname .. ": endpoint '" .. entry.name .. "' has no secret (env LUADCH_" .. string.upper( skey ) .. " / cfg / inline) - skipped" )
                else
                    entry.secret = resolved
                    endpoints[ #endpoints + 1 ] = entry
                end
            end
        end
    end
end

local activate = cfg.get( "etc_webhook_activate" )
if activate and #endpoints > 0 then
    receiver_active = true
    dedup_load()
    flood_start = os_time()
    last_save = os_time()
    -- Create one bot per distinct bot_nick (module-load, like
    -- bot_opchat; killscripts kills all bots on +reload and this file
    -- re-runs, so no duplicates accumulate).
    for _, entry in ipairs( endpoints ) do
        local nick = entry.bot_nick
        if nick and not bots[ nick ] then
            local bot = hub_regbot{ nick = nick, desc = "Webhook announcer", client = function() return true end }
            if bot then bots[ nick ] = bot
            else hub_debug( scriptname .. ": could not create bot '" .. nick .. "' (nick taken?) - using hub bot for '" .. entry.name .. "'" ) end
        end
    end
    hub_debug( scriptname .. ": active with " .. #endpoints .. " endpoint(s)" )
else
    hub_debug( scriptname .. ": inert (" .. ( activate and "no valid endpoints" or "etc_webhook_activate = false" ) .. ")" )
end


hub.setlistener( "onStart", { },
    function( )
        if not hub.http_register then
            hub_debug( scriptname .. ": hub.http_register unavailable - routes not registered" )
            return nil
        end
        -- The router unregister_all's on every +reload before this fires,
        -- so a straight re-register is safe (no duplicate-path throw). Each
        -- register is pcall'd so one bad route never aborts the rest. `extras`
        -- merges request/response_schema + audit_redact_body into the meta.
        local function reg( method, path, scope, handler, desc, extras )
            local meta = { plugin = scriptname, description = desc }
            if extras then for k, v in pairs( extras ) do meta[ k ] = v end end
            local ok, reg_err = pcall( hub.http_register, method, path, scope, handler, meta )
            if not ok then
                hub_debug( scriptname .. ": could not register route " .. method .. " " .. path .. ": " .. tostring( reg_err ) )
            end
        end
        -- One endpoint request schema for POST + PUT/{name} (surfaced in
        -- /v1/endpoints for WebUI form rendering; the router pre-validates
        -- top-level types before the handler's fuller sanitise). `name` is
        -- required on create but path-sourced on update, so it is not
        -- required here - the create handler enforces it.
        local endpoint_req = {
            name             = { type = "string",  required = false, max_length = 64 },
            signature_header = { type = "string",  required = true },
            signature_prefix = { type = "string",  required = false },
            path             = { type = "string",  required = false },
            event_header     = { type = "string",  required = false },
            id_header        = { type = "string",  required = false },
            bot_nick         = { type = "string",  required = false },
            default_template = { type = "string",  required = false },
            min_level        = { type = "integer", required = false, min = 0 },
            enabled          = { type = "boolean", required = false },
            events           = { type = "array",   required = false },
            templates        = { type = "object",  required = false },
            conditions       = { type = "array",   required = false },
            secret           = { type = "string",  required = false },
        }
        local write_resp = {
            action       = { type = "string", required = true },
            apply_status = { type = "string", required = true },
            name         = { type = "string", required = false },
        }
        -- Management API: registered whenever the plugin is loaded, even
        -- when inert (activate=false / no endpoints yet), so the WebUI tab
        -- (gated on GET /v1/webhooks being present) shows up and can create
        -- the first endpoint + flip the master switch. Writes are admin, and
        -- the two routes that ingest a plaintext `secret` (POST + PUT/{name})
        -- set audit_redact_body so the secret never lands in api_audit.log.
        reg( "GET",    "/v1/webhooks",        "read",  http_get_webhooks,   "list webhook endpoints + tuning (secrets redacted)", {
            response_schema = {
                activate  = { type = "boolean", required = true },
                tuning    = { type = "object",  required = true },
                endpoints = { type = "array",   required = true },
            },
        } )
        reg( "POST",   "/v1/webhooks",        "admin", http_create_webhook, "create a webhook endpoint (needs +reload)", {
            request_schema = endpoint_req, response_schema = write_resp, audit_redact_body = true,
        } )
        reg( "PUT",    "/v1/webhooks",        "admin", http_update_settings,"update global webhook tuning (needs +reload)", {
            request_schema = {
                max_per_minute = { type = "integer", required = false, min = 1 },
                dedup_max      = { type = "integer", required = false, min = 1 },
                field_maxlen   = { type = "integer", required = false, min = 1 },
            },
            response_schema = write_resp,
        } )
        reg( "PUT",    "/v1/webhooks/{name}", "admin", http_update_webhook, "update a webhook endpoint (needs +reload)", {
            request_schema = endpoint_req, response_schema = write_resp, audit_redact_body = true,
        } )
        reg( "DELETE", "/v1/webhooks/{name}", "admin", http_delete_webhook, "delete a webhook endpoint (needs +reload)", {
            response_schema = write_resp,
        } )
        -- Receiver routes: one scope="none" POST per LIVE endpoint, only
        -- when active with >=1 valid endpoint (the HMAC-authed inbound path).
        if receiver_active then
            for _, entry in ipairs( endpoints ) do
                reg( "POST", entry.path, "none", make_handler( entry ),
                    "inbound webhook receiver for '" .. entry.name .. "' (HMAC-SHA256 signed; announces to chat)" )
            end
        end
        return nil
    end
)

-- Persist the dedup set on a throttle (not per-event), so a high-volume
-- signed source cannot turn every delivery into a disk write. A crash
-- loses at most the last <=30s of dedup keys (worst case: a duplicate
-- announce for those after a restart - harmless).
hub.setlistener( "onTimer", { },
    function( )
        if receiver_active and seen_dirty and ( os_time() - last_save ) >= 30 then
            dedup_save()
            seen_dirty = false
            last_save = os_time()
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
