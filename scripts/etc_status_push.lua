--[[

    etc_status_push.lua by Aybo

        Pushes this hub's PUBLIC status to an external HTTP(S) endpoint
        on a fixed interval - a heartbeat. Generic: any consumer that
        accepts a JSON POST works (an external status page, a push-uptime
        monitor such as healthchecks.io / Uptime Kuma / Better Uptime, a
        self-hosted dashboard, an automation webhook, a multi-hub status
        aggregator). The DCVault wiki's online-status + user-count graph
        is one such consumer.

        UNLIKE etc_regserver_announce (which registers ONCE per address
        and then goes quiet), this is an UNCONDITIONAL heartbeat: it
        POSTs every interval so the receiver gets evenly-spaced samples
        for a graph and can detect staleness itself. No login/logout
        trigger; no give-up / max-attempts logic - a missed beat is fine,
        the next interval sends again.

        Only PUBLIC fields are sent: the hub name, the online HUMAN-user
        count (bots excluded), and the uptime in seconds. Never a nick,
        a secret, or any internal state.

        Transport is core/http_client (NON-BLOCKING) so the
        single-threaded hub never freezes on a slow/unreachable endpoint.
        The request carries an `Authorization: Bearer <token>` header;
        the token is read env-var-first via core/secrets
        (LUADCH_ETC_STATUS_PUSH_TOKEN, else the etc_status_push_token cfg
        key) and is redacted from /v1/config. TLS
        verification defaults to "peer" (UNLIKE the announce plugin,
        which sends only public info over an unauthenticated channel) -
        this request carries a bearer secret, so it must not leak to a
        man-in-the-middle.

        Opt-in: OFF by default (etc_status_push_activate = false). With
        no url or no token the plugin stays inert (one debug line) and
        never touches the network.

        JSON contract (fixed - the receiver is built against this):
          POST <etc_status_push_url>
          Authorization: Bearer <token>
          Content-Type: application/json
          { "name": "<hub name>", "users": <int>, "uptime": <int seconds> }
        The hub sends NO timestamp - the receiver stamps arrival time
        (avoids clock drift).

        v0.01: initial

]]--


--// settings begin //--

local scriptname = "etc_status_push"
local scriptversion = "0.01"

--// settings end //--


--// table lookups
local hub_debug     = hub.debug
local hub_getusers  = hub.getusers
local cfg_get       = cfg.get
local signal_get    = signal.get
local dkjson_encode = dkjson.encode
local os_time       = os.time
local tostring      = tostring
local type          = type
local pairs         = pairs

local token_key = "etc_status_push_token"

--// runtime state (re-initialised on every onStart / +reload)
local enabled   = false    -- becomes true only after all config checks pass
local url       = nil
local token     = nil
local interval  = 300
local verify    = true
local cafile    = nil
local next_beat = 0
local in_flight = false     -- a beat is outstanding; never overlap requests

--// CODE

-- Count online HUMAN users (no bots). hub.getusers()'s first return is
-- the humans-only table - the same source /v1/stats online_count and
-- the announce plugin use - so counting its entries yields the online
-- non-bot user count.
local count_users = function( )
    local n = 0
    local nobots = hub_getusers( )
    if type( nobots ) == "table" then
        for _ in pairs( nobots ) do n = n + 1 end
    end
    return n
end

-- Seconds since hub start. signal.get("start") is the boot epoch,
-- set as os.time() in core/init.lua (an integer) - the same source
-- /v1/hubinfo uptime_seconds uses. Integer subtraction keeps the value
-- an integer so it JSON-encodes as `300`, not `300.0` (os.difftime
-- would return a float).
local uptime_seconds = function( )
    local start = signal_get( "start" )
    if type( start ) ~= "number" then return 0 end
    local up = os_time( ) - start
    if up < 0 then up = 0 end    -- clock-skew guard
    return up
end

-- Build the fixed-contract JSON body from PUBLIC fields only.
local build_body = function( )
    local name = cfg_get( "hub_name" )
    return dkjson_encode( {
        name   = ( type( name ) == "string" ) and name or tostring( name or "" ),
        users  = count_users( ),
        uptime = uptime_seconds( ),
    } )
end

-- Fire one non-blocking heartbeat POST. It is a heartbeat: on any
-- failure we only log and let the next interval try again - no retry
-- loop, no give-up state.
local send_beat = function( )
    local body = build_body( )
    in_flight = true
    local ok, err = http_client.request {
        url     = url,
        method  = "POST",
        body    = body,
        headers = {
            [ "Authorization" ] = "Bearer " .. token,
            [ "Content-Type" ]  = "application/json",
        },
        timeout = 10,
        verify  = verify and "peer" or "none",
        cafile  = cafile,   -- nil => http_client's bundled certs/ca-bundle.pem
        on_complete = function( res )
            in_flight = false
            local status = res and res.status
            if not ( status and status >= 200 and status < 300 ) then
                hub_debug( scriptname .. ": " .. tostring( url ) .. " returned HTTP " .. tostring( status ) .. " (will retry next interval)" )
            end
        end,
        on_error = function( e )
            in_flight = false
            hub_debug( scriptname .. ": push to " .. tostring( url ) .. " failed (" .. tostring( e ) .. "); will retry next interval" )
        end,
    }
    if not ok then
        in_flight = false    -- not queued: no callback will fire
        hub_debug( scriptname .. ": request not queued: " .. tostring( err ) )
    end
end

hub.setlistener( "onStart", { },
    function( )
        enabled   = false
        in_flight = false
        -- Register the token key as a secret whenever this plugin is
        -- LOADED - BEFORE the activate / url / token gates - so a token
        -- placed in cfg.tbl is redacted from /v1/config (and PUT
        -- /v1/config/{key} refuses it) even while the plugin is inactive.
        -- api_writable: a third-party push-endpoint bearer token the operator may set from
        -- the WebUI (masked write, #178) - not the hub's own auth/crypto material.
        if secrets and secrets.register then secrets.register( token_key, { api_writable = true } ) end
        if not cfg_get( "etc_status_push_activate" ) then
            return nil
        end
        if not ( http_client and http_client.request ) then
            hub_debug( scriptname .. ": core/http_client unavailable; status push disabled" )
            return nil
        end
        url = cfg_get( "etc_status_push_url" )
        if type( url ) ~= "string" or url == "" then
            hub_debug( scriptname .. ": activated but no etc_status_push_url set; disabled" )
            return nil
        end
        -- Resolve the token env-var-first via core/secrets (the key was
        -- registered as a secret above); falls back to a raw cfg read
        -- only if core/secrets is somehow absent.
        token = ( secrets and secrets.lookup and secrets.lookup( token_key ) ) or cfg_get( token_key )
        if type( token ) ~= "string" or token == "" then
            hub_debug( scriptname .. ": activated but no token (" .. token_key .. " / LUADCH_ETC_STATUS_PUSH_TOKEN); disabled" )
            return nil
        end
        interval = cfg_get( "etc_status_push_interval" )
        if type( interval ) ~= "number" or interval <= 0 then interval = 300 end
        verify = cfg_get( "etc_status_push_tls_verify" )
        if verify == nil then verify = true end
        local cf = cfg_get( "etc_status_push_cafile" )
        cafile = ( type( cf ) == "string" and cf ~= "" ) and cf or nil
        enabled   = true
        next_beat = os_time( )    -- first beat fires on the next onTimer tick
        hub_debug( scriptname .. ": enabled; pushing to " .. url .. " every " .. tostring( interval ) .. "s" )
        return nil
    end
)

hub.setlistener( "onTimer", { },
    function( )
        if not enabled then return nil end
        if in_flight then return nil end    -- previous beat still outstanding
        local now = os_time( )
        if now >= next_beat then
            next_beat = now + interval
            send_beat( )
        end
        return nil
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )
