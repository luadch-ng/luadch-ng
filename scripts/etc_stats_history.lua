--[[

    etc_stats_history.lua

        Samples the online-user count on a timer into a multi-tier, RRD-style
        ring buffer and exposes it via GET /v1/stats/history, feeding the WebUI
        dashboard online-users history graph (hub side of webui#183, #665).

        Endpoint-only: no ADC command, no report, no lang file.

        Three round-robin tiers consolidate the SAME 10-minute samples into
        progressively wider buckets, each keeping the MAX online count seen in
        the bucket (peak concurrent). The tiers ARE the resolutions, so the
        endpoint just returns the one matching the requested range - no
        server-side downsampling:

            tier1: 10-min slots x 144 = 24h
            tier2:  1-h   slots x 168 =  7d
            tier3:  6-h   slots x 120 = 30d

        The buffers persist to scripts/data/etc_stats_history.tbl (operator-
        owned, survives +reload and restart, upgrade-safe). No backfill is
        possible - the graph accumulates from first enable.

        v0.1:
            - initial: 3-tier sampler + GET /v1/stats/history (#665)

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_stats_history"
local scriptversion = "0.1"


--// imports
local hub_getusers = hub.getusers
local data_file = "scripts/data/etc_stats_history.tbl"

-- Tier config: the base sample interval is tier1's slot (10 min); the coarser
-- tiers consolidate those samples into wider buckets. cap * slot gives exactly
-- the documented window. Ordered fine -> coarse.
local TIERS = {
    { key = "tier1", slot = 600,   cap = 144, range = "24h" }, -- 10 min * 144 = 24 h
    { key = "tier2", slot = 3600,  cap = 168, range = "7d"  }, --  1 h  * 168 =  7 d
    { key = "tier3", slot = 21600, cap = 120, range = "30d" }, --  6 h  * 120 = 30 d
}

local DEFAULT_RANGE = "24h"
local RANGE_TO_TIER = { } -- "24h" -> TIERS entry
for _, ti in ipairs( TIERS ) do RANGE_TO_TIER[ ti.range ] = ti end

local SAMPLE_INTERVAL = TIERS[ 1 ].slot -- base tick = tier1's slot (10 min); one source of truth


----------
--[CODE]--
----------

local start = os.time()

-- Count online HUMANS. hub.getusers()'s first return is the humans-only table
-- (bots excluded), the same figure the core /v1/stats `online_count` reports.
local function count_online( )
    local n = 0
    for _ in pairs( hub_getusers( ) ) do n = n + 1 end
    return n
end

-- Load the persisted store, defensively. A missing / corrupt file (fresh hub,
-- deleted file, fs error) degrades to empty buffers rather than crashing the
-- timer; each tier key is guaranteed to be a table on return. Existence is
-- probed with io.open FIRST so a missing store (the normal case before the
-- first sample writes it) does not log a `checkfile: No such file` error -
-- otherwise the first boot of a fresh hub spams one into the error log, which
-- the dashboard's own Recent-errors tile would then surface (the hub_runtime
-- v0.11 / #445 lesson).
local function load_store( )
    local t
    local f = io.open( data_file, "r" )
    if f then f:close( ); t = util.loadtable( data_file ) end
    if type( t ) ~= "table" then t = { } end
    for _, ti in ipairs( TIERS ) do
        if type( t[ ti.key ] ) ~= "table" then t[ ti.key ] = { } end
    end
    return t
end

-- Record one sample into a single tier's point array (mutated in place):
-- update the current bucket's max if the sample falls in the same slot as the
-- last point, else push a new bucket (aligned to `slot`) and trim the oldest
-- points down to `cap`. Pure (no I/O) - the unit-tested consolidation contract.
local function record_tier( points, slot, cap, now, count )
    local bstart = now - ( now % slot )
    local last = points[ #points ]
    if last and bstart < last.t then
        -- Clock stepped backward into an older slot: drop the sample rather
        -- than append an out-of-order point, which would break the endpoint's
        -- documented oldest -> newest ordering until it self-heals (RRDtool
        -- likewise rejects out-of-order updates).
        return
    end
    if last and last.t == bstart then
        if count > last.c then last.c = count end
    else
        points[ #points + 1 ] = { t = bstart, c = count }
        while #points > cap do
            table.remove( points, 1 )
        end
    end
end

-- One sample tick: read the live count once, fan it into all three tiers, and
-- persist. Called on boot (onStart, an immediate first point) and every
-- SAMPLE_INTERVAL seconds thereafter.
local function sample( )
    local now = os.time( )
    local count = count_online( )
    local store = load_store( )
    for _, ti in ipairs( TIERS ) do
        record_tier( store[ ti.key ], ti.slot, ti.cap, now, count )
    end
    util.savetable( store, scriptname, data_file )
end

-- HTTP handler: GET /v1/stats/history?range=24h|7d|30d (read scope, #665).
-- Returns the tier matching the range as {t=epoch, count} points, oldest ->
-- newest. An unknown / absent range falls back to 24h. The bearer token's
-- `read` scope is the authorisation gate.
local function http_handler_history( req )
    local range = req.query and req.query.range or DEFAULT_RANGE
    local tier = RANGE_TO_TIER[ range ]
    if not tier then
        tier = RANGE_TO_TIER[ DEFAULT_RANGE ]
    end
    local store = load_store( )
    local pts = store[ tier.key ]
    local out = { }
    for i = 1, #pts do
        out[ i ] = { t = pts[ i ].t, count = pts[ i ].c }
    end
    return { status = 200, data = {
        range        = tier.range,
        interval_sec = tier.slot,
        points       = out,
    } }
end

hub.setlistener( "onTimer", { },
    function( )
        if os.time( ) - start >= SAMPLE_INTERVAL then
            sample( )
            start = os.time( )
        end
        return nil
    end
)

hub.setlistener( "onStart", { },
    function( )
        -- Seed one data point at boot so the graph is not blank for the first
        -- SAMPLE_INTERVAL. (Few/no users are connected this early, so the first
        -- bucket usually reads low - expected.)
        sample( )
        if hub.http_register then
            hub.http_register( "GET", "/v1/stats/history", "read", http_handler_history, {
                plugin = scriptname,
                description = "sampled online-users time-series for the dashboard history graph; ?range=24h|7d|30d (default 24h) -> {range, interval_sec, points:[{t,count}]}",
                response_schema = {
                    range        = { type = "string",  required = true },
                    interval_sec = { type = "integer", required = true },
                    points       = { type = "array",   required = true },
                },
            } )
        end
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {

    -- Internal test seams (#665): the pure consolidation function + the
    -- defensive store loader. `_`-prefixed per the repo convention for
    -- non-contract, test-only exports.
    _record_tier = record_tier,
    _load_store  = load_store,

}
