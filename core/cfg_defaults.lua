--[[

    cfg_defaults.lua - default settings table extracted from core/cfg.lua

    Extracted in Phase 6c-1 to bring core/cfg.lua under the Phase 6
    1500-line ceiling. The default settings table accounts for ~80%
    of cfg.lua's volume (3000+ lines of value/validator pairs); moving
    it here leaves cfg.lua with just the orchestration logic.

    NOTE ON LINE COUNT: This file deliberately exceeds the Phase 6
    1500-line module ceiling (CLAUDE.md §5). It is a flat data table
    of around 700 cfg-key entries shaped { <default>, <validator-fn> },
    not procedural code with branches and state. CLAUDE.md §5 Phase 6
    review-gate explicitly exempts data tables from the ceiling on the
    grounds that cognitive load on a repetitive lookup is materially
    different from 1500 lines of branching logic. If this file ever
    starts holding logic instead of data, that exception no longer
    applies and it must be split.

    Public surface returned to cfg.lua:

        {
            settings  = { <key> = { <default-value>, <validator-fn> }, ... },
            bind_late = function()  -- see comment below
        }

    Each entry's validator is a closure over the local types_X
    upvalues declared at the top of this file. types_adcstr is
    deliberately late-bound: types.add("adcstr", ...) is registered
    by core/adc.lua, which loads AFTER us during init.lua's core-load
    loop. Lua captures upvalues by reference, so once cfg.init()
    calls bind_late(), every validator that references types_adcstr
    sees the new value automatically.

]]--

local type = use "type"
local pairs = use "pairs"
local ipairs = use "ipairs"

local const = use "const"
local types = use "types"

local CONFIG_PATH = const.CONFIG_PATH

local types_utf8 = types.utf8
local types_table = types.get "table"
local types_number = types.get "number"
local types_boolean = types.get "boolean"

-- Strict-positive number validator. Used by ratelimit cfg keys where a
-- value of 0 or negative would silently put the hub into a degraded
-- mode that's hard to diagnose - msg_rate=0 leaves users connected but
-- unable to chat after the burst is exhausted, msg_burst=-1 mutes
-- every non-op user, NaN poisons the token-bucket math for that
-- bucket. Rejecting at cfg-load time means cfg.lua's checkcfg() logs
-- a clear error and falls back to the default, instead of operators
-- discovering the problem from confused users.
local function ratelimit_pos_number( value )
    return types_number( value, nil, true ) and value > 0
end

-- Tier-table inner field whitelist. Operator typos like `msg_brust = 5`
-- used to pass the type-check and then silently get ignored (scalar
-- fallback) - operators only noticed when their tier didn't behave.
-- A whitelist makes the typo a cfg-load error, surfaced via out_error
-- + default-fallback in cfg.lua:checkcfg(). Keep this list in sync
-- with the field names consumed by core/ratelimit.lua's user_X
-- functions and the _tier_or_scalar helper.
local _RATELIMIT_TIER_FIELDS = {
    msg_rate = true, msg_burst = true,
    pm_rate = true, pm_burst = true,
    inf_rate = true, inf_burst = true,
    ctm_rate = true, ctm_burst = true,
    search_period = true, search_burst = true,
}

-- Late-bound: types.add("adcstr", ...) is registered by core/adc.lua,
-- which loads after us. cfg.init() calls bind_late() at the right
-- time, after which all closures referencing types_adcstr see it.
local types_adcstr

local function bind_late()
    types_adcstr = types.get "adcstr"
end

local defaults = {


    ---------------------------------------------------------------------------------------------------------------------------------
    --// Basic Settings

    hub_name = { "Luadch-NG Hub",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_description = { "your hub description",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_bot = { "[BOT]HubSecurity",
        function( value )
            if not types_adcstr( value, nil, true ) or #value == 0 then
                return false
            end
            return true
        end
    },
    hub_bot_desc = { "[ BOT ] hub security",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_hostaddress = { "your.host.addy.org",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- #77 TLS-only by default: tcp_ports / tcp_ports_ipv6 default to
    -- empty arrays (no plain ADC listener). ssl_ports / ssl_ports_ipv6
    -- keep their port numbers; cert is auto-generated on first boot
    -- by core/cert_bootstrap.lua. Operators who want plain ADC
    -- alongside opt in via cfg/cfg.tbl with explicit port lists.
    tcp_ports = { { },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    ssl_ports = { { 5001 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    tcp_ports_ipv6 = { { },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    ssl_ports_ipv6 = { { 5001 },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_number( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    -- #214 HBRI (Hub-Bridged Reverse Initiation). Opt-in. When a
    -- dual-stack client logs in, the hub can only authenticate the IP
    -- family matching the TCP source; the secondary family is stripped
    -- before broadcast (DDoS-amplification safety). With HBRI enabled
    -- the hub asks such a client to validate its secondary address over
    -- a second-family side-channel connection and, on success, restores
    -- the verified secondary to the broadcast INF. Effective ONLY when
    -- the hub has a plain listener on BOTH families AND both public
    -- advertise addresses below are set (otherwise the hub does not
    -- advertise ADHBRI / never initiates - the secondary just stays
    -- stripped).
    hbri_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Seconds the hub waits for the side-channel validation before
    -- giving up and letting the client into the hub without the
    -- secondary (adchpp default is 5).
    hbri_timeout = { 5,
        function( value )
            return types_number( value, nil, true )
                and value >= 1 and value <= 60 and value % 1 == 0
        end
    },
    -- The hub's PUBLIC IPv4 / IPv6 address that an HBRI client connects
    -- to for the side-channel. Required when hbri_enabled (the hub
    -- cannot reliably auto-detect its routable address behind NAT /
    -- a "::" bind). Empty = do not advertise / initiate HBRI.
    hbri_advertise_v4 = { "",
        function( value )
            if not types_utf8( value, nil, true ) then return false end
            -- Reject whitespace / control bytes: this value is
            -- concatenated raw into the ITCP frame sent to clients, so a
            -- space or newline would inject extra params / frames.
            return value == "" or not value:find( "[%s%c]" )
        end
    },
    hbri_advertise_v6 = { "",
        function( value )
            if not types_utf8( value, nil, true ) then return false end
            return value == "" or not value:find( "[%s%c]" )
        end
    },
    use_ssl = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    use_keyprint = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    keyprint_type = { "/?kp=SHA256/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    keyprint_hash = { "<your_kp>",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_listen = { { "*" },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not types_utf8( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    -- Phase 8 S3 (#82): local read-only HTTP API port. `false` (the
    -- default) = no HTTP listener bound at all. A number = bind the
    -- hardened HTTP framer on http_bind_addr:<n> (default 127.0.0.1;
    -- #82 assumes a reverse proxy for any non-loopback exposure). S3
    -- serves only /health; auth + data endpoints land in a separate
    -- #82 follow-up PR.
    http_port = { false,
        function( value )
            if value == false then
                return true
            end
            -- integer in the valid TCP port range only: types_number
            -- has no range/integer check, so 0 (OS-assigned ephemeral
            -- on all interfaces) and floats would otherwise slip
            -- through.
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1 and value <= 65535
        end
    },
    -- HTTP API bind address. Default "127.0.0.1" keeps the listener
    -- on loopback - the security premise for shipping the API without
    -- TLS/auth at the transport layer. Set to "0.0.0.0" (or "::") ONLY
    -- in container setups where the API is reachable to sibling
    -- containers via a private Docker network and the port is NOT
    -- published to the host. Never bind to a public interface
    -- directly - put a reverse proxy in front and bind to the address
    -- the proxy lives on (typically still loopback, or a Docker-
    -- network address). See docs/HTTP_API.md §2.
    -- Init-time only: the listener binds once during boot. Changing
    -- this value via cfg.tbl + `+reload` does NOT re-bind the
    -- listener; a full hub restart is required (mirrors the
    -- `http_port` behaviour). Validator rejects whitespace + control
    -- bytes (mirrors hbri_advertise_v4 / v6) to prevent injection
    -- into the addserver call.
    http_bind_addr = { "127.0.0.1",
        function( value )
            return types_utf8( value, nil, true )
                and #value > 0
                and not value:find( "[%s%c]" )
        end
    },
    -- Phase 1b of #82 HTTP API: token table for bearer-auth, map-
    -- form so the cfg key IS the token and the value carries the
    -- scope ("read" | "admin") + free-form comment surfaced in
    -- api_audit.log. Default {} (no tokens) keeps the HTTP listener
    -- DOWN even when http_port is set; the first-boot path writes a
    -- sample token to cfg/api_token.first chmod 600 for the operator
    -- to copy into this table - until that copy happens, the
    -- listener does NOT bind (#231). See docs/HTTP_API.md §4 for
    -- the auth model and §4.7 for the activation flow.
    http_api_tokens = { { },
        function( value )
            if not types_table( value ) then return false end
            -- Per-entry validation, NOT whole-table. A single malformed
            -- entry (a scope typo, a non-string key, ...) must not
            -- invalidate the ENTIRE table: that path returned false here,
            -- the cfg loader reset the key to the default {}, and the HTTP
            -- listener then refused to bind at all - one typo locked the
            -- operator out of an otherwise-healthy hub. Instead drop only
            -- the offending entries, keep the valid tokens, and log each
            -- drop so a vanished token is explained rather than silent.
            -- `use "out"` is resolved lazily (out.lua loads AFTER cfg in
            -- the _core order, so it cannot be imported at file top); this
            -- validator only runs at checkcfg / reload time, long after
            -- out is up. Setting an existing field to nil during a pairs()
            -- walk is explicitly permitted by Lua.
            local dropped = 0
            for token, spec in pairs( value ) do
                local ok = true
                if type( token ) ~= "string" or #token == 0 then
                    ok = false
                elseif type( spec ) ~= "table" then
                    ok = false
                elseif spec.scope ~= "read" and spec.scope ~= "admin" then
                    ok = false
                elseif spec.comment ~= nil and type( spec.comment ) ~= "string" then
                    ok = false
                end
                if not ok then
                    value[ token ] = nil
                    dropped = dropped + 1
                end
            end
            if dropped > 0 then
                use( "out" ).error(
                    "cfg.lua: http_api_tokens: dropped ", dropped,
                    " invalid token entr", ( dropped == 1 and "y" or "ies" ),
                    " (bad scope or shape); the remaining valid tokens are kept" )
            end
            return true
        end
    },
    -- Phase 1b of #82: log every GET request to api_audit.log too
    -- (off by default - WebUI polling would otherwise spam the
    -- log). Operators enable for forensic sessions.
    http_api_log_reads = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Phase 1c of #82 HTTP API rate-limit (docs/HTTP_API.md §6.3).
    -- Read default is doubled (120/min) because WebUI polling shares
    -- the read scope; admin (60/min) is the operator/CI surface.
    -- Burst is shared across scopes - a quiet WebUI does not block
    -- a sudden admin batch. Values are requests per MINUTE; the
    -- ratelimit module converts to per-second internally.
    -- X-Confirm endpoints are exempt regardless of this setting
    -- (operator recovery must succeed under load).
    http_api_rate_read = { 120,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_rate_admin = { 60,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-prefix failed-auth bucket (docs/HTTP_API.md §4.8). Keyed
    -- on the first 4 chars of the Bearer token; defaults rate 10/min
    -- burst 5 cap walk-the-token-space attacks without affecting
    -- legitimate WebUI restarts (token unchanged -> bucket unrelated).
    http_api_authfail_prefix_rate = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_authfail_prefix_burst = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- /v1/auth/verify password-oracle bucket (WebUI operator login).
    -- The endpoint checks a hub password via ADC challenge-response, so
    -- it is a password oracle - keep the rate low. Keyed per-nick AND
    -- per-IP (both gate). Values are requests per MINUTE (converted to
    -- per-second internally, like the sibling http_api_* rates).
    http_api_authverify_rate = { 6,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    http_api_authverify_burst = { 3,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Idempotency-key cache cap (docs/HTTP_API.md §6.2). Cache is
    -- always bounded by both the 5-min TTL AND this entry count;
    -- FIFO eviction on cap hit. Default 1024 fits comfortably even
    -- on a hub with thousands of admin actions per hour.
    http_api_idempotency_max_entries = { 1024,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 1048576
        end
    },
    -- #263: ringbuffer cap for the GET /v1/events event stream.
    -- Each entry is ~200 bytes (JSON-encoded); 1000 -> ~200 KB.
    -- Events older than the cap are evicted; clients whose `since`
    -- cursor falls below the buffer's minimum id get `cursor_lost:
    -- true` in the response and must catch up via the per-resource
    -- GET endpoints. PR-B will add the long-poll wait/yield path.
    http_events_buffer_size = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 16
                and value <= 100000
        end
    },
    -- #84: audit-log per-field caps applied by core/audit.lua at
    -- event build time. Caps reason strings and per-meta string
    -- values to prevent a malicious actor from blowing up a log
    -- line. The cap applies BEFORE the writer plugin serializes
    -- so the on-disk JSONL also stays bounded. Apply to both core
    -- audit events AND the corresponding /v1/events ringbuffer
    -- entries (sanitised once at build time, propagated as-is).
    audit_log_max_reason_chars = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 32
                and value <= 100000
        end
    },
    audit_log_max_meta_value_chars = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 32
                and value <= 100000
        end
    },
    -- Phase 8 S4b: ADC-EXT ZLIF (zlib stream compression). Off by
    -- default - operator opt-in, matches the S3 http_port pattern.
    -- When enabled and the client also advertises ADZLIF in HSUP, the
    -- hub initiates compression (sends IZON, installs an outbound
    -- deflate stage) and decompresses inbound after the client's own
    -- ZON. Spec is per-direction; the hub advertises only when
    -- enabled. See docs/SECURITY.md for the CRIME-class chosen-
    -- plaintext-length leak discussion that gates ZLIF over TLS
    -- behind the separate zlif_over_tls flag below.
    zlif_enabled = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- TLS+ZLIF is theoretically vulnerable to CRIME-class length-leak
    -- attacks (chosen-plaintext PM mixed with victim's other traffic
    -- on the same TLS-then-compressed wire). Practical exploitability
    -- is low (eavesdropper needed, broadcast noise masks length
    -- deltas) but the mitigation cost is one cfg flag. Plain-ADC
    -- connections see ZLIF when `zlif_enabled` is true regardless of
    -- this flag.
    zlif_over_tls = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- Phase 8 S5: ADC-EXT BLOM hash-search routing. Off by default
    -- (operator opt-in). When enabled, the hub advertises ADBLOM in
    -- SUP, requests a per-user bloom filter via HGET on entry to
    -- NORMAL state, and routes HASH-search SCH (those carrying a TR
    -- field) only to clients whose filter has all k bits set for
    -- the TTH. KEYWORD-search SCH (AN/NO/EX/TY/etc.) is broadcast
    -- to all clients unchanged regardless of `blom_enabled`; the
    -- filter cannot distinguish keyword matches by design.
    blom_enabled = { false,
        function( value )
            return value == false or value == true
        end
    },
    -- BLOM parameters. Spec restrictions (validated below):
    --   k >= 1
    --   h % 8 == 0       (byte-aligned hash slice per ADC-EXT 3.20)
    --   k * h <= 192     (TTH is 192 bits, the slice source)
    --   m % 64 == 0      (filter byte-aligned to 8-byte words)
    --   2^h > m          (slice must span the filter index space)
    --
    -- Defaults (k=6, h=16, m=32768) give a 4 KiB filter per user
    -- and ~39% false-positive rate at a 10k-file share. Operators
    -- with larger shares should raise `blom_m` (and possibly
    -- `blom_h`); raising `blom_k` past 6 buys little extra
    -- accuracy at typical hub-share sizes.
    blom_k = { 6,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1 and value <= 24
        end
    },
    blom_h = { 16,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 8 and value <= 64
                and value % 8 == 0
        end
    },
    blom_m = { 32768,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 64
                and value % 64 == 0
        end
    },
    hub_website = { "http://yourwebsite.org",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_network = { "your hubnetwork name",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_email = { "hub@mail.com",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    hub_bot_email = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    hub_owner = { "you",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    reg_only = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    nick_change = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    max_users = { 3000,
        function( value )
            return types_number( value, nil, true )
        end
    },
    user_path = { CONFIG_PATH,
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    --[[
        Path to the master key that decrypts cfg/user.tbl
        (Phase 7f F-AUTH-1, AES-256-GCM at rest).

        IMPORTANT:
            Empty string falls back to "<install>/cfg/master.key", which
            sits next to the encrypted user.tbl. That default exists for
            backwards compatibility and zero-config first-boot, but it
            is NOT the recommended production setup: anyone who exfiltrates
            a routine `tar czf backup.tar.gz cfg/` gets BOTH the encrypted
            blob AND its decryption key, and can decrypt offline. The
            at-rest encryption then provides zero protection.

        SET THIS to an absolute path OUTSIDE the install directory before
        you put real users in user.tbl, e.g.:

            master_key_path = "/etc/luadch/master.key"     -- POSIX
            master_key_path = "C:/ProgramData/luadch/master.key"  -- Windows

        Then exclude that path from your routine backup, or back it up to
        a separate destination (different host / encrypted-with-passphrase
        archive). Same handling as your TLS private key. See
        docs/SECURITY.md §3 for the backup-separation rationale.

        On POSIX the hub refuses to start if the file mode is not 0600.
        On Windows use icacls (see docs/BUILDING.md).
    ]]--
    master_key_path = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    --[[
        Encrypt cfg/user.tbl at rest (Phase 7f F-AUTH-1).

        Default: true. New deployments and existing v3.1.x deployments
        keep AES-256-GCM at-rest encryption with the master key at
        master_key_path. user.tbl on disk starts with the four-byte
        magic "LDC1" followed by a per-write nonce + ciphertext + GCM
        auth tag.

        Set to false (#128) to write user.tbl as plaintext Lua source
        instead. Use cases for the operator opting out:
            - Single-user home hub on a private host where the disk-
              level threat model is "if my disk leaves my house I have
              bigger problems".
            - Operator tooling that reads user.tbl directly (custom
              backup scripts, third-party admin UIs, ad-hoc inspection
              with a text editor) and cannot be retrofitted with the
              decrypt path.
            - Recovery-without-master.key as a hard requirement.

        What you give up:
            - Backup confidentiality. A routine `tar czf cfg.tar.gz cfg/`
              exfiltrates plaintext user passwords (ADC mandates the
              hub holds password-equivalents in RAM and on disk, so
              "passwords" in user.tbl are the actual values clients
              type at login).
            - Stolen-disk protection. An attacker who walks off with
              the host's disk reads user.tbl directly.
            - The forced-confidentiality default that makes a casual
                tar/scp/cloud-sync transfer non-leaky.

        What you keep regardless:
            - chmod 600 on user.tbl on POSIX (still set by saveusers).
            - The .bak atomic-refresh + auto-recovery flow.
            - Sandboxed loadtable on the plain-Lua-source path.

        Migration is automatic in both directions:
            - true -> false: the next save writes user.tbl as plain
              Lua source. Until then, the encrypted file on disk still
              decrypts via the existing master.key.
            - false -> true: the next save writes an LDC1 blob using
              master.key (auto-generated if missing).
            - Existing user.tbl files in either format auto-detect on
              load via the LDC1 magic prefix.

        See docs/SECURITY.md §3 for the threat-model trade-off.
    ]]--
    encrypt_usertbl = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    reg_level = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },
    key_level = { 50,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_level = { 55,
        function( value )
            return types_number( value, nil, true )
        end
    },
    debug = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_errors = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_events = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_scripts = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Phase 1b of #82 HTTP API: audit log of API writes (and reads
    -- if http_api_log_reads is also true). Default true because the
    -- write surface is admin-scoped and operators want forensics by
    -- default; disable via cfg if a deployment has a different
    -- audit sink upstream of the hub.
    log_api_audit = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    log_path = { "././log/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    language = { "en",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    core_lang_path = { "lang/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    scripts_lang_path = { "././scripts/lang/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    --[[
    hub_pass = { "jsjfjs87374737472374jdjdfj384",
        function( value )
            return types_boolean( value, nil, true ) or types_adcstr( value, nil, true )
        end
    },
    ]]
    max_bad_password = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bad_pass_timeout = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    min_password_length = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    max_password_length = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },
    min_nickname_length = { 3,
        function( value )
            return types_number( value, nil, true )
        end
    },
    max_nickname_length = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },
    no_cid_taken = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    ranks = { {

        "Bot",
        "Reg",
        "Op",
        "Admin",
        "Owner",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in ipairs( value ) do
                    if not types_utf8( k, nil, true ) then
                        return false
                    end
                end
            end
            return true
        end
    },
    bot_rank = { 1,
        function( value )
            return types_number( value, nil, true )
        end
    },
    reg_rank = { 2,
        function( value )
            return types_number( value, nil, true )
        end
    },
    op_rank = { 4,
        function( value )
            return types_number( value, nil, true )
        end
    },
    admin_rank = { 8,
        function( value )
            return types_number( value, nil, true )
        end
    },
    owner_rank = { 16,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// Your hub levels with level names (array of strings)

    levels = { {

        [ 0 ] = "UNREG",
        [ 10 ] = "GUEST",
        [ 20 ] = "REG",
        [ 30 ] = "VIP",
        [ 40 ] = "SVIP",
        [ 50 ] = "SERVER",
        [ 55 ] = "SBOT",
        [ 60 ] = "OPERATOR",
        [ 70 ] = "SUPERVISOR",
        [ 80 ] = "ADMIN",
        [ 100 ] = "HUBOWNER",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_regchat.lua settings

    bot_regchat_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_regchat_nick = { "[CHAT]RegChat",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_regchat_desc = { "[ CHAT ] chatroom for reg users",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_regchat_history = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_regchat_max_entrys = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_regchat_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_regchat_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_opchat.lua settings

    bot_opchat_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_opchat_nick = { "[CHAT]OpChat",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_opchat_desc = { "[ CHAT ] chatroom for operators",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_opchat_history = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_opchat_max_entrys = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_opchat_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    bot_opchat_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_pm2ops.lua settings

    bot_pm2ops_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    bot_pm2ops_nick = { "[CHAT]PmToOps",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_pm2ops_desc = { "[ CHAT ] send msg to all ops",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    bot_pm2ops_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_accinfo.lua settings

    cmd_accinfo_permission = { {

    [ 0 ] = 0,
    [ 10 ] = 0,
    [ 20 ] = 0,
    [ 30 ] = 0,
    [ 40 ] = 0,
    [ 50 ] = 0,
    [ 55 ] = 0,
    [ 60 ] = 50,
    [ 70 ] = 60,
    [ 80 ] = 70,
    [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_accinfo_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Shared by cmd_accinfo (+accinfo / +accinfoop) and cmd_usersearch:
    -- when true, those commands echo a registered user's stored password
    -- in their chat/PM reply instead of "<REDACTED>". Default false keeps
    -- passwords out of client-side chat logs (#95); enabling it is an
    -- operator tradeoff (see docs/SECURITY.md). The per-user hierarchy
    -- gate still applies (an op only sees passwords of users it may
    -- already inspect), and the HTTP API never exposes passwords.
    show_reguser_password = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_slots.lua settings

    cmd_slots_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_ban.lua settings

    cmd_ban_default_time = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_ban_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_ban_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_ban_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_delreg.lua settings

    cmd_delreg_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_delreg_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_delreg_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_disconnect.lua settings

    cmd_disconnect_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_disconnect_sendmainmsg = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_disconnect_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_errors.lua settings

    cmd_errors_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_help.lua settings

    -- Command prefix shown in the +help list so each line is copy-pasteable.
    -- The hub accepts "+", "!" and "#" (core/hub.lua "^[+!#]"); default "+"
    -- matches the docs and the hub's own "Did you mean +X?" hints.
    cmd_help_prefix = { "+",
        function( value )
            return value == "+" or value == "!" or value == "#"
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_mass.lua settings

    cmd_mass_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_mass_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_reg.lua settings

    cmd_reg_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_reg_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_reg_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 20,
        [ 70 ] = 30,
        [ 80 ] = 60,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_reload.lua settings

    cmd_reload_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_restart.lua settings

    cmd_restart_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_restart_toggle_countdown = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_rules.lua settings

    cmd_rules_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_rules_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_rules_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_setpass.lua settings

    cmd_setpass_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_setpass_permission_own_pw = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_setpass_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_nickchange.lua settings

    cmd_nickchange_minlevel = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_nickchange_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_nickchange_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_nickchange_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_shutdown.lua settings

    cmd_shutdown_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_shutdown_toggle_countdown = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_talk.lua settings

    cmd_talk_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_pm2offliners.lua settings

    cmd_pm2offliners_minlevel = { 30,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_oplevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_delay = { 7,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_pm2offliners_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_unban.lua settings

    cmd_unban_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 60,
        [ 70 ] = 70,
        [ 80 ] = 80,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_upgrade.lua settings

    cmd_upgrade_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_upgrade_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_upgrade_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_upgrade_advanced_rc = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_userinfo.lua settings

    cmd_userinfo_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_userlist.lua settings

    cmd_userlist_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_usersearch.lua settings

    cmd_usersearch_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_usersearch_max_limit = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_hubinfo.lua settings

    cmd_hubinfo_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_hubinfo_onlogin = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_uptime.lua settings

    cmd_uptime_minlevel = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_banner.lua settings

    etc_banner_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_time = { 1,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_banner_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_banner_permission = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_chatlog.lua settings

    etc_chatlog_min_level_adv = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_chatlog_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_chatlog_max_lines = { 200,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_chatlog_default_lines = { 5,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_blacklist.lua settings

    etc_blacklist_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_blacklist_masterlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_cmdlog.lua settings

    etc_cmdlog_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_cmdlog_command_tbl = { {

        [ "reg" ] = true,
        [ "delreg" ] = true,
        [ "disconnect" ] = true,
        [ "ban" ] = true,
        [ "unban" ] = true,
        [ "upgrade" ] = true,
        [ "accinfo" ] = true,
        [ "nickchange" ] = true,
        [ "reload" ] = true,
        [ "restart" ] = true,
        [ "shutdown" ] = true,
        [ "trafficmanager" ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_utf8( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    -- #96: command names whose post-command-name argument string is
    -- replaced with `<redacted>` in log/cmd.log. Prevents passwords
    -- supplied via +setpass / +newpw from landing on disk in plaintext
    -- through etc_cmdlog's audit trail.
    etc_cmdlog_redact_args = { {

        [ "setpass" ] = true,
        [ "newpw" ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_utf8( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_log_cleaner.lua settings

    etc_log_cleaner_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_log_cleaner_activate_error = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_log_cleaner_activate_cmd = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_motd.lua settings

    etc_motd_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_motd_permission = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_motd_destination_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_motd_destination_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_usercommands.lua settings

    etc_usercommands_toplevelmenu = { "Luadch-NG Commands",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_userlogininfo.lua settings

    etc_userlogininfo_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_userlogininfo_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },


    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_nick_prefix.lua settings

    usr_nick_prefix_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_nick_prefix_prefix_table = { {

        [ 0 ] = "[UNREG]",
        [ 10 ] = "[GUEST]",
        [ 20 ] = "[REG]",
        [ 30 ] = "[VIP]",
        [ 40 ] = "[SVIP]",
        [ 50 ] = "[SERVER]",
        [ 55 ] = "[SBOT]",
        [ 60 ] = "[OPERATOR]",
        [ 70 ] = "[SUPERVISOR]",
        [ 80 ] = "[ADMIN]",
        [ 100 ] = "[HUBOWNER]",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_nick_prefix_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    -- Op-chat report when a nick-prefix conflict causes the kick. The
    -- onConnect listener can NOT fire onFailedAuth (the prefix kick
    -- happens inside the same listener chain, causing recursion) so
    -- the plugin sends a direct report.send instead. Same defaults
    -- as sibling reporting plugins.
    usr_nick_prefix_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    usr_nick_prefix_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_desc_prefix.lua settings

    usr_desc_prefix_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_desc_prefix_prefix_table = { {

        [ 0 ] = "[ UNREG ] ",
        [ 10 ] = "[ GUEST ] ",
        [ 20 ] = "[ REG ] ",
        [ 30 ] = "[ VIP ] ",
        [ 40 ] = "[ SVIP ] ",
        [ 50 ] = "[ SERVER ] ",
        [ 55 ] = "[ SBOT ] ",
        [ 60 ] = "[ OPERATOR ] ",
        [ 70 ] = "[ SUPERVISOR ] ",
        [ 80 ] = "[ ADMIN ] ",
        [ 100 ] = "[ HUBOWNER ] ",

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_utf8( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_desc_prefix_permission = { {

        [ 0 ] = false,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_slots.lua settings

    min_slots = { {

        [ 0 ] = 2,
        [ 10 ] = 2,
        [ 20 ] = 2,
        [ 30 ] = 2,
        [ 40 ] = 2,
        [ 50 ] = 2,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 0,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    max_slots = { {

        [ 0 ] = 20,
        [ 10 ] = 20,
        [ 20 ] = 20,
        [ 30 ] = 20,
        [ 40 ] = 20,
        [ 50 ] = 20,
        [ 55 ] = 20,
        [ 60 ] = 20,
        [ 70 ] = 20,
        [ 80 ] = 20,
        [ 100 ] = 20,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_slots_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_share.lua settings

    min_share = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 0,
        [ 70 ] = 0,
        [ 80 ] = 0,
        [ 100 ] = 0,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    max_share = { {

        [ 0 ] = 200,
        [ 10 ] = 200,
        [ 20 ] = 200,
        [ 30 ] = 200,
        [ 40 ] = 200,
        [ 50 ] = 200,
        [ 55 ] = 200,
        [ 60 ] = 200,
        [ 70 ] = 200,
        [ 80 ] = 200,
        [ 100 ] = 200,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_share_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_hubs.lua settings

    max_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- max/min_*_hubs cap how many OTHER hubs a user may be connected
    -- to while present here, broken down by their role at THIS hub.
    -- The values are policy advertisements: the PING extension reports
    -- them as `XU / XR / XO` (max) and `MU / MR / MO` (min) so hublist
    -- scrapers and ping bots can show "this hub requires you to be in
    -- 1-20 other hubs as a registered user" before a client connects.
    -- Enforcement at login / on INF update happens in usr_hubs.lua.
    --
    --   user = unregistered visitor       -> max_user_hubs / min_user_hubs
    --   reg  = registered user (any role) -> max_reg_hubs  / min_reg_hubs
    --   op   = operator-level user        -> max_op_hubs   / min_op_hubs
    --
    -- Typical settings:
    --   * public hubs: max = 20 (block multi-hub crawlers), min = 0
    --     (no federation requirement) - the bundled defaults below.
    --   * federation / "anti-leech" hubs: min_reg_hubs = 1+ so regs
    --     must be present in other hubs too.
    --   * private hubs: leave at defaults.
    --
    -- Operator-side sanity: keep `min_*_hubs <= max_*_hubs` for each
    -- role. The validators here are per-key (no cross-key check), so
    -- a contradiction like `min_user_hubs = 50, max_user_hubs = 20`
    -- loads without error but advertises nonsensical MU > XU in the
    -- PING reply. usr_hubs.lua enforcement runs on both fields
    -- independently so a user satisfying the max but not the min
    -- still gets disconnected. Cross-validation is a future
    -- candidate if the foot-gun ever bites in practice.
    max_user_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    max_reg_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    max_op_hubs = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    min_user_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    min_reg_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    min_op_hubs = { 0,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- ADC-EXT RDEX (3.32) - rich redirect.
    --
    -- hub_redirect_protocols: bitmask of redirect URI schemes this hub
    -- advertises support for. Emitted as IINF.RP so clients (and other
    -- hubs redirecting users here) know which URL scheme to use.
    --   1 = ADC, 2 = ADCS, 4 = NEODC (legacy), sum for combinations.
    --   Default 3 = ADC + ADCS (what luadch itself speaks).
    -- hub_redirect_alternatives: list of alternative redirect URLs
    -- attached as IQUI.RX on every kick/redirect (cmd_redirect etc).
    -- Clients use these as fallback targets if the primary RD URL is
    -- unreachable. Default empty (RX field omitted).
    -- hub_redirect_permanent: if true, IQUI carries PT1 so the client
    -- treats the redirect as permanent (e.g. updates its bookmark).
    -- Default false.
    hub_redirect_protocols = { 3,
        function( value )
            return types_number( value, nil, true ) and value >= 0 and value <= 7
        end
    },
    hub_redirect_alternatives = { { },
        function( value )
            if not types_table( value ) then return false end
            for _, v in pairs( value ) do
                if type( v ) ~= "string" then return false end
            end
            return true
        end
    },
    hub_redirect_permanent = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_godlevel = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_hubs_block_time = { 15,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_hubs_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hubs_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_hubs_redirect = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_topic.lua settings

    cmd_topic_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_topic_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_topic_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_aliases.lua settings (#327)

    etc_aliases_minlevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_aliases_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_aliases_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_auditlog.lua settings (#84)

    -- Master kill-switch. When false the plugin loads but writes
    -- nothing to disk and the HTTP read endpoint returns an empty
    -- list. The /v1/events audit stream remains populated either
    -- way (driven by core/http_events.lua's tap, not this plugin)
    -- - operators who want to disable the live stream entirely
    -- should drop the plugin from cfg.scripts instead.
    etc_auditlog_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Directory for the JSONL files. The default log/ is created at
    -- boot by core/ensuredirs.lua; if you relocate this to a custom
    -- directory, make sure that directory exists. The plugin chmods
    -- every file 0600 (POSIX) since audit content is sensitive (target
    -- nicks / IPs / CIDs).
    etc_auditlog_dir = { "log/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- File-name prefix. Final form: <dir><prefix><YYYY-MM-DD>.jsonl
    -- Default produces log/audit-2026-06-23.jsonl.
    etc_auditlog_prefix = { "audit-",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Days to retain. On rollover (first write past UTC midnight)
    -- the plugin unlinks any matching file whose date is older
    -- than this many days. Set 0 to disable retention sweep
    -- (operator owns the cleanup manually).
    etc_auditlog_retention_days = { 90,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 0
                and value <= 36500
        end
    },

    -- GET /v1/log/audit?lines=N defaults + cap (same envelope as
    -- /v1/log/cmd and /v1/errors per HTTP_API.md §6.4).
    etc_auditlog_http_lines_default = { 200,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 1000
        end
    },

    etc_auditlog_http_lines_max = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 10000
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_clientblocker.lua settings (#81)

    -- Operator level that can run `+blocker add / del` (read is open
    -- to anyone authorised on the ADC cmd, gated by etc_hubcommands).
    -- Mirrors the etc_blacklist convention (oplevel = the write floor).
    etc_clientblocker_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- Which user levels the client check applies to. Operators (60+)
    -- are exempt by default so an operator who adds a pattern that
    -- inadvertently matches their own client does not self-lockout.
    -- HUBOWNER (100) is kept in scope so the maintainer is not given
    -- a quiet bypass - a hub-owner who really wants to test from a
    -- blocked client can flip [100] to false at runtime.
    etc_clientblocker_check_levels = { {
        [ 0 ]   = true,
        [ 10 ]  = true,
        [ 20 ]  = true,
        [ 30 ]  = true,
        [ 40 ]  = true,
        [ 50 ]  = true,
        [ 55 ]  = false,
        [ 60 ]  = false,
        [ 70 ]  = false,
        [ 80 ]  = false,
        [ 100 ] = true,
    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for level, allowed in pairs( value ) do
                    if not ( types_number( level, nil, true )
                             and types_boolean( allowed, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    -- Fallback reason emitted when an operator adds a pattern via
    -- `+blocker add <pattern>` without a custom reason argument.
    -- Per-pattern overrides live in scripts/data/etc_clientblocker.tbl.
    etc_clientblocker_default_reason = { "Your client is not allowed",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Hard cap on operator-supplied pattern length. Lua patterns do
    -- not backtrack the way PCRE does, but `.- ` chains + nested
    -- captures can still produce expensive `string.find` runs on
    -- every onConnect. 200 chars is comfortably larger than any
    -- legitimate AP/VE rule (the v0.2 upstream patterns are <40).
    etc_clientblocker_max_pattern_len = { 200,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 1
                and value <= 4096
        end
    },

    -- Operator-chat report on every kick. When true, the plugin
    -- fires etc_report.send with a human-readable banner (nick,
    -- IP, version, matched pattern) so staff see kicks in chat
    -- without tailing the audit log. Defaults match sibling
    -- plugins (etc_aliases / etc_msgmanager): opchat ON, hubbot
    -- OFF.
    etc_clientblocker_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_clientblocker_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_clientblocker_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Minimum level required to receive the hubbot-PM report (only
    -- consulted when etc_clientblocker_report_hubbot=true). Mirrors
    -- the etc_report.send signature used across bundled plugins.
    etc_clientblocker_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_geoip.lua settings (#78 Phase D2)

    -- Feature toggle. Plugin loads either way (so operators can flip
    -- this + `+reload` without editing cfg.scripts); when false the
    -- onConnect check returns immediately - zero lookup cost.
    etc_geoip_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Paths to the MaxMind GeoLite2 databases. The operator installs +
    -- refreshes these out-of-band with MaxMind's `geoipupdate` tool
    -- (see docs/BLOCKLIST.md). A missing file is not an error - the
    -- plugin logs once and stays inert for that DB. ASN is optional;
    -- leave the path pointing at a non-existent file to disable ASN
    -- checks.
    etc_geoip_country_db_path = { "cfg/geoip/GeoLite2-Country.mmdb",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_geoip_asn_db_path = { "cfg/geoip/GeoLite2-ASN.mmdb",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Blocked ISO-3166-1 alpha-2 country codes, e.g. { "CN", "RU", "KP" }.
    -- Case-insensitive (normalised to upper-case at load); entries that
    -- are not two letters are ignored. Empty = no country is blocked.
    etc_geoip_blocked_countries = { { },
        function( value )
            if not types_table( value ) then return false end
            for _, v in ipairs( value ) do
                if type( v ) ~= "string" or not v:upper( ):match( "^%u%u$" ) then
                    return false
                end
            end
            return true
        end
    },

    -- Blocked autonomous-system numbers, e.g. { 4134, 4837 } (needs an
    -- ASN DB configured). Empty = no ASN is blocked.
    etc_geoip_blocked_asns = { { },
        function( value )
            if not types_table( value ) then return false end
            for _, v in ipairs( value ) do
                if not ( types_number( v, nil, true ) and v % 1 == 0 and v >= 0 ) then
                    return false
                end
            end
            return true
        end
    },

    -- What to do on a match. "log_only" (default) audits + reports the
    -- match but lets the user in - the safe starting mode so an operator
    -- verifies the logs before enforcing. "block" kicks the connection.
    etc_geoip_action = { "log_only",
        function( value )
            return value == "log_only" or value == "block"
        end
    },

    -- Which user levels the GeoIP check applies to. Operators (55-80)
    -- exempt by default so a misconfigured country list cannot lock
    -- staff out; HUBOWNER (100) kept in scope (flip [100]=false to test
    -- from a blocked region). Mirrors etc_clientblocker_check_levels.
    etc_geoip_check_levels = { {
        [ 0 ]   = true,
        [ 10 ]  = true,
        [ 20 ]  = true,
        [ 30 ]  = true,
        [ 40 ]  = true,
        [ 50 ]  = true,
        [ 55 ]  = false,
        [ 60 ]  = false,
        [ 70 ]  = false,
        [ 80 ]  = false,
        [ 100 ] = true,
    },
        function( value )
            if not types_table( value ) then return false end
            for level, allowed in pairs( value ) do
                if not ( types_number( level, nil, true )
                         and types_boolean( allowed, nil, true ) ) then
                    return false
                end
            end
            return true
        end
    },

    -- How often (seconds) to re-read the .mmdb from disk so a
    -- geoipupdate cron write is picked up without a manual +reload.
    -- MaxMind releases twice weekly; hourly is ample. 60s floor keeps
    -- the re-read off the per-tick hot path.
    etc_geoip_recheck_interval_sec = { 3600,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 60
                and value <= 604800
        end
    },

    -- Kick message shown to a blocked user (block mode only).
    etc_geoip_kick_reason = { "Your region is not permitted on this hub.",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Operator level that can run `+geoip` (read-only status).
    etc_geoip_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- Opchat / hubbot report on every match (mirrors etc_clientblocker:
    -- opchat ON, hubbot OFF).
    etc_geoip_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_geoip_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_geoip_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_geoip_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- In-hub DB auto-update (#78 Phase D3). When ON, the hub downloads +
    -- refreshes the .mmdb itself (no geoipupdate cron / sidecar needed) on
    -- every platform. OFF by default; needs a free MaxMind account_id +
    -- license_key. See docs/BLOCKLIST.md.
    etc_geoip_auto_update = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- MaxMind account ID (the HTTP Basic-auth username). "" = unset.
    etc_geoip_account_id = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- MaxMind license key. SECRET: registered + resolved via core/secrets
    -- (env-var-first LUADCH_ETC_GEOIP_LICENSE_KEY, cfg.tbl fallback), sent
    -- in an Authorization header so it never touches the URL / the log.
    -- "" = unset (auto-update stays inert).
    etc_geoip_license_key = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Editions to fetch. Only GeoLite2-Country / GeoLite2-ASN map to the
    -- two reader paths above; any other has no destination and is skipped
    -- (never downloaded).
    etc_geoip_edition_ids = { { "GeoLite2-Country", "GeoLite2-ASN" },
        function( value )
            if not types_table( value ) then return false end
            for _, v in ipairs( value ) do
                if type( v ) ~= "string" or not v:match( "^GeoLite2%-%w+$" ) then
                    return false
                end
            end
            return true
        end
    },

    -- Auto-update cadence (seconds). Default daily; floor 6 h so we never
    -- hammer download.maxmind.com faster than its 2x/week release cadence.
    etc_geoip_update_interval_sec = { 86400,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0
                and value >= 21600
                and value <= 2592000
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_blocklist_feeds.lua settings (#78 Phase E)
    --
    -- Pull external IP/CIDR blocklists (Tor exits, Spamhaus DROP) over
    -- HTTPS and push them into the unified blocklist with source=external.
    -- Every feed is independently opt-in; all OFF by default. The refresh
    -- interval is a sanity-bounded cfg value here; the plugin ADDITIONALLY
    -- clamps each feed up to its provider's published auto-fetch floor
    -- (Tor 30 min, Spamhaus 1 h) at runtime. See docs/BLOCKLIST.md.

    -- Master toggle. The plugin loads either way (it is whitelisted in
    -- cfg.scripts); when false the onTimer refresh loop is inert.
    etc_blocklist_feeds_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Tor exit-node list (plain IPv4, one per line).
    etc_blocklist_feeds_tor_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_tor_url = { "https://check.torproject.org/torbulkexitlist",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_blocklist_feeds_tor_refresh_interval_sec = { 3600,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 60 and value <= 604800
        end
    },
    etc_blocklist_feeds_tor_stealth = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Spamhaus DROP v4 (JSONL: one {"cidr","sblid"} object per line).
    etc_blocklist_feeds_spamhaus_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_spamhaus_url = { "https://www.spamhaus.org/drop/drop_v4.json",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_blocklist_feeds_spamhaus_refresh_interval_sec = { 86400,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 60 and value <= 604800
        end
    },
    etc_blocklist_feeds_spamhaus_stealth = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Spamhaus DROP v6 (same JSONL format, drop_v6.json). Shares the
    -- spamhaus refresh interval + stealth toggle above.
    etc_blocklist_feeds_spamhaus_v6_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_spamhaus_v6_url = { "https://www.spamhaus.org/drop/drop_v6.json",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- AbuseIPDB blacklist (top-N reported IPs, plaintext). Needs an API
    -- key (see etc_blocklist_feeds_abuseipdb_key); free-tier blacklist
    -- download is 5/day so the plugin floors the interval at 6 h.
    etc_blocklist_feeds_abuseipdb_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_abuseipdb_url = { "https://api.abuseipdb.com/api/v2/blacklist?plaintext",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_blocklist_feeds_abuseipdb_refresh_interval_sec = { 86400,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 60 and value <= 604800
        end
    },
    etc_blocklist_feeds_abuseipdb_stealth = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- AbuseIPDB API key. Read env-var-first via core/secrets.lua
    -- (LUADCH_ETC_BLOCKLIST_FEEDS_ABUSEIPDB_KEY) with this cfg value as the
    -- fallback; registered as a secret so GET /v1/config redacts it (once
    -- the plugin is loaded). The env var is never dumped - prefer it.
    -- Empty = the abuseipdb feed stays disabled.
    etc_blocklist_feeds_abuseipdb_key = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Generic operator-supplied line-list (IP/CIDR per line). No default
    -- URL; an operator who enables it must set one. No API key.
    etc_blocklist_feeds_generic_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_generic_url = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_blocklist_feeds_generic_refresh_interval_sec = { 3600,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 60 and value <= 604800
        end
    },
    etc_blocklist_feeds_generic_stealth = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Operator level that can run `+blfeeds` (read-only status).
    etc_blocklist_feeds_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- Opchat / hubbot report on refresh success + on an ok->fail
    -- transition (mirrors etc_geoip: opchat ON, hubbot OFF).
    etc_blocklist_feeds_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_feeds_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_proxydetect.lua settings (#78 Phase F, closes #352)
    --
    -- Live proxy / VPN / Tor detection: on connect the client IP is
    -- looked up against an external provider API and, if it is a
    -- blocked type, the connection is kicked (action="block") or just
    -- logged (action="log_only"). Non-blocking lookup (verdict arrives
    -- in a callback, kick-later); a positive verdict in block mode is
    -- ALSO pushed into the unified blocklist with a TTL so repeat
    -- connections drop pre-handshake. Verdicts are cached to
    -- scripts/data/etc_proxydetect.tbl to save provider quota. OFF by
    -- default. See docs/BLOCKLIST.md.

    -- Master toggle. The plugin loads either way (whitelisted in
    -- cfg.scripts); when false the onConnect check is inert.
    etc_proxydetect_enabled = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Detection provider (pick ONE): "proxycheck", "vpnapi", or "ipqs".
    -- See docs/BLOCKLIST.md for the free-tier / commercial-use terms of
    -- each before enabling - they differ sharply (vpnapi free = non-
    -- commercial only; ipqs free = evaluation only, 1000/month).
    etc_proxydetect_provider = { "proxycheck",
        function( value )
            return value == "proxycheck" or value == "vpnapi" or value == "ipqs"
        end
    },

    -- Provider API key. Read env-var-first via core/secrets.lua
    -- (LUADCH_ETC_PROXYDETECT_API_KEY) with this cfg value as the
    -- fallback; registered as a secret so GET /v1/config redacts it
    -- (once the plugin is loaded). The env var is never dumped - prefer
    -- it. proxycheck works keyless (100/day); a key raises it to
    -- 1000/day. vpnapi + ipqs require a key.
    etc_proxydetect_api_key = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- What to do on a match. "log_only" (default) audits + reports but
    -- lets the user in - the safe starting mode. "block" kicks the
    -- connection AND pushes the IP into the pre-handshake blocklist.
    etc_proxydetect_action = { "log_only",
        function( value )
            return value == "log_only" or value == "block"
        end
    },

    -- Which detected types trigger a block (map of type -> boolean).
    -- proxycheck / ipqs report proxy / vpn / tor; vpnapi additionally
    -- reports "relay" (e.g. iCloud Private Relay) - deliberately left OUT
    -- of the default so mainstream Apple users are not kicked; add
    -- relay=true only to block privacy relays. A detected type counts only
    -- if it is present AND true here.
    etc_proxydetect_block_types = { {
        proxy = true,
        vpn   = true,
        tor   = true,
    },
        function( value )
            if not types_table( value ) then return false end
            for k, v in pairs( value ) do
                if not ( type( k ) == "string"
                         and types_boolean( v, nil, true ) ) then
                    return false
                end
            end
            return true
        end
    },

    -- Which user levels the proxy check applies to (map of integer ->
    -- boolean). Operators (55-80) exempt by default so a provider false
    -- positive cannot lock staff out; HUBOWNER (100) kept in scope.
    -- Mirrors etc_geoip_check_levels.
    etc_proxydetect_check_levels = { {
        [ 0 ]   = true,
        [ 10 ]  = true,
        [ 20 ]  = true,
        [ 30 ]  = true,
        [ 40 ]  = true,
        [ 50 ]  = true,
        [ 55 ]  = false,
        [ 60 ]  = false,
        [ 70 ]  = false,
        [ 80 ]  = false,
        [ 100 ] = true,
    },
        function( value )
            if not types_table( value ) then return false end
            for level, allowed in pairs( value ) do
                if not ( types_number( level, nil, true )
                         and types_boolean( allowed, nil, true ) ) then
                    return false
                end
            end
            return true
        end
    },

    -- How long (seconds) a verdict stays cached AND how long a positive
    -- IP stays in the pre-handshake blocklist. A proxy today may not be
    -- one next week (dynamic IPs), so 1 day is a sane default.
    etc_proxydetect_cache_ttl_sec = { 86400,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 60 and value <= 604800
        end
    },

    -- Per-lookup HTTP timeout (seconds). Kept short - this runs in the
    -- connect path; a slow provider must not stall the pending verdict.
    etc_proxydetect_query_timeout_sec = { 5,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 1 and value <= 30
        end
    },

    -- Behaviour when the provider errors / times out / quota is spent.
    -- true (default) = fail-OPEN (let the user in) so a provider outage
    -- does not lock every joining user out. false = fail-CLOSED (kick on
    -- provider error) - stricter, but risky for hubs without 24/7 ops.
    etc_proxydetect_fail_open = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Stealth flag for the pushed pre-handshake block: true = repeat
    -- connections are silently dropped at accept (no visible kick); the
    -- FIRST detection still gets a visible kick reason post-handshake.
    etc_proxydetect_stealth = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- Daily provider-query cap (quota / cost safety valve). A flood of
    -- DISTINCT IPs (each a cache miss) could otherwise exhaust the free
    -- tier or run up a paid bill. Over the cap -> skip the lookup and
    -- fail-open. 0 = unlimited. Default matches the common 1000/day free
    -- tier.
    etc_proxydetect_max_queries_per_day = { 1000,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 0 and value <= 1000000
        end
    },

    -- Op-chat alert threshold: this many provider failures within a 60s
    -- window fires ONE alert (debounced until a success) so a down provider
    -- or a bad API key does not silently degrade detection. 0 = disabled.
    etc_proxydetect_fail_alert_threshold = { 10,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 0 and value <= 100000
        end
    },

    -- Kick message shown to a detected user (block mode only).
    etc_proxydetect_kick_reason = { "Proxy / VPN / Tor connections are not permitted on this hub.",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- Operator level that can run `+proxydetect` (read-only status).
    etc_proxydetect_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- Opchat / hubbot report on every match (mirrors etc_geoip: opchat
    -- ON, hubbot OFF).
    etc_proxydetect_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_proxydetect_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_proxydetect_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_proxydetect_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_trafficmanager.lua settings

    etc_trafficmanager_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- etc_regserver_announce: opt-in hublist registration (default OFF
    -- = private hub). See scripts/etc_regserver_announce.lua.
    etc_regserver_announce_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- string (one regserver) OR array of strings (announce to several)
    etc_regserver_announce_url = { "https://your.regserver.org/register",
        function( value )
            if types_utf8( value, nil, true ) then return true end
            if type( value ) == "table" then
                for _, v in ipairs( value ) do
                    if not types_utf8( v, nil, true ) then return false end
                end
                return true
            end
            return false
        end
    },
    etc_regserver_announce_tls_verify = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_regserver_announce_cafile = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_regserver_announce_retry_interval = { 300,
        function( value )
            return types_number( value, nil, true ) and value > 0
        end
    },
    etc_regserver_announce_max_attempts = { 12,
        function( value )
            return types_number( value, nil, true ) and value >= 0
        end
    },

    -- etc_status_push.lua: periodic PUBLIC-status heartbeat (name / online
    -- user count / uptime) POSTed as JSON to an external endpoint.
    etc_status_push_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_status_push_url = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- Secret: resolved env-var-first via core/secrets (registered by the
    -- plugin) so GET /v1/config redacts it + PUT /v1/config/{key} refuses
    -- it. Prefer the env var LUADCH_ETC_STATUS_PUSH_TOKEN over a plaintext
    -- value here.
    etc_status_push_token = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    etc_status_push_interval = { 300,
        function( value )
            return types_number( value, nil, true ) and value > 0
        end
    },
    etc_status_push_tls_verify = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_status_push_cafile = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    -- etc_backup.lua (#480): automatic encrypted backups of the operator
    -- state set. The engine (core/backup.lua) reads dir / keep / passphrase /
    -- include; the plugin drives the schedule + the owner readiness nag.
    -- See docs/BACKUP.md.
    etc_backup_enabled = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Destination. Default cfg/backups so artifacts land under the
    -- upgrade-preserved cfg/ tree (and the Docker cfg mount). An absolute
    -- path is allowed (a mounted backup volume); the engine creates it via
    -- the raw makedir primitive.
    etc_backup_dir = { "cfg/backups",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- Retention: keep the newest N artifacts, prune older ones each run.
    etc_backup_keep = { 7,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 1 and value <= 1000
        end
    },
    -- Primary schedule: a daily backup at this server-local HH:MM. Empty
    -- string disables the daily slot (falls back to the interval below). The
    -- plugin parses/validates the HH:MM shape and treats a bad value as "no
    -- daily slot", so the validator only enforces it is a string.
    etc_backup_daily_at = { "04:00",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- Fallback cadence when etc_backup_daily_at is empty: every N hours
    -- (0 = off). For hubs wanting more than one backup a day.
    etc_backup_interval_hours = { 0,
        function( value )
            return types_number( value, nil, true )
                and value % 1 == 0 and value >= 0 and value <= 168
        end
    },
    -- Include master.key in the (encrypted) artifact. Default true for
    -- self-contained disaster recovery; false keeps the key strictly out of
    -- the backup (the plugin then warns the operator to save it separately).
    etc_backup_include_master_key = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Secret: the passphrase that encrypts the artifact (PBKDF2 -> AES-256-
    -- GCM). Resolved env-var-first via core/secrets (registered by the
    -- plugin) so GET /v1/config redacts it. Prefer the env var
    -- LUADCH_ETC_BACKUP_PASSPHRASE over a plaintext value here. Independent
    -- of master.key - store it out-of-band; losing it makes every artifact
    -- unrecoverable.
    etc_backup_passphrase = { "",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- Level allowed to run +backup now / list / status. Default 80 (ADMIN).
    etc_backup_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Level that receives the "backup not configured / not writable" hubbot
    -- nag on login + at start. Default 100 (HUBOWNER).
    etc_backup_notify_level = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    -- etc_webhook.lua: inbound webhook receiver (Discourse / GitHub /
    -- ...). Only the master switch lives in cfg.tbl; ALL endpoint config
    -- (paths, headers, secrets, templates, ...) lives in the
    -- operator-edited cfg/webhooks.tbl so cfg.tbl stays lean. Per-endpoint
    -- secrets resolve env-var-first (LUADCH_ETC_WEBHOOK_<NAME>_SECRET),
    -- else the etc_webhook_<name>_secret cfg key, else an inline secret in
    -- cfg/webhooks.tbl. See docs/WEBHOOKS.md.
    etc_webhook_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    -- etc_prometheus.lua: Prometheus text-exposition /metrics endpoint
    -- (#83). Off by default; the route is not registered when off.
    -- Registered here (not only in examples/cfg/cfg.tbl) so a hub that
    -- whitelists the plugin but whose cfg.tbl predates the key does NOT
    -- crash at plugin load: etc_prometheus.lua reads this via cfg.get at
    -- module scope, and cfg.get indexes _defaultsettings[key][1] with no
    -- fallback for an unregistered key.
    etc_prometheus_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_trafficmanager_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_blocklevel_tbl = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_trafficmanager_sharecheck = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_check_minshare = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_login_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_report_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_send_loop = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_trafficmanager_loop_time = { 6,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_trafficmanager_flag_blocked = { "[BLOCKED]",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_msgmanager.lua settings

    etc_msgmanager_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_msgmanager_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_msgmanager_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_msgmanager_permission_pm = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_msgmanager_permission_main = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_hide_share.lua settings

    usr_hide_share_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    usr_hide_share_restrictions = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    usr_hide_share_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 40,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_gag.lua settings

    cmd_gag_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_gag_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    cmd_gag_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_gag_user_notifiy = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_records.lua settings

    etc_records_min_level = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_whereto_main = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_whereto_pm = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_reportlvl = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_sendMain = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_sendPM = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_records_delay = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_records_min_level_reset = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// bot_session_chat.lua settings

    bot_session_chat_minlevel = { 20,
        function( value )
            return types_number( value, nil, true )
        end
    },

    bot_session_chat_masterlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    bot_session_chat_chatprefix = { "[SESSION-CHAT]",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_hubstats.lua settings

    cmd_hubstats_oplevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// etc_dhtblocker.lua settings

    etc_dhtblocker_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_block_level = { {

        [ 0 ] = true,
        [ 10 ] = true,
        [ 20 ] = true,
        [ 30 ] = true,
        [ 40 ] = true,
        [ 50 ] = true,
        [ 55 ] = true,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    etc_dhtblocker_block_time = { 15,
        function( value )
            return types_number( value, nil, true )
        end
    },

    etc_dhtblocker_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_toopchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_tohubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_dhtblocker_report_level = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_redirect.lua settings

    cmd_redirect_activate = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_permission = { {

        [ 0 ] = 0,
        [ 10 ] = 0,
        [ 20 ] = 0,
        [ 30 ] = 0,
        [ 40 ] = 0,
        [ 50 ] = 0,
        [ 55 ] = 0,
        [ 60 ] = 50,
        [ 70 ] = 60,
        [ 80 ] = 70,
        [ 100 ] = 100,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_number( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_redirect_level = { {

        [ 0 ] = true,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = false,
        [ 100 ] = false,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_redirect_url = { "adc://addy:port",
        function( value )
            return types_utf8( value, nil, true )
        end
    },

    cmd_redirect_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_redirect_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_sslinfo.lua settings

    cmd_sslinfo_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_myinf.lua settings

    cmd_myinf_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// hub_runtime.lua settings

    hub_runtime_minlevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    hub_runtime_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    hub_runtime_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// usr_uptime.lua settings

    usr_uptime_minlevel = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },

    usr_uptime_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = true,
        [ 70 ] = true,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_usercleaner.lua settings | this script shows and removes no longer used and never used accounts from "cfg/users.tbl"

    cmd_usercleaner_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_permission = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_usercleaner_protected_levels = { {

        [ 0 ] = false,
        [ 10 ] = false,
        [ 20 ] = false,
        [ 30 ] = false,
        [ 40 ] = false,
        [ 50 ] = false,
        [ 55 ] = false,
        [ 60 ] = false,
        [ 70 ] = false,
        [ 80 ] = true,
        [ 100 ] = true,

    },
        function( value )
            if not types_table( value ) then
                return false
            else
                for i, k in pairs( value ) do
                    if not ( types_boolean( k, nil, true ) and types_number( i, nil, true ) ) then
                        return false
                    end
                end
            end
            return true
        end
    },

    cmd_usercleaner_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_opchat = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_hubbot = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    cmd_usercleaner_report_llevel = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// cmd_gag.lua settings

    etc_onfailedauth_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    etc_onfailedauth_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },

    ---------------------------------------------------------------------------------------------------------------------------------
    --// user scripts (string array); scripts will be executed in this order!

    scripts = { {

        "hub_cmd_manager.lua",  -- must be the first script in the table!
        "etc_cmdlog.lua",  -- must be the second script in the table!
        "bot_opchat.lua", -- must be above all other scripts who wants to use the opchat import
        "etc_report.lua", -- must be above all other scripts who wants to use the report import / needs opchat
        "cmd_ban.lua", -- must be above all other scripts who wants to use the ban import / needs report
        "usr_uptime.lua", -- must be above all other scripts who wants to use the usersuptime import

        "hub_inf_manager.lua",
        "hub_runtime.lua",
        "bot_regchat.lua",
        "bot_session_chat.lua",
        "bot_pm2ops.lua",
        "usr_slots.lua",
        "usr_share.lua",
        "usr_hubs.lua",
        "usr_nick_prefix.lua",
        "usr_desc_prefix.lua",
        "usr_hide_share.lua",
        "cmd_help.lua",
        "cmd_redirect.lua",
        "cmd_uptime.lua",
        "cmd_hubinfo.lua",
        "cmd_hubstats.lua",
        "cmd_myip.lua",
        "cmd_myinf.lua",
        "cmd_rules.lua",
        "cmd_userinfo.lua",
        "cmd_usersearch.lua",
        "cmd_slots.lua",
        "cmd_accinfo.lua",
        "cmd_setpass.lua",
        "cmd_nickchange.lua",
        "cmd_mass.lua",
        "cmd_talk.lua",
        "cmd_topic.lua",
        "cmd_userlist.lua",
        "cmd_disconnect.lua",
        "cmd_reg.lua",
        "cmd_upgrade.lua",
        "cmd_delreg.lua",
        "cmd_usercleaner.lua",
        "cmd_errors.lua",
        "cmd_reload.lua",
        "cmd_restart.lua",
        "cmd_shutdown.lua",
        "cmd_gag.lua",
        "cmd_sslinfo.lua",
        "etc_hubcommands.lua",
        "etc_aliases.lua",
        "etc_usercommands.lua",
        "etc_blacklist.lua",
        "etc_log_cleaner.lua",
        "etc_motd.lua",
        "etc_userlogininfo.lua",
        "etc_banner.lua",
        "etc_chatlog.lua",
        "etc_msgmanager.lua",
        "etc_trafficmanager.lua",
        "etc_records.lua",
        "etc_dhtblocker.lua",

        "hub_bot_cleaner.lua",
        "etc_unknown_command.lua",

    },
        -- #261: each entry is EITHER a plain string `"name.lua"`
        -- (operator-managed, API-protected) OR a table
        -- `{ "name.lua", enabled = bool }` (API-toggleable). String
        -- entries are equivalent to `{ name, enabled = true }` for
        -- load-time semantics; the form distinguishes operator
        -- intent for the management API.
        function( value )
            if not types_table( value ) then
                return false
            end
            for i, entry in ipairs( value ) do
                if type( entry ) == "string" then
                    if not types_utf8( entry, nil, true ) then
                        return false
                    end
                elseif type( entry ) == "table" then
                    local name = entry[ 1 ]
                    if type( name ) ~= "string" or not types_utf8( name, nil, true ) then
                        return false
                    end
                    if entry.enabled ~= nil and type( entry.enabled ) ~= "boolean" then
                        return false
                    end
                else
                    return false
                end
            end
            return true
        end
    },
    script_path = { "././scripts/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    ssl_params = { {

        mode = "server",  -- do not touch this
        key = "certs/serverkey.pem",  -- your ssl key
        certificate = "certs/servercert.pem",  -- your cert
        cafile = "certs/cacert.pem",  -- your ca file
        -- TLS-1.3-only by design: protocol = "tlsv1_3" pins the
        -- SSL_CTX min == max == TLS1_3_VERSION (verified in luasec
        -- src/context.c), so nothing can negotiate down to <= 1.2.
        -- "no_renegotiation" is defense-in-depth for the case an
        -- operator manually downgrades protocol to "tlsv1_2"
        -- (unsupported - see examples/cfg/cfg.tbl); TLS 1.3 has no
        -- renegotiation anyway (RFC 8446). Requires OpenSSL >= 1.1.0h
        -- (project bundles 3.x; luasec raises "invalid option" on a
        -- flag the linked OpenSSL does not define).
        options = { "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1", "no_renegotiation" },  -- do not touch this
        curve = "prime256v1",  -- do not touch this

        protocol = "tlsv1_3",
        ciphers = "HIGH+kEDH:HIGH+kEECDH:HIGH:!PSK:!SRP:!3DES:!aNULL", -- TLSv1.3

    }, function( ) return true end },
    scripts_cfg_profile = { "default",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    scripts_cfg_path = { "././scripts/cfg/",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    no_global_scripting = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- #78 Precursor 0d: outbound-HTTPS CA bundle management.
    --
    -- `ca_bundle_path` is the runtime location of the trusted-CA
    -- bundle - operator-overwriteable, the default for
    -- http_client.cafile. `ca_bundle_source_path` is the immutable
    -- system-path source-of-truth installed by CMake (NOT under any
    -- volume-mounted directory), used by core/cacert_bootstrap.lua to
    -- restore the runtime file when missing. `ca_bundle_auto_update`
    -- defaults FALSE so the bootstrap leaves the operator-facing
    -- file alone on SHA mismatch (an operator might run a custom
    -- corporate-PKI bundle); flip TRUE for the "always pull the
    -- latest from the install tree" preference. See docs/CACERT.md.
    ca_bundle_path = { "certs/ca-bundle.pem",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    ca_bundle_source_path = { "lib/luadch/ca-bundle.pem",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    ca_bundle_auto_update = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- #97 (default true since v3.1.4), flipped back to false in
    -- v3.2.x: with the #214 Gap 2 fix in place, kill_wrong_ips=false
    -- no longer broadcasts a client-claimed (potentially spoofed) IP
    -- - the hub overrides the claim with the authenticated TCP source
    -- in core/hub_dispatch.lua before any broadcast, so the
    -- DDoS-amplification vector that motivated the strict default
    -- is closed by construction regardless of this toggle.
    --
    -- The practical effect of the strict default was kicking users
    -- with legitimate IP mismatches (VPN clients with stale cached
    -- IPs, clients hand-set with the wrong External / WAN IP, dual-
    -- stack users where the kernel picked a different outbound family
    -- than the user's configured advertise). The gate only concerns
    -- this advertised-vs-source mismatch, and is unrelated to how the
    -- hub blocks users (e.g. the Traffic Manager, which on 3.x decides
    -- on level / share / account-nick, not IP). Per-IP rate limits, GeoIP
    -- rules, abuse logs, and the unified blocklist all operate on the
    -- TCP source IP anyway, so the gate is purely defence-in-depth -
    -- and post-Gap-2 there is nothing left to depend on.
    --
    -- Operators who prefer the loud "tell the user to fix their client"
    -- kick over the silent IP-override can opt in via cfg.tbl:
    --     kill_wrong_ips = true
    -- The improved kick message (PR #331) includes a config hint
    -- pointing the user at their client's 'External / WAN IP' setting.
    kill_wrong_ips = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },

    --// RATE-LIMIT / DOS-HARDENING //--
    --
    -- Phase 7c. All defaults are conservative; tune to traffic profile.
    -- Op-level users (level >= ratelimit_bypass_level) bypass every
    -- per-user check below. Per-IP checks always apply.
    --
    -- Each "rate" key is integer per-second tokens (or bursts/window
    -- where noted). The "burst" key is the bucket capacity, allowing
    -- short spikes above the steady rate.

    ratelimit_activate = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    ratelimit_bypass_level = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- #78 Phase A: unified pre-handshake IP/CIDR blocklist. The
    -- engine + store ship enabled-by-default but the store is
    -- empty - zero overhead until operators add entries via
    -- Phase B's `+blocklist` cmd or Phase D/E/F's auto-feeds.
    -- See core/blocklist.lua + docs/BLOCKLIST.md (Phase B+).
    blocklist_enabled = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    blocklist_store_path = { "scripts/data/etc_blocklist.tbl",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- Per-rule stealth opt-in (default visible-kick), per locked
    -- arc decision: most operators want clear log feedback;
    -- stealth is for the rare "Tor exit pollutes the log" case.
    blocklist_stealth_default = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    -- Aggregated-log rollup window in seconds. Per-IP attempt
    -- counters flush as a single line at this cadence. Default
    -- 3600 = once-per-hour. Range 60..86400 (one-minute lower
    -- bound so the rollup is not also a high-rate log spammer).
    blocklist_aggregated_log_window_sec = { 3600,
        function( value )
            if not types_number( value, nil, true ) then return false end
            return value >= 60 and value <= 86400
        end
    },
    -- #78 allowlist (core/whitelist.lua): a global IP/CIDR allowlist
    -- consulted by every IP-blocking path. A match exempts the IP from
    -- the AUTOMATED blockers (GeoIP / proxydetect / feeds / hub-limit)
    -- and from automated blocklist-store entries, but NOT from a
    -- deliberate manual +blocklist/+ban (a manual block wins). Engine
    -- ships enabled with an empty store; Phase B's `+whitelist` plugin
    -- seeds the bundled hublist-pinger allowlist on first run.
    whitelist_enabled = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    whitelist_store_path = { "scripts/data/etc_whitelist.tbl",
        function( value )
            return types_utf8( value, nil, true )
        end
    },
    -- #78 allowlist, Phase B: `+whitelist` admin plugin
    -- (etc_whitelist.lua). Operator-facing chat command + JSONL
    -- export/import + a bundled hublist-pinger seed. The engine in
    -- core/whitelist.lua is independent; these keys gate the plugin.
    etc_whitelist_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },
    etc_whitelist_show_limit = { 200,
        function( value )
            if not types_number( value, nil, true ) then return false end
            return value >= 1 and value <= 10000
        end
    },
    -- Seed the bundled known-hublist-pinger allowlist on the FIRST run
    -- (store .tbl missing). Seed-on-missing only; operator edits are
    -- never overwritten. Set false to boot with an empty whitelist.
    etc_whitelist_seed = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_whitelist_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_whitelist_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_whitelist_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_whitelist_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Minimum level to RUN `+whitelist import <path>`. Same threat
    -- model as etc_blocklist_import_min_level: JSONL rows may carry
    -- master-added entries; default 100 = master-only.
    etc_whitelist_import_min_level = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- #501: etc_lockdown.lua transient maintenance-mode gate. The
    -- lockdown state itself is RUNTIME ( the `+lockdown` command,
    -- persisted to scripts/data/etc_lockdown.tbl ); these keys only tune
    -- the plugin. The plugin ships disabled in examples/cfg.
    etc_lockdown_command_minlevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    etc_lockdown_default_retry = { 120,
        function( value )
            if not types_number( value, nil, true ) then return false end
            return value >= 1 and value <= 86400
        end
    },
    etc_lockdown_exempt_whitelist = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_lockdown_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_lockdown_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_lockdown_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_lockdown_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- #500: etc_forcetlstransfer.lua force-ADCS C2C-transfer gate. On each
    -- peer-connection setup event it reads the transfer protocol and, per
    -- mode, drops ( "block" ) or warns ( "warn", default ) on a plain
    -- ( non-ADCS ) setup. All-or-nothing: no level / whitelist exemption.
    -- Ships ENABLED in "warn" mode in examples/cfg ( non-breaking );
    -- escalate to "block" to enforce.
    etc_forcetlstransfer_mode = { "warn",
        function( value )
            if not types_utf8( value, nil, true ) then return false end
            return value == "warn" or value == "block"
        end
    },
    -- #78 Phase B: `+blocklist` admin plugin (etc_blocklist.lua).
    -- Operator-facing chat command + JSONL export/import. The
    -- engine in core/blocklist.lua is independent; these keys
    -- only gate the plugin surface.
    etc_blocklist_oplevel = { 80,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Hard cap on rows returned by `+blocklist show`. Operator can
    -- still filter via `+blocklist show <source>` to narrow further.
    -- Cap exists so a 10k-row geoip-populated store doesn't dump a
    -- ten-thousand-line wall of text into one DMSG.
    etc_blocklist_show_limit = { 200,
        function( value )
            if not types_number( value, nil, true ) then return false end
            return value >= 1 and value <= 10000
        end
    },
    -- Opchat report toggles, same shape as etc_clientblocker. Add /
    -- remove / export / import events get a one-liner to the
    -- op-chat so all staff see the action live; the audit log
    -- carries the structured event for forensics.
    etc_blocklist_report = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_report_hubbot = { false,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_report_opchat = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },
    etc_blocklist_llevel = { 60,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Minimum level to RUN `+blocklist import <path>`. JSONL files
    -- can contain entries originally added by higher-level masters;
    -- without a level guard a mid-level operator could import +
    -- thereby take ownership of entries another master added.
    -- Default 100 = master-only; lower if your hub trusts every
    -- operator at `etc_blocklist_oplevel` with arbitrary imports.
    etc_blocklist_import_min_level = { 100,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP parallel-socket cap. Connection refused at accept time.
    -- Default 16 accommodates small-office NAT / CGNAT deployments
    -- where many users share one public IP. Lower for tighter hubs.
    ratelimit_perip_max_conns = { 16,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP new-connection rate (tokens/second + burst).
    -- Defaults sized for NAT bursts (e.g. an office reconnecting after
    -- internet flap). Burst >= max_conns so the parallel-cap is the
    -- binding limit at steady-state, not the rate-bucket.
    ratelimit_perip_conn_rate = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_perip_conn_burst = { 30,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- TLS handshake wallclock deadline (seconds). 0 disables.
    ratelimit_handshake_timeout = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- #207: cadence of the dedicated "kill stuck TLS handshakes"
    -- sweep. Decoupled from the broader _checkinterval (120s) so a
    -- handshake whose `ratelimit_handshake_timeout` expired gets
    -- reaped within roughly `sweep_interval` seconds rather than
    -- waiting for the next 120s sweep. Worst-case stuck-handshake
    -- lifetime = handshake_timeout + sweep_interval (default
    -- 10 + 10 = ~20s). Setting to 0 effectively disables the fast
    -- sweep and falls back to the broader 120s cadence.
    ratelimit_handshake_sweep_interval = { 10,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-IP bad-auth attempts. Per-account counter still applies on
    -- top of this (max_bad_password / bad_pass_timeout).
    ratelimit_perip_authfail_rate = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_perip_authfail_burst = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- When an IP exceeds the per-IP authfail rate above, block all
    -- further accepts from it for this many seconds (independent of
    -- the per-account bad_pass_timeout).
    ratelimit_authfail_lockout = { 300,
        function( value )
            return types_number( value, nil, true )
        end
    },
    -- Per-user mainchat (BMSG) rate.
    ratelimit_user_msg_rate = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_msg_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user PM (DMSG / EMSG) rate. Split out of the mainchat bucket
    -- in #80 so DMs and broadcasts can be tuned independently. Defaults
    -- match user_msg for behaviour-equivalence with v3.1.7.
    ratelimit_user_pm_rate = { 5,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_pm_burst = { 10,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user BINF-update rate (#80, post-login only). Defaults are
    -- deliberately lenient: watch-folders emit a BINF on every share-
    -- size change, and starting N parallel downloads emits N quick
    -- slot-count updates. burst=20 absorbs that without flagging
    -- legitimate users; rate=2/s lets steady-state churn through and
    -- caps any flood at ~120/min after the burst is exhausted.
    ratelimit_user_inf_rate = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_inf_burst = { 20,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user connection-setup rate (#80). Shared bucket for DCTM and
    -- DRCM since they are alternatives for the same primitive (peer
    -- connection initiation, choice depends on NAT routing). burst=30
    -- tolerates the explicit use case from the issue: a user firing
    -- many CTMs when their search results resolve to lots of peers,
    -- or kicking off a deep download queue. rate=2/s caps a malicious
    -- crawler at ~120 attempts per minute after the burst.
    ratelimit_user_ctm_rate = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_ctm_burst = { 30,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- Per-user search (BSCH / FSCH / DSCH) cooldown. The bucket fills
    -- at one token every ratelimit_user_search_period seconds.
    ratelimit_user_search_period = { 2,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    ratelimit_user_search_burst = { 3,
        function( value )
            return ratelimit_pos_number( value )
        end
    },
    -- #80 PR 4/4: per-userlevel tier overlay. Optional. Default empty
    -- tables = behaviour identical to the global scalars above. To use:
    -- 1) define one or more named tiers in `ratelimit_tiers`, each with
    --    any subset of the per-bucket fields (msg_rate / msg_burst /
    --    pm_rate / pm_burst / inf_rate / inf_burst / ctm_rate /
    --    ctm_burst / search_period / search_burst); missing fields fall
    --    back to the corresponding global scalar.
    -- 2) map user levels to tier names in `ratelimit_tier_for_level`;
    --    levels not listed in the map use the global scalars.
    -- Op-level users (>= ratelimit_bypass_level) bypass both tiers and
    -- scalars, same as before.
    -- Example:
    --   ratelimit_tiers = {
    --     strict   = { msg_rate = 2, msg_burst = 5, pm_rate = 2, pm_burst = 5 },
    --     generous = { msg_rate = 10, msg_burst = 20, ctm_burst = 60 },
    --   },
    --   ratelimit_tier_for_level = { [0] = "strict", [10] = "strict",
    --     [55] = "generous" },
    ratelimit_tiers = { { },
        function( value )
            if not types_table( value ) then return false end
            for tier_name, tier in pairs( value ) do
                if type( tier_name ) ~= "string" then return false end
                if not types_table( tier ) then return false end
                for k, v in pairs( tier ) do
                    if type( k ) ~= "string" then return false end
                    -- Typo guard: only the 10 known field names from
                    -- _RATELIMIT_TIER_FIELDS get through. msg_brust=5
                    -- (typo) raises here instead of silently falling
                    -- back to the global scalar.
                    if not _RATELIMIT_TIER_FIELDS[ k ] then return false end
                    -- Inner values feed the token bucket directly; same
                    -- strict-positive guard as the global scalar keys
                    -- above. msg_rate=0 / msg_burst=-1 in a tier would
                    -- silent-mute every user mapped to it.
                    if not ratelimit_pos_number( v ) then return false end
                end
            end
            return true
        end
    },
    ratelimit_tier_for_level = { { },
        function( value )
            if not types_table( value ) then return false end
            for level, tier_name in pairs( value ) do
                if not types_number( level, nil, true ) then return false end
                if type( tier_name ) ~= "string" then return false end
            end
            return true
        end
    },

    --// PING //--

    use_ping = { true,
        function( value )
            return types_boolean( value, nil, true )
        end
    },


}

return {
    settings  = defaults,
    bind_late = bind_late,
}
