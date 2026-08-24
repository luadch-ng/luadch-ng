--[[

    hub_dispatch.lua - the ADC command dispatcher extracted from core/hub.lua

    Phase 6d-3 of the hub.lua decomposition. Contains:

      - the four state-machine handler tables _protocol, _identify,
        _verify, _normal (one per ADC connection state)
      - states(), which routes an incoming command to the right
        handler based on the user's current state

    These ~270 lines were the largest remaining chunk of "logic with many
    upvalues" in hub.lua after the createuser / createbot extractions.
    Moving them here drops hub.lua under the Phase 6 1500-line ceiling.

    The dispatcher reads HEAVILY from hub.lua's cfg cache (_cfg_*),
    i18n strings (_i18n_*), format strings (_pingsup, _normalsup,
    _normalsup_regonly, _hubinf_regonly), and the user-state count
    (_user_count). Same bind_late() pattern as cfg_defaults / cfg_users /
    cfg_lang / hub_user_object / hub_bot_object: hub.lua calls
    _dispatch_module.bind({...}) once after init() and again whenever
    any of these caches are refreshed (loadsettings, loadlanguage,
    updateusers).

    _user_count is incremented/decremented in hub.lua's incoming and
    disconnect; we receive it as a getter closure so the dispatcher
    sees the live value rather than a stale snapshot.

    Public surface:

        {
            bind   = function(deps)
            states = function(user, adccmd, fourcc, state, targetuser)
        }

]]--

local use = use

local pairs = use "pairs"
local tostring = use "tostring"
-- Phase 8 S5 BLOM: the HSND handler parses the `bytes` positional
-- as a number. Core scripts run in a sandboxed env (see
-- core/init.lua setenv) where tonumber is not in scope - import it
-- explicitly. Same lesson as the iostream `pcall` import from S4b.
local tonumber = use "tonumber"

local adclib = use "adclib"
local bloom = use "bloom"    -- Phase 8 S5: hash-search membership oracle
local cfg = use "cfg"
local iostream = use "iostream"
local out = use "out"        -- audit-trail log for BLOM filter capture (#192)
local ratelimit = use "ratelimit"
local scripts = use "scripts"
local signal = use "signal"
local unicode = use "unicode"
local util = use "util"
local os = use "os"
local hbri = use "hbri"    -- #214 HBRI secondary-family validation

local out_put = out.put

-- ADC 1.0.1 requires the GPA password-challenge salt to be at least 24
-- random bytes (base32 encoded). createsalt(n) emits n base32 chars, which
-- hashpas (adclib) decodes as floor(n*5/8) bytes; 39 chars -> 24 bytes, the
-- spec floor. The historical default of 10 chars (6 bytes) was below it (#551).
local GPA_SALT_CHARS = 39

-- Stable upvalues - resolved once at file load.
local adclib_createsalt = adclib.createsalt
local adclib_escape = adclib.escape
local adclib_hash = adclib.hash
local adclib_hashpas = adclib.hashpas
local iostream_newdeflatestage = iostream.newdeflatestage
local iostream_newcountedstage = iostream.newcountedstage
local adclib_hasholdpas = adclib.hasholdpas
local escapeto = adclib_escape
local escapefrom = adclib.unescape
local utf_format = unicode.utf8.format    -- lang-template formatter (as in hub.lua)

local cfg_get = cfg.get
local cfg_saveusers = cfg.saveusers

local ratelimit_user_msg = ratelimit.user_msg
local ratelimit_user_pm = ratelimit.user_pm
local ratelimit_user_inf = ratelimit.user_inf
local ratelimit_user_ctm = ratelimit.user_ctm
local ratelimit_user_search = ratelimit.user_search
local ratelimit_record_authfail = ratelimit.record_authfail

local scripts_firelistener = scripts.firelistener
local signal_get = signal.get

local utf_format = unicode.utf8.format

local util_date = util.date
local util_difftime = util.difftime

local os_time = os.time
local os_difftime = os.difftime

-- Late-bound from hub.lua via bind(). Closures inside the four state
-- tables and states() pick these up via upvalue refs; hub.lua sets
-- them once init() has run, and re-binds after loadsettings,
-- loadlanguage, or updateusers refreshes anything.
--
-- Helpers and internal state
local isuserconnected
local isuserregged
local insertuser
local insertreguser
local login

local _regusers
local _normalstatesids
local _get_user_count   -- closure, returns current _user_count

-- The four state-machine tables and states() are file-local; the
-- bodies below assign to them. Forward-declare here so the sandbox env
-- recognises the assignments as local-writes rather than undeclared
-- globals.
local _protocol
local _identify
local _verify
local _normal
local states

-- VERSION (set once at hub start, but we late-bind to keep all the
-- "stamped-from-hub.lua" identifiers in one place).
local VERSION

-- Format strings (rebuilt on +reload via loadlanguage).
local _hubinf_regonly
local _pingsup
local _normalsup
local _normalsup_regonly

-- Cached cfg values (rebuilt by hub.lua's loadsettings on +reload).
local _cfg_reg_only
local _cfg_max_users
local _cfg_kill_wrong_ips
local _cfg_max_bad_password
local _cfg_bad_pass_timeout
local _cfg_min_share
local _cfg_max_share
local _cfg_min_slots
local _cfg_max_slots
local _cfg_max_user_hubs
local _cfg_max_reg_hubs
local _cfg_max_op_hubs
local _cfg_min_user_hubs
local _cfg_min_reg_hubs
local _cfg_min_op_hubs
local _cfg_hub_redirect_protocols
local _cfg_hub_email
local _cfg_hub_name
local _cfg_hub_description
local _cfg_hub_hostaddress
local _cfg_hub_website
local _cfg_hub_network
local _cfg_hub_owner
local _cfg_zlif_enabled
local _cfg_zlif_over_tls
local _cfg_blom_enabled
local _cfg_blom_k
local _cfg_blom_h
local _cfg_blom_m

-- #301: single table holding all i18n strings (was 11 individual
-- `local _i18n_*` slots before, threaded as 11 separate deps entries
-- from hub.lua; consolidated to free locals slots in hub.lua's main
-- chunk and shrink the deps surface). Rebuilt on +reload via
-- loadlanguage in hub.lua, re-bound here on _bind_dispatch_module().
local _i18n = { }

local function bind( deps )
    -- helpers
    isuserconnected      = deps.isuserconnected
    isuserregged         = deps.isuserregged
    insertuser           = deps.insertuser
    insertreguser        = deps.insertreguser
    login                = deps.login
    -- state
    _regusers            = deps._regusers
    _normalstatesids     = deps._normalstatesids
    _get_user_count      = deps._get_user_count
    -- constants / cache
    VERSION              = deps.VERSION
    _hubinf_regonly      = deps._hubinf_regonly
    _pingsup             = deps._pingsup
    _normalsup           = deps._normalsup
    _normalsup_regonly   = deps._normalsup_regonly
    _cfg_reg_only        = deps._cfg_reg_only
    _cfg_max_users       = deps._cfg_max_users
    _cfg_kill_wrong_ips  = deps._cfg_kill_wrong_ips
    _cfg_max_bad_password = deps._cfg_max_bad_password
    _cfg_bad_pass_timeout = deps._cfg_bad_pass_timeout
    _cfg_min_share       = deps._cfg_min_share
    _cfg_max_share       = deps._cfg_max_share
    _cfg_min_slots       = deps._cfg_min_slots
    _cfg_max_slots       = deps._cfg_max_slots
    _cfg_max_user_hubs   = deps._cfg_max_user_hubs
    _cfg_max_reg_hubs    = deps._cfg_max_reg_hubs
    _cfg_max_op_hubs     = deps._cfg_max_op_hubs
    _cfg_min_user_hubs   = deps._cfg_min_user_hubs
    _cfg_min_reg_hubs    = deps._cfg_min_reg_hubs
    _cfg_min_op_hubs     = deps._cfg_min_op_hubs
    _cfg_hub_redirect_protocols = deps._cfg_hub_redirect_protocols
    _cfg_hub_email       = deps._cfg_hub_email
    _cfg_hub_name        = deps._cfg_hub_name
    _cfg_hub_description = deps._cfg_hub_description
    _cfg_hub_hostaddress = deps._cfg_hub_hostaddress
    _cfg_hub_website     = deps._cfg_hub_website
    _cfg_hub_network     = deps._cfg_hub_network
    _cfg_hub_owner       = deps._cfg_hub_owner
    _cfg_zlif_enabled    = deps._cfg_zlif_enabled
    _cfg_zlif_over_tls   = deps._cfg_zlif_over_tls
    _cfg_blom_enabled    = deps._cfg_blom_enabled
    _cfg_blom_k          = deps._cfg_blom_k
    _cfg_blom_h          = deps._cfg_blom_h
    _cfg_blom_m          = deps._cfg_blom_m
    -- #301: single i18n table (replaces 11 individual deps entries).
    -- DO NOT reassign `_i18n = {}` anywhere - hub.lua's loadlanguage
    -- mutates the table in place on +reload, and downstream readers
    -- (this file, hub_bot_object.lua) hold the same reference.
    _i18n = deps._i18n
end

-- #214 Gap 1: the hub can only authenticate the IP family matching the
-- TCP source (userfam, validated in _identify.BINF). The OTHER family's
-- address is unverified - a sender connecting on v4 has no v6 socket
-- through which we could authenticate a claimed v6 address. Broadcasting
-- the unverified secondary lets a hostile client conscript other users
-- into directing CTM / RCM connection attempts at an arbitrary victim
-- address (the historical DC++ DDoS-amplification pattern). Strip the
-- unverified secondary family's I/U address fields and its SU transport
-- flags before the INF is stored + broadcast. Real HBRI (#214 PR-B)
-- re-adds a secondary address only after validating it over a
-- second-family side-channel socket.
local function strip_unverified_secondary( adccmd, userfam )
    local ip_field, udp_field, tcp_flag, udp_flag
    if userfam == "I4" then
        ip_field, udp_field, tcp_flag, udp_flag = "I6", "U6", "TCP6", "UDP6"
    else
        ip_field, udp_field, tcp_flag, udp_flag = "I4", "U4", "TCP4", "UDP4"
    end
    adccmd:deletenp( ip_field )
    adccmd:deletenp( udp_field )
    local su = adccmd:getnp "SU"
    if su then
        local kept
        for tok in su:gmatch( "[^,]+" ) do
            if tok ~= tcp_flag and tok ~= udp_flag then
                kept = kept and ( kept .. "," .. tok ) or tok
            end
        end
        if kept then
            adccmd:setnp( "SU", kept )
        else
            adccmd:deletenp( "SU" )
        end
    end
end

-- The four state-machine handler tables follow verbatim from hub.lua.
-- The only edits are: replace bare _user_count with _get_user_count(),
-- since _user_count mutates during normal hub operation and our cached
-- copy would go stale otherwise.

_protocol = {

    HSUP = function( user, adccmd )
        if adccmd:hasparam "ADBASE" or adccmd:hasparam "ADBAS0" then
            local response
            if (not _cfg_reg_only) and adccmd:hasparam "ADPING" then
                local min_share = _cfg_min_share[ 0 ] or 100
                local max_share = _cfg_max_share[ 0 ] or 100
                min_share = min_share * 1024^3
                max_share = max_share * 1024^4
                -- T1.3 of #147: aggregate SS / SF over online users.
                -- Bot user objects expose .share() returning 0 (not
                -- nil) and may not expose .files() at all; the
                -- short-circuit on `u.files and u:files()` plus the
                -- nil-check before accumulation handles both shapes
                -- and contributes 0 from bots either way. Cost is
                -- O(N) once per PING handshake - not a hot path.
                local total_ss, total_sf = 0, 0
                for _, u in pairs( _normalstatesids ) do
                    local s = u.share and u:share()
                    local f = u.files and u:files()
                    if s then total_ss = total_ss + s end
                    if f then total_sf = total_sf + f end
                end
                response = utf_format( _pingsup,
                    user.sid( ),
                    _cfg_hub_name,
                    adclib_escape( VERSION ),
                    _cfg_hub_description,
                    _cfg_hub_hostaddress,
                    _cfg_hub_website,
                    _cfg_hub_network,
                    _cfg_hub_owner,
                    adclib_escape( _cfg_hub_email or "" ),
                    _cfg_hub_redirect_protocols,
                    -- UC = humans online only. _get_user_count() is the
                    -- humans-only counter (incremented solely in login()'s
                    -- non-bot branch); _normalstatesids is the
                    -- humans+bots union, so tablesize() over it inflated
                    -- hublist UC by the bot count (#179). This now also
                    -- matches the max_users capacity gate below, which
                    -- already uses _get_user_count().
                    _get_user_count(),
                    total_ss,
                    total_sf,
                    min_share,
                    max_share,
                    _cfg_min_slots[ 0 ] or 1,
                    _cfg_max_slots[ 0 ] or 100,
                    _cfg_min_user_hubs,
                    _cfg_min_reg_hubs,
                    _cfg_min_op_hubs,
                    _cfg_max_user_hubs,
                    _cfg_max_reg_hubs,
                    _cfg_max_op_hubs,
                    _cfg_max_users,
                    os_difftime( os_time( ), signal_get( "start" ) )
                )
            elseif not _cfg_reg_only then
                local tpl = _normalsup
                -- Append Phase 8 feature tokens to the SUP advertise
                -- in a SINGLE gsub so they accumulate correctly when
                -- multiple features are enabled. Anchor: "ADUCMD\n"
                -- - the last token in the SUP segment. DO NOT remove
                -- or rename ADUCMD in _normalsup / _normalsup_regonly
                -- without updating this gsub. The S4b ZLIF smoke
                -- test asserts ADZLIF appears in the advertise, and
                -- the S5 BLOM smoke test does the same for ADBLOM,
                -- so a dropped anchor fails CI loudly.
                local extras = ""
                if _cfg_zlif_enabled then extras = extras .. " ADZLIF" end
                if _cfg_blom_enabled then extras = extras .. " ADBLOM" end
                if hbri.active( ) then extras = extras .. " ADHBRI" end    -- #214
                if extras ~= "" then
                    tpl = tpl:gsub( "ADUCMD\n", "ADUCMD" .. extras .. "\n", 1 )
                end
                response = utf_format( tpl,
                    user.sid( ),
                    _cfg_hub_name,
                    adclib_escape( VERSION ),
                    _cfg_hub_description,
                    _cfg_hub_redirect_protocols
                )
            elseif _cfg_reg_only then
                local tpl = _normalsup_regonly
                local extras = ""
                if _cfg_zlif_enabled then extras = extras .. " ADZLIF" end
                if _cfg_blom_enabled then extras = extras .. " ADBLOM" end
                if hbri.active( ) then extras = extras .. " ADHBRI" end    -- #214
                if extras ~= "" then
                    tpl = tpl:gsub( "ADUCMD\n", "ADUCMD" .. extras .. "\n", 1 )
                end
                response = utf_format( tpl,
                    user.sid( ),
                    adclib_escape( VERSION ),
                    _cfg_hub_redirect_protocols
                )
            end
            user.write( response )
            -- Phase 8 S4b: ZLIF activation. Decision is made by the
            -- hub on every connect; the client's `ADZLIF` token in
            -- HSUP signals it CAN do compression. Hub-initiated:
            -- write the IZON marker UNCOMPRESSED (it is the last
            -- plain frame, per ADC-EXT) then install the outbound
            -- deflate stage so subsequent writes are deflated. The
            -- client decides separately whether to compress its own
            -- outbound (and signals via its own ZON; we install
            -- inbound inflate on receipt in hub.lua's incoming
            -- intercept). zlif_over_tls separately gates the TLS
            -- path - see SECURITY.md for the CRIME discussion. PING
            -- (hublist) handshakes are excluded - pingers disconnect
            -- immediately after the response, and dispatching them a
            -- deflate stage would compress nothing useful and only
            -- complicate the scraper's debug output.
            if _cfg_zlif_enabled
                and adccmd:hasparam "ADZLIF"
                and ( not adccmd:hasparam "ADPING" )
            then
                local client = user:client()
                local is_tls = client.ssl and client.ssl( )
                if ( not is_tls ) or _cfg_zlif_over_tls then
                    user.write( "IZON\n" )
                    client.outframer_prepend( iostream_newdeflatestage( ) )
                end
            end
            if _cfg_max_users <= _get_user_count() then
                user:kill( "ISTA 211 " .. _i18n.hub_is_full .. "\n" )-----!
                return true
            end
            user:sup( adccmd )
            user:state "identify"
            user:hash "TIGR"    -- assume TIGR support^^
        else
            user:kill( "ISTA 220 " .. _i18n.no_base_support .. "\n", "TL-1" )-----!
        end
        return true
    end,
    -- Pre-login QUI - client gave up mid-handshake. Spec allows QUI
    -- in any state; we close cleanly so no ISTA 125 reaches the
    -- client. The normal disconnect path will not broadcast IQUI to
    -- others because state != "normal" (hub.lua:1325).
    HQUI = function( user, adccmd )
        user:client():close()
        return true
    end,
    -- #214 HBRI: a fresh connection whose FIRST frame is HTCP (not the
    -- usual HSUP) is an HBRI side-channel - a client validating its
    -- secondary IP family for a session it already logged in on. This
    -- transient connection is never a real hub user: hand it to the
    -- validator, which checks the token + family + source IP, answers
    -- ISTA, and closes the socket. No server.lua hook needed - the
    -- validation socket rides the normal accept path and is identified
    -- purely by this HTCP+token first frame.
    HTCP = function( user, adccmd )
        hbri.validate( user, adccmd )
        return true
    end,

}

_identify = {

    BINF = function( user, adccmd )
        local pid = adccmd:getnp "PD"
        local cid = adccmd:getnp "ID"
        local nick = adccmd:getnp "NI"
        -- I4 / I6 are conditionally required per ADC 4.3.x - clients
        -- without TCP4 / UDP4 / TCP6 / UDP6 in their SU may legitimately
        -- omit them (hublist pingers, IP-agnostic probes). The hub
        -- accepts no-IP login and fills the slot with the TCP-source
        -- IP under the connection's address family - see #161.
        --
        -- #147 T3.1: probe I4 and I6 independently so a dual-stack peer
        -- can advertise both in one BINF. The hub verifies only the
        -- family matching the TCP source against userip; the OTHER
        -- family is unverified and is STRIPPED before broadcast by
        -- strip_unverified_secondary (#214 Gap 1) - it is not stored or
        -- forwarded. Real HBRI (#214 PR-B) re-adds a validated secondary
        -- via a second-family side-channel socket.
        local inf_i4 = adccmd:getnp "I4"
        local inf_i6 = adccmd:getnp "I6"
        local hash = user.hash( )
        local userip = user.ip( ) or ""
        if not ( cid and pid and nick ) then
            user:kill( "ISTA 220 " .. _i18n.no_cid_nick_found .. "\n", "TL-1" )
            -- IP arg: log the authenticated TCP source rather than
            -- `inf_i4 or inf_i6` (the client-claimed INF address). The
            -- INF claim is unreliable here by construction - the BINF
            -- is malformed - and operators correlate failed-auth lines
            -- by source IP. Falls back to `unknown` only if the socket
            -- has no peer (defensive; should not happen post-connect).
            scripts_firelistener( "onFailedAuth", ( nick or _i18n.unknown ), ( userip ~= "" and userip or _i18n.unknown ), ( cid or _i18n.unknown ), escapefrom( _i18n.no_cid_nick_found ) )
            return true
        end
        local userfam = ( userip:find( ":", 1, true ) and "I6" or "I4" )
        -- Field that the TCP source's family can authenticate. The
        -- other family (if advertised) is stripped below, post-stamp.
        local infip_match = ( userfam == "I4" ) and inf_i4 or inf_i6
        if ( not inf_i4 and not inf_i6 )
                or infip_match == nil
                or infip_match == "0.0.0.0"
                or infip_match == "::" then
            -- Client advertised no IP for the connecting family (or
            -- used a spec placeholder, or advertised only the OTHER
            -- family - which is unusual but legal for a v6-only peer
            -- reaching us via a v4 socket via a relay etc.). Stamp
            -- the connecting family with userip. The other family,
            -- if the client did set it, is stripped below (#214 Gap 1).
            adccmd:setnp( userfam, userip )
        elseif infip_match ~= userip then
            if _cfg_kill_wrong_ips then
                -- Two %s args ordered (claim, actual) - the user-facing
                -- message reads more naturally as "you advertise X but
                -- are connecting from Y". Lang strings updated accordingly.
                local msg = utf_format( _i18n.invalid_ip, infip_match, userip )
                user:kill( "ISTA 246 " .. msg .. "\n", "TL-1" )
                scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( msg ) )
                return true
            else
                -- #214 Gap 2: kill_wrong_ips=false is the NAT-weird-
                -- deployment opt-out from killing-on-mismatch. The
                -- opt-out preserves the user's connection but the
                -- claimed (wrong) IP MUST NOT be broadcast - other
                -- clients would then direct CTM / RCM at the spoofed
                -- address (DDoS-amplification, see issue body). Stamp
                -- the authenticated TCP-source IP over the lie so the
                -- broadcast INF carries `userip`, not the claim. (The
                -- secondary family, if any, is additionally stripped
                -- below by strip_unverified_secondary - #214 Gap 1.)
                adccmd:setnp( userfam, userip )
            end
        end
        if cid ~= adclib_hash( pid ) then
            user:kill( "ISTA 227 " .. _i18n.invalid_pid .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", nick, userip, cid,  escapefrom( _i18n.invalid_pid ) )
            return true
        end
        local onlineuser = isuserconnected( nil, nil, cid, hash ) -- isuserconnected( nick, sid, cid, hash )
        if onlineuser then
            onlineuser:kill( "ISTA 224 " .. _i18n.cid_taken .. "\n", "TL-1" )
            --scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( _i18n.cid_taken ) )
        end
        onlineuser = isuserconnected( nick )
        if onlineuser then
            -- F-AUTH-NICK (#91): the legacy "kill zombie client" branch in
            -- reg_only mode killed the existing online user before HPAS
            -- proved the new connection holds the password. Pre-auth DoS:
            -- attacker only needed the target nick. Defer the takeover
            -- until HPAS validates: stash the existing user, skip
            -- insertuser/onConnect, and let _verify.HPAS perform the swap
            -- on success or kill the new connection on failure.
            if cfg_get "reg_only" then
                user._takeover_target = onlineuser
            else
                user:kill( "ISTA 222 " .. _i18n.nick_taken .. "\n", "TL-1" ) -- kill connecting client
                return true
            end
        end
        local profile = isuserregged( nick )
        if not profile and cfg_get "reg_only" then -- reg only hub; unregged user will be disconnected
            user:kill( "ISTA 226 " .. _i18n.reg_only .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", nick, userip, cid,  escapefrom( _i18n.reg_only ) )
            return true
        --else
        elseif profile then
            local bol, err = insertreguser( user, profile, cid, hash, nick )
            if not bol then
                user:kill( "ISTA 220 " .. escapeto(err) .. "\n", "TL-1" )
                return true
            end
        end
        adccmd:deletenp "PD"
        -- #214 HBRI: when the hub can validate secondaries, capture the
        -- client's unverified secondary claim BEFORE Gap 1 strips it so
        -- HBRI can re-add it after the side-channel proves the address.
        -- core/hbri.lua's eligible()/initiate() read user._hbri_claim.
        if hbri.active( ) then
            local sec_fam = ( userfam == "I4" ) and "I6" or "I4"
            -- NOT `(sec_fam=="I6") and inf_i6 or inf_i4`: the and/or
            -- ternary returns inf_i4 when inf_i6 is nil (the classic Lua
            -- trap), which would mint a bogus secondary claim for every
            -- v4 client that sent only I4 -> spurious HBRI + 5s timeout
            -- on every such login. Branch explicitly.
            local sec_ip
            if sec_fam == "I6" then sec_ip = inf_i6 else sec_ip = inf_i4 end
            -- #291: a non-empty secondary field is an HBRI request even
            -- when it is the spec placeholder (0.0.0.0 / ::). Per the
            -- adchpp HBRI contract the placeholder means "I'm capable on
            -- this family but cannot self-report my address; discover it
            -- via the side-channel getpeername()" - the COMMON real-client
            -- case (AirDC++ auto-detect). hbri.validate() commits the
            -- authenticated socket source for a placeholder claim and
            -- only cross-checks a CONCRETE stated address. A genuinely
            -- ABSENT field (nil / "") - the family is not offered at all -
            -- must NOT be solicited (the #288 v4-only-client guard, above).
            if sec_ip and sec_ip ~= "" then
                local su_flags = { }
                local su = adccmd:getnp "SU"
                if su then
                    local tcp_flag = ( sec_fam == "I6" ) and "TCP6" or "TCP4"
                    local udp_flag = ( sec_fam == "I6" ) and "UDP6" or "UDP4"
                    for tok in su:gmatch( "[^,]+" ) do
                        if tok == tcp_flag or tok == udp_flag then
                            su_flags[ #su_flags + 1 ] = tok
                        end
                    end
                end
                user._hbri_claim = {
                    family   = sec_fam,
                    ip       = sec_ip,
                    udp      = adccmd:getnp( ( sec_fam == "I6" ) and "U6" or "U4" ),
                    su_flags = su_flags,
                }
            end
        end
        strip_unverified_secondary( adccmd, userfam )
        user:inf( adccmd )
        if user:hasfeature "CCPM" then user:hasccpm( true ) end
        -- F-AUTH-NICK (#91): defer insertuser + onConnect when this BINF
        -- is a pending takeover. _usernicks[nick] still belongs to the
        -- existing user; clobbering it before HPAS would re-introduce
        -- the DoS we are fixing. The HPAS success handler completes the
        -- swap: kill the existing user, then insertuser + fire onConnect.
        if not user._takeover_target then
            insertuser( nick, cid, hash, user )
            if scripts_firelistener( "onConnect", user ) or user.waskilled then
                return true
            end
        end
        if profile then
            profile.lastconnect = profile.lastconnect or util_date()
            local lc = tostring( profile.lastconnect )
            if #lc ~= 14 then profile.lastconnect = util_date() end -- util.date() has allways 14 chars: yyyymmddhhmmss
            local sec, y, d, h, m, s = util_difftime( util_date(), profile.lastconnect )
            if ( ( profile.badpassword or 0 ) >= _cfg_max_bad_password ) and ( sec < _cfg_bad_pass_timeout ) then
                -- Seconds left on the lockout, floored to a whole number for the
                -- %d template. `sec` is an os.difftime float and bad_pass_timeout
                -- is only type-checked, so a fractional value must not reach %d
                -- (string.format "%d" errors on a non-integer) and crash the auth
                -- path. Clamp to >= 1 so a sub-second remainder (a fractional
                -- timeout, or clock skew) never renders "Try again in 0 seconds".
                local remaining = ( _cfg_bad_pass_timeout - sec ) // 1
                if remaining < 1 then remaining = 1 end
                user:kill( "ISTA 223 " .. utf_format( _i18n.max_bad_password, remaining ) .. "\n" )
                scripts_firelistener( "onFailedAuth", nick, userip, cid, escapefrom( utf_format( _i18n.max_bad_password, remaining ) ) )
                return true
            end
            user:salt( adclib_createsalt( GPA_SALT_CHARS ) )
            user.write( "IGPA " .. user.salt( ) .. "\n" )
            user:state "verify"
        else
            login( user, false )
        end
        return true
    end,
    -- Same rationale as the protocol-state HQUI handler: spec allows
    -- QUI in any state, clean-close instead of ISTA 125.
    HQUI = function( user, adccmd )
        user:client():close()
        return true
    end,

}

_verify = {

    HPAS = function( user, adccmd )
        local salt = user.salt( )
        local pass
        local regged = user.isregged( )
        local usercid = user.cid( )
        local userip = user.ip( ) or _i18n.unknown
        local userhash = adccmd[ 4 ]
        if regged then
            pass = user.password( )
        end
        local profile = user.profile( )
        local hubhash = adclib_hashpas( pass, salt )
        local hubhashold = adclib_hasholdpas( pass, salt, usercid )

        if ( userhash ~= hubhash ) and ( userhash ~= hubhashold ) then
            -- F-AUTH-FAIL (#94): on failed auth we MUST NOT update
            -- lastconnect / lastseen / is_online afterwards; the user
            -- never connected. The badpassword counter still has to
            -- persist, both for #91 takeover-defence book-keeping and
            -- for Phase 7c F-AUTH-3 per-account bad_pass_timeout.
            profile.badpassword = ( profile.badpassword or 0 ) + 1
            ratelimit_record_authfail( userip )
            cfg_saveusers( _regusers )
            user:kill( "ISTA 223 " .. _i18n.invalid_pass .. "\n", "TL-1" )
            scripts_firelistener( "onFailedAuth", profile.nick, userip, usercid, escapefrom( _i18n.invalid_pass ) )
            return true
        end

        -- F-AUTH-NICK (#91): if this BINF was deferred as a takeover
        -- pending HPAS, the new connection has now proven password
        -- ownership. Swap the slot: kill the existing user, claim
        -- _usernicks[nick] via insertuser, fire the deferred onConnect.
        if user._takeover_target then
            local target = user._takeover_target
            user._takeover_target = nil
            local nick = user:nick( )
            -- Race guard: another concurrent takeover may already have
            -- swapped the slot to a third connection. If so, our target
            -- is no longer the canonical owner; refuse this takeover.
            local current_owner = isuserconnected( nick )
            if current_owner and current_owner ~= target then
                user:kill( "ISTA 222 " .. _i18n.nick_taken .. "\n", "TL-1" )
                scripts_firelistener( "onFailedAuth", profile.nick, userip, usercid, escapefrom( _i18n.nick_taken ) )
                return true
            end
            if not target.waskilled then
                target:kill( "ISTA 222 " .. _i18n.nick_taken .. "\n", "TL-1" )
            end
            insertuser( nick, usercid, user.hash( ), user )
            if scripts_firelistener( "onConnect", user ) or user.waskilled then
                return true
            end
        end

        profile.badpassword = 0
        if not user:sup( ):hasparam( "ADOSNR" ) then
            user.write( utf_format( _hubinf_regonly, _cfg_hub_name, _cfg_hub_description ) )
        end
        login( user )
        profile.lastconnect = util_date( )
        profile.lastseen = util_date( )
        profile.is_online = 1
        cfg_saveusers( _regusers )
        return true
    end,
    -- Same rationale as the protocol-state / identify-state HQUI
    -- handlers above. Reaching verify means BINF was accepted but
    -- HPAS was either not sent or aborted; client-initiated QUI here
    -- means the password prompt was abandoned.
    HQUI = function( user, adccmd )
        user:client():close()
        return true
    end,

}

-- Phase 7c F-RL-1 / F-RL-2 helpers, plus the #80 PM/INF/CTM splits.
-- Token-bucket-protected entry points to the BMSG / EMSG / DMSG /
-- BINF / DCTM / DRCM / *SCH listeners. Returning `true` from the
-- handler tells incoming() the message has been handled (so the
-- broadcast / fan-out is suppressed) without disconnecting the user.
-- Op-level users (>= ratelimit_bypass_level) bypass the check inside
-- the ratelimit module.
--
-- IMPORTANT: a `true` return here also skips the plugin listener fan-
-- out (scripts_firelistener is not called). Throttled messages do not
-- reach onBroadcast / onPrivateMessage / onInf / onConnectToMe /
-- onRevConnectToMe listeners. Documented in docs/SECURITY.md "Rate-
-- limit and plugin contract" - plugins doing count-based heuristics
-- on per-user messages need to be aware that the hub-level drop hides
-- the post-burst tail from them.
local function rl_msg_drop( user )
    return not ratelimit_user_msg( user.cid( ), user.level( ) )
end
local function rl_pm_drop( user )
    return not ratelimit_user_pm( user.cid( ), user.level( ) )
end
local function rl_inf_drop( user )
    return not ratelimit_user_inf( user.cid( ), user.level( ) )
end
local function rl_ctm_drop( user )
    return not ratelimit_user_ctm( user.cid( ), user.level( ) )
end
local function rl_search_drop( user )
    return not ratelimit_user_search( user.cid( ), user.level( ) )
end

_normal = {
    -- ADC: 6.3.4. INF
    BINF = function( user, adccmd )
        if rl_inf_drop( user ) then return true end
        -- #286 post-login HBRI: detect a newly-advertised secondary family
        -- and solicit a side-channel BEFORE the onInf strip removes it.
        -- No-op unless HBRI is active and the client advertised ADHBRI; the
        -- unverified secondary is still stripped from this broadcast by
        -- hub_inf_manager (the #97/#222 invariant), and only re-added once
        -- the side-channel proves it (core/hbri.lua commit_and_complete).
        hbri.postlogin_inf( user, adccmd )
        return scripts_firelistener( "onInf", user, adccmd )
    end,
    -- ADC: 6.3.5. MSG
    BMSG = function( user, adccmd )
        if rl_msg_drop( user ) then return true end
        return scripts_firelistener( "onBroadcast", user, adccmd, escapefrom( adccmd[ 6 ] ) )
    end,
    --FMSG = function( user, adccmd )  -- cannot see a good scenario for FMSG; why should a user want to send mainchat messages to clients with specific features only?
    --    return scripts_firelistener( "onBroadcast", user, adccmd, escapefrom( adccmd[ 8 ] ) )
    --end,
    EMSG = function( user, adccmd, targetuser )
        if rl_pm_drop( user ) then return true end
        return scripts_firelistener( "onPrivateMessage", user, targetuser, adccmd, escapefrom( adccmd[ 8 ] ) )
    end,
    DMSG = function( user, adccmd, targetuser )
        if rl_pm_drop( user ) then return true end
        return scripts_firelistener( "onPrivateMessage", user, targetuser, adccmd, escapefrom( adccmd[ 8 ] ) )
    end,
    -- ADC: 6.3.8. CTM
    DCTM = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onConnectToMe", user, targetuser, adccmd )
    end,
    -- E-class CTM: modern DC++ uses ECTM in some peer-connection flows
    -- where the sender wants the hub-side echo back to itself in
    -- addition to the targeted client. Same handler / rate-limit as
    -- DCTM - the E-vs-D fan-out is handled in hub.lua's class router.
    ECTM = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onConnectToMe", user, targetuser, adccmd )
    end,
    -- ADC: 6.3.9. RCM
    DRCM = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onRevConnectToMe", user, targetuser, adccmd )
    end,
    -- E-class RCM, symmetric to ECTM above.
    ERCM = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onRevConnectToMe", user, targetuser, adccmd )
    end,
    -- ADC-EXT 3.9 NATT. Hub-relay-only NAT-traversal between two peers.
    -- DNAT is the initiator-to-target traversal request; DRNT is the
    -- target-to-initiator response. Hub does not advertise NATT in
    -- ISUP - the spec signals NATT support per-user via INF.SU, the
    -- hub is just a relay. Both gate through the same rate-limit
    -- bucket as DCTM/DRCM since they are semantically peer-connection
    -- setup.
    DNAT = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onNatTraversal", user, targetuser, adccmd )
    end,
    DRNT = function( user, adccmd, targetuser )
        if rl_ctm_drop( user ) then return true end
        return scripts_firelistener( "onNatTraversalReply", user, targetuser, adccmd )
    end,
    -- ADC: 6.3.6. SCH
    BSCH = function( user, adccmd )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
    end,
    FSCH = function( user, adccmd )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
     end,
    DSCH = function( user, adccmd, targetuser )
        if rl_search_drop( user ) then return true end
        return scripts_firelistener( "onSearch", user, adccmd )
    end,
    -- ADC: 6.3.7. RES (D-class single-recipient + F-class feature-
    -- filtered fan-out via #147 T1.6).
    DRES = function( user, adccmd, targetuser )
        return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    end,
    -- F-class search-result. Sent when the responder wants the result
    -- delivered to a set of clients matching feature flags rather
    -- than a single SID (e.g. delivering NMDC-bridged results only
    -- to ADC clients that support the bridge). The feature-fan-out
    -- itself happens in hub.lua's class router; the dispatcher just
    -- has to recognise the command. Fire the onSearchResult listener
    -- with nil targetuser so plugins can distinguish F-class
    -- (multi-target) from D-class (single-target) results.
    FRES = function( user, adccmd, _targetuser )
        -- F-class has no single targetuser by definition. Argument
        -- kept in signature for visual symmetry with DRES so the
        -- dispatcher table reads consistently top-to-bottom; the
        -- onSearchResult listener still receives nil here so plugins
        -- can branch on `if targetuser` to distinguish D-class from
        -- F-class results. **Plugin contract note:** returning a
        -- truthy value from an onSearchResult listener on a FRES path
        -- suppresses the ENTIRE feature-filtered fan-out, not just a
        -- single recipient as with DRES. See docs/SCRIPTS.md
        -- "Passthrough extensions" for the implications.
        return scripts_firelistener( "onSearchResult", user, nil, adccmd )
    end,
    --URES = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    --end,
    --CRES = function( user, adccmd, targetuser ) -- new
    --    return scripts_firelistener( "onSearchResult", user, targetuser, adccmd )
    --end,
    -- ADC 6.3.10 QUI (client-initiated). Spec lists QUI as permitted
    -- in any state and the hub's expected reaction is to close the
    -- connection. Before this handler the parser accepted HQUI but
    -- the dispatcher had no entry, so the hub answered ISTA 125
    -- (unknown command) instead of treating QUI as the polite
    -- goodbye it is.
    --
    -- We just close the client here. server.lua's read loop catches
    -- the resulting EOF and calls disconnect(), which broadcasts
    -- IQUI <sid> to the remaining users and fires onLogout via the
    -- normal cleanup path. T1.7 of #147.
    HQUI = function( user, adccmd )
        user:client():close()
        return true
    end,
    -- Phase 8 S5 BLOM: client uploads its per-user bloom filter in
    -- response to our HGET. Positional params are
    -- (type, identifier, start, bytes); the binary phase that
    -- follows on the wire is `bytes` bytes long and is captured by
    -- the iostream counted-binary stage installed below.
    --
    -- We only accept the BLOM-shaped HSND (type=blom, ident=/,
    -- start=0, bytes == m/8 where m is our cfg). Any other HSND is
    -- a protocol violation (we never initiate ZLIG file transfers
    -- on the hub side) and is dropped without a response.
    --
    -- Security: bytes is bounded by the cfg-validated _cfg_blom_m,
    -- so a malicious HSND cannot request the hub to allocate an
    -- arbitrarily large counted-buffer.
    HSND = function( user, adccmd )
        if not _cfg_blom_enabled then
            return true    -- never asked for it; drop silently
        end
        local typ   = adccmd:pos( 2 ) or ""
        local ident = adccmd:pos( 3 ) or ""
        local start = tonumber( adccmd:pos( 4 ) or "" )
        local bytes = tonumber( adccmd:pos( 5 ) or "" ) or 0
        if typ ~= "blom" or ident ~= "/" or start ~= 0 then
            return true    -- shape mismatch; not for us
        end
        if bytes ~= ( _cfg_blom_m // 8 ) then
            -- Client ignored our BK/BH params or is buggy. Discard;
            -- the user simply will not get filtered routing (the
            -- bloom hash-router falls back to broadcast for users
            -- without a filter).
            return true
        end
        local k, h, m = _cfg_blom_k, _cfg_blom_h, _cfg_blom_m
        -- Phase-9 follow-up (#192): splice counted BEFORE the
        -- terminal, not at the front. With ZLIF active the pipeline
        -- is [inflate, adcline]; counted must sit between them so
        -- it captures decompressed filter bytes, not raw deflated
        -- wire bytes. Without ZLIF the pipeline is [adcline] and
        -- insert_before_terminal degenerates to prepend.
        user:client().inframer_insert_before_terminal(
            iostream_newcountedstage( bytes, function( blob )
                local filter = bloom.newfilter( blob, k, h, m )
                user:setblom( filter )
                out_put( "hub_dispatch.lua: BLOM filter captured for user ", user.sid( ), " (", bytes, " bytes)" )
            end )
        )
        return true
    end,

}

states = function( user, adccmd, fourcc, state, targetuser )
    local ret
    if state == "normal" then
        ret = _normal[ fourcc ]
        if ret then
            return ret( user, adccmd, targetuser )  -- forward it with fireing script listeners
        end
        return false    --forward it later without fireing script listeners
    elseif state == "protocol" then
        ret = _protocol[ fourcc ]
    elseif state == "identify" then
        ret = _identify[ fourcc ]
    elseif state == "verify" then
        ret = _verify[ fourcc ]
    end
    if not ret then
        user.write( "ISTA 125 FC" .. fourcc .. "\n" )
    else
        ret( user, adccmd, targetuser )
    end
    return true
end


return {
    bind   = bind,
    states = states,
}
