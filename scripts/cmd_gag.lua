--[[

        cmd_gag.lua by motnahp

            - this script adds a command "gag" to mute, kennylize or shadowmute a user
            - usage: [+!#]gag mute|kennylize|shadowmute|ungag|show <NICK> [<DURATION>]

            v0.14:
                - carry a gag over to the new nick on +nickchange / HTTP
                  rename. gag_tbl records key on .user_nick (= firstnick);
                  a rename only updated user.tbl, so the mute was silently
                  lifted - same class Sopor reported for etc_trafficmanager.
                  An onAudit tap on reg.nickchange now re-keys the record
                  (covers the ADC self / othernick / othernicku paths AND
                  the HTTP API).

            v0.13:
                - resolve an online target by firstnick when a nick-prefix
                  is active. usr_nick_prefix re-keys the hub's nick table
                  to the PREFIXED nick, so `+gag ... <base nick>` and
                  `+gag ungag <base nick>` silently hit the "user offline"
                  path on a prefixed online user (no gag / no notify). The
                  gag store already keys by firstnick, so only resolution
                  was affected. Same firstnick-fallback idiom as
                  etc_trafficmanager (upstream luadch/luadch#240).

            v0.12:
                - the ADC `+gag mute|kennylize|shadowmute` path now
                  rejects a bot target (Hubbot / OpChat / RegChat) with
                  "User is a bot.", matching the guard the other user-
                  action commands already carry and the HTTP path's
                  util_http non-bot preflight (closes #355). ungag is
                  left unguarded so a stale gag set on a bot before this
                  fix can still be removed.

            v0.11:
                - route the inline duration unit labels "y "/"d "/"h "/"m "/"s"
                  through lang (msg_unit_*). Part of #301 i18n cleanup.

            v0.10: by Aybo
                - HTTP API endpoints (#82 Phase 2 PR-3):
                    POST   /v1/users/{sid}/gag    (body: mode, duration_minutes?)
                    DELETE /v1/users/{sid}/gag
                  Both via util_http.http_register_user_action; the
                  helper handles the preflight (online + non-bot) and
                  the §7.1.1 response envelope. The ADC `+gag` cmd is
                  unchanged. HTTP path is online-only; offline-
                  registered ungag stays ADC-only.
                - signature change: `add_user(target, mode, duration,
                  actor_nick)` and `remove_user(first_nick, display_nick,
                  online_obj, actor_nick)` now take `actor_nick` as a
                  string (was a user object). Both ADC call sites
                  pass `user:nick()` instead. The helper applies
                  `util.strip_control_bytes(actor_nick)` so an HTTP
                  caller's `req.token_label` (operator-controlled cfg
                  comment field) cannot smuggle `\r` / `\n` / NUL into
                  the opchat report frame or the persisted
                  `entry.added_by` value.
                - HTTP 409 E_CONFLICT on re-POST of an already-gagged
                  user (operator must DELETE first to change mode);
                  HTTP 404 E_NOT_FOUND on DELETE of a non-gagged user
                  (REST-orthodox over idempotent 200-no-op).

            v0.09: by Aybo
                - new shadowmute mode (closes luadch-ng/luadch-ng#85): the
                  sender sees their own messages echoed back, others see
                  nothing. The user does not know they are muted. Useful
                  against persistent spam bots.
                - optional duration argument for mute / kennylize /
                  shadowmute, e.g. "+gag mute Bob 1h30m". Tokens: s, m,
                  h, d, w. Empty / missing = permanent (existing
                  behaviour). Plain digits ("3600") parse as seconds.
                - expired entries auto-remove on the per-minute timer and
                  emit an opchat report. No target notification for
                  shadowmute (preserves the silent semantic) regardless
                  of user_notifiy.
                - ungag accepts offline registered users (not just
                  online targets) via hub.getregusers() lookup.
                - bug fix: gag_tbl was nil if util.loadtable returned
                  nil (no file / corrupt), crashing every onBroadcast
                  with "attempt to get length of nil value". Now
                  initialised to {} on load.
                - bug fix: silent no-op on incomplete commands like
                  "+gag mute" without target - now replies with
                  msg_usage.
                - bug fix: permission[user:level()] could be nil for
                  unconfigured caller levels, crashing the
                  target:level() > nil comparison. Now defensively 0.
                - bug fix: kennylize byte-iterated message via
                  string.gmatch(msg, ".") and dropped non-ASCII
                  characters entirely (Umlauts, Cyrillic, etc.).
                  utf.gmatch / utf8 iteration now passes non-Latin
                  codepoints through unchanged.
                - code style: tabs/8-space mix in add_user / remove_user
                  replaced with 4-space indent (rest of the file).
                - schema additions, all optional / backwards-compatible:
                    expires_at = nil | os.time() + secs
                    added_by   = nick of operator
                    added_at   = os.time()
                  Old entries without these fields stay valid (treated
                  as permanent / unknown).

            v0.08: by pulsar
                - changed visuals
                - removed table lookups

            v0.07: by pulsar
                - added "user_notifiy" to choose if the target gets informed about his gag/ungag or not  / request by Sopor

            v0.06: by pulsar
                - removed send_report() function, using report import functionality now
                - fix command declaration in messages

            v0.05: by pulsar
                - removed "cmd_gag_minlevel" import
                    - using util.getlowestlevel( tbl ) instead of "cmd_gag_minlevel"

            v0.04: by pulsar
                - check if opchat is activated

            v0.03: by pulsar
                - added some new table lookups
                - added possibility to send report as feed to opchat

            v0.02: by Motnahp
                - small fix in "onBroadcast" listener

]]--


--// settings begin //--

local scriptname = "cmd_gag"
local scriptversion = "0.14"

local cmd = "gag"
local prm_mute = "mute"
local prm_kennylize = "kennylize"
local prm_shadowmute = "shadowmute"
local prm_show = "show"
local prm_ungag = "ungag"

--// imports
local hubcmd, help, ucmd
local scriptlang = cfg.get("language")
local lang, err = cfg.loadlanguage(scriptlang, scriptname); lang = lang or {}; err = err and hub.debug(err)
local permission = cfg.get("cmd_gag_permission")
local hub_bot_nick = cfg.get("hub_bot")
local op_chat_nick = cfg.get("bot_opchat_nick")
local reg_chat_nick = cfg.get("bot_regchat_nick")
local op_chat_permission = cfg.get("bot_opchat_permission")
local reg_chat_permission = cfg.get("bot_regchat_permission")
local user_notifiy = cfg.get("cmd_gag_user_notifiy")
local report = hub.import("etc_report")
local report_activate = cfg.get("cmd_gag_report")
local llevel = cfg.get("cmd_gag_llevel")
local report_hubbot = cfg.get("cmd_gag_report_hubbot")
local report_opchat = cfg.get("cmd_gag_report_opchat")

local char_tbl = {

    a = "*abfl* ", b = "*Bumf* ", c = "*Coh* ", d = "*umfl* ", e = "*uff* ", f = "*offl* ", g = "*omhg* ",
    h = "*umulum* ", i = "*mm* ", j = "*luh* ", k = "*lumf* ", l = "*egll* ", m = "*umlum* ", n = "*uuuh* ",
    o = "*pfffl* ", p = "*mflo* ", q = "*ugugu* ", r = "*olol* ", s = "*uhgg* ", t = "*blll* ", u = "*aggah* ",
    v = "*hugh* ", w = "*ahll* ", x = "*tuguh* ", y = "*uumh* ", z = "*omph* ",

    A = "*abfl* ", B = "*Bumf* ", C = "*Coh* ", D = "*umfl* ", E = "*uff* ", F = "*offl* ", G = "*omhg* ",
    H = "*umulum* ", I = "*mm* ", J = "*luh* ", K = "*lumf* ", L = "*egll* ", M = "*umlum* ", N = "*uuuh* ",
    O = "*pfffl* ", P = "*mflo* ", Q = "*ugugu* ", R = "*olol* ", S = "*uhgg* ", T = "*blll* ", U = "*aggah* ",
    V = "*hugh* ", W = "*ahll* ", X = "*tuguh* ", Y = "*uumh* ", Z = "*omph* ",

}
--// settings end //--

--// database
--
-- gag_tbl is an array of records:
--   { user_nick = "Bob", mode = "mute"|"kennylize"|"shadowmute",
--     expires_at = nil | epoch_secs, added_by = nick, added_at = epoch_secs }
-- expires_at / added_by / added_at are optional (added in v0.09); pre-v0.09
-- entries lack them and are treated as permanent / unknown.
local gag_path = "scripts/data/cmd_gag.tbl"
local gag_tbl = util.loadtable(gag_path) or {}   -- v0.09 fix: nil-safe

--// msgs
local msg_denied = lang.msg_denied or "You are not allowed to use this command."
local msg_usage = lang.msg_usage or "usage: [+!#]gag mute|kennylize|shadowmute|ungag|show <NICK> [<DURATION>]"
local msg_off = lang.msg_off or "User not found/regged."
local msg_god = lang.msg_god or "You cannot touch gods."
local msg_invalid_duration = lang.msg_invalid_duration or "Invalid duration. Use e.g. 30s / 10m / 2h / 1d / 1w (combinable: 1h30m). Empty = permanent."

local msg_show_users = lang.msg_show_users or [[

=== GAG =========================

Muted users: (%s)
%s

Kennylized users: (%s)
%s

Shadowmuted users: (%s)
%s

========================= GAG ===
  ]]

local msg_add_user = lang.msg_add_user or "[ GAG ]--> User:  %s  was gagged with mode: %s  |  by:  %s"
local msg_add_user_with_duration = lang.msg_add_user_with_duration or "[ GAG ]--> User:  %s  was gagged with mode: %s  for  %s  |  by:  %s"
local msg_remove_user = lang.msg_remove_user or "[ GAG ]--> User:  %s  was ungagged by:  %s"
local msg_expired = lang.msg_expired or "[ GAG ]--> User:  %s  restriction (%s) auto-expired."
local msg_error_in = lang.msg_error_in or "User already gagged, remove his restrictions before adding another one."
local msg_error_out = lang.msg_error_out or "User:  %s  has no restriction set."
local msg_isbot = lang.msg_isbot or "User is a bot."
local msg_user_restriction_added = lang.msg_user_restriction_added or "You were gagged with mode: %s"
local msg_user_restriction_removed = lang.msg_user_restriction_removed or "Your chat restrictions were removed."

-- #301 PR-3: duration unit labels - routed through lang so a future
-- translation can render them as "j t st m s" etc. without source edit.
local msg_unit_year   = lang.msg_unit_year   or "y "
local msg_unit_day    = lang.msg_unit_day    or "d "
local msg_unit_hour   = lang.msg_unit_hour   or "h "
local msg_unit_minute = lang.msg_unit_minute or "m "
local msg_unit_second = lang.msg_unit_second or "s"

local help_title = lang.help_title or "gag"
local help_usage = lang.help_usage or "[+!#]gag mute|kennylize|shadowmute|ungag|show <NICK> [<DURATION>]"
local help_desc = lang.help_desc or "mute, kennylize, shadowmute or ungag a user (with optional duration); or show restricted users"

local ucmd_nick = lang.ucmd_nick or "Nick:"
local ucmd_duration = lang.ucmd_duration or "Duration (e.g. 1h30m, empty = permanent):"

local ucmd_menu_ct0 = lang.ucmd_menu_ct0 or { "Gag", "Mute User" }
local ucmd_menu_ct1 = lang.ucmd_menu_ct1 or { "Gag", "Kennylize User" }
local ucmd_menu_ct1b = lang.ucmd_menu_ct1b or { "Gag", "Shadowmute User" }
local ucmd_menu_ct2 = lang.ucmd_menu_ct2 or { "User", "Control", "Gag", "show Users" }
local ucmd_menu_ct3 = lang.ucmd_menu_ct3 or { "User", "Control", "Gag", "ungag User by nick" }
local ucmd_menu_ct4 = lang.ucmd_menu_ct4 or { "Gag", "Ungag User" }

--// functions
local show_users
local add_user
local remove_user
local check_user_input
local save
local replace_chars
local parse_duration
local find_entry
local find_online_by_firstnick
local resolve_target_for_ungag
local cleanup_expired
local http_handler_gag
local http_handler_ungag


local minlevel = util.getlowestlevel(permission)

-- Upper bound on parsed durations. Anything beyond 10 years is
-- treated as a typo (a serious operator wanting "forever" leaves
-- the field empty, which is the canonical permanent path). Without
-- the cap, a typo like "99999999999d" wraps the Lua 5.4 integer
-- after * 86400, expires_at lands in the past, and the gag is
-- instantly auto-expired - worst possible UX outcome (operator
-- thinks they gagged, target is free immediately).
local MAX_DURATION = 10 * 365 * 86400

-- Parse "1h30m" / "45s" / "2d" / "1w" / "3600" / "" into seconds.
-- Returns nil for "" (= permanent), seconds (number) on success,
-- false on parse error (incl. negative / overflow / exceeds cap).
parse_duration = function(s)
    if not s or s == "" then return nil end
    -- plain digits => seconds shorthand
    local plain = tonumber(s)
    if plain then
        if plain < 0 or plain > MAX_DURATION then return false end
        return plain
    end
    local total = 0
    local matched_any = false
    local consumed = 0
    -- iterate over a renamed capture + fresh local rather than reassigning
    -- the loop variable: Lua 5.5 makes generic-for control variables const,
    -- so `n = tonumber(n)` would be a compile error there (the hub runs
    -- 5.4.8, but the Windows CI's msys2 lua tracks 5.5).
    for ns, unit in s:gmatch("(%d+)([smhdw])") do
        local n = tonumber(ns)
        if unit == "s" then total = total + n
        elseif unit == "m" then total = total + n * 60
        elseif unit == "h" then total = total + n * 3600
        elseif unit == "d" then total = total + n * 86400
        elseif unit == "w" then total = total + n * 604800
        end
        matched_any = true
        consumed = consumed + #tostring(n) + 1
        -- Bail out early if the running total has overflowed past
        -- the cap. Avoids edge cases where the multiplications above
        -- wrap before this check would catch them.
        if total < 0 or total > MAX_DURATION then return false end
    end
    if not matched_any or consumed ~= #s then return false end
    return total
end

-- Find a gag entry by firstnick. Returns (index, entry) or (nil, nil).
find_entry = function(nick)
    for i, e in ipairs(gag_tbl) do
        if e.user_nick == nick then return i, e end
    end
    return nil, nil
end

-- Resolve an online user by their firstnick when the plain nick lookup
-- misses. usr_nick_prefix re-keys the hub's _usernicks table to the
-- PREFIXED display nick (via user:updatenick), so hub.isnickonline(<base
-- nick>) returns nil for a prefixed online user and the gag/ungag paths
-- would silently take the "user offline" branch. firstnick is the
-- ORIGINAL nick, captured once at login and never re-keyed, so iterating
-- it is robust against ANY nick-prefix scheme (the gag store already
-- keys by firstnick). Same idiom as etc_trafficmanager's
-- find_online_by_firstnick (closed upstream luadch/luadch#240). Kept
-- plugin-local rather than changed in core hub.isnickonline, whose
-- exact-current-nick semantics back availability checks elsewhere.
-- firstnick fallback -> the shared core helper (#537 dedup).
find_online_by_firstnick = hub.find_online_by_firstnick

-- Resolve target for ungag: accept online users OR offline registered
-- users (looked up via hub.getregusers). Returns:
--   firstnick, display_nick, level, online_user_obj_or_nil
-- or nil if neither online nor registered.
resolve_target_for_ungag = function(nick_arg)
    local online = hub.isnickonline(nick_arg) or find_online_by_firstnick(nick_arg)
    if online then
        return online:firstnick(), online:nick(), online:level(), online
    end
    -- offline: look up by firstnick in regusers
    local regusers = hub.getregusers()
    for i, u in ipairs(regusers) do
        if u.nick == nick_arg then
            return u.nick, u.nick, u.level, nil
        end
    end
    return nil
end


local onbmsg = function(user, command, parameters)
    local level = user:level()
    if level < minlevel then
        user:reply(msg_denied, hub.getbot())
        return PROCESSED
    end

    -- Parse: <action> [<target>] [<duration>]
    -- We deliberately accept trailing whitespace-separated tokens.
    local action, rest = utf.match(parameters, "^(%S+)%s*(.*)$")
    if not action then
        user:reply(msg_usage, hub.getbot())
        return PROCESSED
    end

    -- show: no target, no duration
    if action == prm_show then
        user:reply(show_users(), hub.getbot())
        return PROCESSED
    end

    -- All other actions need a target.
    local target_arg, duration_arg = utf.match(rest, "^(%S+)%s*(%S*)$")
    if not target_arg or target_arg == "" then
        user:reply(msg_usage, hub.getbot())
        return PROCESSED
    end

    if action == prm_ungag then
        local first_nick, display_nick, target_level, online_obj =
            resolve_target_for_ungag(target_arg)
        if not first_nick then
            user:reply(msg_off, hub.getbot())
            return PROCESSED
        end
        local max_target_level = permission[user:level()] or 0   -- v0.09 fix: nil-safe
        if target_level > max_target_level then
            user:reply(msg_god, hub.getbot())
            return PROCESSED
        end
        user:reply(remove_user(first_nick, display_nick, online_obj, user:nick()), hub.getbot())
        audit.fire(audit.build("gag.remove", user, { nick = first_nick }, nil, nil))
        return PROCESSED
    end

    if action ~= prm_mute and action ~= prm_kennylize and action ~= prm_shadowmute then
        user:reply(msg_usage, hub.getbot())
        return PROCESSED
    end

    -- mute / kennylize / shadowmute require online target.
    local target = hub.isnickonline(target_arg) or find_online_by_firstnick(target_arg)
    if not target then
        user:reply(msg_off, hub.getbot())
        return PROCESSED
    end
    -- Never gag a bot (Hubbot / OpChat / RegChat). Mirrors the bot-target
    -- guard the other user-action commands carry (cmd_redirect's msg_isbot,
    -- cmd_disconnect's msg_bot, ...) and the HTTP path's util_http non-bot
    -- preflight (#355). ungag is deliberately NOT guarded so a stale gag
    -- set on a bot before this fix can still be removed.
    if target:isbot() then
        user:reply(msg_isbot, hub.getbot())
        return PROCESSED
    end
    local max_target_level = permission[user:level()] or 0   -- v0.09 fix: nil-safe
    if target:level() > max_target_level then
        user:reply(msg_god, hub.getbot())
        return PROCESSED
    end
    if target:firstnick() == user:firstnick() then
        user:reply(msg_god, hub.getbot())
        return PROCESSED
    end

    -- Parse optional duration. parse_duration returns nil = permanent,
    -- number = seconds, false = invalid syntax.
    local duration = parse_duration(duration_arg)
    if duration == false then
        user:reply(msg_invalid_duration, hub.getbot())
        return PROCESSED
    end

    user:reply(add_user(target, action, duration, user:nick()), hub.getbot())
    audit.fire(audit.build("gag.add", user, target, nil,
        { mode = action, duration_sec = duration }))
    return PROCESSED
end

hub.setlistener("onBroadcast", {},
    function(user, adccmd, msg)
        if #gag_tbl == 0 then return end
        local mode, answer = check_user_input(user, msg)
        if mode == "kennylize" then
            adccmd[6] = hub.escapeto(answer)
        elseif mode == "mute" then
            return PROCESSED
        elseif mode == "shadowmute" then
            -- Echo the user's own message back only to them as a BMSG
            -- with themselves as the sender (user:reply(msg, user)
            -- writes "BMSG <user.sid> msg" via the 2-arg path in
            -- hub_user_object.reply). It appears in their main chat
            -- as if the broadcast succeeded; everybody else gets
            -- nothing because we PROCESSED-swallow the original BMSG.
            user:reply(msg, user)
            return PROCESSED
        end
    end
)

hub.setlistener("onPrivateMessage", {},
    function(user, targetuser, adccmd, msg)
        if #gag_tbl == 0 then return end
        local mode, answer = check_user_input(user, msg)
        if mode == "kennylize" then
            local targetuser_nick = targetuser:firstnick()
            if targetuser:isbot() and not (targetuser_nick == hub_bot_nick) then
                local chan_permission
                local send = false
                if targetuser_nick == op_chat_nick then
                    chan_permission = op_chat_permission
                    send = true
                elseif targetuser_nick == reg_chat_nick then
                    chan_permission = reg_chat_permission
                    send = true
                end
                if send and chan_permission[user:level()] then
                    for sid, tuser in pairs(hub.getusers()) do
                        if send and chan_permission[tuser:level()] then
                            tuser:reply(answer, user, targetuser)
                        end
                    end
                end
                return PROCESSED
            else
                user:reply(answer, user, targetuser)
                targetuser:reply(answer, user, user)
                return PROCESSED
            end
        elseif mode == "mute" then
            return PROCESSED
        elseif mode == "shadowmute" then
            -- Echo own PM back to the sender only. Target sees nothing.
            user:reply(msg, user, targetuser)
            return PROCESSED
        end
    end
)

hub.setlistener("onTimer", {},
    function()
        cleanup_expired()
        return nil
    end
)

--// keep a chat gag attached to its user across a nick rename. gag_tbl
-- records key on .user_nick (= firstnick); +nickchange (and the HTTP
-- rename) renames the user in user.tbl but not here, so without this a
-- rename silently lifted the mute (same class Sopor reported for
-- etc_trafficmanager). audit.fire is unconditional (core/audit.lua), so
-- one onAudit tap catches every reg.nickchange. Returns nil (never
-- PROCESSED) so the etc_auditlog / http_events taps still receive it.
hub.setlistener("onAudit", {},
    function(event)
        if type(event) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type(old_nick) ~= "string" or type(new_nick) ~= "string" or old_nick == new_nick then return nil end
        local _, entry = find_entry(old_nick)
        if not entry then return nil end
        entry.user_nick = new_nick
        -- drop any stale record already under the new nick so the list
        -- keeps one entry - the renamed user's own gag wins.
        for i = #gag_tbl, 1, -1 do
            if gag_tbl[i] ~= entry and gag_tbl[i].user_nick == new_nick then
                table.remove(gag_tbl, i)
            end
        end
        util.savearray(gag_tbl, gag_path)
        return nil
    end
)

hub.setlistener("onStart", {},
    function()
        help = hub.import("cmd_help")
        if help then
            help.reg(help_title, help_usage, help_desc, minlevel)
        end
        ucmd = hub.import("etc_usercommands")
        if ucmd then
            -- mute / kennylize / shadowmute all take an optional duration.
            ucmd.add(ucmd_menu_ct0,  cmd, { prm_mute,        "%[userNI]", "%[line:" .. ucmd_duration .. "]" }, { "CT2" }, minlevel)   -- mute
            ucmd.add(ucmd_menu_ct1,  cmd, { prm_kennylize,   "%[userNI]", "%[line:" .. ucmd_duration .. "]" }, { "CT2" }, minlevel)   -- kennylize
            ucmd.add(ucmd_menu_ct1b, cmd, { prm_shadowmute,  "%[userNI]", "%[line:" .. ucmd_duration .. "]" }, { "CT2" }, minlevel)   -- shadowmute
            ucmd.add(ucmd_menu_ct2,  cmd, { prm_show },                                                       { "CT1" }, minlevel)   -- show
            ucmd.add(ucmd_menu_ct3,  cmd, { prm_ungag, "%[line:" .. ucmd_nick .. "]" },                        { "CT1" }, minlevel)   -- ungag-by-nick
            ucmd.add(ucmd_menu_ct4,  cmd, { prm_ungag, "%[userNI]" },                                          { "CT2" }, minlevel)   -- ungag-from-list
        end
        hubcmd = hub.import("etc_hubcommands")
        assert(hubcmd)
        assert(hubcmd.add(cmd, onbmsg, minlevel))
        -- HTTP API endpoints (#82 Phase 2 PR-3). The util_http
        -- helper handles the standard SID-online-non-bot preflight,
        -- the §7.1.1 response envelope, and the audit log. This
        -- plugin only owns the handler bodies above. The HTTP path
        -- is online-only by design - offline registered ungag is
        -- ADC-only via `+gag ungag` (the helper rejects offline
        -- SIDs with 404 before the handler is reached).
        --
        -- MAX_DURATION_MINUTES caps duration_minutes at ~10 years,
        -- matching the Lua-side MAX_DURATION cap on parse_duration.
        -- Beyond this the schema validator rejects with 400 before
        -- any state mutation.
        local MAX_DURATION_MINUTES = 10 * 365 * 24 * 60
        util_http.http_register_user_action(scriptname,
            "POST", "/v1/users/{sid}/gag", "gag",
            http_handler_gag, {
                description = "gag (silence) an online user by SID; body { mode: \"mute\"|\"kennylize\"|\"shadowmute\" required, duration_minutes: integer optional (omitted = permanent) }",
                request_schema = {
                    mode = { type = "string", required = true,
                             enum = { prm_mute, prm_kennylize, prm_shadowmute } },
                    duration_minutes = { type = "integer",
                                         min = 1, max = MAX_DURATION_MINUTES },
                },
            }
        )
        util_http.http_register_user_action(scriptname,
            "DELETE", "/v1/users/{sid}/gag", "ungag",
            http_handler_ungag, {
                description = "remove an existing gag from an online user by SID",
            }
        )
        return nil
    end
)


-- functions --
show_users = function()
    local lists = { mute = "", kennylize = "", shadowmute = "" }
    local counts = { mute = 0, kennylize = 0, shadowmute = 0 }
    local now = os.time()
    for i, tbl in ipairs(gag_tbl) do
        local mode = tbl.mode
        if lists[mode] then
            counts[mode] = counts[mode] + 1
            local nick_line = "\n\t" .. (tbl.user_nick or " ")
            if tbl.expires_at then
                local remaining = tbl.expires_at - now
                if remaining > 0 then
                    local y, d, h, m, s = util.formatseconds(remaining)
                    nick_line = nick_line .. " (expires in " .. y .. msg_unit_year .. d .. msg_unit_day .. h .. msg_unit_hour .. m .. msg_unit_minute .. s .. msg_unit_second .. ")"
                end
            end
            lists[mode] = lists[mode] .. nick_line
        end
    end
    return utf.format(msg_show_users,
        counts.mute, lists.mute,
        counts.kennylize, lists.kennylize,
        counts.shadowmute, lists.shadowmute)
end

-- v0.10 (#82 Phase 2 PR-3): `user` arg replaced by `actor_nick`
-- string so both the ADC `+gag` path (passing user:nick()) and the
-- HTTP `POST /v1/users/{sid}/gag` path (passing
-- util.strip_control_bytes(req.token_label)) can share the helper.
-- The actor_nick is also control-byte sanitised here as
-- defence-in-depth around adclib::escape - the ADC side's
-- user:nick() is already login-validated but the HTTP side
-- inherits whatever the operator put in cfg.http_api_tokens[].comment.
add_user = function(target, mode, duration, actor_nick)
    local nick = target:firstnick()
    if find_entry(nick) then
        return utf.format(msg_error_in, nick)
    end
    local clean_actor = util.strip_control_bytes(actor_nick)
    local entry = {
        user_nick = nick,
        mode = mode,
        added_by = clean_actor,
        added_at = os.time(),
    }
    if duration then
        entry.expires_at = os.time() + duration
    end
    gag_tbl[#gag_tbl + 1] = entry
    save()
    -- Notify target. Shadowmute MUST NOT notify the target (the whole
    -- point is the user does not know). For mute / kennylize honour
    -- the existing user_notifiy cfg.
    if mode ~= prm_shadowmute and user_notifiy then
        target:reply(utf.format(msg_user_restriction_added, mode), hub.getbot(), hub.getbot())
    end
    local report_msg
    if duration then
        local y, d, h, m, s = util.formatseconds(duration)
        report_msg = utf.format(msg_add_user_with_duration, target:nick(), mode,
            y .. msg_unit_year .. d .. msg_unit_day .. h .. msg_unit_hour .. m .. msg_unit_minute .. s .. msg_unit_second,
            clean_actor)
    else
        report_msg = utf.format(msg_add_user, target:nick(), mode, clean_actor)
    end
    report.send(report_activate, report_hubbot, report_opchat, llevel, report_msg)
    return report_msg
end

-- target_firstnick is the canonical lookup key. display_nick is for
-- the report. online_obj is the user object if currently online, used
-- to send the target notification. actor_nick (v0.10) is the
-- operator/token name for the opchat report; sanitised here.
remove_user = function(target_firstnick, display_nick, online_obj, actor_nick)
    local idx, entry = find_entry(target_firstnick)
    if not idx then
        return utf.format(msg_error_out, display_nick)
    end
    local mode = entry.mode
    table.remove(gag_tbl, idx)
    save()
    -- Notify target if online + not shadowmute (preserves silent
    -- semantic) + user_notifiy enabled.
    if online_obj and mode ~= prm_shadowmute and user_notifiy then
        online_obj:reply(msg_user_restriction_removed, hub.getbot(), hub.getbot())
    end
    local clean_actor = util.strip_control_bytes(actor_nick)
    local report_msg = utf.format(msg_remove_user, display_nick, clean_actor)
    report.send(report_activate, report_hubbot, report_opchat, llevel, report_msg)
    return report_msg
end

-- HTTP handler body: POST /v1/users/{sid}/gag (#82 Phase 2 PR-3).
-- Preflight + envelope owned by util_http.http_register_user_action;
-- this handler resolves the mode + duration, calls add_user (which
-- fires the opchat report internally), and returns the
-- action-specific fields for the §7.1.1 envelope.
--
-- Body schema:
--   mode              required string enum {mute, kennylize, shadowmute}
--   duration_minutes  optional integer 1..5256000 (~10 years cap)
--                     missing/omitted -> permanent gag (no expires_at)
--
-- Errors:
--   409 E_CONFLICT  - user is already gagged (matches ADC msg_error_in;
--                     operator must DELETE first to change mode).
-- Schema rejects (mode missing / wrong enum / duration out of range)
-- land as 400 E_BAD_INPUT via the router BEFORE this handler runs.
--
-- The util_http helper rejects offline / bot SIDs with 404 / 409
-- before this handler is called; the HTTP path is online-only by
-- design (use the ADC `+gag` cmd for offline registered targets).
http_handler_gag = function(req, target)
    local mode = req.body and req.body.mode
    if find_entry(target:firstnick()) then
        return nil, { status = 409, error = { code = "E_CONFLICT",
            message = "user is already gagged; ungag first to change mode" } }
    end
    local duration_minutes = req.body and req.body.duration_minutes
    local duration_seconds = duration_minutes and ( duration_minutes * 60 ) or nil
    local actor_label = req.token_label or "http-api"
    -- add_user fires report.send + persists gag_tbl internally; we
    -- only need the side-effect, not the returned report-message
    -- string (the HTTP audit log already covers the operator trail).
    add_user(target, mode, duration_seconds, actor_label)
    audit.fire(audit.build("gag.add",
        { nick = actor_label, sid = "<http>" }, target, nil,
        { mode = mode, duration_sec = duration_seconds }))
    local data = { mode = mode }
    if duration_seconds then
        data.duration_minutes = duration_minutes
        data.expires_at = os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() + duration_seconds)
    end
    return data
end

-- HTTP handler body: DELETE /v1/users/{sid}/gag (#82 Phase 2 PR-3).
-- Errors:
--   404 E_NOT_FOUND - user is not currently gagged. This is the
--   strict "REST-orthodox" choice over the idempotent 200-no-op
--   alternative: an admin tool benefits from knowing whether their
--   DELETE actually changed state. ADC `+gag ungag` returns a
--   verbose "user has no restriction set" message which is the same
--   intent (informs the operator their action was a no-op).
http_handler_ungag = function(req, target)
    local first_nick = target:firstnick()
    local _idx, entry = find_entry(first_nick)
    if not entry then
        return nil, { status = 404, error = { code = "E_NOT_FOUND",
            message = "user is not currently gagged" } }
    end
    local previous_mode = entry.mode
    local actor_label = req.token_label or "http-api"
    remove_user(first_nick, target:nick(), target, actor_label)
    audit.fire(audit.build("gag.remove",
        { nick = actor_label, sid = "<http>" }, target, nil,
        { previous_mode = previous_mode }))
    return { previous_mode = previous_mode }
end

check_user_input = function(target, msg)
    local nick = target:firstnick()
    local idx, entry = find_entry(nick)
    if not entry then return nil end
    if entry.mode == "mute" or entry.mode == "shadowmute" then
        return entry.mode, msg
    end
    if entry.mode == "kennylize" then
        return entry.mode, replace_chars(msg)
    end
    return nil
end

save = function()
    util.savearray(gag_tbl, gag_path)
    hub.debug("saved gag tbl")
end

-- Codepoint-aware character replacement. v0.09 fix: pre-fix used
-- string.gmatch(msg, ".") which iterates bytes - any non-ASCII
-- codepoint (Umlauts, Cyrillic, ...) is at least 2 bytes in UTF-8
-- with bytes outside [A-Za-z], so non-Latin characters were
-- silently dropped. Now we walk by UTF-8 codepoint: ASCII letters
-- get kennylized, everything else (digits, punctuation, non-Latin
-- letters) passes through unchanged.
replace_chars = function(msg)
    local output = {}
    -- utf.gmatch iterates by codepoint (one UTF-8 sequence per step).
    -- Fall back to string.gmatch with "[%z\1-\127\194-\244][\128-\191]*"
    -- if utf.gmatch is not available - covers all valid UTF-8 sequences.
    local iter
    if utf.gmatch then
        iter = utf.gmatch(msg, ".")
    else
        iter = string.gmatch(msg, "[%z\1-\127\194-\244][\128-\191]*")
    end
    for c in iter do
        if char_tbl[c] then
            output[#output + 1] = char_tbl[c]
        else
            output[#output + 1] = c
        end
    end
    return table.concat(output)
end

-- Walk gag_tbl, remove entries whose expires_at is past, emit an
-- opchat report per expiry. Throttled to once per minute so onTimer
-- (which fires every second) does not save_array on every tick.
local _last_cleanup = os.time()
local _cleanup_interval = 60
cleanup_expired = function()
    if os.time() - _last_cleanup < _cleanup_interval then return end
    _last_cleanup = os.time()
    if #gag_tbl == 0 then return end
    local now = os.time()
    local changed = false
    local i = 1
    while i <= #gag_tbl do
        local entry = gag_tbl[i]
        if entry.expires_at and entry.expires_at <= now then
            table.remove(gag_tbl, i)
            changed = true
            local report_msg = utf.format(msg_expired, entry.user_nick, entry.mode)
            report.send(report_activate, report_hubbot, report_opchat, llevel, report_msg)
            -- No target notification on expiry. Shadowmute MUST stay
            -- silent; for mute/kennylize the operator already gets the
            -- opchat report and the user discovering the lift by sending
            -- a successful message is fine UX.
        else
            i = i + 1
        end
    end
    if changed then save() end
end

hub.debug("** Loaded " .. scriptname .. " " .. scriptversion .. " **")


-- exposed for the unit tests (#355 bot-guard regression + nick-prefix
-- resolution regression)
return {
    _onbmsg                   = onbmsg,
    _gag_tbl                  = gag_tbl,
    _find_online_by_firstnick = find_online_by_firstnick,
}
