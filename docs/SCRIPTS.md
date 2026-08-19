# Bundled scripts

This document lists every plugin shipped with luadch under
[`scripts/`](../scripts/), with a one-line description, the operator
commands it registers, and the cfg keys it reads. It is the operator-
facing reference for "what's running on my hub and how do I tune it".

Each plugin's full docstring + version history lives in the file header
itself. The cfg keys listed here are documented in
[`core/cfg_defaults.lua`](../core/cfg_defaults.lua) (defaults + inline
explanation) and editable in `cfg/cfg.tbl`.

The rate-limit section at the end is the most invasive operator-facing
knob the hub exposes - dedicated section because it has more moving
parts than a single cfg key.

---

## Index

Jump-links to every entry below, grouped by category. Purposes are the
one-line summary from each entry; see the entry for commands and cfg keys.

### 🤖 Bot plugins

| Plugin | Purpose |
|---|---|
| [bot_opchat](#bot_opchat) | Internal op-chat bot for operator coordination |
| [bot_pm2ops](#bot_pm2ops) | Routes operator private messages to the opchat bot |
| [bot_regchat](#bot_regchat) | Registered-user chat with optional message history |
| [bot_session_chat](#bot_session_chat) | Temporary per-session chats for user collaboration |

### ⌨️ Command plugins

| Plugin | Purpose |
|---|---|
| [cmd_accinfo](#cmd_accinfo) | Display extended account details for registered users |
| [cmd_ban](#cmd_ban) | Ban / unban users by nick, CID, or IP with optional duration and reason |
| [cmd_botflag](#cmd_botflag) | Toggle the bot icon (ADC CT bot bit) on a registered account, no privilege change |
| [cmd_delreg](#cmd_delreg) | Delete registrations by nick |
| [cmd_disconnect](#cmd_disconnect) | Forcefully disconnect a user with optional reason message |
| [cmd_errors](#cmd_errors) | Display the hub error log to users with sufficient permissions |
| [cmd_gag](#cmd_gag) | Mute, kennylize (garble), or shadowmute users with optional duration |
| [cmd_help](#cmd_help) | Central help registry for all operator commands |
| [cmd_hubinfo](#cmd_hubinfo) | Display comprehensive hub information |
| [cmd_hubstats](#cmd_hubstats) | Track hub statistics over time (user averages, share, registrations, bans) |
| [cmd_mass](#cmd_mass) | Broadcast mass messages to all users or specific user levels |
| [cmd_myinf](#cmd_myinf) | Display own or target user's raw INF command output (client information) |
| [cmd_myip](#cmd_myip) | Display own or target user's IP address |
| [cmd_nickchange](#cmd_nickchange) | Change registered user nicknames |
| [cmd_redirect](#cmd_redirect) | Redirect users to an alternate hub URL based on level or manual command |
| [cmd_reg](#cmd_reg) | Register new users or add / modify registration descriptions |
| [cmd_reload](#cmd_reload) | Reload hub configuration, user database, and restart scripts without full hub restart |
| [cmd_restart](#cmd_restart) | Gracefully restart the hub with optional broadcast message to users |
| [cmd_rules](#cmd_rules) | Display hub rules to users (sent at login or on command) |
| [cmd_setpass](#cmd_setpass) | Set or change passwords for registered users |
| [cmd_shutdown](#cmd_shutdown) | Gracefully shut down the hub with optional broadcast message |
| [cmd_slots](#cmd_slots) | Display list of all currently connected users with available upload slots |
| [cmd_sslinfo](#cmd_sslinfo) | Display TLS / SSL connection information for user's client |
| [cmd_talk](#cmd_talk) | Broadcast messages anonymously without nickname prefix |
| [cmd_topic](#cmd_topic) | Set or reset the hub topic string |
| [cmd_upgrade](#cmd_upgrade) | Set or change a registered user's level by SID or nick |
| [cmd_uptime](#cmd_uptime) | Display hub uptime (session and cumulative since first start) |
| [cmd_usercleaner](#cmd_usercleaner) | Show and remove inactive or never-used accounts |
| [cmd_userinfo](#cmd_userinfo) | Display user information (nick, level, IP, features, share, slots) |
| [cmd_userlist](#cmd_userlist) | List all registered users sorted by level or registration date |
| [cmd_usersearch](#cmd_usersearch) | Search registered users by partial nick match |

### 🧩 Etc (utility) plugins

| Plugin | Purpose |
|---|---|
| [etc_banner](#etc_banner) | Broadcast periodic banner messages to main chat at configurable intervals |
| [etc_blacklist](#etc_blacklist) | Maintain and display the blacklist of delreg'd users to prevent re-registration |
| [etc_chatlog](#etc_chatlog) | Log main chat messages with timestamps, user nicks, and message content |
| [etc_cmdlog](#etc_cmdlog) | Audit log of all operator `+cmd` invocations (who, what, when) |
| [etc_dhtblocker](#etc_dhtblocker) | Disconnect users with DHT (Distributed Hash Table) search enabled |
| [etc_dummy_warning](#etc_dummy_warning) | Warn level-100 admin on login if the default "dummy" account is still registered |
| [etc_hubcommands](#etc_hubcommands) | Internal registry module for `+cmd` handlers |
| [etc_aliases](#etc_aliases) | Operator-defined command aliases |
| [etc_auditlog](#etc_auditlog) | Persistent JSONL audit trail for staff actions |
| [etc_blocklist](#etc_blocklist) | Operator-facing chat command for the unified pre-handshake IP/CIDR blocklist |
| [etc_whitelist](#etc_whitelist) | Operator-facing chat command for the global IP/CIDR allowlist |
| [etc_geoip](#etc_geoip) | Country / ASN policy blocking via a MaxMind GeoLite2 database |
| [etc_blocklist_feeds](#etc_blocklist_feeds) | External IP/CIDR blocklist feed puller |
| [etc_proxydetect](#etc_proxydetect) | Live proxy / VPN / Tor detection via an external provider API on connect |
| [etc_status_push](#etc_status_push) | Periodically pushes the hub's public status to an external HTTP(S) endpoint |
| [etc_prometheus](#etc_prometheus) | Prometheus text-exposition `/metrics` endpoint for the HTTP API |
| [etc_regserver_announce](#etc_regserver_announce) | Announces this hub to an external ADC hublist regserver |
| [etc_clientblocker](#etc_clientblocker) | Block clients by Lua-pattern match against the BINF `AP+VE` field |
| [etc_keyprint](#etc_keyprint) | Automatically extract and cache hub certificate keyprint (SHA256) for client validation |
| [etc_log_cleaner](#etc_log_cleaner) | Clean error.log and cmd.log files |
| [etc_motd](#etc_motd) | Send message-of-the-day to users on login |
| [etc_msgmanager](#etc_msgmanager) | Block main chat and / or PM for specific user levels |
| [etc_onfailedauth](#etc_onfailedauth) | Send report when user fails authentication (bad password, IP ban, etc) |
| [etc_records](#etc_records) | Track and display hub records (peak users, largest user share, etc) |
| [etc_report](#etc_report) | Internal library for sending operator reports to hub bot and / or opchat |
| [etc_trafficmanager](#etc_trafficmanager) | Block downloads, uploads, and searches for specific users |
| [etc_unknown_command](#etc_unknown_command) | Reject mistyped or malformed commands in main chat with helpful error message |
| [etc_usercommands](#etc_usercommands) | Internal registry module for client right-click context menus |
| [etc_userlogininfo](#etc_userlogininfo) | Display detailed user connection info on login |
| [etc_webhook](#etc_webhook) | Inbound webhook receiver: an external service POSTs an HMAC-signed JSON body, announced in chat as a named bot |
| [etc_backup](#etc_backup) | Automatic encrypted local backups of the hub's restore-critical state, rotated on a schedule |
| [etc_forcetlstransfer](#etc_forcetlstransfer) | Force TLS-encrypted client-to-client transfers (force ADCS) |
| [etc_lockdown](#etc_lockdown) | Transient maintenance-mode access gate: temporarily admit only users at or above a given level |

### 🎛️ Hub management plugins

| Plugin | Purpose |
|---|---|
| [hub_bot_cleaner](#hub_bot_cleaner) | Remove unused bot accounts from user database on timer |
| [hub_cmd_manager](#hub_cmd_manager) | Enforce permission levels on direct ADC commands (EMSG, DMSG, SCH, etc) |
| [hub_inf_manager](#hub_inf_manager) | Validate user INF flags on connect and broadcast |
| [hub_runtime](#hub_runtime) | Track cumulative hub runtime (survives restarts) and provide show / reset commands |
| [hub_user_lastseen](#hub_user_lastseen) | Update `lastseen` timestamp in user database on periodic timer |

### 🚫 User restriction plugins

| Plugin | Purpose |
|---|---|
| [usr_desc_prefix](#usr_desc_prefix) | Prepend level-based prefix to user descriptions (e.g. `[VIP]`, `[MOD]`) |
| [usr_hide_share](#usr_hide_share) | Hide share size for specified user levels |
| [usr_hubs](#usr_hubs) | Enforce minimum / maximum hub count per level |
| [usr_nick_length](#usr_nick_length) | Enforce min / max nickname length on connect and INF updates |
| [usr_nick_prefix](#usr_nick_prefix) | Prepend level-based prefix to user nicknames (e.g. `[Op]Bob`, `[VIP]Alice`) |
| [usr_share](#usr_share) | Enforce minimum / maximum share per user level |
| [usr_slots](#usr_slots) | Enforce minimum / maximum upload slots per user level |
| [usr_uptime](#usr_uptime) | Track per-user session and cumulative online time |

### 🚦 Rate-limit configuration

| Section | Purpose |
|---|---|
| [What it protects](#what-it-protects) | The buckets the limiter protects, with their limits and defaults |
| [Op-level bypass](#op-level-bypass) | Users at or above this level skip all per-user checks |
| [Tier overlay (per-userlevel limits)](#tier-overlay-per-userlevel-limits) | By default every non-op user uses the same scalar bucket settings |
| [Default tuning rationale](#default-tuning-rationale) | Why each per-user bucket default is sized the way it is |
| [Throttle behaviour - important plugin contract note](#throttle-behaviour---important-plugin-contract-note) | When a bucket is exhausted the dispatcher suppresses both the message fan-out and the plugin listener chain |
| [Bucket disable](#bucket-disable) | To disable a single bucket, raise its limit very high |

---

## Bot plugins

### bot_opchat

Internal op-chat bot for operator coordination. Broadcasts staff
messages to all logged-in ops at or above the configured level.

**Commands:** `+opchat help|history|historyall|historyclear`

**Config:** `bot_opchat_activate`, `bot_opchat_nick`, `bot_opchat_desc`,
`bot_opchat_history`, `bot_opchat_max_entrys`, `bot_opchat_permission`,
`bot_opchat_oplevel`

### bot_pm2ops

Routes operator private messages to the opchat bot. Forwards messages
with sender name and level to the operator coordination chat.

**Config:** `bot_pm2ops_activate`, `bot_pm2ops_nick`,
`bot_pm2ops_desc`, `bot_pm2ops_permission`

### bot_regchat

Registered-user chat with optional message history. Similar to opchat
but restricted to registered users instead of operators.

**Commands:** `+regchat help|history|historyall|historyclear`

**Config:** `bot_regchat_activate`, `bot_regchat_nick`,
`bot_regchat_desc`, `bot_regchat_history`, `bot_regchat_max_entrys`,
`bot_regchat_permission`, `bot_regchat_oplevel`

### bot_session_chat

Temporary per-session chats for user collaboration. Chat owners can
add/remove members; membership revokes on disconnect.

**Commands:** `+sessionchat <chatname>`

**Config:** `bot_session_chat_minlevel`,
`bot_session_chat_masterlevel`, `bot_session_chat_chatprefix`

---

## Command plugins

### cmd_accinfo

Display extended account details for registered users (nick, level,
registration date, last seen, ban status). Operator version shows
description and timestamps.

**Commands:** `+accinfo sid|nick|cid <target>` / `+accinfoop sid|nick|cid <target>`

**Config:** `cmd_accinfo_permission`, `cmd_accinfo_advanced_rc`,
`show_reguser_password`, `etc_msgmanager_activate`,
`etc_trafficmanager_activate`, `etc_trafficmanager_flag_blocked`

### cmd_ban

Ban / unban users by nick, CID, or IP with optional duration and
reason. Maintains ban records with history and state tracking.

**Commands:** `+ban nick|cid|ip <target> [<duration_minutes>] [<reason>]` /
`+ban show|showhis [<nick>]|clear|clearhis` /
`+unban nick|cid|ip <target>`

**Config:** `cmd_ban_permission`, `cmd_ban_default_time`,
`cmd_ban_report`, `cmd_ban_report_hubbot`, `cmd_ban_report_opchat`,
`cmd_ban_llevel`, `cmd_unban_permission`

### cmd_botflag

Toggle the ADC `CT` bot bit on a registered account so it renders with the
bot icon in DC++ / AirDC++ (e.g. an external announcer client), without any
privilege change. `CT` is display-only - authorization gates on level, not
`CT` - so this changes only the icon. Distinct from the in-hub `is_bot`
flag (which `hub_bot_cleaner` would delete while offline). Takes effect on
the account's next login. Ships disabled (`enabled = false`); enable it in
`cfg/cfg.tbl` and set `cmd_botflag_permission`.

**Commands:** `+botflag <nick> on|off`

**Config:** `cmd_botflag_permission`

### cmd_delreg

Delete registrations by nick. Optionally blacklist with reason to
prevent re-registration.

**Commands:** `+delreg nick <nick> [<reason>]`

**Config:** `cmd_delreg_permission`, `cmd_delreg_report`,
`cmd_delreg_report_hubbot`, `cmd_delreg_report_opchat`,
`cmd_delreg_llevel`

### cmd_disconnect

Forcefully disconnect a user with optional reason message.

**Commands:** `+disconnect <nick> <reason>`

**Config:** `cmd_disconnect_minlevel`, `cmd_disconnect_sendmainmsg`,
`cmd_disconnect_report`, `cmd_disconnect_report_hubbot`,
`cmd_disconnect_report_opchat`, `cmd_disconnect_llevel`

### cmd_errors

Display the hub error log to users with sufficient permissions.

**Commands:** `+errors`

**Config:** `cmd_errors_permission`

### cmd_gag

Mute, kennylize (garble), or shadowmute users with optional duration.
Tracks restrictions and auto-expires.

**Commands:** `+gag mute|kennylize|shadowmute|ungag|show <nick> [<duration>]`

**Config:** `cmd_gag_permission`, `cmd_gag_user_notifiy`,
`cmd_gag_report`, `cmd_gag_report_hubbot`, `cmd_gag_report_opchat`,
`cmd_gag_llevel`

### cmd_help

Central help registry for all operator commands. Displays all
available commands filtered by user level.

**Commands:** `+help`

### cmd_hubinfo

Display comprehensive hub information including version, uptime, user
counts, ports, SSL/TLS mode, system info, and user level breakdown.

**Commands:** `+hubinfo`

**Config:** `cmd_hubinfo_minlevel`, `cmd_hubinfo_onlogin`

### cmd_hubstats

Track hub statistics over time (user averages, share, registrations,
bans). Data aggregated daily / weekly / monthly / yearly.

**Commands:** `+hubstats`

**Config:** `cmd_hubstats_oplevel`

### cmd_mass

Broadcast mass messages to all users or specific user levels. Optional
sender anonymity (`+masshub`).

**Commands:** `+mass <message>` / `+masslvl <level> <message>` /
`+masshub <message>`

**Config:** `cmd_mass_permission`, `cmd_mass_oplevel`

### cmd_myinf

Display own or target user's raw INF command output (client
information).

**Commands:** `+myinf [<nick>]`

**Config:** `cmd_myinf_permission`

### cmd_myip

Display own or target user's IP address. Unrestricted command.

**Commands:** `+myip [<nick>]`

### cmd_nickchange

Change registered user nicknames. Owner can change own; operators can
change others' subject to level hierarchy.

**Commands:** `+nickchange mynick <newnick>` /
`+nickchange othernick <oldnick> <newnick>`

**Config:** `cmd_nickchange_minlevel`, `cmd_nickchange_oplevel`,
`cmd_nickchange_advanced_rc`, `cmd_nickchange_report`,
`cmd_nickchange_report_hubbot`, `cmd_nickchange_report_opchat`

### cmd_redirect

Redirect users to an alternate hub URL based on level or manual
command.

**Commands:** `+redirect <nick> <url>`

**Config:** `cmd_redirect_activate`, `cmd_redirect_permission`,
`cmd_redirect_level`, `cmd_redirect_url`, `cmd_redirect_report`,
`cmd_redirect_report_hubbot`, `cmd_redirect_report_opchat`,
`cmd_redirect_llevel`

### cmd_reg

Register new users or add / modify registration descriptions. Generates
initial passwords and enforces level hierarchies.

**Commands:** `+reg nick <nick> <level> [<comment>]` /
`+reg desc <nick> <comment>`

**Config:** `cmd_reg_permission`, `cmd_reg_report`,
`cmd_reg_report_hubbot`, `cmd_reg_report_opchat`, `cmd_reg_llevel`

### cmd_reload

Reload hub configuration, user database, and restart scripts without
full hub restart.

**Commands:** `+reload`

**Config:** `cmd_reload_permission`

### cmd_restart

Gracefully restart the hub with optional broadcast message to users.
Optional countdown timer.

**Commands:** `+restart [<message>]`

**Config:** `cmd_restart_permission`, `cmd_restart_toggle_countdown`

### cmd_rules

Display hub rules to users (sent at login or on command). Supports
placeholder substitution.

**Commands:** `+rules`

**Config:** `cmd_rules_minlevel`, `cmd_rules_destination_main`,
`cmd_rules_destination_pm`

### cmd_setpass

Set or change passwords for registered users. Operators can reset
other users' passwords.

**Commands:** `+setpass myself <password>` /
`+setpass nick <nick> <password>`

**Config:** `cmd_setpass_permission`, `cmd_setpass_advanced_rc`,
`cmd_setpass_report`, `cmd_setpass_report_hubbot`,
`cmd_setpass_report_opchat`

### cmd_shutdown

Gracefully shut down the hub with optional broadcast message. Optional
countdown timer.

**Commands:** `+shutdown [<message>]`

**Config:** `cmd_shutdown_permission`,
`cmd_shutdown_toggle_countdown`

### cmd_slots

Display list of all currently connected users with available upload
slots.

**Commands:** `+slots`

**Config:** `cmd_slots_minlevel`

### cmd_sslinfo

Display TLS / SSL connection information for user's client (protocol
version, cipher, certificate details).

**Commands:** `+sslinfo [<nick>]`

**Config:** `cmd_sslinfo_minlevel`

### cmd_talk

Broadcast messages anonymously without nickname prefix.

**Commands:** `+talk <message>`

**Config:** `cmd_talk_permission`

### cmd_topic

Set or reset the hub topic string. Broadcasts topic changes to all
users.

**Commands:** `+topic <newtopic>` / `+topic default`

**Config:** `cmd_topic_minlevel`, `cmd_topic_llevel`, `cmd_topic_report`,
`cmd_topic_report_hubbot`, `cmd_topic_report_opchat` (the default topic is
read from / reset to `hub_description`)

### cmd_upgrade

Set or change a registered user's level by SID or nick. Enforces the
operator's permission ceiling (an operator can only promote up to their
own limit and cannot touch a user above their own level) and kicks the
online target with `ISTA 230 ... TL300` so the client picks up the new
permission set on reconnect. Works on offline registrations too.

**Commands:** `+upgrade sid|nick <sid>|<nick> <level>`

**HTTP API:** `PUT /v1/registered/{nick}/level` (admin) - mirrors the
ADC `+upgrade nick` path; humans only (bots return 404). The bearer
token's admin scope is the gate, so the ADC permission ladder does NOT
apply on the HTTP path. See [HTTP_API.md](HTTP_API.md).

**Audit events:** `reg.level.set` (meta `previous_level`; the HTTP
path also records `online_kicked`).

**Config:** `cmd_upgrade_permission` (level -> promotable-up-to
ceiling table), `cmd_upgrade_advanced_rc`, `cmd_upgrade_report`,
`cmd_upgrade_report_hubbot`, `cmd_upgrade_report_opchat`,
`cmd_upgrade_llevel`

### cmd_uptime

Display hub uptime (session and cumulative since first start) and the
calling user's personal session duration.

**Commands:** `+uptime [<nick>]`

**Config:** `cmd_uptime_minlevel`

### cmd_usercleaner

Show and remove inactive or never-used accounts. Supports time-based
expiry and exception lists.

**Commands:** `+usercleaner showall|showexpired|showghosts|delexpired|delghosts|addexception|delexception|delexceptionall|showexceptions|setdays`

**Config:** `cmd_usercleaner_activate`, `cmd_usercleaner_permission`,
`cmd_usercleaner_protected_levels`, `cmd_usercleaner_report`,
`cmd_usercleaner_report_opchat`, `cmd_usercleaner_report_hubbot`,
`cmd_usercleaner_report_llevel` (the inactivity-day threshold and the
nick exception list are runtime state in `cmd_usercleaner_settings.tbl`
/ `cmd_usercleaner_exceptions.tbl`, managed via `+usercleaner setdays` /
`addexception`, not cfg keys)

### cmd_userinfo

Display user information (nick, level, IP, features, share, slots).
Filters by online / offline status.

**Commands:** `+userinfo [sid|nick|cid <target>]`

**Config:** `cmd_userinfo_permission`

### cmd_userlist

List all registered users sorted by level or registration date.
Useful for administration.

**Commands:** `+userlist [bydate]`

**Config:** `cmd_userlist_permission`

### cmd_usersearch

Search registered users by partial nick match. Results include level
and registration date (the password column is redacted by default,
#95; set `show_reguser_password = true` to show it).

**Commands:** `+usersearch <searchstring>`

**Config:** `cmd_usersearch_minlevel`, `cmd_usersearch_max_limit`,
`show_reguser_password`

---

## Etc (utility) plugins

### etc_banner

Broadcast periodic banner messages to main chat at configurable
intervals.

**Config:** `etc_banner_activate`, `etc_banner_time`

### etc_blacklist

Maintain and display the blacklist of delreg'd users to prevent
re-registration.

### etc_chatlog

Log main chat messages with timestamps, user nicks, and message
content. Display on user login.

**Config:** `etc_chatlog_activate`

### etc_cmdlog

Audit log of all operator `+cmd` invocations (who, what, when).

**Commands:** `+cmdlog show`

**Config:** `etc_cmdlog_activate`

### etc_dhtblocker

Disconnect users with DHT (Distributed Hash Table) search enabled.
Prevents unwanted network search participation.

**Config:** `etc_dhtblocker_activate`, `etc_dhtblocker_report`,
`etc_dhtblocker_report_hubbot`, `etc_dhtblocker_report_opchat`

### etc_dummy_warning

Warn level-100 admin on login if the default "dummy" account is still
registered.

### etc_hubcommands

Internal registry module for `+cmd` handlers. Exported library used by
every command plugin via `hub.import("etc_hubcommands")`. Also emits
the "Did you mean +X?" reminder on bare-word typos. Exports `add(cmd, fn)`
plus `has(cmd)` (predicate, used by etc_aliases at `+addalias` time) and
`list()` (enumeration helper used by `+aliases` to show built-in
command names).

### etc_aliases

Operator-defined command aliases. Lets the hub admin map short or
memorable alias names to existing commands (e.g. `+us` -> `+usersearch`,
`+tm` -> `+trafficmanager`). Closes [#327](https://github.com/luadch-ng/luadch-ng/issues/327).

**Commands:**
- `+addalias <alias> <target>` - create a new alias
- `+delalias <alias>` - remove an alias
- `+aliases` - list configured aliases AND built-in command names

**Storage:** `cfg/aliases.tbl`, grouped by target for human readability:

```lua
return {
    usersearch     = { "us" },
    trafficmanager = { "tm", "trma" },
}
```

The plugin inverts to a flat `{ [alias] = target }` map in memory.
`+addalias` / `+delalias` rewrite the file atomically; `+reload` re-reads.

**Validation at `+addalias`** rejects with a distinct error string:
- alias not matching `^%a+$` (the hub dispatcher's regex constraint)
- alias name is already a real command (real commands always win,
  cannot be aliased)
- alias already mapped (use `+delalias` first - no silent overwrite)
- target command does not exist

**Resolver fallback** runs in `etc_hubcommands` on direct-lookup miss:
the typed token is resolved through `etc_aliases.resolve(name)` and
the real command's handler dispatches, receiving the resolved command
name as its `command` argument (so help-text generation matches). The
`[command] +<typed>` echo line shows the user's original input
verbatim - it's a chat acknowledgement, not a routing trace. Both
fall-through hints ("Did you mean +X?" and the literal-bracket hint)
DO surface the resolved target, since those messages exist to teach
the operator the correct command name.

**HTTP API:** `GET /v1/aliases`, `POST /v1/aliases` (admin),
`DELETE /v1/aliases/{alias}` (admin). See [HTTP_API.md](HTTP_API.md).

**Config:** `etc_aliases_minlevel` (default 80 = admin),
`etc_aliases_report` / `_report_hubbot` / `_report_opchat` / `_llevel`
(opchat audit trail toggles, matching the cmd_topic / etc_msgmanager
pattern).

### etc_auditlog

Persistent JSONL audit trail for staff actions. Subscribes to
`onAudit` events fired by every staff-action plugin via the
core/audit.lua helper (`audit.fire(audit.build(action, actor,
target, reason, meta))`). Closes [#84](https://github.com/luadch-ng/luadch-ng/issues/84).

**Commands:** `+auditlog show` (today's file as chat banner).

**Storage:** `log/audit-YYYY-MM-DD.jsonl`, one JSON object per
line. UTC daily rollover; on the first write past midnight the
plugin opens a new file and unlinks any `audit-*.jsonl` older than
`etc_auditlog_retention_days`. POSIX chmod 0600 on every file
(no-op on Windows; see SECURITY.md §4 for the NTFS ACL recipe).

**Append-only.** The plugin opens `io.open(path, "ab")` exclusively;
no code path truncates the active file. The `DELETE /v1/log/audit`
endpoint deliberately does NOT exist (audit-trail philosophy:
clearing must be a filesystem-level operation with explicit
chain-of-custody).

**Per-line shape:**

```json
{
    "ts":     "2026-06-23T15:42:11Z",
    "action": "ban.add",
    "actor":  { "nick": "op", "level": 80, "sid": "ABCD",
                "cid": "...", "ip": "1.2.3.4" },
    "target": { "nick": "baduser", "ip": "5.6.7.8" },
    "reason": "spam",
    "meta":   { "by": "ip", "duration_sec": 86400, "online": true }
}
```

`actor.nick` is the canonical firstnick (prefix-less); the visible
form (e.g. `[OP]op`) lands in optional `display_nick` when it
differs. `actor.sid = "<http>"` for events fired via the HTTP API
(actor_label = the bearer token's `comment`). Optional fields
(`target`, `reason`, `meta`, `display_nick`) are dropped when
empty so the on-disk shape stays compact.

**Action vocabulary:**
`ban.add`, `ban.remove`, `ban.clear`, `ban.history.clear`,
`gag.add`, `gag.remove`, `user.kick`, `user.redirect`,
`user.mass.kick`, `reg.add`, `reg.remove`, `reg.update`,
`reg.desc.set`, `reg.level.set`, `reg.nickchange`,
`reg.password.change`, `hub.topic.set`, `hub.topic.reset`,
`hub.reload`, `hub.restart`, `hub.shutdown`,
`hub.announce.{all,hub,level}`,
`alias.{add,remove}`, `msgmanager.{block,unblock}`,
`blacklist.remove`, `log.clear`, `records.reset`,
`user.cleanup`, `user.cleanup.exception.{add,remove,clear}`,
`user.cleanup.setdays`, `user.cleanup.orphan_comments`.

**HTTP API:** `GET /v1/log/audit?lines=N` (admin). Same envelope
(`{lines, returned, total_lines}`) as `/v1/log/cmd` and
`/v1/errors`. The audit stream also surfaces as
`GET /v1/events?types=audit` (admin scope only, see HTTP_API.md
§10.1 footnote).

**Config:** `etc_auditlog_activate` (master kill-switch, default
true), `etc_auditlog_dir` (`log/`), `etc_auditlog_prefix`
(`audit-`), `etc_auditlog_retention_days` (90, `0` disables the
sweep), `etc_auditlog_http_lines_default` (200),
`etc_auditlog_http_lines_max` (1000). Cap keys live on the core
side: `audit_log_max_reason_chars` (1000),
`audit_log_max_meta_value_chars` (1000) - applied at `audit.build`
time so both disk and `/v1/events` payloads stay bounded.

### etc_blocklist

Operator-facing chat command for the unified pre-handshake
IP/CIDR blocklist. Engine is `core/blocklist.lua` (#78 Phase A);
this plugin (#78 Phase B) ships the `+blocklist` admin CLI with
six verbs.

**Commands** (all require `etc_blocklist_oplevel`, default 80):

- `+blocklist show [source]` - list active entries; optional
  filter by source (`manual`, `geoip`, `external`, `proxycheck`,
  `vpnapi`, `ipqs`). Output capped at `etc_blocklist_show_limit`
  rows (default 200) to keep a single DMSG readable on
  geoip-populated stores.
- `+blocklist add <cidr|ip> [stealth] [reason="..."] [expires=YYYY-MM-DD]` -
  add a CIDR (or single IP, treated as `/32` for v4 or `/128`
  for v6). `stealth` is a literal positional flag; `reason` and
  `expires` are key=value pairs with quoted-string values. The
  engine REJECTS host-bits-set CIDRs (`1.2.3.4/24` -> use
  `1.2.3.0/24` instead); the error surfaces back to the operator.
- `+blocklist del <id>` - remove an entry by numeric id from the
  `+blocklist show` output. A level-N operator CANNOT remove an
  entry added by a level-(N+) master (hierarchy guard via the
  entry's `by_level` field, captured at add time).
- `+blocklist count` - `{total, by_source}` summary.
- `+blocklist export` - write
  `cfg/blocklist-export-YYYYMMDD.jsonl` with all manual entries
  (auto-feeds are skipped; they re-fetch themselves). One JSON
  object per line, encoded with dkjson.
- `+blocklist import <path>` - read JSONL from the supplied
  path. Every string field is run through
  `util.strip_control_bytes` before insertion. Invalid rows
  (bad JSON, missing cidr) are counted as `errors`; rows whose
  cidr the engine rejects are counted as `skipped`. Importing
  attributes all rows to the importing operator's
  nick + level - the original `by_*` fields in the file are
  preserved as audit metadata in the imported row only.

**Auto-feed entries.** Phase D (`etc_geoip`), Phase E
(`etc_blocklist_feeds`), and Phase F (`etc_proxydetect`) plugins
will push entries into the same store with their respective
source tags. An operator at or above the master level can
remove any source via `+blocklist del`, but the matching
auto-feed will re-add the entry on the next refresh cycle - the
correct path is to disable / reconfigure the feed plugin, not
hand-delete its rows. Manual entries (`source=manual`) are
operator-owned and survive any feed refresh.

**Audit fires:** `blocklist.add` (cidr / source / stealth /
expires / id), `blocklist.remove` (id / cidr / source),
`blocklist.export` (path / count), `blocklist.import` (path /
added / skipped / errors). The accept-time TCP drop on a
matched IP fires NO per-attempt audit; aggregated rollup lines
land in the hub log on the
`blocklist_aggregated_log_window_sec` cadence (default 3600s).

**Storage and reload.** The engine writes
`scripts/data/etc_blocklist.tbl` on every successful add /
remove. The file appears on the first successful `+blocklist
add` (no empty stub on fresh install). The path is configurable
via `blocklist_store_path` cfg key; `scripts/data/` matches the
convention used by sibling plugins (`cmd_ban_bans.tbl`,
`etc_clientblocker.tbl`, `etc_blacklist.tbl`) so operators find
all plugin-owned state in one place. `+reload` re-snapshots the
cfg keys (`blocklist_enabled`, `blocklist_stealth_default`,
`blocklist_aggregated_log_window_sec`) and re-reads the .tbl.

**HTTP API surface (v0.02 / Phase C).** Four endpoints alongside
the ADC verbs, all documented in `docs/HTTP_API.md`:

- `GET /v1/blocklist` (read) - list with filter/sort/pagination
  via the shared `http_filter` convention. Query params include
  `source`, `stealth`, `cidr_contains`, `reason_contains`,
  `by_nick`, and range-filters on `by_level` / `created_at` /
  `expires_at`.
- `GET /v1/blocklist/counts` (read) - `{total, by_source}` for
  prometheus + dashboard use.
- `POST /v1/blocklist` (admin) - body `{cidr, source?, stealth?,
  reason?, expires_at?}`. `source` enum-locked; `expires_at` is a
  unix timestamp integer (HTTP path skips the ADC-side
  `YYYY-MM-DD` date parsing).
- `DELETE /v1/blocklist/{id}` (admin) - stable numeric ids from
  GET; unlike `/v1/bans/{id}` these do NOT shift on removal.

HTTP admin tokens bypass the ADC-side hierarchy guard: the token
is the trust surface, so a token can undo any entry regardless
of who added it. Entries created via HTTP are attributed with
`by_nick = <token label>` and `by_level = 100` (synthetic
master).

**Tradeoffs.** JSONL export/import remains the cross-hub sync
path (dedicated GET `/v1/blocklist/export` for bulk snapshots is
NOT provided; use GET /v1/blocklist with pagination if a caller
wants machine-readable batches). Importing the same JSONL twice
creates duplicate entries (no dedup on cidr alone, since (cidr,
source) is the engine's identity tuple); operators rely on the
`+blocklist show` id + `+blocklist del` (or the DELETE endpoint)
for cleanup.

**Upgrading from a pre-Phase-B hub.** `cfg.scripts` is
replace-not-merge - an operator with a `cfg.tbl` predating this
plugin must add the line `{ "etc_blocklist.lua", enabled = true },`
to their `cfg.scripts` block (next to `etc_clientblocker.lua`
is the canonical position) and run `+reload`. The example file
at `examples/cfg/cfg.tbl` shows the placement. The new cfg
keys (`etc_blocklist_oplevel`, `etc_blocklist_import_min_level`,
etc.) all have safe defaults via `core/cfg_defaults.lua` so
omitting them from `cfg.tbl` is fine.

Operators who ran the very first Phase-B build (`v0.01`) and
already have data at the old `cfg/blocklist.tbl` path from that
window: move the file to `scripts/data/etc_blocklist.tbl` (or
set `blocklist_store_path = "cfg/blocklist.tbl"` in `cfg.tbl`
to pin the old location). No auto-migration is provided; the
old-path window was small.

### etc_whitelist

Operator-facing chat command for the global IP/CIDR allowlist (the
deferred #78 allowlist). Engine is `core/whitelist.lua` (Phase A);
this plugin ships the `+whitelist` admin CLI (Phase B) and the HTTP
API (Phase D). A whitelisted IP is exempt from the AUTOMATED
blockers - GeoIP, proxy detection, external feeds, the hub-limit ban
- and from automated blocklist-store entries, but NOT from a
deliberate manual `+ban` / `+blocklist add` (a manual block wins). To
block a whitelisted IP, remove it from the whitelist first.

**Commands** (all require `etc_whitelist_oplevel`, default 80):

- `+whitelist show [source]` - list active entries; optional filter
  by source (`manual`, `pinger`). Capped at `etc_whitelist_show_limit`
  (default 200).
- `+whitelist add <cidr|ip> [reason="..."] [expires=YYYY-MM-DD]` -
  allow a CIDR (or single IP = `/32` v4 / `/128` v6). Host-bits-set
  CIDRs are rejected (`1.2.3.4/24` -> use `1.2.3.0/24`).
- `+whitelist del <id>` - remove by numeric id; same `by_level`
  hierarchy guard as `+blocklist`.
- `+whitelist count` - `{total, by_source}` summary.
- `+whitelist export` - write
  `cfg/whitelist-export-YYYYMMDD-HHMMSS.jsonl` with the operator-added
  (`source=manual`) entries. The bundled pinger seed is NOT exported
  (it re-seeds itself on a fresh hub).
- `+whitelist import <path>` - read JSONL; every string field is
  control-byte stripped; master-only via `etc_whitelist_import_min_level`
  (default 100), rows reattributed to the importing operator.

**Bundled pinger seed.** On the FIRST run (store `.tbl` missing) the
plugin seeds a small set of known hublist-pinger IPs as
`source=pinger` (v6 as `/64`, v4 as `/32`) so the pingers are not
flagged by the automated blockers out of the box. Seed-on-missing
ONLY - once the `.tbl` exists your edits (including deletions) are
authoritative and never re-seeded. Set `etc_whitelist_seed = false`
to boot with an empty whitelist. The list bit-rots (pinger IPs
rotate); review + extend via `+whitelist add`. A `/64` exempts a
whole subnet - each seeded range is meant to be a single per-VPS
pinger allocation; narrow to `/128` if that matters for your hub.

**Precedence (which blocker wins).** whitelist > automated blockers
(GeoIP / proxydetect / feeds / hub-limit ban + automated
blocklist-store entries); a manual `+ban` / `+blocklist add`
(`source=manual`) > whitelist. Enforced in `core/blocklist.check_ip`
and in each blocker plugin's per-connection guard. NOT yet extended
to the share / slots / nick-policy plugins (`usr_share` / `usr_slots`
/ `usr_nick_*`) - a whitelisted IP still faces those.

**Audit fires:** `whitelist.add` / `whitelist.remove` /
`whitelist.export` / `whitelist.import`.

**Storage and reload.** `scripts/data/etc_whitelist.tbl`, written on
every add / remove; path via `whitelist_store_path`. `+reload`
re-snapshots `whitelist_enabled` / `whitelist_store_path` and
re-reads the .tbl (config-only changes need no restart).

**HTTP API surface (v0.02 / Phase D).** Four endpoints mirroring the
blocklist API (in `docs/HTTP_API.md`): `GET /v1/whitelist` (read,
filter/sort/paginate), `GET /v1/whitelist/counts` (read), `POST
/v1/whitelist` (admin, body `{cidr, source?, reason?, expires_at?}`,
source enum `{manual, pinger}`), `DELETE /v1/whitelist/{id}` (admin).
HTTP admin tokens bypass the ADC hierarchy guard (token = trust
surface; entries attributed `by_nick = <token label>`, `by_level = 100`).

**Enabling.** Ships enabled in `examples/cfg/cfg.tbl`. An operator
upgrading a pre-existing `cfg.tbl` adds
`{ "etc_whitelist.lua", enabled = true },` to `cfg.scripts` and runs
`+reload`; the cfg keys all have safe defaults via
`core/cfg_defaults.lua`.

### etc_geoip

Country / ASN policy blocking via a MaxMind GeoLite2 database (#78
Phase D2). **Off by default** - needs a database the operator installs
with MaxMind's `geoipupdate` tool. Full setup (licence key, Linux /
Windows / Docker recipes, `log_only` -> `block` workflow) is in
[`BLOCKLIST.md`](BLOCKLIST.md).

On each connect (post-handshake) it resolves the client IP to its
country (and ASN, if that DB is configured) and, if it matches
`etc_geoip_blocked_countries` / `etc_geoip_blocked_asns`, either logs
the match (`etc_geoip_action = "log_only"`, the default) or kicks the
connection (`= "block"`). The lookup is a bounded per-connection mmdb
read, not a pre-handshake store sweep; country blocking is policy, so it
kicks post-handshake like `+ban` / the client blocker. Operators are
exempt by default (`etc_geoip_check_levels`), and the hub boots fine
without a database (a missing / stale `.mmdb` logs one warning and the
checks stay inert). Must sit AFTER `hub_inf_manager.lua` in
`cfg.scripts`.

**Command:**
- `+geoip` - read-only status: DB load state + build date, action mode,
  blocked country / ASN lists. Requires `etc_geoip_oplevel` (default 80).

**HTTP API:** `GET /v1/geoip` (read scope) mirrors `+geoip`. There is no
write endpoint - the policy is cfg-driven (`etc_geoip_blocked_countries`
etc. in `cfg.tbl`, then `+reload`).

**Audit events:** `geoip.block` on every match (both modes, with
`country` / `asn` / `matched` / `action` meta), `geoip.db.missing` and
`geoip.db.stale` (once each) on DB problems.

**Config keys:** `etc_geoip_enabled`, `etc_geoip_country_db_path`,
`etc_geoip_asn_db_path`, `etc_geoip_blocked_countries`,
`etc_geoip_blocked_asns`, `etc_geoip_action`, `etc_geoip_check_levels`,
`etc_geoip_recheck_interval_sec`, `etc_geoip_kick_reason`,
`etc_geoip_oplevel`, `etc_geoip_report[_hubbot|_opchat]`,
`etc_geoip_llevel`. See [`BLOCKLIST.md`](BLOCKLIST.md) for the table.

### etc_blocklist_feeds

External IP/CIDR blocklist feed puller (#78 Phase E, closes
[#79](https://github.com/luadch-ng/luadch-ng/issues/79)). Fetches
known-bad-IP lists over HTTPS on a per-feed timer and pushes them into
the unified pre-handshake blocklist (`core/blocklist.lua`) with
`source="external"` + `meta.feed=<name>`, so matched IPs are dropped at
TCP accept before they cost a handshake.

**Off by default at two levels:** the plugin master switch
(`etc_blocklist_feeds_enabled`) AND each feed's own `_enabled` key are
all `false`. Enabling the plugin alone pulls nothing; every feed is
opted in individually.

**Built-in feeds:**
- `tor` - Tor exit-node list (plain IPv4, one per line). Interval
  floor 30 min.
- `spamhaus` / `spamhaus_v6` - Spamhaus DROP v4 / v6 (JSONL, `.cidr` +
  `.sblid`). Interval floor 1 h (their published auto-fetch floor).
- `abuseipdb` - AbuseIPDB blacklist (top-N reported IPs, plaintext).
  Needs an API key (`Key` header, env-var-first via `core/secrets`);
  the free-tier blacklist download is 5/day, so the interval floor is
  6 h. Enabled without a key, the feed disables itself and warns once.
- `generic` - operator-supplied line-list URL (IP/CIDR per line,
  `#`/`;` comments tolerated). No key, no default URL.

Each successful refresh REPLACES the feed's prior entries via
`blocklist.bulk_replace` (one atomic disk write, not O(N^2) per-CIDR
adds that would freeze the single hub thread on a real feed). Entries
carry a TTL of 2x the refresh interval as a backstop, so a few missed
refreshes do not instantly unblock but a permanently-dead feed ages
out. A fetch / parse / HTTP failure keeps the last-good entries
(`bulk_replace` refuses to wipe a feed on an all-invalid parse) and
fires a `feed.refresh.fail` audit. The per-feed interval is clamped UP
to the adapter minimum regardless of the cfg value - polling faster
gets the hub's IP firewalled by the provider. The last-fetch time
persists to `scripts/data/etc_blocklist_feeds.tbl` so repeated
`+reload`s cannot re-pull a feed inside its interval and hammer the
provider (v0.02).

**Command:**
- `+blfeeds` - read-only status: per-feed enabled state, interval,
  entry count, last refresh. Requires `etc_blocklist_feeds_oplevel`
  (default 80).

**HTTP API:** `GET /v1/blocklist/feeds` (read scope) mirrors
`+blfeeds`. No write endpoint - which feeds run is cfg-driven
(edited in `cfg.tbl`, then `+reload`).

**Audit events:** `feed.refresh.success` (feed / added / removed /
skipped), `feed.refresh.fail` (feed / err). Op-chat reports are
debounced to first-refresh + fail<->ok transitions so a steady feed
does not spam the chat.

**Config keys:** `etc_blocklist_feeds_enabled`, then a per-feed block
for each of `tor` / `spamhaus` / `spamhaus_v6` / `abuseipdb` /
`generic` (`_<feed>_enabled`, `_<feed>_url`,
`_<feed>_refresh_interval_sec`, `_<feed>_stealth`;
`spamhaus_v6` shares the `spamhaus` interval + stealth), plus
`etc_blocklist_feeds_abuseipdb_key` (prefer the
`LUADCH_ETC_BLOCKLIST_FEEDS_ABUSEIPDB_KEY` env var),
`etc_blocklist_feeds_oplevel`, and
`etc_blocklist_feeds_report[_hubbot|_opchat]` /
`etc_blocklist_feeds_llevel`. See [`BLOCKLIST.md`](BLOCKLIST.md) for
the table.

### etc_proxydetect

Live proxy / VPN / Tor detection via an external provider API on connect
(#78 Phase F, closes [#352](https://github.com/luadch-ng/luadch-ng/issues/352)).
**Off by default** - needs a provider (`etc_proxydetect_provider`) and,
for most, an API key. Full setup, the provider free-tier / commercial-use
comparison, and the `log_only` -> `block` workflow are in
[`BLOCKLIST.md`](BLOCKLIST.md).

On each connect (post-handshake) it fires a **non-blocking** provider
lookup of the client IP; the verdict arrives in a callback, which kicks
the still-connected user (`etc_proxydetect_action = "block"`) or just
logs it (`"log_only"`, the default). A positive verdict in block mode is
**also pushed into the pre-handshake blocklist** with a TTL, so the next
connection from that IP is dropped at accept (silently, by default) with
no further query. Clean verdicts are cached to
`scripts/data/etc_proxydetect.tbl`, and a daily query cap
(`etc_proxydetect_max_queries_per_day`) protects the provider quota. On a
provider error / timeout / spent quota the plugin **fails open** (allows
the connection) unless `etc_proxydetect_fail_open = false`. Operators are
exempt by default (`etc_proxydetect_check_levels`). Must sit AFTER
`hub_inf_manager.lua` in `cfg.scripts`. Three providers: `proxycheck`
(keyless-capable), `vpnapi`, and `ipqs` (both key-required). For `vpnapi`
/ `ipqs` the key rides in the request URL, so the plugin passes a
key-free `log_url` to keep it out of the hub's failure logs. A run of
provider failures fires one op-chat alert
(`etc_proxydetect_fail_alert_threshold`).

**Command:**
- `+proxydetect` - read-only status: provider, action mode, blocked
  types, cached-verdict count, queries used today. Requires
  `etc_proxydetect_oplevel` (default 80).

**HTTP API:** `GET /v1/proxydetect` (read scope) mirrors `+proxydetect`.
No write endpoint - the policy is cfg-driven.

**Audit events:** `proxydetect.block` on every match (both modes, with
`ip` / `provider` / `types` / `action` / `cached` meta),
`proxydetect.query.fail` on a provider error / timeout,
`proxydetect.provider.down` when failures cross the alert threshold.

**Config keys:** `etc_proxydetect_enabled`, `etc_proxydetect_provider`,
`etc_proxydetect_api_key` (prefer the `LUADCH_ETC_PROXYDETECT_API_KEY`
env var), `etc_proxydetect_action`, `etc_proxydetect_block_types`,
`etc_proxydetect_check_levels`, `etc_proxydetect_cache_ttl_sec`,
`etc_proxydetect_query_timeout_sec`, `etc_proxydetect_fail_open`,
`etc_proxydetect_stealth`, `etc_proxydetect_max_queries_per_day`,
`etc_proxydetect_fail_alert_threshold`, `etc_proxydetect_kick_reason`,
`etc_proxydetect_oplevel`, `etc_proxydetect_report[_hubbot|_opchat]`,
`etc_proxydetect_llevel`. See [`BLOCKLIST.md`](BLOCKLIST.md) for the table.

### etc_status_push

Periodically PUSHES the hub's PUBLIC status to an external HTTP(S)
endpoint - a heartbeat. Generic: any consumer that accepts a JSON POST
works (an external status page, a push-uptime monitor such as
healthchecks.io / Uptime Kuma / Better Uptime, a self-hosted dashboard,
an automation webhook, a multi-hub status aggregator).

Unlike `etc_regserver_announce` (register once, then quiet) this is an
unconditional heartbeat: it POSTs every `etc_status_push_interval`
seconds (default 300) so the receiver gets evenly-spaced samples for a
graph and detects staleness itself. No login/logout trigger, no
give-up logic - a missed beat is fine. Complements `etc_prometheus`:
that is a PULL model (a scraper GETs `/metrics`, inbound); this is
PUSH (the hub dials out), which needs no inbound exposure and works
behind NAT.

Only PUBLIC fields are sent - never a nick, secret, or internal state.
The fixed JSON body is `{ "name": <hub name>, "users": <online humans,
no bots>, "uptime": <seconds since start> }`; the hub sends no
timestamp (the receiver stamps arrival). The request carries an
`Authorization: Bearer <token>` header over TLS (`verify=peer` by
default, since the token must not leak). Transport is the non-blocking
`core/http_client`.

**Off by default** (`etc_status_push_activate = false`); with no url or
no token it stays inert. The token is read env-var-first via
`core/secrets` and is redacted from `GET /v1/config`.

**Config keys:** `etc_status_push_activate`, `etc_status_push_url`,
`etc_status_push_token` (prefer the `LUADCH_ETC_STATUS_PUSH_TOKEN` env
var), `etc_status_push_interval`, `etc_status_push_tls_verify`,
`etc_status_push_cafile`.

### etc_prometheus

Prometheus text-exposition `/metrics` endpoint for the HTTP API
([#83](https://github.com/luadch-ng/luadch-ng/issues/83)). A PULL model:
a Prometheus scraper GETs `/metrics` and the hub returns 7 gauges +
7 counters in the 0.0.4 exposition format. The pull counterpart to
`etc_status_push` (push heartbeat) and the metrics sibling of
`etc_webhook` (inbound receiver).

**Off by default** (`etc_prometheus_activate`); when off the route is
never registered and `GET /metrics` returns a generic 404. Counters
are monotonic since plugin onStart and reset on `+reload` (the standard
Prometheus scrape-target-restart convention). `/metrics` is `read`
scope, so the scraper needs the bearer token; keep
`http_api_log_reads` off (the default) so scrape pulls do not flood
the API audit log.

Gauges: online humans, online bots, total share bytes, total files,
hub uptime, Lua memory KiB, active bans (0 when cmd_ban is not
loaded). Counters: logins, logouts, failed auths, chat msgs, PMs,
searches, script errors. The full metric catalog is in
[HTTP_API.md](HTTP_API.md).

**HTTP API:** `GET /metrics` (read scope), content-type
`text/plain; version=0.0.4; charset=utf-8`.

**Config:** `etc_prometheus_activate`

### etc_regserver_announce

Announces this hub to an external ADC hublist regserver by POSTing an
ADC `IINF` line (public fields only) to the regserver's `/register`
endpoint; external ADC pingers then take over liveness + removal.

**Off by default** (`etc_regserver_announce_activate`) - this is the
privacy gate: a private hub leaves it off and never appears on a
hublist. Registers ONCE per advertised address
(`adcs://<hub_hostaddress>:<ssl_port>`, preferring the TLS port, is the
dedup key): after a confirmed 2xx it goes quiet and does not
re-announce until the address changes - the pingers already maintain
liveness, so re-announcing on a timer is wasted bandwidth. On a host
change or an unconfirmed registration it retries every
`etc_regserver_announce_retry_interval` (default 300s) up to
`etc_regserver_announce_max_attempts`, then gives up until the next
`+reload` / restart.

Only PUBLIC hub fields are sent (name, app, version, address,
description, website, network, owner, online human count, total
share) - never a nick, secret, or internal state. The POST goes
through the non-blocking `core/http_client` so a slow / unreachable
regserver never freezes the hub. Multiple regservers are supported
(`etc_regserver_announce_url` accepts a string OR an array).

**Storage:** `scripts/data/etc_regserver_announce.tbl` (the per-target
confirmed address, so a `+reload` with an unchanged address does not
re-announce).

**Config keys:** `etc_regserver_announce_activate`,
`etc_regserver_announce_url`, `etc_regserver_announce_tls_verify`,
`etc_regserver_announce_cafile`,
`etc_regserver_announce_retry_interval`,
`etc_regserver_announce_max_attempts`

### etc_clientblocker

Block clients by Lua-pattern match against the BINF `AP+VE` field
(`user:version()` returns the concatenated `<AP> <VE>` form). Closes
[#81](https://github.com/luadch-ng/luadch-ng/issues/81). Promoted into
core from the `luadch-ng/scripts` companion repo (basis: pulsar
v0.2, GPLv3).

**Commands:**
- `+addblocker <pattern> [reason]` - add a pattern. First whitespace-
  token is the pattern; everything after it is the kick reason
  (defaults to `etc_clientblocker_default_reason`).
- `+delblocker <pattern|N>` - remove a pattern by literal pattern OR by 1-based row number from the `+blocker` list output (so operators don't need to retype the `^anchor.+` form of the bundled defaults).
- `+blocker` - list configured patterns.

**Storage:** `scripts/data/etc_clientblocker.tbl`, flat
`{ [pattern] = reason }`. The plugin auto-creates an empty file at
onStart if the file is missing.

**Listener-chain placement:** MUST sit AFTER `hub_inf_manager.lua`
in `cfg.scripts`. The structural BINF validator (forbidden flags /
identity-spoof kill / I4/I6 strip) is a hard precondition for the
client-policy match; running the policy filter on un-validated INFs
would be a layering inversion. `examples/cfg/cfg.tbl` ships them in
the right order.

**Operator self-lockout footgun.** The default
`etc_clientblocker_check_levels` table exempts OPERATOR (60),
SUPERVISOR (70) and ADMIN (80); HUBOWNER (100) stays in scope
deliberately. If you add a pattern that matches your own client
from a HUBOWNER session, flip `[100]` to `false` first, otherwise
the next `+reload` will kick you on the next connect.

**Pattern validation at edit time.** `+addblocker` / `POST
/v1/clientblocker` reject patterns that are empty, exceed
`etc_clientblocker_max_pattern_len` (default 200), contain
URL-unsafe `/`, `?`, `#` or `&` (the DELETE endpoint uses the
pattern as a path-var and the router does not percent-decode -
those four chars would silently 404), or fail a
`pcall(string.find, "", pat)` compile probe. This fails loud at
add time rather than silently at the next onConnect (the pcall
guard around the actual match call is belt-and-suspenders).
All other Lua-pattern punctuation (`%`, `+`, `.`, `(`, `)`,
`[`, `]`, `*`, `-`, `^`, `$`) is allowed.

**Audit events:** `client.block.add`, `client.block.remove`,
`client.block.kick`. The kick event's `meta` carries `{pattern,
version}` so post-mortem can reconstruct which rule fired and what
the offending VE actually was.

**Op-chat / hubbot report on kick.** When
`etc_clientblocker_report=true` (default) the plugin fires
`etc_report.send` with a human-readable banner
`[ CLIENT BLOCKER ]--> The user <nick> with IP <ip> is running
<version> and is not allowed in this hub. Matching pattern: <pat>`
so staff see kicks live in op-chat without tailing the audit log.
The audit log carries the same fields structured for forensics;
the report is for operational awareness. Sub-toggles
`etc_clientblocker_report_opchat` (default true) and
`etc_clientblocker_report_hubbot` (default false) match the
sibling-plugin convention.

Flood-control note: the report fires synchronously on every kick.
Op-chat flood protection relies on the upstream per-IP / per-CID
connect rate-limit in `core/ratelimit.lua` (Phase 7); a determined
attacker who throttles connections below the limit can sustain
~1 kick/sec/IP. If your hub sees this and op-chat noise becomes
unmanageable, flip `etc_clientblocker_report=false` and rely on
the audit log alone.

**Default blocklist** (`scripts/data/etc_clientblocker.tbl`):
when the .tbl file does NOT exist on disk, onStart seeds 6
well-known cheat/mod clients into it (`CleanDC++`, `RSX++`,
`CrZ++`, `SmVDC++`, `DC@fe++`, `FearDC`). These are universally-
malicious clients across DC hubs - operators almost never want
them. Remove individual entries via `+delblocker <N>` (row
number from `+blocker` output) or `+delblocker <pattern>`.

The defaults are only seeded ONCE, on first run when the .tbl
file is missing. An operator who later `+delblocker`s every
entry keeps an empty .tbl across reloads - no silent re-seed.
To recover the bundled defaults after deliberately emptying
the file: `rm scripts/data/etc_clientblocker.tbl` then `+reload`
(or hub restart). To recover a single removed default: copy
the line from `examples/data/etc_clientblocker.tbl.example`.

**Extended example list** (`examples/data/etc_clientblocker.tbl.example`):
~40 additional patterns curated by Sopor over years of hub
operation - blocks outdated stable releases of DC++ (0.0xx-0.8xx),
AirDC++ (1.0-4.29 + Web Client 0.x-2.14b + nano), EiskaltDC++ (<2.4.1),
ApexDC++ (<1.6.4), ncdc (<1.18), Jucy (<0.86), plus legacy mods
(StrgDC++, IceDC++, PDC++, PWDC++). Copy this file to
`scripts/data/etc_clientblocker.tbl` and `+reload` to adopt the
broader policy.

**HTTP API:**
- `GET /v1/clientblocker` (read scope) - list patterns
- `POST /v1/clientblocker` (admin scope) - add pattern; body
  `{pattern, reason?}`
- `DELETE /v1/clientblocker/{pattern}` (admin scope) - remove
  pattern (path-encoded; the router decodes the path var)

**F-INF-1d nil-VE guard** (Phase 8a): a client that did not send
a `VE` field at BINF has nothing to match against. The check
skips silently rather than crashing; matches the "no rule
applies" semantic for any other missing input.

**Config:** `etc_clientblocker_oplevel` (write floor for the ADC
cmd; default 80), `etc_clientblocker_check_levels` (per-level
boolean table; level 55 (SBOT) + 60/70/80 exempt by default),
`etc_clientblocker_default_reason`
(`"Your client is not allowed"`),
`etc_clientblocker_max_pattern_len` (200),
`etc_clientblocker_report` (true), `etc_clientblocker_report_opchat`
(true), `etc_clientblocker_report_hubbot` (false),
`etc_clientblocker_llevel` (60).

### etc_keyprint

Automatically extract and cache hub certificate keyprint (SHA256) for
client validation. Sets `keyprint_hash` / `use_keyprint` in cfg.

### etc_log_cleaner

Clean error.log and cmd.log files. Keeps last N lines and supports
manual or scheduled cleanup.

**Commands:** `+cleanlog error|cmd`

**Config:** `etc_log_cleaner_permission`, `etc_log_cleaner_lines`

### etc_motd

Send message-of-the-day to users on login. Supports placeholder
substitution.

**Config:** `etc_motd_activate`, `etc_motd_permission`,
`etc_motd_destination_main`, `etc_motd_destination_pm`

### etc_msgmanager

Block main chat and / or PM for specific user levels. Useful for spam
or abuse prevention.

**Commands:** `+msgmanager blockmain|blockpm|blockboth|unblock <nick>` /
`+msgmanager showusers|showsettings`

**Config:** `etc_msgmanager_activate`, `etc_msgmanager_permission`,
`etc_msgmanager_permission_main`, `etc_msgmanager_permission_pm`,
`etc_msgmanager_report`, `etc_msgmanager_report_hubbot`,
`etc_msgmanager_report_opchat`, `etc_msgmanager_llevel`

### etc_onfailedauth

Send report when user fails authentication (bad password, IP ban,
etc).

**Config:** `etc_onfailedauth_report`

### etc_records

Track and display hub records (peak users, largest user share, etc).
Reset capability for admins.

**Commands:** `+records` / `+records reset`

**Config:** `etc_records_min_level`, `etc_records_min_level_reset`,
`etc_records_whereto_main`, `etc_records_whereto_pm`,
`etc_records_sendMain`, `etc_records_sendPM`, `etc_records_reportlvl`,
`etc_records_delay`

### etc_report

Internal library for sending operator reports to hub bot and / or
opchat. Exported by other scripts.

### etc_trafficmanager

Block downloads, uploads, and searches for specific users. Useful for
spam or abuse control.

**Commands:** `+trafficmanager block|unblock <nick> [<reason>]` /
`+trafficmanager show settings|blocks`

**Config:** `etc_trafficmanager_activate`,
`etc_trafficmanager_permission`,
`etc_trafficmanager_blocklevel_tbl`,
`etc_trafficmanager_check_minshare`,
`etc_trafficmanager_flag_blocked`, `etc_trafficmanager_report`,
`etc_trafficmanager_report_hubbot`,
`etc_trafficmanager_report_opchat`, `etc_trafficmanager_llevel`

> **CCPM side effect:** ADC uses the same `CTM` / `RCM` commands for
> file-transfer connection setup AND for CCPM (encrypted client-to-
> client PM) channel setup. The plugin blocks both at the hub level
> for blocked users, so adding a level to `etc_trafficmanager_blocklevel_tbl`
> ALSO disables CCPM for that level. Affected users can still chat
> through the hub via regular `EMSG` / `DMSG`; only the direct
> end-to-end encrypted channel is unreachable. There is no clean
> wire-level differentiator between the two uses; operators who want
> CCPM available for a level must remove that level from the block
> list and accept the corresponding file-transfer permission. The
> source-level rationale is in the [`etc_trafficmanager.lua` header](../scripts/etc_trafficmanager.lua).

### etc_unknown_command

Reject mistyped or malformed commands in main chat with helpful error
message.

### etc_usercommands

Internal registry module for client right-click context menus.
Exported library used by command plugins via
`hub.import("etc_usercommands")`.

### etc_userlogininfo

Display detailed user connection info on login (client type, tag,
feature list, TLS cipher, upload / download speeds).

**Config:** `etc_userlogininfo_activate`

### etc_webhook

INBOUND webhook receiver: an external service (a Discourse forum,
GitHub, GitLab, CI, monitoring, ...) POSTs an HMAC-SHA256-signed JSON
body to a hub HTTP endpoint; the hub verifies the signature over the raw
body, filters + de-duplicates, renders a templated message and announces
it in chat as a named bot. The push-inbound mirror of `etc_status_push`
(outbound) and the inbound complement of `etc_prometheus` (pull
`/metrics`).

Multi-endpoint: the operator-edited `cfg/webhooks.tbl` holds an array of
endpoints, each with its own path, signature / event / id headers, event
filter, bot nick, min-level and `{dotted.path}` message templates.
Per-endpoint secrets resolve env-var-first
(`LUADCH_ETC_WEBHOOK_<NAME>_SECRET`), else the `etc_webhook_<name>_secret`
cfg key, else an inline `secret` in the file; an endpoint with no secret
is skipped (never runs unsigned). The endpoint registers with
`scope="none"` and does its own HMAC auth (`adclib.constant_time_eq`
over `req.raw_body`).

Only the master switch `etc_webhook_activate` lives in `cfg.tbl`; all
endpoint config lives in `cfg/webhooks.tbl` (copy
`examples/cfg/webhooks.tbl`). The HTTP API listener must be reachable
from the sender - put a reverse proxy with TLS in front. Full setup
(Discourse / GitHub webhook config, reverse proxy, security) in
[`docs/WEBHOOKS.md`](WEBHOOKS.md).

**Config:** `etc_webhook_activate` + `cfg/webhooks.tbl`

### etc_backup

Automatic encrypted local backups of the hub's restore-critical state
(`cfg/`, `scripts/data/`, `user.tbl`, the keys), sealed as a
password-protected `.ldbk` archive (LDBK1 = tar + AES-256-GCM, PBKDF2
key derivation) and rotated on a schedule. No cloud - archives are
written locally; off-site copying (rclone, ...) is the operator's
choice. Restore is a standalone OFFLINE step - `./luadch --restore
<file>` - not a chat command. Full setup, passphrase / master-key
handling, Docker and off-site walkthrough in
[`docs/BACKUP.md`](BACKUP.md).

**Commands:** `+backup now|list|status`

**Config:** `etc_backup_enabled`, `etc_backup_dir`, `etc_backup_keep`,
`etc_backup_daily_at`, `etc_backup_interval_hours`,
`etc_backup_include_master_key`, `etc_backup_passphrase`,
`etc_backup_oplevel`, `etc_backup_notify_level`

### etc_forcetlstransfer

Force TLS-encrypted client-to-client transfers (force ADCS). On an
`adcs://` hub the client<->hub link is encrypted, but a peer can still
negotiate a plaintext DIRECT transfer; this plugin refuses to broker a
plaintext transfer setup (`CTM` / `RevCTM` / NAT-traversal + its reply),
forcing `ADCS/`. All-or-nothing - no level or whitelist exemption.
Ships ENABLED in `warn` mode (PMs both parties a client-setup hint and
lets the transfer through); set `etc_forcetlstransfer_mode = "block"` to
actually drop plaintext setups (which needs each user's own TLS transfer
port reachable).

**Config:** `etc_forcetlstransfer_mode` (`warn` | `block`)

### etc_lockdown

Transient maintenance-mode access gate: temporarily admit only users at
or above a given level so the hub can be drained for maintenance without
a permanent `reg_only` config change. While active, logins below the
level are refused (with a reconnect countdown) and online users below it
are kicked; an optional timer auto-lifts it, or `+lockdown off` does.
Whitelisted IPs (hublist pingers) stay admitted when
`etc_lockdown_exempt_whitelist` is true, so the hub stays visible on
hublists during a lockdown. State survives `+reload` / restart
(`scripts/data/etc_lockdown.tbl`). Ships disabled.

**Commands:** `+lockdown <level> [minutes] [reason]` / `+lockdown off` /
`+lockdown status`

**Config:** `etc_lockdown_command_minlevel`, `etc_lockdown_default_retry`,
`etc_lockdown_exempt_whitelist`, `etc_lockdown_report`,
`etc_lockdown_report_hubbot`, `etc_lockdown_report_opchat`,
`etc_lockdown_llevel`

---

## Hub management plugins

### hub_bot_cleaner

Remove unused bot accounts from user database on timer. Prevents
clutter from disabled scripts.

**Config:** `hub_bot_cleaner_days`

### hub_cmd_manager

Enforce permission levels on direct ADC commands (EMSG, DMSG, SCH,
etc). Blacklist / whitelist support.

### hub_inf_manager

Validate user INF flags on connect and broadcast. Kill users whose
TCP source IP and BINF-advertised IP disagree (`kill_wrong_ips`).

**Config:** `kill_wrong_ips`

### hub_runtime

Track cumulative hub runtime (survives restarts) and provide show /
reset commands. Persists to `scripts/data/hub_runtime.tbl` (moved from
`core/hci.lua` in #445 - `core/` is shipped and every upgrade clobbered
the counter; `scripts/data/` is the operator-owned, upgrade-safe state
dir. `cmd_uptime` / `cmd_hubinfo` read the same file).

**Commands:** `+runtime show|reset`

### hub_user_lastseen

Update `lastseen` timestamp in user database on periodic timer (every
minute).

---

## User restriction plugins

### usr_desc_prefix

Prepend level-based prefix to user descriptions (e.g. `[VIP]`,
`[MOD]`). Configurable per level.

**Config:** `usr_desc_prefix_activate`, `usr_desc_prefix_permission`,
`usr_desc_prefix_prefix_table`

### usr_hide_share

Hide share size for specified user levels. Manual toggle via command.
Prevents share-based discrimination.

**Commands:** `+hideshare <nick>`

**Config:** `usr_hide_share_activate`,
`usr_hide_share_restrictions`, `usr_hide_share_permission`

### usr_hubs

Enforce minimum / maximum hub count per level. Redirect or disconnect
violators. Anti-multi-hub enforcement.

**Config:** `max_user_hubs`, `max_reg_hubs`, `max_op_hubs`, `max_hubs`,
`usr_hubs_godlevel`, `usr_hubs_redirect`

### usr_nick_length

Enforce min / max nickname length on connect and INF updates (multi-
byte codepoint-aware since v3.1.6).

**Config:** `min_nickname_length`, `max_nickname_length`

### usr_nick_prefix

Prepend level-based prefix to user nicknames (e.g. `[Op]Bob`,
`[VIP]Alice`). Configurable per level.

**Config:** `usr_nick_prefix_activate`, `usr_nick_prefix_permission`,
`usr_nick_prefix_prefix_table`

### usr_share

Enforce minimum / maximum share per user level. Redirect or disconnect
violators with optional blocking.

**Config:** `min_share`, `max_share`, `usr_share_redirect`

### usr_slots

Enforce minimum / maximum upload slots per user level. Redirect or
disconnect violators.

**Config:** `min_slots`, `max_slots`, `usr_slots_redirect`

### usr_uptime

Track per-user session and cumulative online time. Aggregates by
month and displays totals.

**Commands:** `+useruptime [<nick>]`

**Config:** `usr_uptime_permission`

---

## Rate-limit configuration

The hub-level rate limiter lives in
[`core/ratelimit.lua`](../core/ratelimit.lua) and runs **before** any
plugin listener. It is a core feature, not a plugin, but operators
tune it the same way - via `cfg/cfg.tbl`. The full design rationale
is in [`docs/SECURITY.md` §5](SECURITY.md).

### What it protects

| Bucket | Limits | Default |
|---|---|---|
| Per-IP parallel sockets | Concurrent connections from one IP | 16 |
| Per-IP new-conn rate | Tokens / s with burst | 10 / s, burst 30 |
| Per-IP failed-auth | Bad-password rate before sticky lockout | 10 / min, burst 5 |
| TLS-handshake deadline | Wallclock seconds before a half-open TLS is killed | 10 s |
| Per-user **mainchat** (BMSG) | Tokens / s with burst | 5 / s, burst 10 |
| Per-user **PM** (DMSG / EMSG) | Tokens / s with burst | 5 / s, burst 10 |
| Per-user **BINF** (post-login updates) | Tokens / s with burst | 2 / s, burst 20 |
| Per-user **CTM / RCM** (peer-connection setup) | Tokens / s with burst | 2 / s, burst 30 |
| Per-user **search** (BSCH / FSCH / DSCH) | One token every N seconds with burst | 1 / 2 s, burst 3 |

The five per-user buckets (mainchat, PM, BINF, CTM/RCM, search) each
have their own rate-and-burst config; operators can dial each
independently. The defaults are sized so a normal user never hits
them - the limits only fire for floods.

### Op-level bypass

```lua
ratelimit_bypass_level = 60,
```

Users at or above this level skip **all per-user** checks. Per-IP
checks always apply regardless of level. Default 60 = "operator and
above bypass". Set higher (e.g. 80) to also rate-limit operators.

### Tier overlay (per-userlevel limits)

By default every non-op user uses the same scalar bucket settings
above. To set different limits per user level, define one or more
named **tiers** and map levels to them. Tiers are layered on top of
the scalars - any field a tier omits falls back to the scalar default,
and levels not in the map use the scalars unchanged.

```lua
-- unreg + guest get a stricter chat budget; bots get headroom on the
-- connection-setup bucket; everyone else stays on the defaults
ratelimit_tiers = {
    strict = {
        msg_rate    = 2,
        msg_burst   = 5,
        pm_rate     = 2,
        pm_burst    = 5,
    },
    bot = {
        ctm_rate    = 5,
        ctm_burst   = 60,
    },
},

ratelimit_tier_for_level = {
    [0]  = "strict",   -- unreg
    [10] = "strict",   -- guest
    [55] = "bot",      -- sbot
},
```

The 10 known tier fields are:

```
msg_rate     pm_rate     inf_rate     ctm_rate     search_period
msg_burst    pm_burst    inf_burst    ctm_burst    search_burst
```

Typo'd field names (e.g. `msg_brust = 5`) are rejected at cfg load
with an `out_error` log entry, so the operator notices the typo
instead of silently falling back to the global scalar.

### Default tuning rationale

- **chat (BMSG) 5 / s burst 10** - well above normal chat cadence (a
  user typing fast still trips at maybe 1 / s sustained); covers a
  ten-line paste without dropping.
- **PM (DMSG / EMSG) 5 / s burst 10** - same as chat (split out from
  the shared bucket in #80 so operators can tighten PM independently
  if abuse arises; PMs are harder to observe publicly).
- **BINF 2 / s burst 20** - tolerates watch-folder churn (one BINF
  per file added / removed during a sync) and parallel-download
  startup (ten slot-count updates in one second). Sustained 2 / s
  caps any flood at 120 / min after the burst.
- **CTM / RCM 2 / s burst 30** - covers "download all from this
  search results page" with up to 30 peers in the burst; same flood
  cap after.
- **Search 1 / 2 s burst 3** - search is server-side expensive
  (every connected client gets the query), so the cooldown is
  tighter. Burst 3 lets a user fire three quick refinements before
  the next 2 s.

### Throttle behaviour - important plugin contract note

When a bucket is exhausted the dispatcher returns `true` from the
handler, which **suppresses both the message fan-out AND the plugin
listener chain**. Throttled BINFs do not reach `onInf`, throttled
CTMs do not reach `onConnectToMe`, throttled DMSGs do not reach
`onPrivateMessage`. The full discussion is in
[`docs/SECURITY.md` §5 "Rate-limit and plugin contract"](SECURITY.md#rate-limit-and-plugin-contract-80).

For most operators this is the right behaviour. If you write a
plugin that does count-based heuristics on per-user messages, be
aware that the hub-level drop hides the post-burst tail from you.

### Bucket disable

To disable a single bucket, raise its limit very high - there's no
explicit off-switch per bucket. To disable the entire rate-limit
machinery:

```lua
ratelimit_activate = false,
```

This skips every check (per-IP, per-user, handshake-deadline). Not
recommended for public-facing deployments.

---

## ADC-EXT passthrough extensions

ADC defines a number of optional extensions where the hub's role is
purely transparent: clients negotiate the extension between
themselves (typically via `INF.SU` advertisement) and the hub just
relays the resulting commands like any other D-class / B-class
message. luadch supports these by simply not blocking them - no
SUP advertisement, no validation, no special parsing beyond the
already-existing default-validator path on unknown named
parameters (Phase 7d hardening).

Extensions in this category that the audit catches as
\"spec-defined, hub-passthrough\":

| Ext | What it does | Hub-side |
|---|---|---|
| **TYPE** | Typing notifications (\"user X is composing...\"), like instant-messenger clients show | passthrough |
| **ONID** | Per-user metadata about external services (email, ICQ, etc.); informational relay only | passthrough |
| **DFAV** | Decentralised hub-list: clients exchange their public hub favourites via `GFA` / `RFA` to build a community hublist | passthrough |
| **FEED** | RSS feed broadcasts inside the hub chat | passthrough |
| **ASCH** | Extended search NPs (file/folder filter, depth limit, etc.) | passthrough |
| **SEGA** | File-extension grouping in SCH | passthrough |
| **SUDP** | Encrypted UDP search-result delivery (`KY` key NP) | passthrough |
| **CCPM** | Client-to-client private messaging (`MSG.PM`) - hub detects support on login but stays out of the actual PM session | detect + passthrough |
| **BZIP** | bzip2-compressed filelist transport (client-pair) | passthrough |

luadch doesn't advertise any of these in its own ISUP because the
hub itself doesn't speak them - the client signals support per-user
in `INF.SU` and peers negotiate accordingly. If you write a plugin
that wants to gate one of these (e.g. forbid TYPE for level-0
unregistered users), it's a standard `onBroadcast` / `onPrivateMessage`
listener on the relevant command 4cc.

If a future ADC-EXT extension appears that the hub MUST validate
or transform (rather than just relay), it gets a first-class entry
in this doc and full \`core/hub_dispatch.lua\` plumbing - same way
NATT (#147 T1.1) and FRES (#147 T1.6) landed. The four extensions
above were filed as #147 T1.8 and explicitly do not need that.

---

## Optional plugins (companion repo)

The bundled tree above ships with luadch and is install-and-go. For
extra functionality - download bots, info commands, share-policy
plugins, RSS feeds, custom commands - see the curated companion
repository:

**[luadch-ng/scripts](https://github.com/luadch-ng/scripts)**

Each companion plugin lives in its own subdirectory under `scripts/`.
Drop the subdirectory into your `scripts/` tree, whitelist the plugin
in the `cfg.scripts` array in `cfg/cfg.tbl`, then `+reload`. Each
plugin folder contains its own README describing its commands and
cfg keys.

Note that the companion repo has a separate maintenance state - some
plugins there require luadch v3.1.7+ for features like
`util.atomic_write` (see the plugin header for the minimum hub
version).
