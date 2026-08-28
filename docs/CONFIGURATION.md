# Configuring luadch

This document covers how to configure a running hub: edit `cfg/cfg.tbl`,
register your operator account, manage plugins, set up TLS. For getting
the hub built and deployed in the first place, see
[BUILDING.md](BUILDING.md) and [INSTALLING.md](INSTALLING.md).

> **Status:** parts of this document are scaffolding with `TODO`
> markers. The skeleton lays out the topics; detailed semantics for
> individual `cfg.tbl` keys and plugins will be filled in as the
> documentation matures.

---

## First-run checklist

After a fresh install, before opening the hub to real users:

1. **Start the hub.** On first boot the hub auto-generates a self-signed
   P-256 ECDSA cert at `certs/servercert.pem` and `certs/serverkey.pem`
   and logs the keyprint to stdout (and Docker `docker logs`):
   ```
   cert_bootstrap: generated self-signed P-256 cert at certs/servercert.pem
   TLS keyprint (SHA256, base32): NUB44T3WNOUAC4QIG7CHGGRNOMNL3RDI5ZRWRSLUWAC2NT7YZMQA
   share with users as: adcs://<your-host>:5001/?kp=SHA256/NUB44T3WNOUAC4QIG7CHGGRNOMNL3RDI5ZRWRSLUWAC2NT7YZMQA
   ```
   Pin the cert deterministically: hand users the `adcs://host:port/?kp=SHA256/<keyprint>` URL. DC++ clients trust the keyprint, not a CA chain - no Let's Encrypt or paid cert needed (see [`docs/SECURITY.md`](SECURITY.md) §6).

   To regenerate later, delete `certs/servercert.pem` and `certs/serverkey.pem` and restart the hub. The `certs/make_cert.{sh,bat}` scripts (installed alongside the cert material) are still around for manual regeneration outside the hub process (e.g. for cron-based rotation).

2. **Connect with an ADC client** (AirDC++, EiskaltDC++, …):
   - Address: `adcs://127.0.0.1:5001/?kp=SHA256/<keyprint from step 1>`
   - Nick: `dummy`
   - Password: `test`

   The default cfg ships TLS-only (#77). To enable plain ADC alongside, add port numbers to `tcp_ports` / `tcp_ports_ipv6` in `cfg/cfg.tbl` - empty arrays mean "no plain listener."

3. **Register your own operator account**:
   ```
   +reg <yournick> 100
   ```
   Level 100 = HUBOWNER. Reconnect as that user.

4. **Delete the dummy account**:
   ```
   +delreg dummy
   ```
   This is **not optional**. The dummy account is a hubowner with
   public credentials.

5. **Edit `cfg/cfg.tbl`** to your deployment (see "cfg.tbl tour" below),
   then reload:
   ```
   +reload
   ```

---

## File layout (configuration-relevant parts)

| Path                     | What it is                                                   |
|--------------------------|--------------------------------------------------------------|
| `cfg/cfg.tbl`            | Main hub configuration (Lua-serialised table)                |
| `cfg/user.tbl`           | Registered users + password-equivalents (cleartext-equivalent as ADC requires; encrypted at rest by default - see SECURITY.md) |
| `cfg/user.tbl.bak`       | Rolling backup the hub maintains automatically               |
| `lang/de/hub.json`, `en/hub.json` | Hub-side strings (greeting, error messages, …)      |
| `scripts/lang/de/*.json` / `en/*.json` | Per-script translations                          |
| `scripts/data/*.tbl`     | Per-script runtime state (bans, chatlog, records, …)         |
| `certs/`                 | TLS keys + helpers                                           |

Editing rules:
- All `.tbl` files are Lua tables. Don't open them in a UTF-16 editor.
- Use a UTF-8 capable editor with Lua syntax highlighting.
- After edits, run `+reload` in the hub for changes to take effect
  (no full restart needed for cfg/script changes).

---

## cfg.tbl tour

The shipped `cfg/cfg.tbl` has comments alongside every key. The
high-impact ones to set on first run:

```lua
-- TODO(maintainer): expand this with the most common keys
-- (hub_name, hub_hostaddress, hub_owner, hub_email, hub_topic,
--  tcp_ports / ssl_ports, max_users, ssl_params.certificate / .key,
--  scripts list, language)
```

For now, open `cfg/cfg.tbl` in your editor — every key has an inline
explanation in the file itself.

### TLS configuration

The hub auto-generates a self-signed cert on first boot if none exists at the configured `ssl_params` paths. The default `cfg.tbl` already points at the right locations:

```lua
ssl_params = {
    mode        = "server",
    key         = "certs/serverkey.pem",
    certificate = "certs/servercert.pem",
    cafile      = "certs/cacert.pem",
    protocol    = "tlsv1_3",   -- TLS 1.3 only; cannot negotiate down
    options     = { "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1", "no_renegotiation" },
    ciphers     = "HIGH",
    ciphersuites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
    curve       = "prime256v1",
},
```

The verified TLS posture out of the box is **TLS 1.3 + AES-256-GCM**
(verified during the modernization phases). Nothing else needs to be
hardened for a default deploy.

### Port configuration

Default: TLS-only on v4 + v6, no plain ADC listener:

```lua
tcp_ports      = { },        -- empty = no plain ADC listener
ssl_ports      = { 5001 },   -- TLS ADC v4
tcp_ports_ipv6 = { },        -- empty = no plain ADC v6 listener
ssl_ports_ipv6 = { 5001 },   -- TLS ADC v6 (same port as v4 since v3.2.x)
```

To enable plain ADC alongside TLS, set `tcp_ports = { 5000 }` (and / or `tcp_ports_ipv6 = { 5000 }`) in `cfg/cfg.tbl`. Same port number on v4 and v6 is supported since v3.2.x (HTTP/80-style dual-stack); the historical 5000/5002 split is still accepted for operators who prefer it.

### Default account warning

The bundled `etc_dummy_warning` plugin warns level-100 users at login
(both in main chat and via PM) as long as the `dummy` account is still
registered - the message is delivered by the hub bot (default nick
`[BOT]HubSecurity`). **Take that warning seriously** - do not run a
public hub with `dummy / test` active.

---

## User levels

The hub uses an integer-based user level system. Higher levels grant
more permissions. Bundled defaults:

| Level | Name       | What it can do                                   |
|-------|------------|--------------------------------------------------|
| 100   | HUBOWNER   | Everything (registers / deletes / shutdown)      |
| 80    | ADMIN      | Admin operations, user + registration management |
| 70    | SUPERVISOR | Senior moderation, above operators               |
| 60    | OPERATOR   | Moderation (ban / kick / gag / redirect)         |
| 55    | SBOT       | Service-bot account level                        |
| 50    | SERVER     | Server / linked-service account level            |
| 40    | SVIP       | Super-VIP: elevated privileges, exemptions       |
| 30    | VIP        | VIP user, extra privileges                       |
| 20    | REG        | Registered user, basic chat / commands           |
| 10    | GUEST      | Guest account, minimal privileges                |
| 0     | UNREG      | Anonymous (unregistered) connection              |

Customise per-script `minlevel` in `cfg.tbl` to grant or restrict
specific commands.

> TODO(maintainer): full level table is in
> [docs/Luadch_Default_Levels.txt](Luadch_Default_Levels.txt) — pull the
> authoritative list from there.

---

## Registering and deleting users

```
+reg <nick> <level>           # register a new user at <level>
+delreg <nick>                # remove a registered user
+regme <nick> <password>      # self-register (optional add-on; install
                              #   examples/etc/other_available_scripts/cmd_regme.lua first)
+setpass <newpass>            # change your own password
+accinfo <nick>               # show registration info for someone
```

`user.tbl` is updated atomically; the rolling backup `user.tbl.bak`
captures the previous state.

---

## Plugins (scripts/)

Plugins live in `scripts/` and are loaded at hub start in the order
listed under `cfg.scripts` in `cfg.tbl`. Adding or removing a plugin:

1. Add the `.lua` file under `scripts/` (or remove it).
2. Edit `cfg.scripts` in `cfg/cfg.tbl` to include / exclude the
   plugin name (without `.lua`).
3. `+reload` to apply.

### Bundled plugin categories

| Prefix  | What                          | Examples                              |
|---------|-------------------------------|---------------------------------------|
| `cmd_`  | User chat commands            | `cmd_help`, `cmd_ban`, `cmd_uptime`   |
| `bot_`  | Bots that appear in user list | `bot_opchat`, `bot_regchat`           |
| `etc_`  | Background features           | `etc_chatlog`, `etc_motd`             |
| `hub_`  | Core hub-level scripts        | `hub_runtime`, `hub_cmd_manager`      |
| `usr_`  | Per-user constraints          | `usr_share`, `usr_slots`, `usr_uptime`|

> TODO(maintainer): per-script descriptions / common configuration
> snippets for the plugins that have non-trivial settings (`etc_motd`,
> `etc_blacklist`, `etc_msgmanager`, …).

### Writing your own plugin

The plugin API is documented in
[docs/PLUGIN_API.md](PLUGIN_API.md). The core hooks:

- `onStart`, `onExit`
- `onLogin`, `onFailedAuth`
- `onBroadcast` (main chat), `onPrivateMessage`
- `onReg`, `onDelreg`
- `onTimer`, `onError`

Register a listener with `hub.setlistener(event, id, function)`. See any
of the bundled `cmd_*.lua` files for working examples.

---

## Languages

Two layers:

- **Hub-side strings** (`lang/de/hub.json`, `lang/en/hub.json`) — chosen via
  `cfg.language` in `cfg.tbl`. Affects core hub messages.
- **Per-script strings** (`scripts/lang/de/<scriptname>.json` / `en/<scriptname>.json`)
  — overrides the script's default texts. Edit the file matching your
  selected language; missing keys fall back to the script's hardcoded
  defaults.

After editing language files: `+reload`.

---

## Operational commands at a glance

| Command            | Effect                                              |
|--------------------|-----------------------------------------------------|
| `+reload`          | Re-read `cfg.tbl`, reload all scripts (no restart) |
| `+restart`         | Full hub restart                                    |
| `+shutdown`        | Stop the hub gracefully                             |
| `+hubinfo`         | Show OS / CPU / RAM / uptime / connected user counts |
| `+uptime`          | Just the uptime line                                |
| `+userlist`        | Online users                                        |
| `+usercleaner`     | Prune stale registrations                           |
| `+ban <nick>`      | Ban a user (see cmd_ban for full syntax)            |
| `+gag <nick>`      | Mute a user temporarily                             |

A full command list is generated in-hub by `+help`. Each registered
plugin appends its own entries.

---

## Troubleshooting

| Symptom                                                    | Likely cause                                                        |
|------------------------------------------------------------|---------------------------------------------------------------------|
| Hub starts but `[BOT]HubSecurity` keeps warning about dummy| `dummy` not yet `+delreg`'d                                         |
| TLS port 5001 binds but client cannot connect              | Self-signed cert; accept the warning once OR generate a CA-signed cert |
| `+help` from main chat returns "I am the Hubbot…"          | Older issue, fixed in modernization PR #13 (5.4 build only)         |
| `wmic` errors on Windows 11 24H2+                          | Older issue, fixed in modernization PR closing #16                  |
| `+hubinfo` crashes on `attempt to concatenate a nil value` | Older bug, fixed in modernization PR closing it                     |
| Hub starts but does not bind ports                         | Cert path wrong in `ssl_params`, OR firewall blocking, OR another process on the port |

> TODO(maintainer): expand this with deployment-specific debugging
> patterns (systemd unit failures, log lines that point to specific
> misconfigurations).

---

## Where to look for more

- The shipped `cfg/cfg.tbl` itself — every key has an inline comment
- [PLUGIN_API.md](PLUGIN_API.md) - the plugin API reference
- [SCRIPTS.md](SCRIPTS.md) — bundled plugin reference + rate-limit configuration
- [SECURITY.md](SECURITY.md) - threat model, at-rest crypto, file permissions
- [BLOCKLIST.md](BLOCKLIST.md) - blocklist engine, GeoIP, feeds, proxy detection
- [BACKUP.md](BACKUP.md) - encrypted automatic backups + offline restore
- [HTTP_API.md](HTTP_API.md) - inbound HTTP/JSON management API
- [WEBHOOKS.md](WEBHOOKS.md) - inbound signed-webhook receiver
- [CACERT.md](CACERT.md) - CA-bundle reconciliation
- [TRANSLATING.md](TRANSLATING.md) - language files + Weblate workflow
- [docs/phases/](phases/) — modernization journals (what changed and why)
