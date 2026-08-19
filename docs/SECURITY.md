# Security model

This document describes the security boundaries luadch enforces, the
trust assumptions it makes about its operating environment, and the
design rationale behind the at-rest data protections introduced in
the Phase 7 security audit.

It is the authoritative reference for operators deciding how to deploy
luadch and for contributors reviewing security-relevant changes. The
detailed audit findings live in
[`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md).

- 🕵️ [1. Threat model](#1-threat-model)
- 🤝 [2. Plugin trust contract](#2-plugin-trust-contract)
- 🔑 [3. Password storage and the ADC `BASE` constraint](#3-password-storage-and-the-adc-base-constraint)
- 🔒 [4. File-permission baseline](#4-file-permission-baseline)
- 🌐 [5. Network-level defenses](#5-network-level-defenses)
- 🔐 [6. TLS configuration](#6-tls-configuration)
- 🐛 [7. CVE / dependency tracking](#7-cve--dependency-tracking)
- 📣 [8. Reporting a security issue](#8-reporting-a-security-issue)
- 📜 [9. Audit history](#9-audit-history)

---

## 1. Threat model

The hub serves untrusted ADC clients on the public internet. The
classes of attacker we defend against:

| Attacker | Capability | Defended against? |
|---|---|---|
| Network attacker | Can send arbitrary bytes to the listening ports | yes |
| Authenticated user | Has valid credentials, opens a normal session | yes |
| Backup thief | Reads `cfg/`, `certs/` from a snapshot or unprotected backup, no host access | yes |
| World-readable share | Hub data ends up on a misconfigured Samba / NFS / Dropbox mount | yes |
| Local file-write | Has filesystem write to `cfg/` but no shell on the host | partially (RCE eliminated; file-tamper still causes load-fail) |
| Host-level RCE / shell | Can read process memory, exec arbitrary code | **no** |
| Plugin author | Writes a malicious script and the operator installs it | **no** (see §2) |

The "host-level RCE" row is the one that matters most: ADC's password
challenge protocol forces the hub to keep a password-equivalent secret
in process memory while the hub runs (see §3). Anyone who breaks out
of the host's OS-level isolation can read it. The same trade-off
applies to Firefox's primary password, Telegram's local DB, and Apple
Keychain in its unlocked state. We accept it as a protocol constraint.

---

## 2. Plugin trust contract

Plugins under [`scripts/`](../scripts/) are **trusted by design**.
The trust boundary is between "operator-installed plugin" and
"untrusted ADC client", **not** between "plugin" and "core".

[`core/scripts.lua`](../core/scripts.lua) builds each plugin's
`_ENV` from an explicit `SANDBOX_GLOBALS` whitelist (added in
[#206](https://github.com/luadch-ng/luadch-ng/issues/206)). `os` and
`io` are curated shims: `os` exposes only `time` / `date` /
`difftime`; `io` exposes only a path-restricted `open` (relative
paths, no `..` traversal) - `io.popen`, `io.lines`, `package`,
`require`, and `debug` are NOT reachable. Subprocess access lives
in a separate [`core/sysinfo.lua`](../core/sysinfo.lua) module
that exposes a small audited surface for the bundled
`cmd_hubinfo` plugin.

The same path-restriction gate covers the plugin-callable I/O
functions exported by [`core/util.lua`](../core/util.lua)
(`checkfile`, `loadtable`, `savetable`, `savearray`, `maketable`,
`atomic_write`) via the shared `util.safe_path` helper - closed
in [#266](https://github.com/luadch-ng/luadch-ng/issues/266) where
`util` had previously captured the unsandboxed `io.open` at module
load and bypassed `_io_safe`.

These mechanisms are **defence-in-depth**, not a hard boundary. A
malicious plugin can still:

- Read any file under the hub's working directory via the
  permitted relative-path range (e.g. `cfg/master.key`,
  `certs/serverkey.pem`).
- Write `.tbl` content to any permitted relative location.
- Reach all hub-internal data: in-RAM cleartext of `user.tbl`,
  the full plugin sandbox table, every other loaded plugin.

The gate raises the floor for accidental escapes by buggy
plugins; it does not protect against an actively malicious one.
`cfg.no_global_scripting` adds an error-on-undeclared-globals
metatable on top, also defence-in-depth.

**Operator responsibilities:**

1. Audit every plugin you install. Read the source. Do not pull
   plugins from random forums.
2. Treat the `scripts/` directory like the rest of the hub binary:
   write-protect it from non-admin users on the host.
3. A compromised plugin trivially exfiltrates `cfg/master.key`,
   `certs/serverkey.pem`, and the in-RAM cleartext of `user.tbl`.
   No in-hub mechanism prevents that.

The corresponding audit finding is
[F-SAND-1](phases/PHASE_7_FINDINGS.md) (info-level; #206 / #213 /
#266 are incremental hardening on top, not a "fix" - tightening
the sandbox further would break the existing plugin ecosystem).

### HTTP API admin tokens are total-trust

An `admin`-scope HTTP API token can do everything `+masteruser` can
do, including:

- Read its own and every other admin token's audit-log bodies via
  `GET /v1/log/api`. Bodies for routes that opt into the
  [`HTTP_API.md`](HTTP_API.md) §8 redact mechanism
  (`audit_redact_body = true` - currently the two
  password endpoints) log as `[redacted]` even to admin readers,
  but everything else is plaintext.
- Issue `POST /v1/restart` / `POST /v1/shutdown` / `POST /v1/reload`.
- Toggle plugins (`PUT /v1/plugins/{name}/enabled`).
- Mutate any non-denylisted cfg key (`PUT /v1/config/{key}`).
- Bypass ADC `+unban` level checks (HTTP-created bans persist with
  `by_level = 100`).

Treat the admin token like the `+masteruser` password. Rotate it
on operator turnover; never embed it in a non-loopback-reachable
process; use `comment` to label tokens so audit lines are
traceable.

---

## 3. Password storage and the ADC `BASE` constraint

luadch implements the ADC `BASE` extension's HPAS challenge-response:

```
Server: IGPA <fresh_per_login_salt>
Client: HPAS base32(Tiger(password || salt))
Server: must compute Tiger(stored, salt) and match
```

The salt is CSPRNG-backed (OpenSSL `RAND_bytes` via `adclib`) and freshly
generated per login. Its length is **24 bytes** (39 base32 chars on the wire),
the ADC 1.0.1 minimum ("at least 24 random bytes"); raised from an earlier
6-byte default in [#551](https://github.com/luadch-ng/luadch-ng/issues/551).

For the server's hash to match the client's, **the stored value must
equal the client's password input**. Any one-way KDF (Argon2id,
bcrypt, scrypt, PBKDF2) makes the server unable to produce the same
Tiger output, so login breaks. This constraint is shared by the
entire ADC ecosystem (ADCH++ stores cleartext in XML, uHub in
`users.conf`, …) and there is no published ADC extension that lifts
it. The audit research is recorded in issue
[#52](https://github.com/luadch-ng/luadch-ng/issues/52).

### What luadch actually does

1. **In RAM, while the hub runs:** plaintext passwords are present as
   field values on each registered user's profile object. There is
   no way around this within standard ADC.
2. **On disk:** `cfg/user.tbl` is AES-256-GCM encrypted under a
   host-bound master key (Phase 7f, [F-AUTH-1](phases/PHASE_7_FINDINGS.md)).

### Wire format on disk

```
offset  bytes
  0     4    magic "LDC1"
  4    12    nonce (96-bit, fresh per write via OpenSSL RAND_bytes)
 16    N     ciphertext
16+N   16    GCM authentication tag
```

GCM authentication is the security-critical signal: a tampered file
fails the tag check and `loadusers` returns an error. The hub does
not silently accept tampered input.

`cfg/user.tbl` is **not** a SQLite database (a SQLite GUI cannot open
it and there is no "password" - the secret is the 32-byte key file).
It is a Lua table (`return { ... }`); the LDC1 layer just encrypts
that same serialized form.

### Inspecting / editing user.tbl offline

To read or edit the registered-user database by hand (account
recovery, bulk edit) while keeping encryption on, decrypt it offline
with the matching `master.key` using [`tools/usertbl.py`](../tools/usertbl.py):

```sh
python tools/usertbl.py decrypt cfg/user.tbl cfg/master.key -o user.plain.lua
#   ... edit user.plain.lua (plain Lua) in a text editor ...
python tools/usertbl.py encrypt user.plain.lua cfg/master.key -o cfg/user.tbl
```

- **Stop the hub first.** A running hub holds `user.tbl` in RAM and
  rewrites it from that copy on the next save, silently clobbering an
  offline edit.
- The decrypted plaintext holds password-equivalent secrets; treat it
  and `master.key` like the TLS private key (`0600`, delete the
  plaintext when done).
- `master.key` and the `user.tbl` it sealed are a **matched pair** -
  back them up **together**. An old `user.tbl` snapshot without its
  contemporaneous key is unrecoverable by design.
- If you would rather avoid the key requirement entirely, use the
  `encrypt_usertbl = false` opt-out below instead - the hub then writes
  plaintext Lua directly, no tool needed.

### Master key

- **Default path:** `cfg/master.key` (set the `master_key_path` cfg
  key to override; see "Backup separation" below)
- **Size:** 32 raw bytes (AES-256)
- **Generation:** automatic on first boot via OpenSSL `RAND_bytes`
- **POSIX permissions:** `chmod 600`. The hub **refuses to start** if
  the existing key file has any other mode (modeled on OpenSSH's
  `~/.ssh/id_rsa` strict-mode check).
- **Windows permissions:** see §4 below.

### Backup separation - **required for the encryption to be meaningful**

The default `cfg/master.key` location was chosen for first-boot
convenience and backwards compatibility, **not** for production
security. With the default, a routine
`tar czf backup.tar.gz cfg/` bundles **both** the encrypted
`user.tbl` AND its decryption key into one archive. An attacker who
exfiltrates that backup decrypts everything offline; the at-rest
encryption provides zero protection in that scenario.

For production deployments, set the `master_key_path` cfg key in
`cfg/cfg.tbl` to an absolute path **outside** the install directory:

```lua
master_key_path = "/etc/luadch/master.key"            -- POSIX
master_key_path = "C:/ProgramData/luadch/master.key"  -- Windows
```

Then handle that path the same way you handle
`certs/serverkey.pem`:

- exclude it from the routine `cfg/` backup, or
- back it up to a separate destination (different host, different
  storage tier, or pass-phrase-encrypted archive).

The hub still enforces 0600 on the configured path on POSIX. On
Windows, apply `icacls` to the new path - see §4.

The built-in encrypted backup ([`docs/BACKUP.md`](BACKUP.md), #480) is the
pass-phrase-encrypted archive this section recommends: the `.ldbk` is sealed
with AES-256-GCM under an operator passphrase independent of `master.key`, and
`etc_backup_include_master_key = false` keeps the key out of the archive
entirely - so an exfiltrated backup does not hand over both halves. Prefer it
over a raw `tar czf cfg/`.

### What the on-disk encryption protects against

- Backup / snapshot exfiltration of `cfg/` without the host - **only
  if `master_key_path` points outside `cfg/` per the section above**
- World-readable `cfg/user.tbl` from a default umask
- File-system-only read primitive (read-only mount, share, lost
  laptop, …)

### What it does NOT protect against

- On-host RCE / Lua-sandbox escape (see §1, §2)
- Plugin compromise (see §2)
- Master-key file theft. If the attacker exfiltrates both
  `cfg/master.key` and `cfg/user.tbl`, they have all the credentials.

OS-bound key wrapping (TPM, DPAPI machine-scope, libsecret, macOS
Keychain) would harden the master-key-theft case and is tracked as a
Phase 8+ candidate in
[#48](https://github.com/luadch-ng/luadch-ng/issues/48).

### Operator opt-out: `encrypt_usertbl = false` ([#128](https://github.com/luadch-ng/luadch-ng/issues/128))

Some deployments do not need disk-level confidentiality and prefer
the operational convenience of a plaintext `user.tbl` (custom backup
scripts, third-party admin UIs that read the file directly, ad-hoc
inspection with a text editor, recovery without the master key as a
hard requirement). For those, the cfg toggle `encrypt_usertbl` can be
flipped to `false` in `cfg/cfg.tbl`:

```lua
encrypt_usertbl = false,
```

Default: `true`. New deployments and upgrades from earlier v3.1.x
keep encryption on.

**What you give up by setting it to false:**

- Backup confidentiality. A routine `tar czf cfg.tar.gz cfg/`
  exfiltrates plaintext user passwords. ADC mandates the hub
  hold password-equivalents in RAM; with the toggle off, the same
  values land on disk in `return { ... }` Lua source.
- Stolen-disk protection. An attacker who walks off with the
  host's disk reads `user.tbl` directly.
- The forced-confidentiality default that makes a casual
  `tar` / `scp` / cloud-sync transfer non-leaky.

**What you keep regardless of the toggle:**

- `chmod 600` on `user.tbl` on POSIX (still set by `saveusers`).
- The atomic-write + always-fresh `.bak` flow (closes upstream
  `luadch/luadch#189`).
- Sandboxed `loadtable` on the plain-Lua-source path (the
  `loadfile(path, "t", { })` empty-`_ENV` from Phase 7e blocks RCE
  on a tampered `user.tbl` regardless of the encryption toggle).

**Migration is automatic in both directions:**

- `true` -> `false`: the next `saveusers` writes `user.tbl` as plain
  Lua source. Until then, the encrypted file on disk still decrypts
  on read via the existing `master.key` (the key file is loaded as
  long as it exists on disk, regardless of the toggle).
- `false` -> `true`: the next `saveusers` writes an LDC1 blob using
  `master.key` (auto-generated if missing).
- Existing `user.tbl` files in either format auto-detect on load via
  the LDC1 magic prefix, so no operator action is required during
  the toggle flip itself.

Pick the toggle based on your threat model. Public-facing hub on a
shared host: keep the default (`true`). Single-user home hub on a
private host where the disk-level threat model is "if my disk
leaves my house I have bigger problems": `false` is reasonable. The
hub does not assume which one applies.

### Password disclosure in command replies ([#95](https://github.com/luadch-ng/luadch-ng/issues/95))

The same cleartext-equivalent password the hub must hold for the ADC
`BASE` challenge (F-AUTH-1, above) used to be echoed back over the
chat / PM channel by four admin commands. On a plain-ADC listener that
exposes the value on the wire; even on TLS it lands in the client's
local chat log (DC++ keeps one by default).

**Redacted (PR [#119](https://github.com/luadch-ng/luadch-ng/pull/119)):**

- `+accinfo` and `+usersearch` show `<REDACTED>` in the password
  column of every output format (the pre-existing permission gate is
  unchanged: a denied row still shows `<Not allowed to view>`).
- `+setpass` no longer echoes the new password back to the **caller**
  (who typed it, or is the target). The **target** of an admin
  `+setpass nick <NICK> <PASS>` still receives it via PM - they need
  it to log in.

**Opt-in reversal - `show_reguser_password` (default false).** Operators
repeatedly reported a workflow the redaction breaks: a user forgets their
password and asks an op for it, and many users cannot self-reset. The cfg
key `show_reguser_password` (shared by `cmd_accinfo` and `cmd_usersearch`,
default false) restores the pre-redaction behaviour when set true -
`+accinfo` / `+accinfoop` and `+usersearch` then show the stored password
instead of `<REDACTED>`. This is a deliberate operator tradeoff: enabling
it puts the cleartext-equivalent password back into chat/PM and thus into
client-side (and any hub-side) chat logs, exactly the exposure the
redaction closed. Two bounds still hold regardless: the per-user hierarchy
gate (an op only sees passwords of users it may already inspect; a
`+usersearch` row otherwise shows `<Not allowed to view>`), and the HTTP
API, which never exposes the password field. `+usersearch` is a BULK view
- a broad query can list many passwords in one reply - so it is the
higher-exposure of the two. The default stays redacted; a single shared
key (not a per-plugin pair) is deliberate so the two paths cannot drift,
and it is the supported escape hatch for operators who would otherwise
hand-edit the plugin source.

**`+reg` auto-generated password: delivered by design, not a defect.**
`+reg` generates the password with `util.generatepass()` and it must
reach the new user for their first login. In a base DC hub the only
in-hub channel is a private message, so `+reg` PMs the value to the
new user (when online) and to the registering admin. The admin copy
is **required** for the offline-target case: if the registered nick is
not connected, the admin is the only party who receives the password
and conveys it out of band - dropping it would leave a freshly
registered user unable to log in. This is a directed disclosure to the
two parties who need the value, not a broadcast; the opchat reg-report
(`report.send`) never contains the password. The residual exposure
(the value sits in the admin's and the new user's local client logs)
is inherent to password-based ADC registration without an external
side channel, and is mitigated by the at-rest encryption above plus
the `cmd.log` redaction from
[#96](https://github.com/luadch-ng/luadch-ng/issues/96). A leak-free
delivery (SMTP invite via [#100](https://github.com/luadch-ng/luadch-ng/issues/100),
or a first-login token flow) is a Phase 8+ candidate that depends on
infrastructure luadch does not yet ship; until then the chat-delivery
behaviour is retained deliberately.

---

## 4. File-permission baseline

The hub automatically `chmod 600`s every secret file it writes on
POSIX (Phase 7b,
[F-SEC-1](phases/PHASE_7_FINDINGS.md)). That covers:

- `cfg/user.tbl` (registered-user database, encrypted blob)
- `cfg/user.tbl.bak`
- `cfg/master.key`
- `log/audit-YYYY-MM-DD.jsonl` (#84 staff-action audit trail;
  `etc_auditlog` `chmod_secret`s the file on first write per
  daily path).
- `certs/serverkey.pem` and `certs/cakey.pem` are 0600'd by
  `examples/certs/make_cert.sh` at generation time.

### Linux / BSD - one-time migration

Existing deployments that pre-date Phase 7b should run once:

```sh
chmod 600 cfg/user.tbl cfg/user.tbl.bak certs/serverkey.pem certs/cakey.pem
# master.key is created by Phase 7f and ships pre-chmod'd. If you
# moved it via master_key_path, chmod that path too.
```

### Windows - manual ACL setup

NTFS does not have POSIX permission bits, so the hub does not
attempt to enforce permissions automatically. After install, run:

```cmd
icacls "cfg\user.tbl"           /inheritance:r /grant:r "%USERNAME%:F"
icacls "cfg\user.tbl.bak"       /inheritance:r /grant:r "%USERNAME%:F"
icacls "cfg\master.key"         /inheritance:r /grant:r "%USERNAME%:F"
icacls "log"                    /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\serverkey.pem"    /inheritance:r /grant:r "%USERNAME%:F"
icacls "certs\cakey.pem"        /inheritance:r /grant:r "%USERNAME%:F"
```

Replace `%USERNAME%` with the dedicated service account if the hub
runs as `LocalService` or similar. If `master_key_path` points to a
different location (e.g. `C:\ProgramData\luadch\master.key`), apply
the same `icacls` line there. The same recipe lives in
[`docs/BUILDING.md`](BUILDING.md).

### Audit log of staff actions ([#84](https://github.com/luadch-ng/luadch-ng/issues/84))

`log/audit-YYYY-MM-DD.jsonl` is the centralised, machine-readable
record of every staff action across both ADC chat (`+ban`, `+reg`,
`+disconnect`, ...) and the HTTP API (`POST /v1/registered`,
`DELETE /v1/users/{sid}`, ...). One JSON object per line; see
[`SCRIPTS.md` etc_auditlog](SCRIPTS.md#etc_auditlog) for the shape
and the full action vocabulary.

**Append-only contract.** `scripts/etc_auditlog.lua` opens the
file via `io.open(path, "ab")` exclusively. No code path in the
plugin truncates the active file. There is no
`DELETE /v1/log/audit` endpoint and no `+clearauditlog` ADC cmd.
Clearing is filesystem-level only (operator deletes the file
with explicit OS chain-of-custody). This is deliberate: a
mutable audit trail provides no compliance value.

**chmod 0600.** First write to each new daily path triggers
`util.chmod_secret(path)` (POSIX). Audit lines carry target IPs,
CIDs, and actor session metadata; world-readable defaults would
leak operator activity. Per-process tracking set ensures the
chmod fires once per file, not once per event.

**Retention.** `etc_auditlog_retention_days` (default 90). On
each UTC-midnight rollover (and once at boot) the plugin
unlinks any `audit-*.jsonl` whose embedded date is older. Set
`0` to disable the sweep; operator-driven cleanup then. The
sweep probes by reconstructing the known filename pattern day
by day from `now - retention_days - 1` back to `now -
retention_days - 365` (sandboxed plugins cannot enumerate the
directory; this approach handles retention shrinkage).

**Plugin trust contract.** Any admin-trusted plugin can call
`audit.fire(audit.build(...))` with arbitrary actor / target /
reason fields. The audit log is therefore as trustworthy as the
plugin set in `cfg.scripts`. This is the same baseline as
[`§2 Plugin trust contract`](#2-plugin-trust-contract):
operators MUST review every third-party plugin before enabling
it. A malicious plugin could spoof audit entries; the file's
append-only contract bounds the damage to "addition only, no
deletion of legitimate entries". The four-fields-snapshotted-at-
fire-time invariant (`core/audit.lua` `_snapshot_actor`) means
even a misbehaving plugin cannot fabricate a different actor's
session metadata than its own at the moment of fire.

**Field caps.** `audit_log_max_reason_chars` (default 1000) and
`audit_log_max_meta_value_chars` (default 1000) bound per-string
length at `audit.build` time, applied to both the disk JSONL and
the `/v1/events` ringbuffer entries. Defense against a malicious
input ballooning a single log line.

**Control-byte sanitization.** Every string field that lands on
disk or in the events ringbuffer is `util.strip_control_bytes`'d
at build time (`core/audit.lua` `_safe_str` for user-object
snapshots, `_normalize_str` for flat-table input). INF-derived
strings are F-INF-2-clamped at parse time too, so this is
defense-in-depth.

### cfg-level secrets, env-var fallback, and HTTP API redaction

Some cfg keys hold authentication material (HTTP API bearer tokens,
future plugin API keys) or paths that protect at-rest encryption.
These are tracked in a SINGLE registry at
[`core/secrets.lua`](../core/secrets.lua) - the same module that
`GET /v1/config` redaction consults and that plugin secrets-lookup
helpers go through.

**Registry semantics.** A cfg key registered via
`secrets.register(cfg_key)` is treated as sensitive for the
process lifetime:

- `GET /v1/config` masks its value as `"<redacted>"`.
- `PUT /v1/config/{key}` returns `403 E_FORBIDDEN` (rotate via
  direct `cfg.tbl` edit + restart).
- Future `+showcfg` / `+config show` cmds (when added) will
  consult the same registry.

Baseline registrations are seeded by `secrets.init()`:

- `http_api_tokens` (HTTP API auth tokens, existed pre-arc).
- `master_key_path` (cfg_secret encryption key path, existed
  pre-arc).

Plugins register their own sensitive keys at `onStart`:

```lua
local secrets = use "secrets"
secrets.register( "etc_geoip_license_key" )
secrets.register( "etc_proxydetect_api_key" )
secrets.register( "etc_status_push_token" )   -- heartbeat bearer token
-- etc_webhook registers one HMAC secret PER configured endpoint,
-- dynamically named etc_webhook_<name>_secret, e.g.:
secrets.register( "etc_webhook_discourse_secret" )
```

`register()` is exposed to every plugin via `SANDBOX_GLOBALS` and
takes effect for the process lifetime - the same trust assumption
as §2 applies. A hostile plugin can hide a live cfg key from
`GET /v1/config` by registering it, but the sandbox already grants
worse capabilities (file I/O, network, hub state). The registry is
defense-in-depth alongside the per-key chmod baseline above, not a
plugin-trust boundary.

**Env-var-first lookup.** Plugins that need an API key call
`secrets.lookup(cfg_key)` instead of `cfg.get(cfg_key)`. The helper
checks `LUADCH_<UPPER_CFG_KEY>` (e.g. `LUADCH_ETC_GEOIP_LICENSE_KEY`)
first, then falls back to `cfg.get`. Empty strings in either
location are treated as unset, so an accidentally blank env var
does NOT mask a populated cfg value.

Use cases:

| Deployment | Where the key lives | Why |
|---|---|---|
| Docker / docker-compose | `environment:` section of the service | Survives container restarts; never written to disk; trivial rotation via `docker compose up -d` after a value change |
| Bare-metal (Linux / Windows) | `cfg/cfg.tbl` (chmod 600 / icacls applied per the recipes above) | Stable across reboots; no env var to forget |
| CI / staging | `LUADCH_*` env var injected by the orchestrator | Separation between code-config (cfg.tbl in repo or volume) and secrets (injected per environment) |

Mixed deployments are allowed - any individual key can travel via
env, via cfg, or both (env wins).

**Why env-var-first and not encrypted-cfg.** The hub-itself already
encrypts `cfg/user.tbl` (Phase 7c F-AUTH-1) but `cfg.tbl` itself is
plain on disk with chmod 600. Encrypting individual cfg keys
introduces an at-rest-secrets-management problem that the existing
master-key path already solves at the user.tbl scope. The env-var
fallback gives Docker operators a path that does not touch disk at
all (env vars live in `/proc/<pid>/environ`, readable only by the
process owner), and bare-metal operators a path that mirrors how
they already manage `cfg.tbl` (chmod 600 + backup separation).

**Process-environ leak surface.** `os.getenv` reads from the
process environment, which Linux exposes via `/proc/<pid>/environ`
to the process owner. Run the hub under its own dedicated user;
the per-OS hardening recipes above already cover this.

### Inbound webhook auth (`etc_webhook`)

`etc_webhook` (operator guide: [`docs/WEBHOOKS.md`](WEBHOOKS.md)) is the
first plugin to register an HTTP route with **`scope = "none"`** - the
router's bearer-token gate is skipped and the handler does its OWN
authentication:

- **HMAC-SHA256 over the raw body.** Each endpoint has a shared secret;
  the handler recomputes `hmac.sha256(secret, req.raw_body)` (the exact
  received bytes, before any re-encode) and compares it to the sender's
  signature header (`X-Discourse-Event-Signature` /
  `X-Hub-Signature-256`) with `adclib.constant_time_eq`. A missing or
  wrong signature returns 401 and nothing is announced. An endpoint with
  no resolvable secret is not even registered (it can never run
  unsigned).
- **Secret at rest.** Per-endpoint secrets resolve env-var-first
  (`LUADCH_ETC_WEBHOOK_<NAME>_SECRET`), else the
  `etc_webhook_<name>_secret` cfg key, else inline in the chmod-600
  `cfg/webhooks.tbl` (which is NOT emitted by `GET /v1/config`). The
  value is never logged (debug lines name the key / env-var only).
- **Replay / dedup.** Duplicate deliveries (sender retried) are dropped
  by the delivery-id header (`X-Discourse-Event-Id` /
  `X-GitHub-Delivery`), bounded to `dedup_max` entries.
- **Content safety.** Every templated field is control-byte-stripped and
  length-capped before broadcast; a per-minute flood cap bounds chat
  spam. The announcement carries only the operator-authored template +
  public payload fields.
- **Exposure.** The HTTP listener is plain HTTP on `127.0.0.1` by
  default and only binds once a token is configured; a webhook reachable
  from the internet must sit behind a reverse proxy terminating TLS. The
  64 KiB request-body cap is global - an oversized signed delivery is
  rejected (a missed announcement, not a vulnerability).

---

## 5. Network-level defenses

| Defense | Where | Tunable via cfg |
|---|---|---|
| Per-IP parallel-socket cap | [`core/server.lua` accept](../core/server.lua) | `ratelimit_perip_max_conns` (default 16) |
| Per-IP accept-rate cap | same | `ratelimit_perip_conn_rate` / `_burst` |
| TLS handshake wallclock deadline | same | `ratelimit_handshake_timeout` (default 10s) |
| Per-IP failed-auth tracking + sticky lockout | [`core/hub_dispatch.lua` HPAS](../core/hub_dispatch.lua) | `ratelimit_perip_authfail_*`, `ratelimit_authfail_lockout` |
| Per-account bad-password lockout (independent of per-IP) | same | `max_bad_password`, `bad_pass_timeout` |
| Per-user mainchat rate-limit | [`core/hub_dispatch.lua` BMSG](../core/hub_dispatch.lua) | `ratelimit_user_msg_*` |
| Per-user PM rate-limit ([#80](https://github.com/luadch-ng/luadch-ng/issues/80)) | [`core/hub_dispatch.lua` DMSG/EMSG](../core/hub_dispatch.lua) | `ratelimit_user_pm_*` |
| Per-user BINF-update rate-limit ([#80](https://github.com/luadch-ng/luadch-ng/issues/80)) | [`core/hub_dispatch.lua` BINF](../core/hub_dispatch.lua) | `ratelimit_user_inf_*` |
| Per-user CTM/RCM rate-limit ([#80](https://github.com/luadch-ng/luadch-ng/issues/80)) | [`core/hub_dispatch.lua` DCTM/DRCM](../core/hub_dispatch.lua) | `ratelimit_user_ctm_*` |
| Per-user search rate-limit | [`core/hub_dispatch.lua` BSCH](../core/hub_dispatch.lua) | `ratelimit_user_search_*` |
| Per-userlevel tier overlay ([#80](https://github.com/luadch-ng/luadch-ng/issues/80)) | [`core/ratelimit.lua` init](../core/ratelimit.lua) | `ratelimit_tiers`, `ratelimit_tier_for_level` |
| Op-level bypass of per-user limits | [`core/ratelimit.lua`](../core/ratelimit.lua) | `ratelimit_bypass_level` (default 60) |
| Parser-side message-size cap | [`core/adc.lua` parse](../core/adc.lua) | hardcoded 64 KiB |
| Connection read-buffer cap | [`core/server.lua`](../core/server.lua) | hardcoded 1 MiB |
| INF-IP consistency check (kick on TCP-source vs INF-claim mismatch) | [`core/hub_dispatch.lua` BINF](../core/hub_dispatch.lua) + [`scripts/hub_inf_manager.lua`](../scripts/hub_inf_manager.lua) | `kill_wrong_ips` (default **false** since v3.2.x; see operator note below) |

The full DoS-hardening rationale is in Phase 7c
([#56](https://github.com/luadch-ng/luadch-ng/issues/56)).

### `kill_wrong_ips` operator note ([#97](https://github.com/luadch-ng/luadch-ng/issues/97))

The `kill_wrong_ips` default flipped from `true` (v3.1.4 through
v3.1.x) back to `false` in v3.2.x. The motivation for the v3.1.4
strict default was to prevent a client from broadcasting a spoofed
`I4` / `I6` value to other peers (DDoS-amplification risk: peers
would direct CTM / RCM connection attempts at the spoofed
victim address). Since v3.2.x that vector is closed at a lower
level - the
[#214 Gap 2 fix](https://github.com/luadch-ng/luadch-ng/issues/214)
in [`core/hub_dispatch.lua`](../core/hub_dispatch.lua) overrides
any client-claimed mismatched IP with the authenticated TCP source
IP **before** broadcasting, regardless of `kill_wrong_ips`. The
gate is therefore no longer protecting anything by construction;
it only controls whether a mismatched-claim user is killed (loud)
or has their broadcast INF silently corrected (lenient).

The legitimate **passive-mode `I40.0.0.0`** case is handled before
the gate (the hub fills in the real IP), so passive clients are
unaffected either way.

**With `kill_wrong_ips = false` (new default):**

- Clients whose INF-advertised IP does not match their TCP source -
  a VPN client with a stale cached IP, a client hand-set with the
  wrong External / WAN IP, a dual-stack client where the kernel
  picked a different outbound family than the configured advertise -
  stay connected instead of being kicked. Their broadcast INF is
  rewritten to the authenticated TCP source IP, so peers reach them
  correctly wherever that source IP is itself reachable (VPN-egress,
  single-NAT). This gate only concerns the advertised-vs-source
  *mismatch*; it is unrelated to how the hub blocks users - e.g. the
  Traffic Manager, which on 3.x decides on level / share / account-nick,
  not IP ([#364](https://github.com/luadch-ng/luadch-ng/issues/364)).
- The edge case where the user's TCP source genuinely cannot reach
  their P2P listener (multi-WAN with policy routing, certain
  corporate setups) becomes a silent failure: user stays online,
  P2P connections from peers fail. Empirically this group is small
  in practice (such users typically either run passive mode or are
  CGNAT-blocked from active mode anyway).

**With `kill_wrong_ips = true` (opt-in):**

- Mismatched-IP clients get an explicit kick on login with an
  actionable hint pointing them at their client's
  `External / WAN IP` setting (PR
  [#331](https://github.com/luadch-ng/luadch-ng/pull/331)). Operator
  sees these kicks in `log/error.log` for diagnostics.
- Picks a louder failure mode over a silent one: useful for hubs
  with a known-tightly-configured userbase where any mismatch is
  almost certainly an operator-fixable client problem.

Per-IP rate limits, GeoIP / unified blocklist matches, abuse logs,
and any plugin reading `user:ip()` operate on the **TCP source IP**
regardless of this toggle - none of those primitives depend on
the kill semantic.

### Dual-stack secondary-address verification ([#214](https://github.com/luadch-ng/luadch-ng/issues/214), HBRI)

Since v3.2.x luadch accepts a BINF that carries BOTH `I4` and `I6`
in one frame, so a dual-stack peer can advertise both
([#147](https://github.com/luadch-ng/luadch-ng/issues/147) T3.1). The
hub can only authenticate the field matching the **connecting** TCP
source's family against the actual TCP source IP - it has no socket
on the other family through which to verify the secondary address.

Broadcasting an *unverified* secondary would be a DC++
**DDoS-amplification** vector: a dishonest client could advertise an
arbitrary victim IP as its secondary, and other clients would then
direct CTM / RCM connection attempts at that address (the historical
DC++ DDoS pattern -
[Wikipedia](https://en.wikipedia.org/wiki/Direct_Connect_(protocol)#Direct_Connect_used_for_DDoS_attacks)).
This is **not** an unavoidable trade-off; luadch closes it two ways:

- **Strip by default (Gap 1).** For every client, the unverified
  secondary family's address (`I4` / `I6`), UDP port (`U4` / `U6`)
  and transport SU flags (`TCP4` / `UDP4` / `TCP6` / `UDP6`) are
  **stripped before the INF is stored or broadcast**, in
  [`core/hub_dispatch.lua`](../core/hub_dispatch.lua)'s BINF handler.
  Only the authenticated primary family is ever advertised to other
  users. A dishonest secondary claim never reaches the wire.

- **Verify, then restore (HBRI, opt-in).** With `hbri_enabled` AND a
  listener on both families AND `hbri_advertise_v4` /
  `hbri_advertise_v6` set, the hub advertises `ADHBRI` and validates
  a supporting client's secondary over a second-family side-channel
  ([`core/hbri.lua`](../core/hbri.lua)): it mints a CSPRNG token,
  sends an `ITCP` pointer, and only commits + broadcasts the secondary
  once the client connects back **on the other family** and presents
  the token. The committed address is always the side-channel's
  authenticated TCP source - never a client-supplied value, and a
  connection from the claimed address is proof of reachability. A
  client may advertise either a concrete secondary or the spec
  placeholder (`I6::` / `I40.0.0.0`, the common auto-detect case): the
  placeholder makes the hub **discover** the address from the
  side-channel getpeername
  ([#291](https://github.com/luadch-ng/luadch-ng/issues/291)); a concrete
  value is accepted only if it equals that source. On validation
  failure or a `hbri_timeout`-second timeout the user enters the hub
  normally with the secondary left stripped (the Gap-1 default). The
  side-channel rides the normal accept path, so it uses the advertised
  port's transport - a client connecting back to a TLS / autossl port
  does TLS on the side-channel too (matching its main connection). HBRI
  needs a listener (plain or TLS) on both families; a family with no
  listener disables it
  ([#298](https://github.com/luadch-ng/luadch-ng/issues/298)).

Either path guarantees the broadcast INF only ever carries an address
the hub authenticated. A client that advertises its secondary only in
a **post-login** INF update (not the initial BINF) is handled the same
way ([#286](https://github.com/luadch-ng/luadch-ng/issues/286)): the
unverified `I4` / `I6` is still stripped from that update before
broadcast (the #97 / #222 closeout in
[`scripts/hub_inf_manager.lua`](../scripts/hub_inf_manager.lua) stays
in force), and only a side-channel-validated secondary is then
broadcast - the user is never removed from the normal state for the
re-validation. An *unverified* post-login `I4` / `I6` therefore still
never reaches the wire.

The primary-family sibling of this vector - `kill_wrong_ips = false`
letting a NAT-weird client's *wrong primary* claim broadcast - was
closed under #214 Gap 2: the mismatched primary claim is overwritten
with the authenticated `user:ip()` rather than forwarded.

### Rate-limit and plugin contract ([#80](https://github.com/luadch-ng/luadch-ng/issues/80))

Per-user rate limits fire **before** the plugin listener chain
inside [`core/hub_dispatch.lua`](../core/hub_dispatch.lua). When a
bucket is exhausted, the dispatcher returns from the handler with
`true` (handled), which suppresses both the rest of the dispatch
**and** the plugin `onBroadcast` / `onPrivateMessage` / `onInf` /
`onConnectToMe` / `onRevConnectToMe` listeners. Throttled messages
do not reach plugins at all.

For most plugins this is the correct semantic and matches the
pre-#80 behaviour for `BMSG` (which was already throttled). The
edge cases worth knowing about:

- **Plugins doing count-based heuristics on per-user messages**
  (e.g. "block after N suspicious CTMs from one user") see only the
  pre-throttle subset of traffic. Attackers exceeding the bucket
  hit the hub-level drop and never reach the plugin's counter.
  Operationally that's still a defence (hub drops the abuse) but
  the plugin's own logs / counters undercount.
- **Bundled plugins audited for #80 are unaffected in practice**:
  `etc_trafficmanager` does first-hit blocklist lookup (static, not
  cumulative); `hub_inf_manager` writes user state on each BINF and
  just sees a slightly stale state for one bucket-cycle until the
  next legitimate BINF; `usr_uptime` is timer-driven, not BINF-
  driven; the rest of the `usr_*` / `etc_*` plugins reading INF
  fields tolerate stale state until the next non-throttled update.

If you write a plugin and need exact message accounting, do not
rely on the dispatcher's listener fan-out alone - it is rate-
limited at the hub boundary by design.

### onSearchResult contract widening for F-class ([#147](https://github.com/luadch-ng/luadch-ng/issues/147) T1.6)

Before #147 the `onSearchResult` listener only fired on D-class
(`DRES`) - single-recipient search results. Returning a truthy value
(`return PROCESSED`) from the listener suppressed delivery to the
**one** target SID.

After #147 T1.6 the same listener also fires on F-class (`FRES`) -
feature-filtered fan-out where the message is delivered to any
client matching a feature mask. Returning truthy on the F-class
path suppresses delivery to **the entire set** of matching
recipients, not just one.

Plugins differentiate the two cases by checking the `targetuser`
arg: nil = F-class fan-out (wide impact), non-nil = D-class single
recipient.

```lua
hub.setlistener( "onSearchResult", { },
    function( user, targetuser, adccmd )
        if not targetuser then
            -- F-class. Returning PROCESSED here drops the whole
            -- feature-filtered fan-out. Use with care.
        else
            -- D-class. Returning PROCESSED drops one delivery only.
        end
        return nil    -- let it through
    end
)
```

The bundled `hub_cmd_manager.lua` only reads `user:level()` and
returns PROCESSED unconditionally on level mismatch; it tolerates
the new arg shape but operators using it should be aware that
unauthorised F-class results are now dropped for the whole
recipient set instead of per-recipient.

---

## 6. TLS configuration

luadch supports plain ADC and TLS-wrapped ADCS in parallel. Default
TLS configuration in [`core/cfg_defaults.lua`](../core/cfg_defaults.lua):

- Protocol: TLS 1.3 (`tlsv1_3`)
- Cipher list: `"HIGH+kEDH:HIGH+kEECDH:HIGH:!PSK:!SRP:!3DES:!aNULL"` (excludes PSK / SRP / 3DES / anonymous suites)
- Disabled: SSLv2, SSLv3, TLS 1.0, TLS 1.1, and renegotiation (`options = { "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1", "no_renegotiation" }`)
- Peer-cert verify: off (correct for the server-side ADC role -
  clients are unauthenticated at the TLS layer; auth happens at the
  ADC HPAS layer)

The ADC `KEYP` extension lets clients pin the hub's TLS certificate
fingerprint; operators can publish their fingerprint via the
`+hubinfo` command and clients that support `KEYP` will reject
mismatching certs.

### TLS + ZLIF (`zlif_over_tls`) - CRIME-class length leak

**Recommendation: leave `zlif_over_tls = false` on production hubs.**
The bandwidth saving stacking compression UNDER TLS is usually not
worth the residual CRIME-class risk. Plain-ADC connections see
ZLIF unconditionally when `zlif_enabled = true`; the flag below
only matters for ADCS / TLS connections.

Phase 8 S4b adds optional ADC-EXT ZLIF stream compression. ZLIF is
off by default (`zlif_enabled = false`); when an operator enables
it, a separate flag (`zlif_over_tls`, also default `false`) gates
whether ZLIF activates on TLS-wrapped connections in addition to
plain ADC.

The rationale for the second flag is the CRIME-class
chosen-plaintext-length leak that applies to **any** scheme of
"compress then encrypt". In the luadch + ZLIF + TLS deployment the
shape is:

- An attacker on the same hub PMs a victim chosen plaintext.
- The hub forwards the PM on the victim's TLS-wrapped connection,
  mixed with whatever else that connection carries (broadcast chat,
  user lists, PMs from other peers).
- The hub deflates the per-connection stream BEFORE TLS encrypts
  it, so the ciphertext **length** depends on the compressed length,
  which depends on the dictionary similarity between the attacker's
  chosen plaintext and the victim's other contents.
- A wire-level eavesdropper (LAN/ISP) observing length deltas can
  in principle infer whether the chosen plaintext matched something
  else in the victim's stream.

In practice the exploit is weak: broadcast traffic adds noise, the
attacker needs eavesdropper access on the victim's network, and
distinguishing 1-bit length deltas in a busy hub is hard. But the
mitigation cost is one cfg flag, so the safe default is `false` -
operators who want the bandwidth saving and accept the residual
risk set `zlif_over_tls = true`. Plain-ADC connections see ZLIF
unconditionally when `zlif_enabled = true`; only TLS is gated.

ZLIF also has two transport-level hardening properties enforced by
the binding ([`zlib_stream/zlib_stream.c`](../zlib_stream/zlib_stream.c)):

- **Decompression-bomb cap.** Each inflate call caps decompressed
  output at 4 MiB. Exceeding the cap raises a Lua error which the
  inbound inflate stage propagates as the pipeline's overflow
  signal, and `core/server.lua`'s read loop closes the connection.
  A 1 KB compressed payload that expands to GiB on the wire cannot
  drive runaway memory usage on the hub.
- **Malformed-input close.** zlib `Z_DATA_ERROR` / `Z_NEED_DICT` on
  a corrupted compressed stream is also surfaced as overflow; the
  hub closes rather than continuing on poisoned state.

### Outbound HTTPS verification

Plugins that make outbound HTTPS requests via
[`core/http_client.lua`](../core/http_client.lua) (hublist
announce, future external feed pulls, future proxy/VPN detection
API calls) authenticate the remote against a bundled Mozilla CA
root snapshot:

| Aspect | Default |
|---|---|
| `verify` | `"peer"` (was `"none"` before Precursor 0b of the #78 arc) |
| `cafile` | `certs/ca-bundle.pem` (bundled, 121 trusted roots; renamed from `cacert.pem` in Precursor 0d to avoid the path collision with `cert_bootstrap.lua`'s inbound TLS cafile) |
| Missing cafile behaviour | **Fail-closed** - request is rejected with a clear error rather than silently falling back to unauthenticated |
| First-boot / upgrade | `cacert_bootstrap.lua` copies the bundled file from `lib/luadch/ca-bundle.pem` (immutable system path) into the operator-facing path on first boot; SHA-256 mismatch logs WARN and leaves the operator-managed copy alone unless `ca_bundle_auto_update = true` |
| Operator opt-out | Pass `verify="none"` explicitly per call |
| Response size cap | RAM mode caps the whole response at 1 MiB. Stream-to-disk mode (`download_to_file`, Precursor 0a of the #78 arc, for large external feeds) caps the body at 50 MiB and the response headers separately at 64 KiB, so a server that never terminates its headers cannot grow the RAM buffer without limit. Integrity of the on-disk feed: only a 2xx response is written; a `Transfer-Encoding: chunked` response is rejected (not de-chunked); a `Content-Length` short read is treated as a truncation and discarded; the body streams to `<path>.tmp` and replaces `<path>` only after a complete, in-cap download (atomic rename on POSIX; a move-aside via `<path>.bak` with rollback on Windows keeps the last good file if the swap fails). A partial, non-2xx, or corrupt download therefore never replaces the last good file, and concurrent downloads to the same path are refused. The module owns the `.tmp` / `.bak` siblings. A close-delimited response (no Content-Length, no chunked) cannot have its completeness verified and is committed best-effort - point download-mode feeds at a Content-Length endpoint. The caller owns the target path (same trust boundary as the URL - never derive it from untrusted input). |
| Redirect following | **Opt-in** via `max_redirects` (default `0` = a `3xx` is returned/failed as-is, unchanged behaviour). Needed because MaxMind's GeoLite2 download endpoint 302-redirects to a signed Cloudflare-R2 URL on a different host. Guards on every hop: `Authorization` / `Cookie` / `Proxy-Authorization` are **dropped when the redirect crosses origin** (scheme/host/port) so a credential never reaches the third-party host; an `https -> http` downgrade is **refused**; the target is re-validated by `parse_url`; hops are capped (`max_redirects`, hard ceiling `MAX_REDIRECT_CEIL = 10`) and share ONE `req.timeout`. Only those three header names are stripped - a credential in a custom header (e.g. `X-Api-Key`) would survive a cross-origin hop, so callers must not combine one with `max_redirects`. |

The bundle's provenance, license, refresh recipe, and threat model
live in [`docs/CACERT.md`](CACERT.md). Refresh quarterly or when
the Mozilla NSS root store publishes a new release.

**Redirect trust boundary (SSRF).** Following a redirect widens the
outbound trust boundary: the initial URL is caller-supplied (operator
cfg), but the redirect *target* is chosen by the server that answers.
A compromised or malicious upstream can therefore point the hub at an
arbitrary host. This is bounded by the opt-in default, the hop cap, the
https-only + no-downgrade rules, and the `verify="peer"` default (an
`https://` internal target would still need a publicly-trusted cert),
but there is no RFC1918/link-local denylist - so `max_redirects` must
only be enabled for operator-configured endpoints, never for a URL
derived from untrusted (ADC-client) input. Same rule as the base
`http_client` SSRF note.

The TLS protocol floor is held at TLS 1.2 (SSLv3 / TLS 1.0 / TLS
1.1 disabled via LuaSec options) for outbound calls regardless of
verify mode, so a downgrade attack cannot land on a broken
protocol even when `verify="none"` is the operator's choice.

---

## 7. CVE / dependency tracking

luadch bundles all native dependencies as source. Operators should
subscribe to upstream releases:

- [Lua](https://www.lua.org/versions.html) - currently 5.4.8
- [LuaSec](https://github.com/lunarmodules/luasec) - currently 1.3.2
- [LuaSocket](https://github.com/lunarmodules/luasocket) - currently 3.1.0
- [aiq/basexx](https://github.com/aiq/basexx) - vendored from
  v0.4.1, upstream essentially abandoned
- [OpenSSL](https://github.com/openssl/openssl) - linked dynamically;
  `find_package(OpenSSL 3.0 REQUIRED)` enforces the floor
- [zlib](https://www.zlib.net/) - linked dynamically;
  `find_package(ZLIB REQUIRED)`. Used by the
  [`zlib_stream`](../zlib_stream/zlib_stream.c) ADC-EXT ZLIF binding
  (Phase 8 S4b); only matters at runtime when `zlif_enabled = true`

Quarterly checklist: query
[osv.dev](https://osv.dev) and the GitHub Advisory Database for each
of the above. Record the bundled SHA / version of every dep in
[`docs/BUILDING.md`](BUILDING.md) so audits compare to a written
truth, not to greps.

---

## 8. Reporting a security issue

Open a private security advisory at
<https://github.com/luadch-ng/luadch-ng/security/advisories/new> rather
than a public issue, especially for issues that:

- enable RCE without prior authentication
- bypass auth or login throttling
- leak `master.key`, plaintext credentials, or TLS keys

Public issues are fine for findings that are already documented in
[`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) or
that require operator misconfiguration to exploit (e.g. a
world-readable `master.key` because the operator skipped §4).

---

## 9. Audit history

| Phase | Scope | Doc |
|---|---|---|
| Phase 7a | Read-only audit of every surface listed in [`CLAUDE.md`](../CLAUDE.md) §5 Phase 7 | [`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) |
| Phase 7b - 7g | Each finding either fixed or filed with a documented disposition | [`docs/phases/PHASE_7_FINDINGS.md`](phases/PHASE_7_FINDINGS.md) §5 |

A future phase may re-audit. Until then, this file plus
`PHASE_7_FINDINGS.md` is the security baseline for the 3.x line.
