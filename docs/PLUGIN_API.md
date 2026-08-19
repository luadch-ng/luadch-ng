# Plugin API reference

This document is the developer-facing API reference for writing
plugins for Luadch-NG. The operator-facing catalog of bundled plugins
lives in [`SCRIPTS.md`](SCRIPTS.md); this file describes the contracts
a plugin must follow and the APIs the hub exposes to plugin code.

> **Mental model:** plugins are user-controlled Lua scripts that run
> inside the hub process. They register listeners for hub events,
> manipulate user / message / ADC-command objects, and may export
> public methods that other plugins import. The sandbox protects
> against syntax errors but **not** against malicious or wrong code -
> a plugin can call into core modules with the same authority as the
> hub itself.

- 🚀 [1. Quick start](#1-quick-start)
- 🧪 [2. Sandbox and environment](#2-sandbox-and-environment)
- 📐 [3. Plugin conventions](#3-plugin-conventions)
- 👂 [4. Listeners](#4-listeners)
- 🧱 [5. Modules](#5-modules)
- ⚙️ [6. Objects](#6-objects)
- 🔁 [7. Common patterns](#7-common-patterns)
- 📤 [8. Bundled plugin exports](#8-bundled-plugin-exports)
- ✅ [9. Testing](#9-testing)
- ⚠️ [10. Common pitfalls](#10-common-pitfalls)
- 🔗 [11. See also](#11-see-also)

---

## 1. Quick start

A minimal plugin lives in [`scripts/`](../scripts/), uses an
`etc_*`, `cmd_*`, `bot_*`, or `usr_*` filename prefix, and follows
this shape:

```lua
--[[
        scripts/etc_my_plugin.lua v0.01 by <author>

        v0.01: by <author>
            - first version
]]--

local scriptname = "etc_my_plugin"
local scriptversion = "0.01"

local hub_debug = hub.debug
local cfg_get = cfg.get

hub.setlistener( "onLogin", { },
    function( user )
        hub_debug( scriptname .. ": " .. user:nick() .. " logged in" )
        return nil    -- continue listener chain
    end
)

hub_debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {

    -- methods exported via hub.import("etc_my_plugin")

}
```

**Activation:** the file must be added to the `cfg.scripts` array in
[`cfg/cfg.tbl`](../examples/cfg/cfg.tbl) before the hub will load it.
Dropping a file into `scripts/` is **not** enough.

---

## 2. Sandbox and environment

Each plugin loads into its own restricted environment. Properties of
that environment:

- **Lua 5.4** runtime (since Phase 3).
- **The plugin env is an explicit whitelist** (since #206, 2026-05-23).
  See [`core/scripts.lua` `SANDBOX_GLOBALS`](../core/scripts.lua) for
  the live source of truth. The whitelist contains:
  - Standard Lua basics: `assert`, `error`, `pairs`, `ipairs`, `next`,
    `pcall`, `xpcall`, `select`, `setmetatable`, `getmetatable`,
    `tonumber`, `tostring`, `type`, `print`, `collectgarbage`
  - Full stdlib: `table`, `math`, `coroutine`
  - **Curated stdlib**: `os` (only `time` / `date` / `difftime`), `io`
    (only `open`, with absolute paths and `..` traversal rejected)
  - UTF-8 string lib: `string` is replaced with `utf` (a UTF-8-aware
    wrapper); plain Lua `string.*` byte methods are not directly
    reachable
  - luadch core: `hub`, `cfg`, `util`, `util_http`, `adc`, `adclib`,
    `signal`, `out`, `unicode`, `sysinfo`, `audit`, `secrets`, `hmac`,
    `whitelist`, `blocklist`, `backup` (the automatic-backup
    engine, #480; `+backup` driver `etc_backup` calls `backup.run`/
    `.readiness`/`.list`) - and more; the list above is illustrative, so
    treat `SANDBOX_GLOBALS` as the authority
  - Optional libs (may be `false` if not built): `ssl` (with `.x509`
    pre-attached), `socket`, `basexx`, `zlib_stream`, `dkjson`
- **Notably absent** (a malicious plugin cannot reach these):
  `debug`, `load`, `loadfile`, `dofile`, `require`, `package`,
  `rawget` / `rawset` / `rawlen` / `rawequal`, `_G`, `_ENV`,
  `os.execute` / `remove` / `rename` / `exit`, `io.popen`,
  `io.read` / `write` / `lines` / etc.
- **Globals are forbidden by default.** Assigning to an undeclared
  variable raises `attempt to write undeclared var: 'X'`. Use `local`
  for everything.
- **All strings must be UTF-8 encoded.** The hub does not auto-convert.
  ADC-spec mandates UTF-8 on the wire and this carries through to
  every API.
- **The `use` keyword is core-only.** Plugins cannot `use "X"` to
  import core modules. Instead, plugins access core functionality via
  the whitelisted globals listed above.
- **Type checking is mostly the script's responsibility.** Core
  modules validate inputs rarely; the public `hub.*` API performs
  some checks but most failures surface as nil-with-error or
  silent no-ops.

> **Migrating an older plugin** that worked pre-#206? See
> [`PLUGIN_SANDBOX_MIGRATION.md`](PLUGIN_SANDBOX_MIGRATION.md) for the
> old-API → new-API mapping with copy-paste examples.

### Type vocabulary

These names appear throughout this document:

| Type | Meaning |
|---|---|
| `adcstr` | A UTF-8 string with ADC-escaped whitespace (`"foo\sbar"` instead of `"foo bar"`) |
| `adcstring` | A complete ADC command frame (e.g. `"BMSG ABCD message\n"`) |
| `adccmd` | A parsed ADC-command object; see [`§6.3 adccmd object`](#63-adccmd-object) |
| `user` | A user object; see [`§6.1 user object`](#61-user-object) |
| `bot` | A bot object (subset of user behaviour); see [`§6.2 bot object`](#62-bot-object) |
| `handler` | A wrapped socket from `core/server.lua` |
| `profile` | A registered-user record table; see [`§6.4 profile table`](#64-profile-table) |

---

## 3. Plugin conventions

### 3.1 File naming

| Prefix | Purpose |
|---|---|
| `cmd_*` | Operator / user `+command` plugins |
| `bot_*` | Plugins that register a visible bot in the user list |
| `etc_*` | Cross-cutting features (managers, filters, reports) |
| `usr_*` | Per-user automation / UI sugar |

### 3.2 Plugin header

Every plugin starts with a Lua block comment containing the version
history. The harness uses the first line to display the loaded
version on startup:

```lua
--[[
        etc_my_plugin.lua v1.42 by <author>

        v1.42: by <author>
            - changes since last release

        v1.41: by <previous author>
            - their changes
]]--
```

When you bump the plugin, add a new top entry. Old entries stay -
the changelog lives in the file itself.

### 3.3 Public interface

The plugin's last statement is `return { ... }` exporting public
methods other plugins import via `hub.import()`. Example:

```lua
-- scripts/etc_my_plugin.lua
local public_helper = function( arg ) ... end

return {
    helper = public_helper,
}

-- scripts/cmd_other.lua
local mine = hub.import( "etc_my_plugin" )
mine.helper( "foo" )
```

Plugins that have no public surface still `return {}` at the end.

### 3.4 cfg.tbl whitelist

A plugin file is loaded only if its filename (without `.lua`) appears
in the `cfg.scripts` array in [`cfg/cfg.tbl`](../examples/cfg/cfg.tbl).
Order in the array determines listener-chain order - see
[`§4.3 Listener chain order`](#43-listener-chain-order).

### 3.5 Language files

Plugins with user-facing strings ship a per-language JSON file in a
per-language subdirectory (the Weblate-friendly layout since the #301
P3 i18n migration):

```
scripts/lang/en/etc_my_plugin.json
scripts/lang/de/etc_my_plugin.json
```

Each file is a JSON object of key/value strings. The hub picks the
file matching the `language` cfg key. Loading happens via
[`cfg.loadlanguage()`](../core/cfg.lua) and the plugin reads keys
via the returned table. (The loader is dual-format: if no `.json` is
present it falls back to a legacy flat Lua table at
`scripts/lang/<name>.lang.<lng>`, so an un-migrated third-party plugin
keeps working - but new plugins ship JSON.)

Worked example. `scripts/lang/en/etc_my_plugin.json`:

```json
{
    "etc_my_plugin_msg_done": "Done.",
    "etc_my_plugin_err_denied": "You are not allowed to do that."
}
```

The plugin loads it once at scope top and reads each key with an
in-source fallback (the pattern every bundled plugin uses, e.g.
`scripts/etc_aliases.lua`) - the plugin-side code is identical
regardless of the on-disk format:

```lua
local scriptname = "etc_my_plugin"
local scriptlang = cfg.get( "language" )                  -- the active language, e.g. "en"
local lang       = cfg.loadlanguage( scriptlang, scriptname ) or { }
local msg_done   = lang.etc_my_plugin_msg_done or "Done."  -- fallback if the key is missing
```

Ship every operator-visible string this way in BOTH `en/` and `de/`
(all-or-nothing), and keep DC jargon (Hub, Slot, Share, OP, Kick, Ban,
Nick, PM) in English in both files.

### 3.6 Plugin state persistence

Plugins that need to persist data across hub restarts write
[`util.savetable`](#53-util) calls to `scripts/data/<name>.tbl`
(plugin-private state - the repo-wide convention, matching `cmd_ban`,
`etc_clientblocker`, `etc_blocklist`). Operator-facing artifacts
(exports, backups a human is meant to copy) go under `cfg/`, which
travels with operator config backups.

---

## 4. Listeners

Plugins register callbacks for hub events. The hub fires the event
and walks the registered listeners until one returns `PROCESSED` or
the chain ends.

### 4.1 Registration

```lua
hub.setlistener( event_name, key, listener_fn )
```

- `event_name` (string): one of the events in [`§4.4`](#44-event-reference)
- `key` (anything, conventionally `{ }`): unique per listener, used
  for internal deduplication
- `listener_fn` (function): the callback; signature depends on the event

Multiple plugins can register listeners for the same event. They fire
in [order of `cfg.scripts`](#43-listener-chain-order).

### 4.2 Return semantics

| Return value | Meaning |
|---|---|
| `PROCESSED` | The event is handled; later listeners in the chain are skipped. |
| `nil` or no return | Pass through; the next listener (or the core default) runs. |

`PROCESSED` is a numeric constant (`10`) injected into the plugin
environment. Comparing or returning it is sufficient; do not redefine
it locally.

### 4.3 Listener chain order

Listeners fire in the order their owning plugin appears in
`cfg.scripts`. A plugin earlier in the list sees the event before
one later in the list. If an earlier listener returns `PROCESSED`,
later listeners never see the event.

This matters for plugins like `etc_unknown_command.lua` which sit at
the tail of the chain to catch leftover `+commands` no other plugin
claimed.

### 4.4 Event reference

| Event | Signature | Fired when |
|---|---|---|
| `onStart` | `function()` | Plugin loaded at hub startup or `+restartscripts` |
| `onExit` | `function()` | Plugin unloaded at hub shutdown or `+restartscripts` |
| `onShutdown` | `function()` | Hub is shutting down (fired once, distinct from `onExit`'s per-plugin unload) |
| `onError` | `function( msg )` | Lua error in another listener (do not raise here - infinite loop) |
| `onTimer` | `function()` | Fires roughly once per second |
| `onConnect` | `function( user )` | User passed identify state, before login completes |
| `onLogin` | `function( user )` | User finished login, is in normal state |
| `onLogout` | `function( user )` | User disconnects from the hub |
| `onIncoming` | `function( type, cmd, adccmd, user, targetuser )` | Generic catch-all; fires for every incoming command. Use sparingly |
| `onBroadcast` | `function( user, adccmd, msg )` | Incoming mainchat (BMSG). `msg` is the unescaped text |
| `onPrivateMessage` | `function( user, targetuser, adccmd, msg )` | Incoming DMSG / EMSG to a specific target |
| `onInf` | `function( user, adccmd )` | Post-login INF update from a normal-state user |
| `onConnectToMe` | `function( user, targetuser, adccmd )` | DCTM / ECTM peer-connection request |
| `onRevConnectToMe` | `function( user, targetuser, adccmd )` | DRCM / ERCM reverse peer-connection request |
| `onNatTraversal` | `function( user, targetuser, adccmd )` | ADC-EXT NATT `DNAT` |
| `onNatTraversalReply` | `function( user, targetuser, adccmd )` | ADC-EXT NATT `DRNT` (target-to-initiator) |
| `onSearch` | `function( user, adccmd )` | Incoming BSCH / FSCH search request |
| `onSearchResult` | `function( user, targetuser, adccmd )` | Incoming DRES / FRES search result |
| `onReg` | `function( nick )` | A user was successfully registered. `nick` is the firstnick |
| `onDelreg` | `function( nick )` | A user was successfully delregistered. `nick` is the firstnick |
| `onAudit` | `function( event )` | An audit record was emitted (via `audit.fire`); `event` is the structured audit object. Backs `etc_auditlog` + the HTTP `/v1/events` stream (#84) |
| `onFailedAuth` | `function( nick, ip, cid, reason )` | Authentication failed at any stage during login |

> **Rate-limit interaction:** per-user rate limits fire before the
> plugin listener chain (see [`core/hub_dispatch.lua`](../core/hub_dispatch.lua)).
> Throttled messages do not reach plugins at all. Listed in
> [`docs/SECURITY.md`](SECURITY.md) under "Rate-limit and plugin contract".

> **Family-aware INF (T3.1 HBRI):** since v3.2.x a BINF may carry
> both I4 and I6. The hub validates the family that matches the
> TCP source; the other family is forwarded verbatim. Plugins
> reading `user:ip()` always get the authenticated TCP-source IP.
> See [`docs/SECURITY.md`](SECURITY.md) "HBRI dual-stack INF trade-off".

---

## 5. Modules

### 5.1 hub.*

The `hub` table is the main plugin entrypoint. Core functions:

#### Listeners and broadcast

```lua
hub.setlistener( event, key, fn )
hub.broadcast( msg, from, pm, me )   -- send mainchat to all normal-state users
hub.sendtoall( adcstring )           -- send raw ADC frame to all normal-state users
hub.featuresend( adcstring, features ) -- send to users matching feature filter
hub.debug( ... )                     -- write to script.log if cfg.log_scripts is true
```

> `hub.debug` is **gated on the `log_scripts` cfg key** which is
> `false` by default. Lines emitted by `hub.debug` go to
> `log/script.log` only when enabled; otherwise they are silently
> dropped. For runtime debugging during plugin development, set
> `log_scripts = true` in `cfg.tbl`.

#### Bot management

```lua
local bot, err = hub.regbot( profile )    -- profile = { nick = "X", desc = "Y" }
local bot = hub.getbot( "all" )           -- table with all bots
local hubbot = hub.getbot()               -- the main hub bot
```

#### User management

```lua
local ok, err = hub.reguser( profile )    -- profile = { by, nick, password, level }
local ok, err = hub.delreguser( nick, cid )
local user = hub.iscidonline( cid )       -- nil if not online
local user = hub.isnickonline( nick )
local user = hub.issidonline( sid )
hub.updateusers()                         -- refresh in-memory user table from disk
```

#### Lookups

```lua
local user_in_state, user_in_any_state, conn = hub.getuser( sid )
local nobot_table, all_normalstate, all_connections = hub.getusers()
local regs, regs_by_nick, regs_by_cid = hub.getregusers()
local user = hub.find_online_by_firstnick( nick )   -- online human by firstnick(); nil if none
```

> `hub.getusers()` returns three tables of decreasing strictness.
> The first (`_nobot_normalstatesids`) is **normal-state humans only** -
> bots are inserted into the second/third tables only, never the first
> (a single-assignment `for _, u in pairs( hub.getusers() )` therefore
> iterates humans-only). Use it for per-human iteration; reach for the
> second/third table when you deliberately need bots or in-handshake
> connections. ([#179](https://github.com/luadch-ng/luadch-ng/issues/179),
> which had bots leaking into the first table, is fixed.)

> `hub.find_online_by_firstnick( nick )` resolves an online human by
> `user:firstnick()` - the original login nick, captured once and never
> re-keyed - scanning the humans-only table above. Use it as the fallback
> when `hub.isnickonline( nick )` (keyed by the **current** display nick)
> can miss a user whose nick was re-keyed by a prefix plugin such as
> `usr_nick_prefix`: `hub.isnickonline( nick ) or hub.find_online_by_firstnick( nick )`.
> A typed base nick then still resolves the prefixed online user (the
> [#473](https://github.com/luadch-ng/luadch-ng/issues/473) fix; centralised
> from a dozen plugin-local copies in
> [#537](https://github.com/luadch-ng/luadch-ng/issues/537)).

#### Escaping

```lua
local adcstr = hub.escapeto( "plain text with spaces" )
local plain = hub.escapefrom( "ADC\\sescaped\\stext" )
```

#### Plugin interop

```lua
local other = hub.import( "etc_other_plugin" )    -- loads scripts/etc_other_plugin.lua
```

#### Hub lifecycle (operator-only commands typically)

```lua
hub.restart()           -- restart hub
hub.exit()              -- shut down hub
hub.reloadcfg()         -- reload cfg.tbl
hub.restartscripts()    -- reload all plugins
```

### 5.2 cfg.*

```lua
local value = cfg.get( key )   -- returns cfg value or default
```

The `key` matches an entry in [`core/cfg_defaults.lua`](../core/cfg_defaults.lua)
or `cfg/cfg.tbl`. Returns `nil` if no key exists.

### 5.3 util.*

File I/O and helpers. Errors return `nil, err` unless noted otherwise
(the obfuscation helpers below coerce their input instead of erroring).

#### Persistence

```lua
local tbl, err = util.loadtable( path )    -- load Lua table from file
util.savetable( tbl, name, path )          -- write table to file with name= prefix
util.savearray( array, path )              -- write array to file
util.maketable( name, path )               -- create empty named-table file
```

#### Time

```lua
local d, h, m, s = util.formatseconds( seconds )    -- breakdown
local now = util.date()                             -- yyyymmddhhmmss
local sec, y, d, h, m, s = util.difftime( t1, t2 )  -- between two date()-style values
local ts = util.convertepochdate( os.time() )       -- epoch to date() style
```

#### Format

```lua
local human = util.formatbytes( 1234567890 )   -- "1.15 GB"
```

#### Strings

```lua
local trimmed = util.trimstring( "  hello  " )   -- -> "hello"
local pass = util.generatepass( 20 )           -- random alphanumeric, default len 20
```

`util.trimstring` requires a **string**: a non-string argument returns
`(nil, err)` rather than stringifying it (`trimstring( nil )` is an
error, not the literal `"nil"`). An all-whitespace or empty string
trims to `""`. Guard the result if the input can be nil:

```lua
local rel, err = util.trimstring( maybe_nil )
if not rel then ... end    -- missing / non-string input
```

#### Tables

```lua
for k, v in util.spairs( tbl ) do ... end      -- iterate sorted by key
local min_level = util.getlowestlevel( permission_tbl )
```

#### Obfuscation

```lua
local encoded = util.encode( "secret" )        -- reversible string encoding
local plain = util.decode( encoded )
```

> `util.encode` / `util.decode` are NOT cryptographic. They are a
> simple reversible scramble used historically for embedding literal
> strings in source. For real secrets use the `cfg_secret.lua`
> AES-256-GCM at-rest module. See
> [`docs/SECURITY.md`](SECURITY.md) for the threat model.
>
> Unlike `trimstring`, they accept any value: a non-string is stringified
> via `tostring` first, so the round-trip is guaranteed only for strings
> (and decimal numbers, which round-trip to their string form). Passing a
> table / boolean / nil "works" but encodes the stringified form, not the
> object.

### 5.4 utf.*

UTF-8-aware string functions. Drop-in replacements for `string.*`
that handle multibyte characters correctly:

```lua
utf.sub( s, i, j )
utf.gsub( s, pattern, replacement )
utf.find( s, pattern )
utf.match( s, pattern )
utf.format( fmt, ... )
utf.len( s )
```

Use these instead of `string.*` for any input that may contain
non-ASCII characters (which is most of ADC input).

### 5.5 adclib.*

C-backed cryptographic and ADC-protocol helpers:

```lua
adclib.hash( data )              -- Tiger hash, returns base32
adclib.hashpas( password, salt ) -- Tiger-hashed password for login challenge
adclib.escape( s )               -- ADC-escape whitespace
adclib.unescape( s )             -- ADC-unescape
adclib.createsid()               -- new 4-char base32 SID
adclib.createsalt()              -- new salt for password challenge
adclib.random_bytes( n )         -- CSPRNG via OpenSSL RAND_bytes
adclib.isutf8( s )               -- validate UTF-8 encoding
```

> `adclib.random_bytes` is the CSPRNG. Use it for all random material
> with security relevance (salts, tokens, SIDs). Do not seed `math.random`
> and use that for security-sensitive randomness - it is not CSPRNG.

---

## 6. Objects

### 6.1 user object

User objects represent connected human users. Methods are called via
colon syntax (`user:method()` not `user.method(user)`).

#### Identity

| Method | Returns | Notes |
|---|---|---|
| `user:nick()` | `adcstr` | Current nick (may differ from regnick after rename) |
| `user:firstnick()` | `adcstr` | The nick used at login |
| `user:cid()` | `adcstr` | Client CID |
| `user:sid()` | `adcstr` | 4-char session SID |
| `user:description()` | `adcstr` | INF DE field |
| `user:email()` | `adcstr` | INF EM field |
| `user:version()` | `adcstr` | Client version (`AP` + `VE`) |
| `user:hash()` | `adcstr` | Always `"TIGR"` |
| `user:salt()` | `adcstr` | Current password challenge salt |

#### Network

| Method | Returns | Notes |
|---|---|---|
| `user:ip()` | `string` | Authenticated TCP-source IP |
| `user:serverport()` | `number` | Hub-side port the client connected to |
| `user:clientport()` | `number` | Client's TCP port |
| `user:peer()` | `string, number` | IP and port together |
| `user:ssl()` | `boolean` | True if connection is TLS |
| `user:sslinfo()` | `table` | TLS handshake metadata |
| `user:client()` | `handler` | Underlying socket handler |

#### State and capabilities

| Method | Returns | Notes |
|---|---|---|
| `user:state()` | `string` | `"identify"`, `"verify"`, `"normal"` |
| `user:level()` | `number` | Plugin-defined level (used for permission checks) |
| `user:rank()` | `number` | ADC rank: 16 = hubowner, 32 = hub itself |
| `user:hubs()` | `number, number, number` | Open / reg / op hubs the user is in (each clamped `[0, 2^16]`) |
| `user:share()` | `number` | Total share in bytes (clamped `[0, 2^53]`) |
| `user:files()` | `number` | Total files in share (clamped `[0, 2^32]`) |
| `user:slots()` | `number` | Open slots (clamped `[0, 2^16]`) |
| `user:features()` | `adcstr` | INF SU field |
| `user:supports( feature )` | `boolean` | Listed in SUP |
| `user:hasfeature( feature )` | `boolean` | Listed in INF SU |
| `user:isregged()` | `boolean` | True if regged in user.tbl |
| `user:isbot()` | `boolean` | False for human users; see [`§6.2`](#62-bot-object) for bots |

**Integer INF field clamping (F-INF-2 / #219).** The ADC parser
([`core/adc.lua`](../core/adc.lua)) deliberately accepts any
well-formed integer (including negative ones) so DC++ builds that
emit the `DS-1` "unknown bandwidth" sentinel can still log in
(Phase 7d closeout, [#65](https://github.com/luadch-ng/luadch-ng/pull/65),
upstream luadch/luadch#241). Negative values are NEVER semantically
meaningful in ADC INF integer fields - they exist only as a wire-
format compatibility hack. The accessors above normalise this on
read: negatives become `0`, oversize values cap at the per-field
ceilings shown in the table. Caps are chosen as:

- `SS` (share bytes): `2^53` - the float-safe integer ceiling so
  aggregate sums and JSON serialisation (which downstream clients
  may parse as IEEE-754 double) stay exact.
- `SF` (share files): `2^32` - the natural unsigned-32-bit boundary,
  still well under 2^53 so JSON consumers stay precise, and generous
  enough that real torrenters with many small chunks are not clipped.
- `SL` / `HN` / `HR` / `HO`: `2^16` - well above any real slot /
  hub count.

Plugins that read these values should rely on the clamp rather than
re-implementing defensive coercion; the contract guarantees a
non-nil number in the documented range whenever `_inf` is present.
Direct `user:inf():getnp("SS")` reads bypass the clamp - prefer the
accessor unless you specifically need the raw wire value (e.g.
forensic logging of the original value claimed by a hostile client).

#### INF access

| Method | Returns |
|---|---|
| `user:inf()` | `adccmd` of the current INF (raw, unclamped) |
| `user:sup()` | `adccmd` of the SUP |

#### Sending data

```lua
user:send( adcstring )           -- raw frame
user:reply( msg, from, pm, me )  -- mainchat-style reply
user:sendsta( code, desc )       -- ADC STA status message
user:kill( adcstring, param )    -- disconnect with optional ADC reason; param "TL-1" = no reconnect
user:redirect( url )             -- redirect to a different hub URL
```

> **`user:reply` arity matters.** Different frame types depending
> on argument count:
> - `user:reply( msg, from )` -> `BMSG` (mainchat, only the user
>   sees it locally)
> - `user:reply( msg, from, pm_target )` -> `DMSG` (private message
>   tab in client)
> - `user:reply( msg )` -> `IMSG` (info broadcast from hub itself)
>
> A smoke test that expects `DMSG` will hang on a plugin using the
> 2-arg form (which emits `BMSG`). Match the frame class to the
> intent and to any tests.

#### Setters (regged users)

| Method | Effect |
|---|---|
| `user:setpassword( pw )` | Update password in user.tbl |
| `user:setlevel( level )` | Update plugin-level |
| `user:setrank( rank )` | Update ADC rank |
| `user:setregnick( nick, update, notsend )` | Change regnick (also moves user.tbl entry) |
| `user:updatenick( nick, notsend, bypass )` | Live nick change in INF |

#### Regged-user profile access

| Method | Returns |
|---|---|
| `user:regnick()` | Regged nick or nil if not regged |
| `user:regcid()` | Regged CID or nil if not regged |
| `user:reghash()` | `"TIGR"` or nil |
| `user:password()` | Cleartext password (regged users only) |
| `user:regid()` | Position in user.tbl |
| `user:profile()` | Full profile table; see [`§6.4`](#64-profile-table) |

### 6.2 bot object

Bot objects represent plugin-managed users that appear in the hub
user list. Created via `hub.regbot( profile )`. They share most
methods with `user` but with different semantics:

| Method | Behaviour on bot |
|---|---|
| `bot:isbot()` | Returns `true` (vs `false` for `user`) |
| `bot:ip()` | Returns `"unknown"` (bots have no real IP) |
| `bot:clientport()` | Returns `"unknown"` |
| `bot:state()` | Always `"normal"` |
| `bot:share()` | Always `0` |
| `bot:slots()` | Always `0` |
| `bot:hubs()` | Always `0, 0, 1` (op of this hub) |
| `bot:isregged()` | Always `true` |
| `bot:salt()`, `bot:sup()`, `bot:supports()`, `bot:updatenick()`, `bot:sendsta()`, `bot:setregnick()`, `bot:setpassword()`, `bot:setrank()`, `bot:setlevel()` | No-op stubs |

#### Bot-specific I/O

```lua
bot:send( msg )          -- alias bot:write(msg); routes the frame through the plugin's _client callback
bot:write( msg )         -- same as send
bot:kill()               -- removes bot from hub
```

> **`bot.write` is the plugin-listener dispatcher.** When the hub
> broadcasts a frame to all users via `sendtoall`, `bot.write` is
> invoked for each bot. Internally `bot.write` runs `_client(bot, adccmd)`,
> the callback you supplied when creating the bot. This is how plugin
> bots like HubSecurity / opchat receive mainchat frames and react.
> If you create a bot and want it to react to events, supply a
> meaningful `client` callback in the profile.

### 6.3 adccmd object

A parsed ADC command. Created by the parser when a frame arrives;
plugins manipulate the parameters and the hub re-serialises before
forwarding.

#### Inspection

| Method | Returns | Notes |
|---|---|---|
| `adccmd:fourcc()` | `adcstr` | Command name, e.g. `"BMSG"`, `"BINF"` |
| `adccmd:mysid()` | `adcstr or nil` | Originator SID |
| `adccmd:targetsid()` | `adcstr or nil` | Recipient SID for D-class commands |
| `adccmd:pos( n )` | `adcstr or nil` | Positional parameter at index `n` |

#### Named parameters (NPs)

| Method | Notes |
|---|---|
| `adccmd:getnp( tag )` | Two-char tag, e.g. `"NI"`, `"I4"`, `"SS"` |
| `adccmd:getallnp()` | Iterator: `for tag, value in adccmd:getallnp() do ... end` |
| `adccmd:setnp( tag, value )` | Add or replace |
| `adccmd:addnp( tag, value )` | Add (errors if already present) |
| `adccmd:deletenp( tag )` | Returns `true` if found |
| `adccmd:hasparam( tag )` | Check presence without consuming |

#### Re-serialisation

```lua
local frame = adccmd:adcstring()  -- back to wire format
```

### 6.4 profile table

The shape of the table stored in `cfg/user.tbl` per registered user:

```lua
{
    nick = "user_first_nick",
    password = "...",         -- cleartext (within at-rest AES-GCM if enabled)
    level = 10,
    rank = 0,
    cid = "...",              -- nil if regged by nick only
    by = "regger_nick",
    date = "20260101120000",  -- registration date in util.date() format
    is_bot = nil,             -- 1 for bots, nil otherwise
    -- additional fields populated by plugins:
    lastconnect = "20260101120000",
    lastlogout = "...",
    lastseen = "...",
    badpassword = 0,
}
```

Plugins read profiles via `user:profile()` and write fields then call
`hub.updateusers()` to persist back to disk.

---

## 7. Common patterns

### 7.1 Sending a reply to a user

```lua
-- Mainchat-style reply (appears in user's mainchat tab)
user:reply( "Hello", hub.getbot() )

-- Private-message tab in the user's client
user:reply( "Hello", hub.getbot(), user )

-- Info message from the hub itself
user:reply( "Hello" )
```

### 7.2 Broadcasting to all users

```lua
local _, hub_getbot, hub_broadcast = nil, hub.getbot, hub.broadcast
hub_broadcast( "Mainchat broadcast", hub_getbot() )
```

### 7.3 Permission check by level

```lua
local permission = cfg.get( "etc_my_plugin_permission" ) or { [60] = true, [80] = true }
if not permission[ user:level() ] then
    user:reply( "Permission denied", hub.getbot() )
    return PROCESSED
end
```

### 7.4 Loading another plugin's exports

```lua
local report = hub.import( "etc_report" )
report.send( true, true, true, 60, "something happened" )
```

### 7.5 Plugin state file

```lua
local state_path = "scripts/data/etc_my_plugin.tbl"

-- Load at startup
local state = util.loadtable( state_path ) or { counter = 0 }

-- Persist on change
hub.setlistener( "onLogin", { }, function( user )
    state.counter = state.counter + 1
    util.savetable( state, "state", state_path )
end )
```

---

## 8. Bundled plugin exports

Every bundled plugin with a public surface is listed here - this table
is exhaustive, not a sample. A plugin's public API is whatever its
final `return { ... }` exports under a **bare name**, reached via
`hub.import( "<plugin>" )`. Exports whose name begins with `_` are
internal unit-test or migration seams (the repo convention for "not
API") and are omitted on purpose; the following plugins - `bot_session_chat`,
`cmd_accinfo`, `cmd_disconnect`, `cmd_gag`, `cmd_myinf`, `cmd_myip`,
`cmd_redirect`, `cmd_sslinfo`, `cmd_userinfo`, `cmd_usersearch`,
`etc_backup`, `etc_blocklist`, `etc_forcetlstransfer`, `etc_lockdown`,
`etc_whitelist`, `hub_runtime`, `usr_hide_share` - export **only** such
seams and so appear nowhere below.
Absence from this table therefore means a plugin exports nothing public,
not that the doc is behind.

| Plugin | Import | Public exports |
|---|---|---|
| `bot_opchat` | `opchat = hub.import( "bot_opchat" )` | `opchat.feed( msg )` - send a normal message to the opchat; `opchat.bot` - the opchat bot object |
| `bot_regchat` | `regchat = hub.import( "bot_regchat" )` | `regchat.feed( msg )` - send a normal message to the regchat |
| `cmd_ban` | `ban = hub.import( "cmd_ban" )` | `ban.add( user, target, bantime, reason, script )` (bantime in seconds); `ban.del( target )`; `ban.bans` - the in-memory ban table **by reference** (see note); `ban.bans_path` - the store path for load-on-demand |
| `cmd_help` | `help = hub.import( "cmd_help" )` | `help.reg( title, usage, desc, level )` - register a `+help` entry. `title` is the section header (the script filename by convention); pass it as a plain in-code constant, never a lang-file key - filenames are not translations and must not reach Weblate (#651). |
| `etc_aliases` | `al = hub.import( "etc_aliases" )` | `al.resolve( name )` -> alias target or nil; `al.get_aliases_tbl()` -> the alias table |
| `etc_blocklist_feeds` | `feeds = hub.import( "etc_blocklist_feeds" )` | `feeds.get_status()` -> per-feed refresh status |
| `etc_clientblocker` | `cb = hub.import( "etc_clientblocker" )` | `cb.resolve( version_string )` -> block reason or nil; `cb.get_patterns_tbl()` -> the pattern table |
| `etc_geoip` | `geo = hub.import( "etc_geoip" )` | `geo.resolve( country, asn )` -> match string or nil; `geo.classify( ip )` -> country, asn, org; `geo.get_status()` -> policy + DB status |
| `etc_hubcommands` | `hubcmd = hub.import( "etc_hubcommands" )` | `hubcmd.add( cmd_or_list, onbmsg_fn )` - register a `+command` handler; `hubcmd.has( cmd )` -> bool; `hubcmd.list()` -> `{ name, fn }` pairs |
| `etc_msgmanager` | `msg = hub.import( "etc_msgmanager" )` | `msg.get_block_tbl()` -> the message-block table |
| `etc_proxydetect` | `pd = hub.import( "etc_proxydetect" )` | `pd.classify( parsed, ip )` -> matched proxy/VPN types; `pd.get_status()` -> provider + cache status |
| `etc_report` | `report = hub.import( "etc_report" )` | `report.send( activate, hubbot, opchat, level, msg )` - report to ops at or above `level`; `report.broadcast( msg, llevel, ulevel, from, pm )` - broadcast to a level **range** |
| `etc_trafficmanager` | `block = hub.import( "etc_trafficmanager" )` | `block.add( firstnick, scriptname, reason )`; `block.del( firstnick, scriptname )` |
| `etc_usercommands` | `ucmd = hub.import( "etc_usercommands" )` | `ucmd.add( menu, command, params, flags, llevel )` - register a user command; `ucmd.format( menu, command, params, flags, llevel )` -> the UCMD string |
| `usr_uptime` | `uptime = hub.import( "usr_uptime" )` | `uptime.tbl()` -> the user-uptime database table |

> `cmd_ban.bans` is the live table **by reference** - cmd_ban mutates
> it in place (never rebinds), so a captured `local bans_tbl =
> ban.bans` stays valid; if you rebind your own local instead, that
> local goes stale across `+reload` (the #238/#239 hazard, see
> [`§10`](#10-common-pitfalls)). When you only need a point-in-time
> read, `util.loadtable( ban.bans_path )` at the call site is the
> load-on-demand-safe alternative.

---

## 9. Testing

The protocol-level smoke harness lives in [`tests/smoke/run.py`](../tests/smoke/run.py).
It runs on Linux and Windows via [`.github/workflows/smoke.yml`](../.github/workflows/smoke.yml)
on pushes to `dev` and on every pull request (the `push:` trigger is scoped to
`dev`, #511).

Plugins that ship in `scripts/` are loaded for every smoke run, so a
plugin that breaks login or trips a sandbox error is caught
automatically.

**Locally:**

```sh
cmake --build build -j
cmake --install build
python tests/smoke/run.py build/install/luadch
```

**Plugin syntax check** with the standalone Lua interpreter:

```sh
lua5.4 -e 'local fn, err = loadfile("scripts/etc_my_plugin.lua"); if fn then print("OK") else print("FAIL: "..tostring(err)) end'
```

Note that syntax check does NOT validate the sandbox env - a plugin
that loads fine standalone may still hit "attempt to read undeclared
var" at runtime if it tries to use a global the sandbox does not
expose.

---

## 10. Common pitfalls

### 10.1 The plugin sandbox does NOT expose `use`

Core scripts import modules via `local x = use "X"`. Plugins cannot.
Trying `local x = use "X"` raises `attempt to read undeclared var: 'use'`
on plugin load. Access core functionality via `hub.*`, `cfg.*`,
`util.*`, etc.

### 10.2 `hub.debug` is silently dropped by default

The `log_scripts` cfg key defaults to `false`. Set it to `true` to
get `hub.debug` output in `log/script.log` for plugin development.

### 10.3 Mistyped frame class on `user:reply`

A 2-arg `user:reply(msg, from)` emits `BMSG` (mainchat-style); a 3-arg
`user:reply(msg, from, pm_target)` emits `DMSG` (private). Pick the
right form for the user-experience you want, and remember it when
writing smoke tests against the plugin.

### 10.4 Listener order matters

Two plugins both registering `onBroadcast` see the event in their
`cfg.scripts` declaration order. A plugin earlier in the list
returning `PROCESSED` blocks plugins later in the list. For
"catch-all" plugins like `etc_unknown_command.lua`, place them at
the tail of `cfg.scripts`.

### 10.5 Picking the right `getusers()` table

`hub.getusers()` returns three tables (see §5.1). The first
(`_nobot_normalstatesids`) is normal-state **humans only** - bots go into
the second/third tables, never the first - so a single-assignment
`for _, u in pairs( hub.getusers() )` iterates humans-only. Use the second
table when you deliberately need bots too. (The old
[#179](https://github.com/luadch-ng/luadch-ng/issues/179) bot-leak into the
first table is fixed; the `if not user:isbot() then` guard is no longer
needed for the first table, only harmless.)

### 10.6 Forbidden post-login INF fields

A normal-state user cannot mutate `I4`, `I6`, `PD`, `ID`, `HI`, `CT`,
`OP`, `RG`, `HU`, `BO` via `onInf`. The post-login INF guard in
[`scripts/hub_inf_manager.lua`](../scripts/hub_inf_manager.lua) kicks
with `ISTA 240` on attempt. If your plugin needs to change one of
these, the user must reconnect.

### 10.7 UTF-8 input is the plugin's responsibility

`adclib.isutf8(s)` validates a string. If you receive operator input
from any external source (file, network, OS environment), validate
before passing to ADC-frame-bound APIs - the hub assumes UTF-8 and
will not gracefully degrade.

### 10.8 Never export a mutable table reference across `+reload`

`hub.import` shallow-copies your plugin's export table, so a consumer
that captured a direct reference to one of your tables keeps pointing at
the OLD table the moment you rebind the local - which happens on every
`+reload`/`onStart` reinit and on in-place resets like `bans = { }`. The
consumer then reads stale/empty state with no error. This bit two
plugins ([#238](https://github.com/luadch-ng/luadch-ng/issues/238),
[#239](https://github.com/luadch-ng/luadch-ng/issues/239)).

Two safe patterns:

```lua
-- (a) mutate in place - never rebind the local the consumer captured
for k in pairs( state ) do state[ k ] = nil end   -- clear, don't reassign

-- (b) export a getter, so callers always read the live table
return { get_state = function( ) return state end }   -- not `state = state`
```

See the [`scripts/etc_aliases.lua`](../scripts/etc_aliases.lua) header
for a worked reference.

---

## 11. See also

- [`SCRIPTS.md`](SCRIPTS.md) - operator-facing catalog of bundled plugins
- [`SECURITY.md`](SECURITY.md) - threat model, plugin trust contract,
  rate-limit interaction, HBRI dual-stack INF trade-off
- [`CONFIGURATION.md`](CONFIGURATION.md) - operator configuration
- [`BUILDING.md`](BUILDING.md) - building luadch from source
- [`core/cfg_defaults.lua`](../core/cfg_defaults.lua) - every cfg key
  with inline explanation
- [ADC core spec](https://adc.sourceforge.io/ADC.html)
- [ADC-EXT spec](https://adc.sourceforge.io/ADC-EXT.html)

When adding new plugin-facing API surface (new listener, new `hub.*`
method, new `user.*` method), update this document in the same PR.
