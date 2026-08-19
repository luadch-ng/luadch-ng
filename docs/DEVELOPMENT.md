# Developing luadch

Engineering how-to for anyone (human or AI assistant) writing code in this
repo. `CLAUDE.md` holds the working agreement, architecture map, and roadmap;
this file holds the mechanics: how to author a core module, write a plugin,
test, harden untrusted-input code, and what "done" means.

Written in English so every contributor can read it (project convention). No
point-in-time numbers here either - link the source of truth, don't transcribe
it.

---

## 1. Orientation - which doc for which task

| You want to... | Read |
|---|---|
| Open your first PR (which branch to target, PR scope) | [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Know the rules / architecture / roadmap | `CLAUDE.md` |
| Build from source (Linux / Windows / ARM) | [`BUILDING.md`](BUILDING.md) |
| Deploy / operate a built hub | [`INSTALLING.md`](INSTALLING.md), [`CONFIGURATION.md`](CONFIGURATION.md), [`DOCKER.md`](DOCKER.md) |
| Write or extend a plugin | [`PLUGIN_API.md`](PLUGIN_API.md) (primary) + §3 here |
| Migrate a pre-sandbox plugin | [`PLUGIN_SANDBOX_MIGRATION.md`](PLUGIN_SANDBOX_MIGRATION.md) |
| Add an HTTP API endpoint | [`HTTP_API.md`](HTTP_API.md) §5 + §3 here |
| Understand the threat model / harden code | [`SECURITY.md`](SECURITY.md) + §5 here |
| Author a **core** module | §2 here |
| Write / run tests | [`../tests/README.md`](../tests/README.md) (harness) + §4 here |
| Know what a finished PR contains | §6 here (Definition of Done) |
| Read the history of a past phase | [`phases/`](phases/) |

---

## 2. Authoring a core module (`core/*.lua`)

Core modules run under `core/init.lua`'s **restricted environment**: the
module's `_ENV` has no standard globals. Every stdlib name and every other
module must be pulled in explicitly through `use`.

```lua
local use = use            -- the ONE global the restricted env grants

local type   = use "type"  -- capture every global you touch, as a local
local pairs  = use "pairs"
local string = use "string"
local ipmatch = use "ipmatch"   -- other core modules load the same way
```

### The `use`-trap (burned twice: #353, #358)

```lua
local type = type          -- WRONG. `type` is not in the restricted _ENV.
```

This is the single most common core-module mistake and it is **invisible in
unit tests**: a unit test loads the module with `loadfile(...)` into the test's
own `_G` (which does have `type`), so the bare global resolves and the test
passes. At real hub boot the module loads under the restricted `_ENV` and dies
with `attempt to read undeclared var: 'type'`. Same for a naked `pairs(...)`
call, `os.time()`, `math.floor()` - anything you did not capture via `use`.

**Local self-check before pushing** - load the module under a strict env that
mimics `init.lua` (this is exactly what caught a clean run in the mmdb reader):

```lua
-- strict_load.lua - run: lua5.4 strict_load.lua
local real = { type=type, pairs=pairs, ipairs=ipairs, string=string,
               table=table, tonumber=tonumber, tostring=tostring, error=error,
               pcall=pcall, io=io, math=math }
local function use(name)
  local v = real[name]; if v ~= nil then return v end
  error("use: unregistered dep '"..name.."'")   -- add real deps as needed
end
local env = setmetatable({ use = use }, {
  __index = function(_, k) error("UNDECLARED GLOBAL: '"..tostring(k).."'", 2) end })
assert(loadfile("core/yourmodule.lua", "t", env))()   -- errors on any bare global
```

### Registration + load order

Add the module name to the `_core` array in `core/init.lua`, **with a comment
explaining any ordering constraint** (init.lua calls each module's optional
`init()` in array order after loading them all). A module that does `use "X"`
at load time must appear after `X` in the array. Read the existing `_core`
comments before inserting - they document real ordering dependencies (e.g.
`secrets` after `cfg`, `ipmatch` before `blocklist`, `mmdb` after `ipmatch`).
Not every module belongs in `_core`: some are pulled in on demand via `use`
from another module (e.g. `cfg_secret`, whose `init()` needs `cfg` to be up).

**The same rule runs backwards, and that direction is easy to miss.** `use` is
`_global[name] or loadscript(name)`, so a `use "X"` for a module that is *not
loaded yet* is what pulls X in. **Deleting such a line moves X's load** - it is
not a no-op just because the local was unused. Before removing any
`local X = use "Y"`, check Y's position in `_core` against the module you are
editing: if Y comes first, the call was only reading an already-populated
`_global` entry and the removal is free. If it does not, find out who else pulls
Y in and when (#447 PR 5: removing `cfg`'s unused `types_*` aliases orphaned its
`use "types"`, and `cfg` sits at `_core` 5 while `types` is 28 - safe only
because `cfg.lua` loads `cfg_defaults` itself, which does `use "types"` ~50 lines
further into the same load). Stdlib names (`table`, `debug`, `os`, ...) resolve
from `_G` and never reach `loadscript`, so those are always free.

### Verifying a removal in a core module

`luac -p` proves syntax, not scope. The failure mode that matters here - a
deleted `local` whose assignment or read is still there - is syntactically
perfect and dies at hub load under the restricted env. Two checks catch it:

- **Bytecode scan (categorical).** Under the restricted env any reference to a
  name with no `local` in scope compiles to an `_ENV` access. So:
  `luac -p -l -l core/<file>.lua | grep '_ENV "<name>"'`. A `GETTABUP` means a
  dangling read or a captured closure; a `SETTABUP` means a stray global write.
  Zero hits is proof, not evidence. Validate the scan first by grepping for a
  name you *know* is global in that file, so a silent zero cannot fool you.
- **Boot the hub.** The only end-to-end check. `luac -p` and the unit tests both
  pass on code that cannot load.

### Rules

- **Passive at load.** A core module must only define functions and return its
  table at load time. No file I/O, no socket, no boot-time work in the module
  body - put that in an optional `init()` that init.lua calls after all modules
  are loaded (cfg + out are available by then).
- **1500-line ceiling** per module (Phase 6). Over that, split it.
- **`core/hub.lua`'s main chunk runs close to Lua's 200-local cap.** File-scope
  locals there are scarce - the file has hit the wall before (Phase 8 S4b + S5,
  #301). Use a lazy `use "X"` at the call site, or reuse an existing function
  with a flag parameter, before spending a slot. Measure the headroom rather than
  trusting a number written down here - `luac -p -l core/hub.lua` prints the main
  chunk's `N locals` in its header line (`0+ params, ... slots, ... upvalue,
  N locals, ...`), while plain `-p` only speaks up once you are already over.
- **Security-sensitive surfaces** (network I/O, auth, ADC parsing, config, any
  untrusted-byte parser) get the §5 treatment and are flagged for extra review
  per `CLAUDE.md` §1a.1.

---

## 3. Plugin authoring - deltas on top of PLUGIN_API.md

[`PLUGIN_API.md`](PLUGIN_API.md) is the primary reference (sandbox contents,
listener registration + return semantics, `hub.import`, objects, pitfalls).
The conventions below are either not in it or are easy to get wrong:

- **Plugin state path:** persistent tables go to `scripts/data/<plugin>.tbl`
  (via `util.savetable` / `util.loadtable`). Operator-facing artifacts
  (exports, backups) go to `cfg/`. This matches `cmd_ban`, `etc_clientblocker`,
  `etc_blocklist` (all under `scripts/data/`).
- **Bulky operator INPUT config goes in its own `cfg/<name>.tbl`, not `cfg.tbl`.**
  When a plugin needs a large operator-edited structure (an array of endpoints,
  per-item secrets / templates), keep only the master `_activate` switch in
  `cfg.tbl` and load the rest from a dedicated `cfg/<name>.tbl` via
  `util.loadtable`, pcall-wrapped and first-run-SILENT (a missing file is the
  normal not-configured state, not an error). Ship an annotated template as
  `examples/cfg/<name>.tbl`. Treat it as the same trust level as `cfg.tbl`
  (chmod 600 if it can hold inline secrets); runtime/derived state still goes to
  `scripts/data/`, never mixed into the operator's input file. Precedent:
  `etc_webhook` + `examples/cfg/webhooks.tbl`.
- **Bots at module-load; HTTP routes in `onStart`.** Create bots with
  `hub.regbot{...}` at file scope (module-load), NOT inside an `onStart`
  listener: `+reload` runs `killscripts()`, which kills every registered bot AND
  re-runs the plugin file, so a module-load `regbot` re-creates the bot exactly
  once with no duplicate accumulation (a bot created in `onStart` leaks on every
  reload). HTTP routes are the mirror case - register them in `onStart`, because
  the router `unregister_all()`s the whole route table on `+reload` before
  plugin re-init (pcall each `hub.http_register` so one bad path does not abort
  the rest). Precedents: `bot_opchat`, `etc_webhook`.
- **Never export a mutable table across `+reload` (getter idiom).** `hub.import`
  shallow-copies the export table, so any consumer holding a direct reference
  goes stale the moment your plugin rebinds the local (e.g. `bans = {}` in a
  clean handler, or `state = loadtable()` in `onStart` on reload). Burned in
  #238 / #239. Fix: either mutate the table in place (never rebind the local),
  or export a **getter function** `function() return state end` so callers
  always read the live table. See the `scripts/etc_aliases.lua` header.
- **A periodic outbound fetch must persist its next-fetch deadline across
  `+reload`.** A plugin that polls an external endpoint on an `onTimer`
  deadline (`if now >= next_fetch then ...; next_fetch = now + interval`)
  holds `next_fetch` in a RAM-only file-local. `onStart` fires on every
  `+reload` (a full Lua restart), so re-seeding `next_fetch = now + <small>`
  there means every reload re-fetches shortly after boot - an operator
  reloading several times a day hammers a rate-limited provider (a feed
  gets the hub's IP firewalled; MaxMind / AbuseIPDB have daily quotas).
  Fix: persist the last-fetch epoch to `scripts/data/<plugin>.tbl` - write
  it when a request actually goes out, **including on failure** (a
  429/500/timeout still hit the provider, so those are exactly who a
  reload-loop must not re-hit) - and in `onStart` schedule
  `next_fetch = min(last_fetch + interval, now + interval)`, or a staggered
  `now + <small>` only if never-fetched / overdue (the `min` caps a bogus
  future timestamp from clock skew / a corrupt state file). Note the state
  file loses no protection on reload - the fetched data (feed entries, the
  `.mmdb`) survives independently. Same class of bug fixed twice:
  `etc_blocklist_feeds` (#386) and `etc_geoip` auto-update (#414); when you
  add a third periodic fetcher, do this from the start.
- **i18n: all-or-nothing, en + de.** If a plugin uses `cfg.loadlanguage`, every
  operator-visible string goes through it, and both `scripts/lang/en/<name>.json`
  and `scripts/lang/de/<name>.json` ship (monolingual JSON, per-language subdir
  since the #301 P3 Weblate migration; the loader still accepts a legacy flat
  `scripts/lang/<name>.lang.<lng>` Lua table as a fallback for third-party
  plugins). Keep DC jargon (Hub, Slot, Share, OP, Kick, Ban, Nick, PM) in
  English in both files. Do not half-translate. The plugin's Weblate
  component is created automatically when its `scripts/lang/en/<name>.json`
  lands on `dev` (the `weblate-components` workflow); no manual Weblate step.
- **Operator *policy* text goes in cfg, not lang.** A kick/ban reason the
  operator is meant to customise (e.g. `etc_geoip_kick_reason`) belongs in a cfg
  key, not a `.lang` key - a lang key with the same fallback silently *shadows*
  the cfg key (`local r = lang.x or cfg.get("x")` makes the cfg lever dead), and
  the operator's edit has no effect. Lang files are for the hub-language UI; a
  per-hub policy message is cfg (matches `etc_clientblocker`'s `default_reason`).
- **A plugin that needs a core module must whitelist it.** Plugins have no
  `use`; a core module (e.g. `mmdb`, `blocklist`) is only reachable if its name
  is in `SANDBOX_GLOBALS` in [`core/scripts.lua`](../core/scripts.lua). Forgetting
  this loads fine in a unit test (which sets `_G`) but the plugin cannot see the
  module on the real hub. `os`/`io` reach plugins only through the curated
  `_os_safe`/`_io_safe` shims (no file-stat; use a file's own embedded timestamp,
  not mtime, for staleness).
- **API keys / secrets: env-var-first via `core/secrets.lua`.** Read a key with
  `secrets.lookup("cfg_key")` (checks `LUADCH_CFG_KEY` env first, then `cfg.tbl`)
  and call `secrets.register("cfg_key")` in `onStart` so `GET /v1/config` redacts
  it. Three gotchas: (1) redaction is active only once the plugin is *loaded* (a
  key sat in `cfg.tbl` before the plugin is enabled in `cfg.scripts` is NOT
  redacted, and `/v1/config` is `read`-scoped) - so document "prefer the env var"
  (never dumped); (2) call `secrets.register` at the TOP of `onStart`, BEFORE any
  `activate` / `enabled` early-return - registering it after the gate leaves a
  cfg.tbl-stored key un-redacted while the plugin is loaded-but-inactive (the
  `#395` review catch; `lookup` can stay at the point of use); (3) there is no
  `+showcfg` command today, only `GET /v1/config` redacts, so do not claim
  otherwise. Send the key in a request HEADER, never a URL query param
  (`http_client` logs the URL on failure, never the headers). Precedents:
  `etc_blocklist_feeds` (AbuseIPDB key), `etc_status_push` (heartbeat bearer token).
- **Verifying a signed request body (HMAC).** The sandbox exposes
  `hmac.sha256(secret, raw_body)` (64-char lowercase hex, RFC 2104 over
  `core/sha256.lua`) plus `adclib.constant_time_eq` for the compare - raw
  `sha256` is deliberately withheld from plugins. Strip any `sha256=`-style
  prefix from the signature header first, and verify BEFORE any side effect.
  **Dynamically-named secret keys** (`etc_foo_<name>_secret`, one per configured
  instance) are safe with `secrets.lookup` even when the key is NOT in
  `cfg_defaults`: `lookup` pcall-guards `cfg.get` (which RAISES on a fully-
  unknown key) and degrades to nil. Still `secrets.register` each derived key
  before the activate gate. Precedent: `etc_webhook`.
- **`scriptversion` bump on any semantic change** (behaviour, cfg keys, wire
  surface) - the companion `luadch-ng/scripts` repo syncs by version.
- **Config defaults + validator go in `core/cfg_defaults.lua`.** Add the key
  with a type/range validator closure (see the `ratelimit_pos_number` /
  `_RATELIMIT_TIER_FIELDS` precedents) so an operator typo becomes a clear
  cfg-load error and default-fallback, not silent misbehaviour. Use
  `types_utf8` (not `types_string`) for text keys.
- **Activation gate:** a plugin only runs if it is whitelisted in `cfg.scripts`
  (drop-in is not enough), and `examples/cfg/cfg.tbl` should list it (enabled or
  disabled per its default policy). Array order in `cfg.scripts` = listener-chain
  order; structural plugins (e.g. `hub_inf_manager`) must precede plugins that
  depend on their effect.
- **Auto-kick plugins consult the whitelist first (#78 allowlist).** Any plugin that
  would auto-kick / ban / block trusted infrastructure - whether it decides on the
  connecting IP (GeoIP, proxy detection, feed blocklists) or on a signal that trusted
  infra legitimately trips (a hublist pinger's high hub count) - should call
  `whitelist.is_whitelisted(user:ip())` at the top of its per-connection decision and
  skip on a match, so operator-trusted infrastructure (hublist pingers etc.) is
  exempt. `whitelist` is a sandbox global (mirrors `blocklist`). Precedence is
  deliberate: the whitelist overrides AUTOMATED blocks only - a manual `+ban` /
  `+blocklist` still applies (enforced in `core/blocklist.check_ip`). Put the guard
  BEFORE any cache / quota / network step so a trusted IP costs nothing. Precedents:
  the one-line guard in `etc_geoip`, `etc_proxydetect`, `usr_hubs`. Not yet extended
  to the share / slots / nick-policy plugins (`usr_share` / `usr_slots` /
  `usr_nick_*`) - a whitelisted IP still faces those unless a follow-up adds the guard.
- **Audit fire-sites:** state-changing actions emit `audit.build` / `audit.fire`
  with the firstnick-canonical actor. See [`SECURITY.md`](SECURITY.md) and the
  `#84` audit-log conventions.

### HTTP endpoints

- **`util_http.http_register_user_action`** (from `core/util_http.lua`) for
  actions whose target is a **SID** (kick, redirect, gag, ...): it does the SID
  extraction + online-check + non-bot preflight and builds the standard response
  envelope, so the plugin owns only the action body. Reference call sites:
  `scripts/cmd_disconnect.lua`, `scripts/cmd_redirect.lua`.
- **Raw `hub.http_register`** for read endpoints, non-SID target keys (CIDR,
  numeric id, nick/cid/ip like `cmd_ban`), or a non-standard envelope.
- **`scope="none"` for plugin-owned auth.** `hub.http_register`'s scope is
  `"read"` / `"admin"` / `"none"`. `"none"` skips the router's bearer-token gate
  entirely - use it ONLY when the endpoint does its OWN authentication (e.g. an
  HMAC-signed webhook receiver, `etc_webhook` - the first plugin to use it). The
  handler gets `req.raw_body` (exact unparsed bytes - required for signature
  verification; `req.body` is the parsed JSON) and `req.headers` with keys
  LOWERCASED. Obligations: verify before any side effect, constant-time compare,
  and fail CLOSED - no resolvable secret means the endpoint must refuse to
  register, never accept unsigned. A `scope="none"` route is still only reachable
  per the operator's `http_port` + reverse-proxy exposure. Set
  `meta.plugin = scriptname` for `/v1/endpoints` attribution.
- Request schema uses `min`/`max` (not `minimum`/`maximum`); `enum` is
  supported. Filter/sort via `core/http_filter.lua` - pick the right field
  bucket (`string_fields` = substring, `boolean_fields` = strict true/false,
  `integer_fields` = exact + `_min`/`_max`). Full contract:
  [`HTTP_API.md`](HTTP_API.md) §5-§7.
- `dkjson` encodes an empty Lua table as JSON `[]`. For an object-shaped empty
  value, `setmetatable(t, { __jsontype = "object" })`.

---

## 4. Testing

Harness details (running the smoke suite, ports, `--keep-staging`, adding a
wire test) live in [`../tests/README.md`](../tests/README.md). This section is
the authoring contract + the gotchas that are only learned by getting burned.

### Unit tests (`tests/unit/<name>_test.lua`)

Pure-Lua, no sockets. They stub the `use` shim, `loadfile` the module under
test from the repo root, and count assertions with a tiny harness. Canonical
shape (see `tests/unit/blocklist_test.lua`, `mmdb_test.lua`):

```lua
_G.use = function(name)                    -- stub the restricted-env shim
  local real = { type=type, string=string, table=table, --[[ ... ]] }
  if name == "ipmatch" then return _loaded_ipmatch end   -- real deps too
  return real[name] or error("shim: missing dep " .. name)
end
local mod = assert(loadfile("core/yourmodule.lua"))()

local pass, fail = 0, 0
local function eq(what, got, want) --[[ increment + print FAIL ]] end
-- ... assertions ...
os.exit(fail == 0 and 0 or 1)
```

Run from the repo root before pushing (CI is one iteration too slow - #277):

```sh
lua5.4 tests/unit/yourmodule_test.lua      # exit 0 = pass, 1 = fail
```

**Register every new unit test in `.github/workflows/smoke.yml` on BOTH legs**
- the Linux job runs `lua5.4 tests/unit/X_test.lua`, the Windows job runs the
same under `shell: msys2 {0}` with `lua5.4`. An unregistered test is silent
non-coverage.

**Run under the hub's Lua (5.4.x), never a newer one.** The hub bundles + runs
Lua 5.4.8, so the tests must too. The Windows leg installs the *versioned*
`mingw-w64-ucrt-x86_64-lua54` package (Lua 5.4.8, binary `lua5.4`), NOT the
unversioned `...-lua` - which rolling-release msys2 bumped to Lua 5.5, where
generic-for control variables are `const` (`for x,.. do x = ... end` fails to
even parse) and other 5.4-valid code breaks. Symptom of a re-drift: a
Windows-only unit-test failure (`attempt to assign to const variable`) that
passes on Linux + locally. Don't "fix" the code to satisfy a newer Lua - pin
the CI back to 5.4.x. (Local dev uses a standalone Lua 5.4.8 = the same
version.)

**Old-Windows hubowners are a real population (Server 2008 R2 / Windows 7).**
Two traps when supporting them: (1) the UCRT release build links the Universal
C Runtime (`api-ms-win-crt-*.dll`), absent there until **KB2999226** is
installed (symptom: a missing `api-ms-win-crt-*.dll` at startup). (2) Host-info
shell-outs (`core/sysinfo.lua`) must NOT rely on `Get-CimInstance` - it is
PowerShell 3.0+, and those OSes ship PowerShell 2.0. Query WMI with a
`powershell -Command "try { (Get-CimInstance X).P } catch { (Get-WmiObject X).P }"`
fallback: `Get-WmiObject` exists in every Windows PowerShell (2.0-5.1;
`powershell.exe`, not the PS-7/Core `pwsh`), so PS-2.0 hosts take the catch
branch. A nil result from such a probe must degrade to a sentinel
(`... or msg_unknown`), never reach a concatenation - the pre-refactor 3.1.x
`cmd_hubinfo` crashed exactly there (`attempt to concatenate a nil value`).

### Restricted-env load check for a plugin

A plugin unit test stubs the sandbox globals in `_G`, so it provides *every*
global and **cannot catch a bare global that is missing from `SANDBOX_GLOBALS`**
- the exact use-trap that crashes the real hub at boot ("undeclared var",
#353/#358). Before pushing a new/changed plugin, also load it under an `_ENV`
that errors on any undeclared access, with only the real sandbox set present:

```lua
local E = { }   -- fill with the real SANDBOX_GLOBALS + injected hub/utf/PROCESSED + stubs
setmetatable(E, { __index    = function(_, k) error("undeclared global '"..k.."'") end,
                  __newindex = function(_, k) error("undeclared write '"..k.."'") end })
local src   = io.open("scripts/your.lua"):read("*a")
local chunk = assert(load(src, "@your.lua", "t", E))
assert(pcall(chunk))            -- then run the captured onStart / onTimer too
```

The smoke run is the CI backstop for the same thing: force-enable the plugin
(no live feed/DB) in `override_test_ports` so `test_no_script_errors` loads it
in the real sandbox every boot.

### Regression tests must fail pre-fix (`CLAUDE.md` §1a.7)

A test that is green on both old and new code proves nothing. For a bug fix,
prove the new test **fails on the unpatched code** and passes patched:

```sh
cp core/yourmodule.lua /tmp/patched.lua
git checkout HEAD -- core/yourmodule.lua          # restore pre-fix version
lua5.4 tests/unit/yourmodule_test.lua             # expect the new case to FAIL
cp /tmp/patched.lua core/yourmodule.lua           # restore the fix
lua5.4 tests/unit/yourmodule_test.lua             # all green
```

Exception (`CLAUDE.md`-validated): a fix whose diff IS the proof (e.g. an
index that provably can never reach the out-of-range value) may skip the
ceremony - but the default is strict.

### Smoke harness gotchas (`tests/smoke/run.py`)

- **`TESTS`-list vs staging-runner ordering.** The staging-runner block runs
  under a level-100 identity that gets a strict `ratelimit_tiers` overlay
  (`msg_burst` as low as 2). A BMSG-heavy test placed there starves the token
  bucket and times out. Put BMSG-heavy tests in the initial `TESTS` list
  (before the mode switch).
- **ADC `\s` escaping.** Spaces on the wire are `\s`. A predicate like
  `"0 entries total" in frame` never matches (`"0\sentries\stotal"` on the
  wire) - decode with a helper, and when you *send* a multi-word BMSG body use
  `\\s` in the Python literal (a raw space terminates the body and the rest
  becomes ADC flags).
- **Dynamic `Content-Length`.** For an HTTP body, compute
  `str(len(body)).encode("ascii")` - a hardcoded length that mismatches hangs
  the server.
- **`wait_for_file` for the API token.** The first-boot token is written
  asynchronously; poll for the file instead of racing it.
- **Deadlines use `socket.gettime()`, not `os.time()`** - integer-second
  precision creates flakes at fractional boundaries.
- **Poll the NEGATIVE case when the asserted state installs asynchronously and
  its guard fails open.** If the hub state you assert on (a bloom filter, a
  cache, an enforcement object) is installed off the request path and its check
  FAILS OPEN before installation, a positive control passes either way and
  proves nothing - only the negative outcome (a drop / rejection) proves the
  state is live AND consulted. A fixed `time.sleep()` before that assertion
  races on a loaded runner and fail-opens the negative case (the #147 T2.2 BLOM
  flake, #408). Poll the drop in a `time.monotonic()` deadline loop: re-send,
  treat "echo still arrives" as not-ready-retry and "timeout waiting for echo"
  as proof-of-drop. See `test_blom_roundtrip`.

---

## 5. Security checklists

`SECURITY.md` is the threat model. These are the code-review checklists.

### Untrusted-input parser checklist

Any code reading operator-supplied or network-supplied bytes (config/table
files, `.mmdb`, ADC frames, HTTP bodies, external feeds) runs on paths where a
crash / hang / OOM takes down the single-threaded hub. Required:

- **Bounds-check every read.** `string.sub` silently truncates past the end
  (no error) - guard length before slicing. `string.byte` past the end returns
  nil and the next arithmetic throws - catch it.
- **Bound total WORK, not just recursion depth.** A depth guard does not stop a
  wide-shallow amplification (N pointers each re-expanding one shared M-element
  structure = N*M work at constant depth). Add a per-operation budget. This was
  a runtime-proven CRITICAL DoS in the mmdb reader (#365).
- **`pcall`-wrap the parse** so corrupt/hostile input degrades to `(nil, err)`,
  never a thrown error on a boot / refresh path. Remember `pcall` catches
  throws, NOT hangs or OOM - the work budget is what protects those.
- **Cap size before reading into RAM.** Check the file/response size against a
  ceiling before slurping it.
- **Validate before trusting derived arithmetic.** e.g. reject a claimed
  `node_count` that would overflow when multiplied, before you multiply.
- **Cap the RIGHT dimension.** A cap on a proxy (row count) does not bound a
  resource whose growth is a different function of the input. A feed capped at
  200k ROWS still OOM'd because one low-prefix v6 CIDR expands to ~32k
  bucket-cache slots (#78 E0); the fix caps the actual growth (reject over-broad
  prefixes), not the proxy. Verify the cap bounds what you think it bounds.
- **A "replace" primitive's empty input is a fail-open trap.** If a refresh
  replaces a whole data set and the fetch/parse degenerates to zero items (empty
  body, format drift, mid-transfer close), "replace with nothing" = wipe. Treat
  an empty result from a SUCCESS response as a soft failure (keep last-good),
  never a deliberate clear (#78 E1: an empty 200 wiped the feed and reported
  success). Likewise verify completeness of a fetched replace-set (Content-Length
  match; reject `chunked` if you do not de-chunk) - RAM-mode `http_client` has no
  built-in short-read guard.
- **Untrusted fields entering a shared, serialized store must be bounded
  scalars.** A feed's `sblid` string forwarded verbatim into a store table that
  gets `util.savetable`'d can poison the `.tbl` - a nested/huge value makes the
  next `loadtable` fail, so the WHOLE store loads empty (fail-open, taking
  operator pins with it). Coerce to a length-capped scalar at the trust boundary
  (#78 E1).
- **ADC wire-encoding IS spec-enforceable; validate escapes PAIRWISE.** ADC 1.0
  section 3.1 defines only `\s` `\n` `\\` and mandates "any message containing
  unknown escapes must be discarded" - the parser now does (#419). This is
  malformed *wire encoding* (reject per spec; a compliant client never emits it,
  so nothing legitimate is dropped), distinct from advisory *field semantics*
  (`TL`/`RD`/`MS` - do NOT over-enforce; clients treat them as hints, see the
  ADC-protocol-semantics discipline). Validate PAIRWISE - strip the valid
  `\s`/`\n`/`\\`, and any leftover backslash is unknown: a naive "`\` not followed
  by s/n/`\`" scan is WRONG (false-positives on `\\q` = an escaped backslash +
  literal `q`, and misses a lone trailing `\`). Corollary for CONSTRUCTION: escape
  every value you concatenate into an ADC message you then re-parse. The hub
  parses its own bot INFs, so since #419 an unescaped operator value (e.g.
  `hub_email` in the hub-bot `EM` field) makes the hub discard its OWN output and
  the bot fails to load (#423) - use `adclib.escape` per field, like the bot
  nick/desc.

### Privilege / hierarchy checklist

- **Online vs offline hierarchy divergence (#320).** Online code reads
  `target:level()` (object); offline code reads `target.level` (profile table).
  A privilege check (can actor act on target?) MUST cover BOTH paths - fixing
  only one leaves an escalation hole. Grep both when touching any
  kick/ban/reg/level-change surface.
- **HTTP admin token is total-trust.** It maps to a synthetic level-100 actor
  and bypasses the ADC hierarchy guard by design - the token IS the trust
  surface. Document it at the call site; never treat a token request as a
  lower-privilege actor.
- **A user-action command must reject a bot target (#355).** Any ADC command
  that resolves an online target and does something disruptive (gag / kick /
  ban / disconnect / redirect / nick or level change / setpass) must guard
  `if target:isbot() then user:reply(msg_isbot, hub.getbot()); return PROCESSED end`
  (`msg_isbot = "User is a bot."`). ~10 commands already do; the HTTP path is
  covered automatically by `util_http.http_register_user_action`'s non-bot
  preflight. NOTE: login/connect-time enforcers (`usr_*`, `hub_inf_manager`)
  need NO such guard - bots never fire `onLogin`/`onConnect`/`onInf`, and
  `hub.getusers()` returns humans-only first, so they are structurally
  bot-unreachable.

### Fail-safe checklist

- **Periodic file re-reads must RETAIN the last-good handle on failure.** A
  plugin that re-reads a file on a timer (a GeoIP `.mmdb`, an external feed
  file) MUST keep the previously-loaded reader if the reopen fails - never
  null-it-on-failure. A non-atomic `cp new over old` has a truncation window, a
  permission blip is transient; null-on-failure silently turns enforcement OFF
  until the next successful reload (a fail-*open*). Pattern: `reopen(path,
  current)` returns `current` on open failure and only swaps on success (closing
  the old handle then). Reviewer-caught in #78 D2.
- **A remote peer can vanish between `accept()` and the first socket read.**
  `getpeername()` then returns nil - remote-triggerable (connect + immediate
  RST). Any accept-path guard that keys on the peer IP (blocklist, per-IP
  ratelimit) MUST check for a nil peer address and DROP the socket first;
  feeding nil into `ratelimit.accept_ip` raised inside the single-threaded
  accept loop and took the whole listener down until restart (#401, v3.1.13,
  Sopor). Belt-and-suspenders: the consuming guard also nil-guards (allow + let
  the caller close the dead socket). A crash in the accept loop is hub-DOWN, not
  one-connection-down - treat the accept path with the same paranoia as an
  untrusted-input parser.

---

## 6. Definition of Done (per PR)

A change is not done until all of the following hold. This is the concrete
expansion of `CLAUDE.md` §1 for a single PR.

- [ ] **Code** matches the surrounding style; no new file-scope local in
      `core/hub.lua`; core modules use `use "X"` for every global.
- [ ] **Tests**: unit and/or smoke coverage added; for a bug fix, the
      regression **provably fails pre-fix** (§4); ran locally with `lua5.4`
      before pushing.
- [ ] **CI registration**: any new unit test is wired into `smoke.yml` on both
      the Linux and Windows legs.
- [ ] **Docs**: `CLAUDE.md` and affected `docs/*.md` updated in the SAME PR
      when architecture, conventions, module layout, defaults, or an
      engineering rule changed. No stale numbers introduced.
- [ ] **Plugin extras** (if a plugin): `scripts/lang/en/<name>.json` + `scripts/lang/de/<name>.json`, cfg default +
      validator in `cfg_defaults.lua`, `examples/cfg/cfg.tbl` entry,
      `scriptversion` bumped, audit fire-site where a state change happens.
- [ ] **CHANGELOG.md** `[Unreleased]` entry (Breaking / Features / Bugfixes /
      Notes, breaking-first, short bullets).
- [ ] **Two-pass review** (§1a.6): independent reviewer + maintainer
      spot-check; ALL findings addressed (concerns and nits), not just
      blockers, or each skip justified in writing.
- [ ] **GitFlow A**: branched off `dev`, PR to `dev`; `Part of #N` (not
      `Closes #N`) for multi-tier trackers; `gh` pinned to `--repo
      luadch-ng/luadch-ng`.
