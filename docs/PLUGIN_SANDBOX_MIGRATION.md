# Plugin sandbox migration guide (#206)

This page is for **plugin authors** whose plugins worked on luadch
pre-2026-05-23 and may need fixes on master + future v3.2.x releases.
Operators don't need this guide unless they author or modify plugins.

[Issue #206](https://github.com/luadch-ng/luadch-ng/issues/206)
introduced a tightened plugin sandbox across Tier-1 (PR
[#210](https://github.com/luadch-ng/luadch-ng/pull/210)) and Tier-2 (PRs
[#211](https://github.com/luadch-ng/luadch-ng/pull/211),
[#212](https://github.com/luadch-ng/luadch-ng/pull/212),
[#213](https://github.com/luadch-ng/luadch-ng/pull/213)). The plugin
`_ENV` is now an explicit whitelist; everything else is unreachable.

This guide lists **every primitive that became unreachable** and the
recommended replacement for each.

## TL;DR

If your plugin starts erroring with `attempt to call a nil value` or
`attempt to index nil value` (or, under strict mode, `attempt to read
undeclared var`) after upgrading luadch, **the culprit is likely one
of the patterns in [§ Removed primitives](#removed-primitives) below**.
Each pattern has a copy-paste fix.

## Reference: what the new sandbox contains

Plugins see only an explicit whitelist of globals after #206. The list
below is **illustrative** - the `SANDBOX_GLOBALS` table in
[`core/scripts.lua`](../core/scripts.lua) is authoritative and grows as
new core modules are exposed; if this guide disagrees with that table,
the code wins.

| Category | Globals |
|---|---|
| Lua language basics | `assert`, `error`, `pairs`, `ipairs`, `next`, `pcall`, `xpcall`, `select`, `setmetatable`, `getmetatable`, `tonumber`, `tostring`, `type`, `print`, `collectgarbage`, `PROCESSED` |
| Lua stdlib (full) | `table`, `math`, `coroutine` |
| Lua stdlib (curated) | `os` (only `time`, `date`, `difftime`), `io` (only `open`, path-restricted) |
| String lib | `string` (= `utf`, UTF-8-aware), `utf` (alias for the same) |
| luadch core | `hub`, `cfg`, `util`, `util_http`, `http_filter`, `http_events`, `http_client`, `adc`, `adclib`, `signal`, `out`, `unicode`, `sysinfo`, `const`, `audit`, `secrets`, `whitelist`, `blocklist`, `mmdb`, `geoip_update`, `hmac`, `backup` |
| Optional libs | `ssl` (with `.x509` pre-attached as a field), `socket`, `basexx`, `zlib_stream`, `dkjson` |

Anything not on the `SANDBOX_GLOBALS` whitelist is **unreachable** from
plugin code.

## Removed primitives

### `debug.*` (all of it)

```lua
-- OLD (broken)
local r = debug.getregistry()
local info = debug.getinfo(2)
```

**Replacement:** None. The `debug` library is removed entirely; it's a
Lua-VM-introspection escape hatch with no legitimate plugin use case.
If your plugin needed `debug.getinfo` for error reporting, switch to
`xpcall` with a custom error handler instead.

### `load` / `loadfile` / `dofile`

```lua
-- OLD (broken)
if loadfile("scripts/data/my_state.lua") then
    state = dofile("scripts/data/my_state.lua")
end
local fn = load("return 42")()
```

**Replacement:** `util.loadtable(path)` for data files. The file format
is `return { ... }` (a Lua table literal). The loader runs the chunk in
a restricted env that refuses non-table returns and external globals,
which is strictly stricter than the historic `dofile`.

```lua
-- NEW
state = util.loadtable("scripts/data/my_state.lua") or {}
```

For compiling arbitrary Lua code at runtime (the `load("return 42")`
case), there is no replacement and **none is planned**. If your plugin
needs runtime-loaded code, it's a sandbox escape vector by design and
must move into a hub-side helper.

### `rawget` / `rawset` / `rawlen` / `rawequal`

```lua
-- OLD (broken)
local v = rawget(my_tbl, "k")
rawset(my_tbl, "k", v)
local n = rawlen(my_tbl)
```

**Replacement:** Direct table access. The `rawX` family bypasses
metatable traps, which is only useful in code that uses metatables for
sandbox escape. Plain `my_tbl[k]` / `my_tbl[k] = v` / `#my_tbl` work for
every plugin use case observed in the bundled + companion plugin audit.

### `_G` / `_ENV`

```lua
-- OLD (broken)
for k, v in pairs(_G) do ... end
_ENV.foo = "bar"
```

**Replacement:** None. The plugin env is no longer self-referential by
design. If you need to enumerate plugin-visible globals for debugging,
do it explicitly: list the names you care about and probe them with `pcall`.

### `require`

```lua
-- OLD (broken)
local ssl = require "ssl"
local x509 = require "ssl.x509"
local socket = require "socket"
local basexx = require "basexx"
local http = require "socket.http"
local https = require "ssl.https"
local custom = require "my_plugin_helper"
```

**Replacement** depends on what you're requiring:

| Old call | New code | Notes |
|---|---|---|
| `require "ssl"` | `local ssl = ssl` | ssl is already a global (loaded as optional lib by `core/init.lua`); may be `false` if luasec failed to load - guard accordingly |
| `require "ssl.x509"` | `local x509 = ssl.x509` | x509 is pre-attached to the ssl module table since #211 |
| `require "socket"` | `local socket = socket` | socket is a global (always loaded if luadch built with luasocket) |
| `require "basexx"` | `local basexx = basexx` | basexx is a global if installed |
| `require "socket.http"` | currently no clean path - tracked in [luadch-ng/scripts#30](https://github.com/luadch-ng/scripts/issues/30) | the parent socket is exposed but http submodule is not yet pre-attached |
| `require "ssl.https"` | same as socket.http - issue #30 | |
| `require "<plugin-local module>"` | no replacement yet - tracked in [luadch-ng/scripts#30](https://github.com/luadch-ng/scripts/issues/30) | the proposed `util.load_plugin_module(path)` helper would fill this gap |

If your plugin needs `socket.http`, `ssl.https`, or to load a bundled-
with-plugin Lua module (e.g. `slaxml`), comment on issue
[luadch-ng/scripts#30](https://github.com/luadch-ng/scripts/issues/30)
so the hub-side helpers can be prioritised.

### `package.*` (all of it)

```lua
-- OLD (broken)
local sep = package.config:sub(1, 1)
package.path = package.path .. ";..."
local loaded = package.loaded["foo"]
```

**Replacement:**

| Old call | New code |
|---|---|
| `package.config:sub(1,1)` | `util.path_sep()` |
| `package.path` modification | not supported; modify before hub start |
| `package.loaded` lookup | not supported |
| `package.loadlib` | not supported (was a sandbox escape) |

### `os.execute` / `os.remove` / `os.rename` / `os.exit` / `os.setlocale` / `os.tmpname` / `os.tmpfile` / `os.getenv` / `os.clock`

These were all blocked in Tier-2 Sub-PR-2 (#212).

**Replacement:** None for most. The plugin sandbox exposes only
`os.time`, `os.date`, `os.difftime`. If your plugin shells out to
system commands, that work must move into a luadch core helper (the
canonical example: cmd_hubinfo's OS / CPU / RAM detection moved into
`core/sysinfo.lua` in #213, accessed by the plugin via
`sysinfo.os_name()` / `cpu_info()` / `ram_total()` / `ram_free()`).

If your plugin genuinely needs to read an environment variable, open
an issue describing the use case - a curated `sysinfo.env(name)`
helper with an allowlist of safe variable names is the canonical
expansion path.

### `io.popen` (fully blocked)

```lua
-- OLD (broken)
local f = io.popen("uname -a")
local out = f:read("*a")
f:close()
```

**Replacement:** `core/sysinfo.lua` for OS / CPU / RAM probes. Any
new shell-out use case must live in a hub-side helper.

```lua
-- NEW (for the cmd_hubinfo use case)
local os_name = sysinfo.os_name()
local cpu = sysinfo.cpu_info()
local ram_total = sysinfo.ram_total()
local ram_free = sysinfo.ram_free()
```

### `io.input` / `io.output` / `io.read` / `io.write` / `io.stdin` / `io.stdout` / `io.stderr` / `io.lines` / `io.tmpfile` / `io.close` / `io.type`

All blocked. Only `io.open` survived in the curated shim.

**Replacement:**

| Old call | New code |
|---|---|
| `io.read()` / `io.write()` | `print()` for stdout (already in whitelist), or `hub.debug()` for the event log |
| `io.lines(path)` | `for line in (io.open(path, "r")):lines() do ... end` - the file handle's `:lines()` method survives, only the `io.lines()` shorthand was removed |
| Process-global stdin/stdout/stderr manipulation | not supported |

The file handle returned by `io.open(path, mode)` is the real Lua
userdata - its methods (`:read`, `:write`, `:close`, `:lines`, `:seek`,
`:setvbuf`) all work normally. The shim only narrows the entry point.

### `io.open` with absolute paths or `..` traversal

```lua
-- OLD (worked, now blocked)
io.open("/etc/shadow", "r")          -- absolute POSIX
io.open("C:\\Windows\\foo", "r")     -- absolute Windows
io.open("\\\\server\\share\\x", "r") -- UNC
io.open("../../escape", "r")         -- parent-dir traversal
```

**Replacement:** Use relative paths under the hub working directory
tree. The audit of bundled + companion plugins shows that every legit
plugin file I/O sits under one of:

- `log/<plugin>.log` (plugin logs)
- `cfg/<plugin>.tbl` (plugin settings)
- `certs/...` (cert reading, read-only)
- `scripts/data/<plugin>.tbl` (plugin state)
- `scripts/<plugin>/data/<x>.tbl` (per-plugin state subdirs)

Note: filenames containing `..` are still allowed as long as `..` is
not a complete path component. So `thesis..v2.txt` is fine but
`../etc/shadow` is not (the latter has `..` as a path component
between `/` separators).

## Loose-end primitives not affected

These were already off-limits or never expected to work in plugin code,
listed here for completeness:

- `setfenv` / `getfenv` - removed in Lua 5.1→5.4; plugins on luadch
  v3.x onwards must use Lua 5.4 idioms anyway
- `loadstring` - renamed to `load` in Lua 5.2; `load` itself is now
  blocked, see above
- `module(...)` - removed in Lua 5.2

## Quick migration recipe for state-bearing plugins

If your plugin loads/saves a Lua table from a `.dat` or `.tbl` file,
here's the canonical replacement template:

```lua
-- AT MODULE LOAD or onStart:
local state = util.loadtable(state_path) or {}

-- ON STATE CHANGE:
util.savetable(state, "state", state_path)
-- (savetable writes atomically; replaces the historic
--  `io.open(path, "w+")` + `:write(serialize(t))` + `:close()` dance)
```

Use `util.savetable(tbl, name, path)` for a **keyed** table (a map, or
scalars like `{ counter = 0 }`): it serialises string keys. `util.savearray(tbl, path)`
writes ONLY the array part (`ipairs`) and silently drops string keys, so
it is for **pure array-indexed** tables only. The bundled state-bearing
plugins pick per shape - e.g. `cmd_ban` uses `savearray` for its
array-indexed `bans` list and `savetable` for its keyed `history`.

## See also

- [Issue #206](https://github.com/luadch-ng/luadch-ng/issues/206) - the
  original sandbox-escape issue + closure record
- [PLUGIN_API.md §2 Sandbox and environment](PLUGIN_API.md#2-sandbox-and-environment)
  for the live spec of what's available
- [`core/scripts.lua`](../core/scripts.lua) - the `SANDBOX_GLOBALS`
  table is the source of truth; if this guide disagrees with that,
  the code wins
- [luadch-ng/scripts#30](https://github.com/luadch-ng/scripts/issues/30) -
  open discussion on `socket.http` / `ssl.https` / plugin-local module
  loading
