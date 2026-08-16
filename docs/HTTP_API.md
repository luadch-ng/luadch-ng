# HTTP API design

Local HTTP listener for hub state and admin actions. Plugin-extensible
read/write API, designed as the substrate for a future WebUI.

**Status:** shipped - the [#82](https://github.com/luadch-ng/luadch-ng/issues/82)
HTTP-API arc is complete and on `master`; the endpoint catalog below is
live. Implementation was phased - see
[§13 Implementation phases](#13-implementation-phases). This document is
the authoritative spec; it is kept in lockstep with the implementation.

- 🎯 [1. Goals + non-goals](#1-goals--non-goals)
- 🌐 [2. Transport](#2-transport)
- 🏗️ [3. Architecture](#3-architecture)
- 🔐 [4. Auth model](#4-auth-model)
- 🧩 [5. Plugin registration API](#5-plugin-registration-api)
- 📥 [6. Request shape](#6-request-shape)
- 📤 [7. Response shape](#7-response-shape)
- 🧾 [8. Audit log](#8-audit-log)
- 🧭 [9. Discovery endpoint](#9-discovery-endpoint)
- 📇 [10. Endpoint catalog](#10-endpoint-catalog)
- 🚧 [11. Out-of-scope of the catalog](#11-out-of-scope-of-the-catalog)
- 📦 [12. Dependencies](#12-dependencies)
- 🗺️ [13. Implementation phases](#13-implementation-phases)
- ❓ [14. Open questions](#14-open-questions)
- 🔗 [15. Related](#15-related)

---

## 1. Goals + non-goals

**Goals.**

- Read + write API over HTTP for hub state and operator commands.
- **Plugin-extensible** - bundled and third-party plugins register
  their own endpoints via a hub-side API. Core only ships the router
  + a handful of hub-intrinsic endpoints; everything else is plugin-
  owned. If a plugin is not loaded, its path is not registered and
  the router answers `404 E_NOT_FOUND` ("no such endpoint") - there
  is no code that distinguishes "not configured" from "unknown".
- Designed to underpin a future WebUI (live monitoring + plugin
  management) - discoverable, versioned, machine-readable error shape.
- Inherits the Phase-8 S3 hardened HTTP framer (`core/iostream.lua:
  newhttpstage`) for transport robustness.

**Non-goals.**

- HTTPS termination on the API port. The listener is local-only
  (bind details in §2); operators put a reverse proxy in front for
  non-loopback access.
- Public-facing API. The threat model is "operator + their tools on
  the same host or behind their reverse proxy" - not anonymous
  internet traffic.
- Event streams (WebSocket, SSE). May be added in a future phase; not
  in v3.2.0.
- Service discovery beyond `GET /v1/endpoints` (no consul / mDNS).

---

## 2. Transport

| Property | Value |
|---|---|
| Protocol | HTTP/1.1 (HTTP/1.0 accepted, downgraded to no-keep-alive) |
| Bind | cfg `http_bind_addr` (default `127.0.0.1`). Loopback IS the security premise; only set to `0.0.0.0` / `::` in container deployments where the API reaches sibling containers via a private Docker network whose port is NOT published to the host |
| Port | cfg `http_port` (default `false` = off). Distinct from ADC ports |
| TLS | Never. Use a reverse proxy if remote access is needed |
| Connection | One request per connection (`Connection: close`) - rationale in `core/iostream.lua` framer comment |
| Server header | Never emitted (no version fingerprint pre-auth) |
| Content-Type response | `application/json; charset=utf-8` (envelope); except `/health` which returns `text/plain` for LB compatibility |
| Content-Type request | `application/json; charset=utf-8` for endpoints with a body; rejected with `415` otherwise |

The framer is `core/iostream.lua:newhttpstage`, extended for phase 1
of this API to permit a `Content-Length`-bounded body. S3 ships
GET/HEAD-only with hard body-reject; the extension is not a knob
flip - see §2.1.

Caps in the framer:

- Request-line: 8192 bytes
- Single header line: 8192 bytes
- Total headers (incl. request-line): 16384 bytes
- Header count: 100
- Request target: 2048 bytes
- Body: `MAXBODY = 65536` bytes (writes are operator-shaped, not
  bulk-upload; cap is generous but bounded)
- `Transfer-Encoding`: rejected outright (smuggling defence)
- Multiple `Content-Length`: rejected (smuggling defence)
- OWS before header colon: rejected (smuggling defence)

### 2.1 Framer body extension (phase 1 substrate change)

The current S3 framer is a single-shot stage (`done = true` after
the header parse; subsequent `push` returns `nil` and discards
trailing bytes - `core/iostream.lua` `newhttpstage`). Phase 1 adds a new
post-header state for collecting body bytes, plus a richer emit
shape. The state machine becomes:

```
[parsing-headers]  ── headers complete, CL == 0 or absent ─►  emit{method, target, version, headers, body=""}; done
                ╲
                 ╲── headers complete, CL > 0, CL <= MAXBODY ─►  [collecting-body]
                ╲
                 ╲── headers complete, CL > MAXBODY ─►  emit{reject = 413}; done
                ╲
                 ╲── any smuggling-defence trigger (TE, multi-CL, ...) ─►  emit{reject = 400}; done

[collecting-body]  ── enough bytes received ─►  emit{method, target, version, headers, body=<CL bytes>}; done
                (mid-body socket EOF emits NOTHING: no close-hook, the connection is torn
                 down and the framer state is GC'd - there is no per-push 413 guard here,
                 413 fires only on the declared Content-Length during header parse)

[done]  any further push  ─►  returns nil, false  (trailing bytes discarded)
```

Concrete contracts:

- **Rejection ordering is preserved:** smuggling defences (TE,
  multi-CL, OWS-before-colon, malformed CL value) ALL fire during
  the header-complete branch BEFORE the body-state transition.
- **413 fires on the CL value, not on byte count.** If a client
  sends `Content-Length: 1000000`, the framer emits `413` and
  closes WITHOUT reading any body bytes. Prevents per-request
  memory amplification.
- **The router gets the 413 (and 400) reject units the same way it
  gets parsed-request units today** - via the existing
  `{reject = <status>}` shape. No new router-side code path for
  rejection.
- **`body` field on success is a Lua string of EXACTLY
  `Content-Length` bytes** (or `""` for no-body requests). The
  router JSON-parses it; the framer is content-agnostic.
- **HEAD requests:** body MUST be absent (per RFC). If a HEAD
  arrives with `Content-Length > 0`, framer emits `400`.
- **Connection close mid-body:** when the underlying socket closes
  before `Content-Length` bytes have been collected, the framer
  stays in `[collecting-body]` with no emitted unit. server.lua's
  read loop tears down the handler on EOF, the framer state is
  GC'd. **No response is sent** - the client crashed first, a
  partial-write would have nowhere to land. Matches RFC 7230 §3.4
  (implicit recovery). The stage has no close-hook today; if a
  future use-case demands an explicit 400 on mid-body EOF, add a
  `flush_on_close()` method to the stage contract then.

Unit-test coverage required for phase-1 framer extension:

- POST with `Content-Length: 0` and no body → success unit, empty body
- POST with `Content-Length: N` and exactly N body bytes → success
- POST with `Content-Length: N` arriving in 1, 2, N TCP segments → success
- POST with `Content-Length: MAXBODY` (exact boundary) → success
- POST with `Content-Length: MAXBODY+1` → 413, no body read
- POST with `Transfer-Encoding: chunked` → 400 (smuggling defence)
- POST with `Content-Length: 0\r\nContent-Length: 5\r\n` → 400 (multi-CL)
- POST with lowercase method (`post`) → 400 (request-line regex anchors `^(%u+)`)
- POST with NUL bytes in body → success, body byte-exact
- POST with body containing `\r\n\r\n` → success, body byte-exact (must not mis-parse as header end)
- GET with `Content-Length: 5` → 400 (no GET endpoint accepts a body)
- HEAD with `Content-Length: 5` → 400
- HEAD with `Content-Length: 0` → success (HEAD)

---

## 3. Architecture

```
                    /v1/...
client  ─►  iostream.newhttpstage  ─►  core/http.lua router  ─┬─►  core handler
   ▲           (framer + caps)              │                 │
   │                                        │                 └─►  plugin handler
   │                                        │                       (registered via hub.http_register)
   └────────  envelope response  ◄──────────┘
                  + audit log
                  + rate-limit decision
```

`core/http.lua` owns:

- Request dispatch (method + path → registered handler)
- Auth check (token resolve → scope check)
- Rate-limit decision (per-token bucket)
- Idempotency-key cache (per-token TTL map)
- Audit log emission (every write goes to `api_audit.log`)
- Envelope formatting (success + error)
- JSON encode/decode (via bundled `dkjson`)
- Discovery endpoint `GET /v1/endpoints`

Plugins (and core itself for the few hub-intrinsic endpoints) register
handlers via the [Plugin Registration API](#5-plugin-registration-api).
Handlers receive a parsed request struct and return a result struct;
the core router does everything else.

---

## 4. Auth model

Token-based bearer auth with three scopes: `none`, `read`, and
`admin`. `none` marks routes that skip the router's bearer gate -
unauthenticated routes like `/health` and plugin-self-auth routes
like the webhook receiver (the handler does its own auth); `read`
and `admin` are token-gated. §4.4 details each.

### 4.1 cfg shape

```lua
http_api_tokens = {
    ["dashboard-readonly-7f3..."] = { scope = "read",  comment = "grafana scraper" },
    ["operator-3kd2..."]          = { scope = "admin", comment = "ops cli" },
}
```

- Map key = token (opaque string, operator-generated). Any non-empty
  string works syntactically; recommended ≥32 bytes from
  `/dev/urandom` base64-encoded for adequate entropy.
- `scope`: required, exactly one of `"read"` or `"admin"`. A
  malformed entry (bad scope or wrong shape) is dropped per-entry at
  startup: only the offending entry is removed, the remaining valid
  tokens stay active, and a warning is logged. (An earlier version
  invalidated the WHOLE table on a single bad entry and left the
  listener unbound; that is fixed.)
- `comment`: optional, free-form; surfaced in `api_audit.log` for
  attribution.
- Empty table or missing key = API is reachable but answers `401`
  for everything except `/health`. The first-boot bootstrap (§4.7)
  ensures a freshly-installed hub still has a usable admin token.

### 4.2 Token lifecycle

- Read at hub startup (`loadsettings`).
- Re-read on `+reload` (operator changed cfg, intent is to pick up
  the change). Tokens that were removed in cfg invalidate immediately;
  tokens that were added become active. Tokens with no change persist.
- **Tokens never rotate without explicit operator action.** External
  apps only need to update their token when the operator rotates it.

### 4.3 Token transport

- Header `Authorization: Bearer <token>` (RFC 6750).
- No query-string fallback (tokens in URLs leak into proxy logs).
- Constant-time comparison required: Lua's `==` on strings short-
  circuits at first mismatch byte, leaking length and prefix-match
  timing. The hub ships `adclib.constant_time_eq( a, b )` in C
  (XOR-accumulate over equal-length strings, single branch on the
  final accumulator); it is the active path whenever `adclib` is
  loaded - the normal case. A pure-Lua fallback (same algorithm with
  Lua 5.4 native bitwise `~`/`|` / `string.byte`) runs ONLY in
  stripped builds without `adclib`. Both are timing-leak-free at the
  Lua level; our hub uses the plain Lua 5.4 interpreter, not LuaJIT,
  so the constant-time property holds.

### 4.4 Scope semantics

| Scope | Can | Cannot |
|---|---|---|
| `none` | Reached without a bearer token; the route is part of the route table and listed by `/v1/endpoints`. Used by `/health` and by plugins that do their OWN authentication (e.g. `etc_webhook`'s HMAC-signed webhook routes - the handler verifies the signature over `req.raw_body`). | n/a (no router auth gate; the handler authenticates) |
| `read` | GET endpoints + `GET /v1/endpoints` filtered to {`none`, `read`} routes | Any non-GET; admin-scoped GETs (these DO ship - e.g. `GET /v1/log/api`, `/v1/log/error`, `/v1/log/cmd`, `/v1/log/audit`) |
| `admin` | Everything `read` + all writes (POST/PUT/PATCH/DELETE) + admin-scoped GETs | n/a |

The dispatcher checks scope BEFORE invoking the handler. A scope
mismatch returns `403 E_FORBIDDEN`. Auth itself is skipped for
`scope = "none"` routes; the route still goes through the regular
route-lookup + 405 + OPTIONS machinery.

### 4.5 `/health`

Unversioned, registered with `scope = "none"` (unauthenticated),
public on the loopback port. Returns `200 text/plain "ok\n"`.
Purpose: load-balancer / supervisor health probe (cfg-management
ops should not have to ship a token to systemd or similar). Carries
no hub state. Listed in `/v1/endpoints` like every other registered
route; the implementation routes it through the regular dispatch
pipeline (the `scope = "none"` flag is what makes it
unauthenticated, not a special case in the router).

### 4.6 `X-Confirm: yes` for destructive endpoints

A small handful of endpoints have outsized blast radius if hit
accidentally (shell history misfire, IDE autocompletion of a wrong
URL). Those require the client to set the header

```
X-Confirm: yes
```

in addition to the bearer token. Missing or wrong value returns
`400 E_CONFIRMATION_REQUIRED`. A WebUI sets the header automatically
when the operator clicks the confirm dialog; a CLI tool spells it
out (the muscle-memory step the guardrail is meant to add).

Endpoints with `X-Confirm: yes` required:

- `POST /v1/reload`
- `POST /v1/restart`
- `POST /v1/shutdown`
- `DELETE /v1/registered/{nick}`
- `DELETE /v1/usercleaner/expired`
- `DELETE /v1/usercleaner/ghosts`
- `DELETE /v1/usercleaner/orphan-comments`

Not required for `DELETE /v1/users/{sid}` (kick) or other write
endpoints - those are common, low-impact, and the audit log is
sufficient.

The router enforces this list at `core/http_router.lua`
`_xconfirm_required`; the §10 catalog footnotes also flag each
endpoint individually.

### 4.7 First-boot token sample (no auto-activation, #231)

The HTTP API is **opt-in on BOTH `http_port` AND `http_api_tokens`**.
Setting one without the other does NOT bind the listener; the
operator must explicitly populate both for the API to come up.

If `http_port` is set but `cfg.tbl http_api_tokens` is empty or
absent at startup, the hub generates a securely-random admin-scoped
sample token, writes it to `cfg/api_token.first` (chmod 600,
owner-only) as a convenience for the operator to copy, and logs:

```
hub.lua: http_port is set but cfg.tbl http_api_tokens is empty; wrote sample token to cfg/api_token.first (chmod 600). Copy it into cfg.tbl and restart (or +reload) to activate the HTTP API. Listener was NOT bound.
```

(Logged via `out.error` with the standard `hub.lua: ...` prefix.)

The sample token is **NOT activated in-memory**. It is purely
documentation: a securely-generated value that the operator may
copy into `cfg.tbl http_api_tokens` (or ignore in favour of
generating their own via e.g. `openssl rand -base64 32`). The HTTP
listener will not bind until cfg.tbl carries at least one token.

**Activation flow:**

1. Operator sets `http_port = 5005` and `http_api_tokens = { }`
   (or omits the key entirely) in `cfg.tbl`, restarts the hub.
2. Hub writes `cfg/api_token.first` and logs the warning above.
   HTTP listener does NOT bind. ADC listeners are unaffected.
3. Operator copies the token from `cfg/api_token.first` into
   `cfg.tbl http_api_tokens`, restarts the hub (or, on a later
   boot where the listener IS bound, just `+reload`).
4. HTTP listener binds on `http_port`. API is now reachable.
5. Operator deletes `cfg/api_token.first`.

**Why no in-memory activation (history):** earlier drafts of this
spec activated the sample token in-memory via `cfg.set(...,
nosave = true)`. This made the API "just work" on first boot but
introduced a footgun: `+reload` reads `cfg.tbl` fresh and silently
wipes the in-memory token, locking the operator out until a full
process restart (which then generates a NEW token, overwriting
`api_token.first`). Issue #231 removed the in-memory activation;
`cfg.tbl` is now the single source of truth for API tokens.

**Re-running with empty tokens.** If the operator removes all tokens
from `cfg.tbl` and triggers `+reload` while the listener is already
bound, the listener stays bound but every request returns 401.
The operator recovers by restoring tokens in `cfg.tbl` + another
`+reload`. The "sample token" path only runs at hub start, not
during `+reload`.

**Ordering on boot:** the sample-token file is written BEFORE any
HTTP listener bind attempt. If the file write fails (EACCES,
filesystem full) the hub logs the error and does NOT bind the
listener. ADC listeners are unaffected.

### 4.8 Failed-auth rate-limit

The per-token rate-limit (§6.3) only attributes to known tokens. A
brute-forcer hitting random tokens gets `401` but no token-bucket
attribution. To bound that traffic without locking out the WebUI
that happens to share the loopback IP with a misbehaving client:

- **Per-prefix failed-auth bucket.** When an
  `Authorization: Bearer <X>` header is present and resolves to no
  known token, the per-prefix bucket is consumed. The bucket is
  keyed on the first 4 chars of `<X>` (length-leak limited; not the
  full token because we don't want to log it). Default 10
  failed-auths / minute / prefix, burst 5. Cfg keys
  `http_api_authfail_prefix_rate` / `_burst`. Bucket exhaustion
  returns `429 E_RATE_LIMITED` with `Retry-After: 60`.
  Anonymous probes (no `Authorization` header) and malformed headers
  do NOT consume the prefix bucket - they fall straight into 401.
- **Per-connection counter is moot under the current transport.**
  The spec originally called for a per-TCP-connection counter
  (`MAX_FAILED_AUTHS_PER_CONN = 3`) as the first line of defence.
  The HTTP listener currently issues `Connection: close` on every
  response (one HTTP request per TCP connection), which makes the
  per-connection counter equivalent to a 1-strike rule before TCP
  teardown. The per-prefix bucket already carries the abuse-
  defence load on its own; the per-connection counter would only
  add value if we ever introduced HTTP keep-alive, at which point
  it can be revisited.
- **Reverse-proxy-aware:** if the listener is reached via a reverse
  proxy (operator deployment), the proxy SHOULD set
  `X-Forwarded-For`. Loopback proxy → use `X-Forwarded-For` value
  to augment the prefix bucket. Without trusted X-F-F, accounting
  stays at the prefix level. The reverse-proxy X-F-F augmentation
  is not implemented in Phase 1c (no proxy in the loopback-only
  default deployment); it is reserved for the Phase 2+ WebUI work.
- Loopback hits are NOT exempt: the prefix bucket fires even when
  the connecting peer is `127.0.0.1`.

---

## 5. Plugin registration API

Plugins register endpoints by calling a hub-provided global from
inside an `onStart` listener.

```lua
hub.http_register( method, path, scope, handler, meta )
```

### 5.1 Arguments

| Arg | Type | Meaning |
|---|---|---|
| `method` | string | `"GET"` / `"POST"` / `"PUT"` / `"PATCH"` / `"DELETE"` |
| `path` | string | URL path including version prefix, e.g. `"/v1/bans"`. Path variables in `{name}` form, e.g. `"/v1/bans/{id}"` |
| `scope` | string | `"read"`, `"admin"`, or `"none"`. `"none"` skips the router's bearer-token gate - use ONLY when the endpoint does its OWN authentication (e.g. an HMAC-signed webhook receiver, `etc_webhook`); see the §4.4 scope table |
| `handler` | function | `function(req) -> result` (see §6 + §7) |
| `meta` | table or nil | Optional metadata - `{plugin=, description=, request_schema=, response_schema=, audit_redact_body=}`. `plugin` is the source plugin name, for `/v1/endpoints` + `/v1/plugins` attribution. Surfaced via `/v1/endpoints` (except `audit_redact_body`, which is router-internal). Used by WebUI for form rendering. `audit_redact_body = true` opts the route into §8 audit-body redaction (used by password endpoints) |

#### 5.1.1 Higher-level helper: `util_http.http_register_user_action`

For the common "user action by SID" pattern (kick / redirect /
gag / etc — an admin endpoint that operates on one online user
identified by `{sid}` in the path), prefer the helper in
`core/util_http.lua`:

```lua
util_http.http_register_user_action(
    scriptname,          -- plugin name (for /v1/endpoints discovery)
    method,              -- "POST" / "DELETE" / ...
    path,                -- "/v1/users/{sid}" or "/v1/users/{sid}/<action>"
    action_verb,         -- "disconnect" / "redirect" / ... (static literal)
    handler_fn,          -- function(req, target) -> data | (nil, err)
    meta                 -- optional, same shape as hub.http_register's meta
)
```

The helper:
- Verifies `{sid}` is present, the SID is online, and the user is
  not a bot — returns 400 / 404 / 409 with the standard error
  codes on failure. The plugin handler never sees those cases.
- Constructs the §7.1.1 response envelope (`{action, sid, nick,
  ...handler_fields}`); the plugin handler returns just the
  action-specific fields (e.g. `{reason="flood"}` or
  `{url="adc://..."}`).
- Is fail-soft: returns `false` if `hub.http_register` is absent
  (stripped builds without the HTTP API framework still load the
  plugin's ADC chat-cmd surface unchanged).
- Hard-codes scope = `"admin"` — user-action endpoints are
  always admin by definition. Read-only or per-user-self
  surfaces use `hub.http_register` directly with their own scope.

When to use the lower-level `hub.http_register` instead:
- Read endpoints (`GET`) that need scope `"read"`.
- Resource endpoints with non-SID target keys (e.g. `cmd_ban`
  with nick / cid / ip targets — Phase 2 PR-4).
- Endpoints with a different response envelope shape (none in
  Phase 2; `/health` and `/v1/endpoints` in Phase 1).

**Convention: who fires `report.send`?** Within the
`handler_fn(req, target)` body, the plugin owns the opchat-report
firing. Both styles are valid; pick the one that matches the
plugin's existing ADC code path so the ADC-vs-HTTP behaviour stays
symmetric:
- **Caller-invoked report** (PR-1 `cmd_disconnect`, PR-2
  `cmd_redirect`): the shared `do_<verb>()` helper returns the
  formatted report message; both the ADC `onbmsg` path and the
  HTTP handler call `report.send` themselves at the right moment.
  Needed when the ADC path interleaves a chat-echo to the operator
  between the kick and the report.
- **Helper-internal report** (PR-3 `cmd_gag`): the existing
  `add_user` / `remove_user` helpers already call `report.send`
  inline; the HTTP handler just invokes them and returns. Simpler
  but harder to override the report timing.

### 5.2 Registration lifecycle

- Plugin calls `hub.http_register` from inside its `onStart` listener.
- `+reload` clears the entire route table BEFORE re-running plugin
  init. Plugins re-register their routes on the new `onStart` cycle.
- Conflict (two plugins claim the same method + path) raises an error
  at registration time and the second plugin's `onStart` returns
  false. Operator sees a startup error in `error.log`; hub continues
  with the first registration.
- Registration is single-shot per plugin per route: a duplicate
  method + path always raises "duplicate route" at registration
  time, regardless of handler identity. There is no same-handler
  no-op - a second `register` for an already-claimed method + path
  is an error.

### 5.3 Naming convention

- Bundled plugins use the unprefixed `/v1/<resource>` form, e.g.
  `cmd_ban` → `/v1/bans`.
- Third-party plugins SHOULD use `/v1/x/<plugin-id>/...` to avoid
  clashing with future bundled plugins. The router does not enforce
  this - it is convention.

### 5.4 Handler contract

```lua
local handler = function( req )
    -- req = parsed request struct (§6)
    -- return either a success result or an error result (§7)
    return { status = 200, data = { ... } }
    -- or:  return { status = 400, error = { code = "E_BAD_INPUT", message = "..." } }
end
```

The handler MUST be pure-Lua; it MUST NOT block on I/O (the hub's
event loop is single-threaded). It SHOULD return an error result
table for expected error cases (clearer trace, machine-readable code)
rather than raising. The router wraps every handler call in `pcall`
as a defence-in-depth - an uncaught error becomes
`500 E_INTERNAL` and is logged to `error.log` with the traceback.
A handler that uses errors for control flow works but is harder to
debug.

### 5.5 Router-side schema validation (optional)

`meta.request_schema` may declare a minimal type + required spec.
The router validates the parsed `req.body` against it BEFORE the
handler is invoked. Failure returns `400 E_BAD_INPUT` with a
`message` naming the offending field. Reduces boilerplate in every
handler.

```lua
hub.http_register( "POST", "/v1/bans", "admin", ban_handler, {
    description = "create a ban",
    request_schema = {
        target_type      = { type = "string", required = true, enum = { "nick", "cid", "ip" } },
        target           = { type = "string", required = true, max_length = 64 },
        duration_minutes = { type = "integer", required = false, min = 1, max = 525600 },
        permanent        = { type = "boolean", required = false },
        reason           = { type = "string", required = false, max_length = 256 },
    },
    response_schema = {
        id = { type = "string", required = true },
    },
} )
```

Supported field-spec keys: `type` (`"string"` / `"integer"` /
`"number"` / `"boolean"` / `"object"` / `"array"`), `required`,
`enum`, `min` / `max` (numbers), `min_length` / `max_length`
(strings), `pattern` (Lua pattern - NOT PCRE; `%d` is digit, `.`
matches any char, no `\d` / `\w`; WebUI builders MUST be told this).

For `type = "array"` and `"object"` the router validates ONLY that
the value is a table and is present - it does NOT distinguish array
from object (both collapse to a `type == "table"` check), so
`type = "array"` accepts an object and vice-versa. Array-vs-object,
plus nested item or property validation, is the handler's job.
Rationale: phase 1
endpoints (see catalog §10) all have flat request bodies; a full
recursive validator is bloat we don't pay for until a real
nested-body endpoint shows up. The schema mini-spec is
intentionally constrained.

If a future endpoint genuinely needs nested validation, options:
(a) extend the mini-spec with `items` + `properties` (~20 LoC), or
(b) keep flat schemas and have the handler validate the nested
shape inline. Decide at that endpoint's design time, not pre-
emptively here.

Handlers MAY skip the schema and validate inside themselves; that
is fine when the validation is dynamic (e.g. depends on a runtime
table). For static shapes the schema is the canonical and shorter
way.

**`response_schema` is documentation only.** It surfaces via
`GET /v1/endpoints` so the WebUI can pre-build forms / table
columns, but the router does NOT validate the handler's actual
response against it. The handler is trusted to keep them in sync;
diverging schema vs response is a bug to find in code review, not
at runtime.

---

## 6. Request shape

The router parses the framer's parsed-request unit into a `req`
struct passed to the handler:

```lua
req = {
    method      = "POST",                      -- uppercase
    path        = "/v1/bans",                  -- with version prefix
    path_vars   = { id = "abc" },              -- {} if no {name} segments; values ARE
                                               -- percent-decoded (a {name} nick may carry
                                               -- non-ASCII / escaped chars)
    query       = { lines = "100" },           -- query-string parsed; values are RAW URL-encoded strings
                                               -- (the router does NOT %-decode; handlers do so per-endpoint)
    headers     = { ["content-type"] = "..." },-- lowercased keys
    body        = { reason = "spam" },         -- nil for no-body methods or empty body;
                                               -- parsed JSON object for endpoints with a body
    raw_body    = "{ \"reason\": \"spam\" }",  -- original string, for handlers that want it
    token_label = "ops cli (operato…3kd2)",    -- non-secret label for logs:
                                               -- "comment (first4…last4)". Handlers MUST
                                               -- log this, never the cfg key itself.
    token_scope = "admin",
    source_ip   = "127.0.0.1",                 -- for audit log
    idempotency_key = nil,                     -- string if client sent X-Idempotency-Key
    request_id  = "01HKE7...",                 -- client-sent X-Request-ID, or an auto-generated
                                               -- UUIDv4-SHAPED id (NOT a real UUIDv4 - see §6.5)
    confirm     = false,                       -- true iff client sent X-Confirm: yes
    actor       = "alice",                     -- client-sent X-Actor (§6.7), sanitised; nil if
                                               -- absent. Audit-only correlation hint, NOT authz.
}
```

### 6.1 JSON parsing

- Body is parsed with `dkjson` once by the router; failure returns
  `400 E_BAD_JSON` to the client and the handler is not invoked.
- Top-level MUST be a JSON object (not array, not bare value). Arrays
  go in fields of the object.

### 6.2 Idempotency-key

- Header `X-Idempotency-Key: <opaque-string>` (recommended UUID).
- Per-token cache mapping `(token_bucket, method, path, key) → (status, body, headers)`
  with a 5-minute TTL. The cache key includes method + path-template
  so a client that reuses the same `X-Idempotency-Key` across two
  different write endpoints (e.g. a shared request-correlation id)
  does NOT get the first action's cached reply replayed for the
  second - each route has its own slot.
- Cache hit ⇒ router returns the cached response immediately, handler
  is not invoked, **audit log NOT re-emitted** (the original write
  was already logged; an idempotent retry must not double-log).
  The current request's `X-Request-ID` is overlaid on the replay
  so the client can correlate its log line with this turn rather
  than the original.
- Cache miss ⇒ handler runs, the response is stored before being
  returned, audit log emits once.
- Applies only to write methods (POST/PUT/PATCH/DELETE). GET / HEAD
  responses are not cached. Errors (4xx/5xx) ARE cached: a retry of
  a deterministically-failing request gets the same response, not
  a re-execution that might race differently.
- **Bounded size.** Cfg `http_api_idempotency_max_entries`
  (default 1024). When the cap is hit, oldest entry by insertion
  time is evicted (FIFO, not LRU - keeps the data structure
  trivial; the cache is bounded by both 5-min TTL and entry-count,
  so eviction strategy precision matters little).
- **Cache is cleared on `+reload`.** The route table clear (§5.2)
  invalidates the handler closures the cached responses were
  produced by - keeping the cache across reload could surface a
  response whose code path no longer exists. A write retry that
  spans a `+reload` may therefore double-execute; that is the
  intended trade-off (operator-initiated reloads are rare, retries
  spanning one are rarer, double-execution is recoverable while
  a stale cache hit is silent and confusing).
- **Deferred-response endpoints are NOT idempotency-cached.** The
  long-poll path (`GET /v1/events?wait=...`) uses the deferred-
  dispatch sentinel mechanism described in §10.1; the router
  returns from `dispatch()` before the response bytes exist, so
  no `(status, body, headers)` tuple is available to store. Today
  the only deferred endpoint is GET (idempotency doesn't apply to
  GET anyway); a hypothetical future deferred write endpoint
  would need its own at-rest dedup story. Spec note added per
  #275 holistic review.

### 6.3 Rate-limit

- Token-bucket per `token_label`. Defaults: `read` scope 120/min,
  `admin` scope 60/min, burst 10 (shared across scopes). Cfg-
  tunable per scope (`http_api_rate_read`, `http_api_rate_admin`)
  and burst (`http_api_burst`). Read default is doubled because
  the WebUI polls.
- Exceeded ⇒ `429 E_RATE_LIMITED` with `Retry-After: <seconds>` header.
- Buckets share `core/ratelimit.lua` infrastructure with the ADC
  side. Per-token buckets are keyed on an internal `bucket_id`
  (first 8 + last 8 chars of the token = 16 chars, or the whole
  token when it is shorter than 16); no comment is included. The
  full token never enters the bucket map, so the rate-limit state
  cannot leak secrets even if dumped.
- The failed-auth bucket (§4.8) is checked BEFORE the token bucket:
  an attacker grinding tokens hits the failed-auth defences first.
- `/health` is NOT rate-limited (probes are noisy by design;
  scope=none routes bypass auth and therefore have no token to
  attribute the bucket to).
- **Scope=none routes (`/health`) bypass rate-limit** entirely as a
  consequence of bypassing auth. **X-Confirm endpoints (the full
  §4.6 list - `/v1/reload`, `/v1/restart`, `/v1/shutdown`,
  `DELETE /v1/registered/{nick}`, `DELETE /v1/usercleaner/expired`,
  `DELETE /v1/usercleaner/ghosts`,
  `DELETE /v1/usercleaner/orphan-comments`) are exempt** from the per-token
  bucket budget (§4.6): an operator's recovery action must succeed
  even if a runaway script just burned the admin token's budget.
  The X-Confirm header is the abuse-protection guard for these
  endpoints (forces human intent); the audit log is the forensic
  trail.
- **403 / X-Confirm-missing responses do not consume bucket
  budget.** The rate-limit gate runs after the scope check + the
  X-Confirm carve-out lookup, so a token that lacks scope (403) or
  fails the X-Confirm check (400) does not pay the bucket cost.

### 6.4 Pagination

`GET /v1/users` and `GET /v1/registered` may return large lists and
support pagination:

```
GET /v1/users?limit=100&offset=0
```

- `limit` default 200, max 1000. Values outside the range are
  clamped (not rejected) - clients that ask for `limit=999999` get
  1000, which is friendlier than 400.
- `offset` default 0.
- Response carries a `pagination` sibling of `data`:

```json
{
  "ok": true,
  "data": { "users": [...] },
  "pagination": { "total": 4231, "limit": 100, "offset": 0, "next_offset": 100 }
}
```

- `next_offset` is OMITTED (the JSON key is absent, not `null`) on
  the last page - dkjson does not serialise a nil field. Clients
  MUST treat a MISSING `next_offset` as "no more pages" rather than
  testing for `null`.

### Filtering and sorting (#264)

Phase 1 reserved the convention; #264 lands the concrete contract.
**Per-endpoint allowlist** - each list endpoint declares its
searchable + sortable fields; unknown filter or sort fields return
400 `E_BAD_INPUT` with the allowed-fields list in the error message.

**Field types and semantics:**

| Type | Convention | Example |
|---|---|---|
| String | substring match, case-sensitive (`string.find` plain=true) | `?nick=ali` matches `alice`, `alibaba` |
| Integer | exact `?field=N` AND optional `?field_min=N` / `?field_max=N` range | `?level=20`, `?level_min=20&level_max=50` |
| Boolean | `?field=true` / `?field=false` | `?is_online=true` |
| Date | `?field_after=...` / `?field_before=...` paired params | `?regged_at_after=2026-01-01 / 00:00:00` |

**Sort:** `?sort=field` ascending, `?sort=-field` descending. Single
sort key only. Default sort is per-endpoint (see each endpoint's
footnote).

**Filter applies BEFORE pagination.** `pagination.total` reflects
the filtered count, NOT the unfiltered hub total.

PR-A landed `/v1/users` and `/v1/registered`. PR-B landed
`/v1/bans`, `/v1/blacklist`, `/v1/msgmanager`,
`/v1/trafficmanager/blocks`, and `/v1/usercleaner/expired+ghosts`.

**Query-string values are NOT URL-decoded by the router** (#275
CON-3 note). `core/http_router.lua` `parse_query` strips the `?`
prefix and splits on `&` / `=`, returning raw URL-encoded values
to handlers. A filter like `?nick=ali%20ce` will look for the
literal substring `ali%20ce` in the stored nick - NOT `ali ce`.
Clients should send filter values in their unencoded form (i.e.
let the HTTP library use the raw query string; do not pre-encode).
A future router-side decode pass is an open follow-up; until then
the contract is "raw bytes, no decode".
`/v1/bans/history` is **not** in scope - its response is a
dict-keyed-by-nick rather than a flat array, so the helper's
filter/sort/paginate flow does not map cleanly; the pre-existing
`?nick=` param remains. Tracked as a separate future enhancement
if structured filter on its entries is needed.

**Tail-style endpoints (logs, chatlog) use `?lines=N` instead of
limit/offset.** Different shape because they return a contiguous
window from the end of the resource, not paginated random-access
through it. Cap `max_lines = 1000`; clamping rules follow §6.4.

### 6.5 X-Request-ID

- If the client sends `X-Request-ID: <opaque>`, the router echoes it
  in the response header and in the audit log.
- If the client does NOT send one, the router generates a
  UUIDv4-shaped id (8-4-4-4-12 hex with the version nibble pinned to
  4) and echoes it back. It is NOT a real UUIDv4 - the variant nibble
  is unconstrained and `math.random` is not a CSPRNG - so it is a
  log-correlation handle, not a cryptographic uniqueness guarantee.
  The client can then correlate its log line with the audit log entry
  without having to invent IDs.

### 6.6 OPTIONS + HEAD auto-support

- For any registered `GET` route, `HEAD` automatically works -
  responds with the same headers as `GET` and an empty body. Status
  is the would-be GET status. Handlers do NOT receive HEAD; the
  router runs the GET handler, serializes the JSON envelope to
  measure its length, sets `Content-Length` to that exact value,
  then discards the body before writing. This is the RFC-conformant
  answer; the cost (a discarded serialization) is acceptable for
  the very rare HEAD on an admin API.
  - **GET handler side-effect contract.** Because HEAD invokes the
    same handler as GET, GET handlers MUST be idempotent / side-
    effect-free. A counter increment or a state mutation inside a
    GET handler would fire on HEAD probes too. Plugin authors:
    write changes in POST/PUT/PATCH/DELETE handlers only.
- `OPTIONS <path>` on a registered path returns the allowed methods
  for that path in the `Allow` header. Body is empty, status 204.
  No auth required (this is introspection, not data). HEAD is
  implicitly listed alongside any registered GET; OPTIONS itself
  is always listed. OPTIONS on an UNKNOWN path falls into the
  normal unknown-path handling (401 anonymous, 404 authed).
- Method mismatch (path registered for POST but client sends GET)
  returns `405 E_METHOD_NOT_ALLOWED` with `Allow: POST` header.
  Distinct from `404 E_NOT_FOUND` which means "path not registered
  at all". Anonymous callers do NOT see 405 - they get 401 first
  (no path-existence leak to unauthenticated callers).

### 6.7 X-Actor (audit attribution)

Some deployments front the API with a service that holds ONE hub
token and acts on behalf of many operators - the WebUI BFF (#82) is
the reference case: it authenticates the operator itself, then calls
the hub with its single admin token. Without extra information the
audit log would attribute every such call to that one token, losing
"who actually did this".

- If the caller sends `X-Actor: <nick>`, the router records it in the
  audit log as an `actor=` field (§8), alongside the authenticated
  `token=` field. The token remains the authenticated principal; the
  actor is the caller's CLAIM about who is behind the call.
- **X-Actor is never an authorization input.** It does not affect
  routing, scope, rate-limit buckets, or any handler decision - it is
  purely an audit-correlation hint. A token holder can set it to any
  string, so treat `actor=` as "the token holder asserted this nick",
  not as a verified identity. The trust boundary is the token; the
  actor is only as trustworthy as whoever holds it (for the WebUI,
  the BFF, which verified the operator via `POST /v1/auth/verify`).
- The value is sanitised exactly like any attacker-supplied header:
  control bytes, whitespace, and `=` all become `?` (so the value can
  never introduce an audit-line field boundary - e.g. forge a `src=`
  ahead of the real one), then it is capped at 64 chars (the
  auth-verify nick contract). A reguser nick that legitimately contains
  a space therefore appears as `foo?bar` in the hint; `token=` remains
  the authoritative identity. Absent/empty renders as `-`.
- It is recorded ONLY when the request carried a valid bearer token
  (an authenticated principal). Every request without one renders
  `actor=-`: the rejected probes (`401 / 404 / 405 / 429-prefix`) AND
  anonymous calls to `scope="none"` routes such as the webhook
  receiver. So an anonymous caller can never put a chosen `actor=`
  string in the file - the authenticated `token=` is the gate.

---

## 7. Response shape

All responses except `/health` use a JSON envelope.

### 7.1 Success

```json
{
  "ok": true,
  "data": { ... }
}
```

HTTP status carries the high-level outcome (200 / 201 / 204) and the
`data` field carries the payload. For 204 No Content, `data` is `null`
and the body may be empty.

#### 7.1.1 Write-endpoint response convention (Phase 2 lock-in, #200)

Write endpoints (POST / PUT / PATCH / DELETE that mutate hub state)
follow a uniform `data` shape so a generic admin client can dispatch
on a single field rather than switching on N per-endpoint boolean
verb flags:

```json
{
  "ok": true,
  "data": {
    "action": "<verb>",
    "sid":    "<sid>",
    "nick":   "<nick>",
    ...                    // action-specific fields, e.g. `reason`, `url`, `gag_duration_minutes`
  }
}
```

- `action` is a short kebab-case (or single-word) verb identifying
  the operation that just happened. Stable across the API: a client
  can map `action` to a handler table.
- `sid` + `nick` identify the target where applicable. Endpoints that
  don't operate on a single online user (e.g. `/v1/announce`,
  `/v1/topic`) omit them.
- Action-specific fields (`reason`, `url`, `duration_minutes`, ...)
  sit flat alongside, NOT nested under a `params` block. The flat
  shape was chosen over `{action, target, params, result}` because
  client code reads `data.url` more naturally than
  `data.params.url`, and the extra nesting costs bytes on the wire
  without a corresponding payoff for the read case.
- Verb-boolean fields (`disconnected: true`, `redirected: true`)
  are NOT used. The early Phase-2 PRs (#199, #201) shipped that
  shape; #200 is the tracker that normalised on the current
  convention.

Read endpoints (GET) MAY use any shape under `data` they like
(e.g. `/v1/users` carries a `pagination` sibling, `/v1/version`
carries flat fields directly). The `action`-verb convention is
specifically for state-mutating endpoints; reads don't perform an
action.

### 7.2 Error

```json
{
  "ok": false,
  "error": {
    "code":    "E_NOT_FOUND",
    "message": "user with sid 'ABCD' not found"
  }
}
```

HTTP status mirrors the broad error class (400 / 401 / 403 / 404 /
409 / 429 / 500); the `error.code` is the precise machine-readable
discriminator. WebUI / clients pattern-match on `code`, surface
`message` to humans.

### 7.3 Reserved error codes

| Code | HTTP | Meaning |
|---|---|---|
| `E_BAD_JSON` | 400 | Body is not valid JSON or not an object |
| `E_BAD_INPUT` | 400 | Body parsed but a field is missing / wrong type / fails schema |
| `E_CONFIRMATION_REQUIRED` | 400 | Endpoint requires `X-Confirm: yes` header (§4.6) |
| `E_UNAUTHENTICATED` | 401 | No / bad bearer token |
| `E_FORBIDDEN` | 403 | Token scope insufficient for endpoint |
| `E_NOT_FOUND` | 404 | Resource does not exist (e.g. sid not online), or the path is not registered at all ("no such endpoint" - e.g. the plugin that would own it is not loaded) |
| `E_METHOD_NOT_ALLOWED` | 405 | Method not implemented for path; `Allow` header lists what is |
| `E_CONFLICT` | 409 | State conflict (e.g. user already banned) |
| `E_PAYLOAD_TOO_LARGE` | 413 | Reserved only. A 413 is emitted by the framer as transport-level `text/plain` ("413 Payload Too Large") with NO JSON envelope, so it carries no machine-readable `error.code` - unlike every routed error above |
| `E_UNSUPPORTED_MEDIA_TYPE` | 415 | Request body present but Content-Type is not JSON |
| `E_RATE_LIMITED` | 429 | Token bucket or failed-auth bucket empty; check `Retry-After` |
| `E_INTERNAL` | 500 | Handler raised; details in `error.log` only |

Plugins MAY define their own error codes following the `E_*` prefix
convention. They SHOULD document them in their `meta.response_schema`.

---

### 7.4 Timestamp + ID conventions

- **Timestamps**: ISO 8601 UTC, second precision, trailing `Z`:
  `"2026-05-21T19:32:11Z"`. Never epoch seconds. Generated via
  Lua `os.date("!%Y-%m-%dT%H:%M:%SZ", t)`.
- **Durations**: integer seconds in field name `_seconds` (e.g.
  `uptime_seconds`, `connect_time_seconds_ago`) or integer minutes
  in `_minutes` for human-input-sized things (ban duration).
  Never both for the same concept.
- **IDs**: opaque strings unless explicitly noted. SIDs are 4-char
  Base32 (ADC native). Ban IDs are server-assigned UUIDv4. User
  nicks are the natural primary key for the registered-users
  resource.

### 7.5 CORS - explicitly not handled

The hub does NOT emit CORS headers. The listener is loopback-only;
non-loopback access goes through a reverse proxy where the operator
handles CORS (and TLS, and IP allowlisting, and request logging) at
that layer. If a future WebUI is hosted on a separate origin from
the API, that origin's reverse proxy adds the `Access-Control-Allow-
Origin` headers - not the hub.

Same-origin WebUI (served by the hub on the same port - future
phase, not now) would not need CORS at all.

---

## 8. Audit log

Dedicated `api_audit.log` in the standard log path, written through
the existing `out.createlog` infrastructure for consistency with
`event.log` / `error.log` / `script.log`:

```lua
-- in core/out.lua's return table:
api_audit = createlog( "api_audit", "api_audit.log", "log_api_audit" )
```

New cfg key `log_api_audit` (default `true`) gates the stream;
operators can disable via cfg + reload. One line per non-GET request:

```
[2026-05-22 | 14:32:11] POST /v1/bans 200 token=ops cli (oper...3kd2) actor=alice src=127.0.0.1 idem=- req_id=8f14a2c0-1b3d-4e5a-9c7f-2a6b1d0e4f88 body={"target_type":"nick","target":"baduser","duration_minutes":60}
```

- Token field shows first + last 4 chars (full token never in logs).
- `comment` field from cfg (when set) appears BEFORE the parens; the
  parens hold the `first4...last4` token fragment. An `actor=` field
  always sits between `token=` and `src=`; a `req_id=` field always
  sits between `idem=` and `body=`.
- `actor=` is the client-asserted operator nick from `X-Actor` (§6.7),
  a correlation hint for services that front the API with one token
  (the WebUI BFF). It is NEVER an authorization input - the `token=`
  field remains the authenticated principal. It is `-` whenever there
  is no authenticated bearer principal (rejected probes AND anonymous
  `scope="none"` calls) or when no `X-Actor` header was sent, so an
  anonymous caller cannot inject a chosen actor.
- Body is JSON-serialised, max 512 bytes (truncated to 509 plus `...`
  if longer), control-bytes replaced with `?` (see
  `core/http_router.lua:logsafe_body`). **The 512-byte truncation is a log-
  injection defence, NOT a secret-redaction primitive.** A 256-byte
  token or a 30-byte password both fit well under the cap and land
  on disk verbatim unless the route opts into the redact mechanism
  below.
- Failure responses are logged with the resolved HTTP status.

**Per-route body redaction.** A route declares `audit_redact_body =
true` in its `hub.http_register(...)` meta when its body contains
secrets (passwords, tokens, paths to keys). The router replaces the
`body=...` field with `body=[redacted]` for that route. Diagnostics
still get method + path + status + token + idempotency-key +
request-id, which is enough to correlate with the request without
storing the secret. Currently used by:
- `PUT /v1/registered/{nick}/password` (entire body is the new
  password)
- `POST /v1/registered` (optional `password` field in body)

Redaction is whole-body, not per-field: an operator inspecting the
audit log for a redacted route sees `body=[redacted]` even for
non-sensitive sibling fields (nick / level / comment on
`POST /v1/registered`). The values are still recoverable from the
resource state (`GET /v1/registered/{nick}`) - the audit log is the
correlation channel (who did what, when), not a structured query
surface. If a future endpoint has only one sensitive field among
many useful diagnostics, a per-field redact primitive can be added
without changing the existing whole-body flag.

**Unauthenticated / unmatched requests** (`401`, `404`, `405`,
`429-prefix`) log `body=[skipped]`. The bytes are attacker-chosen
and have no diagnostic value (no route resolution happened, so the
per-route redact policy is unknown); landing them on disk would
give an unauthenticated caller an insider-exfil channel via
`/v1/log/api`. The method + path + source-ip + token-prefix are
still logged so brute-force attempts remain visible to operators.

GET requests are NOT logged in `api_audit.log` (would be noisy under
WebUI polling). They can be enabled by cfg flag
`http_api_log_reads = true` for forensic sessions.

---

## 9. Discovery endpoint

`GET /v1/endpoints` (scope `read`) returns the live route registry,
scope-filtered to what the calling token can reach:

```json
{
  "ok": true,
  "data": {
    "endpoints": [
      {
        "method": "GET",
        "path": "/v1/users",
        "scope": "read",
        "plugin": "core",
        "description": "list online users",
        "request_schema": null,
        "response_schema": { "type": "object", "properties": { "users": { "type": "array" } } }
      },
      {
        "method": "POST",
        "path": "/v1/bans",
        "scope": "admin",
        "plugin": "cmd_ban",
        "description": "create a ban",
        "request_schema": { "type": "object", "required": ["target_type","target"] },
        "response_schema": { "type": "object", "properties": { "id": { "type": "string" } } }
      }
    ]
  }
}
```

- A `read` token sees `none`- and `read`-scoped endpoints (e.g.
  `/health`).
- An `admin` token sees all scopes.
- The `/v1/endpoints` route is itself listed in its own output (the
  registry is self-describing).
- Plugin authors who omit `meta` get `description=null`, schemas
  `null`. Bundled plugins SHOULD include meta.

---

## 10. Endpoint catalog

Distinguishes **core endpoints** (hub-intrinsic, always available
when the listener is bound) from **plugin endpoints** (registered
when the named plugin is loaded; a disabled plugin has no registered
route, so it answers 404 `E_NOT_FOUND` like any unknown path).

> **Authorisation on the HTTP path.** Across every endpoint below, the
> ADC-side level / permission guards (an operator's `permission[level]`
> hierarchy, per-command level tables, `_oplevel` / `_minlevel` /
> `_masterlevel` gates) do NOT apply. The bearer token's scope - `read`
> or `admin` - is the sole authorisation gate; issue admin tokens
> accordingly.

### 10.1 Core endpoints

| Method | Path | Scope | Description |
|---|---|---|---|
| GET | `/health` | none | Health probe, plain text `ok` |
| GET | `/v1/version` | read | hub name, version, build, uptime (seconds), start_time (ISO 8601) |
| GET | `/v1/stats` | read | online user count, total share, traffic, by-level breakdown |
| GET | `/v1/users` | read | online users list - **paginated** + **filter/sort** [^http-users-filter] |
| GET | `/v1/users/{sid}` | read | full INF + session metadata |
| GET | `/v1/endpoints` | read | live route registry (scope-filtered) |
| GET | `/v1/log/api` | admin | tail of this API's own audit log; query `?lines=N` (default 200, max 1000); response `{lines, returned, total_lines}` matches sibling tail endpoints |
| GET | `/v1/plugins` | read | list plugins in `cfg.scripts` + runtime state [^http-plugins-1] |
| PUT | `/v1/plugins/{name}/enabled` | admin | toggle a manageable plugin's enabled flag [^http-plugins-2] |
| GET | `/v1/config` | read | full cfg snapshot; sensitive keys masked as `<redacted>` [^http-config-1] |
| PUT | `/v1/config/{key}` | admin | update one cfg key; response carries `apply_status` [^http-config-2] |
| GET | `/v1/events` | read | event stream; `?since=<id>&types=<csv>&wait=<seconds>` [^http-events-1] |
| POST | `/v1/auth/verify` | read | verify an operator's hub credential via ADC challenge-response (WebUI login) [^http-auth-verify] |

[^http-events-1]: #263. Returns 200 with `data: {events: [...], cursor}`. Each event carries `id` (monotonic per-process counter), `type`, `timestamp` (ISO 8601 UTC), plus per-type payload fields - login (`nick`, `sid`, `level`), logout (`nick`, `sid`), broadcast (`nick`, `sid`, `message`), pm (`from_nick`, `to_nick`, `message`), failed_auth (`nick`, `source_ip`, `reason`), reg_added (`nick`), reg_removed (`nick`), script_error (`message`), ban_added (`id`, `target_type`, `target`, `nick`, `cid`, `ip`, `reason`, `by_nick`, `ban_seconds` - via `cmd_ban` v0.40+), ban_removed (`id`, `nick`, `cid`, `ip`, `reason`, `by_nick` - via `cmd_ban` v0.40+), topic_changed (`topic`, `previous`, `by` - via `cmd_topic` v0.05+), audit (`action`, `actor_nick`, `actor_level`, `actor_sid`, `actor_cid`, `actor_ip`, `target_nick`, `target_sid`, `target_cid`, `target_ip`, `target_level`, `reason` - #84; emitted for every onAudit fire from a staff-action plugin; `meta` is dropped on the wire to keep the live stream bounded, full payload stays in the disk JSONL). Query params: `?since=<id>` (`0` returns from the start of the buffer, `latest` returns empty with the current cursor for no-replay subscription); `?types=<csv>` (optional filter; e.g. `?types=login,logout`); **`?wait=<seconds>`** (PR-B; default 0 = immediate return, clamps to [0, 60]; when > 0 and no events match the cursor + filter, the server holds the request until either a matching event fires (sub-tick latency via `http_events.emit` notifying waiters) OR the deadline elapses (~1s tick granularity from `server.addtimer`)). Ringbuffer is bounded by `cfg.http_events_buffer_size` (default 1000, ~200 KB). If `since` is below the buffer's minimum id (events evicted), the response carries `cursor_lost: true` and the client catches up via per-resource endpoints then resumes polling at the returned `cursor` (`cursor_lost` always takes immediate return - no waiting on a stale cursor). The `pm` and `audit` event types are **admin-only** (filtered out for read-scope tokens by `core/http_router.lua` `filter_for_scope`); other types are read-scope. All string payload fields are control-byte-sanitised at emit time. Long-poll uses a deferred-response handshake at the dispatch layer (status sentinel `"deferred"`), not a coroutine yield - the connection is held open + registered in a waiter list, write+close happens later when the resolver fires; this fits the existing request/response model without an SSE-grade rewrite of `core/iostream.lua`. Operators wanting true real-time / `text/event-stream` should track a future SSE issue if a concrete need emerges.

[^http-auth-verify]: WebUI operator-login primitive. The caller (a token-bearing BFF) mints a fresh RFC4648 base32 salt, the browser computes `adclib.hashpas(password, salt)` (Tiger, per the ADC PAS construction) and never sends the plaintext; the hub recomputes from the STORED password and compares in **constant time** (`adclib.constant_time_eq` - unlike the native ADC login path's `~=` at `core/hub_dispatch.lua`). Body `{ nick, salt, response }` (all required strings; `salt` must be base32 `A-Z2-7`, 16..102 chars). Response `{ ok: bool, level?: int }` - `level` (the hub level scheme: 0 UNREG .. 60 OPERATOR .. 100 HUBOWNER) is returned ONLY on success, never leaked on failure. `scope=read` keeps this password oracle behind the bearer (never unauthenticated). The request body is **audit-redacted** (auth material). Throttled by a dedicated per-nick AND per-IP bucket (`cfg http_api_authverify_rate` default 6/min, `http_api_authverify_burst` default 3; both must have budget), independent of the per-token bucket. Unknown-nick and wrong-password both return `{ ok = false }` after an equal-cost `hashpas` compare, so timing does not reveal whether a nick is registered. It does NOT touch the ADC `badpassword` lockout counter - a WebUI brute-force cannot lock a user out of the ADC login; the endpoint's own rate-limit bounds it. Mirrors the `core/hub_dispatch.lua` HPAS recompute. Deployment notes: in the recommended BFF-behind-loopback topology every login arrives from one IP, so the per-IP bucket collapses to a single global limit - multi-operator hubs should raise `http_api_authverify_rate` accordingly (or have the BFF forward the real client IP); the per-nick bucket still isolates per account. Any `read`-scope token can call this endpoint, so a leaked read token is a rate-limited password oracle over the whole reguser table - deciding which level may do what is the BFF's responsibility, on the returned `level`.

[^http-plugins-1]: Returns 200 with `data: {plugins: [...]}`. Each entry: `{name, filename, version, manageable, enabled, loaded, order_index, listeners[], http_routes[]}`. The `enabled` / `manageable` / `order_index` fields reflect the LIVE `cfg.scripts` table (so a PUT-driven mutation is immediately visible on the next GET, without requiring a reload); `loaded` / `version` / `listeners` / `http_routes` reflect what is actually running in memory (those flip after `POST /v1/reload`). `manageable: true` means the cfg.scripts entry is in table-form `{ "name.lua", enabled = bool }` (operator opted-in for API toggling); `manageable: false` means string-form (operator-protected). `version` is extracted via source-grep of `local scriptversion = "..."` at load time; plugins can opt-in to override via `return { _version = "..." }`. Plugins not in cfg.scripts are not listed (no directory scan).

[^http-config-1]: #262. Returns 200 with `data: {config: {key: value, ...}}` containing every key registered in `core/cfg_defaults.lua`. Keys on the denylist (`http_api_tokens`, `master_key_path`) are replaced with the literal string `"<redacted>"`; the actual value is never sent over the wire. No pagination - the cfg snapshot is bounded (~200 keys, ~10-30 KiB JSON). Values are returned in their native types (strings as JSON strings, integers as JSON numbers, booleans, arrays, tables) - whatever `dkjson.encode` produces. Redaction is driven by the secrets registry: any key for which `secrets.is_secret_key(key)` is true (see `core/secrets.lua`, populated via `secrets.register(...)`) is masked. Marking a new key sensitive means registering it there, not editing a denylist.

[^http-config-2]: #262. Body `{value: <any JSON type>}`, required. Path variable `{key}` is the bare cfg key name. Mutates via `cfg.set` (validator check + atomic write to `cfg.tbl`). Response carries `apply_status` from a small lookup table in `core/http_router.lua`: `live` (effect on `cfg.set` - default for the ~200 keys not in either bucket); `reload_required` (needs `POST /v1/reload` to apply; currently `scripts`, `language`, plus the path-pointer keys `user_path` / `script_path` / `scripts_cfg_path` / `scripts_lang_path` / `core_lang_path`); `restart_required` (needs full hub restart; currently `tcp_ports`, `ssl_ports`, `tcp_ports_ipv6`, `ssl_ports_ipv6`, `http_port`, `hub_listen`, `master_key_path`, `log_path`, `ssl_params`, `use_ssl`). Returns 403 `E_FORBIDDEN` if `{key}` is on the denylist (sensitive credentials rotate via direct cfg.tbl edit + restart); 404 `E_NOT_FOUND` if the key is not registered in `cfg_defaults.lua`; 400 `E_BAD_INPUT` if body is missing the `value` field OR the validator rejected the value (the validator's err_msg is surfaced in the response). The change is NOT auto-reload-triggered - the operator chains `POST /v1/reload` for reload-required keys, or restarts the hub for restart-required keys. Per-key validator schemas are NOT exposed (the validator closures aren't designed to be introspectable); deferred to a future `GET /v1/config/{key}/schema` endpoint if a real need emerges.

[^http-plugins-2]: Body `{enabled: bool}`, required. Path variable `{name}` is the filename with or without `.lua` suffix (e.g. `etc_prometheus` or `etc_prometheus.lua`). Mutates the entry's `enabled` flag in `cfg.scripts` via `cfg.set()` (atomic write to `cfg.tbl`). Does NOT trigger a reload; response carries `reload_required: true` so the client can chain `POST /v1/reload` after a batch of toggles. Returns 403 `E_FORBIDDEN` if the entry is in string-form (operator-protected); 404 `E_NOT_FOUND` if the name is not in cfg.scripts; 400 `E_BAD_INPUT` if the body is missing or `enabled` is not a boolean. Per-plugin reload is NOT supported - the existing `POST /v1/reload` (full hub script restart) is the apply mechanism (tracked under #48 if/when per-plugin reload becomes feasible).

### 10.2 Plugin endpoints

Mapped from existing `+cmd` operations. Each row's `plugin` column
names the bundled plugin that registers the endpoint; if that plugin
is disabled in `cfg.scripts`, the endpoint returns 404
`E_NOT_FOUND` (the router does not distinguish a disabled plugin from
an unknown path).

#### User control

| Method | Path | Scope | Plugin |
|---|---|---|---|
| DELETE | `/v1/users/{sid}` | admin | `cmd_disconnect` |
| POST | `/v1/users/{sid}/redirect` | admin | `cmd_redirect` [^http-redirect-1] |
| POST | `/v1/users/{sid}/gag` | admin | `cmd_gag` [^http-gag-1] |
| DELETE | `/v1/users/{sid}/gag` | admin | `cmd_gag` [^http-gag-2] |
| GET | `/v1/gags` | read | `cmd_gag` - list active gags (= ADC `+gag show`) [^http-gag-list] |

[^http-redirect-1]: Body `{url: string?}`, URL scheme locked to `adc://` / `adcs://`. If the body has no `url` field, the cfg key `cmd_redirect_url` is used as the default. Body URL strings undergo control-byte sanitisation before reaching the `RD` field of the outbound IQUI; an admin operator with a leaked token can still redirect any user, by design - issue admin tokens accordingly.

[^http-gag-1]: Body `{mode: "mute"|"kennylize"|"shadowmute" required, duration_minutes: integer optional}`. `mode` is enum-validated, `duration_minutes` is range-clamped at the schema layer to `1..5256000` (~10 years cap matching the ADC-side `MAX_DURATION` in `parse_duration`). Missing/omitted duration = permanent gag (no `expires_at`). Returns 200 with `data: {action:"gag", sid, nick, mode, duration_minutes?, expires_at?}` (ISO 8601 UTC). Returns **409 E_CONFLICT** if the user is already gagged - the operator must `DELETE` first to change mode (matches the ADC-side `msg_error_in` semantic; mode-change-in-place is intentionally NOT supported to keep the audit trail clean). The HTTP path is **online-only**: the helper rejects offline SIDs with 404 before the handler runs. Offline registered users can still be ungagged via the ADC `+gag ungag` cmd.

[^http-gag-2]: No body. Returns 200 with `data: {action:"ungag", sid, nick, previous_mode}` so the caller learns which mode was lifted. Returns **404 E_NOT_FOUND** if the user is not currently gagged - chosen over an idempotent 200-no-op so admin tools can distinguish "I just ungagged" from "user was already free" (matches REST-orthodox DELETE-of-missing semantics). The ADC `+gag ungag` cmd uses the verbose `msg_error_out` "user has no restriction set" message for the same intent.

[^http-gag-list]: `cmd_gag` v0.15. Returns 200 with `data: {gags: [...]}` (no pagination - the active-gag set is small). Each entry: `{firstnick, mode, added_by, added_at, expires_at, sid}`. `firstnick` is the gag store's key - the user's ORIGINAL login nick, stable across a `usr_nick_prefix` decoration or a `+nickchange`. `mode` is `"mute"|"kennylize"|"shadowmute"`. `added_by` is the operator/token that set the gag; `added_at` / `expires_at` are ISO 8601 UTC (§7.4, matching the `POST` sibling and `/v1/bans`), `expires_at` `null` for a permanent gag. `sid` is the gagged user's live session id if they are currently online (resolved per firstnick via the same `find_online_by_firstnick` the ADC command uses), `null` if the gag is on an offline registered user - so a client can join a gag onto `/v1/users[].sid` even when `usr_nick_prefix` has re-keyed the *displayed* nick that `/v1/users` returns. The list mirrors the ADC `+gag show` surface: it reports **every** gag the hub is enforcing, INCLUDING one already past its `expires_at` that the 60s cleanup timer has not yet swept - `check_user_input` does not consult `expires_at`, so such a user is still muted until the sweep, and reporting the gag as active is what matches enforcement (a consumer that wants to hide an expiring gag has `expires_at` to compare). **Read-scoped, never mutates** - it is the read counterpart to the write-only `POST` / `DELETE /v1/users/{sid}/gag` pair, added for the WebUI's status-aware Gag/Ungag toggle. Registered via raw `hub.http_register` (like `/v1/bans`), not the `util_http` per-`{sid}` helper, because it is a hub-wide collection rather than a single-user action.

#### Registered users

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/registered` | read | `cmd_reg` - **paginated** + **filter/sort** [^http-registered-list] [^http-registered-filter] |
| GET | `/v1/registered/{nick}` | read | `cmd_accinfo` [^http-registered-get] |
| POST | `/v1/registered` | admin | `cmd_reg` [^http-registered-create] |
| PUT | `/v1/registered/{nick}/password` | admin | `cmd_setpass` [^http-registered-setpass] |
| PUT | `/v1/registered/{nick}/nick` | admin | `cmd_nickchange` [^http-registered-nickchange] |
| PUT | `/v1/registered/{nick}/level` | admin | `cmd_upgrade` [^http-registered-upgrade] |
| PATCH | `/v1/registered/{nick}` | admin | `cmd_reg` (free-form: `comment`) [^http-registered-patch] |
| DELETE | `/v1/registered/{nick}` | admin | `cmd_delreg` - requires `X-Confirm: yes` (§4.6) [^http-registered-delreg] |

[^http-users-filter]: #264 PR-A filter/sort. Searchable: `nick` (string), `description` (string), `level` (integer exact + `level_min` / `level_max` range), `share_bytes` (integer + `_min` / `_max`). Sortable: `nick`, `level`, `share_bytes`, `files`. Default sort = stable SID order (no `?sort=` param applied). Unknown filter or sort field returns 400 `E_BAD_INPUT` with the allowed-fields list. Filter applies BEFORE pagination; `pagination.total` reflects the filtered count. The hub's `usr_nick_prefix` plugin may decorate the displayed nick (e.g. `[HUBOWNER]dummy`); the filter uses the decorated value as visible in the response - substring search on `dummy` still matches `[HUBOWNER]dummy`. CID filtering is intentionally NOT in the allowlist (operator workflows that need a specific user reach for `/v1/users/{sid}` instead). The free-text response fields (`nick`, `description`, `email`, `version`) are **ADC-unescaped to plain UTF-8** - a nick "John Doe" travels the wire as `John\sDoe` and is returned decoded, the same way `/v1/chatlog` returns decoded message bodies - while the structured `cid` / `features` fields carry no escapable chars and pass through verbatim. Filter/sort operate on that same decoded value (a substring search compares against the decoded text, not the wire escapes); note that query-string values are themselves NOT url-decoded by the hub, so a filter term containing a space or non-ASCII char must reach the hub unencoded to match a decoded nick.

[^http-bans-filter]: #264 PR-B filter/sort. Searchable: `nick`, `cid`, `ip`, `by_nick`, `reason` (string), `ban_seconds` (integer + `_min` / `_max`), `expires_at_after` / `expires_at_before` (ISO 8601 "YYYY-MM-DDTHH:MM:SSZ" string compare on the persisted format - the field is only present for still-active bans; already-expired entries are naturally excluded). Sortable: `id` (default; preserves insertion / `+ban show` order), `nick`, `by_nick`, `ban_seconds`, `ban_start`. The `target_type` filter from the #264 spec is intentionally NOT wired - it is not a stored ban-entry field; would need an inferred-from-non-empty-field implementation, deferred as a separate enhancement. Operators searching by target type can substring-filter on `cid` / `ip` / `nick` directly.

[^http-blacklist-filter]: #264 PR-B filter/sort. Searchable: `nick`, `by`, `reason` (string), `blacklisted_at_after` / `blacklisted_at_before` (string compare on the persisted "YYYY-MM-DD / HH:MM:SS" format - lex-sortable, pass the same format as the response shows). Sortable: `nick` (default), `by`, `blacklisted_at`. Filter applies before pagination; `pagination.total` reflects the filtered count.

[^http-msgmanager-filter]: #264 PR-B filter/sort. Searchable: `nick`, `mode` (`main` / `pm` / `both`). Sortable: `nick` (default ascending). `mode` is a string substring filter against the stored mode string: `?mode=pm` matches `pm`; `?mode=both` matches `both`; `?mode=p` matches only `pm` (`both` does not contain `p`). For semantically-exact mode filtering pass the full word. The `settings` sibling field is unaffected by the filter (it reflects per-hub config, not per-block state).

[^http-trafficmgr-filter]: #264 PR-B filter/sort. Searchable: `nick`, `by`, `reason` (string), `blocked_at_after` / `blocked_at_before` (string compare on the normalised "YYYY-MM-DD / HH:MM:SS" format). Legacy entries with no recorded date carry the localised `msg_unknown` placeholder; the date getter returns nil for those so they fail BOTH `_after` and `_before` queries (the helper treats nil as "missing", which sorts last and never matches a range). Sortable: `nick` (default), `by`, `blocked_at`.

[^http-usercleaner-expired-filter]: #264 PR-B filter/sort. Searchable: `nick` (string), `level` (integer + `_min` / `_max`), `days_offline` (integer + `_min` / `_max`), `nick_protected` (boolean), `level_protected` (boolean). Sortable: `days_offline` (default descending - oldest first, matches the pre-#264 vPairs reverse-sort), `nick`, `level`.

[^http-usercleaner-ghosts-filter]: #264 PR-B filter/sort. Same shape as `/v1/usercleaner/expired` but the per-mode integer field is `days_since_reg` instead of `days_offline` (matches the GET response field name and the DELETE handler's `_classify_and_delete` mode discriminator). Sortable: `days_since_reg` (default descending - oldest reg-with-no-login first), `nick`, `level`. Boolean filters `nick_protected` / `level_protected` are present for surface symmetry with `/expired` even though ghosts ignore the level guard at DELETE time.

[^http-registered-filter]: #264 PR-A filter/sort. Searchable: `nick` (string), `by` (string), `comment` (string), `level` (integer exact + `_min` / `_max`), `regged_at_after` / `regged_at_before` (string compare on the persisted `YYYY-MM-DD / HH:MM:SS` format - lex-sort matches chronological for this format; pass the same format as you see in the response), `lastseen_after` / `lastseen_before` (packed-decimal `YYYYMMDDHHMMSS` integer, hub local time - pass the same 14-digit form you see in the response `lastseen`; a numeric compare on the packed form is chronological, same as `regged_at`. ISO 8601 / wall-clock parsing is deliberately deferred to keep core dependency-free in this phase). Sortable: `nick` (default ascending), `level`, `by`, `regged_at`, `lastseen`. Unknown filter or sort field returns 400 `E_BAD_INPUT` with the allowed-fields list. Filter applies BEFORE pagination; `pagination.total` reflects the filtered count.

[^http-registered-list]: Returns `{ok:true, data:{registered:[entry, ...]}, pagination:{total, limit, offset, next_offset}}` per §6.4. Each entry carries `nick`, `level` (integer), `level_name` (resolved via `cfg.levels`), `by` (the firstnick of the original registrar, or the token-label for HTTP-created users), `regged_at` (the raw stored date string `YYYY-MM-DD / HH:MM:SS`, hub local time - not ISO 8601 because the persisted format predates that convention; clients that need ISO can parse it), `lastseen` (a packed-decimal `YYYYMMDDHHMMSS` integer, hub local time - `util.date()`'s "new luadch date style", matching `regged_at`'s local-time convention; `0` if never logged in), and `comment` (from `cmd_reg_descriptions.tbl`, empty string if none). Password is **not** included on the list view - it is only returned exactly once at `POST /v1/registered` creation time; subsequent access to the cleartext password is intentionally not provided (see `cmd_accinfo` v0.32 / sub-task of #95). Bots are excluded from the list (matches `/v1/users` humans-only semantics; a separate `/v1/bots` endpoint is a Phase 8+ candidate). `limit` defaults to 200, clamps to `[1, 1000]`; `offset` defaults to 0. The list is sorted by `nick` (ASCII order) for pagination stability.

[^http-registered-create]: Body `{nick: string required (max 64, no whitespace, length in `[min_nickname_length, max_nickname_length]`), level: integer required (must exist in cfg.levels), password?: string (max 256, no whitespace - absent OR empty => auto-generated via `util.generatepass()`), comment?: string (max 256, control-byte sanitised - stored in `cmd_reg_descriptions.tbl`)}`. Returns 200 with `data: {action:"register", nick, level, level_name, password, comment}` per §7.1.1 - the password is echoed back in the response because the operator needs it to communicate with the newly-registered user (this is the ONE place the cleartext password is surfaced; treat the response as sensitive at the API boundary). Returns **409 E_CONFLICT** if the nick is already regged OR is on the `cmd_delreg` blacklist (operator must clear the blacklist via `+delreg <nick>` first - silent re-reg of blacklisted nicks is intentionally not allowed). Returns **400 E_BAD_INPUT** for invalid nick length, whitespace in nick, unknown level. Persists via `hub.reguser` and refreshes `cfg/user.tbl.bak` via `cfg.checkusers()` (matches the ADC `+reg nick` path).

[^http-registered-get]: Returns 200 with `data: {nick, level, level_name, by, regged_at, lastseen, is_online, comment, traffic_blocked, msg_blocked, ban}`. `regged_at` is the raw stored date string `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s persistence format, not ISO 8601). `lastseen` is a packed-decimal `YYYYMMDDHHMMSS` integer (hub local time, the same "new luadch date style" as `util.date()`, matching `regged_at`'s local-time convention), `0` if the user has never logged in. `is_online` is `true` iff any currently connected user's `firstnick()` matches. `comment` is the entry from `cmd_reg_descriptions.tbl` (empty string if none). `traffic_blocked` is `true` iff `etc_trafficmanager` is active AND the user is currently online with the block flag in their description. `msg_blocked` is `null` if not blocked, otherwise `{mode: "main"|"pm"|"main+pm"}` (mirrors the ADC banner's mode mapping). `ban` is `null` if not banned, otherwise `{by_nick, reason, start, time_seconds, permanent, remaining_seconds?, expires_at?}` - `permanent` (bool, #444) flags a never-expiring ban, for which `time_seconds` is `0` and BOTH `remaining_seconds` and `expires_at` are omitted; for a time-limited ban `expires_at` is ISO 8601 UTC, omitted when `remaining_seconds <= 0` (matches the `/v1/bans` shape; `cid`/`ip`-only bans without a resolved nick do not appear here). Returns **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (humans-only filter matches PR-1 GET list + PATCH). Password is **not** included - the HPAS challenge-response is protocol-mandated cleartext-equivalent (#95 / F-AUTH-1), but the API surface never echoes it back; admins who need to rotate must use `PUT /v1/registered/{nick}/password` (PR-3). The HTTP path always returns the expanded view (= ADC `+accinfoop`).

[^http-registered-delreg]: Requires `X-Confirm: yes` header (§4.6) - router-enforced; missing header returns **400 E_CONFIRMATION_REQUIRED** before the handler runs. Body `{reason?: string (max 256, control-byte sanitised)}` - absent / empty reason performs a plain delreg; non-empty reason also adds the nick to `cmd_delreg_blacklist.tbl` (so a subsequent `POST /v1/registered` for the same nick returns 409). Returns 200 with `data: {action:"delreg", nick, blacklisted, online_kicked}` per §7.1.1. `blacklisted` is `true` iff a non-empty reason was supplied (matches the ADC `+delreg nick <NICK> <REASON>` blacklist-add behaviour); `online_kicked` is `true` iff the target was currently online and received the `ISTA 230 ... TL-1` immediate-kick (the banner carries the reason if one was supplied, plain message otherwise). Cascade cleanups on success: `cmd_reg_descriptions.tbl` entry removed, ban entry removed (via `cmd_ban.del`), trafficmanager block removed (via `etc_trafficmanager.del`). `cfg.checkusers()` refreshes `cfg/user.tbl.bak` (matches the ADC v0.29 path). Returns **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (humans-only filter matches PR-1 / PR-2 / PR-3 / PR-4 / PR-5). The HTTP endpoint is delreg-only - the ADC `+delreg` chat-cmd has a secondary path that removes a nick from `cmd_delreg_blacklist.tbl` when the nick is NOT regged but IS blacklisted; that blacklist-only removal is intentionally out of scope here and belongs to a future `DELETE /v1/blacklist/{nick}` endpoint owned by `etc_blacklist`.

[^http-registered-upgrade]: Body `{level: integer required (must exist in `cfg.levels`)}`. Returns 200 with `data: {action:"level-changed", nick, level, level_name, previous_level, online_kicked}` per §7.1.1. Online users get the `ISTA 230 ... TL300` kick with the formatted level-change message (matches the ADC `+upgrade` kill semantics; the 5-minute TL gives the client a graceful reconnect window). `previous_level` is the integer value before the change. Setting the same level is idempotent - returns 200 with `online_kicked=false` and no mutation (matches PR-3 / PR-4 same-value treatment). Returns **400 E_BAD_INPUT** if `level` is missing, non-integer, negative, or absent from `cfg.levels`; **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (humans-only filter matches PR-1 / PR-2 / PR-3 / PR-4). The API can set any level present in `cfg.levels`, including levels above any individual operator's ceiling.

[^http-registered-nickchange]: Body `{new_nick: string required (max 64, no whitespace, length in `[min_nickname_length, max_nickname_length]`, control-byte sanitised)}`. Returns 200 with `data: {action:"nick-changed", nick, previous_nick, online_kicked}` per §7.1.1 - `nick` is the NEW nick (the target identifier post-action); `previous_nick` is the old one so the caller can correlate. `online_kicked` is `true` iff the renamed user was currently online and got the `ISTA 230 ... TL-1` disconnect to force a reconnect with the new nick; `false` for offline targets (they pick up the new nick on their next login). Renaming to the same nick is idempotent - returns 200 with `online_kicked=false` and no actual mutation (matches the PR-3 setpass treatment of "same value"). Returns **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (humans-only filter matches PR-1 / PR-2 / PR-3); **409 E_CONFLICT** if `new_nick` is already registered. `cfg.nick_change` is the chat-side self-service feature flag for end users and is intentionally not enforced for operator actions through the API. Side-effects on persisted state: `hub.updateusers()` rebuilds the internal regnick index (mandatory after the mutation - same call as the ADC path, see #140); the `cmd_reg_descriptions.tbl` entry (if any) is migrated from old to new nick via `description_check`.

[^http-registered-setpass]: Body `{password: string required (max 256, no whitespace, length in `[cfg.min_password_length, cfg.max_password_length]`, control-byte sanitised)}`. Returns 200 with `data: {action:"password-set", nick, online_notified}` per §7.1.1. `online_notified` is `true` iff the target user was currently online and received the new-password PM (matches the ADC `msg_ok2` behaviour); `false` for offline targets - the operator is responsible for communicating the new password through an out-of-band channel in that case. Returns **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (humans-only filter matches PR-1 / PR-2). The previous-vs-new password sameness check from the ADC path is NOT applied: PUT is idempotent on the HTTP surface, setting the same password twice returns 200 both times.

[^http-registered-patch]: Body `{comment: string required (max 256, control-byte sanitised)}`. Returns 200 with `data: {action:"patch-registered", nick, comment}` per §7.1.1. Currently the only patchable field is `comment` (= ADC `+reg desc <nick> <text>`); the structured fields password / nick / level have their own PUT subresources per §10.2. Empty-string comment is accepted as an explicit "remove" - the entry is deleted from `cmd_reg_descriptions.tbl` so a subsequent GET shows `comment=""`. (The HTTP path diverges from ADC here: `+reg desc <nick> ""` silently no-ops because the ADC parser treats an empty trailing argument as missing, while the structured HTTP body distinguishes "field absent" from "field present and empty".) Returns **404 E_NOT_FOUND** if `{nick}` is not registered OR is a bot (bots are excluded from /v1/registered by the GET handler's humans-only filter; PATCH mirrors that for surface consistency); **400 E_BAD_INPUT** if the body is missing the `comment` field (a no-op PATCH is treated as a usage error rather than an idempotent success so misspelled field names surface to the operator).

#### Bans + blacklist

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/bans` | read | `cmd_ban` (= `+ban show`) - **paginated** + **filter/sort** [^http-ban-1] [^http-bans-filter] |
| GET | `/v1/bans/history` | read | `cmd_ban` (= `+ban showhis`); query `?nick=` for single-nick history [^http-ban-2] |
| POST | `/v1/bans` | admin | `cmd_ban`. body: `{target_type: nick\|cid\|ip\|sid, target, duration_minutes?, permanent?, reason?}` [^http-ban-3] |
| DELETE | `/v1/bans/{id}` | admin | `cmd_ban` [^http-ban-4] |
| GET | `/v1/blacklist` | read | `etc_blacklist` - **paginated** + **filter/sort** [^http-blacklist-1] [^http-blacklist-filter] |
| DELETE | `/v1/blacklist/{nick}` | admin | `etc_blacklist` [^http-blacklist-2] |
| GET | `/v1/clientblocker` | read | `etc_clientblocker` (= ADC `+blocker`) - **landed (#81)** [^http-clientblocker-1] |
| POST | `/v1/clientblocker` | admin | `etc_clientblocker` (= ADC `+addblocker`) - **landed (#81)** [^http-clientblocker-2] |
| DELETE | `/v1/clientblocker/{pattern}` | admin | `etc_clientblocker` (= ADC `+delblocker`) - **landed (#81)** [^http-clientblocker-3] |
| GET | `/v1/blocklist` | read | `etc_blocklist` (= ADC `+blocklist show`) - **paginated** + **filter/sort** [^http-blocklist-list-1] |
| GET | `/v1/blocklist/counts` | read | `etc_blocklist` (= ADC `+blocklist count`) - **landed (#78 Phase C)** [^http-blocklist-list-2] |
| POST | `/v1/blocklist` | admin | `etc_blocklist` (= ADC `+blocklist add`) - **landed (#78 Phase C)** [^http-blocklist-list-3] |
| DELETE | `/v1/blocklist/{id}` | admin | `etc_blocklist` (= ADC `+blocklist del`) - **landed (#78 Phase C)** [^http-blocklist-list-4] |
| GET | `/v1/whitelist` | read | `etc_whitelist` (= ADC `+whitelist show`) - **paginated** + **filter/sort** [^http-whitelist-1] |
| GET | `/v1/whitelist/counts` | read | `etc_whitelist` (= ADC `+whitelist count`) - **landed (#78 allowlist Phase D)** [^http-whitelist-2] |
| POST | `/v1/whitelist` | admin | `etc_whitelist` (= ADC `+whitelist add`) - **landed (#78 allowlist Phase D)** [^http-whitelist-3] |
| DELETE | `/v1/whitelist/{id}` | admin | `etc_whitelist` (= ADC `+whitelist del`) - **landed (#78 allowlist Phase D)** [^http-whitelist-4] |
| GET | `/v1/geoip` | read | `etc_geoip` - GeoIP policy + MMDB status (country/ASN DB freshness) |
| GET | `/v1/proxydetect` | read | `etc_proxydetect` - proxy/VPN detection provider + cache status |
| GET | `/v1/blocklist/feeds` | read | `etc_blocklist_feeds` - per-feed refresh status (last pull, entry counts, errors) |

[^http-ban-1]: Returns `{ok:true, data:{bans:[entry, ...]}}`. Each entry carries `id` (1-based index into the live bans array - the same `{id}` accepted by DELETE), `nick`, `cid`, `hash`, `ip`, `reason`, `by_nick`, `by_level`, `ban_seconds`, `ban_start` (epoch seconds, hub clock), `permanent` (bool - a permanent ban never expires; #444), `remaining_seconds` (can be negative for not-yet-pruned-expired entries; pruning happens on `onConnect` of the banned user, not on a timer), and `expires_at` (ISO 8601 UTC, omitted when `remaining_seconds <= 0`). **For a permanent ban** (`permanent:true`) `ban_seconds` is `0` and BOTH `remaining_seconds` and `expires_at` are omitted - a consumer distinguishes "permanent" from "expired-not-yet-pruned" by the `permanent` flag, not by the absent expiry. The `id` is NOT a stable surrogate key - it shifts every time a ban is removed (the underlying `bans` array is reindexed by `table.remove`). Operators / tooling MUST re-list before issuing a follow-up DELETE.

[^http-ban-2]: Returns `{ok:true, data:{history:{nick: [entry, ...]}}}` keyed by firstnick. Each entry carries `date` (string `YYYYMMDDhhmmss`), `reason`, `by_nick`, `bantime` (seconds), `start` (epoch seconds), and `state` (`"active"` or `"expired"` based on `bantime + start` vs now). Query `?nick=<NICK>` restricts the response to one user; missing/empty returns the full history. `cid`/`ip`-targeted bans without a resolved firstnick do NOT appear in the history (the ADC-side `addban` only writes history rows for `nick != ""` entries; matches `+ban showhis` behaviour).

[^http-ban-3]: Body `{target_type: "nick"|"cid"|"ip"|"sid" required, target: string required (max 64), duration_minutes: integer optional (1..525600 = 1 year cap, schema-enforced; falls back to cfg `cmd_ban_default_time` if omitted), permanent: boolean optional (default false), reason: string optional (max 256)}`. **`permanent: true` bans forever** (= ADC `+ban ... permanent`, #444): it ignores `duration_minutes`, stores a `permanent` marker with `ban_seconds 0`, and the response omits `duration_minutes` + `expires_at`. Returns 200 with `data: {action:"ban", id, target_type, target, target_nick?, duration_minutes?, permanent, reason, by, expires_at?}` per §7.1.1 (`duration_minutes` and `expires_at` present only for a time-limited ban). `target_nick` is present only when the target was resolved to an online user (sid path always; nick/cid/ip if currently online). Resolution rules: `sid` is strict-online-only (404 if not online); `nick` falls back to `hub.getregusers()` for offline registered nicks (404 if neither online nor registered); `cid`/`ip` are blind-add (no offline lookup - matches the ADC `+ban` behaviour). Persisted entries get `by_level = 100` so they cannot be lifted by lower-level operators via the ADC `+unban` cmd (only level >= ban.by_level can lift). Online targets are kicked with `ISTA 232 ... TL<bantime>` (time-limited) or `ISTA 231 ... TL-1` (permanent), matching the ADC path. `reason` and `req.token_label` are control-byte sanitised (`util.strip_control_bytes`) before they hit the bans table or the opchat report frame.

[^http-ban-4]: `{id}` is the 1-based index from GET /v1/bans. Returns 200 with `data: {action:"unban", id, removed:{nick, cid, ip, reason, by_nick}, by}` so the operator's audit / undo flow has the snapshot of what was lifted. The response `id` echoes the requested index (which no longer exists post-removal, and may even point to a different victim now if a concurrent mutation reindexed the array); for any audit or undo workflow the stable identifiers are the `removed.nick` / `removed.cid` / `removed.ip` fields, NOT the response `id`. Returns **404 E_NOT_FOUND** if there is no entry at that index, **400 E_BAD_INPUT** if `{id}` is not a positive integer. The index race window (between GET and DELETE another mutation reindexes the array) is documented but not papered over: the DELETE always operates on `bans[id]` as-of the request, so a concurrent removal can cause a misaligned delete. Operator tooling MUST refresh the list between deletes to be safe; for batch deletes, sort the targets by descending id (so earlier removals don't shift later indices). The `+unban` ADC cmd uses nick/cid/ip lookups instead and is unaffected.

[^http-blacklist-1]: Returns 200 with `data: {entries: [{nick, blacklisted_at, by, reason}, ...]}`. `blacklisted_at` is the raw stored string `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s persistence format, not ISO 8601). `by` is the nick of the operator who issued the original `+delreg nick <NICK> <REASON>` (the chat-cmd that produces blacklist entries). `reason` is the verbatim reason text the original delreg supplied. Entries are returned sorted by `nick` ascending by default (per the `[^http-blacklist-filter]` filter/sort spec; `?sort=` can override). Prior to #264 PR-B the response was in `pairs()` hash-table order; #275 CON-N2 footnote update. The file is loaded on-demand per request (same pattern as the ADC `+blacklist show` cmd; `cmd_delreg` also writes on-demand without an in-memory cache). Lua is single-threaded and the handlers do not yield between load and save, so there is no cross-plugin write race despite both plugins doing independent load-modify-save against the same file.

[^http-blacklist-2]: No request body. Returns 200 with `data: {action: "blacklist-removed", nick, removed: {blacklisted_at, by, reason}}` per §7.1.1 - the `removed` snapshot lets the operator's audit / undo flow record the deletion. Returns **404 E_NOT_FOUND** if `{nick}` is not on the blacklist (idempotent 200 would mask the typo case where an operator misspells the target nick). **No X-Confirm gate**: a single-nick removal is reversible by issuing ADC `+delreg <nick> <reason>` against the same nick (which re-adds the blacklist entry), so the cost of accidental removal is bounded.

[^http-clientblocker-1]: No request body. Returns 200 with `data: {patterns: [{pattern, reason}, ...], count}` per §7.1. Entries sorted by `pattern` ascending for stable output. The match runs against the wire-unescaped `user:version()` (= concatenated `<AP> <VE>` from BINF) via `string.find` so a `pattern` here is a Lua pattern, NOT a PCRE. Use `%+` to match a literal `+`, `%s` for whitespace, etc.

[^http-clientblocker-2]: Body `{pattern: string required (max 4096 chars wire / 200 effective per `etc_clientblocker_max_pattern_len`), reason?: string (max 1024 chars; defaults to `cfg.etc_clientblocker_default_reason` when absent or empty)}`. Returns **201 Created** with `data: {action:"added", pattern, reason}` per §7.1.1. Persists immediately to `scripts/data/etc_clientblocker.tbl`. Error mapping: **400 E_BAD_INPUT** (`bad_pattern` - empty / over the configured length cap / fails the `pcall(string.find, "", pat)` compile probe); **409 E_CONFLICT** (`exists` - pattern is already configured; operator must `DELETE` first - no silent overwrite). The kick that the pattern eventually drives uses ADC `ISTA 231 ... TL-1` so the client treats the disconnect as permanent (do-not-reconnect). Emits `client.block.add` audit event with `meta: {pattern, reason}`.

[^http-clientblocker-3]: No request body. Path parameter is the verbatim pattern - the router uses `([^/]+)` capture and does NOT percent-decode, so the pattern must NOT contain `/`, `?`, `#` or `&` (POST/+addblocker reject those at edit time with `bad_pattern`). All other URL-unreserved-ish chars used by Lua patterns (`%`, `+`, `.`, `(`, `)`, `[`, `]`, `*`, `-`, `^`, `$`) pass through cleanly. Returns 200 with `data: {action:"deleted", pattern, previous}` per §7.1.1 - `previous` is the kick reason the pattern used to carry (so the caller can correlate / restore). Returns **404 E_NOT_FOUND** (`not_found`) if the pattern is not configured; **400 E_BAD_INPUT** (`bad_pattern`) for an empty path var. The unblock takes effect IMMEDIATELY in the in-memory pattern cache (the next onConnect iterates the fresh map) - no `+reload` needed. Emits `client.block.remove` audit event with `meta: {pattern, previous_reason}`.

[^http-blocklist-list-1]: Returns `{ok:true, data:{entries:[entry, ...]}, pagination:{...}}`. Each entry carries `id` (stable monotonically-assigned integer - unlike `/v1/bans` where `id` is a 1-based index that shifts on removal, blocklist ids are engine-assigned surrogate keys and stay valid across removes; a re-add of the same CIDR gets a fresh id), `cidr` (canonical form; the engine normalises host bits to zero at add-time and rejects host-bits-set CIDRs with a clear error), `source` (one of `manual` / `geoip` / `external` / `proxycheck` / `ipqs` / `vpnapi` - matches the Phase A `_SOURCE_PRIORITY` enum), `stealth` (bool), `reason`, `by_nick`, `by_level` (nil for auto-feed sources), `expires_at` (unix ts, nil for permanent entries), `created_at`, and `meta` (per-source free-form; Phase D fills country + asn, Phase E fills feed name, Phase F fills provider + detection-type). Supports http_filter query params: `source=<one>`, `stealth=true|false` (strict boolean - non-`true`/`false` returns 400 E_BAD_INPUT), `cidr=<substring>` (substring match on canonical CIDR form; e.g. `?cidr=192.0.2` narrows to that /24), `reason=<substring>`, `by_nick=<substring>`, `by_level=<int>`, `by_level_min=<int>`, `by_level_max=<int>`, `created_at_min=<ts>`, `created_at_max=<ts>`, `expires_at_min=<ts>`, `expires_at_max=<ts>`. Sort field via `sort=<field>` (default `id`, descending prefix `-`); sortable fields: `id`, `cidr`, `source`, `created_at`, `expires_at`.

[^http-blocklist-list-2]: No request body. Returns 200 with `data: {total, by_source}` per §7.1. Shape is prometheus + WebUI dashboard-friendly: `total` is a flat integer scalar, `by_source` is a `{source: count}` map (empty `{}` on a fresh install). A source with zero live entries is OMITTED from `by_source` rather than reported as `0` - callers building rate charts should treat absence as zero. Snapshot-at-request-time (not cached); on a fully-populated store the count iterates `_entries` once (cheap - no bucket walk). Same auth semantics as GET list (`read` scope).

[^http-blocklist-list-3]: Body `{cidr: string required (max 45; IPv4 or IPv6 with optional prefix - `1.2.3.4` = `/32`, `2001:db8::` = `/128`; CIDRs with host bits set are rejected - `1.2.3.4/24` -> error with "use network address instead"), stealth?: boolean (default false - per-rule opt-in matching the ADC positional flag), source?: string (enum: manual / geoip / external / proxycheck / ipqs / vpnapi; default `manual`), reason?: string (max 256, control-byte sanitised via `util.strip_control_bytes`), expires_at?: integer (unix timestamp, 1..2147483647 = 2038-01-19 upper bound covering int32 platforms; nil / absent for permanent entries. `0` is rejected as a UX trap to prevent an accidentally-immediately-expired entry)}`. Returns **201 Created** with `data: {action:"added", id, cidr, source}` per §7.1.1. Error mapping: **400 E_BAD_INPUT** for malformed CIDR / host-bits-set / engine-rejected input; **500 E_INTERNAL** for on-disk persistence failure (rare - would mean `scripts/data/` write failed). HTTP-created entries are attributed with `by_nick = <token label>` and `by_level = 100` (synthetic master) so a subsequent DELETE via the same token bypasses the Phase B hierarchy guard - the token IS the trust surface. `source = "geoip" / "external" / "proxycheck" / "ipqs" / "vpnapi"` from an admin token is ALLOWED but the plan expectation is that the auto-feed plugins (Phase D/E/F) own those source labels; a manual POST with a non-manual source competes with the feed plugin's next refresh cycle (which will re-add the entry with fresh metadata). Emits `blocklist.add` audit event with `meta: {cidr, source, stealth, id}`.

[^http-blocklist-list-4]: No request body. Path parameter `{id}` is the stable numeric id from GET /v1/blocklist entries. Returns 200 with `data: {action:"removed", id, removed:{cidr, source, reason, by_nick}}` per §7.1.1 so the operator's audit / undo flow has the snapshot of what was lifted. Returns **404 E_NOT_FOUND** if the id is not in the live store (idempotent 200 would mask the typo case); **400 E_BAD_INPUT** if `{id}` is not a positive integer. Unlike `/v1/bans/{id}` (which uses a 1-based array index that shifts on removal), blocklist ids are stable monotonic - GET-then-DELETE is safe against concurrent mutations of unrelated entries. HTTP treats the token as master (level 100), so an admin token can undo ANY entry regardless of who added it. Operators wanting tighter control on HTTP-driven removes gate at the token-scope layer (revoking the token), not the entry-level layer. The unblock takes effect IMMEDIATELY (the engine's bucket cache is mutated in the same tick and re-persisted to `scripts/data/etc_blocklist.tbl` before the response returns). Emits `blocklist.remove` audit event with `meta: {id, cidr, source}` and the entry's original reason as the audit reason field (matching cmd_ban convention).

[^http-whitelist-1]: Returns `{ok:true, data:{entries:[entry, ...]}, pagination:{...}}`. Each entry carries `id` (stable monotonically-assigned integer, valid across removes; a re-add gets a fresh id), `cidr` (canonical form; host-bits-set CIDRs rejected at add), `source` (`manual` = operator add, `pinger` = bundled hublist-pinger seed - a LABEL only, no priority), `reason`, `by_nick`, `by_level` (nil for the seed), `expires_at` (unix ts, nil for permanent), `created_at`, `meta`. There is NO `stealth` field (the whitelist is allow-only). Supports http_filter query params `source=<one>`, `cidr=<substring>`, `reason=<substring>`, `by_nick=<substring>`, `by_level[_min|_max]=<int>`, `created_at[_min|_max]=<ts>`, `expires_at[_min|_max]=<ts>`; sort via `sort=<field>` (default `id`, descending prefix `-`; sortable: `id`, `cidr`, `source`, `created_at`, `expires_at`).

[^http-whitelist-2]: No request body. Returns 200 with `data: {total, by_source}` per §7.1 - `total` a flat integer, `by_source` a `{source: count}` map (empty `{}` on a store with no entries). Same auth as GET list (`read` scope). A fresh hub reports the bundled pinger seed (source `pinger`), so `total` is non-zero out of the box.

[^http-whitelist-3]: Body `{cidr: string required (max 45; `1.2.3.4` = `/32`, `2001:db8::` = `/128`; host-bits-set CIDRs rejected - `1.2.3.4/24` -> error), source?: string (enum: manual / pinger; default `manual`), reason?: string (max 256, control-byte sanitised via `util.strip_control_bytes`), expires_at?: integer (unix ts, 1..2147483647; nil / absent for permanent; `0` rejected as a UX trap)}`. Returns **201 Created** with `data: {action:"added", id, cidr, source}` per §7.1.1. Error mapping: **400 E_BAD_INPUT** for malformed / host-bits-set / engine-rejected CIDR; **500 E_INTERNAL** for on-disk persistence failure. HTTP-created entries are attributed `by_nick = <token label>`, `by_level = 100` (synthetic master) so a subsequent DELETE via the same token bypasses the hierarchy guard - the token IS the trust surface. Emits `whitelist.add` audit event with `meta: {cidr, source, id, by_level}`. Precedence reminder: a whitelisted IP overrides the AUTOMATED blockers (GeoIP / proxydetect / feeds / hub-limit + automated blocklist entries) but NOT a manual `+ban` / `+blocklist add` (enforced in `core/blocklist.check_ip`).

[^http-whitelist-4]: No request body. Path parameter `{id}` is the stable numeric id from GET /v1/whitelist. Returns 200 with `data: {action:"removed", id, removed:{cidr, source, reason, by_nick}}` (control-byte sanitised) per §7.1.1 so the operator's audit / undo flow has the snapshot. Returns **404 E_NOT_FOUND** if the id is not in the live store; **400 E_BAD_INPUT** if `{id}` is not a positive integer. Whitelist ids are stable monotonic (GET-then-DELETE is safe against unrelated mutations). HTTP treats the token as master (level 100), so an admin token can undo ANY entry regardless of who added it (including the bundled seed). Emits `whitelist.remove` audit event with `meta: {id, cidr, source}`.

#### Hub control

| Method | Path | Scope | Plugin |
|---|---|---|---|
| POST | `/v1/announce` | admin | `cmd_mass` [^http-announce-1] |
| POST | `/v1/topic` | admin | `cmd_topic` [^http-topic-1] |
| GET | `/v1/aliases` | read | `etc_aliases` [^http-aliases-1] |
| POST | `/v1/aliases` | admin | `etc_aliases` [^http-aliases-2] |
| DELETE | `/v1/aliases/{alias}` | admin | `etc_aliases` [^http-aliases-3] |
| POST | `/v1/reload` | admin | `cmd_reload` - requires `X-Confirm: yes` (§4.6) [^http-reload-1] |
| POST | `/v1/restart` | admin | `cmd_restart` - requires `X-Confirm: yes` (§4.6) [^http-restart-1] |
| POST | `/v1/shutdown` | admin | `cmd_shutdown` - requires `X-Confirm: yes` (§4.6) [^http-shutdown-1] |

[^http-announce-1]: Body `{message: string required (max 1024 chars, control-byte sanitised), scope: "all"|"hub"|"level" required, level?: integer (REQUIRED when scope="level", must exist in cfg.levels)}`. `scope="all"` broadcasts the banner to all online users with the operator's token-label as the visible sender (= ADC `+mass`); `scope="hub"` broadcasts without sender in the banner (= ADC `+masshub`); `scope="level"` PMs only users at the given level (= ADC `+masslvl N`). Returns 200 with `data: {action:"announce", scope, message, sender, level?, recipients?}` per §7.1.1; `recipients` is the matched-user count for scope="level" (broadcast variants omit it - derive from `/v1/stats`). A single `admin`-scoped token can issue any of the three ADC variants via the structured body.

[^http-topic-1]: Body `{topic?: string}` (max 256 chars, control-byte sanitised). Missing OR empty `topic` resets the hub topic to `cfg.hub_description`; non-empty sets it. The ADC `+topic default` magic-keyword does NOT apply on the HTTP path - the structured body expresses "reset" via absence, so HTTP callers CAN literally set the topic to the word "default" via `{"topic": "default"}`. Returns 200 with `data: {action:"topic-set"|"topic-reset", topic, previous}` per §7.1.1. The new topic is broadcast to all connected users via `IINF DE...` and persisted to `scripts/data/cmd_topic.tbl`.

[^http-reload-1]: No request body. Returns 200 with `data: {action:"reload", reloaded:["cfg", "scripts"]}` per §7.1.1 (hub-control variant: no `sid`/`nick`). `hub.restartscripts()` clears + re-registers the entire HTTP route table from plugin `onStart` listeners; the in-flight handler's closure is captured and the response is sent normally. Lua is single-threaded so no concurrent-reload guard is needed. Idempotent retries via `X-Idempotency-Key` replay the cached 200 (desired - operator-tool retry should not double-reload).

[^http-restart-1]: Body `{message?: string}` (max 1024 chars, control-byte sanitised). The message broadcasts to the hub as a chat banner just like `+restart <MSG>`; absent / empty message skips the broadcast. Returns 200 with `data: {action:"restart", message, countdown}` per §7.1.1 (no `sid`/`nick` - hub-control endpoint). `countdown` reflects `cfg.cmd_restart_toggle_countdown` (true = 10-second ASCII countdown before exit; false = immediate exit after ~2s). A concurrent second call returns **409 E_CONFLICT** (restart already armed); use `X-Idempotency-Key` for safe retries.

[^http-shutdown-1]: Body `{message?: string}` (max 1024 chars, control-byte sanitised). Same shape as `POST /v1/restart`. Returns 200 with `data: {action:"shutdown", message, countdown}` per §7.1.1 (no `sid`/`nick` - hub-control endpoint). `countdown` reflects `cfg.cmd_shutdown_toggle_countdown` (true = 10-second ASCII countdown before exit; false = `hub.requestexit()` immediately, which fires `onShutdown` and the do_exit timer). A concurrent second call returns **409 E_CONFLICT**; use `X-Idempotency-Key` for safe retries.

[^http-aliases-1]: No request body. Returns 200 with `data: {aliases: [{alias, target}, ...], count}` per §7.1. Entries are sorted by `alias` for stable pagination-free output. The list mirrors what `+aliases` shows in the "Operator-defined aliases" section - built-in plugin multi-name registrations (e.g. usr_uptime's `useruptime` + `uu`) are NOT included; those are surfaced only on the ADC side via `etc_hubcommands.list()` and are visible in the `+aliases` "Built-in command names" section. The `read` scope gate (not `admin`) matches the GET-is-read convention.

[^http-aliases-2]: Body `{alias: string required (max 64, must match `^[A-Za-z]+$` - letters only, matching the ADC dispatcher's `%a+` capture), target: string required (max 64, must be an existing registered command name)}`. Returns **201 Created** with `data: {action:"added", alias, target}` per §7.1.1. Persists immediately to `cfg/aliases.tbl` (atomic write). Error mapping: **400 E_BAD_INPUT** (`bad_alias` - non-alpha alias / target name); **404 E_NOT_FOUND** (`no_target` - target is not a registered command); **409 E_CONFLICT** (`conflict_command` - alias name collides with an existing real command, real commands always win; or `exists` - alias is already mapped to a target, the operator must `DELETE` first - no silent overwrite).

[^http-aliases-3]: No request body. Returns 200 with `data: {action:"deleted", alias, previous}` per §7.1.1 - `previous` is the target the alias used to map to (so the caller can correlate / restore). Persists immediately to `cfg/aliases.tbl`. Returns **404 E_NOT_FOUND** (`not_found`) if the alias is not configured; **400 E_BAD_INPUT** (`bad_alias`) if the path parameter does not match `^[A-Za-z]+$`.

#### Logs + records + runtime

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/log/error?lines=N` | admin | `cmd_errors` [^http-log-error-1] |
| GET | `/v1/log/cmd?lines=N` | admin | `etc_cmdlog` [^http-log-cmd-1] |
| GET | `/v1/log/audit?lines=N` | admin | `etc_auditlog` (#84) [^http-log-audit-1] |

[^http-log-audit-1]: Registered by the `etc_auditlog` plugin, NOT hub-intrinsic - returns 404 `E_NOT_FOUND` when that plugin is disabled. Tail of today's staff-action audit log (`log/audit-YYYY-MM-DD.jsonl`); query `?lines=N` (default 200, max 1000); response `{lines, returned, total_lines}` matches sibling tail endpoints; multi-day reads are filesystem-side (`jq` / `cat`) by design.

[^http-log-error-1]: Query `?lines=N` (default 200, max 1000 per §6.4 tail-style cap). Non-numeric or out-of-range values are clamped to the default, not rejected. Returns 200 with `data: {lines:[...], returned, total_lines}`. `total_lines` is the file's full line count (operators can spot "the last 200 of 1500" at a glance). Missing log file returns 200 with `lines: []` and `total_lines: 0` (matches the ADC path's "No errors." semantic without surfacing a 404 for a file that has not been written yet).
| DELETE | `/v1/log/{name}` | admin | `etc_log_cleaner` - `{name}` ∈ `error`, `cmd` [^http-log-clean-1] |

[^http-log-cmd-1]: Same query / response / clamping semantics as `GET /v1/log/error` (§10.2). Returns 200 with `data: {lines:[...], returned, total_lines}`. The ADC-side `+cmdlog show` path remains unchanged - it sends the whole file as a chat banner; the HTTP path is line-tail per the §6.4 convention.

[^http-log-clean-1]: `{name}` is restricted to the values the bundled `etc_log_cleaner` plugin supports: `error` (truncates `log/error.log`) and `cmd` (truncates `log/cmd.log`). Unknown name returns **400 E_BAD_INPUT**. Returns 200 with `data: {action:"log-cleared", name, bytes_before}` per §7.1.1 (hub-control variant: no `sid`/`nick`); `bytes_before` is the file's pre-truncate size for the operator audit trail. (Spec was originally aspirational about `event` / `script` here; the plugin never supported those, and the spec is now corrected to match plugin reality.)
| GET | `/v1/records` | read | `etc_records` [^http-records-1] |
| DELETE | `/v1/records` | admin | `etc_records` [^http-records-2] |
| GET | `/v1/runtime` | read | `hub_runtime` [^http-runtime-1] |
| PUT | `/v1/runtime` | admin | `hub_runtime` [^http-runtime-2] |
| GET | `/v1/chatlog?lines=N` | read | `etc_chatlog` [^http-chatlog-1] |
| GET | `/metrics` | read | `etc_prometheus` - **landed (#83)** [^http-metrics-1] |

[^http-metrics-1]: Returns 200 with `Content-Type: text/plain; version=0.0.4; charset=utf-8` and a Prometheus 0.0.4 text-exposition body. **Not a JSON-envelope response** - the handler uses the router's `raw_body` + `content_type` escape hatch (same as `/health`). 7 gauges (`luadch_users_online`, `luadch_users_online_bots`, `luadch_share_total_bytes`, `luadch_files_total`, `luadch_hub_uptime_seconds`, `luadch_lua_memory_kb`, `luadch_active_bans`) + 7 counters (`luadch_logins_total`, `luadch_logouts_total`, `luadch_failed_auths_total`, `luadch_chat_msgs_total`, `luadch_pm_msgs_total`, `luadch_searches_total`, `luadch_script_errors_total`). Gauges are computed on every scrape from `hub.getusers()` + `signal.get("start")` + `collectgarbage("count")` + `cmd_ban.bans` (nil-safe if cmd_ban not loaded). Counters increment on the corresponding lifecycle hooks (`onLogin` / `onLogout` / `onFailedAuth` / `onBroadcast` / `onPrivateMessage` / `onSearch` / `onError`); they reset on hub restart AND on `+reload` (the plugin's file-local upvalues re-initialise) - matches Prometheus' monotonic-since-target-restart convention. The plugin is opt-in via cfg `etc_prometheus_activate` (default `false`); when off the route is not registered and the router returns 404 E_NOT_FOUND. The endpoint uses scope `read`; Prometheus must be configured with the bearer token. With `http_api_log_reads = false` (default) the scrape pulls do not flood `log/api_audit.log`. No level breakdown labels - keeps the time-series cardinality flat (one series per metric).

[^http-runtime-1]: Returns 200 with `data: {session_seconds, total_seconds}`. Both are raw integer seconds (consistent with `/v1/version`'s `uptime` and the raw-bytes convention of `/v1/records`). `session_seconds` is the current process's uptime (from `signal.get("start")`); `total_seconds` is the persisted accumulator written to `scripts/data/hub_runtime.tbl` by the plugin's 60s `onTimer` (moved from `core/hci.lua` in #445 so an upgrade no longer zeros it). ADC `+runtime show` formats both via `util.formatseconds` into "X years, Y days, ..." strings; the HTTP path returns raw seconds and lets the client format. On a fresh hub before the first onTimer tick fires, `total_seconds` is `0`.

[^http-runtime-2]: Body `{hubruntime: integer (>= 0) required}`. Sets the persisted runtime accumulator to the supplied value and rewrites `hubruntime_last_check` to `util.date()` so the next 60s `set_hubruntime` tick computes its diff from now (rather than racing the accumulator forward by whatever value sat in the file before the PUT). Returns 200 with `data: {action: "runtime-set", hubruntime}` per §7.1.1 (hub-control variant: no `sid`/`nick`). Returns **400 E_BAD_INPUT** if `hubruntime` is missing, non-integer, or negative. PUT is family-consistent with the #236 registered-users PUTs (all require a typed body). The closest ADC chat-cmd is `+runtime reset` (= `PUT {hubruntime: 0}` on the HTTP path), but PUT is not strictly equivalent: ADC `reset_hubruntime` only zeros `hubruntime` and does NOT touch `hubruntime_last_check`, so the first 60s onTimer tick after `+runtime reset` adds the pre-reset accumulator-diff back into the file (the user sees ~60s of "leftover" on the first post-reset tick). The HTTP PUT path resets `hubruntime_last_check` together with `hubruntime`, so the first tick after PUT adds exactly ~60s. The HTTP path also generalises to "set runtime to N" because the underlying storage (`scripts/data/hub_runtime.tbl`) is a plain integer count - a future ops workflow that needs to seed runtime from a backup uses the same endpoint without a new verb.

[^http-records-1]: Returns 200 with `data: {hub_share: {total_bytes, recorded_at}, max_users: {count, recorded_at}, top_sharer: {nick, share_bytes}}`. Raw byte counts (no unit formatting - clients decide display units); ADC `+records show` builds a `MB / GB / TB / PB` string via `shareoptimize`, the HTTP path does NOT (consistent with `/v1/stats` raw-bytes convention). `recorded_at` is `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s persistence format, not ISO 8601); collapses to `""` when both halves of the persisted record are missing (never-sampled hub). On a fresh hub before any sample fires, all three counters default to `0` - `hub_share.total_bytes`, `max_users.count`, and `top_sharer.share_bytes` - with `top_sharer.nick` defaulting to `"none"`, so a value of `0` unambiguously means "no record yet". (#618 normalised the `hub_share` seed from a vestigial `1` to `0`; the `> records[3]` max-tracker in `hubshare()` increments identically from a `0` seed since no real hub totals exactly 1 byte. Hubs recorded before the fix keep their persisted value until the next `+records reset`.)

[^http-records-2]: No request body. Returns 200 with `data: {action: "records-reset"}` per §7.1.1. Calls the same `reset()` function the ADC `+records reset` chat-cmd uses: the persisted records table is reseeded to zero / today, then immediately re-sampled against the live hub via `hubshare()` + `onliners()` so a follow-up GET returns current values rather than a transient zero. **Not X-Confirm gated**: records are recomputed continuously from live hub state, so the "destruction" is bounded - only the historical max-share / max-users date stamps are lost, and they re-accrete as the hub runs.

[^http-chatlog-1]: Query `?lines=N` (default = cfg `etc_chatlog_default_lines`, hard cap = `min(cfg etc_chatlog_max_lines, 1000)` per §6.4 tail-style cap). Non-numeric or out-of-range `lines` values are clamped to the default, not rejected. Returns 200 with `data: {lines:[{timestamp, nick, message}, ...], returned, total_lines}`. Each entry carries the raw stored timestamp string `YYYY-MM-DD / HH:MM:SS` (hub local time - matches `cmd_reg`'s persistence format, not ISO 8601; clients that need ISO can parse it), the sender nick at post time, and the chat message body (already `hub.escapefrom`-decoded, plain UTF-8 text not ADC wire). `total_lines` is the in-memory log buffer size (capped at `etc_chatlog_max_lines`); operators can spot "the last 200 of 1500 ever written" is NOT possible because the script persists only the rolling window. Returns 200 + empty `lines` array if the log has not yet been written. The exception list is for chat-side users opting out of the join-time banner reroll; an operator with an API token is expected to see the full history.

#### Subsystem managers

| Method | Path | Scope | Plugin |
|---|---|---|---|
| GET | `/v1/msgmanager` | read | `etc_msgmanager` - **paginated** + **filter/sort** [^http-msgmanager-1] [^http-msgmanager-filter] |
| POST | `/v1/msgmanager/{nick}` | admin | `etc_msgmanager` [^http-msgmanager-2] |
| DELETE | `/v1/msgmanager/{nick}` | admin | `etc_msgmanager` [^http-msgmanager-3] |
| GET | `/v1/trafficmanager/settings` | read | `etc_trafficmanager` [^http-trafficmgr-1] |
| GET | `/v1/trafficmanager/blocks` | read | `etc_trafficmanager` - **paginated** + **filter/sort** [^http-trafficmgr-2] [^http-trafficmgr-filter] |
| POST | `/v1/trafficmanager/blocks/{nick}` | admin | `etc_trafficmanager` [^http-trafficmgr-3] |
| DELETE | `/v1/trafficmanager/blocks/{nick}` | admin | `etc_trafficmanager` [^http-trafficmgr-4] |
| GET | `/v1/usercleaner/expired` | read | `cmd_usercleaner` - **paginated** + **filter/sort** [^http-usercleaner-1] [^http-usercleaner-expired-filter] |
| DELETE | `/v1/usercleaner/expired` | admin | `cmd_usercleaner` - requires `X-Confirm: yes` (§4.6) [^http-usercleaner-2] |
| GET | `/v1/usercleaner/ghosts` | read | `cmd_usercleaner` - **paginated** + **filter/sort** [^http-usercleaner-3] [^http-usercleaner-ghosts-filter] |
| DELETE | `/v1/usercleaner/ghosts` | admin | `cmd_usercleaner` - requires `X-Confirm: yes` (§4.6) [^http-usercleaner-4] |
| DELETE | `/v1/usercleaner/orphan-comments` | admin | `cmd_usercleaner` - requires `X-Confirm: yes` (§4.6) [^http-usercleaner-5] |

[^http-msgmanager-1]: Returns 200 with `data: {blocks: [{nick, mode}, ...], settings: {activate, blocked_main_levels, blocked_pm_levels}}`. Merges the ADC `+msgmanager showusers` (per-nick block overrides) and `+msgmanager showsettings` (cfg permission tables) views into one response - operator clients typically want both. `mode` is the HTTP enum form `"main"|"pm"|"both"`; internal storage is single-letter `m`/`p`/`b` (mapped at the HTTP boundary so the ADC ShowUsers display stays unchanged while the API surface is readable). `blocked_main_levels` / `blocked_pm_levels` are sorted ascending integer arrays of cfg level keys where `permission_main` / `permission_pm` is false (those levels are blacklisted from sending main / pm chat). Empty array means no level-based block. The endpoint returns 404 if the plugin is disabled (cfg `etc_msgmanager_activate = false` - early return at module load prevents the http_register call; the router emits a generic 404 E_NOT_FOUND because no route was ever registered for that path).

[^http-msgmanager-2]: Body `{mode: "main"|"pm"|"both" required}` - schema-enum-validated by the router; missing or unknown mode returns **400 E_BAD_INPUT** before the handler runs. Returns 200 with `data: {action: "blocked", nick, mode}` per §7.1.1. Target nick is treated as the firstnick (the stable registered identifier). Online check intentionally relaxed vs ADC `+msgmanager blockmain` (which requires `hub.isnickonline`): offline registered nicks can be pre-blocked so the next reconnect fires the onBroadcast / onPrivateMessage filter immediately. Returns **409 E_CONFLICT** if the nick is already in block_tbl (operator must `DELETE` first to change mode; mode-change-in-place is intentionally NOT supported, matching the ADC `msg_stillblocked` semantic). Returns **400 E_BAD_INPUT** for empty / missing nick. Returns 404 if the plugin is disabled (same generic 404 mechanism as the GET endpoint above).

[^http-msgmanager-3]: No request body. Returns 200 with `data: {action: "unblocked", nick, previous_mode}` per §7.1.1 - `previous_mode` is the mode the entry was set to before removal so the operator's audit / undo flow has the snapshot. Returns **404 E_NOT_FOUND** if the nick is not in block_tbl (idempotent 200 would mask typos). Offline-tolerant - no online check (a divergence from the ADC `+msgmanager unblock` cmd which requires the target to be online; the HTTP path intentionally fixes this pre-existing chat-cmd UX limitation, since the per-nick override is a stored key, not a session attribute). Returns 404 if the plugin is disabled (same generic 404 mechanism as the GET endpoint above).

[^http-usercleaner-1]: Returns 200 with `data: {expired_days, entries: [{nick, days_offline, level, nick_protected, level_protected}, ...]}`. `expired_days` echoes the cfg threshold (`cmd_usercleaner_settings.tbl` `expired_days`, default 365). `entries` lists offline regged accounts whose `lastseen` (or `lastconnect` fallback) is older than that threshold. `days_offline` is the elapsed offline days (matches ADC `+usercleaner showexpired`). `nick_protected` is true iff the nick is in `cmd_usercleaner_exceptions.tbl`; `level_protected` is true iff the level appears with `true` in cfg `cmd_usercleaner_protected_levels`. Both flags preview what the DELETE handler would skip - operator can plan accordingly.

[^http-usercleaner-2]: Requires `X-Confirm: yes` header (§4.6) - router-enforced; missing header returns **400 E_CONFIRMATION_REQUIRED** before the handler runs. No request body. Returns 200 with `data: {action: "users-cleaned", mode: "expired", expired_days, deleted, skipped_exception, skipped_protected_level, orphan_comments_removed}` per §7.1.1 - the three arrays mirror the categories from the ADC `delUsers` loop (rows on the exception list, rows whose level is in `protected_levels`, and rows actually delreg'd). Each array entry includes `{nick, days_offline}` (same field name as the GET endpoint above for semantic stability); the protected-level array additionally carries the `protected_level` integer. Cascade cleanups on each delete: `cmd_reg_descriptions.tbl` entry removed, ban removed (via `cmd_ban.del`), trafficmanager block removed (via `etc_trafficmanager.del`); matches the ADC path. The opchat report.send fires once per delete with the same `msg_delreg_expired` template the chat path uses. `orphan_comments_removed` (added in #311) reports the count of orphan comment entries the per-call sweep removed alongside the user deletes; routinely 0 once the historical backlog has been cleared.

[^http-usercleaner-3]: Returns 200 with `data: {expired_days, entries: [{nick, days_since_reg, level, nick_protected, level_protected}, ...]}`. Same shape as the expired GET endpoint but with `days_since_reg` instead of `days_offline` - ghosts are accounts that have NEVER logged in (no `lastseen` AND no `lastconnect`) and whose reg date is older than `expired_days`. The `level_protected` flag is reported but the DELETE handler ignores it for ghosts (matches the ADC `delUsers` asymmetry - never-used accounts are presumed throwaways).

[^http-usercleaner-4]: Requires `X-Confirm: yes` header (§4.6) - router-enforced; missing header returns **400 E_CONFIRMATION_REQUIRED** before the handler runs. No request body. Same response shape as the expired DELETE (`action: "users-cleaned"`, `mode: "ghosts"`), but each array entry uses `{nick, days_since_reg}` (matching the GET ghosts endpoint above) instead of `days_offline`. `skipped_protected_level` is always an empty array because ghosts ignore the level guard (response-shape symmetry only). Same cascade cleanups + opchat report.send (using the `msg_delreg_unused` template instead) as the expired path. `orphan_comments_removed` (added in #311) reports the count of orphan comment entries the per-call sweep removed alongside the user deletes; routinely 0 once the historical backlog has been cleared.

[^http-usercleaner-5]: Requires `X-Confirm: yes` header (§4.6) - router-enforced; missing header returns **400 E_CONFIRMATION_REQUIRED** before the handler runs. No request body. Returns 200 with `data: {action: "orphan-comments-cleaned", orphan_comments_removed: N}` per §7.1.1. Sweeps `cmd_reg_descriptions.tbl` for entries whose nick is no longer in user.tbl - historical leftovers from pre-Aug-2022 hub versions whose usercleaner did not call `description_del` on user delete. Non-destructive: only removes entries whose nick is absent from `hub.getregusers()` (a live entry never matches, since its nick is by definition still registered). Idempotent: a second call without intervening reg activity always returns `orphan_comments_removed: 0`. The expired/ghosts DELETE endpoints (above) also run this sweep as a side-effect; this endpoint is for the standalone case (operator wants to clean the file without triggering a user-delete batch). Equivalent to the ADC chat command `+usercleaner cleancomment`.

[^http-trafficmgr-1]: Returns 200 with `data: {activate, blocked_levels, sharecheck, minsharecheck, report_on_login, report_on_timer, report_to_main, report_to_pm}`. `blocked_levels` is the sorted ascending integer list of cfg level keys with `etc_trafficmanager_blocklevel_tbl[level] = true` (those levels are auto-blocked from CTM / RCM / SCH regardless of per-nick override). The other booleans mirror the cfg flags driving the periodic block-report behaviour. Returns 404 if the plugin is disabled (cfg `etc_trafficmanager_activate = false` - early return at module load prevents the http_register call).

[^http-trafficmgr-2]: Returns 200 with `data: {entries: [{nick, by, reason, blocked_at}, ...]}`. Lists ONLY manually-blocked nicks (per-nick override table); level-based auto-blocks are runtime classifications on every user and would change every login - they are reported via the settings endpoint instead. `blocked_at` is `YYYY-MM-DD / HH:MM:SS` parsed from the persisted `YYYYMMDDHHMMSS` format (the same parsing the ADC `+trafficmanager show blocks` cmd does); legacy boolean / string block-table entries (pre-v1.7 storage shapes) coerce to `msg_unknown` for `by` / `blocked_at` and the raw string for `reason`.

[^http-trafficmgr-3]: Body `{reason?: string (max 256, control-byte sanitised)}`. Absent / empty reason is stored as `msg_unknown` (matches ADC `+trafficmanager block <NICK>` with no reason). Returns 200 with `data: {action: "blocked", nick, by, reason, online_kicked: false}` per §7.1.1; `online_kicked` is always false because traffic-block does NOT kick the user - it filters their CTM/RCM/SCH frames going forward and updates their description flag if they are online. `nick` is the firstnick (stable registered identifier; the response always reflects the canonical key the block was stored under, even if the operator passed a prefixed display nick in the path). `by` is the bearer token's label (control-byte sanitised), falling back to `"http-api"` if the token has no label. Resolution is offline-tolerant - the per-nick override is a stored key, not a session attribute. Returns **409 E_CONFLICT** if the nick is already manually-blocked (operator must DELETE first to change reason; matches ADC `msg_stillblocked` semantic) OR if the target is autoblocked by script permissions (level in `blocklevel_tbl` or shares below threshold - manual block on an autoblocked user is redundant). Returns **400 E_BAD_INPUT** for empty / missing nick, reason >256 chars, or target is a bot. Cascade on success: block_tbl += entry, persist, opchat report.send, and if target online: target reply + description-flag update via `cmd:setnp("DE", ...)` + sendtoall BINF.

[^http-trafficmgr-4]: No request body. Returns 200 with `data: {action: "unblocked", nick, by, removed: {by, reason, blocked_at}}` per §7.1.1; `removed` is the pre-DELETE entry snapshot for the operator's audit / undo flow. Returns **404 E_NOT_FOUND** if the nick is not manually-blocked (idempotent 200 would mask typos); the same error fires if the nick is only autoblocked by script permissions - the autoblock is a runtime classification, not a stored entry, and lifts only via cfg changes to `blocklevel_tbl` / share thresholds. Cascade on success: block_tbl -= entry, persist, opchat report.send, and if target online: target reply + description-flag removal via `cmd:setnp("DE", new_desc)` + sendtoall BINF.

#### Webhooks (inbound)

| Method | Path | Scope | Plugin |
|---|---|---|---|
| POST | `/v1/webhook/<name>` | none | `etc_webhook` (#398) [^http-webhook-1] |

[^http-webhook-1]: One route per operator-configured endpoint (`<name>` is the endpoint's configured path segment). Scope is `none` - the router does NOT gate it; the plugin authenticates each delivery itself via an HMAC-SHA256 signature over the raw body (see [`WEBHOOKS.md`](WEBHOOKS.md)). Signature mismatch returns **401** with the plugin's own `{code:"unauthorized"}` body; a body over the 64 KiB cap returns **413**; a non-JSON content type returns **415**. Registered only when `etc_webhook` is loaded and the endpoint has a resolvable secret - otherwise the path is absent and an unregistered path falls through to the router's generic 401/404.

#### Shipped post-Phase-4 (#82 arc closed 2026-05-27)

The four "future-scope" items below were shipped in a single day on
top of the Phase 1-4 endpoint migrations and are now in the catalog
above:

- **Plugin management** (#261, PR #269) - `GET /v1/plugins`,
  `PUT /v1/plugins/{name}/enabled`. Listed in §10.1.
- **Config view/edit** (#262, PR #272) - `GET /v1/config`,
  `PUT /v1/config/{key}` with denylist masking on read +
  apply-status classification. Listed in §10.1.
- **Event polling** (#263 PR-A #273 + PR-B #274) -
  `GET /v1/events?since=...&types=...&wait=...`. Polling +
  long-poll via deferred-response dispatch (NOT SSE). Listed in
  §10.1.
- **Filter + sort** (#264 PR-A #270 + PR-B #271) - common helper
  `core/http_filter.lua` wired into every paginated list
  endpoint. Per-endpoint allowlist documented in each footnote.

True SSE (`text/event-stream`) is still deliberately deferred -
the long-poll handshake covers the WebUI use cases without the
multi-write iostream rewrite SSE would need.

---

## 11. Out-of-scope of the catalog

User SELF-service commands (`+myinf`, `+myip`, `+slots`, `+sslinfo`,
`+accinfo` self, `+nickchange` self, `+setpass` self, `+talk`,
`+uptime`, `+hubinfo`, `+rules`, `+hubstats` user-side,
`+help`) are excluded - users already have an ADC session for these.
Operator-side inspection of an arbitrary user's INF / slots / SSL
info lives in `GET /v1/users/{sid}` per §10.1; the exclusions
listed here are the USER-SELF variants only.
Cosmetic plugins (`bot_*`, `etc_motd`, `etc_banner`, `etc_keyprint`,
`etc_userlogininfo`, `etc_unknown_command`, `usr_*`) don't expose
actionable operations.

---

## 12. Dependencies

- `dkjson` (pure Lua, ~700 LoC): bundled as `dkjson/dkjson.lua`,
  registered via `core/init.lua` import block. Decision rationale:
  pure Lua keeps the build dep-free; performance is fine for an admin
  API (no 10k req/sec workload).
- No new C modules.

---

## 13. Implementation phases

Each phase ships as its own sub-PR with its own review gate per
CLAUDE.md §1a.6. The phases are designed to be independently
reviewable and shippable.

### Phase 1: core framework + read-only core endpoints

- Bundle `dkjson` as `dkjson/dkjson.lua`; wire it through
  `core/init.lua`.
- Extend `core/iostream.lua:newhttpstage` to permit a CL-bounded
  body for non-GET methods (S3 caps stay; body cap = 64 KiB).
- Auto-support HEAD for GET routes; OPTIONS introspection; 405 + `Allow`
  header for method mismatch (§6.6).
- New module `core/http_router.lua` (or extend `core/http.lua`):
  route table, dispatch, auth, scope, envelope, JSON marshalling,
  error mapping, rate-limit (token + per-prefix failed-auth), idempotency-
  key cache, audit log, X-Request-ID generation, schema validation.
- New plugin API global `hub.http_register(...)` with optional `meta`
  (description + request_schema + response_schema).
- `+reload` integration: clear route table before re-running plugin
  `onStart` cycle.
- First-boot token sample (§4.7): generate + write
  `cfg/api_token.first` with chmod 600 when `http_api_tokens` empty.
  Listener does NOT bind until operator copies the value into
  `cfg.tbl http_api_tokens` and restarts (or `+reload`) (#231).
- Core endpoints: `/health` (already exists), `/v1/version`,
  `/v1/stats`, `/v1/users` (paginated), `/v1/users/{sid}`,
  `/v1/endpoints`, `/v1/log/api`.
- New cfg keys: `http_api_tokens` (table), `http_api_rate_read`
  (default 120/min), `http_api_rate_admin` (default 60/min),
  `http_api_log_reads` (default false).
- Smoke tests: token resolution + scope check, envelope shape, error
  codes (esp. 404 vs 405), idempotency-key behaviour + 5-min TTL +
  max-entries cap, rate-limit kick-in (per-token AND per-conn
  failed-auth AND prefix-bucket), X-Confirm enforcement, route
  registration / re-registration on +reload, idempotency cache
  cleared on +reload, pagination clamping (limit=999999 → 1000),
  HEAD/OPTIONS auto-response, first-boot bootstrap file generated +
  chmoded BEFORE port bind, ISO-8601 timestamp format on both Linux
  + Windows MinGW builds (locale-safety of `os.date("!%Y-%m-%dT%H:
  %M:%SZ", t)`), framer body-extension state machine (§2.1
  test list).

### Phase 2: bundled-plugin migration (writes, low-risk)

Plugins migrate to register their endpoints. Each plugin gets the
register call added in `onStart` plus a thin handler that calls into
the same code path the `+cmd` listener uses.

> **Convention:** plugins SHOULD extract the actual operation into a
> module-local function (e.g. `local function do_ban(target_type,
> target, dur, reason) ... end`). Both the `+cmd` listener and the
> HTTP handler call into it. Avoids duplicating ban logic between
> the chat side and the API side - a divergence here is the kind of
> bug that takes months to surface.

- `cmd_mass` → `POST /v1/announce`
- `cmd_topic` → `POST /v1/topic`
- `cmd_ban` → `GET/POST /v1/bans`, `DELETE /v1/bans/{id}`
- `cmd_disconnect` → `DELETE /v1/users/{sid}`
- `cmd_gag` → `POST/DELETE /v1/users/{sid}/gag`, `GET /v1/gags`
- `cmd_redirect` → `POST /v1/users/{sid}/redirect`
- `cmd_reg`, `cmd_delreg`, `cmd_setpass`, `cmd_nickchange`,
  `cmd_upgrade`, `cmd_accinfo` → `/v1/registered/*` family
- `cmd_reload` → `POST /v1/reload`

### Phase 3: destructive ops + log endpoints

- `cmd_restart` → `POST /v1/restart` (requires `X-Confirm`, see §4.6)
- `cmd_shutdown` → `POST /v1/shutdown` (requires `X-Confirm`, see §4.6)
- `cmd_errors` → `GET /v1/log/error`
- `etc_cmdlog` → `GET /v1/log/cmd`
- `etc_log_cleaner` → `DELETE /v1/log/{name}`

(Note: `GET /v1/log/api` is in Phase 1 because the router owns the
audit log; the other log endpoints are plugin-owned.)

### Phase 4: subsystem manager plugins

- `etc_blacklist`, `etc_msgmanager`, `etc_trafficmanager`,
  `etc_records`, `etc_chatlog`, `hub_runtime`, `cmd_usercleaner`.

### Shipped on top of Phase 1-4 (#82 closed 2026-05-27)

These four originally "future" items landed as discrete follow-up
PRs after the Phase 1-4 endpoint migrations. The #82 arc is now
closed; details in their respective PRs / docs.

- **Plugin management** - #261 (PR #269): `GET /v1/plugins`,
  `PUT /v1/plugins/{name}/enabled`. Catalog row in §10.1.
- **Config view/edit** - #262 (PR #272): `GET /v1/config`,
  `PUT /v1/config/{key}`. Denylist masking on read; apply-status
  classification (`live` / `reload_required` / `restart_required`).
- **Event polling** - #263 PR-A (#273) + PR-B (#274):
  `GET /v1/events?since=&types=&wait=`. Polling + long-poll via
  the deferred-response dispatch handshake; NOT SSE.
- **Filter + sort** - #264 PR-A (#270) + PR-B (#271): shared
  helper `core/http_filter.lua` wired into every paginated list
  endpoint. Per-endpoint allowlist documented in each footnote.

### Still deferred

- **Server-Sent Events** (`text/event-stream`). Long-poll covers
  the current WebUI use cases without the multi-write iostream
  rewrite SSE needs. Revisit only if hard-realtime emerges.
- **Unix-domain-socket bind** as an alternative to TCP loopback
  (`http_socket_path = "/var/run/luadch/api.sock"`). luasocket
  3.1.0 has bundled AF_UNIX; feasibility confirmed. Deferred YAGNI
  until a concrete operator request lands.
- **WebUI itself** (separate repo, consumes this API). Was the
  gating reason for shipping the four items above together.

---

## 14. Open questions

- **Bulk endpoints.** `DELETE /v1/users` with body
  `{sids: [...]}` for bulk kick? YAGNI for now; clients can loop.
  Same call applies to `+ban clear` / `+ban clearhis` /
  `+trafficmanager` bulk clears: not surfaced, clients loop
  client-side. The audit log gets one entry per call this way,
  which is the right shape for forensic review.
- **API versioning lifecycle.** When does `/v2` land? Document a
  deprecation policy before the first breaking change is needed.
  Convention: `/v1` is supported as long as the 3.x major line is
  current; a `/v2` rollout overlaps with `/v1` for one full minor
  version before `/v1` is removed.
- **Schema validation depth.** Phase 1 ships the minimal type +
  required + enum + min/max + min_length/max_length/pattern
  validator. Full JSON-Schema is out of scope unless a real client
  demand surfaces.

---

## 15. Related

- Issue [#82](https://github.com/luadch-ng/luadch-ng/issues/82)
- Phase 8 IO substrate: [`docs/phases/PHASE_8_IO.md`](phases/PHASE_8_IO.md)
- Plugin model: [`docs/PLUGIN_API.md`](PLUGIN_API.md)
- Security model: [`docs/SECURITY.md`](SECURITY.md) (loopback-only +
  reverse-proxy posture lives there)
