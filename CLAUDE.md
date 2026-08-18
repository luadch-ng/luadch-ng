# CLAUDE.md

Context for Claude Code (and any AI assistant) working on luadch. Read this before
making changes — it captures the working agreement, architecture map, and roadmap
that span sessions. Engineering how-to (core-module authoring, testing contract,
security checklists, Definition of Done) lives in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

User communication is in **German**; all written artifacts (this file, code, comments,
commits, PRs, issues) stay in **English** so other contributors can read them.

---

## 1. Working agreement (non-negotiable)

These rules are set by the maintainer and apply to every change.

### 1a. Per-change discipline (every PR, no size exemption)

1. **Security and consistency come first.** Treat any change touching network I/O,
   authentication, ADC protocol parsing, or configuration as security-sensitive. When
   fixing a pattern in one place, grep for the same pattern across the repo and fix it
   everywhere - divergent code paths are a defect.
2. **No spaghetti code.** Prefer small, focused functions and modules. Don't grow
   `core/cfg.lua` or `core/hub.lua` further; if new logic doesn't have an obvious home,
   propose a new module before writing the code.
3. **Deep-dive before implementation.** Analyse the issue/idea from the source
   outward before writing code, even when it costs more tokens. A clean
   implementation pays the tokens back twice over (#179: the deep-dive replaced a
   proposed 50-LoC redesign with a 1-line fix).
4. **An issue/plan is a hypothesis, not ground truth.** Always re-derive the root
   cause from spec + current source before implementing. If the issue/plan is wrong,
   correct the issue/plan - do not implement the wrong thing. (HUBI, CTM/RCM, the
   #179 split-table proposal: same trap three times.)
5. **Verify every assumption** against the current code/spec before building on it.
   Recalled memory and old docs are point-in-time; confirm before relying.
6. **Mandatory two-pass pre-merge review.** Before any merge - regardless of how
   small the diff - run: (a) an independent reviewer (subagent / fresh perspective)
   and (b) a maintainer-side spot-check. The review covers **security**, **new
   bugs**, **breaking existing behaviour**, **consistency / anti-spaghetti**. No
   "it's just a one-liner" exemption: the #179 one-line fix's review is exactly what
   caught a latent counter underflow.
7. **Regression tests must provably fail pre-fix.** A test green on both old and new
   code proves nothing. For every fix, demonstrate the new test FAILS on the
   unpatched code and PASSES patched (PR #177 lesson; applied per-tier in #179).
8. **Small reviewable PRs.** One logical change per PR. Reference the GitHub issue it
   closes. Never bundle unrelated fixes.
9. **No wall of text.** Chat answers, issues, PR bodies, release notes: minimal,
   technical, complete - result first. Internal artifacts (commit messages, code
   comments, repo docs, phase journals) stay as detailed as needed.

### 1b. Phase & milestone discipline

10. **One phase at a time.** Work proceeds strictly phase by phase (see §5 Roadmap).
    Do not pull tickets forward from a later phase, even if they look trivial.
11. **Review gate between phases, and before any release/milestone.** Run an
    explicit, PR-grade review (same depth as 1a.6) covering:
    - **Security** - input validation, auth boundaries, network surface, file I/O.
    - **Consistency** - did similar code paths drift apart? Did naming get inconsistent?
    - **Code quality** - readability, dead code, duplication, function length.
    - **Build & smoke test** - both Linux and Windows builds succeed, hub starts, a
      test client (`adcs://127.0.0.1:5001`) can connect.
    - **Docs currency** - this file and the affected `docs/*.md` were updated in the
      same PR whenever architecture, conventions, module layout, or defaults changed.
      A stale CLAUDE.md poisons every future session's context; treat doc drift as a
      review-blocking defect, not cosmetics.
12. **Fix-then-advance.** Anything found in the review must be fixed before the next
    phase begins or the release is cut. No "we'll get back to it." If something is
    genuinely out of scope, open a tracking issue and link it from the phase summary.

When uncertain whether a change fits the current phase, **stop and ask the maintainer**.

---

## 2. Project overview

luadch is a DC++ **ADC** hub server written in Lua with a thin C launcher
(`hub/hub.c`) that embeds the Lua interpreter and hands off to `core/init.lua`.

- **Current source version:** `v3.2.0-dev` on `master`, `PROGRAM_NAME = "Luadch-NG"`
  (see `core/const.lua`). The 3.1.x maintenance line keeps `PROGRAM_NAME = "Luadch"`.
- **Latest release:** `v3.1.15` (2026-07-29, on `release/3.1.x`)
- **Status:** the Phase 1-7 modernisation programme is content-complete; work is now
  3.2.x feature development (Phase 8+) plus 3.1.x security-only maintenance
  until the `v3.2.0` tag (which EOLs the 3.1.x line - see §8).
- **Open issues:** check `gh issue list --repo luadch-ng/luadch-ng` (never trust a
  count written into a doc).
- **Testing:** a pure-Lua unit suite (`tests/unit/*_test.lua`) plus a protocol-level
  smoke harness (`tests/smoke/run.py`) run in CI on Linux AND Windows on every push
  and PR (`.github/workflows/smoke.yml`). See [`tests/README.md`](tests/README.md)
  and [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
- **License:** GPLv3.0

The repo bundles all runtime dependencies as source - there is no external package
manager. This is intentional (the project ships as a self-contained build) but means
dependency updates are manual.

### Bundled dependencies (verified 2026-07-21; a dependency bump MUST update this table)

| Component   | Bundled version | Path           | Notes                                |
|-------------|-----------------|----------------|--------------------------------------|
| Lua         | **5.4.8**       | `lua/`         | bumped from 5.1.5 in Phase 3; check `lua/src/lua.h` |
| LuaSec      | **1.3.2**       | `luasec/`      | TLS support, links against OpenSSL; upstream-blocked for OpenSSL-3 API (Phase 4, #3) |
| LuaSocket   | **3.1.0**       | `luasocket/`   | TCP/UDP, IPv6 capable                |
| basexx      | (no version)    | `basexx/`      | Pure Lua, base32/64 encoding         |
| unicode     | shim            | `slnunicode/unicode.lua` | ~40-line Lua shim that replaces the unmaintained slnunicode C module; uses `string.X` and Lua 5.4 builtin `utf8` |
| adclib      | (no version)    | `adclib/`      | C module: ADC hashing & escaping     |
| zlib_stream | (own binding)   | `zlib_stream/` | C binding for ZLIF stream compression (Phase 8 S4b); links the **system** zlib (`find_package(ZLIB REQUIRED)`) - the one dependency NOT bundled |

---

## 3. Architecture

### Boot sequence

```
hub/hub.c           ── luaL_newstate(), register C functions, load core/init.lua
  └─ core/init.lua  ── restricted env, load libs + _core modules in order
       └─ core/hub.lua          ── hub.loop() — main event loop
            ├─ core/server.lua  ── event loop over sockets (poll on POSIX,
            │                      select on Windows - #310), SSL wrap
            └─ core/hub_dispatch.lua ── per-command ADC dispatch (most
                                        listener events fire from here)
```

### Core modules (grouped by subsystem)

No line counts here on purpose - they bit-rot. Run `wc -l core/*.lua` for
current sizes. `core/init.lua`'s `_core` array is the authoritative load
order (its inline comments explain each ordering constraint).

| Subsystem | Modules | Responsibility |
|---|---|---|
| Boot + config | `init`, `const`, `cfg`, `cfg_defaults`, `cfg_users`, `cfg_lang`, `cfg_secret`, `secrets`, `cfg_write` | Restricted env + module loader; program constants; settings/user.tbl/language handling; AES-256-GCM at-rest crypto; env-var-first secret lookup; comment/layout-preserving single-key cfg.tbl writer (#644) |
| Network + ADC | `server`, `iostream`, `adc`, `hub`, `hub_dispatch`, `hub_user_object`, `hub_bot_object`, `hbri`, `ratelimit`, `blocklist`, `whitelist`, `ipmatch` | event loop + SSL (poll on POSIX / select on Windows, #310); framing pipeline; ADC parse/escape/format; main loop + login; command dispatch; user/bot objects; dual-stack secondary-IP verification; DoS limits; pre-handshake IP/CIDR blocklist; global allowlist (whitelist beats automated blocks, not manual pins); IP/CIDR primitives |
| HTTP API | `http`, `http_router`, `http_client`, `http_filter`, `http_events`, `util_http` | Inbound HTTP/JSON API + router + auth; non-blocking OUTBOUND client; filter/sort/paginate helper; deferred-event endpoints; plugin endpoint helper |
| Crypto + boot trust | `sha256`, `hmac`, `cert_bootstrap`, `cacert_bootstrap`, `backup_archive` | Pure-Lua SHA-256; HMAC-SHA256 (RFC 2104, sandbox-exposed for signed-webhook auth, #398); first-boot TLS-cert auto-gen (#77); CA-bundle reconciliation; LDBK1 encrypted backup archive format (tar + AES-256-GCM, PBKDF2, #480) |
| Infra | `util`, `out`, `mem`, `signal`, `types`, `scripts`, `audit`, `sysinfo`, `mmdb`, `geoip_update`, `bloom`, `ensuredirs`, `backup` | File I/O + table helpers; logging; GC; timers; ADC type validation; plugin loader + sandbox + listener registry; onAudit JSONL log; system info; MaxMind DB reader + in-hub GeoLite2 auto-update; bloom filter; boot-time runtime-dir self-heal; backup engine (collect restore-min set + seal + rotate, #480, exposed to the sandbox as `backup`) |

**`core/restore.lua` is a standalone offline entry, not a `_core` module.**
The C launcher's `run_restore()` (`hub/hub.c`) loads it into a fresh Lua state
for `./luadch --restore <file>` (backup restore, #480 PR-B); it boots no hub
(the cfg it would read is what it restores) and never appears in `_core` -
like `init.lua` itself. Two C primitives back the arc: `listdir(path)`
(core-only global, like `makedir` - NOT sandboxed) enumerates the state dirs
for the backup engine, and `adclib.pbkdf2_sha256` (OpenSSL PKCS5_PBKDF2_HMAC)
keeps the KDF off the pure-Lua path that would freeze the single-threaded hub
~40s per backup. Operator guide: [`docs/BACKUP.md`](docs/BACKUP.md).

**`core/hci.lua` is a now-legacy data file** (a plain `hubruntime` /
`hubruntime_last_check` table). It backs `/v1/runtime` +
`+runtime`/`+uptime`/`+hubinfo`. It used to be the LIVE store - read and
rewritten by `hub_runtime` (60s `onTimer`), `cmd_uptime` and `cmd_hubinfo` -
but that put mutable plugin state under `core/`, which is shipped wholesale
(`install(DIRECTORY core/)`, and Docker bakes it into the image rather than
mounting it), so every upgrade overwrote the operator's accumulated runtime
with pristine zeros. [#445](https://github.com/luadch-ng/luadch-ng/issues/445)
moved the live store to `scripts/data/hub_runtime.tbl` (operator-owned,
upgrade-safe, per §7): `hub_runtime` is now the sole writer and migrates the
legacy value once on load; `cmd_uptime` / `cmd_hubinfo` are pure readers.
`CMakeLists.txt` excludes `hci.lua` from the `core/` install (`PATTERN
"hci.lua" EXCLUDE`) so a `cmake --install` upgrade does not zero the
operator's on-disk `core/hci.lua` before the migration can read it - without
that, the migration adopts the just-clobbered zeros and recovers nothing.
`core/hci.lua` is now read-only, kept in-tree as the migration source only;
a future release deletes it. (Docker cannot migrate - its old counter lived
in the ephemeral container layer - but persists going forward.) Its absence
from `_core` is correct either way (it is a data file, not a module) - do not
"fix" it by adding it.

Two hard ceilings (both enforced by review, not tooling):

- **1500 lines per code module** (Phase 6). If a module needs more, split it.
  Two pre-existing modules are grandfathered over the line and NOT a licence to
  add more: `core/hub.lua` (the main loop; a split fights its 200-locals budget,
  see below) and `core/http_router.lua`. Check current sizes with
  `wc -l core/*.lua` (`cfg_defaults.lua` is a data/defaults file, not code, so the
  ceiling does not apply to it). New modules stay under 1500.
- **`core/hub.lua`'s main chunk runs close to Lua's 200-locals-per-chunk cap.**
  File-scope locals there are scarce - the file has hit the wall before (Phase 8
  S4b + S5, #301). Prefer a lazy `use "X"` at the call site, or pack related
  values into one table, before spending a slot. Measure the headroom rather than
  trusting a number written down here: `luac -p -l core/hub.lua` prints the main
  chunk's `N locals` in its header (plain `-p` only speaks up once you are
  already over).

### Plugin / hook model

Plugin scripts live in `scripts/` and are loaded via `core/scripts.lua` into a
whitelist sandbox (no `use`, no raw `io`/`os` - see
[`docs/PLUGIN_API.md`](docs/PLUGIN_API.md) §2). A plugin only loads if it is
whitelisted in `cfg.scripts`; array order = listener-chain order.

Listener events (full set; semantics in
[`docs/PLUGIN_API.md`](docs/PLUGIN_API.md) §4):

- Lifecycle: `onStart`, `onExit`, `onError`, `onShutdown`, `onTimer`
- Connection/login: `onIncoming`, `onConnect`, `onLogin`, `onLogout`, `onFailedAuth`
- Protocol traffic: `onInf`, `onBroadcast`, `onPrivateMessage`, `onConnectToMe`,
  `onRevConnectToMe`, `onNatTraversal`, `onNatTraversalReply`, `onSearch`,
  `onSearchResult`
- Registration/audit: `onReg`, `onDelreg`, `onAudit`

Plugins use the `hub` table API: `hub.getuser(nick)`, `hub.broadcast(msg)`,
`hub.setlistener(event, id, func)`, plus `cfg.get(key)`, `utf.sub()`, etc.

---

## 4. Build & run

luadch uses CMake (≥ 3.20). Same three-step pipeline on every platform:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release [-DOPENSSL_ROOT_DIR=...]
cmake --build build -j
cmake --install build
```

Output lands in `build/install/luadch/`. Run `./luadch` (Linux) or
`Luadch.exe` (Windows) from there.

Linux defaults work without options. Windows needs `-G "MinGW Makefiles"`
and an OpenSSL location, e.g. `-DOPENSSL_ROOT_DIR=C:/OpenSSL`. ARM
(native or cross-compile) is supported and verified up to aarch64.

**Full prerequisites, OpenSSL cross-compile recipe, ARM cross-toolchain
setup, first-time login walkthrough:** see [`docs/BUILDING.md`](docs/BUILDING.md).

### First-time login

Fresh installs are **TLS-only**: `tcp_ports = {}` (no plain listener),
`ssl_ports = {5001}` on both IPv4 and IPv6 (`core/cfg_defaults.lua`). The TLS
certificate is **auto-generated on first boot** by `core/cert_bootstrap.lua`
(#77) - no manual cert step. `examples/certs/make_cert.{sh,bat}` exist only
for manual regeneration.

```
Nick:     dummy
Password: test
Address:  adcs://127.0.0.1:5001    (TLS; production clients should pin the
                                    keyprint: adcs://host:5001/?kp=SHA256/...)
```

Plain `adc://` requires explicitly enabling `tcp_ports` in `cfg/cfg.tbl`.

After login: `+reg <yournick> 100`, then `+delreg dummy`, then `+reload`.

---

## 5. Roadmap

### Modernisation programme (Phases 1-7): CLOSED

Content-complete since v3.1.8. One journal per phase in
[`docs/phases/`](docs/phases/) carries the full narrative; this table is only
the index. Do not re-plan closed phases.

| Phase | Outcome (one line) | Journal |
|---|---|---|
| 1 - Foundation | Reproducible Linux + Windows builds, smoke baseline documented | [`PHASE_1.md`](docs/phases/PHASE_1.md) |
| 2 - Quick wins | `.gitattributes`, `lua_open` -> `luaL_newstate`, reproducible Windows toolchain | [`PHASE_2.md`](docs/phases/PHASE_2.md) |
| 3 - Lua 5.4 | Interpreter 5.1.5 -> 5.4, `_ENV` sandbox migration, C-API updates | [`PHASE_3.md`](docs/phases/PHASE_3.md) |
| 4 - Dependency audit | Closed audit-only; LuaSec OpenSSL-3 API stays upstream-blocked (#3) | [`PHASE_4.md`](docs/phases/PHASE_4.md) |
| Interlude 1 | Upstream bug triage round 1 (6 fixed, 3 audited-already-fixed) | [`INTERLUDE_UPSTREAM_TRIAGE.md`](docs/phases/INTERLUDE_UPSTREAM_TRIAGE.md) |
| 5 - CMake build | Single three-step CMake pipeline for Linux/Windows/ARM | [`PHASE_5.md`](docs/phases/PHASE_5.md) |
| 6 - Refactor + tests | cfg/hub split, 1500-line ceiling, smoke harness + CI | [`PHASE_6.md`](docs/phases/PHASE_6.md) |
| 7 - Security audit | 24 findings / 22 closed; ratelimit, at-rest crypto, sandboxed loaders, `docs/SECURITY.md` | [`PHASE_7.md`](docs/phases/PHASE_7.md), [`PHASE_7_FINDINGS.md`](docs/phases/PHASE_7_FINDINGS.md) |
| Interlude 2 | Upstream triage rounds 2 + 3 | [`INTERLUDE_UPSTREAM_TRIAGE_2.md`](docs/phases/INTERLUDE_UPSTREAM_TRIAGE_2.md) |

### Phase 8+ - feature development (current era)

Each Phase-8+ item gets its own tracker issue, scope, and §1a.6 review gate.
The strict "one phase at a time" discipline (§1b) still applies. The Phase-8
engineering journals ([`PHASE_8_IO.md`](docs/phases/PHASE_8_IO.md) IO/framing
rework, [`PHASE_8A.md`](docs/phases/PHASE_8A.md) ADC input-validation audit,
[`PHASE_8B_DUAL_STACK.md`](docs/phases/PHASE_8B_DUAL_STACK.md) dual-stack +
HBRI) are **historical** - those arcs shipped; read them for the narrative,
not for open work.

Shipped feature arcs so far (closed trackers, details in the issues): HTTP
API #82, audit log #84, real HBRI #214, registered-users API family #236,
subsystem managers #249, client blocker #81, aliases #327, unified blocklist
+ in-hub GeoIP #78/#79/#352, global whitelist/allowlist (#78 deferred item),
status-push heartbeat #395, inbound webhook receiver #398, automatic
encrypted backup + offline restore #480, maintenance-mode lockdown gate
#501, force-ADCS transfer gate #500.

**Unified blocklist arc [#78](https://github.com/luadch-ng/luadch-ng/issues/78)
COMPLETE + on master (2026-07-10); #78 + #79 + #352 closed.** All precursors
+ Phases A-F + D3 in-hub GeoIP auto-update shipped (`core/blocklist`,
`ipmatch`, `mmdb`, `geoip_update`; plugins `etc_blocklist`, `etc_geoip`,
`etc_blocklist_feeds`, `etc_proxydetect`). Post-arc testhub-gap follow-ups:
`http_client` opt-in redirect following (#383, MaxMind download 302s
cross-host to a signed CDN URL), boot-time runtime-dir self-heal
(`core/ensuredirs.lua` + a `makedir` C primitive #382, #384) with a daemon
`umask(027)` hardening, and an `etc_blocklist_feeds` reload-throttle (#386).

**Current state (3.2.x on `master`, still no `v3.2.0` tag).** The items that
used to sit here as "in flight on `dev`" have all merged. Recently shipped to
master (frozen history - the live delta is always
`git log --oneline origin/master..origin/dev`, never a list written here):

- **`select`->`poll` event-loop port (#310)** - lifts the ~1024 concurrent-
  socket ceiling on POSIX (the Linux sibling of Sopor's Windows 64-socket
  `FD_SETSIZE` crash #416); Windows stays on `select`. `hub/hub.c` raises the
  fd soft limit to hard at boot.
- **#78 global whitelist / allowlist** - `core/whitelist.lua` consulted by
  every IP-blocking path so trusted infra (hublist pingers etc.) is exempt
  from the AUTOMATED blockers (GeoIP / proxydetect / feeds / hub-limit) but
  NOT from a deliberate manual `+ban` / `+blocklist` (**Model A**: a manual
  block wins). Engine + `etc_whitelist` + pinger seed + per-plugin guards +
  HTTP `/v1/whitelist`. NOT extended to `usr_share` / `usr_slots` /
  `usr_nick_*`.
- **single-instance lock + port-hijack fix (#433/#434)**, `sysinfo`
  old-Windows `Get-WmiObject` fallback (#432), `CONTRIBUTING.md` (#440), a
  repo-wide plugin lang-key guard (#442), a `release.yml` zlib-dev fix (#441),
  external cleanups from @Kcchouette (#437/#438/#439).
- **`etc_status_push` #395** (push heartbeat) + **`etc_webhook` #398** (inbound
  HMAC receiver, first `scope="none"` route) + the ADC unknown-escape discard
  #419 / hub-bot `EM` escaping #423 / webhook `conditions` filter #420.
- **the #447 dead-code audit**, then a post-#447 correctness/i18n batch:
  `cmd_ban` permanent ban (#444 keyword + #475 right-click menu entry),
  `hub_runtime` store moved out of shipped `core/` (#445), `etc_records`
  defensive load (#465), exhaustive PLUGIN_API §8 (#457),
  `etc_cmdlog` / `cmd_userinfo` / blocklist+whitelist i18n + alignment
  (#460 / #459 / #456).
- **nick-prefix resolution arc (#473/#474/#477)** - `usr_nick_prefix` re-keys
  the hub nick table to the PREFIXED nick, so ten operator commands
  (+ `bot_session_chat`) that resolved an online user by a TYPED base nick
  silently took the offline path (`+ban` stored but no kick; others no-op).
  They now fall back to `user:firstnick()` - the `etc_trafficmanager` /
  upstream-`luadch/luadch#240` idiom; `bot_session_chat` re-keys its whole
  member/owner identity model to firstnick.
- **#480 automatic-backup arc** - encrypted local backups + offline restore,
  no cloud. `core/backup_archive` (LDBK1 = pure-Lua tar + AES-256-GCM,
  PBKDF2-in-C, P0 #481) + `core/backup` engine + `etc_backup` scheduler
  plugin (PR-A #482) + `./luadch --restore` as a standalone offline entry
  (`core/restore` loaded by the C `run_restore` into a fresh Lua state,
  PR-B #484). Manifest eval bounded by an instruction budget so a crafted
  archive can't hang restore (#485); Docker restore UX + a `BACKUP.md`
  operator guide with an rclone off-site walkthrough (#487); docs currency
  pass (#489). Follow-up: the `adclib` `%zu`->`%I` diagnostic fix (#483,
  same `lua_pushvfstring`-conversion bug class as the P0 `listdir` `%lu`
  fix). Operator guide: [`docs/BACKUP.md`](docs/BACKUP.md).
- **maintenance + transfer-security plugins, and a trafficmanager /
  proxydetect batch (2026-07-27)** - `etc_lockdown` #501 (transient
  maintenance-mode access gate: `onConnect` veto + kick-below-level, timed
  auto-expiry, self-lockout guard, whitelist-exempt pingers; ships disabled)
  and `etc_forcetlstransfer` #500 (force-ADCS C2C transfers by dropping a
  plaintext CTM/RCM/NAT setup at `adccmd[8]`; all-or-nothing, ships ENABLED in
  `warn` + PM-both-parties, operator escalates to `block`); plus
  `etc_trafficmanager` show-blocks now lists auto-blocked ONLINE users
  (#502/#503, + a v2.2.1 drop-in for the 3.1.x operator) and `etc_proxydetect`
  reports the connect-time nick, not "?" (#504/#505). CI: `smoke.yml` `push:`
  scoped to `[dev]` so feature/master pushes are not re-smoked - their PRs are
  (#511). All live-validated on `:dev` via the devclient harness, no
  Sopor-testhub wait (Sopor runs 3.1.x, engages at the official 3.2.0 release).

`dev` and `master` track closely; open work is the feature-arc backlog -
`gh issue list --repo luadch-ng/luadch-ng` (no open bugs). Durable pattern from
this era: a **periodic-fetch plugin must persist its next-fetch deadline
across `+reload`**, or every reload re-hits a rate-limited provider - fixed
twice (`etc_blocklist_feeds` #386, `etc_geoip` #414); general rule in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) §3. Workflow: GitFlow A per fix
(deep-dive from source per §1a.3/4); batch dev->master as a MERGE commit
(never squash - §8 branch hygiene).

**HTTP-endpoint authoring** (which helper for which endpoint shape, envelope
contract, preflight): see [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) §3 and
[`docs/HTTP_API.md`](docs/HTTP_API.md) §5.

---

## 6. External state & memory

- **Phase journals** — [`docs/phases/`](docs/phases/) holds one Markdown file per
  modernization phase: activities, findings, build-output specs, and the review-gate
  checklist. Entry point for "what happened in phase N" is `docs/phases/PHASE_N.md`.
  These are the narrative — issues and code are the actionable state.
- **GitHub issues** — https://github.com/luadch-ng/luadch-ng/issues — the actionable backlog.
  Each finding from a phase journal that needs work is an issue here, labeled with the
  target phase (`phase-2`, `phase-3`, …). Use `gh issue list --label phase-2` to scope
  upcoming work. Upstream `luadch/luadch` issues are referenced selectively when we
  adopt one (no bulk import — see §6 *Upstream policy* below).
- **Auto-memory** — Claude's per-user auto-memory directory for this project — holds
  user profile and high-level context. Architecture / build / roadmap details live in
  **this file**, not in memory, because they belong with the code. Durable
  engineering patterns belong in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) so
  they reach every assistant and contributor, not just one memory owner.
- **Releases** - this fork's latest release is `v3.1.14` (see §2 and §8); UPSTREAM
  `luadch/luadch` last released v2.23 back in 2022-04-02 (see Upstream policy below).

### Upstream policy

The repo at `luadch-ng/luadch-ng` is a fork of `luadch/luadch`. The upstream is
not actively released (last release 2022-04-02) but still receives occasional commits.
We do **not** plan to push modernization work back upstream and do **not** bulk-import
upstream's open issues. When a phase touches an area covered by an upstream issue, we
open a fresh issue here that references the upstream one in its body.

---

## 7. Conventions for changes

- **Commit style:** match `git log` — concise, imperative, optional `fix #NNN` trailer.
- **PR scope:** one issue per PR, except for tightly coupled changes.
- **Lua style:** match the file you're editing. Don't reformat unrelated lines.
- **Comments:** explain *why*, not *what*. Don't add a comment that just restates code.
- **No drive-by refactors.** If you spot something during an unrelated change, open
  an issue instead of fixing it inline.
- **No em-dashes anywhere.** Use `-` in all written output: chat, commits, PRs,
  issues, docs. (Pre-existing em-dashes in this file are legacy; don't mass-reformat,
  but new/edited lines use `-`.)

### Engineering rules (each one paid for in a real incident; how-to detail in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md))

- **Core modules: every global via `local X = use "X"`.** Core modules run under
  `core/init.lua`'s restricted env - a bare global (`local type = type`, or a
  naked `pairs(...)` call) passes unit tests but crashes the hub at boot with
  "undeclared var". Burned twice (#353, #358). New modules register in `_core`
  with an ordering comment and must be passive at load (no `init()` side
  effects, no file I/O). Self-check recipe: DEVELOPMENT.md §2.
- **Run unit tests locally with Lua 5.4 BEFORE pushing.** CI catches failures
  one iteration too late (#277). New unit tests must be registered in
  `.github/workflows/smoke.yml` on BOTH legs (Linux `lua5.4` + Windows msys2
  `lua`) - an unregistered test is silent non-coverage.
- **Plugin state lives at `scripts/data/<plugin>.tbl`;** operator-facing
  artifacts (exports, backups) go to `cfg/`. Never export a mutable table
  reference across `+reload` - use the getter idiom (DEVELOPMENT.md §3).
- **Untrusted-input parsers** (anything reading operator-supplied or
  network-supplied bytes) follow the DEVELOPMENT.md §5 checklist: bounds-check
  every read, bound total WORK not just depth, pcall-wrap so corrupt input
  degrades to `(nil, err)` on boot paths, cap sizes before RAM reads.
- **No live point-in-time numbers in this file.** Counts that keep changing -
  current module line counts, open-issue counts, "N tests today", percentages -
  rot within weeks and then poison every session that loads this file. Link the
  source of truth (`wc -l`, `gh issue list`, CI) instead. Two exemptions, because
  they do NOT drift: (a) frozen historical facts about a CLOSED phase (e.g. "24
  findings / 22 closed" in the §5 table); (b) release/version/"verified-on"
  markers (e.g. "latest release v3.1.14", the deps-table verified date). A live
  status line (like §5 "In flight") must name the tracker as its source of truth.

### Tooling gotchas (these have already burned us)

- **Always pin `gh` to the repo:** `gh ... --repo luadch-ng/luadch-ng`. The checkout has
  an upstream remote; bare `gh` defaults to the parent-of-fork and acts on the wrong
  repository.
- **Multi-tier tracker issues: never `Closes #N`.** GitHub auto-closes the whole
  tracker on squash-merge even if only one subtask landed (killed the #147 tracker
  once). Use `Part of #N` / `Closes Tier-X (subtask of #N)`. Single-issue bugs may
  use `Closes #N` normally.
- **Backport security fixes master-first**, then cherry-pick to `release/3.1.x` (see
  §8). Never open a fix PR directly against the maintenance branch.
- **Verify a merge's CONTENT landed; check PR state before folding in follow-ups.**
  Two misses in one session (2026-07-13): `git merge dev` used a STALE local `dev`
  ref and silently dropped a whole change from the merge commit (operate on
  `origin/dev`, or `git fetch` + `git branch -f dev origin/dev` first); and a commit
  pushed onto a PR that was already green / on auto-merge was LOST (dev landed #419
  without the folded-in #423, because #422 merged at the pre-#423 HEAD). After any
  merge, `git reset --hard origin/<target>` and grep the working tree for a signature
  line of EACH change - a squash subject can be the PR title and hide a missing delta.
  Recover a dropped commit by cherry-picking its still-local sha (it survives branch
  deletion). If the base PR may merge imminently, do the follow-up as its OWN PR.

---

## 8. Release lines and support policy

Starting with **v3.1.8** (the "modernisation-complete" release that
closed Phases 1-7 plus the ADC-coverage tracker #147 T1 line), the
project follows a standard maintenance-branch model:

| Line | Where | Status | What it gets |
|---|---|---|---|
| **3.2.x** | `master` | active development (release substrate) | Tagged releases only. Feature PRs land here after dev testhub validation. |
| **dev** | `dev` | testing staging | Long-lived. Every feature lands here first for testhub validation (`ghcr.io/luadch-ng/luadch-ng:dev` auto-built on push). PR'd to master once green on the testhub. |
| **3.1.x** | `release/3.1.x` | security fixes only, **until `v3.2.0`** | Critical CVE / severity-1 backports only, and only while `v3.2.0` is unreleased. No features, no refactors, no Phase-8-anything. **The `v3.2.0` tag EOLs this line** (see below). |
| ≤ v3.0.x | (untagged history) | end of life | No updates of any kind. |

### Workflow

- **New work** (GitFlow A): branch `feat/X` off `dev`, PR to `dev` when
  ready. Docker auto-builds `ghcr.io/luadch-ng/luadch-ng:dev` on merge.
  Maintainer pulls + tests on the testhub. When green, second PR
  `dev -> master`. Master tag (e.g. `v3.2.0`) cuts from master HEAD.
- **Security backport**: PR against master first (NOT dev - security
  fixes skip the dev-validation cycle because they are time-sensitive),
  merge there, then cherry-pick the merge commit to `release/3.1.x`,
  push, tag the next v3.1.N patch. master is the canonical source of
  truth for the backport chain.
- **3.2.x first release** will be tagged `v3.2.0` when Phase 8 has
  enough content to merit a release. No fixed timeline.
- **3.1.x EOL**: declared **with the `v3.2.0` release tag**. The moment
  `v3.2.0` ships, `release/3.1.x` reaches end of life and gets **no
  further commits at all** - no security backports, nothing. There is
  **no 6-12 month grace window**: the message to operators is upgrade to
  the 3.2.x line. Until `v3.2.0` is tagged, 3.1.x still receives critical
  security backports per the table below; after the tag, that table
  lapses entirely.

### When to backport vs not

| Issue severity | 3.2.x master | 3.1.x backport? |
|---|---|---|
| Critical CVE in hub-itself code | yes | **yes** |
| Critical CVE in bundled C dep (luasocket / luasec / openssl) | yes | **yes** |
| Hub-crash on adversarial input | yes | **yes** |
| Plugin-state corruption | yes | maybe (judgement call - if data loss is the failure mode, yes) |
| Spec-compliance bug, no security impact | yes | **no** |
| New feature | yes | **no** |
| UX / cosmetic | yes | **no** |
| Documentation | yes | **no** |

The bar for 3.1.x backport is high. When in doubt, don't. And this whole
table applies **only while `v3.2.0` is unreleased** - once the `v3.2.0`
tag ships, 3.1.x is EOL and the answer is always **no**, regardless of
severity.

**Drop-in plugin patch as a lighter alternative to a 3.1.x release.**
When a bug hits a plugin already shipped on 3.1.x but the fix does not
merit cutting a full `v3.1.N` tag (maintainer judgement), an option
between "backport + release" and "wontfix" is to hand the operator a
standalone patched plugin file: bump `scriptversion`, add a header note
describing the fix, and they drop it into `scripts/`. master/dev still
carry the canonical fix. Use sparingly - it is an out-of-band artifact
with no release record (e.g. the `usr_uptime.lua` v0.10.1 drop-in given
to Sopor for the #405 undercount; master/dev carry v0.12).

### Branch hygiene

- Long-lived branches: `master`, `dev`, `release/3.1.x`. All three
  have GitHub branch-protection: `allow_deletions: false` +
  `allow_force_pushes: false`. Nobody can wipe them with a stray
  push.
- `dev` is the rolling testing-staging branch. Feature merges
  land here continuously; cherry-pick or merge to master once the
  testhub validates the `:dev` image. `dev` is not a release
  substrate (no tags are cut from `dev`).
- `release/3.1.x` is the only maintenance branch. Do not create
  `release/3.0.x` or similar for older lines (those are EOL).
- Tags `v3.1.8`, `v3.1.9`, ... live on `release/3.1.x`. Tags
  `v3.2.0`, `v3.2.1`, ... live on `master`. NEVER tag from `dev`.
- Feature branches (`feat/X`) are short-lived: created off `dev`,
  PR'd into `dev`, deleted post-merge. Squash-merge keeps `dev`
  history readable.
- Old `release/vX.Y.Z` prep branches (the per-release prep branches
  we used through v3.1.7) can be deleted post-merge - their tags
  preserve the history.
