# Inbound webhooks (`etc_webhook`)

`etc_webhook` lets an external service announce events in your hub chat.
The service POSTs an HMAC-signed JSON body to a hub HTTP endpoint; the
hub verifies the signature, filters + de-duplicates, and posts a
templated message as a named bot.

It is the inbound push receiver - the mirror of `etc_status_push`
(outbound heartbeat) and the complement of `etc_prometheus` (pull
`/metrics`). First consumer: a Discourse forum announcing new topics /
posts. The same protocol works for **GitHub, GitLab, CI systems,
monitoring / alerting** - anything that signs its webhook body with
HMAC-SHA256.

Security model + threat notes: [`docs/SECURITY.md` -> "Inbound webhook
auth"](SECURITY.md). This page is the operator setup.

---

## 1. How it fits together

```
Discourse / GitHub / ...            your server                    the hub
  POST /webhook  --HTTPS-->  reverse proxy (nginx/Caddy)  --HTTP-->  127.0.0.1:<http_port>
     X-*-Signature: sha256=<hmac over the body>                       |
     body = { ...event... }                                           v
                                                    etc_webhook: verify HMAC -> filter
                                                    -> dedup -> render template -> announce
```

Two facts to plan around:

- The hub's HTTP API listens **plain HTTP on `127.0.0.1`** by default and
  only binds when `http_port` is set **and** `http_api_tokens` has at
  least one entry (see [`docs/HTTP_API.md`](HTTP_API.md)). To receive
  webhooks from the internet you put a **reverse proxy with TLS** in
  front and proxy to the loopback port. (The webhook route itself needs
  no API token - it authenticates by HMAC - but the listener still needs
  a token configured to come up at all.)
- The request-body cap is **64 KiB**. A very large signed delivery is
  rejected before the handler runs (a missed announcement, not a
  security problem).

---

## 2. Enable it

1. **Whitelist the plugin.** In `cfg/cfg.tbl`, in the `cfg.scripts`
   list, set `etc_webhook.lua` to enabled:

   ```lua
   { "etc_webhook.lua", enabled = true },
   ```

2. **Flip the master switch.** In `cfg/cfg.tbl`:

   ```lua
   etc_webhook_activate = true,
   ```

3. **Create `cfg/webhooks.tbl`.** Copy `examples/cfg/webhooks.tbl` to
   `cfg/webhooks.tbl` and edit it (see section 3). `chmod 600` it if you
   put secrets inline.

4. **Make sure the HTTP API is up** (`http_port` set + a token in
   `http_api_tokens`) and reachable from the sender via your reverse
   proxy.

5. `+reload` (or restart). The hub log (`log/error.log` with
   `log_scripts = true`) shows `etc_webhook: active with N endpoint(s)`
   or an `inert (...)` reason.

---

## 3. `cfg/webhooks.tbl`

Plain Lua, `return { ... }`. Global tuning + an `endpoints` array:

```lua
return {
    max_per_minute = 10,   -- flood cap on announced messages (all endpoints)
    dedup_max      = 500,  -- how many recent delivery-ids to remember
    field_maxlen   = 300,  -- max length of one {placeholder} value

    endpoints = {
        {
            name             = "discourse",       -- [A-Za-z0-9_]; used in the path + env-var name
            path             = "/v1/webhook/discourse",   -- default: /v1/webhook/<name>
            signature_header = "x-discourse-event-signature",  -- required
            signature_prefix = "sha256=",          -- stripped before compare ("" if the header is raw hex)
            event_header     = "x-discourse-event",  -- optional; the SPECIFIC event (topic_created), NOT x-discourse-event-type (= category "topic")
            events           = { "topic_created", "post_created" },  -- optional; must be values of event_header; empty/omitted = all events
            id_header        = "x-discourse-event-id",  -- optional; enables dedup
            bot_nick         = "Forum",            -- optional; omit to announce as the hub bot
            min_level        = 0,                  -- 0 = everyone; e.g. 50 = ops-only
            templates = {                          -- keyed by event_header value; a bare https:// URL is auto-linkified by DC clients
                topic_created = "New topic by {topic.created_by.username}: {topic.title} -> https://forum.example.com/t/{topic.slug}/{topic.id}",
                post_created  = "New post by {post.username} in \"{post.topic_title}\" -> https://forum.example.com/t/{post.topic_slug}/{post.topic_id}/{post.post_number}",
            },
            -- optional: filter on a body field (see "Conditions" below).
            -- Here: skip a new topic's own opening post so it announces once.
            conditions = { { path = "post.post_number", not_equals = 1 } },
            -- default_template = "..."           -- optional TOP-LEVEL field (sibling of templates, NOT inside it); used when no per-event template matches
            -- secret: see section 4
        },
    },
}
```

Header names are matched case-insensitively (the hub lowercases them).
Any number of endpoints is supported; edit the file and `+reload` to add
more.

**Templates** use `{dotted.path}` placeholders resolved against the
decoded JSON body, plus `{event}` (the value of the header named by
`event_header` - so `{event}` is empty unless `event_header` is set). A
missing path renders empty. Every value is control-byte-stripped and
truncated to `field_maxlen`. The example paths are typical but payloads
differ by product / version - **check your webhook's own "Recent
Deliveries" / test payload for the exact field names** and adjust.

**Conditions** (optional) filter a delivery on a decoded body field, not
just the event header. Each entry is `{ path = "dotted.path", equals = X }`
or `{ path = ..., not_equals = X }`; ALL listed conditions must hold or the
delivery is acknowledged (200) without announcing. Two numbers compare
numerically (a config `1` matches JSON `1` or `1.0`); anything else
compares as strings. A path that does not resolve is `nil`, so `not_equals`
passes when the field is absent - but `equals` *fails* (drops it), so an
`equals` condition also drops any accepted event that lacks the field
(scope `events` accordingly). Conditions apply endpoint-wide (to every
event the endpoint accepts). Two common uses:

- **GitHub release action:** a GitHub `release` webhook fires for every
  action (`created` / `edited` / `published` / `released` / ...) under the
  same `x-github-event: release` header - only the body `action` differs.
  `{ path = "action", equals = "released" }` announces just the final one.
- **Discourse opening post:** a new topic fires `topic_created` AND
  `post_created` (its auto opening post). `{ path = "post.post_number",
  not_equals = 1 }` drops that duplicate opening post while still announcing
  the topic (which carries no `post.post_number`) and real replies (>= 2).

---

## 4. Secrets

Each endpoint needs a shared secret (the HMAC key). Generate one:

```sh
openssl rand -hex 32
```

Set the SAME value at the sender and at the hub. The hub resolves it
per endpoint in this order (first hit wins):

1. env var `LUADCH_ETC_WEBHOOK_<NAME>_SECRET` (Docker-friendly), e.g.
   `LUADCH_ETC_WEBHOOK_DISCOURSE_SECRET`
2. cfg key `etc_webhook_<name>_secret` in `cfg/cfg.tbl`
3. inline `secret = "..."` in `cfg/webhooks.tbl`

An endpoint with **no resolvable secret is skipped** (logged) - it never
runs unsigned. The value is never logged and (for the cfg-key path)
redacted from `GET /v1/config`.

---

## 5. Sender setup

### Discourse

Admin -> API -> Webhooks -> New:

- **Payload URL:** your public proxy URL, e.g.
  `https://hub.example.org/webhook/discourse` (proxied to the hub's
  `/v1/webhook/discourse`).
- **Content Type:** `application/json` (required - the hub rejects other
  body types).
- **Secret:** the value from section 4.
- **Events:** pick "Topic Event" / "Post Event" (or "Send me everything"
  and filter with `events` in `cfg/webhooks.tbl`). Note: with BOTH
  categories enabled, a new topic fires `topic_created` AND `post_created`
  (its opening post), so it would announce twice - the example config's
  `conditions = { { path = "post.post_number", not_equals = 1 } }` drops
  that duplicate opening post (real replies still announce). Or subscribe
  to only one category.

Discourse signs the body as `X-Discourse-Event-Signature: sha256=<hmac>`
and sends both `X-Discourse-Event` (the specific event, e.g.
`topic_created`) and `X-Discourse-Event-Type` (only the category, e.g.
`topic`), plus `X-Discourse-Event-Id`. Match `event_header` on
`x-discourse-event` (the example config does) so `events` / template keys
line up with `topic_created` / `post_created`. Use the webhook's "Go" /
ping to test - a ping validates the secret and returns 200; with an
`events` filter set it is not announced (ping is not in the list).

### GitHub

Repo (or org) -> Settings -> Webhooks -> Add webhook:

- **Payload URL:** `https://hub.example.org/webhook/github`
- **Content type:** `application/json`
- **Secret:** the value from section 4.
- **Events:** subscribe to what you want (e.g. "Releases"). A "Releases"
  subscription delivers every release action under one
  `x-github-event: release`; use `conditions` to announce only the one you
  want (the example filters to `action = "released"`).

GitHub signs as `X-Hub-Signature-256: sha256=<hmac>` and sends
`X-GitHub-Event` + `X-GitHub-Delivery`. Uncomment the GitHub block in
`examples/cfg/webhooks.tbl` as a starting point - it announces only the
final `released` action (with the release URL); an org-level webhook
covers all repos, and `{repository.name}` distinguishes them.

### Reverse proxy (nginx example)

```nginx
location /webhook/ {
    proxy_pass http://127.0.0.1:5010/v1/webhook/;   # your http_port
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

TLS is terminated by the proxy; the hub speaks plain HTTP on loopback.

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Log: `endpoint '<name>' has no secret ... skipped` | No secret resolved - set the env var, cfg key, or inline `secret`. |
| Sender shows **401**, body `{code:"unauthorized"}` | Signature mismatch on a registered route. The secret differs between sender and hub, or `signature_header` / `signature_prefix` is wrong for that sender. |
| Sender shows **401**, body `{code:"E_UNAUTHENTICATED"}` | The route is not registered (wrong `<name>` in the URL, endpoint has no resolvable secret, or `etc_webhook` disabled). The router 401s an unknown path (it presents no bearer token) rather than leaking which paths exist - fix the path / secret / plugin toggle, not the signature. |
| Sender shows **415** | The sender isn't using `Content-Type: application/json`. |
| **200 but no chat message** | The event isn't in your `events` filter, a `conditions` filter dropped it, there's no `templates` entry for it, or the rendered text is empty. A ping is a 200-with-no-announce by design. |
| Sender shows **413** | The delivery body exceeds the 64 KiB cap. |
| Sender can't reach the hub | The HTTP listener isn't up (`http_port` + a token needed) or the reverse proxy isn't forwarding to the loopback port. |
| Duplicate announcements | Only if the source sends no delivery-id header (dedup needs `id_header`), or `dedup_max` is too small for the volume. |

Enable `log_scripts = true` in `cfg/cfg.tbl` to see `etc_webhook` debug
lines in `log/error.log`.
