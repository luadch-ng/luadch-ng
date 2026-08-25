--[[

    util_http.lua - HTTP-API-specific plugin helpers (#82 Phase 2 PR-B).

    Extracted from core/util.lua to keep the HTTP-API plugin surface
    separate from the generic string / file / table helpers in
    util.lua. As the HTTP API grows (Phase 2 PR-3 cmd_gag, PR-4
    cmd_ban, Phase 3 destructive ops, Phase 4 subsystem managers),
    a dedicated module avoids the "util.lua dumping ground" failure
    mode flagged in the PR-B independent review.

    Generic helpers (`strip_control_bytes`) stay in util.lua because
    they are useful outside the HTTP API too (any string that hits
    an ADC frame benefits from the same defence in depth).

    Public surface:

        util_http.http_register_user_action(
            scriptname, method, path, action_verb, handler_fn, meta?
        )
            Register an admin-scope HTTP endpoint that operates on
            ONE online user identified by `{sid}` in the path. The
            helper handles the preflight (sid + online + non-bot
            check) and constructs the response envelope per
            docs/HTTP_API.md §7.1.1 (action / sid / nick + handler
            data). `handler_fn(req, target)` returns either a flat
            table of action-specific data fields or
            (nil, error_table) for a custom error response.

    Loaded as a core module via init.lua's _core list; plugins see
    `util_http` as a global in their sandbox env via the standard
    _G iteration in core/scripts.lua.

]]--

----------------------------------// DECLARATION //--

local use = use

local pairs = use "pairs"
local type = use "type"

----------------------------------// DEFINITION //--

-- HTTP API helper: register a "user action by SID" endpoint with
-- shared preflight + envelope (#82 Phase 2 PR-B). Captures the
-- pattern PR-1 (cmd_disconnect) and PR-2 (cmd_redirect) both
-- duplicated by hand, and keeps the HTTP_API.md §7.1.1 response
-- envelope shape correct by construction. Future Phase 2 plugin
-- migrations (PR-3 cmd_gag, PR-4 cmd_ban where the target is a
-- SID) SHOULD prefer this helper over a raw hub.http_register
-- call. Plugins that need a different scope, a non-SID target
-- (cmd_ban with nick/cid/ip), or a different envelope shape use
-- the lower-level hub.http_register directly.
--
-- Arguments:
--   scriptname    - the calling plugin's name string; embedded in
--                   the route's `meta.plugin` field for /v1/endpoints
--                   discovery. Pass the script's local `scriptname`.
--   method        - uppercase HTTP method ("POST", "DELETE", ...)
--   path          - URL path template with `{sid}` placeholder, e.g.
--                   "/v1/users/{sid}" or "/v1/users/{sid}/gag"
--   action_verb   - short string used for two things: (a) the
--                   `data.action` field in the response envelope,
--                   (b) the bot-rejection error message
--                   ("cannot <verb> via this endpoint"). MUST be
--                   a static literal at registration time, never
--                   user-controlled input (it is interpolated
--                   into an error string without further sanitisation).
--                   Should be a single-word verb ("disconnect",
--                   "redirect", "gag", "ungag", ...) in lower-case.
--   handler_fn    - function(req, target) -> (data_or_nil, err_or_nil)
--                   Called AFTER the helper has already verified
--                   the SID is online and non-bot; the target arg
--                   is the live user object. Returns either:
--                     - a flat table of action-specific fields to
--                       merge into the response envelope (e.g.
--                       {reason="flood"}); the helper adds the
--                       `action`/`sid`/`nick` convention fields
--                       and SILENTLY drops any handler-supplied
--                       value at those three keys (the envelope
--                       owns them per §7.1.1)
--                     - nil, error_table to bail out with a custom
--                       error response (e.g. 409 if the user is
--                       already in the right state for this action)
--   meta          - optional table forwarded to hub.http_register
--                   (description, request_schema, response_schema).
--                   `plugin = scriptname` is filled in automatically.
--
-- Returns:
--   the registration's result (or false if hub.http_register is
--   absent - the helper is fail-soft so a hypothetical stripped
--   build without the API framework still loads the plugin's ADC
--   surface unchanged).
--
-- Scope is always "admin" - user actions are by-definition admin
-- operations in the current Phase-2 design. A future read-only
-- endpoint or per-user-self surface would NOT use this helper and
-- call hub.http_register directly with its own scope.
local function http_register_user_action( scriptname, method, path, action_verb, handler_fn, meta )
    -- `use "hub"` returns the hub MODULE table (`{init, loop, object}`),
    -- NOT the plugin-facing `_luadch`. The `http_register` /
    -- `issidonline` / etc methods live on `_luadch`, which is
    -- exposed via the `object()` thunk (see core/hub.lua return).
    local _hub_mod = use "hub"
    local hub_obj = _hub_mod and _hub_mod.object and _hub_mod.object( )
    if not hub_obj or not hub_obj.http_register then return false end
    meta = meta or { }
    meta.plugin = meta.plugin or scriptname
    return hub_obj.http_register( method, path, "admin", function( req )
        local sid = req.path_vars and req.path_vars.sid
        if not sid or sid == "" then
            return { status = 400, error = { code = "E_BAD_INPUT",
                message = "missing sid path variable" } }
        end
        local target = hub_obj.issidonline( sid )
        if not target then
            return { status = 404, error = { code = "E_NOT_FOUND",
                message = "no such online sid" } }
        end
        if target:isbot() then
            return { status = 409, error = { code = "E_CONFLICT",
                message = "target is a bot; cannot " .. action_verb ..
                          " via this endpoint" } }
        end
        local data, err = handler_fn( req, target )
        if err then return err end
        local out = {
            action = action_verb,
            sid    = sid,
            nick   = target:nick(),
        }
        if type( data ) == "table" then
            for k, v in pairs( data ) do
                -- Convention fields are owned by the envelope; a
                -- handler MUST NOT override them. Silently skip
                -- any collision - the handler can stash a custom
                -- nick / action / sid value under a different key
                -- if it really needs one.
                if k ~= "action" and k ~= "sid" and k ~= "nick" then
                    out[ k ] = v
                end
            end
        end
        return { status = 200, data = out }
    end, meta )
end

-- Resolve the human operator behind an HTTP-API request, for the
-- audit trail, stored records (ban `by_nick`, gag `added_by`), and
-- operator-facing reports (opchat). The BFF asserts the logged-in
-- operator's nick in the `X-Actor` header, surfaced as `req.actor`
-- (already logsafe-sanitised by the router); a direct token call
-- without that header falls back to the token's non-secret label,
-- then a fixed "http-api".
--
-- IMPORTANT: `req.actor` is client-asserted (any token holder can set
-- X-Actor) and is therefore an ACCOUNTABILITY label ONLY, never an
-- authorisation input - the bearer token's scope is the auth gate.
-- End-user-visible attribution (a kicked/banned user's message, a
-- main-chat post, the announce banner) must use the hubbot nick
-- instead, so the operator identity never reaches end users (#177).
-- `use "util"` is resolved lazily here (matching http_register_user_action's
-- `use "hub"` pattern) to avoid any _core load-order dependency.
local function operator_label( req )
    local util = use "util"
    local actor = req and req.actor
    if type( actor ) == "string" and actor ~= "" then
        return util.strip_control_bytes( actor )
    end
    return util.strip_control_bytes( ( req and req.token_label ) or "http-api" )
end

----------------------------------// PUBLIC INTERFACE //--

return {

    http_register_user_action = http_register_user_action,
    operator_label            = operator_label,

}
