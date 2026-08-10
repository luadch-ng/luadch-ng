--[[

    etc_trafficmanager.lua by pulsar

        based on my etc_transferblocker.lua

        usage:

        [+!#]trafficmanager block <NICK> [<REASON>] -- blocks downloads, uploads and search requests
        [+!#]trafficmanager unblock <NICK>  -- unblock user
        [+!#]trafficmanager show settings  -- shows current settings from "cfg/cfg.tbl"
        [+!#]trafficmanager show blocks  -- shows all blocked users and their blockmodes


        Operator note - CCPM side effect:

        ADC overloads the CTM / RCM commands for BOTH file-transfer
        connection setup AND CCPM (encrypted client-to-client PM)
        channel setup. The onConnectToMe / onRevConnectToMe /
        onNatTraversal / onNatTraversalReply listeners below block
        CTM / RCM and the DNAT / DRNT NAT-traversal fallback for
        blocked levels to stop file transfers, but the wire-level
        commands look identical for
        CCPM - so blocking a level via `etc_trafficmanager_blockedlevels`
        (or via individual `+trafficmanager block <nick>`) ALSO
        disables CCPM for those users. They can still chat through
        the hub via regular EMSG / DMSG; only the direct, end-to-end
        encrypted channel is unreachable.

        There is no clean wire-level differentiator (same protocol
        token, same DCTM shape). A heuristic fix would be "exempt
        CTM / RCM that closely follows a PM between the same SID
        pair" - tracked but not implemented as of v2.5; operators who
        want CCPM available for a level must remove that level from
        the block list and accept the corresponding file-transfer
        permission.

        v2.10:
            - carry a manual block over to the new nick on +nickchange /
              HTTP rename. block_tbl is keyed by firstnick; a rename only
              updated user.tbl, so the block was silently dropped - an
              operator could unblock a user just by renaming them. An
              onAudit tap on reg.nickchange now re-keys block_tbl (covers
              the ADC self / othernick / othernicku paths AND the HTTP
              API). Reported by Sopor.

        v2.9:
            - fix a nil-scriptname leak in the external add() / del()
              API: a caller passing scriptname (or reason) = nil produced
              a literal "nil" in the op report and block_tbl, because
              tostring( nil ) is the truthy string "nil" so the intended
              `... or msg_unknown` fallback never fired. Guarded with
              `~= nil` before tostring at all three sites. Correct callers
              (non-nil scriptname/reason) are unaffected. Reported by an
              operator whose usr_upload_speed passed scriptname = nil.

        v2.8:
            - also block the NAT-traversal fallback (DNAT / DRNT, via the
              new onNatTraversal / onNatTraversalReply listeners), not
              only CTM / RCM. A blocked user could still establish a
              file-transfer OR CCPM connection whenever a DIRECT
              connection was impossible - exactly passive / CGNAT peers,
              whose clients fall back to NAT traversal - because that
              path was never hooked (reported by Sopor: CCPM succeeds on
              passive users despite both being blocked, with no common
              hub). The two new listeners mirror the CTM / RCM block
              logic (masterlevel gate + need_block on user and target;
              need_block tolerates a nil target). Closes the passive /
              CGNAT bypass for both transfers and CCPM.

        v2.7:
            - `show blocks` now also lists currently-online users who
              are auto-blocked by share (0 B / below minshare) or by a
              blocked level. These are runtime classifications computed
              by need_block() on every event and are never persisted to
              block_tbl, so `show blocks` (which only iterates block_tbl)
              previously showed nothing for them - the operator saw an
              empty list plus an empty etc_trafficmanager.tbl while the
              users were in fact being blocked (luadch-ng/luadch-ng#502,
              reported by Sopor). The new section is online-only (share
              is a per-session INF field; an offline user is not being
              share-blocked) and skips nicks already in the manual
              block_tbl list so each user appears in exactly one section.
            - `show settings` now also reports the minshare-check toggle
              (etc_trafficmanager_check_minshare); it previously showed
              only the 0-B-share toggle, so a hub running minshare-only
              gave no indication in settings that share-blocking was on.

        v2.5:
            - fix latent dispatch bug in add() / del() exports
              (closes #257). `( not scriptname ) or ( not scriptname == 1 )`
              parses as `(not X) == 1` which is always false; the
              external-string code path was unreachable. After fix:
              scriptname=nil OR string -> external, scriptname=1 ->
              internal (matches function-header doc-comments).
            - fix latent crash in add() external path: line ~672 used
              `user:nick()` to populate `block_tbl[nick][1]` but `user`
              is nil in the external path - would have crashed if the
              dispatch had ever reached it. Now uses scriptname (the
              external "by" label) consistently with del()'s external
              path and the on-disk by-field semantics.

        v2.4:
            - HTTP API: GET /v1/trafficmanager/{settings,blocks},
              POST + DELETE /v1/trafficmanager/blocks/{nick}
              #82 Phase 4 PR-7

        v2.3:
            - cosmetic refactor: unify return-nil exit pattern in
              onConnectToMe / onRevConnectToMe / onSearchResult.
              Three listeners had two `return nil` paths (inside-gate
              "allow" + outside-gate "exempt") that were functionally
              identical. Now a single explicit `return nil` after the
              gate block. Behaviour unchanged. Bytecode is two
              instructions shorter per listener (the deduplicated
              LOADNIL / RETURN1 pair); verified with `luac -l`.
              Closes luadch-ng/luadch-ng#166. onSearch is not part of
              this refactor because its control-flow shape is
              different (no masterlevel gate, returns PROCESSED
              after fan-out).

        v2.2:
            - defense-in-depth: onSearchResult listener swallows
              RES / DRES / FRES from or to blocked users
                - closes luadch-ng/luadch-ng#160 (Sopor) - covers the
                  unsolicited-result edge case the onSearch filter
                  alone cannot reach

        v2.0 / v2.1:
            - (no header changelog entries; the script-version
              counter was bumped twice without a matching block here.
              Bug-history reconstruction would need `git log -p` on
              this file in the upstream luadch/luadch repo)

        v1.9:
            - fix missing links to language file  / thx Sopor

        v1.8:
            - fix: #171 -> https://github.com/luadch/luadch/issues/171
                - Prevent BLOCKED users from receiving/replying searches

        v1.7:
            - command: [+!#]trafficmanager show blocks
                - shows blocked levels on the bottom
            - command: [+!#]trafficmanager show settings
                - shows levelnumbers of blocked levels
            - fix #82 -> https://github.com/luadch/luadch/issues/82
                - add date and time to blocked users
            - fix #23 -> https://github.com/luadch/luadch/issues/23
                - possibility to block/unblock offline users
            - rewrite "add" & "del" function
            - outsourced "flag_blocked" to "cfg/cfg.tbl"
                - fix #141 -> https://github.com/luadch/luadch/issues/141
            - added comments to some code parts

        v1.6:
            - simplify 'activate' logic
            - changed some parts of code

        v1.5:
            - changed visuals

        v1.4:
            - some modifications based on issue #37  / thx Sopor
                - fix #37 -> https://github.com/luadch/luadch/issues/37
            - removed table lookups
            - add "del()" function for export feature

        v1.3:
            - users with lower level can't block or unblock higher levels or the same level

        v1.2:
            - added "etc_trafficmanager_check_minshare"
                - block user instead of disconnect if usershare < minshare
            - small typo fix  / thx WitchHunter

        v1.1:
            - possibility to set a reason on block
            - using target:nick() instead of target:firstnick() for output msgs
            - send msg to target on block/unblock
            - send block reason to target on login/rotation msg
            - using new util.spairs() function for blocked users list
            - added block export function
            - small permission fix
            - save/show nickname of blocker to/from db too

        v1.0:
            - there is only one block method now: download + upload + search
            - fix problem with passive users
            - users with permissions can download from blocked users now
            - removed unneeded code parts
            - new default description tag for blocked users is: "[BLOCKED] "
            - added "msg_onsearch"  / requested by Sopor

        v0.9:
            - small fix in "onbmsg" function
            - added "is_autoblocked()" function
            - changed "msg_notfound" msg
            - code cleanup

        v0.8:
            - possibility to send the user report msg as loop every x hours  / requested by DerWahre
            - fix output messages to prevent possible client emotions  / thx Sopor
            - fix small bug in "onExit" listener
            - fix small bug in "onStart" listener  / thx Sopor
            - removed send_report() function, using report import functionality now
            - send specific msg to user if targetuser was autoblocked by script  / thx Sopor

        v0.7:
            - small bugfix  / thx Mocky

        v0.6:
            - check if target is a bot  / thx Kaas
            - fix "msg_notonline"  / thx Sopor
            - add "is_blocked()"
                - fix double block issue  / thx Sopor

        v0.5:
            - possibility to block/unblock single users from userlist  / requested by Sopor
            - show list of all blocked users
            - show settings
            - show blockmode in user description
            - add new table lookups, imports, msgs
            - rewrite some parts of code

        v0.4:
            - possibility to block users with 0 B share

        v0.3:
            - small fix in "onLogin" listener
                - remove return PROCESSED
                - add return nil

        v0.2:
            - add missing permission check  / thx Kaas

        v0.1:
            - option to block download for specified levels
            - option to block upload for specified levels
            - option to block search for specified levels

]]--


--------------
--[SETTINGS]--
--------------

local scriptname = "etc_trafficmanager"
local scriptversion = "2.10"

local cmd = "trafficmanager"
local cmd_b = "block"
local cmd_u = "unblock"
local cmd_s = "show"

--// imports
local scriptlang = cfg.get( "language" )
local lang, err = cfg.loadlanguage( scriptlang, scriptname ); lang = lang or { }; err = err and hub.debug( err )
local activate = cfg.get( "etc_trafficmanager_activate" )
local permission = cfg.get( "etc_trafficmanager_permission" )
local report = hub.import( "etc_report" )
local report_activate = cfg.get( "etc_trafficmanager_report" )
local report_hubbot = cfg.get( "etc_trafficmanager_report_hubbot" )
local report_opchat = cfg.get( "etc_trafficmanager_report_opchat" )
local llevel = cfg.get( "etc_trafficmanager_llevel" )
local blocklevel_tbl = cfg.get( "etc_trafficmanager_blocklevel_tbl" )
local sharecheck = cfg.get( "etc_trafficmanager_sharecheck" )
local minsharecheck = cfg.get( "etc_trafficmanager_check_minshare" )
local min_share = cfg.get( "min_share" )
local oplevel = cfg.get( "etc_trafficmanager_oplevel" )
local login_report = cfg.get( "etc_trafficmanager_login_report" )
local report_main = cfg.get( "etc_trafficmanager_report_main" )
local report_pm = cfg.get( "etc_trafficmanager_report_pm" )
local nick_prefix_activate = cfg.get( "usr_nick_prefix_activate" )
local nick_prefix_permission = cfg.get( "usr_nick_prefix_permission" )
local nick_prefix_prefix_table = cfg.get( "usr_nick_prefix_prefix_table" )
local desc_prefix_activate = cfg.get( "usr_desc_prefix_activate" )
local desc_prefix_permission = cfg.get( "usr_desc_prefix_permission" )
local desc_prefix_table = cfg.get( "usr_desc_prefix_prefix_table" )
local send_loop = cfg.get( "etc_trafficmanager_send_loop" )
local loop_time = cfg.get( "etc_trafficmanager_loop_time" )
local block_file = "scripts/data/etc_trafficmanager.tbl"
local block_tbl = util.loadtable( block_file ) or {}
local flag_blocked = cfg.get( "etc_trafficmanager_flag_blocked" )

--// msgs
local help_title = lang.help_title or "etc_trafficmanager.lua - Operators"
local help_usage = lang.help_usage or "[+!#]trafficmanager show settings|blocks"
local help_desc = lang.help_desc or "Shows current settings from 'cfg/cfg.tbl' | Shows all blocked users and their blockmodes"

local help_title2 = lang.help_title2 or "etc_trafficmanager.lua - Owners"
local help_usage2 = lang.help_usage2 or "[+!#]trafficmanager block <NICK> [<REASON>] | unblock <NICK>"
local help_desc2 = lang.help_desc2 or "Blocks downloads ( d ), uploads ( u ) and search ( s ) | Unblock user"

local msg_denied = lang.msg_denied or "[ TRAFFICMANAGER ]--> You are not allowed to use this command."
local msg_god = lang.msg_god or "[ TRAFFICMANAGER ]--> You are not allowed to block/unblock this user."
local msg_notfound = lang.msg_notfound or "[ TRAFFICMANAGER ]--> User isn't blocked."
local msg_stillblocked = lang.msg_stillblocked or "[ TRAFFICMANAGER ]--> User:  %s  is already blocked by:  %s  |  reason:  %s"
local msg_isbot = lang.msg_isbot or "[ TRAFFICMANAGER ]--> User is a bot."
local msg_block = lang.msg_block or "[ TRAFFICMANAGER ]--> Block user:  %s  |  reason:  %s"
local msg_unblock = lang.msg_unblock or "[ TRAFFICMANAGER ]--> Unblock user:  %s"
local msg_op_report_block = lang.msg_op_report_block or "[ TRAFFICMANAGER ]--> User:  %s  |  has blocked user:  %s  |  IP:  %s  |  reason:  %s"
local msg_op_report_unblock = lang.msg_op_report_unblock or "[ TRAFFICMANAGER ]--> User:  %s  |  has unblocked user:  %s  |  IP:  %s"
local msg_autoblock = lang.msg_autoblock or "[ TRAFFICMANAGER ]--> This user was autoblocked by script permissions."
local msg_onsearch = lang.msg_onsearch or "[ TRAFFICMANAGER ]--> Your search function is disabled."
local msg_unknown = lang.msg_unknown or "<UNKNOWN>"
local msg_reason = lang.msg_reason or "Reason:"
local msg_blocked_by = lang.msg_blocked_by or "Blocked by:"
local msg_date = lang.msg_date or "Blocked date:"
local msg_ab_level = lang.msg_ab_level or "Blocked level"
local msg_ab_zeroshare = lang.msg_ab_zeroshare or "0 B share"
local msg_ab_minshare = lang.msg_ab_minshare or "Below minshare"
local msg_ab_none = lang.msg_ab_none or "(none)"
local msg_target_block = lang.msg_target_block or "[ TRAFFICMANAGER ]--> You were blocked by:  %s  |  reason:  %s"
local msg_target_unblock = lang.msg_target_unblock or "[ TRAFFICMANAGER ]--> You were unblocked by:  %s"
local ucmd_nick = lang.ucmd_nick or "User firstnick:"
local ucmd_menu_ct1_1 = lang.ucmd_menu_ct1_1 or { "Hub", "etc", "Traffic Manager", "show", "Settings" }
local ucmd_menu_ct1_2 = lang.ucmd_menu_ct1_2 or { "Hub", "etc", "Traffic Manager", "show", "Blocked users" }
local ucmd_menu_ct1_3 = lang.ucmd_menu_ct1_3 or { "User", "Control", "Traffic Manager", "block user" }
local ucmd_menu_ct1_4 = lang.ucmd_menu_ct1_4 or { "User", "Control", "Traffic Manager", "unblock user" }
local ucmd_menu_ct2_1 = lang.ucmd_menu_ct2_1 or { "Traffic Manager", "block" }
local ucmd_menu_ct2_3 = lang.ucmd_menu_ct2_3 or { "Traffic Manager", "unblock" }
local ucmd_desc = lang.ucmd_desc or "Reason:"

local report_msg = lang.report_msg or [[


=== TRAFFIC MANAGER =====================================

     Hello %s, your level in this hub:  %s [ %s ]

     Downloads, Uploads and Searches are blocked.

===================================== TRAFFIC MANAGER ===
  ]]

local report_msg_2 = lang.report_msg_2 or [[


=== TRAFFIC MANAGER =====================================

     Hello %s,
     your sharesize does not meet the minshare requirements:

     Downloads, Uploads and Searches are blocked.

===================================== TRAFFIC MANAGER ===
  ]]

local report_msg_3 = lang.report_msg_3 or [[


=== TRAFFIC MANAGER =====================================

     Hello %s, your nick is on the blocklist.

     Blocked by: %s
     Reason: %s

     Downloads, Uploads and Searches are blocked.

===================================== TRAFFIC MANAGER ===
  ]]

local opmsg = lang.opmsg or [[


=== TRAFFIC MANAGER =====================================

   Script is active:  %s
   Send report to blocked users on login:  %s
   Send report to blocked users on timer:  %s

         Send to Main:  %s
         Send to PM:  %s

   Blocked levels:

%s
   Block users with 0 B share:  %s
   Block users below minshare:  %s

===================================== TRAFFIC MANAGER ===
  ]]

local msg_usage = lang.msg_usage or [[


=== TRAFFIC MANAGER ===========================================================

Usage:

 [+!#]trafficmanager block <NICK> [<REASON>]  -- blocks downloads ( d ), uploads ( u ) and search ( s )
 [+!#]trafficmanager unblock <NICK>  -- unblock user
 [+!#]trafficmanager show settings  -- shows current settings from "cfg/cfg.tbl"
 [+!#]trafficmanager show blocks  -- shows all blocked users and their blockmodes

=========================================================== TRAFFIC MANAGER ===
  ]]

local msg_users = lang.msg_users or [[


=== TRAFFIC MANAGER ========================================================================
%s

   Blocked levels:

%s

   Auto-blocked ( online ):
%s
======================================================================== TRAFFIC MANAGER ===
  ]]

--// functions
local onbmsg
local get_blocklevels
local get_autoblocked_online
local get_bool
local check_share
local is_blocked
local is_autoblocked
local send_user_report
local format_description
local add, del
local remove_udp4
local inf_listener
local connect_listener


----------
--[CODE]--
----------

flag_blocked = flag_blocked .. " "

if not activate then
   hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " (not active) **" )
   return
end

--// timer
local delay = loop_time * 60 * 60
local start = os.time()

-- Op-exempt gate for **three** of the four blocking listeners:
-- onConnectToMe, onRevConnectToMe, onSearchResult. (onSearch is
-- intentionally exempt-less - see the note below.)
-- `masterlevel` is the lowest level with non-zero entries in
-- `etc_trafficmanager_permission` - by default 60 (operator).
-- Those three listeners gate their filter behaviour on
-- `user:level() < masterlevel`, which means users at level >= 60
-- (ops and above) bypass the block filter for those three event
-- types even when they appear in `block_tbl`. This is
-- **intentional**:
--   1. Admin self-soft-lock protection: a typo on
--      `+trafficmanager block <yournick>` doesn't cut you out
--      of your own hub.
--   2. The `[BLOCKED]` description flag and userlist annotation
--      still apply, so the block is visible to other operators
--      even though the filter is bypassed - an op-vs-op block
--      is effectively a "this user is hereby noted as
--      blocklist-flagged" gesture for CTM / RCM / RES rather
--      than a hard restriction on those three event types.
--
-- **onSearch asymmetry:** the onSearch listener (block SCH) has
-- NO `< masterlevel` gate; it checks `need_block( user )`
-- directly and blocks searches from any user on `block_tbl`,
-- including ops. This is a real difference from the other three
-- listeners. The block does not lock an op out of the hub
-- entirely (they can still PM and main-chat), so the
-- self-soft-lock concern is weaker for searches than for the
-- peer-connection primitives.
--
-- If your threat model requires hard-blocking ops on CTM / RCM /
-- RES too (e.g. defense against a rogue / compromised op-account),
-- see luadch-ng/luadch-ng#167 for the design discussion + options.
-- The options (global hardblock toggle, per-block flag, separate
-- filter-min-level cfg) are not implemented because no operator
-- has reported needing them yet. Threat-model is "ops are
-- trusted" by design.
local masterlevel = util.getlowestlevel( permission )

--// get all levelnames from blocked table in sorted order
get_blocklevels = function()
    local levels = cfg.get( "levels" ) or {}
    local tbl = {}
    local i = 1
    local msg = ""
    for k, v in pairs( blocklevel_tbl ) do
        if k >= 0 then
            if v then
                tbl[ i ] = k
                i = i + 1
            end
        end
    end
    table.sort( tbl )
    for _, level in pairs( tbl ) do
        msg = msg .. "\t" .. level .. "\t[ " .. levels[ level ] .. " ]\n"
    end
    return msg
end

--// list currently online users that are auto-blocked by share or by
--  a blocked level. These are runtime need_block() classifications
--  that are never written to block_tbl, so `show blocks` (which only
--  iterates block_tbl) would otherwise not surface them (#502). Nicks
--  already present in block_tbl are skipped so each user appears in
--  exactly one section (the manual list is the actionable one). Only
--  online users are listed: share is a per-session INF field, so an
--  offline user is not being share-blocked. hub.getusers() single-
--  assignment yields the humans-only table, so bots are excluded.
get_autoblocked_online = function()
    local levels = cfg.get( "levels" ) or {}
    local rows = {}
    for sid, user in pairs( hub.getusers() ) do
        local firstnick = user:firstnick()
        if not is_blocked( firstnick ) then
            local level = user:level()
            local reason
            if blocklevel_tbl[ level ] then
                reason = msg_ab_level .. " [ " .. ( levels[ level ] or "Unreg" ) .. " ]"
            elseif check_share( user ) then
                --> distinguish the two share triggers for the operator.
                --  check_share short-circuits on the 0-B case only when
                --  sharecheck is on; a 0-B user under a minshare-only
                --  config is correctly labelled "below minshare".
                local share = user:share() or 0
                if sharecheck and share == 0 then
                    reason = msg_ab_zeroshare
                else
                    reason = msg_ab_minshare
                end
            end
            if reason then
                rows[ #rows + 1 ] = { nick = firstnick, reason = reason }
            end
        end
    end
    table.sort( rows, function( a, b ) return a.nick < b.nick end )
    local msg = ""
    for _, row in ipairs( rows ) do
        msg = msg .. "\n   Nickname:  " .. row.nick .. "\n" ..
                     "\t" .. msg_reason .. " " .. row.reason .. "\n"
    end
    if msg == "" then msg = "\n   " .. msg_ab_none .. "\n" end
    return msg
end

--// returns value of a bool as string
get_bool = function( var )
    if var then return "true" end
    return "false"
end

--// check if user has no share
check_share = function( target )
    if target:level() < oplevel then
        -- Phase 8a F-INF-1: target:share() is nil for clients that did
        -- not declare SS in their BINF; treat as 0 so the no-share /
        -- under-min checks both fire on the missing-field case (which
        -- is the safe semantic - a client that did not declare share
        -- is treated identically to one declaring 0).
        local share = target:share() or 0
        if sharecheck then
            if share == 0 then return true end
        end
        if minsharecheck then
            local min = min_share[ target:level() ] * 1024 * 1024 * 1024
            if share < min then return true end
        end
    end
    return false
end

--// check if target user is still autoblocked
is_autoblocked = function( target, target_level )
    if target and check_share( target ) then return true end
    if target_level and blocklevel_tbl[ target_level ] then return true end
    return false
end

--// check if target user is still blocked
is_blocked = function( firstnick )
    if firstnick then
        if type( block_tbl[ firstnick ] ) ~= "nil" then return true end
    end
    return false
end

--// user report msg on timer
send_user_report = function()
    if send_loop then
        for sid, user in pairs( hub.getusers() ) do
            local user_level = user:level()
            local user_firstnick = user:firstnick()
            local msg
            local need_save = false
            if blocklevel_tbl[ user_level ] then
                local levelname = cfg.get( "levels" )[ user_level ] or "Unreg"
                msg = utf.format( report_msg, user_firstnick, user_level, levelname )
                if report_main then user:reply( msg, hub.getbot() ) end
                if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
            elseif check_share( user ) then
                msg = utf.format( report_msg_2, user_firstnick )
                if report_main then user:reply( msg, hub.getbot() ) end
                if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
            elseif type( block_tbl[ user_firstnick ] ) ~= "nil" then
                if type( block_tbl[ user_firstnick ] ) == "boolean" then  -- downward compatibility with older versions
                    block_tbl[ user_firstnick ] = nil
                    block_tbl[ user_firstnick ] = {}
                    block_tbl[ user_firstnick ][ 1 ] = msg_unknown
                    block_tbl[ user_firstnick ][ 2 ] = msg_unknown
                    need_save = true
                elseif type( block_tbl[ user_firstnick ] ) == "string" then  -- downward compatibility with older versions
                    local reason = block_tbl[ user_firstnick ]
                    block_tbl[ user_firstnick ] = nil
                    block_tbl[ user_firstnick ] = {}
                    block_tbl[ user_firstnick ][ 1 ] = msg_unknown
                    block_tbl[ user_firstnick ][ 2 ] = reason
                    need_save = true
                end
                msg = utf.format( report_msg_3, user_firstnick, block_tbl[ user_firstnick ][ 1 ], block_tbl[ user_firstnick ][ 2 ] )
                if report_main then user:reply( msg, hub.getbot() ) end
                if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
                if need_save then util.savetable( block_tbl, "block_tbl", block_file ) end
            end
        end
    end
end

--// add/remove description flag
format_description = function( flag, listener, target, cmd )
    local desc, new_desc = "", ""
    if listener == "onStart" then
        if desc_prefix_activate and desc_prefix_permission[ target:level() ] then
            local desc_tag = hub.escapeto( desc_prefix_table[ target:level() ] )
            local desc = target:description() or ""
            local desc_part1 = desc:sub( 1, #desc_tag )
            local desc_part2 = desc:sub( #desc_tag + 1, #desc )
            local prefix = hub.escapeto( flag )
            new_desc = desc_part1 .. prefix .. desc_part2
        else
            local prefix = hub.escapeto( flag )
            local desc = target:description() or ""
            new_desc = prefix .. desc
        end
    end
    if listener == "onExit" then
        if desc_prefix_activate and desc_prefix_permission[ target:level() ] then
            local prefix = hub.escapeto( flag )
            local desc = target:description() or ""
            new_desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
        else
            local prefix = hub.escapeto( flag )
            local desc = target:description() or ""
            new_desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
        end
    end
    if listener == "onInf" then
        -- Phase 8a F-INF-1e (luadch-ng/luadch-ng#121 review pass): cmd:getnp
        -- "DE" returns nil if the incoming INF carries no DE field. Pre-
        -- fix the only caller (the onInf listener at the bottom of this
        -- file) gated the call with `if desc then`, so this branch was
        -- safe in practice - but the precondition was implicit. Coerce
        -- to "" defensively so a future caller that drops the gate does
        -- not reintroduce the crash. Matches the `target:description()
        -- or ""` pattern the other three listener branches already use.
        if desc_prefix_activate and desc_prefix_permission[ target:level() ] then
            local desc_tag = hub.escapeto( desc_prefix_table[ target:level() ] )
            local desc = cmd:getnp "DE" or ""
            local desc_part1 = desc:sub( 1, #desc_tag )
            local desc_part2 = desc:sub( #desc_tag + 1, #desc )
            local prefix = hub.escapeto( flag )
            new_desc = desc_part1 .. prefix .. desc_part2
        else
            local prefix = hub.escapeto( flag )
            local desc = cmd:getnp "DE" or ""
            new_desc = prefix .. desc
        end
    end
    if listener == "onConnect" then
        if desc_prefix_activate and desc_prefix_permission[ target:level() ] then
            local desc_tag = hub.escapeto( desc_prefix_table[ target:level() ] )
            local desc = target:description() or ""
            local desc_part1 = desc:sub( 1, #desc_tag )
            local desc_part2 = desc:sub( #desc_tag + 1, #desc )
            local prefix = hub.escapeto( flag )
            new_desc = desc_part1 .. prefix .. desc_part2
        else
            local prefix = hub.escapeto( flag )
            local desc = target:description() or ""
            new_desc = prefix .. desc
        end
    end
    return new_desc
end

--// add block (with export feature)
-- Look up an online user by their first/registered nick. The original
-- add()/del() code computed an expected display-nick by appending the
-- standard usr_nick_prefix prefix and then called hub.isnickonline()
-- on it; that failed silently for any custom nick-prefix script
-- (different prefix table, different transform), leaving `target` nil
-- so the user got no message and no description flag - the bug
-- reported as upstream luadch/luadch#240. Iterating by firstnick is
-- robust against any prefix scheme.
-- firstnick fallback -> the shared core helper (#537 dedup).
local find_online_by_firstnick = hub.find_online_by_firstnick

add = function( firstnick, scriptname, reason, user )
    local err, by
    local target_nick
    local target_level = 0
    local otherScript = false
    --> internal or external block.
    --  scriptname == 1 means ADC chat-cmd internal path (user is
    --  required); anything else (string OR nil) means external
    --  caller via hub.import. Fix for #257: pre-fix used
    --  `( not scriptname ) or ( not scriptname == 1 )` which
    --  Lua-parses as `(not X) == 1` and is always false, so the
    --  external-string path was unreachable.
    if ( not scriptname ) or ( scriptname ~= 1 ) then
        otherScript = true --> external block
        -- Guard `~= nil` BEFORE tostring: an external caller may pass a
        -- nil scriptname/reason, and `tostring( nil )` is the truthy
        -- string "nil", so a bare `tostring( x ) or msg_unknown` fallback
        -- never fires and leaks a literal "nil" into the op report /
        -- block_tbl (reported by an operator whose script passed nil).
        scriptname = scriptname ~= nil and tostring( scriptname ) or msg_unknown
    end
    --> set reason msg
    reason = reason ~= nil and tostring( reason ) or msg_unknown
    if otherScript then reason = reason .. "  |  blocked by scriptname: " .. scriptname end
    --> Resolve target. The `firstnick` argument may be an unprefixed
    --  registered nick (e.g. from cmd_ban export) or a prefixed
    --  display-nick (from a right-click usercommand). Try both.
    --  Closes upstream luadch/luadch#240.
    local target = hub.isnickonline( firstnick )
    if not target then target = find_online_by_firstnick( firstnick ) end
    if target then firstnick = target:firstnick() end
    --> get all regged nicks
    local regusers, reggednicks, reggedcids = hub.getregusers()
    --> check if target is regged
    local isRegged = reggednicks[ firstnick ]
    --> get target_level
    if isRegged then target_level = isRegged.level end
    --> get target_nick (display name; used in op-side reports)
    if nick_prefix_activate and nick_prefix_permission[ target_level ] then
        local prefix = hub.escapeto( nick_prefix_prefix_table[ target_level ] )
        target_nick = prefix .. firstnick
    else
        target_nick = firstnick
    end
    --> target is bot
    if target and target:isbot() then
        err = msg_isbot
        return false, err
    end
    --> check if target is autoblocked
    if target and is_autoblocked( target, target_level ) then
        err = msg_autoblock
        return false, err
    end
    --> check if target nick is blocked
    if is_blocked( firstnick ) then
        err = utf.format( msg_stillblocked, firstnick, block_tbl[ firstnick ][ 1 ], block_tbl[ firstnick ][ 2 ] )
        return false, err
    end
    --> function to add flag to description
    local add_flag = function()
        --> add description flag
        for sid, buser in pairs( hub.getusers() ) do
            if buser:firstnick() == firstnick then
                local new_desc = format_description( flag_blocked, "onStart", buser, nil )
                buser:inf():setnp( "DE", new_desc ) --> add new desc flag to target INF
                hub.sendtoall( "BINF " .. sid .. " DE" .. new_desc .. "\n" ) --> send new desc to all
                break
            end
        end
    end

    --// internal block
    if not otherScript then
        --> check user permission
        if ( permission[ user:level() ] or 0 ) < target_level then
            err = msg_god
            return false, err
        end
        --> add target to block tbl
        block_tbl[ firstnick ] = {}
        block_tbl[ firstnick ][ 1 ] = user:nick()
        block_tbl[ firstnick ][ 2 ] = reason
        block_tbl[ firstnick ][ 3 ] = util.date()
        util.savetable( block_tbl, "block_tbl", block_file )
        --> send msg to user
        local msg_user = utf.format( msg_block, firstnick, reason )
        user:reply( msg_user, hub.getbot() )
        --> send report
        local target_ip = ( target and target:ip() ) or msg_unknown
        local msg_report = utf.format( msg_op_report_block, user:nick(), target_nick, target_ip, reason )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
        --> if target is online
        if target then
            --> send msg to target
            local msg_target = utf.format( msg_target_block, user:nick(), reason )
            target:reply( msg_target, hub.getbot(), hub.getbot() )
            --> add description flag
            add_flag()
        end
        return PROCESSED

    --// external block
    else
        --> add target to block tbl. The "by" field (block_tbl[
        --  nick][1]) must NOT be `user:nick()` here - in the
        --  external path `user` is nil. Use `scriptname` (the
        --  external caller's label) consistent with del()'s
        --  external path and the show-blocks display format. Fix
        --  for the second half of #257.
        block_tbl[ firstnick ] = {}
        block_tbl[ firstnick ][ 1 ] = scriptname
        block_tbl[ firstnick ][ 2 ] = reason
        block_tbl[ firstnick ][ 3 ] = util.date()
        util.savetable( block_tbl, "block_tbl", block_file )
        --> send report
        local target_ip = ( target and target:ip() ) or msg_unknown
        local msg_report = utf.format( msg_op_report_block, scriptname, target_nick, target_ip, reason )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
        --> if target is online
        if target then
            --> send msg to target
            local msg_target = utf.format( msg_target_block, scriptname, reason )
            target:reply( msg_target, hub.getbot(), hub.getbot() )
            --> add description flag
            add_flag()
        end
        return PROCESSED
    end
    return true
end

--// del block (with export feature)
del = function( firstnick, scriptname, user )
    local err
    local target_nick
    local target_level = 0
    local otherScript = false
    local new_desc
    --> internal or external unblock? Same dispatch contract as
    --  add() above: scriptname==1 -> internal, else (string or
    --  nil) -> external. See add() for the #257 fix rationale.
    if ( not scriptname ) or ( scriptname ~= 1 ) then
        otherScript = true --> external unblock
        -- `~= nil` guard before tostring, same nil-leak fix as add().
        scriptname = scriptname ~= nil and tostring( scriptname ) or msg_unknown
    end
    --> Resolve target (same dual-input handling as add(); closes
    --  upstream luadch/luadch#240).
    local target = hub.isnickonline( firstnick )
    if not target then target = find_online_by_firstnick( firstnick ) end
    if target then firstnick = target:firstnick() end
    --> get all regged nicks
    local regusers, reggednicks, reggedcids = hub.getregusers()
    --> check if target is regged
    local isRegged = reggednicks[ firstnick ]
    --> get target_level
    if isRegged then target_level = isRegged.level end
    --> get target_nick (display name; used in op-side reports)
    if nick_prefix_activate and nick_prefix_permission[ target_level ] then
        local prefix = hub.escapeto( nick_prefix_prefix_table[ target_level ] )
        target_nick = prefix .. firstnick
    else
        target_nick = firstnick
    end
    --> check if target nick is blocked
    if not is_blocked( firstnick ) then
        err = msg_notfound
        return false, err
    end
    if target then
        --> remove description flag
        if desc_prefix_activate and desc_prefix_permission[ target_level ] then
            local prefix = hub.escapeto( flag_blocked )
            local desc_tag = hub.escapeto( desc_prefix_table[ target_level ] )
            -- Phase 8a F-INF-1c: target:description() is nil for clients
            -- without DE in BINF; coerce to "" so utf.sub does not crash.
            local desc = utf.sub( target:description() or "", utf.len( desc_tag ) + 1, -1 )
            local desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
            new_desc = desc_tag .. desc
        else
            local prefix = hub.escapeto( flag_blocked )
            local desc = target:description() or ""
            new_desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
        end
    end

    --// internal unblock
    if not otherScript then
        --> check user permission
        if user:level() < masterlevel then
            err = msg_denied
            return false, err
        end
        --> unblock target
        block_tbl[ firstnick ] = nil
        util.savetable( block_tbl, "block_tbl", block_file )
        --> send report
        local target_ip = ( target and target:ip() ) or msg_unknown
        local msg_report = utf.format( msg_op_report_unblock, user:nick(), target_nick, target_ip )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
        --> send msg to user
        local msg_user = utf.format( msg_unblock, firstnick )
        user:reply( msg_user, hub.getbot() )
        if target then --> target is online
            --> send msg to target
            local msg_target = utf.format( msg_target_unblock, user:nick() )
            target:reply( msg_target, hub.getbot(), hub.getbot() )
            --> remov description flag
            target:inf():setnp( "DE", new_desc or "" )
            hub.sendtoall( "BINF " .. target:sid() .. " DE" .. new_desc .. "\n" )
        end
        return PROCESSED

    --// external script unblock
    else
        --> unblock target
        block_tbl[ firstnick ] = nil
        util.savetable( block_tbl, "block_tbl", block_file )
        --> send report
        local target_ip = ( target and target:ip() ) or msg_unknown
        local msg_report = utf.format( msg_op_report_unblock, scriptname, target_nick, target_ip )
        report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )
        if target then --> target is online
            --> send msg to target
            local msg_target = utf.format( msg_target_unblock, scriptname )
            target:reply( msg_target, hub.getbot(), hub.getbot() )
            --> remove description flag
            target:inf():setnp( "DE", new_desc or "" )
            hub.sendtoall( "BINF " .. target:sid() .. " DE" .. new_desc .. "\n" )
        end
        return PROCESSED
    end
    return true
end

--// if user logs in
hub.setlistener( "onLogin", {},
    function( user )
        local msg
        local need_save = false
        if user:level() < masterlevel then
            if blocklevel_tbl[ user:level() ] then
                if login_report then
                    local levelname = cfg.get( "levels" )[ user:level() ] or "Unreg"
                    msg = utf.format( report_msg, user:firstnick(), user:level(), levelname )
                    if report_main then user:reply( msg, hub.getbot() ) end
                    if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
                end
            elseif check_share( user ) then
                if login_report then
                    msg = utf.format( report_msg_2, user:firstnick() )
                    if report_main then user:reply( msg, hub.getbot() ) end
                    if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
                end
            elseif type( block_tbl[ user:firstnick() ] ) ~= "nil" then
                if login_report then
                    if type( block_tbl[ user:firstnick() ] ) == "boolean" then  -- downward compatibility with older versions
                        block_tbl[ user:firstnick() ] = nil
                        block_tbl[ user:firstnick() ] = {}
                        block_tbl[ user:firstnick() ][ 1 ] = msg_unknown
                        block_tbl[ user:firstnick() ][ 2 ] = msg_unknown
                        need_save = true
                    elseif type( block_tbl[ user:firstnick() ] ) == "string" then  -- downward compatibility with older versions
                        local reason = block_tbl[ user:firstnick() ]
                        block_tbl[ user:firstnick() ] = nil
                        block_tbl[ user:firstnick() ] = {}
                        block_tbl[ user:firstnick() ][ 1 ] = msg_unknown
                        block_tbl[ user:firstnick() ][ 2 ] = reason
                        need_save = true
                    end
                    msg = utf.format( report_msg_3, user:firstnick(), block_tbl[ user:firstnick() ][ 1 ], block_tbl[ user:firstnick() ][ 2 ] )
                    if report_main then user:reply( msg, hub.getbot() ) end
                    if report_pm then user:reply( msg, hub.getbot(), hub.getbot() ) end
                    if need_save then util.savetable( block_tbl, "block_tbl", block_file ) end
                end
            end
        end
        return nil
    end
)

--// hubcmd
onbmsg = function( user, command, parameters )
    local target_nick, target_firstnick, target_level, target_sid
    local p1, p2, p3 = utf.match( parameters, "^(%S+) (%S+) ?(.*)" )
    if p3 == "" then p3 = msg_unknown end --> reason
    --// [+!#]trafficmanager show settings
    if ( ( p1 == cmd_s ) and ( p2 == "settings" ) ) then
        if user:level() < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local msg = utf.format( opmsg,
            get_bool( activate ),
            get_bool( login_report ),
            get_bool( send_loop ),
            get_bool( report_main ),
            get_bool( report_pm ),
            get_blocklevels(),
            get_bool( sharecheck ),
            get_bool( minsharecheck )
        )
        user:reply( msg, hub.getbot() )
        return PROCESSED
    end
    --// [+!#]trafficmanager show blocks
    if ( ( p1 == cmd_s ) and ( p2 == "blocks" ) ) then
        if user:level() < oplevel then
            user:reply( msg_denied, hub.getbot() )
            return PROCESSED
        end
        local msg = ""
        local blocker, reason, blockdate
        for k, v in util.spairs( block_tbl ) do
            if type( v ) == "boolean" then  -- downward compatibility with older versions
                blocker = msg_unknown
                reason = msg_unknown
                blockdate = msg_unknown
            elseif type( v ) == "string" then  -- downward compatibility with older versions
                blocker = msg_unknown
                reason = v
                blockdate = msg_unknown
            elseif type( v ) == "table" then
                blocker = v[ 1 ] or msg_unknown
                reason = v[ 2 ] or msg_unknown
                blockdate = v[ 3 ] or msg_unknown
                if blockdate ~= msg_unknown then
                    blockdate = tostring( blockdate )
                    local y, m, d, h, M, s
                    y = blockdate:sub( 1, 4 )
                    m = blockdate:sub( 5, 6 )
                    d = blockdate:sub( 7, 8 )
                    h = blockdate:sub( 9, 10 )
                    M = blockdate:sub( 11, 12 )
                    s = blockdate:sub( 13, 14 )
                    blockdate = y .. "-" .. m .. "-" .. d .. " / " .. h .. ":" .. M .. ":" .. s
                end
            end
            msg = msg .. "\n   Nickname:  " .. k .. "\n\n" ..
                         "\t" .. msg_blocked_by .. " " .. blocker .. "\n" ..
                         "\t" .. msg_date .. " " .. blockdate .. "\n" ..
                         "\t" .. msg_reason .. " " .. reason .. "\n"
        end
        --> arg order MUST match msg_users' %s order (manual, levels,
        --  auto-blocked). The auto-blocked %s is LAST so a stale lang
        --  file with the old two-%s msg_users degrades gracefully
        --  (drops the auto section) instead of rendering it under the
        --  "Blocked levels" header and losing the real level list -
        --  lang files are add-only on upgrade, so drift is the norm.
        local msg_out = utf.format( msg_users, msg, get_blocklevels(), get_autoblocked_online() )
        user:reply( msg_out, hub.getbot() )
        return PROCESSED
    end
    --// [+!#]trafficmanager block <NICK>
    if ( ( p1 == cmd_b ) and p2 ) then
        local _, err = add( p2, 1, p3, user )
        if err then
            user:reply( err, hub.getbot() )
        end
        return PROCESSED
    end
    --// [+!#]trafficmanager unblock <NICK>
    if ( ( p1 == cmd_u ) and p2 ) then
        local _, err = del( p2, 1, user )
        if err then
            user:reply( err, hub.getbot() )
        end
        return PROCESSED
    end
    user:reply( msg_usage, hub.getbot() )
    return PROCESSED
end

--// check if user needs to be blocked
local need_block = function( user )
    if user then
        if blocklevel_tbl[ user:level() ] or check_share( user ) or type( block_tbl[ user:firstnick() ] ) ~= "nil" then return true end
    end
    return false
end

--// remove "UDP4"
remove_udp4 = function( user, cmd, su )
    local s, e = string.find( su, "UDP4" )
    if s then
        local new_su
        local l = #su
        if e < l then
            new_su = su:gsub( "UDP4,", "" )
        else
            new_su = su:gsub( ",UDP4", "" )
        end
        cmd:setnp( "SU", new_su )
    end
end

--// remove "UDP4/TCP4"
inf_listener = function( user, cmd )
    local su = cmd:getnp "SU"
    if su then
        remove_udp4( user, cmd, su )
    end
    return nil
end

--// remove "UDP4/TCP4"
connect_listener = function( user )
    local cmd = user:inf( )
    local su = cmd:getnp "SU"
    if su then
        remove_udp4( user, cmd, su )
    end
    return nil
end

--// block CTM
hub.setlistener( "onConnectToMe", {},
    function( user, target, adccmd )
        if user:level() < masterlevel then
            if need_block( user ) then return PROCESSED end
            if need_block( target ) then return PROCESSED end
        end
        return nil
    end
)

--// block RCM
hub.setlistener( "onRevConnectToMe", {},
    function( user, target, adccmd )
        if user:level() < masterlevel then
            if need_block( user ) then return PROCESSED end
            if need_block( target ) then return PROCESSED end
        end
        return nil
    end
)

--// block NAT traversal (DNAT) - the passive / CGNAT C2C fallback.
-- CTM / RCM above only cover the direct-connection setup; when a direct
-- connection is impossible (both peers passive / behind CGNAT) clients
-- fall back to NAT traversal, which would otherwise let a blocked user
-- still establish a file-transfer OR CCPM connection. Mirrors the CTM /
-- RCM logic; need_block tolerates a nil target.
hub.setlistener( "onNatTraversal", {},
    function( user, target, adccmd )
        if user:level() < masterlevel then
            if need_block( user ) then return PROCESSED end
            if need_block( target ) then return PROCESSED end
        end
        return nil
    end
)

--// block NAT traversal reply (DRNT)
hub.setlistener( "onNatTraversalReply", {},
    function( user, target, adccmd )
        if user:level() < masterlevel then
            if need_block( user ) then return PROCESSED end
            if need_block( target ) then return PROCESSED end
        end
        return nil
    end
)

--// block SCH
hub.setlistener( "onSearch", {},
    function( user, adccmd )
        if need_block( user ) then
            user:reply( msg_onsearch, hub.getbot() )
            return PROCESSED
        end
        -- Direct / echo search (DSCH / ESCH) carries an explicit
        -- target SID. The previous code re-sent the message to every
        -- user via a hub.getusers() fan-out, with the target SID
        -- still pointing at the original recipient - so every other
        -- user received a DSCH addressed to someone else, which
        -- AirDC++ surfaces as "SECURITY WARNING: received a DSCH
        -- message that should have been sent to a different user".
        -- Closes upstream luadch/luadch#200.
        --
        -- For D / E we let the hub's default direct-routing path
        -- (core/hub.lua incoming(): targetuser.write(...)) deliver
        -- the message to the single intended recipient. We still
        -- swallow the search if the target is on the block list.
        local cmdtype = adccmd:type( )
        if cmdtype == "D" or cmdtype == "E" then
            local targetsid = adccmd:targetsid( )
            local target = hub.getusers( )[ targetsid ]
            if target and need_block( target ) then
                return PROCESSED    -- swallow, do not forward
            end
            return nil    -- fall through to default hub-side routing
        end
        -- Broadcast (B / F) search: fan out to non-blocked users.
        for sid, target in pairs( hub.getusers() ) do
            if not need_block( target ) then
                target:send( table.concat( adccmd ) )
            end
        end
        return PROCESSED
    end
)

--// block RES (defense-in-depth, #160)
-- The onSearch listener above blocks searches in both directions, so
-- a blocked user normally has no search to reply to. This catches the
-- protocol-violating "unsolicited DRES / FRES" edge case - a malicious
-- or buggy client could send a search-result without a preceding
-- search. For F-class (feature-filtered) results target is nil; per
-- the hub_dispatch.lua plugin contract a truthy return on a FRES path
-- suppresses the entire feature fan-out, which is the right behaviour
-- when the sender is blocked.
hub.setlistener( "onSearchResult", {},
    function( user, target, adccmd )
        if user:level() < masterlevel then
            if need_block( user ) then return PROCESSED end
            if target and need_block( target ) then return PROCESSED end
        end
        return nil
    end
)

--// HTTP API handlers (#82 Phase 4 PR-7).
--
-- Design note: the HTTP handlers deliberately re-implement the
-- block / unblock cascade rather than calling the `add()` /
-- `del()` exports above. The dispatch bug that originally drove
-- this decision was fixed in #257 / #258 (v2.5) and the external
-- path now works correctly - but the duplication remains
-- intentional because the two surfaces have different semantics:
--
-- 1. add()'s external branch appends `"  |  blocked by
--    scriptname: <label>"` to the stored reason (line 610). The
--    HTTP API's spec contract stores the reason verbatim;
--    routing through add() would silently change what API
--    clients see in the `reason` field of GET responses.
--
-- 2. add() / del() return `PROCESSED` or `false, err` with
--    localised err strings (msg_isbot / msg_autoblock /
--    msg_stillblocked). The HTTP path needs clean HTTP status
--    codes (400 / 404 / 409); pre-checking the conditions
--    before calling add() means we still own all the validation
--    logic. Routing through add() and then matching the
--    localised err strings would be locale-fragile.
--
-- 3. The HTTP response envelope `{action, nick, by, reason,
--    online_kicked, removed: {...}}` is built outside add() /
--    del() either way - they only return PROCESSED. The shape
--    construction stays here regardless of who runs the
--    cascade.
--
-- 4. HTTP sanitises `req.token_label` with
--    `util.strip_control_bytes` before any state touches the
--    block_tbl or report frame. add() trusts its inputs - the
--    HTTP path's pre-cascade sanitisation is the correct
--    boundary.
--
-- Net: the ~40 lines of cascade duplication buy a stable
-- spec contract + clean HTTP status mapping. Future external
-- block.add callers (e.g. a hypothetical AbuseIPDB plugin from
-- #79) can use add() directly via hub.import and get the
-- ADC-side cascade semantics.

-- Stringify a single block_tbl entry into the HTTP wire shape.
-- Block-table values come in three legacy variants (boolean,
-- string, or table { by, reason, date_str }); coerce all to the
-- table form on the wire so clients don't need to handle the
-- legacy shapes (matches the ADC `+trafficmanager show blocks`
-- migration logic at lines 882-895).
local _http_format_block_entry = function( nick, v )
    local by, reason, blockdate
    if type( v ) == "table" then
        by        = v[ 1 ] or msg_unknown
        reason    = v[ 2 ] or msg_unknown
        blockdate = v[ 3 ] or msg_unknown
        if blockdate ~= msg_unknown then
            blockdate = tostring( blockdate )
            if #blockdate == 14 then
                blockdate = blockdate:sub( 1, 4 ) .. "-" .. blockdate:sub( 5, 6 ) .. "-" .. blockdate:sub( 7, 8 )
                         .. " / " .. blockdate:sub( 9, 10 ) .. ":" .. blockdate:sub( 11, 12 ) .. ":" .. blockdate:sub( 13, 14 )
            end
        end
    elseif type( v ) == "string" then
        by        = msg_unknown
        reason    = v
        blockdate = msg_unknown
    else  -- boolean / nil / legacy
        by        = msg_unknown
        reason    = msg_unknown
        blockdate = msg_unknown
    end
    return {
        nick         = nick,
        by           = by,
        reason       = reason,
        blocked_at   = blockdate,
    }
end

-- HTTP handler: GET /v1/trafficmanager/settings (#82 Phase 4 PR-7).
-- Read scope. Returns the cfg-driven configuration: which levels
-- are auto-blocked, whether the share-check / minshare-check
-- gates are on, whether the periodic report is enabled.
--
-- The ADC-side `etc_trafficmanager_oplevel` gate does NOT apply
-- on the HTTP path: the bearer token's `read` scope IS the
-- authorisation gate.
local http_handler_settings = function( req )
    local levels = {}
    for k, v in pairs( blocklevel_tbl or {} ) do
        if type( k ) == "number" and k >= 0 and v then
            levels[ #levels + 1 ] = k
        end
    end
    table.sort( levels )
    return { status = 200, data = {
        activate                  = activate and true or false,
        blocked_levels            = levels,
        sharecheck                = sharecheck and true or false,
        minsharecheck             = minsharecheck and true or false,
        report_on_login           = login_report and true or false,
        report_on_timer           = send_loop and true or false,
        report_to_main            = report_main and true or false,
        report_to_pm              = report_pm and true or false,
    } }
end

-- HTTP handler: GET /v1/trafficmanager/blocks (#82 Phase 4 PR-7).
-- Read scope. Returns all manually-blocked nicks (the per-nick
-- override table; the level-based auto-block is configured via
-- the settings endpoint, not listed per-nick because it's a
-- runtime classification on every user).
-- #264 PR-B filter/sort spec for /v1/trafficmanager/blocks.
-- Operates on the formatted entry shape. blocked_at is the
-- "YYYY-MM-DD / HH:MM:SS" string when set, or msg_unknown for
-- legacy entries; lex-compare works for the normalised form.
local _trafficmanager_filter_spec = {
    string_fields = {
        nick   = function( e ) return e.nick   or "" end,
        by     = function( e ) return e.by     or "" end,
        reason = function( e ) return e.reason or "" end,
    },
    date_fields = {
        blocked_at = {
            -- Legacy entries that never persisted a block date carry
            -- the localised `msg_unknown` placeholder (e.g.
            -- "<UNKNOWN>") which would lex-sort below any real date
            -- and falsely match `_before` queries. Return nil for
            -- those so the filter excludes them on both sides.
            get         = function( e )
                local v = e.blocked_at
                if not v or v == "" or v == msg_unknown then return nil end
                return v
            end,
            parse_query = function( q ) return q end,
        },
    },
    sortable_fields = {
        nick       = function( e ) return e.nick       or "" end,
        by         = function( e ) return e.by         or "" end,
        blocked_at = function( e ) return e.blocked_at or "" end,
    },
    default_sort_field      = "nick",
    default_sort_descending = false,
}

local http_handler_list_blocks = function( req )
    local entries = {}
    for nick, v in pairs( block_tbl or {} ) do
        entries[ #entries + 1 ] = _http_format_block_entry( nick, v )
    end
    local ok, rows, code, msg = http_filter.apply(
        req.query or {}, _trafficmanager_filter_spec, entries
    )
    if not ok then
        return { status = rows, error = { code = code, message = msg } }
    end
    local pagination = code
    local wire = dkjson.encode( {
        ok         = true,
        data       = { entries = rows },
        pagination = pagination,
    } )
    return { status = 200, raw_body = wire,
        content_type = "application/json; charset=utf-8" }
end

-- HTTP handler: POST /v1/trafficmanager/blocks/{nick} (#82 Phase 4 PR-7).
-- Admin scope. Body `{reason?: string (max 256, control-byte
-- sanitised)}`; absent / empty reason stored as msg_unknown.
--
-- Target identified by firstnick (the stable registered
-- identifier). The handler is offline-tolerant - offline registered
-- nicks can be pre-blocked so the next reconnect immediately hits
-- the onConnect description-flag + UDP4-strip cascade.
--
-- Returns **409 E_CONFLICT** if the nick is already in block_tbl
-- (operator must DELETE first to change reason; mode-change in
-- place not supported, matching the ADC `msg_stillblocked`
-- semantic).
--
-- Cascade on success: block_tbl += entry; persist; if target
-- online, send target msg + description-flag update via setnp +
-- sendtoall BINF; opchat report.send fires once.
--
-- The ADC-side level-ladder permission check (operator's
-- permission >= target_level) does NOT apply on the HTTP path:
-- the bearer token's `admin` scope IS the authorisation gate.
-- The autoblock check (target level in blocklevel_tbl or shares
-- below threshold) DOES still apply - blocking an auto-blocked
-- user is redundant and matches the ADC `msg_autoblock` reject.
local http_handler_block_user = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )
    local body = req.body or {}
    local reason = body.reason
    if type( reason ) == "string" then
        reason = util.strip_control_bytes( reason )
        if reason == "" then reason = nil end
    else
        reason = nil
    end
    if reason and #reason > 256 then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "reason must be at most 256 characters" } }
    end
    reason = reason or msg_unknown

    -- Resolve target (online optional - the block stores by
    -- firstnick).
    local target = hub.isnickonline( nick )
    if not target then target = find_online_by_firstnick( nick ) end
    local target_firstnick = nick
    if target then target_firstnick = target:firstnick() end

    if target and target:isbot() then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "target is a bot" } }
    end

    -- Get target_level for autoblock check (offline-tolerant
    -- via getregusers).
    local target_level = 0
    local _, reggednicks, _ = hub.getregusers()
    local profile = reggednicks[ target_firstnick ]
    if profile then target_level = profile.level end

    if is_autoblocked( target, target_level ) then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "target is auto-blocked by script permissions" } }
    end

    if is_blocked( target_firstnick ) then
        return { status = 409, error = { code = "E_CONFLICT",
            message = "nick '" .. target_firstnick .. "' is already blocked" } }
    end

    local by = util.strip_control_bytes( req.token_label or "http-api" )
    if by == "" then by = "http-api" end

    block_tbl[ target_firstnick ] = {
        [ 1 ] = by,
        [ 2 ] = reason,
        [ 3 ] = util.date(),
    }
    util.savetable( block_tbl, "block_tbl", block_file )

    -- opchat report
    local target_nick = target_firstnick
    if nick_prefix_activate and nick_prefix_permission[ target_level ] then
        local prefix = hub.escapeto( nick_prefix_prefix_table[ target_level ] or "" )
        target_nick = prefix .. target_firstnick
    end
    local target_ip = ( target and target:ip() ) or msg_unknown
    local msg_report = utf.format( msg_op_report_block, by, target_nick, target_ip, reason )
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )

    -- If target online: notify + add description flag + broadcast INF
    if target then
        local msg_target = utf.format( msg_target_block, by, reason )
        target:reply( msg_target, hub.getbot(), hub.getbot() )
        for sid, buser in pairs( hub.getusers() ) do
            if buser:firstnick() == target_firstnick then
                local new_desc = format_description( flag_blocked, "onStart", buser, nil )
                buser:inf():setnp( "DE", new_desc )
                hub.sendtoall( "BINF " .. sid .. " DE" .. new_desc .. "\n" )
                break
            end
        end
    end

    return { status = 200, data = {
        action       = "blocked",
        nick         = target_firstnick,
        by           = by,
        reason       = reason,
        online_kicked = false,  -- traffic block does not kick; it filters CTM/RCM/SCH
    } }
end

-- HTTP handler: DELETE /v1/trafficmanager/blocks/{nick}
-- (#82 Phase 4 PR-7). Admin scope. Offline-tolerant.
--
-- Returns **404 E_NOT_FOUND** if the nick is not in block_tbl
-- (idempotent 200 would mask typos).
--
-- Cascade on success: block_tbl -= entry; persist; if target
-- online, remove description flag + broadcast INF + notify;
-- opchat report.send fires once.
local http_handler_unblock_user = function( req )
    local nick_raw = req.path_vars and req.path_vars.nick
    if not nick_raw or nick_raw == "" then
        return { status = 400, error = { code = "E_BAD_INPUT",
            message = "missing {nick} path variable" } }
    end
    local nick = util.strip_control_bytes( nick_raw )

    local target = hub.isnickonline( nick )
    if not target then target = find_online_by_firstnick( nick ) end
    local target_firstnick = nick
    if target then target_firstnick = target:firstnick() end

    if not is_blocked( target_firstnick ) then
        return { status = 404, error = { code = "E_NOT_FOUND",
            message = "nick '" .. target_firstnick .. "' is not blocked" } }
    end

    local previous = block_tbl[ target_firstnick ]

    local by = util.strip_control_bytes( req.token_label or "http-api" )
    if by == "" then by = "http-api" end

    local target_level = 0
    local _, reggednicks, _ = hub.getregusers()
    local profile = reggednicks[ target_firstnick ]
    if profile then target_level = profile.level end

    local target_nick = target_firstnick
    if nick_prefix_activate and nick_prefix_permission[ target_level ] then
        local prefix = hub.escapeto( nick_prefix_prefix_table[ target_level ] or "" )
        target_nick = prefix .. target_firstnick
    end

    -- Compute new_desc BEFORE the block_tbl mutation + savetable
    -- (matches ADC `del()` ordering at lines 723-737). If
    -- `utf.sub` on an adversarial description raises, the on-disk
    -- + in-memory block_tbl stays intact - operator can retry.
    -- Inverting this order (clearing first) would leave the
    -- target wearing the [BLOCKED] description flag forever
    -- after a mid-handler crash.
    local new_desc
    if target then
        if desc_prefix_activate and desc_prefix_permission[ target_level ] then
            local prefix = hub.escapeto( flag_blocked )
            local desc_tag = hub.escapeto( desc_prefix_table[ target_level ] or "" )
            local desc = utf.sub( target:description() or "", utf.len( desc_tag ) + 1, -1 )
            desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
            new_desc = desc_tag .. desc
        else
            local prefix = hub.escapeto( flag_blocked )
            local desc = target:description() or ""
            new_desc = utf.sub( desc, utf.len( prefix ) + 1, -1 )
        end
    end

    block_tbl[ target_firstnick ] = nil
    util.savetable( block_tbl, "block_tbl", block_file )

    local target_ip = ( target and target:ip() ) or msg_unknown
    local msg_report = utf.format( msg_op_report_unblock, by, target_nick, target_ip )
    report.send( report_activate, report_hubbot, report_opchat, llevel, msg_report )

    if target then
        local msg_target = utf.format( msg_target_unblock, by )
        target:reply( msg_target, hub.getbot(), hub.getbot() )
        target:inf():setnp( "DE", new_desc or "" )
        hub.sendtoall( "BINF " .. target:sid() .. " DE" .. ( new_desc or "" ) .. "\n" )
    end

    local prev_reason, prev_by, prev_date
    if type( previous ) == "table" then
        prev_by     = previous[ 1 ] or msg_unknown
        prev_reason = previous[ 2 ] or msg_unknown
        prev_date   = previous[ 3 ] or msg_unknown
    else
        prev_by     = msg_unknown
        prev_reason = msg_unknown
        prev_date   = msg_unknown
    end

    return { status = 200, data = {
        action  = "unblocked",
        nick    = target_firstnick,
        by      = by,
        removed = {
            by         = prev_by,
            reason     = prev_reason,
            blocked_at = prev_date,
        },
    } }
end

--// script start
hub.setlistener( "onStart", {},
    function()
        --// help, ucmd, hucmd
        local help = hub.import( "cmd_help" )
        if help then
            help.reg( help_title, help_usage, help_desc, oplevel )
            help.reg( help_title2, help_usage2, help_desc2, masterlevel )
        end
        local ucmd = hub.import( "etc_usercommands" )
        if ucmd then
            -- CT1 (hub)
            ucmd.add( ucmd_menu_ct1_1, cmd, { cmd_s, "settings" }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct1_2, cmd, { cmd_s, "blocks" }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct1_3, cmd, { cmd_b, "%[line:" .. ucmd_nick .. "]", "%[line:" .. ucmd_desc .. "]" }, { "CT1" }, oplevel )
            ucmd.add( ucmd_menu_ct1_4, cmd, { cmd_u, "%[line:" .. ucmd_nick .. "]" }, { "CT1" }, oplevel )
            -- CT2 (userlist)
            ucmd.add( ucmd_menu_ct2_1, cmd, { cmd_b, "%[userNI]", "%[line:" .. ucmd_desc .. "]" }, { "CT2" }, masterlevel )
            ucmd.add( ucmd_menu_ct2_3, cmd, { cmd_u, "%[userNI]" }, { "CT2" }, masterlevel )
        end
        local hubcmd = hub.import( "etc_hubcommands" )
        assert( hubcmd )
        assert( hubcmd.add( cmd, onbmsg, oplevel ) )

        for sid, user in pairs( hub.getusers() ) do
            if need_block( user ) then
                --// add description flag
                local new_desc = format_description( flag_blocked, "onStart", user, nil )
                user:inf():setnp( "DE", new_desc )
                hub.sendtoall( "BINF " .. sid .. " DE" .. new_desc .. "\n" )
                --// delete "U4"
                user:inf():deletenp( "U4" )
                --// remove "UDP4"
                connect_listener( user )
            end
        end
        -- HTTP API endpoints (#82 Phase 4 PR-7). Only registered
        -- when the plugin is `activate=true` (early-return at top
        -- of file short-circuits the entire module otherwise).
        if hub.http_register then
            hub.http_register( "GET", "/v1/trafficmanager/settings", "read", http_handler_settings, {
                plugin = scriptname,
                description = "trafficmanager cfg snapshot (= ADC `+trafficmanager show settings`)",
                response_schema = {
                    activate         = { type = "boolean", required = true },
                    blocked_levels   = { type = "array",   required = true },
                    sharecheck       = { type = "boolean", required = true },
                    minsharecheck    = { type = "boolean", required = true },
                    report_on_login  = { type = "boolean", required = true },
                    report_on_timer  = { type = "boolean", required = true },
                    report_to_main   = { type = "boolean", required = true },
                    report_to_pm     = { type = "boolean", required = true },
                },
            } )
            hub.http_register( "GET", "/v1/trafficmanager/blocks", "read", http_handler_list_blocks, {
                plugin = scriptname,
                description = "manually-blocked nicks (= ADC `+trafficmanager show blocks`)",
                response_schema = {
                    entries = { type = "array", required = true },
                },
            } )
            hub.http_register( "POST", "/v1/trafficmanager/blocks/{nick}", "admin", http_handler_block_user, {
                plugin = scriptname,
                description = "block a nick from CTM/RCM/SCH (= ADC `+trafficmanager block`); body `{reason?}`",
                response_schema = {
                    action        = { type = "string",  required = true },
                    nick          = { type = "string",  required = true },
                    by            = { type = "string",  required = true },
                    reason        = { type = "string",  required = true },
                    online_kicked = { type = "boolean", required = true },
                },
            } )
            hub.http_register( "DELETE", "/v1/trafficmanager/blocks/{nick}", "admin", http_handler_unblock_user, {
                plugin = scriptname,
                description = "lift a trafficmanager block (= ADC `+trafficmanager unblock`); offline-tolerant",
                response_schema = {
                    action  = { type = "string", required = true },
                    nick    = { type = "string", required = true },
                    by      = { type = "string", required = true },
                    removed = { type = "object", required = true },
                },
            } )
        end
        return nil
    end
)

--// script exit
hub.setlistener( "onExit", {},
    function()
        for sid, user in pairs( hub.getusers() ) do
            if need_block( user ) then
                --// remove description flag
                local new_desc = format_description( flag_blocked, "onExit", user, nil )
                user:inf():setnp( "DE", new_desc or "" )
                hub.sendtoall( "BINF " .. sid .. " DE" .. new_desc .. "\n" )
                --// delete "U4"
                user:inf():deletenp( "U4" )
            end
        end
        return nil
    end
)

--// incoming INF
hub.setlistener( "onInf", {},
    function( user, cmd )
        local desc = cmd:getnp "DE"
        if desc then
            if need_block( user ) then
                --// add/update description flag
                local new_desc = format_description( flag_blocked, "onInf", user, cmd )
                cmd:setnp( "DE", new_desc )
                user:inf():setnp( "DE", new_desc )
                --// delete "U4"
                cmd:deletenp( "U4" )
                user:inf():deletenp( "U4" )
                --// remove "UDP4"
                inf_listener( user, cmd )
            end
        end
        return nil
    end
)

--// user connects to hub
hub.setlistener( "onConnect", {},
    function( user )
        if need_block( user ) then
            --// add description flag
            local new_desc = format_description( flag_blocked, "onConnect", user, nil )
            user:inf():setnp( "DE", new_desc )
            --// delete "U4"
            user:inf():deletenp( "U4" )
            --// remove "UDP4"
            connect_listener( user )
        end
        return nil
    end
)

--// send user report on timer
hub.setlistener( "onTimer", { },
    function()
        if os.time() - start >= delay then
            send_user_report()
            start = os.time()
        end
        return nil
    end
)

--// keep a manual block attached to its user across a nick rename.
-- block_tbl is keyed by firstnick; +nickchange (and the HTTP rename)
-- renames the user in user.tbl but not here, so without this the block
-- was silently lost on rename (reported by Sopor). audit.fire is
-- unconditional (core/audit.lua), so one onAudit tap catches every
-- reg.nickchange - the ADC self / othernick / othernicku paths AND the
-- HTTP API. Returns nil (never PROCESSED) so the etc_auditlog /
-- http_events onAudit taps still receive the event.
hub.setlistener( "onAudit", {},
    function( event )
        if type( event ) ~= "table" or event.action ~= "reg.nickchange" then return nil end
        local new_nick = event.target and event.target.nick
        local old_nick = event.meta and event.meta.previous_nick
        if type( old_nick ) ~= "string" or type( new_nick ) ~= "string" then return nil end
        if old_nick == new_nick or block_tbl[ old_nick ] == nil then return nil end
        -- If a stale entry already sits under the new nick, the renamed
        -- user's own block wins - overwrite keeps it intact.
        block_tbl[ new_nick ] = block_tbl[ old_nick ]
        block_tbl[ old_nick ] = nil
        util.savetable( block_tbl, "block_tbl", block_file )
        return nil
    end
)

hub.debug( "** Loaded " .. scriptname .. " " .. scriptversion .. " **" )

--// public //--

return {    -- export

    add = add,  -- use: block = hub.import( "etc_trafficmanager" ); block.add( target_firstnick [ ,scriptname, reason ] )  -- to block a user; return "true, nil" or "false, err"
    del = del,  -- use: block = hub.import( "etc_trafficmanager" ); block.del( target_firstnick [ ,scriptname ] )  -- to unblock a user; return "true, nil" or "false, err"

}