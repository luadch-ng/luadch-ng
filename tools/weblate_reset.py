#!/usr/bin/env python3
"""Reset the Weblate repository to its upstream branch once it is fully in sync.

Every translation is a separate commit on Weblate's own git branch; the funnel
(tools/weblate_funnel.py + .github/workflows/weblate-funnel.yml) brings only a
filtered/squashed version of those to `dev`. So Weblate's branch is permanently
ahead of `dev` and that divergence never self-clears - it grows until Weblate
can no longer merge the next `dev` change ("Could not merge the repository" ->
the component auto-locks and translators are blocked). The cure is to reset
Weblate's git to `dev` whenever `dev` already contains everything Weblate has,
which is exactly the state right after a funnel PR merges.

A reset is destructive (`git reset --hard origin/dev`: it discards Weblate's
local commits AND its uncommitted DB units), so it runs ONLY when Weblate holds
nothing `dev` lacks. Weblate content lives in three states, and a reset is
refused if ANY of them still has work `dev` has not seen:

  - uncommitted DB units          -> repository status `needs_commit`
  - committed but NOT yet pushed  -> repository status `needs_push`
  - committed, pushed, unfunneled -> tools/weblate_funnel.py would still import
                                     (FUNNEL_CHANGED=1 against origin/weblate)

The `needs_push` case matters most: the merge-failure state this tool targets is
one where Weblate typically cannot push either, so committed-but-unpushed
translations are the expected condition - resetting then would discard them.

For a real run the component is LOCKED first, then all three checks run under
the lock (a fresh origin/weblate fetch + status read), so nothing can land in
the gap between the check and the reset. Every check is fail-closed: if it
cannot be evaluated, the reset is skipped. A skipped reset is a normal outcome -
the divergence clears on the next cycle once the work is funneled.

Dry run by default: reports the decision and the repository status, locks
nothing, resets nothing. Set APPLY=1 to actually lock / reset / unlock. Must run
from a checkout of the target branch (`dev`) so the funnel check can compare.

Environment (same conventions as tools/weblate_apply_settings.py):
  WEBLATE_URL        base URL, e.g. https://translate.dcvault.net   (required)
  WEBLATE_API_TOKEN  a Weblate API token (Settings -> API access)   (required)
  WEBLATE_PROJECT    project slug                    (default: luadch-ng)
  WEBLATE_COMPONENT  the repo-owning component slug  (default: core-hub)
  APPLY=1            actually lock / reset / unlock (otherwise dry run)

Exit code 0 = handled (reset done, or a legitimate skip), 1 = an API/git error.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

URL = os.environ.get("WEBLATE_URL", "").rstrip("/")
TOKEN = os.environ.get("WEBLATE_API_TOKEN", "")
PROJECT = os.environ.get("WEBLATE_PROJECT") or "luadch-ng"
# The repo-owning component. Its 70 linked plugin components share this VCS
# checkout, so resetting it resets them all; the separate `glossary` component
# has its own repo and is not touched here.
COMPONENT = os.environ.get("WEBLATE_COMPONENT") or "core-hub"
APPLY = os.environ.get("APPLY", "") not in ("", "0", "false", "False")

if not URL or not TOKEN:
    sys.exit("error: WEBLATE_URL and WEBLATE_API_TOKEN must be set")

REPO = f"{URL}/api/components/{PROJECT}/{COMPONENT}/repository/"
LOCK = f"{URL}/api/components/{PROJECT}/{COMPONENT}/lock/"

HERE = os.path.dirname(os.path.abspath(__file__))
FUNNEL = os.path.join(HERE, "weblate_funnel.py")

# A browser-like User-Agent - urllib's default is served the Cloudflare
# "Just a moment..." challenge on translate.dcvault.net (see
# tools/weblate_apply_settings.py for the same treatment).
USER_AGENT = os.environ.get(
    "WEBLATE_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
)


def short(resp):
    """One-line summary of a response body so an error is diagnosable, not a
    50k-char dump. Only the actual Cloudflare interstitial ("Just a moment...")
    is a challenge; the `challenge-platform` script Cloudflare injects into
    NORMAL pages (incl. 404s) is NOT one - do not flag on that alone, or a plain
    404 gets misread as a Cloudflare block."""
    s = resp if isinstance(resp, str) else json.dumps(resp)
    low = s.lower()
    if "just a moment" in low or "attention required" in low:
        return ("Cloudflare challenge page - this request was actually challenged "
                "by Cloudflare (not just proxied)")
    if "<!doctype html" in low or "<html" in low:
        return "HTML page (not JSON): " + " ".join(s.split())[:200]
    return " ".join(s.split())[:300]


def api(method, url, data=None):
    """Return (status_code, parsed_or_text). JSON body when data is given."""
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token {TOKEN}")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    req.add_header("Accept-Encoding", "identity")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, str(e)


def repo_status():
    status, body = api("GET", REPO)
    if status != 200 or not isinstance(body, dict):
        sys.exit(f"error: repository status failed ({status}): {short(body)}")
    return body


def fmt(st):
    return (f"needs_commit={st.get('needs_commit')} "
            f"needs_merge={st.get('needs_merge')} "
            f"needs_push={st.get('needs_push')} "
            f"merge_failure={st.get('merge_failure')!r}")


def set_lock(locked):
    status, body = api("POST", LOCK, {"lock": locked})
    if status not in (200, 201):
        sys.exit(f"error: {'lock' if locked else 'unlock'} failed ({status}): {short(body)}")


def reset_repo():
    status, body = api("POST", REPO, {"operation": "reset"})
    if status not in (200, 201):
        # Raise, not sys.exit: the caller holds the lock and must unlock first.
        raise RuntimeError(f"reset failed ({status}): {short(body)}")


def funnel_would_change():
    """True if the funnel would still import translations from origin/weblate
    into the dev checkout (Weblate has pushed content dev lacks). Fetches
    origin/weblate first so the comparison is current. Fail-closed: any error
    (missing git, unreadable ref, funnel breakage) raises, so the caller treats
    an un-evaluable check as unsafe and skips the reset."""
    fetch = subprocess.run(
        ["git", "fetch", "origin", "weblate:refs/remotes/origin/weblate"],
        capture_output=True, text=True,
    )
    if fetch.returncode != 0:
        raise RuntimeError(f"git fetch weblate failed: {fetch.stderr.strip() or fetch.stdout.strip()}")
    run = subprocess.run(
        [sys.executable, FUNNEL], capture_output=True, text=True,
    )
    if run.returncode != 0:
        raise RuntimeError(f"funnel check failed: {short(run.stdout + run.stderr)}")
    # weblate_funnel.py prints a machine line `FUNNEL_CHANGED=<0|1>`.
    return "FUNNEL_CHANGED=1" in run.stdout


def unsafe_reason(st):
    """Reason a reset would lose work right now, or None if safe. For a real run
    this must be evaluated with the component LOCKED so the snapshot is stable."""
    if st.get("needs_commit"):
        return "pending uncommitted units (needs_commit)"
    if st.get("needs_push"):
        return "committed but unpushed local commits (needs_push)"
    try:
        if funnel_would_change():
            return "funnel would still import translations (committed, pushed, unfunneled)"
    except RuntimeError as e:
        return f"funnel check could not be evaluated - {e}"
    return None


def main():
    print(f"component: {PROJECT}/{COMPONENT}   "
          f"mode: {'APPLY' if APPLY else 'DRY RUN (set APPLY=1 to act)'}")

    if not APPLY:
        st = repo_status()
        print(f"status: {fmt(st)}")
        reason = unsafe_reason(st)   # not locked -> a preview, may race; no action taken
        print(f"DRY RUN: would {'SKIP - ' + reason if reason else 'RESET'}.")
        return 0

    # Lock first so nothing lands between the checks and the reset, then evaluate
    # all three guards under the lock.
    set_lock(True)
    try:
        st = repo_status()
        print(f"before: {fmt(st)}")
        reason = unsafe_reason(st)
        if reason:
            print(f"::notice::skipping reset - {reason} "
                  f"(safe; the divergence clears on the next cycle once funneled).")
            return 0
        reset_repo()
        try:
            print(f"after:  {fmt(repo_status())}")
        except SystemExit:
            # A status read that fails AFTER a successful reset is not an error
            # worth failing the run over - the reset already happened.
            print("after:  (post-reset status read failed; reset itself succeeded)")
        print("::notice::Weblate repository reset to upstream and unlocked.")
    finally:
        set_lock(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
