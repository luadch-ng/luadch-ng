#!/usr/bin/env python3
"""
luadch smoke-test harness.

Starts a freshly-installed luadch hub on test ports, runs a small set of
protocol-level checks (plain ADC handshake, TLS ADC handshake, log scan
for plugin errors), and tears it down. Exits 0 on all-pass, non-zero on
any failure.

Usage:
    python3 tests/smoke/run.py <path-to-built-install-tree>

The argument is the directory that "cmake --install build" produced,
typically build/install/luadch. The harness copies it to a temp dir,
overrides ports to avoid collisions with a real hub on the same host,
and runs everything from there. The original install tree is untouched.

Exit codes:
    0   all tests passed
    1   one or more tests failed
    2   harness error (could not start hub, etc.)
"""

import argparse
import base64
import contextlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

# Vendored pure-Python Tiger-192 hash. Used to compute CIDs (Tiger(PID)) and
# password challenge responses (Tiger(password || salt)) for the login flow
# tests below. Self-tests on import; if it ever breaks the harness fails fast.
sys.path.insert(0, str(Path(__file__).parent))
import tiger as _tiger


# Test ports, deliberately offset from the upstream defaults (5000-5003)
# so a developer running the suite locally does not collide with their
# real hub. CI is isolated so the offset does not matter there.
TEST_PORT_PLAIN = 15500
TEST_PORT_TLS = 15501
TEST_PORT_PLAIN_V6 = 15502
TEST_PORT_TLS_V6 = 15503
TEST_PORT_HTTP = 15510    # Phase 8 S3: local HTTP API listener (#82)
TEST_PORT_REGSERVER = 15520    # fake regserver for etc_regserver_announce end-to-end test

# Second HTTP API token (read scope) injected alongside the
# bootstrap admin token by `_switch_to_http_active_mode`. Used by
# `test_http_auth_scope_matrix` (#275 COV-1) and other tests that
# need to exercise the read-vs-admin scope gate. The hub does not
# validate token format (any non-empty string works), so a fixed
# memorable literal is fine; collision with the random bootstrap
# token is astronomically unlikely.
SMOKE_READ_TOKEN = "smokereadXX12345678901234567890ABCDEFGH4242kthxbai9"

HUB_HOST = "127.0.0.1"

# How long to wait for the hub to bind ports / shut down.
START_TIMEOUT_SEC = 20
STOP_TIMEOUT_SEC = 10
PROTOCOL_TIMEOUT_SEC = 5
# How long to wait for a rejected second instance to exit. The launcher
# guard fires before Lua/socket init so it exits near-instantly; the
# slack is for slow CI. A timeout here means the guard did NOT fire.
SINGLE_INSTANCE_TIMEOUT_SEC = 15
# How long to wait for a second hub (ports already held) to log the clear
# port-in-use message. The bind attempt happens during boot; slack is for
# a slow runner + cert auto-gen preceding the listener setup.
PORT_IN_USE_TIMEOUT_SEC = 25


class TestFailure(Exception):
    """Raised by individual tests on assertion failure."""


def log(msg):
    print(f"[smoke] {msg}", flush=True)


# -----------------------------------------------------------------------------
# Setup / teardown
# -----------------------------------------------------------------------------

def stage_install(source_install_dir: Path) -> Path:
    """
    Copy the install tree into a fresh temp dir so the test mutates a
    disposable copy (cfg.tbl rewrites, generated certs, log files).
    """
    staging = Path(tempfile.mkdtemp(prefix="luadch-smoke-"))
    log(f"staging install tree at {staging}")
    shutil.copytree(source_install_dir, staging / "luadch")
    return staging / "luadch"


def override_test_ports(staging_dir: Path):
    """
    Rewrite the four port arrays in cfg.tbl to our test values. Done as a
    targeted regex on the four canonical lines so we do not touch
    surrounding cfg structure or comments.
    """
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    rewrites = [
        (r"tcp_ports\s*=\s*\{[^}]*\}", f"tcp_ports = {{ {TEST_PORT_PLAIN} }}"),
        (r"ssl_ports\s*=\s*\{[^}]*\}", f"ssl_ports = {{ {TEST_PORT_TLS} }}"),
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}", f"tcp_ports_ipv6 = {{ {TEST_PORT_PLAIN_V6} }}"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}", f"ssl_ports_ipv6 = {{ {TEST_PORT_TLS_V6} }}"),
        # Flip the #214 HBRI knobs on so the dual-stack validation smoke
        # tests have an HBRI-active hub. HBRI is opt-in PER CLIENT (only
        # clients advertising ADHBRI in HSUP ever trigger it), so every
        # other smoke test is unaffected. The advertise addresses are the
        # loopback addresses the test listeners already bind; the
        # side-channel port the hub derives is the first plain port per
        # family (TEST_PORT_PLAIN_V6 for v6).
        (r"hbri_enabled\s*=\s*false", "hbri_enabled = true"),
        (r'hbri_advertise_v4\s*=\s*""', f'hbri_advertise_v4 = "{HUB_HOST}"'),
        (r'hbri_advertise_v6\s*=\s*""', 'hbri_advertise_v6 = "::1"'),
        # Enable event-log writes so tests can assert on parser / dispatcher
        # log traces (e.g. #265 regression test scans event.log for the
        # 'invalid named parameter' line emitted on `nowhitespace` reject).
        (r"log_events\s*=\s*false", "log_events = true"),
        # #78 Phase D2: turn etc_geoip ON (ships OFF) with NO database
        # present in the staging tree. This exercises the plugin's
        # real-sandbox load path + graceful missing-DB handling on every
        # smoke boot: a sandbox-undeclared-global or a load-time crash
        # would surface as a script error (caught by test_no_script_errors)
        # or prevent the hub from binding its ports. onConnect stays inert
        # without a DB, so no other test is affected.
        (r'\{\s*"etc_geoip\.lua",\s*enabled\s*=\s*false\s*\}',
         '{ "etc_geoip.lua", enabled = true }'),
        (r"etc_geoip_enabled\s*=\s*false", "etc_geoip_enabled = true"),
        # #78 Phase E: turn etc_blocklist_feeds ON (ships OFF) with NO feed
        # enabled - exercises the plugin's real-sandbox load path + onStart
        # command registration on every smoke boot WITHOUT any outbound
        # network (no feed is scheduled). A sandbox-undeclared-global or a
        # load-time crash surfaces via test_no_script_errors.
        (r'\{\s*"etc_blocklist_feeds\.lua",\s*enabled\s*=\s*false\s*\}',
         '{ "etc_blocklist_feeds.lua", enabled = true }'),
        (r"etc_blocklist_feeds_enabled\s*=\s*false", "etc_blocklist_feeds_enabled = true"),
        # #78 Phase F: turn etc_proxydetect ON (ships OFF). Keep the real
        # default provider (proxycheck) so the real-sandbox load + onStart
        # command registration run on every smoke boot, but EMPTY
        # check_levels so onConnect never fires an outbound provider query -
        # no network dependency in CI. A sandbox-undeclared-global or a
        # load-time crash surfaces via test_no_script_errors.
        (r'\{\s*"etc_proxydetect\.lua",\s*enabled\s*=\s*false\s*\}',
         '{ "etc_proxydetect.lua", enabled = true }'),
        (r"etc_proxydetect_enabled\s*=\s*false", "etc_proxydetect_enabled = true"),
        (r"etc_proxydetect_check_levels = \{[^}]*\}", "etc_proxydetect_check_levels = { }"),
        # #480: etc_backup ships ENABLED but is inert (nags, never runs)
        # until a passphrase is set. Set one so test_backup_now can drive a
        # real +backup now and assert a sealed artifact lands on disk. The
        # daily_at schedule stays at 04:00, so no scheduled backup fires
        # during the run; only the explicit +backup now does.
        (r'etc_backup_passphrase\s*=\s*""', 'etc_backup_passphrase = "smoke-backup-pass"'),
    ]
    for pattern, replacement in rewrites:
        new_text, count = re.subn(pattern, replacement, text, count=1)
        if count != 1:
            raise RuntimeError(f"could not rewrite cfg.tbl pattern: {pattern}")
        text = new_text

    cfg_path.write_text(text, encoding="utf-8")
    log(f"rewrote ports: plain={TEST_PORT_PLAIN}, tls={TEST_PORT_TLS}, "
        f"plain_v6={TEST_PORT_PLAIN_V6}, tls_v6={TEST_PORT_TLS_V6}")


def seed_dummy_botflag(staging_dir: Path):
    """#571 regression setup: add the `show_as_bot` profile flag to the
    default `dummy` account in the staged cfg/user.tbl, so
    test_botflag_ct_bit can assert the ADC CT bot bit (1) is OR-ed into
    dummy's level-derived CT (16 -> 17) at login.

    This also exercises the _regex.reguser schema add in core/hub.lua: if
    `show_as_bot` is not a known reguser key, updateusers() rejects the
    unknown key at boot and wipes user.tbl ("corrupt database, creating new
    one") - dummy then no longer exists and every dummy login (this test
    plus the login battery) fails. That is the fail-pre-fix signal for the
    schema line the #571 issue calls out as the single most important
    change to guard. Nothing reads CT for authorization, so flagging dummy
    changes only its icon bit - no other smoke test asserts CT.

    NOTE for future test authors: dummy now carries the CT bot bit (17, not
    16) for the ENTIRE shared-hub run. A new smoke test that asserts dummy's
    exact CT must account for this seed (or run against its own staged tree,
    which is not seeded)."""
    user_tbl = staging_dir / "cfg" / "user.tbl"
    text = user_tbl.read_text(encoding="utf-8")
    new_text, count = re.subn(r'(nick = "dummy",)', r"\1 show_as_bot = 1,",
                              text, count=1)
    if count != 1:
        raise RuntimeError("could not seed show_as_bot on the dummy account in user.tbl")
    user_tbl.write_text(new_text, encoding="utf-8")
    log("seeded show_as_bot=1 on the dummy account (#571)")


def start_hub(staging_dir: Path):
    """
    Launch luadch from a CWD outside the staging tree. The hub anchors
    its own runtime paths to the binary's directory at startup
    (issue #12 / Phase 6b), so it must work regardless of the caller's
    CWD. Picking a foreign CWD here turns the smoke run into a positive
    proof of that anchoring; before #12 was fixed the hub would bail
    out looking for ./core/init.lua relative to the harness's CWD.
    """
    binary = staging_dir / ("Luadch.exe" if sys.platform == "win32" else "luadch")
    if not binary.exists():
        raise RuntimeError(f"hub binary not found at {binary}")

    foreign_cwd = staging_dir.parent  # the temp dir the staging lives inside
    log_file = open(staging_dir / "log" / "smoke-hub.log", "wb")
    log(f"starting {binary} (cwd={foreign_cwd})")
    proc = subprocess.Popen(
        [str(binary)],
        cwd=str(foreign_cwd),
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return proc, log_file


def wait_for_port(host: str, port: int, timeout: float):
    """Poll TCP connect until success or timeout."""
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    raise TimeoutError(f"port {host}:{port} did not open within {timeout}s; last error: {last_err}")


def wait_for_file(path: Path, timeout: float):
    """Poll filesystem until `path` exists, or timeout.

    Used by mode-switch helpers that flip the hub into a state where
    the hub itself emits a sentinel file as part of boot (e.g.
    `cfg/api_token.first` when `http_port` is set + `http_api_tokens`
    is empty - the #231 first-boot bootstrap). On Windows MinGW the
    ADC port can bind before the HTTP-side bootstrap finishes
    writing the sample-token file, so a setup that only does
    `wait_for_port(ADC)` and then asserts the file is present races
    on a slow runner. Symmetric with wait_for_port: setup ensures
    the precondition; the test asserts behaviour."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"file {path} did not appear within {timeout}s")


def stop_hub(proc, log_file):
    if proc.poll() is None:
        log("stopping hub")
        proc.terminate()
        try:
            proc.wait(timeout=STOP_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            log("hub did not exit cleanly, killing")
            proc.kill()
            proc.wait(timeout=STOP_TIMEOUT_SEC)
    log_file.close()


# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

def test_hub_binds_ports():
    """The hub bound both plain and TLS ports within the start timeout."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    wait_for_port(HUB_HOST, TEST_PORT_TLS, START_TIMEOUT_SEC)


def adc_handshake(sock):
    """
    Send the canonical client SUP and read until we see ISUP, ISID and
    IINF in the response stream. ADC frames are newline-terminated.
    """
    sock.settimeout(PROTOCOL_TIMEOUT_SEC)
    sock.sendall(b"HSUP ADBASE ADTIGR\n")

    seen = {"ISUP": False, "ISID": False, "IINF": False}
    buffer = b""
    deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC

    while time.monotonic() < deadline and not all(seen.values()):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
        while b"\n" in buffer:
            line, _, buffer = buffer.partition(b"\n")
            for fourcc in seen:
                if line.startswith(fourcc.encode()):
                    seen[fourcc] = True

    missing = [k for k, v in seen.items() if not v]
    if missing:
        raise TestFailure(f"handshake response missing frames: {missing}")


def test_plain_handshake():
    """Plain ADC: send HSUP, expect ISUP/ISID/IINF."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        adc_handshake(sock)


def test_tls_handshake():
    """TLS ADC: same as plain but wrapped in TLS. Hub uses a self-signed cert."""
    ctx = ssl.create_default_context()
    # Self-signed test cert; we are not validating identity in the smoke
    # test, only that the TLS handshake completes and ADC frames flow.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pin TLS 1.2 minimum (closes CodeQL py/insecure-protocol). The
    # default context still admits TLSv1 / TLSv1.1 negotiation paths
    # we never want even in test code.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.create_connection((HUB_HOST, TEST_PORT_TLS), timeout=PROTOCOL_TIMEOUT_SEC) as raw:
        with ctx.wrap_socket(raw, server_hostname=HUB_HOST) as sock:
            adc_handshake(sock)


# -----------------------------------------------------------------------------
# ADC protocol helpers (used by the login flow tests below)
# -----------------------------------------------------------------------------

def _b32_encode(data: bytes) -> str:
    """ADC base32: standard RFC 4648 alphabet, no padding."""
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _b32_decode(s: str) -> bytes:
    """ADC base32 decode: re-pad to a multiple of 8, then standard b32decode."""
    return base64.b32decode(s + "=" * (-len(s) % 8))


def _adc_escape(s: str) -> str:
    """Escape spaces, newlines and backslashes for an ADC named-parameter value."""
    return s.replace("\\", "\\\\").replace(" ", "\\s").replace("\n", "\\n")


class _ADCReader:
    """Buffered reader that yields complete newline-terminated ADC frames."""

    def __init__(self, sock):
        self._sock = sock
        self._buffer = b""

    def recv_until(self, predicate, timeout: float = PROTOCOL_TIMEOUT_SEC) -> str:
        """Read frames from the socket until predicate(frame) returns truthy.
        Returns the matching frame as a string (without the trailing \\n)."""
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self._buffer:
                line, _, self._buffer = self._buffer.partition(b"\n")
                frame = line.decode("utf-8", errors="replace")
                if predicate(frame):
                    return frame
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(f"timed out after {timeout}s waiting for matching ADC frame")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure("connection closed by hub before matching frame arrived")
            self._buffer += chunk


def _adc_login(sock, nick: str, password: str, ve: str | None = None,
               ap: str | None = None, expect_kill: bool = False):
    """Run a full ADC client login as a registered user. On success returns
    (sid, reader) so the caller can keep using the same socket for further
    interactions (e.g. sending +help).

    Optional `ve` / `ap` append `VE<ve>` and `AP<ap>` fields to the BINF -
    useful for #81 etc_clientblocker tests that need to drive the AP+VE
    match path. If `expect_kill=True` we DO NOT raise on a hub-side ISTA;
    instead we return (None, reader) so the caller can inspect the kick
    frame and confirm the connection was dropped."""
    reader = _ADCReader(sock)

    # 1. SUP exchange. Hub responds with ISUP (its supported features),
    #    ISID (the SID it has assigned us) and IINF (hub info).
    sock.sendall(b"HSUP ADBASE ADTIGR\n")
    reader.recv_until(lambda f: f.startswith("ISUP "))
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))

    # 2. Compute identity and send BINF. CID = Tiger(PID); the hub validates
    #    this match in core/hub.lua's BINF handler.
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    # SU (supported features) needs a non-empty value or the ADC parser
    # rejects the BINF as malformed. TCP4 declares we accept active TCPv4
    # CTM connections - inert for the smoke test, but parser-valid.
    extras = ""
    if ap is not None:
        extras += f" AP{_adc_escape(ap)}"
    if ve is not None:
        extras += f" VE{_adc_escape(ve)}"
    binf = (
        f"BINF {sid}"
        f" ID{cid_b32}"
        f" PD{pid_b32}"
        f" NI{_adc_escape(nick)}"
        f" I40.0.0.0"
        f" SUTCP4"
        f"{extras}\n"
    )
    sock.sendall(binf.encode("utf-8"))

    if expect_kill:
        # etc_clientblocker fires its kill on the onConnect listener
        # BEFORE the hub answers IGPA (the listener chain runs after
        # parsing BINF but before the password challenge), so we
        # never see IGPA in this branch. The kick we expect is
        # ISTA 231 ... TL-1.
        frame = reader.recv_until(
            lambda f: f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        return None, reader, frame

    # 3. Hub answers IGPA <salt> for a registered user. Decode salt, compute
    #    the response = Tiger(password || salt_bytes), send HPAS.
    gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
    salt_b32 = gpa.split(" ", 1)[1].strip()
    salt_bytes = _b32_decode(salt_b32)
    # ADC 1.0.1: the GPA salt must be at least 24 random bytes (base32 encoded).
    # Guards against a regression to a shorter salt (#551 raised it from a
    # 6-byte / 10-char default to 24 bytes / 39 chars).
    if len(salt_bytes) < 24:
        raise TestFailure(
            f"GPA salt too short: {len(salt_bytes)} bytes "
            f"({len(salt_b32)} base32 chars); ADC 1.0.1 requires >= 24 bytes"
        )
    response = _tiger.tiger(password.encode("utf-8") + salt_bytes)
    sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

    # 4. On success the hub transitions us to NORMAL state and starts
    #    streaming our own and other users' INFs. The first BINF that starts
    #    with our own SID is the canonical signal we are logged in. On a
    #    bad-password failure the hub instead emits ISTA 223 and disconnects.
    final = reader.recv_until(
        lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
        timeout=PROTOCOL_TIMEOUT_SEC,
    )
    if final.startswith("ISTA "):
        raise TestFailure(f"login failed: hub returned {final!r}")

    # Stash the hub's broadcast BINF for our own SID (the augmented INF the
    # hub sends via sendtoall AFTER insertreglevel appends OP/RG + CT) so a
    # caller can inspect the hub-assigned fields (e.g. CT) without changing
    # this helper's (sid, reader) return contract. #571 uses this.
    reader.login_binf = final

    return sid, reader


@contextlib.contextmanager
def _logged_in_user(nick: str = "dummy", password: str = "test"):
    """Context manager wrapping `_adc_login` for tests that need a
    short-lived live ADC session.

    Yields (sock, sid, reader). On exit, closes the socket (catching
    OSError so a hub-side kick that already half-closed the socket
    does not raise out of the `with` block - the kick is the
    expected outcome of HTTP write-endpoint smoke tests).

    Phase 2 (#82 / #198) of the HTTP API has ~8 call sites that need
    a logged-in ADC user; before this helper each one carried 5-7
    lines of `socket.create_connection` / try / finally / except
    OSError boilerplate. PR-3 (cmd_gag) and PR-4 (cmd_ban) will
    reuse this helper plus `_assert_adc_drops` / `_assert_adc_alive`
    extensively, so the trajectory is for the helper count to stay
    small and this file to stay readable rather than splitting into
    a `tests/smoke/helpers.py` (revisit only if the helper count
    grows past ~6 single-purpose functions).
    """
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sid, reader = _adc_login(sock, nick, password)
        yield sock, sid, reader
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _assert_adc_drops(sock, timeout: float = 2.0, attempts: int = 10):
    """Assert that the hub closes the ADC socket within `timeout`
    seconds. After an HTTP-driven kick or redirect, the hub sends
    `ISTA 230 ...` (or `IQUI <sid> RD ...`) and then FINs the
    socket. The test side sees a series of recv() calls returning
    chunks of frames followed by an empty bytes object (EOF) or an
    OSError (RST). A `socket.timeout` is treated as **failure**:
    the kick is fast on healthy CI, a 2s budget is more than enough
    for the hub-side close to land on the wire, and silently
    passing on timeout (the pre-PR-C inline pattern did this) hides
    the very regression this assertion exists to detect - a
    handler that no-ops without actually invoking the kick.

    Raises TestFailure if the kick is not observable within budget.
    """
    sock.settimeout(timeout)
    try:
        for _ in range(attempts):
            chunk = sock.recv(4096)
            if not chunk:
                return    # clean FIN observed - dropped
    except OSError:
        return    # RST also means the conn is dead (good)
    raise TestFailure(
        "ADC connection did NOT drop within the timeout - "
        "the HTTP write-endpoint did not deliver the kick "
        "(or did so faster than recv could observe, which is "
        "unrealistic for a non-keepalive hub close)"
    )


def _assert_adc_alive(sock, timeout: float = 1.0):
    """Assert that the ADC socket is still alive. Used after a 400/
    403/404/409/415 from an HTTP write-endpoint to confirm the
    handler short-circuited BEFORE the kick fired.

    Drains the socket in a recv-loop for `timeout` seconds and
    fails if a FIN (empty bytes) ever lands. Hub-pushed frames
    (BINF / IINF / queued chat) are fine - the loop swallows them.
    A timeout means "no evidence of close" which is the alive
    signal. The single-recv pre-PR-C inline pattern had a
    false-pass window: a hub frame queued before the assertion
    would short-circuit the check before the FIN arrived; this
    loop addresses that.
    """
    deadline = time.monotonic() + timeout
    sock.settimeout(timeout)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return    # timeout = no FIN observed = alive
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return    # idle = alive
        except OSError:
            raise TestFailure(
                "ADC connection unexpectedly dropped (OSError) - "
                "the HTTP handler ran the side-effect when it "
                "should have short-circuited"
            )
        if chunk == b"":
            raise TestFailure(
                "ADC connection unexpectedly dropped (FIN) - the "
                "HTTP handler ran the side-effect when it should "
                "have short-circuited"
            )
        # non-empty: hub pushed a frame (BINF / IINF / chat). The
        # socket is alive; keep draining until the deadline.


# -----------------------------------------------------------------------------
# Tests (continued)
# -----------------------------------------------------------------------------

def _open_tls_socket():
    """Helper: return a connected TLS-wrapped socket to the hub's TLS port.
    Validation is disabled because the smoke harness uses a self-signed
    test cert generated by certs/make_cert.{sh,bat}."""
    raw = socket.create_connection((HUB_HOST, TEST_PORT_TLS), timeout=PROTOCOL_TIMEOUT_SEC)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Pin TLS 1.2 minimum (closes CodeQL py/insecure-protocol).
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx.wrap_socket(raw, server_hostname=HUB_HOST)


def test_full_login_plain():
    """Plain ADC: full login flow as dummy/test, BINF + HPAS to NORMAL state.
    Exercises createuser's user object, the BINF parser, IGPA / salt
    generation, HPAS verification, login() listener firing."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        if not sid or len(sid) != 4:
            raise TestFailure(f"unexpected SID format from hub: {sid!r}")


def test_full_login_tls():
    """Same as plain, but over the TLS port."""
    sock = _open_tls_socket()
    try:
        sid, _reader = _adc_login(sock, "dummy", "test")
        if not sid or len(sid) != 4:
            raise TestFailure(f"unexpected SID format from hub: {sid!r}")
    finally:
        sock.close()


def test_botflag_ct_bit():
    """#571: a registered account carrying the `show_as_bot` profile flag
    logs in with the ADC CT bot bit (1) OR-ed into its level-derived CT,
    and nothing else changes. seed_dummy_botflag() set show_as_bot=1 on the
    level-100 `dummy` account, so insertreglevel() must emit CT (16 | 1) =
    17.

    FAIL-PRE-FIX two ways:
      - without the `show_as_bot` line in core/hub.lua's _regex.reguser
        schema, updateusers() wipes user.tbl at boot (unknown key) and
        `dummy` no longer exists -> _adc_login below fails outright.
      - without the insertreglevel() change, CT stays 16 (no bot bit) ->
        the bot-bit assertion below fails.
    """
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        binf = getattr(reader, "login_binf", "") or ""
        m = re.search(r"\bCT(\d+)\b", binf)
        if not m:
            raise TestFailure(f"no CT field in dummy's login BINF: {binf!r}")
        ct = int(m.group(1))
        if ct & 1 != 1:
            raise TestFailure(
                f"CT bot bit (1) not set: got CT{ct}; the show_as_bot flag "
                f"did not reach insertreglevel()"
            )
        if ct != 17:
            raise TestFailure(
                f"expected CT17 (16 | 1) for the flagged level-100 dummy "
                f"account, got CT{ct}"
            )


def test_command_routing():
    """After a full login, send `+help` and expect any EMSG/DMSG response from
    the hubbot. Exercises onBroadcast listener chain + etc_hubcommands routing
    + cmd_help running and replying."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        # cmd_help replies via user:reply(...) which goes out as a private
        # message frame (E or D type). We accept either kind.
        response = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(response) < 20:
            raise TestFailure(f"+help response unexpectedly short: {response!r}")


def test_backup_now(staging_dir: Path):
    """#480 PR-A: `+backup now` produces an encrypted .ldbk artifact + a
    .sha256 sidecar. Exercises the whole engine path through the plugin
    command: real file collection (io + the listdir C primitive over
    scripts/data + scripts/cfg), OpenSSL PBKDF2 + AES-256-GCM seal, atomic
    write, and the sidecar. dummy is level 100 (> etc_backup_oplevel 80); the
    passphrase is set in the staged cfg by override_test_ports."""
    backups_dir = staging_dir / "cfg" / "backups"
    before = (
        set(backups_dir.glob("luadch-backup-*.ldbk"))
        if backups_dir.exists()
        else set()
    )
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        # The space in "+backup now" MUST be the ADC escape \s, or the hub
        # parses "now" as a separate ADC field and the command sees no
        # subcommand (multi-word BMSG bodies need \s, not a raw space).
        sock.sendall(f"BMSG {sid} +backup\\snow\n".encode("utf-8"))
        # The hubbot reply carries "Backup written: <path>" on success or
        # "Backup failed: ..." otherwise. Match on those words so we skip
        # etc_hubcommands' own "[command] +backup" chat-echo frame.
        response = reader.recv_until(
            lambda f: f.startswith(("EMSG ", "DMSG ", "BMSG ")) and ("written" in f or "failed" in f),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
    if "written" not in response:
        raise TestFailure(f"+backup now did not report success: {response!r}")

    # A new artifact must exist on disk.
    new = set(backups_dir.glob("luadch-backup-*.ldbk")) - before
    if not new:
        raise TestFailure(f"+backup now wrote no .ldbk artifact in {backups_dir}")
    artifact = next(iter(new))
    if artifact.stat().st_size < 100:
        raise TestFailure(
            f"backup artifact suspiciously small: {artifact.stat().st_size} bytes"
        )
    # It must be an LDBK1 blob, not plaintext (the seal actually ran).
    if artifact.read_bytes()[:4] != b"LDBK":
        raise TestFailure(f"artifact is not an LDBK archive: {artifact.name}")
    # The sidecar exists and is the standard `sha256sum` format.
    sidecar = artifact.parent / (artifact.name + ".sha256")
    if not sidecar.exists():
        raise TestFailure(f"backup sidecar missing: {sidecar}")
    sc = sidecar.read_text(encoding="utf-8").strip()
    if not re.match(r"^[0-9a-f]{64}  luadch-backup-.*\.ldbk$", sc):
        raise TestFailure(f"backup sidecar format wrong: {sc!r}")


def test_backup_restore_roundtrip(source_install: Path, keep_staging=False):
    """#480 PR-B: an engine-sealed backup restores cleanly through the real
    binary via `Luadch --restore`, with genuine AES-256-GCM decrypt. Full
    loop on its OWN staged tree (independent of the shared hub):

        boot -> +backup now -> stop hub -> corrupt cfg/cfg.tbl
             -> --restore --verify (must write nothing)
             -> --restore --force  (must restore cfg.tbl byte-for-byte)

    Exercises the C arg parsing (--restore/--verify/--force), run_restore(),
    core/restore.lua's bootstrap (real adclib require + backup_archive load),
    the sidecar check, unpack, path-sanitize, and the atomic apply. Provably
    fails without PR-B: the pre-PR binary rejects --restore as an unknown
    option and never writes the file back."""
    st = stage_install(source_install)
    proc = None
    log_file = None
    # Dedicated ports: the shared hub is still running on TEST_PORT_* when this
    # runs, so reusing them would make the client connect to THAT hub (whose
    # dummy password an earlier +setpass test changed). Own ports -> own hub.
    rt_plain = TEST_PORT_PLAIN + 100
    try:
        override_test_ports(st)   # sets etc_backup_passphrase = smoke-backup-pass
        rt_cfg = st / "cfg" / "cfg.tbl"
        rt_text = rt_cfg.read_text(encoding="utf-8")
        for pat, repl in (
            (r"tcp_ports\s*=\s*\{[^}]*\}", f"tcp_ports = {{ {rt_plain} }}"),
            (r"ssl_ports\s*=\s*\{[^}]*\}", f"ssl_ports = {{ {TEST_PORT_TLS + 100} }}"),
            (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}", f"tcp_ports_ipv6 = {{ {TEST_PORT_PLAIN_V6 + 100} }}"),
            (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}", f"ssl_ports_ipv6 = {{ {TEST_PORT_TLS_V6 + 100} }}"),
        ):
            rt_text, n = re.subn(pat, repl, rt_text, count=1)
            if n != 1:
                raise RuntimeError(f"round-trip: could not re-port cfg.tbl: {pat}")
        rt_cfg.write_text(rt_text, encoding="utf-8")
        for stale in ("servercert.pem", "serverkey.pem", "cacert.pem", "cakey.pem"):
            (st / "certs" / stale).unlink(missing_ok=True)
        proc, log_file = start_hub(st)
        wait_for_port(HUB_HOST, rt_plain, START_TIMEOUT_SEC)

        # Produce one real backup through the engine.
        backups_dir = st / "cfg" / "backups"
        with socket.create_connection(
            (HUB_HOST, rt_plain), timeout=PROTOCOL_TIMEOUT_SEC
        ) as sock:
            sid, reader = _adc_login(sock, "dummy", "test")
            sock.sendall(f"BMSG {sid} +backup\\snow\n".encode("utf-8"))
            reader.recv_until(
                lambda f: f.startswith(("EMSG ", "DMSG ", "BMSG ")) and ("written" in f or "failed" in f),
                timeout=PROTOCOL_TIMEOUT_SEC,
            )
        arts = sorted(backups_dir.glob("luadch-backup-*.ldbk"))
        if not arts:
            raise TestFailure("round-trip: no backup artifact was produced")
        artifact = arts[-1]

        # Stop the hub so --restore can take the single-instance lock (a
        # restore over a running hub is refused by design).
        stop_hub(proc, log_file)
        proc = None

        cfg = st / "cfg" / "cfg.tbl"
        original = cfg.read_bytes()
        corrupt = b"-- CORRUPTED BY SMOKE TEST --\n"
        cfg.write_bytes(corrupt)

        binary = st / ("Luadch.exe" if sys.platform == "win32" else "luadch")
        env = dict(os.environ, LUADCH_BACKUP_PASSPHRASE="smoke-backup-pass")

        # --verify is a dry run over the POPULATED tree (no --force): it must
        # still exit 0 and write nothing - the conflict refusal is for a real
        # apply, not a verify. It also drives the passphrase via the FALLBACK
        # env name (LUADCH_ETC_BACKUP_PASSPHRASE, the backup engine's own) with
        # the primary NOT set, proving restore accepts either.
        verify_env = {k: v for k, v in os.environ.items() if k != "LUADCH_BACKUP_PASSPHRASE"}
        verify_env["LUADCH_ETC_BACKUP_PASSPHRASE"] = "smoke-backup-pass"
        rv = subprocess.run(
            [str(binary), "--restore", str(artifact), "--verify"],
            cwd=str(st), env=verify_env, capture_output=True, text=True, timeout=60,
        )
        if rv.returncode != 0:
            raise TestFailure(f"--verify exited {rv.returncode}:\n{rv.stdout}\n{rv.stderr}")
        if cfg.read_bytes() != corrupt:
            raise TestFailure("--verify wrote to disk; it must be a dry run")

        # Real restore: cfg.tbl must come back exactly.
        rr = subprocess.run(
            [str(binary), "--restore", str(artifact), "--force"],
            cwd=str(st), env=env, capture_output=True, text=True, timeout=60,
        )
        if rr.returncode != 0:
            raise TestFailure(f"--restore exited {rr.returncode}:\n{rr.stdout}\n{rr.stderr}")
        if cfg.read_bytes() != original:
            raise TestFailure("cfg.tbl was not restored to its original bytes")

        # A wrong passphrase must be rejected (GCM auth), not silently applied.
        cfg.write_bytes(corrupt)
        bad = subprocess.run(
            [str(binary), "--restore", str(artifact), "--force"],
            cwd=str(st), env=dict(os.environ, LUADCH_BACKUP_PASSPHRASE="wrong-pass"),
            capture_output=True, text=True, timeout=60,
        )
        if bad.returncode == 0:
            raise TestFailure("--restore accepted a wrong passphrase")
        if cfg.read_bytes() != corrupt:
            raise TestFailure("--restore wrote files despite a wrong passphrase")
    finally:
        if proc is not None:
            stop_hub(proc, log_file)
        if keep_staging:
            log(f"restore round-trip staging kept at {st.parent}")
        else:
            shutil.rmtree(st.parent, ignore_errors=True)


def test_s1_fragmented_frame_reassembled():
    """Phase 8 S1: an ADC frame split across two TCP segments must be
    reassembled and processed as one frame.

    Pre-S1 (`receive(socket, "*l")`) a plain-TCP partial line returned
    nil,"timeout",<partial>, which the old _readbuffer guard treated as
    fatal -> the hub dropped the connection. This test therefore FAILS
    on pre-S1 code (connection closed / no reply) and PASSES on S1 - a
    true pre/post differentiator (CLAUDE.md s1a.7), and it directly
    exercises the latent "unwanted disconnects in big hubs" bug the S1
    journal documents.
    """
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sid, reader = _adc_login(sock, "dummy", "test")
        # Send "+help" as two TCP segments with the frame boundary (\n)
        # only in the second write.
        sock.sendall(f"BMSG {sid} +he".encode("utf-8"))
        time.sleep(0.25)  # force a separate read event on the hub side
        sock.sendall(b"lp\n")
        response = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(response) < 20:
            raise TestFailure(
                f"fragmented +help reply unexpectedly short: {response!r}"
            )


def test_s1_two_frames_one_segment():
    """Phase 8 S1: two ADC frames delivered in a single TCP segment must
    be processed as two independent frames (no over-merge into one
    unparseable blob, no desync of the trailing-byte buffer).

    Over-merge would make adc_parse choke on an embedded \\n and produce
    no reply at all; a desynced remainder buffer would break the next
    command. The test asserts a reply to the doubled send AND that a
    subsequent independent command still works."""
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sid, reader = _adc_login(sock, "dummy", "test")
        # Two complete frames, one write / one segment.
        sock.sendall(f"BMSG {sid} +help\nBMSG {sid} +help\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        # Stream must not be desynced by the framer's remainder handling:
        # an independent follow-up command still gets answered.
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        followup = reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if len(followup) < 20:
            raise TestFailure(
                f"stream desynced after pipelined frames; follow-up "
                f"reply too short: {followup!r}"
            )


def test_literal_bracket_command_hint():
    """#137 regression: a user who types `[+!#]<cmd>` (with literal
    square brackets, copying the doc-notation as if it were the
    actual syntax) gets a hint and the broadcast is swallowed.

    The hint MUST:
      - mention the correct prefix form (e.g. `+help`)
      - NOT echo the input args - args may contain a password
        (e.g. `[+!#]reg <user> <pw>` would leak credentials if
        the bot replied with the original line)

    The test sends `[+!#]help foo bar` where `foo bar` stands in
    for arbitrary "secret" args, then asserts the bot's EMSG/DMSG
    reply does NOT contain `foo` or `bar`.
    """
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        # ADC escape: spaces become \s. So `[+!#]help foo bar` ->
        # `[+!#]help\sfoo\sbar`.
        sock.sendall(f"BMSG {sid} [+!#]help\\sfoo\\sbar\n".encode("utf-8"))
        # Drain all frames the hub sends back within 3 seconds and
        # collect them ALL. Two independent assertions:
        #   1. the hint BMSG (with "pick one of") arrived
        #   2. NO BMSG frame contains the input args "foo"/"bar"
        # Matching only the hint frame and checking it for leakage
        # would miss a regression where the broadcast escapes the
        # PROCESSED swallow and is echoed back from the user's own
        # SID before the hint - that BMSG would contain foo/bar
        # and the privacy claim would silently regress (the hint
        # itself never echoes input, but the un-swallowed broadcast
        # would).
        all_frames = []
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                f = reader.recv_until(lambda x: True, timeout=0.5)
                all_frames.append(f)
            except TestFailure:
                break
        bmsg_frames = [f for f in all_frames if f.startswith("BMSG ")]
        hint_frames = [f for f in bmsg_frames if "pick\\sone\\sof" in f]
        if not hint_frames:
            raise TestFailure(
                f"did not receive the literal-bracket hint BMSG; "
                f"BMSG frames seen: {bmsg_frames!r}"
            )
        hint = hint_frames[0]
        if "help" not in hint:
            raise TestFailure(
                f"hint did not mention the command name 'help': {hint!r}"
            )
        # Privacy assertion across ALL BMSG frames (hint plus any
        # leaked broadcast). `foo` / `bar` are stand-ins for
        # hypothetical password tokens; either appearing in any
        # BMSG returned by the hub means the swallow regressed.
        for frame in bmsg_frames:
            if "foo" in frame or "bar" in frame:
                raise TestFailure(
                    f"hub leaked input args (privacy regression of "
                    f"#137 - either hint echoed them or the broadcast "
                    f"was not swallowed): {frame!r}"
                )


def test_csprng_salt_uniqueness():
    """Open N sequential connections to a registered nick, drive each through
    SUP/BINF until the hub answers IGPA <salt>, capture the salt and disconnect
    before HPAS (so badpassword stays at 0). Assert all salts are distinct.

    Smoke-coverage for the F-AUTH-2 fix: the math.random() salt source was
    replaced with OpenSSL RAND_bytes via adclib.random_bytes. A regression to
    a deterministic / poorly-seeded PRNG would make this test fail on
    repeated salts."""
    salts = []
    N = 10
    for _ in range(N):
        with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
            reader = _ADCReader(sock)
            sock.sendall(b"HSUP ADBASE ADTIGR\n")
            reader.recv_until(lambda f: f.startswith("ISUP "))
            isid = reader.recv_until(lambda f: f.startswith("ISID "))
            sid = isid.split(" ", 1)[1].strip()
            reader.recv_until(lambda f: f.startswith("IINF "))

            pid_bytes = secrets.token_bytes(24)
            cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
            pid_b32 = _b32_encode(pid_bytes)
            binf = (
                f"BINF {sid}"
                f" ID{cid_b32}"
                f" PD{pid_b32}"
                f" NIdummy"
                f" I40.0.0.0"
                f" SUTCP4\n"
            )
            sock.sendall(binf.encode("utf-8"))

            gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
            salts.append(gpa.split(" ", 1)[1].strip())
            # Drop the connection before HPAS - no badpassword increment.

    if len(set(salts)) != N:
        dupes = [s for s in salts if salts.count(s) > 1]
        raise TestFailure(f"salt collision in {N} draws: {dupes!r}")


def test_perip_connection_cap():
    """Open more parallel TCP connections from one IP than ratelimit_perip_max_conns
    (default 16). The N+1th accept must fail or get torn down by the hub before
    a SUP exchange completes. Smoke coverage for F-NET-1.

    We keep the first batch alive (don't close until end of test), then attempt
    one extra. If the hub honours the cap, the extra socket either errors at
    connect or the hub closes it before SUP can complete."""
    cap = 16
    keep = []
    try:
        for _ in range(cap):
            sock = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC)
            keep.append(sock)
        # The cap+1 attempt: connect may succeed (kernel-level) but the hub must
        # not produce an ISUP. Give it ~1s; if we get nothing, the hub refused.
        try:
            extra = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC)
        except OSError:
            return  # connect refused at OS level - that's also acceptable
        try:
            extra.settimeout(1.5)
            extra.sendall(b"HSUP ADBASE ADTIGR\n")
            data = b""
            try:
                data = extra.recv(4096)
            except (socket.timeout, OSError):
                pass
            if data:
                raise TestFailure(
                    f"hub accepted connection #{cap + 1} from one IP and answered "
                    f"with {data[:80]!r}; expected the per-IP cap to refuse"
                )
        finally:
            extra.close()
    finally:
        for s in keep:
            s.close()
        # Give the hub time to process disconnects and free per-IP slots
        # before the next test connects.
        time.sleep(0.6)


# -----------------------------------------------------------------------------
# Phase 8a-2 - negative-test fuzz suite (issue #121)
# -----------------------------------------------------------------------------
# These tests feed malformed ADC input into the hub and assert that the hub
# handles it cleanly: no crash, no Lua error in error.log (caught by
# test_no_script_errors at end of run), and the hub stays available for
# further connections (caught by test_neg_canary at end of this section).
#
# Each test opens its own socket and closes it before the next one starts,
# so the per-IP connection cap (16) is not exhausted - sequential access
# stays well within the burst budget (30).
#
# Tests deliberately do NOT assert specific hub responses: any of "ISTA
# error frame", "clean disconnect", "silent ignore-and-keep-going" is an
# acceptable handling of a malformed input. The non-acceptable outcomes
# are "hub crash" and "Lua script error" - both caught by the canary +
# test_no_script_errors pair at the end of the run.

def _neg_handshake_get_sid(sock):
    """Drive HSUP -> ISUP/ISID/IINF on a freshly connected socket. Returns
    (reader, sid) so the caller can send a malformed BINF. Caller owns
    the socket lifetime."""
    reader = _ADCReader(sock)
    sock.sendall(b"HSUP ADBASE ADTIGR\n")
    reader.recv_until(lambda f: f.startswith("ISUP "))
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))
    return reader, sid


def _neg_drain_briefly(sock, timeout: float = 2.0):
    """Drain whatever the hub sends back, up to `timeout` seconds. Used
    after sending a malformed payload to give the hub time to react before
    the test exits and closes the socket. Never raises."""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return
    except (socket.timeout, OSError):
        return


def _neg_send_binf_extra(binf_extra: str):
    """Open a fresh plain socket, run the SUP exchange to acquire a SID,
    then send a single BINF with `binf_extra` appended after `BINF <sid>`.
    Drain briefly so the hub has a chance to react. The caller's intent is
    to verify that whatever malformed extra was sent does not crash the
    hub - the actual response is not asserted here."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        binf = f"BINF {sid} {binf_extra}\n".encode("utf-8")
        try:
            sock.sendall(binf)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # hub already closed - acceptable
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def _neg_random_pid_cid_pair():
    """A fresh PID + matching CID = Tiger(PID), both base32-encoded. Use
    these in BINF tests where the test is about a *different* malformed
    field - the hub still has to compute Tiger(PID) and compare to CID,
    so passing a valid pair avoids spurious early-rejection on
    CID/PID mismatch."""
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    return cid_b32, pid_b32


def test_neg_inf_negative_numerics():
    """BINF with negative SS / SF / SL / DS / US. Hub should reject or
    ignore; should not propagate the negative value into ban / quota
    arithmetic where it could underflow."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIneg-numerics I40.0.0.0 SUTCP4"
        f" SS-1 SF-1 SL-1 DS-1 US-1"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_oversize_numerics():
    """BINF with absurdly large SS / SF. Hub should reject or clamp; raw
    value must not blow up integer math anywhere downstream."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIoversize-num I40.0.0.0 SUTCP4"
        f" SS999999999999999999999999999 SF999999999"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_invalid_ipv4():
    """BINF with syntactically-invalid I4. Parser/validator must reject
    cleanly; specifically must not try to resolve, normalize, or use the
    bogus value as a key."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NIbad-ipv4 I4999.999.999.999 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_invalid_ipv6():
    """BINF with non-IPv6 garbage in I6."""
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NIbad-ipv6 I40.0.0.0 I6not-an-ipv6 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_overlong_nick():
    """BINF with a 1000-character NI. Should hit the parser size limits or
    a per-field validator without trampling the buffer."""
    long_nick = "A" * 1000
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = f"ID{cid_b32} PD{pid_b32} NI{long_nick} I40.0.0.0 SUTCP4"
    _neg_send_binf_extra(extra)


def test_neg_inf_overlong_description():
    """BINF with a 10000-character DE. Stress test the per-field size
    handling on a large optional string."""
    long_desc = "X" * 10000
    cid_b32, pid_b32 = _neg_random_pid_cid_pair()
    extra = (
        f"ID{cid_b32} PD{pid_b32} NIlong-desc I40.0.0.0 SUTCP4"
        f" DE{long_desc}"
    )
    _neg_send_binf_extra(extra)


def test_neg_inf_malformed_utf8_nick():
    """BINF with raw bytes that are not valid UTF-8 in NI. Phase 7d's
    re-enabled UTF-8 entry check (#65) should reject; this test guards
    that behaviour as a regression net."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # 0xFF is a lone continuation byte - never valid UTF-8 by itself.
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NIbad".encode("utf-8")
            + b"\xff\xfe"
            + f" I40.0.0.0 SUTCP4\n".encode("utf-8")
        )
        try:
            sock.sendall(binf)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_inf_missing_required_fields():
    """BINF with no ID / PID at all. Login flow expects both to validate
    the CID = Tiger(PID) constraint; missing fields must not crash the
    handler."""
    cid_b32, _pid_b32 = _neg_random_pid_cid_pair()
    # Send only a NI - no ID, no PD. Hub should either ISTA-reject or
    # silently drop the connection.
    extra = "NImissing-pid-id I40.0.0.0 SUTCP4"
    _neg_send_binf_extra(extra)


def _neg_inf_nick_escape_sequence_rejected(staging_dir: Path, escape_seq: str):
    """Issue #265 regression: BINF with NI containing an ADC escape
    sequence (\\s or \\n) must be rejected by `_regex.nowhitespace`. NI
    per ADC §2.4 must never contain whitespace in ANY form - including
    escape-encoded, because a spec-compliant receiver decodes \\s / \\n
    back to real space / LF in the nick string.

    Differentiator: the parser's rejection log line. We embed a unique
    per-run marker in the nick so the matching line can be located in
    the shared hub log among other concurrent test traffic.

      Pre-fix:  `_regex.nowhitespace` only checks raw %c; \\s / \\n pass,
                parse() succeeds, NO 'invalid named parameter' log line
                with our marker is emitted.
      Post-fix: validator rejects \\s / \\n on top of %c, parse() emits
                'invalid named parameter in BINF: <marker-nick>'.
    """
    marker = secrets.token_hex(4)
    nick = f"esc{marker}{escape_seq}name"
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NI{nick}"
            f" I40.0.0.0 SUTCP4\n"
        ).encode("utf-8")
        sock.sendall(binf)
        _neg_drain_briefly(sock, timeout=1.0)
    finally:
        sock.close()

    # `out_put` writes to log/event.log gated by `log_events=true` (set in
    # override_test_ports). Parser rejection emits a 'invalid named
    # parameter in BINF: <body>' line where <body> includes our marker.
    log_path = staging_dir / "log" / "event.log"
    if not log_path.exists():
        raise AssertionError(
            f"event.log not found at {log_path}; smoke harness must enable "
            f"log_events in cfg.tbl override for this assertion to work"
        )
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    matches = [
        line for line in log_text.splitlines()
        if "invalid named parameter" in line and marker in line
    ]
    if not matches:
        raise AssertionError(
            f"BINF with NI containing escape sequence {escape_seq!r} "
            f"was NOT rejected by the parser; no 'invalid named "
            f"parameter' log line with marker {marker!r} found in "
            f"event.log. `_regex.nowhitespace` must reject \\s / \\n "
            f"escapes in NI per ADC §2.4 (a spec-compliant receiver "
            f"decodes the escape sequence back to whitespace in the "
            f"nick value)."
        )


def test_neg_inf_nick_escape_space_rejected(staging_dir: Path):
    """Issue #265 regression: NI containing \\s (escaped space, two bytes
    5C 73) must be rejected."""
    _neg_inf_nick_escape_sequence_rejected(staging_dir, "\\s")


def test_neg_inf_nick_escape_newline_rejected(staging_dir: Path):
    """Issue #265 regression: NI containing \\n (escaped newline, two
    bytes 5C 6E) must be rejected."""
    _neg_inf_nick_escape_sequence_rejected(staging_dir, "\\n")


def _send_binf_with_ni(nick: str):
    """Partial handshake + one BINF carrying the given NI, then drain+close.
    Used by the #419 unknown-escape tests below."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NI{nick}"
            f" I40.0.0.0 SUTCP4\n"
        ).encode("utf-8")
        sock.sendall(binf)
        _neg_drain_briefly(sock, timeout=1.0)
    finally:
        sock.close()


def _event_log_discarded_escape(staging_dir: Path, marker: str) -> bool:
    """True iff parse() logged an 'unknown escape ... discarding' line for a
    message carrying `marker` (log_events=true in the smoke override)."""
    log_path = staging_dir / "log" / "event.log"
    if not log_path.exists():
        raise AssertionError(f"event.log not found at {log_path}")
    txt = log_path.read_text(encoding="utf-8", errors="replace")
    return any(
        "unknown escape" in line and marker in line
        for line in txt.splitlines()
    )


def test_neg_unknown_escape_discarded(staging_dir: Path):
    """#419 / ADC 1.0 section 3.1: a message containing an unknown escape
    (anything other than \\s \\n \\\\) must be discarded. A BINF whose NI
    carries \\q is dropped by parse(). Pre-fix it was accepted (no line)."""
    marker = secrets.token_hex(4)
    _send_binf_with_ni(f"esc{marker}\\qname")     # \q on the wire
    if not _event_log_discarded_escape(staging_dir, marker):
        raise AssertionError(
            f"BINF with unknown escape \\q was NOT discarded; no 'unknown "
            f"escape' log line with marker {marker!r} in event.log (#419)"
        )


def test_neg_trailing_backslash_discarded(staging_dir: Path):
    """#419: a value ending in a lone backslash is an incomplete/unknown
    escape and must be discarded (the issue's own naive regex misses this)."""
    marker = secrets.token_hex(4)
    _send_binf_with_ni(f"esc{marker}name\\")      # NI ends in a bare backslash
    if not _event_log_discarded_escape(staging_dir, marker):
        raise AssertionError(
            f"BINF with a trailing backslash was NOT discarded; no 'unknown "
            f"escape' log line with marker {marker!r} in event.log (#419)"
        )


def test_valid_escaped_backslash_not_discarded(staging_dir: Path):
    """#419 positive control: \\\\ (an escaped backslash) is a VALID escape
    and must NOT be discarded - exactly the case a naive
    '\\ not followed by s/n/\\' scan would wrongly reject."""
    marker = secrets.token_hex(4)
    _send_binf_with_ni(f"esc{marker}\\\\name")    # \\ on the wire = valid escaped backslash
    if _event_log_discarded_escape(staging_dir, marker):
        raise AssertionError(
            f"BINF with a VALID escaped backslash (\\\\) was wrongly "
            f"discarded (over-rejection); marker {marker!r} (#419)"
        )


def test_binf_without_i4_or_i6_accepted():
    """#161 regression: a BINF that omits I4 AND I6 must NOT be rejected
    with ISTA 220 'No CID/PID/NICK/IP found in your INF.'. Per ADC 4.3.x
    the I4 / I6 fields are conditionally required (only when the client
    supports TCP4 / UDP4 / TCP6 / UDP6). Hublist pingers and any
    IP-agnostic probe omit them legitimately. The hub fills in the
    TCP-source IP, same canonical path as the 0.0.0.0 placeholder.

    Test uses the registered `dummy` account so the success path is
    `IGPA <salt>` (password challenge), which lets us distinguish the
    fix from the bug:
      - Pre-fix: ISTA 220 immediately after BINF
      - Post-fix: IGPA, meaning BINF was accepted and identify-state
        passed

    BINF intentionally omits TCP4 / UDP4 in SU - the real pinger profile
    advertises no TCP/UDP feature (see go-dcpp dcping in upstream
    luadch/luadch#176: `SUKEYP,OSNR,UCM0,UCMD,BAS0,BASE,TIGR`). This is
    the spec-defined case where I4/I6 are *not* required at all. A
    future hardening that adds "if SU has TCP4 then require I4" must
    not break this test (it wouldn't, since we don't claim TCP4).

    IPv6 coverage note: the `userip:find(":", 1, true) and "I6" or "I4"`
    fallback in core/hub_dispatch.lua only exercises the "I6" branch
    when the socket is IPv6. This test connects to TEST_PORT_PLAIN
    (IPv4 only) so the IPv6 branch is untested here - the logic is
    trivial fallback (colon-presence in TCP-source IP string), proven
    by inspection rather than test. Worth a dedicated IPv6 smoke run
    if/when we expand IPv6 feature coverage.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # BINF with NO I4, NO I6, NO TCP4/UDP4 in SU - matches the real
        # hublist-pinger profile. The bug fix lets the hub fill the IP
        # slot with the TCP-source IP via setnp(ipver, userip).
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" SUBAS0,BASE,TIGR\n"
        )
        sock.sendall(binf.encode("utf-8"))
        # Read the first frame the hub emits after BINF. With the fix
        # this is IGPA (the password challenge for a registered user).
        # Without the fix it is ISTA 220 + IQUI.
        try:
            frame = reader.recv_until(
                lambda f: f.startswith("IGPA ") or f.startswith("ISTA "),
                timeout=PROTOCOL_TIMEOUT_SEC,
            )
        except TestFailure as e:
            raise TestFailure(
                f"hub did not respond to no-I4/no-I6 BINF within "
                f"{PROTOCOL_TIMEOUT_SEC}s: {e}"
            ) from e
        if frame.startswith("ISTA 220 "):
            raise TestFailure(
                f"hub rejected BINF without I4/I6 with ISTA 220 "
                f"(regression of #161): {frame!r}. Per ADC 4.3.x the "
                f"I4/I6 fields are conditionally required, not absolutely "
                f"required - the hub must fill in the TCP-source IP."
            )
        if not frame.startswith("IGPA "):
            raise TestFailure(
                f"unexpected response to no-I4/no-I6 BINF: {frame!r}. "
                f"Expected IGPA (registered user password challenge)."
            )


def test_binf_with_both_i4_and_i6_accepted():
    """#147 T3.1: a BINF that carries BOTH I4 AND I6 must be
    accepted, with the hub validating ONLY the family matching the
    connecting TCP source against userip. The OTHER (secondary)
    family is unverified; since #214 Gap 1 it is STRIPPED before
    broadcast (see test_binf_secondary_family_stripped). This test
    only asserts the login is ACCEPTED (advances to IGPA); the
    strip-on-broadcast assertion lives in the Gap 1 test.

    This test exercises the HBRI differentiator: it connects via
    **IPv6** (TEST_PORT_PLAIN_V6) and sends BINF with a wrong I4
    (8.8.8.8, definitely not the TCP source) AND a correct I6 (::1,
    matches the v6 TCP source).

    Pre-T3.1 the hub probed I4 FIRST and validated the I4 against
    userip - which is ::1 here, so 8.8.8.8 != ::1 trips
    kill_wrong_ips and the user gets ISTA 246 invalid_ip.

    Post-T3.1 the hub probes both families, picks the field matching
    the v6 connection (= I6), validates ::1 == ::1, passes. The wrong
    secondary I4 is unverified and is stripped before broadcast
    (#214 Gap 1); this test only checks acceptance.

    Test uses the registered `dummy` account so success advances to
    IGPA (password challenge), distinguishing the fix from the bug:
      - Pre-fix: ISTA 246 invalid_ip immediately after BINF
      - Post-fix: IGPA, BINF accepted, identify-state passed
    """
    sock = socket.create_connection(
        ("::1", TEST_PORT_PLAIN_V6), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader, sid = _neg_handshake_get_sid(sock)
        cid_b32, pid_b32 = _neg_random_pid_cid_pair()
        # I4 8.8.8.8 (wrong - we are connecting on v6 ::1) + correct I6.
        # The smoke harness's v6 listener accepts connections from ::1
        # and userip will resolve to "::1" inside the hub. Pre-T3.1 the
        # I4-first validation kicks with ISTA 246; post-T3.1 the I6
        # check (matching family) passes.
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" I48.8.8.8"
            f" I6::1"
            f" SUTCP4,TCP6,BAS0,BASE,TIGR\n"
        )
        sock.sendall(binf.encode("utf-8"))
        try:
            frame = reader.recv_until(
                lambda f: f.startswith("IGPA ") or f.startswith("ISTA "),
                timeout=PROTOCOL_TIMEOUT_SEC,
            )
        except TestFailure as e:
            raise TestFailure(
                f"hub did not respond to dual-stack BINF within "
                f"{PROTOCOL_TIMEOUT_SEC}s: {e}"
            ) from e
        if frame.startswith("ISTA 246 "):
            raise TestFailure(
                f"hub rejected dual-stack BINF with ISTA 246 invalid_ip: "
                f"{frame!r}. T3.1 must validate ONLY the family matching "
                f"the TCP source (I6 here); the I4 is the 'other family', "
                f"accepted on login then stripped before broadcast (#214 Gap 1)."
            )
        if frame.startswith("ISTA "):
            raise TestFailure(
                f"unexpected ISTA response to dual-stack BINF: {frame!r}. "
                f"Expected IGPA."
            )
        if not frame.startswith("IGPA "):
            raise TestFailure(
                f"unexpected response to dual-stack BINF: {frame!r}. "
                f"Expected IGPA (registered user password challenge)."
            )
    finally:
        sock.close()


def test_binf_secondary_family_stripped():
    """#214 Gap 1: a dual-stack login over IPv4 may advertise a
    secondary I6 / U6 (+ TCP6 / UDP6 in SU), but the hub cannot
    authenticate the v6 address over a v4 socket. The unverified
    secondary family MUST be stripped before the INF is broadcast -
    otherwise a hostile client could publish a spoofed I6 and have
    other users direct CTM / RCM at that victim (DC++ DDoS
    amplification).

    Connect via v4 as the registered `dummy` account, log in fully
    with a BINF carrying a correct I4 (127.0.0.1) plus a claimed
    secondary (I6 2001:db8::1, U6, SU TCP6/UDP6). Capture the hub's
    own-SID BINF broadcast echo and assert:
      - the verified primary survives (I4 present, SU TCP4 present)
      - the unverified secondary is gone (no I6 / U6 param; no
        TCP6 / UDP6 SU flag)

    Falsifiable: pre-#214-Gap-1 the hub stored + broadcast the
    secondary as-sent (#147 T3.1 trade-off), so the echo carried
    I6 / U6 / TCP6 / UDP6 and the asserts below FAIL.
    """
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader = _ADCReader(sock)
        sock.sendall(b"HSUP ADBASE ADTIGR\n")
        reader.recv_until(lambda f: f.startswith("ISUP "))
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))

        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" I4127.0.0.1"
            f" I62001:db8::1"
            f" U65555"
            f" SUTCP4,UDP4,TCP6,UDP6\n"
        )
        sock.sendall(binf.encode("utf-8"))

        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_bytes = _b32_decode(gpa.split(" ", 1)[1].strip())
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if echo.startswith("ISTA "):
            raise TestFailure(f"login failed: hub returned {echo!r}")

        # Parse the broadcast INF into space-separated params so we
        # inspect the SU flag-list and I6/U6 params precisely (a raw
        # substring search for "TCP6" could false-match a base32
        # CID/PID by chance).
        params = echo.strip().split(" ")
        su = next((p[2:] for p in params if p.startswith("SU")), "")
        su_flags = su.split(",") if su else []
        has_i4 = any(p.startswith("I4") for p in params)
        has_i6 = any(p.startswith("I6") for p in params)
        has_u6 = any(p.startswith("U6") for p in params)

        if has_i6:
            raise TestFailure(
                f"broadcast INF still carries unverified secondary I6: "
                f"{echo!r}. #214 Gap 1 must strip it."
            )
        if has_u6:
            raise TestFailure(
                f"broadcast INF still carries unverified secondary U6: "
                f"{echo!r}. #214 Gap 1 must strip it."
            )
        if "TCP6" in su_flags or "UDP6" in su_flags:
            raise TestFailure(
                f"broadcast INF SU still advertises secondary transport "
                f"flags (TCP6/UDP6): SU={su!r}. #214 Gap 1 must strip them."
            )
        if not has_i4:
            raise TestFailure(
                f"broadcast INF lost the VERIFIED primary I4: {echo!r}. "
                f"Gap 1 must strip only the secondary family."
            )
        if "TCP4" not in su_flags:
            raise TestFailure(
                f"broadcast INF SU lost the primary-family TCP4 flag: "
                f"SU={su!r}. Gap 1 must strip only secondary flags."
            )
    finally:
        sock.close()


def _hbri_param(frame, name):
    """Extract a named ADC param value (e.g. 'TO', 'P6') from a frame."""
    for tok in frame.strip().split(" "):
        if tok.startswith(name):
            return tok[len(name):]
    return None


def _hbri_main_login(sock, i6="::1"):
    """Drive a dual-stack v4 login that advertises ADHBRI and a secondary
    I6 as the registered `dummy` account. The HBRI-active smoke hub parks
    such a client in the 'hbri' state after HPAS and sends an ITCP pointer
    instead of completing NORMAL entry. Returns (reader, sid, itcp_frame).

    `i6` is the secondary value placed in the BINF: the default "::1" is a
    concrete v6 (verify path); pass "::" to drive the #291 discovery path
    (placeholder = "discover my v6 from the side-channel getpeername")."""
    reader = _ADCReader(sock)
    sock.sendall(b"HSUP ADBASE ADTIGR ADHBRI\n")
    isup = reader.recv_until(lambda f: f.startswith("ISUP "))
    if "ADHBRI" not in isup:
        raise TestFailure(f"HBRI-active hub did not advertise ADHBRI in ISUP: {isup!r}")
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    binf = (
        f"BINF {sid}"
        f" ID{cid_b32}"
        f" PD{pid_b32}"
        f" NIdummy"
        f" I4127.0.0.1"
        f" I6{i6}"
        f" SUTCP4,TCP6\n"
    )
    sock.sendall(binf.encode("utf-8"))
    gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
    salt_bytes = _b32_decode(gpa.split(" ", 1)[1].strip())
    response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
    sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))
    itcp = reader.recv_until(
        lambda f: f.startswith("ITCP ") or f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
        timeout=PROTOCOL_TIMEOUT_SEC,
    )
    if not itcp.startswith("ITCP "):
        raise TestFailure(
            f"expected an ITCP HBRI pointer after HPAS (dual-stack + ADHBRI); got {itcp!r}. "
            f"The hub should park the user in the 'hbri' state, not complete login."
        )
    return reader, sid, itcp


def test_hbri_success():
    """#214 HBRI happy path. A dual-stack client logs in over v4
    advertising ADHBRI + a secondary I6, is parked in the 'hbri' state
    and sent an ITCP pointer. It opens the v6 side-channel, sends HTCP
    with the token; the hub validates the v6 TCP source matches the
    claim and restores the verified I6 to the broadcast INF.

    Falsifiable: without the HBRI mechanism the hub never sends ITCP
    (login completes immediately) and never restores the stripped I6 -
    each assert below (ITCP present, ISTA 000 on the side-channel, I6
    in the broadcast echo) fails."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader, sid, itcp = _hbri_main_login(main)
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P6")
        if not token or not port:
            raise TestFailure(f"ITCP missing TO / P6 params: {itcp!r}")
        side = socket.create_connection(
            ("::1", int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        side.sendall(f"HTCP I6::1 TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 000"):
            raise TestFailure(
                f"expected ISTA 000 (validation success) on the side-channel, got {sta!r}"
            )
        # The main connection now completes NORMAL entry, broadcasting
        # the validated secondary.
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}"), timeout=PROTOCOL_TIMEOUT_SEC
        )
        params = echo.strip().split(" ")
        if not any(p == "I6::1" for p in params):
            raise TestFailure(
                f"validated secondary I6 was not restored to the broadcast INF: {echo!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_hbri_discovery_placeholder():
    """#291 HBRI discovery - the common real-client path. A dual-stack
    client connects over v4 advertising ADHBRI + SU TCP6 but sends the v6
    PLACEHOLDER (I6::, "discover my address"), exactly what auto-detect
    AirDC++ emits. The hub must (1) solicit HBRI for the placeholder and
    (2) on the side-channel DISCOVER the v6 from getpeername rather than
    reject the placeholder as an address mismatch - then broadcast the
    discovered I6.

    Two coupled regressions guarded (both pre-#291):
      1. claim-capture skipped placeholders (:: / 0.0.0.0) -> no ITCP for
         the common case, so HBRI never fired for real clients.
      2. validate() rejected a placeholder claimed value as a mismatch
         (claimed '::' != getpeername '::1') -> ISTA 155 not success.

    Falsifiable: pre-fix the hub either never sends ITCP (regression 1,
    _hbri_main_login's ITCP assert fires) or answers ISTA 155 on the
    side-channel (regression 2); post-fix it answers ISTA 000 and the
    discovered I6::1 appears in the broadcast echo."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader, sid, itcp = _hbri_main_login(main, i6="::")
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P6")
        if not token or not port:
            raise TestFailure(f"ITCP missing TO / P6 params: {itcp!r}")
        side = socket.create_connection(
            ("::1", int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        # Placeholder on the side-channel too: the hub must discover the v6
        # from the socket source (::1), not trust this stated value.
        side.sendall(f"HTCP I6:: TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 000"):
            raise TestFailure(
                f"expected ISTA 000 (discovery validation success) on the side-channel, got {sta!r}"
            )
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}"), timeout=PROTOCOL_TIMEOUT_SEC
        )
        params = echo.strip().split(" ")
        if not any(p == "I6::1" for p in params):
            raise TestFailure(
                f"discovered secondary I6 (getpeername ::1) was not committed to the broadcast INF: {echo!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_hbri_concrete_mismatch_rejected():
    """#291 anti-spoof: a client that states a CONCRETE secondary address
    on the validation socket which does NOT equal the socket's real TCP
    source (getpeername) is rejected with ISTA 155 - the hub never accepts
    a self-named address that the side-channel cannot prove. (The #291
    discovery relaxation only exempts the placeholder ::/0.0.0.0; a
    concrete claim is still cross-checked, exactly as adchpp validateIP.)

    Falsifiable: drop the `claimed ~= vip` reject and the side-channel
    answers ISTA 000 (the validation would succeed, committing getpeername
    silently under a mismatched stated address) - the assert below fires."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        # Concrete secondary in the BINF (verify path, not discovery).
        reader, sid, itcp = _hbri_main_login(main, i6="2001:db8::dead")
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P6")
        if not token or not port:
            raise TestFailure(f"ITCP missing TO / P6 params: {itcp!r}")
        side = socket.create_connection(
            ("::1", int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        # Side-channel states a concrete v6 that is NOT the real source
        # (::1). The hub must reject the mismatch, not commit it.
        side.sendall(f"HTCP I62001:db8::dead TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 155"):
            raise TestFailure(
                f"expected ISTA 155 (concrete address mismatch) on the side-channel, got {sta!r}"
            )
        # Login still completes, WITHOUT the bogus secondary.
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}"), timeout=PROTOCOL_TIMEOUT_SEC
        )
        if "2001:db8::dead" in echo:
            raise TestFailure(
                f"rejected secondary leaked into the broadcast INF: {echo!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def _hbri_normal_login_capable(sock):
    """#286 helper. Log in as `dummy` over v4 advertising ADHBRI + SU
    TCP4,TCP6 but WITHOUT a secondary I6, so login-time HBRI does NOT fire
    and the user reaches NORMAL state HBRI-capable. Returns (reader, sid).
    The post-login tests then send a NORMAL-state INF carrying I6."""
    reader = _ADCReader(sock)
    sock.sendall(b"HSUP ADBASE ADTIGR ADHBRI\n")
    reader.recv_until(lambda f: f.startswith("ISUP "))
    isid = reader.recv_until(lambda f: f.startswith("ISID "))
    sid = isid.split(" ", 1)[1].strip()
    reader.recv_until(lambda f: f.startswith("IINF "))
    pid_bytes = secrets.token_bytes(24)
    cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
    pid_b32 = _b32_encode(pid_bytes)
    binf = (
        f"BINF {sid} ID{cid_b32} PD{pid_b32} NIdummy"
        f" I40.0.0.0 SUTCP4,TCP6\n"
    )
    sock.sendall(binf.encode("utf-8"))
    gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
    salt_bytes = _b32_decode(gpa.split(" ", 1)[1].strip())
    response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
    sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))
    # NORMAL entry: own login BINF echo, NO ITCP (no secondary at login).
    echo = reader.recv_until(
        lambda f: f.startswith("ITCP ") or f.startswith(f"BINF {sid}"),
        timeout=PROTOCOL_TIMEOUT_SEC,
    )
    if echo.startswith("ITCP "):
        raise TestFailure(
            f"login-time HBRI fired for a no-secondary login: {echo!r}"
        )
    return reader, sid


def test_hbri_postlogin_success():
    """#286 post-login HBRI happy path. An HBRI-capable client already in
    NORMAL state that LATER advertises a secondary via a post-login INF
    (I6::) is solicited for a side-channel WITHOUT being parked, and on
    validation the hub broadcasts the discovered secondary. sendtoall
    reaches the user's own connection, so the validated I6 lands on the
    main reader.

    Falsifiable: pre-#286 the post-login I6 is silently stripped and no
    ITCP is ever sent (the ITCP recv below fires)."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader, sid = _hbri_normal_login_capable(main)
        # Post-login INF newly advertising a v6 secondary (placeholder).
        main.sendall(f"BINF {sid} I6:: SUTCP4,TCP6\n".encode("utf-8"))
        itcp = reader.recv_until(
            lambda f: f.startswith("ITCP "), timeout=PROTOCOL_TIMEOUT_SEC
        )
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P6")
        if not token or not port:
            raise TestFailure(f"post-login ITCP missing TO / P6: {itcp!r}")
        side = socket.create_connection(
            ("::1", int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        side.sendall(f"HTCP I6:: TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 000"):
            raise TestFailure(
                f"expected ISTA 000 on the post-login side-channel, got {sta!r}"
            )
        # The validated secondary is now broadcast (the stripped post-login
        # echo carries no I6, so require I6::1 explicitly).
        reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") and "I6::1" in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_hbri_postlogin_failure_stays_stripped():
    """#286 post-login HBRI failure. If the side-channel never opens, the
    sweep times out the attempt; the user stays in NORMAL with the
    secondary unvalidated and NEVER broadcast (the #97/#222 strip
    invariant holds for the failed-HBRI case).

    Falsifiable: a hub that committed the secondary without validation
    leaks I6::1; a hub that dropped the user breaks the alive check."""
    main = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=20)
    try:
        reader, sid = _hbri_normal_login_capable(main)
        main.sendall(f"BINF {sid} I6:: SUTCP4,TCP6\n".encode("utf-8"))
        reader.recv_until(lambda f: f.startswith("ITCP "), timeout=PROTOCOL_TIMEOUT_SEC)
        # Do NOT open the side-channel. Sweep fails the attempt after
        # hbri_timeout; the user is told (ISTA 155) but stays connected.
        reader.recv_until(lambda f: f.startswith("ISTA 155"), timeout=18)
        # No validated secondary may ever be broadcast.
        leaked = None
        try:
            leaked = reader.recv_until(lambda f: "I6::1" in f, timeout=2)
        except TestFailure as e:
            if "timed out" not in str(e):
                raise
        if leaked is not None:
            raise TestFailure(
                f"secondary leaked after a failed post-login HBRI: {leaked!r}"
            )
        _assert_adc_alive(main)
    finally:
        try:
            main.close()
        except OSError:
            pass


def test_hbri_postlogin_no_resolicit_cooldown():
    """#286 loop guard. After a FAILED post-login HBRI the hub must not
    re-solicit on the very next INF update - a v6-broken dual-stack client
    re-emits its connectivity on every INF (share change, NAT rebind) and
    would otherwise eat an HBRI timeout each time. The per-user cooldown
    suppresses the immediate retry.

    Falsifiable: drop the cooldown and the second I6:: INF re-solicits an
    ITCP (the assert below fires)."""
    main = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=20)
    try:
        reader, sid = _hbri_normal_login_capable(main)
        main.sendall(f"BINF {sid} I6:: SUTCP4,TCP6\n".encode("utf-8"))
        reader.recv_until(lambda f: f.startswith("ITCP "), timeout=PROTOCOL_TIMEOUT_SEC)
        # Let it time out (no side-channel) -> fail arms the cooldown.
        reader.recv_until(lambda f: f.startswith("ISTA 155"), timeout=18)
        # Immediately re-advertise the secondary; the cooldown must block
        # a fresh solicit.
        main.sendall(f"BINF {sid} I6:: SUTCP4,TCP6\n".encode("utf-8"))
        resolicit = None
        try:
            resolicit = reader.recv_until(lambda f: f.startswith("ITCP "), timeout=3)
        except TestFailure as e:
            if "timed out" not in str(e):
                raise
        if resolicit is not None:
            raise TestFailure(
                f"post-login HBRI re-solicited within the cooldown window: {resolicit!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass


def test_hbri_timeout():
    """#214 HBRI timeout. If the client never opens the side-channel,
    the hub's sweep fails the attempt after hbri_timeout seconds, sends
    ISTA 155, and lets the client into the hub WITHOUT the unverified
    secondary (it stays stripped, per Gap 1).

    Falsifiable: a hub that committed the secondary without validation
    leaks I6 into the echo; a hub that never released the parked user
    never sends the BINF echo at all."""
    main = socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=20)
    try:
        reader, sid, itcp = _hbri_main_login(main)
        # Do NOT open the side-channel. The hub fails the attempt on the
        # ~1s sweep once hbri_timeout (5s) elapses: ISTA 155 first, then
        # the completed-login BINF echo (without I6). Worst case is ~6s;
        # the generous recv window keeps this robust under heavy CI load.
        sta = reader.recv_until(
            lambda f: f.startswith("ISTA 155") or f.startswith(f"BINF {sid}"),
            timeout=18,
        )
        if sta.startswith(f"BINF {sid}"):
            raise TestFailure(
                f"expected ISTA 155 (validation timed out) before login completed, got {sta!r}"
            )
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}"), timeout=PROTOCOL_TIMEOUT_SEC
        )
        params = echo.strip().split(" ")
        if any(p == "I6::1" for p in params):
            raise TestFailure(
                f"unverified secondary I6 leaked into the broadcast INF after timeout: {echo!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass


def test_hbri_unknown_token():
    """#214 HBRI: an HTCP on a fresh connection bearing a token the hub
    never minted is rejected with ISTA 220 and the socket closed. Stops
    a blind attacker from completing (or probing) someone else's HBRI
    validation."""
    side = socket.create_connection(
        ("::1", TEST_PORT_PLAIN_V6), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sreader = _ADCReader(side)
        side.sendall(b"HTCP I6::1 TOAAAAAAAAAAAAAAAA\n")
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 220"):
            raise TestFailure(
                f"expected ISTA 220 (unknown validation token), got {sta!r}"
            )
    finally:
        try:
            side.close()
        except OSError:
            pass


def test_hbri_disconnect_cleanup():
    """#214 HBRI: a client that is parked in the 'hbri' state and then
    drops its main connection (never validating) must be cleaned up
    without wedging the hub - the pending token is cancelled and the
    transient parked user torn down. Exercises the disconnect-mid-HBRI
    path (the cancel hook) and confirms the hub still serves a fresh
    login afterwards. The end-of-run 'no script errors' canary catches
    any crash in the teardown."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader, sid, itcp = _hbri_main_login(main)
        # Parked in 'hbri'; drop the main connection without validating.
    finally:
        try:
            main.close()
        except OSError:
            pass
    # The hub must remain healthy: a fresh normal login still succeeds.
    with _logged_in_user("dummy", "test") as (sock, sid2, reader2):
        _assert_adc_alive(sock)


def test_hbri_no_secondary_no_solicit():
    """#214 regression: a client that advertises ADHBRI but connects on
    one family WITHOUT a secondary (the common case - e.g. a v4-only
    AirDC++) must NOT be solicited for HBRI. It logs in immediately; no
    ITCP, no timeout delay.

    Guards the and/or-ternary trap (`(sec_fam=="I6") and inf_i6 or
    inf_i4`) that minted a bogus '0.0.0.0' secondary claim for every v4
    client sending only I4, making every such login eat the ~5s HBRI
    timeout. Caught via a live AirDC++ 4.30 test, missed by the other
    HBRI smoke tests because they all send a real I6.

    Falsifiable: on the buggy code the hub sends an ITCP right after
    HPAS (the assert below fires); on the fix the next frame is the
    login BINF echo."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader = _ADCReader(main)
        main.sendall(b"HSUP ADBASE ADTIGR ADHBRI\n")
        reader.recv_until(lambda f: f.startswith("ISUP "))
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))
        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        # v4 connection, ADHBRI advertised, NO I6 secondary - mirrors a
        # real v4 AirDC++ login (passive I40.0.0.0, SU TCP4/UDP4 only).
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NIdummy"
            f" I40.0.0.0 SUTCP4,UDP4\n"
        )
        main.sendall(binf.encode("utf-8"))
        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_bytes = _b32_decode(gpa.split(" ", 1)[1].strip())
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        main.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))
        # Promptly (well under hbri_timeout=5s) the hub must complete the
        # login with the BINF echo and must NEVER send an ITCP.
        frame = reader.recv_until(
            lambda f: f.startswith("ITCP ") or f.startswith(f"BINF {sid}"),
            timeout=3,
        )
        if frame.startswith("ITCP "):
            raise TestFailure(
                f"hub solicited HBRI for a client with NO secondary: {frame!r}. "
                f"A client advertising ADHBRI but no I6 must not be HBRI'd "
                f"(the and/or-ternary bogus-claim regression)."
            )
    finally:
        try:
            main.close()
        except OSError:
            pass


def test_hbri_wrong_family_rejected():
    """#294 (audit Tier-2): a VALID token presented over the WRONG IP
    family must be rejected. The side-channel family must be the opposite
    of the main connection; if a client (or attacker holding a token)
    connects the side-channel on the SAME family as the main connection,
    validate() rejects it with ISTA 155 and the secondary stays stripped.
    This is the anti-cross-family-spoof branch - previously only reasoned-
    correct, now exercised.

    The main login is v4 (secondary family I6). We open the side-channel
    on v4 (the WRONG family - same as main) carrying the real token; the
    hub sees vfam == main family != entry.family (I6) and rejects.

    The HTCP carries the PLACEHOLDER I6:: (not a concrete address) on
    purpose: a placeholder skips the address cross-check, so the ONLY
    branch that can reject is the family check. That makes this test
    falsifiable for the family check specifically - drop it and the hub
    would commit the v4 getpeername into the I6 field and answer ISTA 000
    (verified: the assert below then fires)."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader, sid, itcp = _hbri_main_login(main)
        token = _hbri_param(itcp, "TO")
        if not token:
            raise TestFailure(f"ITCP missing TO: {itcp!r}")
        # Connect the side-channel on v4 (same family as main) instead of
        # the expected v6, carrying the valid token + a placeholder I6.
        side = socket.create_connection(
            (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        side.sendall(f"HTCP I6:: TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 155"):
            raise TestFailure(
                f"expected ISTA 155 (validation on wrong IP protocol), got {sta!r}"
            )
        # The main login then completes WITHOUT the secondary. A
        # family-check regression would have committed the v4 getpeername
        # into the I6 field (I6<v4addr>); assert it never appears.
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}"), timeout=PROTOCOL_TIMEOUT_SEC
        )
        if f"I6{HUB_HOST}" in echo:
            raise TestFailure(
                f"v4 source leaked into the I6 field after a wrong-family validation: {echo!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_hbri_v4_secondary_direction():
    """#294 (audit Tier-2): the v6-main / v4-secondary direction. The CI
    suite otherwise only exercises v4-main / v6-secondary; this connects
    the main login over v6 advertising a v4 secondary, validates over a v4
    side-channel, and confirms the verified I4 is broadcast - covering the
    digit-'4' / advertise_v4 / I4-commit branch with no prior CI.

    Falsifiable: without the v4-secondary path the hub never sends the
    ITCP P4 pointer or never restores I4."""
    main = socket.create_connection(
        ("::1", TEST_PORT_PLAIN_V6), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader = _ADCReader(main)
        main.sendall(b"HSUP ADBASE ADTIGR ADHBRI\n")
        reader.recv_until(lambda f: f.startswith("ISUP "))
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))
        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        # Main connection on v6 (primary I6 = the v6 source); secondary is
        # a concrete v4 address that the side-channel source must match.
        binf = (
            f"BINF {sid} ID{cid_b32} PD{pid_b32} NIdummy"
            f" I6::1 I4{HUB_HOST} SUTCP4,TCP6\n"
        )
        main.sendall(binf.encode("utf-8"))
        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_bytes = _b32_decode(gpa.split(" ", 1)[1].strip())
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        main.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))
        itcp = reader.recv_until(
            lambda f: f.startswith("ITCP ") or f.startswith(f"BINF {sid}"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not itcp.startswith("ITCP "):
            raise TestFailure(
                f"expected an ITCP P4 pointer (v4 secondary), got {itcp!r}"
            )
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P4")
        if not token or not port:
            raise TestFailure(f"ITCP missing TO / P4 (v4 direction): {itcp!r}")
        side = socket.create_connection(
            (HUB_HOST, int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        side.sendall(f"HTCP I4{HUB_HOST} TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 000"):
            raise TestFailure(
                f"expected ISTA 000 on the v4 side-channel, got {sta!r}"
            )
        reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") and f"I4{HUB_HOST}" in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_hbri_postlogin_disconnect_cleanup():
    """#294 (audit Tier-2): a NORMAL-state client that solicited a
    post-login HBRI and then drops its main connection before validating
    must have its pending token cancelled (the disconnect cancel hook
    covers the post-login path too, not just the login-parked path). The
    hub stays healthy; the end-of-run no-script-errors canary catches any
    teardown crash."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader, sid = _hbri_normal_login_capable(main)
        main.sendall(f"BINF {sid} I6:: SUTCP4,TCP6\n".encode("utf-8"))
        reader.recv_until(lambda f: f.startswith("ITCP "), timeout=PROTOCOL_TIMEOUT_SEC)
        # Drop the main connection mid-validation (no side-channel opened).
    finally:
        try:
            main.close()
        except OSError:
            pass
    # The hub must remain healthy: a fresh normal login still succeeds.
    with _logged_in_user("dummy", "test") as (sock, sid2, reader2):
        _assert_adc_alive(sock)


def test_hbri_postlogin_concrete_mismatch_rejected():
    """#294 (audit Tier-2): the post-login path must also reject a CONCRETE
    secondary address that does not match the side-channel getpeername
    (the login-path concrete mismatch is covered by
    test_hbri_concrete_mismatch_rejected; this covers the post-login
    branch). The bogus secondary must not be broadcast."""
    main = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    side = None
    try:
        reader, sid = _hbri_normal_login_capable(main)
        # Post-login INF advertising a CONCRETE v6 secondary.
        main.sendall(f"BINF {sid} I62001:db8::beef SUTCP4,TCP6\n".encode("utf-8"))
        itcp = reader.recv_until(lambda f: f.startswith("ITCP "), timeout=PROTOCOL_TIMEOUT_SEC)
        token = _hbri_param(itcp, "TO")
        port = _hbri_param(itcp, "P6")
        if not token or not port:
            raise TestFailure(f"post-login ITCP missing TO / P6: {itcp!r}")
        side = socket.create_connection(
            ("::1", int(port)), timeout=PROTOCOL_TIMEOUT_SEC
        )
        sreader = _ADCReader(side)
        # Side-channel states the concrete address, but the real source is
        # ::1 - mismatch must be rejected.
        side.sendall(f"HTCP I62001:db8::beef TO{token}\n".encode("utf-8"))
        sta = sreader.recv_until(lambda f: f.startswith("ISTA "))
        if not sta.startswith("ISTA 155"):
            raise TestFailure(
                f"expected ISTA 155 (post-login concrete mismatch), got {sta!r}"
            )
        # The bogus secondary must never reach a broadcast.
        leaked = None
        try:
            leaked = reader.recv_until(lambda f: "2001:db8::beef" in f, timeout=2)
        except TestFailure as e:
            if "timed out" not in str(e):
                raise
        if leaked is not None:
            raise TestFailure(
                f"mismatched post-login secondary leaked into a broadcast: {leaked!r}"
            )
    finally:
        try:
            main.close()
        except OSError:
            pass
        if side:
            try:
                side.close()
            except OSError:
                pass


def test_post_login_i4_silent_stripped():
    """#222: post-login BINF carrying `I4 <new_ip>` MUST be silent-
    stripped, not killed. Pre-fix the `forbidden.flags_on_inf` check
    in `scripts/hub_inf_manager.lua` killed the user with `ISTA 240`
    + TL300; legitimate DC++ clients refreshing INF (e.g. after NAT
    rebind) were repeatedly bounced.

    Post-fix the I4 field is silent-stripped (broadcast carries no
    I4 update, stored `_inf` IP stays at the verified original); the
    other INF fields in the same update (here `DEnew-desc`) still
    get applied.

    Falsifiable: on unpatched code the test sees ISTA 240 + socket
    close, the `final` predicate hits the ISTA branch.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        # Drain any post-login state (own-BINF echo already consumed
        # by _adc_login). Send a post-login BINF update containing
        # I4 (a wrong-IP claim) + DE (a legitimate field update).
        update = (
            f"BINF {sid}"
            f" I4203.0.113.1"
            f" DEpost-login-i4-strip-test\n"
        )
        sock.sendall(update.encode("utf-8"))

        # Expect the broadcast echo of OUR update (BINF starting with
        # our SID) OR an ISTA reject. ISTA = pre-fix regression.
        echo = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if echo.startswith("ISTA "):
            raise TestFailure(
                f"#222 regression: post-login INF with I4 was rejected "
                f"with ISTA. The fix silent-strips I4/I6 instead of "
                f"killing the user. Got: {echo!r}"
            )
        # Broadcast must NOT contain the wrong-IP claim (stripped).
        if "I4203.0.113.1" in echo:
            raise TestFailure(
                f"#222 regression: post-login broadcast carries the "
                f"client's I4 claim. The fix strips I4 from the cmd "
                f"before broadcast. Echo: {echo!r}"
            )
        # The other field (DE update) MUST be in the broadcast,
        # proving the strip is targeted to I4/I6 only. Note that
        # the bundled `usr_desc_prefix` plugin prepends the user's
        # level label (e.g. `[\sHUBOWNER\s]\s`) to the DE value, so
        # we substring-match the unique marker instead of the
        # exact `DE...=value` form.
        if "post-login-i4-strip-test" not in echo:
            raise TestFailure(
                f"#222 regression: legitimate non-IP INF field (DE) "
                f"was not broadcast. The strip must be targeted to "
                f"I4/I6 only - other fields stay. Echo: {echo!r}"
            )


def test_neg_repeated_binf_burst():
    """Send 30 BINFs back-to-back on a single connection before any HPAS.
    Goal: stress the parse() reentrancy fix (Phase 7d, #65) and any
    per-connection state churn under burst INF traffic."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, sid = _neg_handshake_get_sid(sock)
        for i in range(30):
            cid_b32, pid_b32 = _neg_random_pid_cid_pair()
            binf = (
                f"BINF {sid} ID{cid_b32} PD{pid_b32}"
                f" NIburst{i} I40.0.0.0 SUTCP4\n"
            )
            try:
                sock.sendall(binf.encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                # Hub disconnected mid-burst; that is an acceptable
                # rate-limit response.
                return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_command_before_handshake():
    """Send a BMSG before any HSUP. The hub's state-machine must reject
    the out-of-order command; specifically must not attribute the message
    to an uninitialised user record."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        try:
            sock.sendall(b"BMSG AAAA hello-from-pre-handshake-state\n")
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_hpas_before_binf():
    """Send HPAS immediately after HSUP, before any BINF. The hub does not
    have a salt for us yet - the password-state machine must reject."""
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        _reader, _sid = _neg_handshake_get_sid(sock)
        # 32 zero bytes b32-encoded - syntactically valid base32, but
        # there's no HPAS challenge in flight yet.
        bogus = _b32_encode(b"\x00" * 32)
        try:
            sock.sendall(f"HPAS {bogus}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)
    finally:
        sock.close()


def test_neg_post_login_oversized_msg():
    """After a clean login, send a 70 KiB BMSG. Phase 7d's 64 KiB
    command-size cap (#65) should engage; the hub must close the
    connection without throwing a Lua error."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return  # login failed before we even try the negative; not our bug
        oversized = "X" * 70000
        try:
            sock.sendall(f"BMSG {sid} {oversized}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)


def test_neg_post_login_oversized_search():
    """After a clean login, send an oversized BSCH (5 KiB token list).
    Search dispatch must not buffer the entire payload into a Lua string
    that overruns any per-field cap."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        # Each AN<token> is 12 bytes; 400 of them = ~5 KiB. Well under the
        # 64 KiB total cap, but a flood of named parameters in one frame.
        tokens = " ".join(f"AN{'q' * 8}{i:03d}" for i in range(400))
        try:
            sock.sendall(f"BSCH {sid} {tokens}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        _neg_drain_briefly(sock)


def test_neg_post_login_search_burst():
    """After a clean login, fire 50 BSCH commands back-to-back. Should be
    rate-limited (per-user search rate) or silently absorbed; must not
    produce a Lua error from churned listener state."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"BSCH {sid} ANqt{i}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_inf_burst():
    """After a clean login, fire 50 BINF updates back-to-back. Tests that
    the INF bucket (#80) absorbs share-state-update floods without
    crashing the dispatcher. The first ~burst go through to onInf
    listeners, the rest are silently dropped by rl_inf_drop. Hub must
    stay alive."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                # Vary SS (share size) to look like a watch-folder
                # churning files in / out - the legitimate-use case the
                # bucket is sized to tolerate up to its burst.
                sock.sendall(
                    f"BINF {sid} SS{1000 + i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_pm_burst():
    """After a clean login, fire 50 DMSG private messages back-to-back
    at our OWN sid (self-target). Self-target is accepted by incoming()
    (mysid == usersid check passes, targetuser is non-nil) so the
    dispatcher actually reaches the _normal.DMSG handler and the
    rl_pm_drop rate-limit gate. Targeting a non-existent SID like ZZZZ
    instead would short-circuit at hub.lua:1264 with ISTA 140 BEFORE
    dispatch, defeating the test's purpose. Tests that the PM bucket
    (#80 split from msg) rate-limits / absorbs without crashing the
    dispatcher."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(
                    f"DMSG {sid} {sid} hello{i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_ctm_burst():
    """After a clean login, fire 50 DCTM commands at our own SID
    (self-target). See PM burst test above for why we self-target
    instead of using a non-existent SID. Confirms the #80 CTM bucket
    absorbs a connection-setup flood without crashing the dispatcher
    and actually reaches the rl_ctm_drop gate."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"DCTM {sid} {sid} ADC/1.0 12345 tok{i}\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_post_login_rcm_burst():
    """After a clean login, fire 50 DRCM commands at our own SID.
    DRCM shares the CTM bucket since both are peer-connection
    initiation primitives. Tests the second code path through
    rl_ctm_drop."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            try:
                sock.sendall(f"DRCM {sid} {sid} ADC/1.0\n".encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_post_login_search_result_listener_chain():
    """#160 defense-in-depth: send a small burst of DRES and FRES
    after login so the etc_trafficmanager onSearchResult listener
    runs end-to-end at least once. The listener bodies do
    `user:level() < masterlevel` guards plus need_block() checks;
    we exercise the path so any syntax/upvalue regression in the
    new listener (or a sibling plugin that hooks onSearchResult)
    surfaces here rather than in production.

    Assertion is indirect via the existing test_no_script_errors
    canary at end of run - a hub script-error during onSearchResult
    dispatch would land in error.log and fail that check.
    """
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        # Send 5 DRES (D-class single-target result) + 5 FRES
        # (F-class feature-filtered result). Targets are our own
        # SID for D-class; FRES has no explicit target SID.
        # TR is the TigerTree hash - ADC enforces exactly 39 chars
        # from [A-Z2-7] (core/adc.lua:155). Build the value as 38
        # fixed chars + one digit-suffix in 2..6 (range 2,7) to
        # stay inside the alphabet AND the length cap. A length
        # or alphabet mismatch makes the parser drop the frame
        # silently (event.log, not error.log) and the listener
        # would never fire - the test would pass for the wrong
        # reason without exercising the new onSearchResult path.
        for i in range(2, 7):
            try:
                sock.sendall(
                    f"DRES {sid} {sid} FNself.txt SI100 TR{'A'*38}{i}\n".encode("utf-8")
                )
                sock.sendall(
                    f"FRES {sid} +ADC0 FNself{i}.txt SI100 TR{'B'*38}{i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_hqui_from_client_honored():
    """ADC 6.3.10: client-initiated HQUI must be honored - hub closes
    the connection cleanly without replying ISTA 125 (unknown command).
    Before T1.7 of #147 the parser accepted HQUI but the dispatcher
    had no entry, so the hub answered with the catch-all unknown-
    command STA instead of treating QUI as a polite goodbye."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        try:
            sock.sendall(f"HQUI {sid}\n".encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        # Drain whatever the hub still has buffered for us before the
        # close. Should be empty or contain only normal logout
        # broadcasts, never ISTA 125.
        sock.settimeout(2.0)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, TimeoutError):
            raise TestFailure(
                "hub did not close socket within 2s after HQUI; "
                "T1.7 dispatcher likely not wired correctly"
            )
        if b"ISTA 125" in buf:
            raise TestFailure(
                f"hub rejected client HQUI as unknown command "
                f"(ISTA 125 in tail): {buf[:200]!r}"
            )


def test_neg_post_login_natt_burst():
    """After a clean login, fire 50 mixed DNAT / DRNT commands (ADC-EXT
    NATT, T1.1 of #147) at our own SID. Both new dispatch routes
    share the CTM bucket (peer-connection setup); confirms NATT relay
    absorbs floods the same way DCTM / DRCM do without crashing and
    actually reaches the rl_ctm_drop gate."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        try:
            sid, _reader = _adc_login(sock, "dummy", "test")
        except TestFailure:
            return
        for i in range(50):
            # Alternate the two new commands so the test exercises both
            # dispatch paths through rl_ctm_drop, not just one.
            cmd = "DNAT" if i % 2 == 0 else "DRNT"
            try:
                sock.sendall(
                    f"{cmd} {sid} {sid} ADC/1.0 12345 tok{i}\n".encode("utf-8")
                )
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
        _neg_drain_briefly(sock)


def test_neg_canary_hub_alive():
    """After the negative-test battery, the hub must still accept a clean
    login. This is the canary that catches any of the above tests having
    crashed or destabilised the hub - if the canary fails, walk the
    failed-tests list above and re-run individually to find the offender.

    The negative-test battery burns through per-IP connection-rate budget
    (default ratelimit_perip_conn_burst = 30, refill 10/sec). Sleep up
    front so the bucket has time to refill - we want to test "hub still
    works", not "hub still rate-limits us". Retry the connect a couple
    of times in case the bucket needs a moment more."""
    time.sleep(3)
    last_err = None
    for attempt in range(5):
        try:
            with socket.create_connection(
                (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
            ) as sock:
                sid, _reader = _adc_login(sock, "dummy", "test")
                if not sid or len(sid) != 4:
                    raise TestFailure(
                        f"hub did not accept clean login after "
                        f"negative-test battery; got SID {sid!r}"
                    )
                return
        except (OSError, TestFailure) as e:
            last_err = e
            time.sleep(1.0)
    raise TestFailure(
        f"hub did not accept clean login after 5 retries spanning "
        f"~8 seconds post-fuzz-battery; last error: {last_err!r}"
    )


def test_setpass_preserves_encryption(staging_dir: Path):
    """#92 regression: cmd_setpass must persist user.tbl through the
    encrypted cfg.saveusers() path, not bypass it via util.savearray().
    Pre-fix, every +setpass invocation rewrote user.tbl as plaintext
    Lua source, silently undoing the Phase 7f F-AUTH-1 mitigation.

    Drive a real +setpass from the dummy login, verify the on-disk
    user.tbl still carries the LDC1 magic, and confirm by re-login
    that the new password actually took effect (catches silent no-ops
    that would leave LDC1 magic unchanged from the prior HPAS save).

    The new password must satisfy the default min_password_length=10
    so cmd_setpass does not bail out at the length check before saving.
    No subsequent test logs in as dummy, so we do not reset; staging
    is rebuilt per harness run anyway."""
    new_pass = "smoketestnew"  # 12 chars; passes min_password_length=10
    user_tbl = staging_dir / "cfg" / "user.tbl"

    # ADC BMSG body: spaces inside the message are escaped as `\s` so
    # the parser treats the whole thing as one positional parameter.
    # Without escaping, "+setpass nick myself smoketestnew" arrives at
    # the script as `parameters=""` (only the leading "+setpass" lands
    # in adccmd[6]) and the command silently no-ops.
    body = _adc_escape(f"+setpass nick myself {new_pass}")

    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(f"BMSG {sid} {body}\n".encode("utf-8"))
        # cmd_setpass replies via user:reply(...), which goes out as
        # private chat (E or D type) from the hubbot. Wait for it so
        # we know the script's save path has executed.
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )

    head = user_tbl.read_bytes()[:4]
    if head != b"LDC1":
        raise TestFailure(
            f"user.tbl bypassed encryption after +setpass (head={head!r}); "
            f"#92 regression: cmd_setpass writes plaintext via util.savearray"
        )

    # Confirm cmd_setpass actually persisted the new password (the LDC1
    # magic alone is also produced by the prior HPAS save, so without
    # this the test could pass even with a silent no-op).
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        try:
            _adc_login(sock, "dummy", new_pass)
        except TestFailure as e:
            raise TestFailure(
                f"+setpass did not actually change the password (re-login "
                f"with new value rejected): {e}"
            )

    # Give the hub a moment to flush the disconnect-driven cfg.saveusers
    # so the next disk-state test does not race the io_open("wb") +
    # f:write cycle and observe a transiently empty user.tbl.
    time.sleep(0.5)


def test_usertbl_bak_atomic_refresh(staging_dir: Path):
    """Closes upstream luadch#189: previously user.tbl.bak only got
    refreshed at hub start / +reload, so a corrupted user.tbl would
    fall back to a weeks-old snapshot and silently lose recent regs.

    saveusers() now writes user.tbl atomically (.tmp + rename) and
    immediately mirrors the same on-disk bytes to user.tbl.bak. After
    every successful save the two files should be byte-identical and
    both carry the LDC1 encrypted-at-rest magic. The prior tests in
    this run have driven multiple saveusers calls (HPAS lastconnect
    updates + the +setpass test), so by the time this test runs both
    files exist and reflect the latest save."""
    cfg_dir = staging_dir / "cfg"
    user_tbl = cfg_dir / "user.tbl"
    user_tbl_bak = cfg_dir / "user.tbl.bak"

    if not user_tbl_bak.exists():
        raise TestFailure(f"user.tbl.bak missing at {user_tbl_bak}")
    if user_tbl_bak.read_bytes()[:4] != b"LDC1":
        raise TestFailure(f"user.tbl.bak is not encrypted at rest")

    # Same bytes -> same nonce -> same blob -> byte-equal files.
    # saveusers() builds the encrypted blob once and writes it to both
    # paths, so this is the strict equality check we want.
    if user_tbl.read_bytes() != user_tbl_bak.read_bytes():
        raise TestFailure(
            "user.tbl and user.tbl.bak diverged - .bak refresh after "
            "saveusers is not running atomically"
        )


def test_cert_autogen_first_boot(staging_dir: Path):
    """Closes #77: the hub auto-generates a self-signed P-256 ECDSA
    cert + key on first boot when none exist on disk. The smoke
    harness setup intentionally skips the legacy
    `make_cert.{sh,bat}` pre-gen step, so by the time the prior
    tests' TLS handshakes succeeded, the cert was generated by
    core/cert_bootstrap.lua.

    This test asserts the on-disk shape of the auto-generated
    artifacts: both files exist, both are PEM-formatted, the
    cert has plausible size (an ECDSA self-signed cert with a
    short CN is in the few-hundred-byte range), and the cert
    parses cleanly through Python's `ssl` module."""
    cert_path = staging_dir / "certs" / "servercert.pem"
    key_path = staging_dir / "certs" / "serverkey.pem"

    if not cert_path.exists():
        raise TestFailure(f"hub did not auto-generate cert at {cert_path}")
    if not key_path.exists():
        raise TestFailure(f"hub did not auto-generate key at {key_path}")

    cert_bytes = cert_path.read_bytes()
    key_bytes = key_path.read_bytes()

    if not cert_bytes.startswith(b"-----BEGIN CERTIFICATE-----"):
        raise TestFailure(
            f"servercert.pem is not PEM (head={cert_bytes[:40]!r})"
        )
    # OpenSSL 3.x's PEM_write_bio_PrivateKey emits PKCS#8 format with
    # a generic "PRIVATE KEY" header, regardless of the underlying
    # algorithm. Older PEM_write_bio_ECPrivateKey used "EC PRIVATE
    # KEY"; we accept either so a future API switch (or a build
    # against legacy OpenSSL) does not cause a false failure here.
    if not (
        key_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
        or key_bytes.startswith(b"-----BEGIN EC PRIVATE KEY-----")
    ):
        raise TestFailure(
            f"serverkey.pem is not PEM (head={key_bytes[:40]!r})"
        )

    # Sanity range: a P-256 self-signed cert is ~400-700 bytes.
    if not (200 < len(cert_bytes) < 4096):
        raise TestFailure(
            f"servercert.pem size out of plausible range: {len(cert_bytes)} bytes"
        )

    # Parse the cert - if it's malformed, ssl will raise and the test
    # fails with a useful traceback rather than just "looks like PEM."
    import ssl as _ssl_check
    try:
        ctx = _ssl_check.SSLContext(_ssl_check.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cert_bytes.decode("ascii"))
    except Exception as e:
        raise TestFailure(f"servercert.pem failed to parse via ssl module: {e}")


def test_usertbl_encrypted_at_rest(staging_dir: Path):
    """Phase 7f F-AUTH-1: user.tbl on disk must start with the LDC1 magic
    after the hub has had any reason to save it (HPAS lastconnect update
    runs every login). master.key must exist with the AES-256 key size.

    We rely on the prior tests having logged in dummy/test (forces a
    saveusers via the HPAS handler), so by the time this runs user.tbl
    is in the encrypted format."""
    cfg_dir = staging_dir / "cfg"
    user_tbl = cfg_dir / "user.tbl"
    master_key = cfg_dir / "master.key"
    if not master_key.exists():
        raise TestFailure(f"master.key missing at {master_key}")
    key_bytes = master_key.read_bytes()
    if len(key_bytes) != 32:
        raise TestFailure(f"master.key size {len(key_bytes)}; expected 32")
    if not user_tbl.exists():
        raise TestFailure(f"user.tbl missing at {user_tbl}")
    head = user_tbl.read_bytes()[:4]
    if head != b"LDC1":
        raise TestFailure(
            f"user.tbl is not encrypted at rest (head={head!r}); "
            f"expected LDC1 magic prefix"
        )


# Plaintext user.tbl with the bundled dummy/test reg. Used by the
# #128 plaintext-mode test setup to install a known-good baseline
# after wiping master.key (the existing encrypted user.tbl can no
# longer decrypt without the key). Format mirrors examples/cfg/user.tbl.
_DUMMY_USERTBL_PLAINTEXT = (
    b"\xef\xbb\xbfreturn {\n\n"
    b"    { badpassword = 0, lastconnect = 0, level = 100, "
    b'nick = "dummy", password = "test", rank = "2", },\n\n'
    b"}\n"
)


def _switch_to_plaintext_mode(staging_dir: Path, current_proc, current_log_file):
    """#128 setup: stop the encryption-enabled hub, flip encrypt_usertbl
    to false in cfg.tbl, install a fresh plaintext user.tbl baseline,
    wipe master.key, restart. Returns the new (proc, log_file) so
    main() can clean up regardless of whether the subsequent
    assertions pass."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Target the *setting line* specifically (trailing comma); a more
    # permissive pattern would also match the explanatory comment
    # text "encrypt_usertbl = true." inside the doc block above the
    # actual key.
    text, n = re.subn(
        r"^\s*encrypt_usertbl\s*=\s*true\s*,",
        "    encrypt_usertbl = false,",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not flip encrypt_usertbl to false in cfg.tbl - "
            "the toggle line was not found in the staging tree"
        )
    cfg_path.write_text(text, encoding="utf-8")

    # Sanity check that the *setting line* (not just the comment) now
    # reads false.
    after = cfg_path.read_text(encoding="utf-8")
    if not re.search(r"^\s*encrypt_usertbl\s*=\s*false\s*,",
                     after, flags=re.MULTILINE):
        raise TestFailure(
            "cfg.tbl edit did not persist - the encrypt_usertbl setting "
            "line is not false after the rewrite"
        )

    # Wipe master.key so cfg_secret.init() runs the no-key path on
    # the second start (and we can verify it does NOT regenerate).
    (staging_dir / "cfg" / "master.key").unlink(missing_ok=True)

    # Install a known-good plaintext user.tbl. The current staging
    # user.tbl is AES-encrypted (the first hub rewrote it during the
    # encrypted-mode tests) and master.key is now gone, so it can no
    # longer decrypt. Without a usable user.tbl the dummy/test login
    # below would fail.
    (staging_dir / "cfg" / "user.tbl").write_bytes(_DUMMY_USERTBL_PLAINTEXT)
    # Wipe .bak so saveusers writes both files fresh in the new
    # plaintext format.
    (staging_dir / "cfg" / "user.tbl.bak").unlink(missing_ok=True)

    # Linux kernels can hold the listening sockets in TIME_WAIT for a
    # moment after SIGTERM even with SO_REUSEADDR - the previous start
    # in this same staging tree was bound here. A short sleep avoids
    # racing the kernel cleanup.
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_usertbl_plaintext_when_disabled(staging_dir: Path, proc=None):
    """#128 assertions: with encrypt_usertbl=false in cfg.tbl and a
    fresh staging tree, completing a login must write user.tbl as
    plaintext Lua source (no LDC1 magic) and must NOT auto-generate
    a master.key. Caller is responsible for putting the hub into
    plaintext mode via _switch_to_plaintext_mode() first."""
    try:
        wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    except TimeoutError as e:
        # Hub never bound the port. Surface every diagnostic we can
        # pull so CI shows what the second instance was doing rather
        # than just "timed out".
        diag = ""
        if proc is not None:
            rc = proc.poll()
            diag += f"\nproc.poll() = {rc!r} (None == still running)"
        for fname in ("smoke-hub.log", "error.log"):
            path = staging_dir / "log" / fname
            try:
                size = path.stat().st_size if path.exists() else "missing"
                content = path.read_text(encoding="utf-8", errors="replace") \
                    if path.exists() else ""
                tail = "\n".join(content.splitlines()[-40:])
                diag += f"\n--- {fname} (size={size}, last 40 lines) ---\n{tail}"
            except OSError as oe:
                diag += f"\n--- {fname} (read failed: {oe}) ---"
        # cfg.tbl: check that the toggle edit landed.
        try:
            cfg = (staging_dir / "cfg" / "cfg.tbl").read_text(encoding="utf-8")
            for i, line in enumerate(cfg.splitlines(), 1):
                if "encrypt_usertbl" in line:
                    diag += f"\ncfg.tbl:{i}: {line!r}"
        except OSError:
            pass
        raise TestFailure(f"{e}{diag}")

    # Trigger a save by completing a login; the HPAS handler updates
    # lastconnect on the registered user record and that forces
    # saveusers.
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        _adc_login(sock, "dummy", "test")

    # Give the post-login save path a moment to flush.
    time.sleep(0.5)

    user_tbl = staging_dir / "cfg" / "user.tbl"
    if not user_tbl.exists():
        raise TestFailure(
            "user.tbl missing after login under encrypt_usertbl=false; "
            "save path should have written it as plaintext"
        )

    head = user_tbl.read_bytes()[:4]
    if head == b"LDC1":
        raise TestFailure(
            "user.tbl has LDC1 magic despite encrypt_usertbl=false; "
            "saveusers wrote an encrypted blob - the toggle is not "
            "wired through to the write path"
        )

    # cfg_secret should NOT have generated a master.key when
    # encryption is disabled.
    master_key = staging_dir / "cfg" / "master.key"
    if master_key.exists():
        raise TestFailure(
            "master.key was generated despite encrypt_usertbl=false; "
            "cfg_secret.init() bypass for the disabled path is broken"
        )


def _switch_to_tier_mode(staging_dir: Path, current_proc, current_log_file):
    """#80 PR4 setup: stop the hub, append a strict-tier definition for
    level 100 (dummy) to cfg.tbl, bump bypass_level above 100 so the
    op-bypass does not skip the check, restart. Returns the new
    (proc, log_file) so main() can clean up regardless of whether the
    subsequent assertions pass."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    # Append the three keys just before the final closing brace. The
    # bundled cfg.tbl has no ratelimit_* lines at all (it inherits the
    # defaults from core/cfg_defaults.lua), so this is purely additive
    # - we are not editing an existing setting line.
    tier_block = (
        "\n    -- inserted by smoke harness for the tier-overlay test\n"
        "    ratelimit_bypass_level = 200,\n"
        '    ratelimit_tier_for_level = { [100] = "strict" },\n'
        '    ratelimit_tiers = { strict = { msg_burst = 2, msg_rate = 0.1 } },\n'
    )
    new_text, n = re.subn(
        r"(\n)\}\s*$",
        tier_block + r"\1}\n",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not inject tier block into cfg.tbl - the final "
            "closing brace was not found at the end of the file"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    # Same TIME_WAIT consideration as the plaintext-mode switch above.
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_ratelimit_tier_msg_throttle(staging_dir: Path, proc=None):
    """#80 PR4 assertion: with bypass_level=200 and a tier mapping
    level 100 -> { msg_burst=2 }, dummy (level 100) sending 5 BMSGs in
    rapid succession should see exactly 2 broadcasts echoed back. The
    other 3 are dropped at the hub by rl_msg_drop because the bucket
    is exhausted and the rate is too low (0.1/s) for any refill in the
    test's wall-clock duration. Confirms the tier overlay actually
    replaces the global msg_burst=10 scalar instead of silently falling
    back to it. Caller is responsible for putting the hub into tier
    mode via _switch_to_tier_mode() first."""
    try:
        wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    except TimeoutError as e:
        diag = ""
        if proc is not None:
            rc = proc.poll()
            diag += f"\nproc.poll() = {rc!r} (None == still running)"
        for fname in ("smoke-hub.log", "error.log"):
            path = staging_dir / "log" / fname
            try:
                size = path.stat().st_size if path.exists() else "missing"
                content = path.read_text(encoding="utf-8", errors="replace") \
                    if path.exists() else ""
                tail = "\n".join(content.splitlines()[-40:])
                diag += f"\n--- {fname} (size={size}, last 40 lines) ---\n{tail}"
            except OSError as oe:
                diag += f"\n--- {fname} (read failed: {oe}) ---"
        raise TestFailure(f"{e}{diag}")

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test")
        # Unique per-test marker so we don't collide with anything else
        # the hub may be broadcasting on this connection.
        marker = "tiertest" + secrets.token_hex(4)
        for i in range(5):
            sock.sendall(f"BMSG {sid} {marker}{i}\n".encode("utf-8"))
        # Give the hub a moment to dispatch + echo whatever it accepts.
        time.sleep(0.5)
        sock.settimeout(0.5)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, TimeoutError):
            pass
        echoes = sum(1 for i in range(5) if f"{marker}{i}".encode() in buf)
        if echoes != 2:
            raise TestFailure(
                f"tier overlay did not throttle BMSG as expected: "
                f"with msg_burst=2 in the strict tier for level 100, "
                f"5 BMSGs should produce exactly 2 echoes, got {echoes}. "
                f"Either the tier mapping never resolved (fallback to "
                f"global msg_burst=10 = all 5 echo) or the bypass-level "
                f"check let dummy through (level 100 should NOT bypass "
                f"with bypass_level=200). Buffer sample: {buf[:200]!r}"
            )


def _switch_to_dual_stack_same_port_mode(staging_dir: Path, current_proc, current_log_file):
    """#107 setup: stop the hub, flip tcp_ports_ipv6 and ssl_ports_ipv6
    to the same port numbers as their v4 counterparts so the next test
    can verify the (port, family)-keyed _server registry binds both
    listeners without "already exist" errors. Returns the new
    (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    # Reuse the v4 ports for v6 - the whole point of the fix is that
    # this layout is now legal.
    rewrites = [
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}",
         f"tcp_ports_ipv6 = {{ {TEST_PORT_PLAIN} }}"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}",
         f"ssl_ports_ipv6 = {{ {TEST_PORT_TLS} }}"),
    ]
    for pattern, replacement in rewrites:
        new_text, n = re.subn(pattern, replacement, text, count=1)
        if n != 1:
            raise TestFailure(
                f"could not flip {pattern} to same-as-v4 in cfg.tbl"
            )
        text = new_text
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_dual_stack_same_port_binds(staging_dir: Path, proc=None):
    """#107 regression: with tcp_ports_ipv6 set to the same port number
    as tcp_ports, both v4 and v6 listeners must bind successfully (the
    _server registry is now (port, family)-keyed). Pre-fix the second
    addserver() call hit the existence check on the port and refused
    to bind, leaving the hub v4-only.

    Assertions:
    1. The v4 listener is reachable on 127.0.0.1:TEST_PORT_PLAIN.
    2. The v6 listener is reachable on ::1:TEST_PORT_PLAIN (same port).
    3. A handshake on each completes - confirms the listeners are
       actually wired, not just bound. The v6 listener has its own
       _server registry entry under the composite (port, "ipv6") key.
    4. The hub log does not contain "listeners on port ... already
       exist" - which would mean the existence check fired and one
       of the two never bound.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    # Resolve ::1 explicitly so getaddrinfo on Windows + Linux both
    # use the IPv6 loopback path (not 127.0.0.1).
    deadline = time.monotonic() + START_TIMEOUT_SEC
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("::1", TEST_PORT_PLAIN), timeout=0.5):
                break
        except OSError as e:
            last_err = e
            time.sleep(0.2)
    else:
        raise TestFailure(
            f"v6 listener did not open on [::1]:{TEST_PORT_PLAIN}; "
            f"last error: {last_err}"
        )

    # Quick handshake on both. The hub's HSUP handler is family-
    # agnostic so the assertions are identical; we just want to prove
    # the bytes flow.
    for host_label, host in (("v4", HUB_HOST), ("v6", "::1")):
        with socket.create_connection((host, TEST_PORT_PLAIN), timeout=2) as s:
            s.sendall(b"HSUP ADBASE ADTIGR\n")
            buf = b""
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and b"\nIINF " not in buf:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
            if b"ISUP " not in buf:
                raise TestFailure(
                    f"no ISUP frame received on {host_label} "
                    f"({host}:{TEST_PORT_PLAIN}); buf={buf[:200]!r}"
                )

    # Belt-and-suspenders: scan the hub log for the existence-check
    # error string. If either of the two addserver() calls had hit
    # the check, the hub would have logged it during startup.
    log_path = staging_dir / "log" / "smoke-hub.log"
    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "already exist" in text:
            # Filter to lines from THIS run's startup
            offending = [
                line for line in text.splitlines()
                if "already exist" in line
            ]
            raise TestFailure(
                f"hub log contains 'already exist' line(s) - the "
                f"existence check fired:\n  " +
                "\n  ".join(offending[:3])
            )


_HUBBOT_EMAIL_MARKER = "escq423mark"


def _switch_to_hubbot_email_mode(staging_dir: Path, current_proc, current_log_file):
    """#423 setup: enable hub_bot_email and set hub_email to a value carrying a
    backslash + marker, then restart. The hub bot's BINF builds an EM field
    from hub_email; if that value is not escaped, the backslash is an unknown
    ADC escape and (since #419) the hub discards its OWN hub-bot INF - so the
    bot never comes up. Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # cfg.tbl is Lua: a backslash in a string literal is written "\\" (two
    # bytes), which Lua reads as one backslash. Build the file bytes explicitly
    # and use a callable replacement so re does not reinterpret the backslashes.
    lua_value = _HUBBOT_EMAIL_MARKER + "\\\\qmail"    # file bytes: escq423mark\\qmail -> Lua value has one backslash
    text, n1 = re.subn(
        r'^\s*hub_email\s*=\s*"[^"]*"\s*,',
        lambda m: f'    hub_email = "{lua_value}",',
        text, count=1, flags=re.MULTILINE,
    )
    text, n2 = re.subn(
        r"^\s*hub_bot_email\s*=\s*false\s*,",
        "    hub_bot_email = true,",
        text, count=1, flags=re.MULTILINE,
    )
    if n1 != 1 or n2 != 1:
        raise TestFailure(
            f"could not set hub_email / hub_bot_email in cfg.tbl "
            f"(hub_email n={n1}, hub_bot_email n={n2})"
        )
    cfg_path.write_text(text, encoding="utf-8")
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_hubbot_email_escaped(staging_dir: Path, proc=None):
    """#423 regression: with hub_bot_email=true and a hub_email carrying a
    backslash, the hub bot's EM field must be ESCAPED so the hub-bot INF is
    valid. Pre-fix the value was concatenated raw, so (since #419) the hub
    discards its own hub-bot INF as an unknown escape and the bot never loads.
    createbot builds + parses the INF at boot, so we assert parse() logged no
    'unknown escape' discard for the marker hub-bot INF."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    time.sleep(0.5)
    log_path = staging_dir / "log" / "event.log"
    txt = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    bad = [
        ln for ln in txt.splitlines()
        if "unknown escape" in ln and _HUBBOT_EMAIL_MARKER in ln
    ]
    if bad:
        raise AssertionError(
            f"the hub-bot INF was discarded as an unknown escape - hub_email "
            f"must be escaped in the EM field (#423). Line: {bad[0][:180]!r}"
        )


def _switch_to_hub_listen_loopback_mode(staging_dir: Path, current_proc, current_log_file):
    """#186 setup: stop the hub, set hub_listen to loopback-only and
    blank the IPv6 port arrays (a v4-only bind address yields no IPv6
    listener by design - blanking them keeps the test about the v4
    bind-restriction and avoids a noisy expected v6 bind failure).
    Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    rewrites = [
        (r'hub_listen\s*=\s*\{[^}]*\}', 'hub_listen = { "127.0.0.1" }'),
        (r"tcp_ports_ipv6\s*=\s*\{[^}]*\}", "tcp_ports_ipv6 = { }"),
        (r"ssl_ports_ipv6\s*=\s*\{[^}]*\}", "ssl_ports_ipv6 = { }"),
    ]
    for pattern, replacement in rewrites:
        new_text, n = re.subn(pattern, replacement, text, count=1)
        if n != 1:
            raise TestFailure(
                f"could not apply {pattern!r} in cfg.tbl (is hub_listen "
                f"present in examples/cfg/cfg.tbl?)"
            )
        text = new_text
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_hub_listen_honored(staging_dir: Path, proc=None):
    """#186 regression: with hub_listen = { "127.0.0.1" } the ADC
    listener MUST bind loopback only. Pre-fix, server.addserver bound
    p.addr (never p.ip) so hub_listen was silently ignored and the hub
    bound 0.0.0.0 regardless - an exposure for any operator who set a
    bind restriction. This test FAILS pre-fix (reachable off-loopback)
    and PASSES post-fix.

    1. ADC handshake on 127.0.0.1:<plain> still works.
    2. The same port is NOT reachable on this host's non-loopback
       IPv4 (skipped only if the env has no routable non-loopback
       address - never failed spuriously).
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(b"HSUP ADBASE ADTIGR\n")
        reader = _ADCReader(s)
        reader.recv_until(lambda f: f.startswith("ISUP "))

    nonloop = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no packets; resolves local addr
            cand = probe.getsockname()[0]
        finally:
            probe.close()
        if cand and not cand.startswith("127.") and cand != "0.0.0.0":
            nonloop = cand
    except OSError:
        nonloop = None
    if nonloop:
        try:
            c = socket.create_connection((nonloop, TEST_PORT_PLAIN), timeout=2)
            c.close()
            raise TestFailure(
                f"SECURITY: ADC listener reachable on non-loopback "
                f"{nonloop}:{TEST_PORT_PLAIN} despite hub_listen = "
                f'{{ "127.0.0.1" }} (#186: hub_listen ignored).'
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # expected: refused/unreachable off-loopback
    else:
        log("  (skip non-loopback check: no non-loopback IPv4)")


def _read_first_token_from_file(token_path: Path) -> str:
    """Parse the bootstrap-sample file (`cfg/api_token.first`) written
    by `bootstrap_first_token`. The file starts with comment lines
    (prefix `#`); the first non-comment non-blank line is the token.
    Raises TestFailure if the file is missing or empty."""
    if not token_path.exists():
        raise TestFailure(f"expected sample token file at {token_path}, not present")
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    raise TestFailure(f"sample token file {token_path} has no non-comment line")


def _switch_to_http_no_tokens_mode(staging_dir: Path, current_proc, current_log_file):
    """#231 setup step 1: flip `http_port = false` to a test port but
    leave `http_api_tokens` empty (the cfg.tbl default). Start the
    hub. Expected outcome:
    - The hub writes a sample token to `cfg/api_token.first` and
      logs a warning.
    - The HTTP listener is NOT bound (TCP connect to TEST_PORT_HTTP
      is refused).
    Returns (proc, log_file) so the asserting test can run against
    the live hub before `_switch_to_http_mode` takes over.

    Also applies the burst-bump cfg overrides that
    `_switch_to_http_mode` previously owned. This pre-emptive bump
    avoids re-writing cfg.tbl a third time once the token is
    injected; both cfg flips end up in place before the listener
    binds."""
    stop_hub(current_proc, current_log_file)

    # Remove a stale sample-token file from a previous test run on
    # the same staging dir so the assertion "file was created on
    # this boot" is meaningful. Production deployments do not
    # delete it - operator does, per docs.
    sample_path = staging_dir / "cfg" / "api_token.first"
    sample_path.unlink(missing_ok=True)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"http_port\s*=\s*false",
        f"http_port = {TEST_PORT_HTTP}",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip http_port = false to a test port in cfg.tbl "
            "(is the http_port key present in examples/cfg/cfg.tbl?)"
        )
    new_text, nb = re.subn(
        r"http_api_burst\s*=\s*\d+",
        "http_api_burst = 100",
        new_text,
        count=1,
    )
    if nb != 1:
        raise TestFailure(
            "could not bump http_api_burst in cfg.tbl - missing default key?"
        )
    # Also bump the per-minute admin / read rates: the registered-
    # users family (#236) added dozens of admin-scope tests
    # (cmd_reg POST + PATCH, cmd_setpass PUT, cmd_nickchange PUT,
    # cmd_upgrade PUT, cmd_delreg DELETE) that exhaust the
    # production default of 60/min on Linux CI even after the
    # burst-100 bump. Staging is single-token + single-client, so
    # the production-grade DoS defence is moot here.
    new_text, nra = re.subn(
        r"http_api_rate_admin\s*=\s*\d+",
        "http_api_rate_admin = 600",
        new_text,
        count=1,
    )
    if nra != 1:
        raise TestFailure(
            "could not bump http_api_rate_admin in cfg.tbl - missing default key?"
        )
    new_text, nrr = re.subn(
        r"http_api_rate_read\s*=\s*\d+",
        "http_api_rate_read = 600",
        new_text,
        count=1,
    )
    if nrr != 1:
        raise TestFailure(
            "could not bump http_api_rate_read in cfg.tbl - missing default key?"
        )
    # Also bump the per-IP TCP-connection-rate BURST (NOT the
    # parallel-conn cap _max_conns, which `test_perip_connection_cap`
    # asserts is exactly 16). The Phase 1c bad-prefix flood (15
    # quick HTTP conns) followed by cmd_disconnect's 4-5 ADC logins
    # plus cmd_redirect's 5 more burns through the production-default
    # burst of 30 on Linux CI (faster than Windows MinGW); the next
    # connection from 127.0.0.1 then RSTs in `accept_ip`. Bumping
    # the burst gives headroom for the sequential HTTP test
    # battery without weakening any of the ADC-side limiter tests.
    # The key is NOT in examples/cfg/cfg.tbl by default (only in
    # cfg_defaults.lua at 30), so use a regex that matches the key
    # if present, otherwise append it.
    if re.search(r"ratelimit_perip_conn_burst\s*=", new_text):
        new_text = re.sub(
            r"ratelimit_perip_conn_burst\s*=\s*\d+",
            "ratelimit_perip_conn_burst = 200",
            new_text,
            count=1,
        )
    else:
        # Inject before the closing brace of the cfg.tbl table. The
        # file's last non-blank line is the `}` that terminates the
        # outer table; insert just above it.
        new_text = re.sub(
            r"^\}\s*$",
            "    ratelimit_perip_conn_burst = 200,  -- smoke override (#82 Phase 2)\n}",
            new_text,
            count=1,
            flags=re.MULTILINE,
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    # Wait until the ADC port is bound to ensure the hub finished
    # the boot sequence (incl. the bootstrap_first_token write).
    # Without this, the test below might race the hub's startup.
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    # Also wait for the sample-token file. On Windows MinGW the
    # ADC port can bind a tick BEFORE bootstrap_first_token has
    # finished writing api_token.first; the original wait_for_port
    # alone left a race that caused intermittent post-merge CI
    # failures (every downstream HTTP test then failed with
    # "[Errno 2] No such file or directory: cfg\\api_token.first").
    sample_path = staging_dir / "cfg" / "api_token.first"
    wait_for_file(sample_path, 5.0)
    return proc, log_file


def test_http_no_tokens_means_no_listener(staging_dir: Path, proc=None):
    """#231 regression test: `http_port` set + `http_api_tokens` empty
    must NOT bind the HTTP listener. Sample token must be written to
    `cfg/api_token.first` instead, so the operator has a value to
    copy into cfg.tbl.

    Runs against the hub started by `_switch_to_http_no_tokens_mode`
    immediately above. Verifies:
    - cfg/api_token.first exists and has a non-comment token line.
    - TCP connect to TEST_PORT_HTTP is refused (listener never bound).
    - ADC ports are still up (no collateral damage).
    """
    sample_path = staging_dir / "cfg" / "api_token.first"
    token = _read_first_token_from_file(sample_path)
    # Token format sanity: base32 (A-Z2-7), ~52 chars from 32 bytes.
    if len(token) < 40:
        raise TestFailure(
            f"sample token at {sample_path} is suspiciously short ({len(token)} chars): {token!r}"
        )

    # TCP connect to the HTTP test port must NOT succeed. The hub did
    # NOT bind the listener because cfg.tbl http_api_tokens is empty.
    # Accepted "not listening" signals across platforms:
    #   - ConnectionRefusedError (Linux + Windows WSAECONNREFUSED=10061):
    #     OS responded with TCP RST. Fast.
    #   - socket.timeout / TimeoutError: OS dropped / filtered the SYN.
    #     Slower but still proves nothing is accepting.
    # The only failure mode we care about is a SUCCESSFUL connect (which
    # would mean the listener bound despite the empty token table).
    try:
        with socket.create_connection((HUB_HOST, TEST_PORT_HTTP), timeout=2.0) as s:
            s.close()
        raise TestFailure(
            f"HTTP listener bound on port {TEST_PORT_HTTP} despite empty "
            f"http_api_tokens; #231 regression"
        )
    except (ConnectionRefusedError, socket.timeout, TimeoutError):
        # All three are the expected outcome - no listener accepting.
        pass
    except OSError as e:
        # Some other OSError - investigate. WinError 10061 on Windows
        # is ConnectionRefused-equivalent and already caught above; any
        # other code is surprising.
        if hasattr(e, "winerror") and e.winerror == 10061:
            pass
        else:
            raise TestFailure(
                f"HTTP connect to {TEST_PORT_HTTP} failed with unexpected error: "
                f"{type(e).__name__}: {e}"
            )

    # ADC handshake still works (no collateral damage). Reuse the
    # plain-handshake assertion.
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as s:
        s.sendall(b"HSUP ADBASE\n")
        data = b""
        s.settimeout(PROTOCOL_TIMEOUT_SEC)
        try:
            data = s.recv(1024)
        except socket.timeout:
            pass
    if b"ISUP" not in data:
        raise TestFailure(
            f"ADC handshake degraded by HTTP no-listener path; got: {data!r}"
        )


def _switch_to_http_mode(staging_dir: Path, current_proc, current_log_file):
    """#231 setup step 2: after `_switch_to_http_no_tokens_mode`
    proved that empty http_api_tokens means no listener, copy the
    sample token from `cfg/api_token.first` into cfg.tbl
    http_api_tokens (the documented activation step) and restart
    the hub. Returns (proc, log_file) for the running hub with the
    HTTP listener now bound.

    The pre-#231 design auto-activated a bootstrap token in-memory;
    smoke tests just read `api_token.first` and used it directly.
    Now cfg.tbl is the single source of truth, so smoke must
    perform the operator's copy step explicitly before the listener
    will bind."""
    stop_hub(current_proc, current_log_file)

    sample_path = staging_dir / "cfg" / "api_token.first"
    token = _read_first_token_from_file(sample_path)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Rewrite `http_api_tokens = { }` to embed the sample token
    # with admin scope. The trailing comma on the cfg.tbl line is
    # preserved by the replacement.
    # Inject both admin (bootstrap) and read (#275 COV-1 fixture)
    # tokens. Multiple tests rely on the read token's presence; keep
    # it permanent rather than mode-switching it in and out.
    new_tokens_value = (
        '{ ["' + token + '"] = { scope = "admin", comment = "smoke-bootstrap" }, '
        '["' + SMOKE_READ_TOKEN + '"] = { scope = "read", comment = "smoke-read" } }'
    )
    new_text, n = re.subn(
        r"http_api_tokens\s*=\s*\{\s*\}",
        f"http_api_tokens = {new_tokens_value}",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not inject sample token into cfg.tbl http_api_tokens (regex did not match)"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    # Wait for ADC port first (proves hub booted), then HTTP port
    # (proves the listener actually bound on this run, i.e. the
    # token injection worked).
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, 5.0)
    return proc, log_file


def _http_roundtrip(raw_request: bytes) -> str:
    """Open a fresh connection to the HTTP listener, send a raw
    request, read until the server closes (the hub always answers
    Connection: close - one request per connection), return the
    decoded response."""
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_HTTP), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(raw_request)
        chunks = []
        s.settimeout(PROTOCOL_TIMEOUT_SEC)
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            chunks.append(c)
    return b"".join(chunks).decode("latin-1", errors="replace")


def test_http_health_roundtrip(staging_dir: Path, proc=None):
    """Phase 1b of #82: the hardened HTTP framer + router answer
    correctly and the security posture holds.

    - GET /health -> 200, body "ok" (plain text, no auth, special-case)
    - HEAD /health -> 200, empty body
    - NO Server header (no version fingerprint pre-auth)
    - unknown path WITHOUT auth -> 401 (auth-first; do not leak
      endpoint existence to anonymous callers)
    - DELETE /health WITHOUT auth -> 401 (same; /health is GET/HEAD-
      only as a special case, anything else falls into normal routing)
    - malformed request-line -> 400 (framer-level, pre-auth)
    - bad HTTP version -> 505 (framer-level)
    - Transfer-Encoding (smuggling vector) -> 400 (framer-level)
    - the ADC listener still handshakes (per-listener pipeline
      selection did not regress the ADC path)
    """
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, START_TIMEOUT_SEC)

    def status(resp):
        return resp.split("\r\n", 1)[0]

    # 1. happy path
    r = _http_roundtrip(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /health: expected 200, got {status(r)!r}")
    if "\r\n\r\nok" not in r:
        raise TestFailure(f"GET /health: body 'ok' missing; resp={r!r}")
    if "Connection: close" not in r:
        raise TestFailure("GET /health: missing Connection: close")
    if "server:" in r.lower():
        raise TestFailure(f"Server header leaked (fingerprint): {r!r}")

    # 2. HEAD: same status, empty body
    r = _http_roundtrip(b"HEAD /health HTTP/1.1\r\n\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"HEAD /health: expected 200, got {status(r)!r}")
    if r.split("\r\n\r\n", 1)[1] != "":
        raise TestFailure(f"HEAD /health: body must be empty; resp={r!r}")

    # 3..7 hard-status table
    for label, req, want in [
        # Phase 1b: unknown path without auth -> 401, NOT 404. The
        # router enforces auth before route lookup so anonymous
        # callers cannot enumerate endpoints.
        ("unknown path no auth", b"GET /nope HTTP/1.1\r\n\r\n", "401"),
        # /health is registered (GET, scope="none") but DELETE on
        # it without auth -> 401 (don't leak path existence to
        # anonymous callers; admin API posture). An authenticated
        # client gets 405 + Allow header instead.
        ("bad method on /health no auth", b"DELETE /health HTTP/1.1\r\n\r\n", "401"),
        # framer-level rejections still fire before the router
        ("malformed reqline", b"GET/health HTTP/1.1\r\n\r\n", "400"),
        ("bad version", b"GET /health HTTP/2.0\r\n\r\n", "505"),
        ("TE smuggling", b"GET /health HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "400"),
    ]:
        r = _http_roundtrip(req)
        if want not in status(r):
            raise TestFailure(
                f"HTTP {label}: expected {want}, got {status(r)!r}"
            )

    # 8. /v1/endpoints: requires auth; without it -> 401.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints no-auth: expected 401, got {status(r)!r}"
        )
    if "application/json" not in r.lower():
        raise TestFailure(
            f"401 must use JSON envelope (Content-Type); got {r!r}"
        )
    if '"E_UNAUTHENTICATED"' not in r:
        raise TestFailure(f"401: expected E_UNAUTHENTICATED in body; got {r!r}")

    # 9. /v1/endpoints with the bootstrap token -> 200 + envelope
    #    listing at least /health and /v1/endpoints.
    token_path = staging_dir / "cfg" / "api_token.first"
    if not token_path.exists():
        raise TestFailure(
            f"bootstrap file missing at {token_path}; the hub should "
            f"have generated it on first boot with http_port set"
        )
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")

    req_with_auth = (
        b"GET /v1/endpoints HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req_with_auth)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints with bootstrap token: expected 200, "
            f"got {status(r)!r}; resp={r!r}"
        )
    body = r.split("\r\n\r\n", 1)[1]
    if '"ok":true' not in body.replace(" ", ""):
        raise TestFailure(f"envelope missing ok:true; body={body!r}")
    # The catalog lists ALL registered routes including /health
    # (scope="none", anonymous-accessible) and itself
    # (scope="read", self-describing).
    if '"/v1/endpoints"' not in body:
        raise TestFailure(
            f"endpoint catalog missing /v1/endpoints (self-listing); body={body!r}"
        )
    if '"/health"' not in body:
        raise TestFailure(
            f"endpoint catalog missing /health (scope=none route); body={body!r}"
        )

    # 10. /v1/endpoints with a BOGUS token -> 401.
    bad_req = (
        b"GET /v1/endpoints HTTP/1.1\r\n"
        b"Authorization: Bearer not-a-real-token\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(bad_req)
    if "401" not in status(r):
        raise TestFailure(
            f"GET /v1/endpoints with bad token: expected 401, got {status(r)!r}"
        )

    # 11. OPTIONS introspection per §6.6 - 204 + Allow header, no
    # auth required. /health is GET-only so OPTIONS yields the
    # auto-added HEAD + OPTIONS.
    r = _http_roundtrip(b"OPTIONS /health HTTP/1.1\r\n\r\n")
    if "204" not in status(r):
        raise TestFailure(
            f"OPTIONS /health: expected 204, got {status(r)!r}"
        )
    if "Allow:" not in r:
        raise TestFailure(f"OPTIONS /health: missing Allow header; resp={r!r}")
    # The Allow header MUST list GET (registered) + HEAD (auto-
    # added for GET routes) + OPTIONS (self).
    for must_have in ("GET", "HEAD", "OPTIONS"):
        if must_have not in r:
            raise TestFailure(
                f"OPTIONS /health: Allow must list {must_have}; resp={r!r}"
            )

    # 11b. SECURITY (#533 oracle fix): OPTIONS introspection must NOT
    # reveal the existence of an auth-gated path to an anonymous caller.
    # /v1/endpoints is a registered read-scoped path; anonymous OPTIONS
    # on it must 401 (like an anonymous GET would), NOT 204+Allow.
    # Pre-fix the OPTIONS branch ran before auth and served 204+Allow to
    # anyone, a path-existence + method oracle.
    r = _http_roundtrip(b"OPTIONS /v1/endpoints HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"OPTIONS /v1/endpoints anonymous: expected 401 (no path-existence "
            f"oracle), got {status(r)!r}"
        )
    if "Allow:" in r:
        raise TestFailure(
            f"OPTIONS /v1/endpoints anonymous: must not leak Allow header; resp={r!r}"
        )

    # 11c. Authenticated OPTIONS on the same auth-gated path still
    # introspects: 204 + Allow listing GET/HEAD/OPTIONS.
    r = _http_roundtrip(
        b"OPTIONS /v1/endpoints HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    if "204" not in status(r):
        raise TestFailure(
            f"OPTIONS /v1/endpoints authed: expected 204, got {status(r)!r}"
        )
    for must_have in ("GET", "HEAD", "OPTIONS"):
        if must_have not in r:
            raise TestFailure(
                f"OPTIONS /v1/endpoints authed: Allow must list {must_have}; resp={r!r}"
            )

    # 12. OPTIONS on an unknown path with auth -> 404 (anonymous
    # would get 401 first, but introspection does not bypass auth
    # for paths that simply do not exist).
    r = _http_roundtrip(
        b"OPTIONS /v1/nope HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"OPTIONS /v1/nope authed: expected 404, got {status(r)!r}"
        )

    # 13. Authenticated method-mismatch on /health -> 405 + Allow.
    r = _http_roundtrip(
        b"DELETE /health HTTP/1.1\r\n"
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
        b"\r\n"
    )
    if "405" not in status(r):
        raise TestFailure(
            f"DELETE /health authed: expected 405, got {status(r)!r}"
        )
    if "Allow:" not in r or "GET" not in r:
        raise TestFailure(f"DELETE /health authed: missing Allow: GET; resp={r!r}")

    # SECURITY: the HTTP listener MUST be loopback-only (no TLS / no
    # auth is only acceptable because it is 127.0.0.1-bound). Prove it
    # is NOT reachable on this host's non-loopback address. Skipped
    # only if the environment has no usable non-loopback IPv4 (some
    # locked-down CI net namespaces) - never failed spuriously.
    nonloop = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))  # no packets sent; just resolves the local addr
            cand = probe.getsockname()[0]
        finally:
            probe.close()
        if cand and not cand.startswith("127.") and cand != "0.0.0.0":
            nonloop = cand
    except OSError:
        nonloop = None
    if nonloop:
        try:
            c = socket.create_connection((nonloop, TEST_PORT_HTTP), timeout=2)
            c.close()
            raise TestFailure(
                f"SECURITY: HTTP listener reachable on non-loopback "
                f"{nonloop}:{TEST_PORT_HTTP} - it must bind 127.0.0.1 "
                f"only (regression of B1: addr vs ip)."
            )
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass  # expected: refused/unreachable off-loopback
    else:
        log("  (skip non-loopback bind check: no non-loopback IPv4)")

    # ADC path still works alongside the HTTP listener
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as s:
        s.sendall(b"HSUP ADBASE ADTIGR\n")
        reader = _ADCReader(s)
        reader.recv_until(lambda f: f.startswith("ISUP "))


def test_http_phase1c_endpoints(staging_dir: Path, proc=None):
    """Phase 1c of #82: the 4 core read endpoints answer; rate-limit
    + per-prefix failed-auth + idempotency wiring is alive on the
    dispatch path.

    Smoke-scope (full semantics live in tests/unit/http_router_test.lua):
    - GET /v1/version with bootstrap token -> 200 + envelope with name
    - GET /v1/stats                        -> 200 + envelope w/ online_count
    - GET /v1/users?limit=50               -> 200 + envelope w/ pagination block
    - GET /v1/users/AAAA                   -> 404 (no such SID online)
    - GET /v1/log/api?lines=5              -> 200 + envelope w/ lines array
    - /v1/endpoints catalog now lists all five (plus /health + self)
    - Hammer with wrong-prefix bearer -> 429 from prefix bucket after burst
    - Hammer /v1/version with right token -> 429 from per-token bucket
      eventually (read budget = 120/min, burst = 10 by default)
    """
    # Re-discover the bootstrap token; the hub re-generated it on this
    # boot (every fresh staging run overwrites api_token.first).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. /v1/version
    r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/version: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"ok":true' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/version: envelope ok:true missing; body={b!r}")
    if '"name"' not in b or "Luadch" not in b:
        raise TestFailure(f"GET /v1/version: missing name/Luadch in body={b!r}")
    if '"uptime_seconds"' not in b:
        raise TestFailure(f"GET /v1/version: missing uptime_seconds; body={b!r}")

    # 2. /v1/stats
    r = _http_roundtrip(b"GET /v1/stats HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/stats: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"online_count"' not in b:
        raise TestFailure(f"GET /v1/stats: missing online_count; body={b!r}")
    if '"share_total_bytes"' not in b:
        raise TestFailure(f"GET /v1/stats: missing share_total_bytes; body={b!r}")
    if '"by_level"' not in b:
        raise TestFailure(f"GET /v1/stats: missing by_level; body={b!r}")

    # 3. /v1/users with explicit pagination
    r = _http_roundtrip(b"GET /v1/users?limit=50&offset=0 HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/users: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"pagination"' not in b:
        raise TestFailure(f"GET /v1/users: missing pagination block; body={b!r}")
    for need in ('"users"', '"total"', '"limit"', '"offset"'):
        if need not in b:
            raise TestFailure(f"GET /v1/users: missing {need}; body={b!r}")

    # 4. /v1/users/{sid} for a SID that cannot be online (AAAA is the
    #    spec-reserved sentinel value the SID-assigner skips).
    r = _http_roundtrip(b"GET /v1/users/AAAA HTTP/1.1\r\n" + auth + b"\r\n")
    if "404" not in status(r):
        raise TestFailure(
            f"GET /v1/users/AAAA: expected 404, got {status(r)!r}"
        )
    b = body_of(r)
    if '"E_NOT_FOUND"' not in b:
        raise TestFailure(f"GET /v1/users/AAAA: missing E_NOT_FOUND code; body={b!r}")

    # 5. /v1/log/api (admin scope; bootstrap token is admin)
    r = _http_roundtrip(b"GET /v1/log/api?lines=5 HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/log/api: expected 200, got {status(r)!r}")
    b = body_of(r)
    # #275 CON-1 holistic review: response shape now matches the
    # sibling tail endpoints (/v1/log/error, /v1/log/cmd,
    # /v1/chatlog): {lines, returned, total_lines}. The pre-CON-1
    # `path` field is gone (info leak: leaked cfg.log_path).
    if '"lines"' not in b:
        raise TestFailure(f"GET /v1/log/api: missing lines array; body={b!r}")
    if '"returned"' not in b:
        raise TestFailure(
            f"CON-1: GET /v1/log/api missing `returned` field "
            f"(sibling tail-endpoint shape); body={b!r}"
        )
    if '"total_lines"' not in b:
        raise TestFailure(
            f"CON-1: GET /v1/log/api missing `total_lines` field "
            f"(sibling tail-endpoint shape); body={b!r}"
        )
    if '"path"' in b:
        raise TestFailure(
            f"CON-1: GET /v1/log/api still emits `path` field "
            f"(info leak of cfg.log_path); body={b!r}"
        )

    # 6. /v1/endpoints catalog now lists all Phase 1c endpoints.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/endpoints: expected 200, got {status(r)!r}")
    b = body_of(r)
    for path_must_have in (
        '"/v1/version"', '"/v1/stats"', '"/v1/users"',
        '"/v1/users/{sid}"', '"/v1/log/api"',
    ):
        if path_must_have not in b:
            raise TestFailure(
                f"catalog missing {path_must_have}; body={b!r}"
            )

    # 7. Per-prefix failed-auth bucket (§4.8). Burst is 5 by default;
    #    six wrong-token-same-prefix requests should reach the 429
    #    rate-limit response. Use a Bearer with a distinct 4-char
    #    prefix so this test does not exhaust other tests' budget if
    #    re-ordered.
    bad_prefix = b"PRFX-bogus-token-value-xx"
    bad_auth = b"Authorization: Bearer " + bad_prefix + b"\r\n"
    saw_429 = False
    for i in range(15):
        r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + bad_auth + b"\r\n")
        st = status(r)
        if "429" in st:
            saw_429 = True
            # Retry-After header MUST be present per §4.8
            if "Retry-After:" not in r:
                raise TestFailure(
                    f"per-prefix 429: missing Retry-After; resp={r!r}"
                )
            break
        if "401" not in st:
            raise TestFailure(
                f"per-prefix flood: expected 401 then 429, got {st!r}"
            )
    if not saw_429:
        raise TestFailure(
            "per-prefix failed-auth bucket never tripped after 15 attempts"
        )

    # The right-prefix-bucket SHOULD be unrelated. The valid bootstrap
    # token has its own prefix; a single subsequent request must still
    # succeed (proves the bucket is keyed by prefix not by source IP).
    r = _http_roundtrip(b"GET /v1/version HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"valid token after wrong-prefix flood: expected 200, "
            f"got {status(r)!r}; resp={r!r}"
        )


def test_http_config_editable_secrets(staging_dir: Path, proc=None):
    """#178: opted-in redacted secret keys become editable via a masked write, while
    the hub's own auth/crypto secrets stay write-protected (default-deny).

    Relies on the base staging enabling etc_geoip (Phase D2 above), whose onStart
    registers etc_geoip_license_key as an api_writable secret.

    - GET /v1/config -> 200; carries a `secret_writable` list containing
      etc_geoip_license_key; the value itself is masked "<redacted>".
    - PUT /v1/config/etc_geoip_license_key {value:"..."} -> 200, apply_status
      reload_required, and the response does NOT echo the value.
    - PUT /v1/config/http_api_tokens -> 403 (a baseline auth secret never opts in).
    - PUT /v1/config/etc_geoip_license_key {value:"<redacted>"} -> 400 (the redaction
      sentinel is refused, blocking a naive GET->PUT round-trip).
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put_config(key, value_json):
        body = ('{"value":' + value_json + '}').encode("utf-8")
        return _http_roundtrip(
            b"PUT /v1/config/" + key.encode("ascii") + b" HTTP/1.1\r\n"
            + auth
            + b"Content-Type: application/json\r\n"
            + b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            + b"\r\n"
            + body
        )

    # 1. GET /v1/config: secret_writable lists the opted-in credential; value masked.
    r = _http_roundtrip(b"GET /v1/config HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/config: expected 200, got {status(r)!r}")
    b = body_of(r).replace(" ", "")
    if '"secret_writable"' not in b:
        raise TestFailure(f"GET /v1/config: missing secret_writable list; body={body_of(r)!r}")
    if "etc_geoip_license_key" not in b:
        raise TestFailure(
            "GET /v1/config: etc_geoip_license_key not in secret_writable - precondition "
            "failed: the base staging must keep etc_geoip enabled (Phase D2 patch above) so "
            f"its onStart registers the api_writable secret; body={body_of(r)!r}"
        )
    if '"etc_geoip_license_key":"<redacted>"' not in b:
        raise TestFailure(f"GET /v1/config: etc_geoip_license_key not masked; body={body_of(r)!r}")

    # 2. Masked write of an opted-in secret -> 200 + reload_required, no value echo.
    r = put_config("etc_geoip_license_key", '"smoke-license-key"')
    if "200 OK" not in status(r):
        raise TestFailure(f"PUT etc_geoip_license_key: expected 200, got {status(r)!r}; resp={r!r}")
    b = body_of(r).replace(" ", "")
    if '"apply_status":"reload_required"' not in b:
        raise TestFailure(f"PUT etc_geoip_license_key: expected reload_required; body={body_of(r)!r}")
    if "smoke-license-key" in body_of(r):
        raise TestFailure(f"PUT etc_geoip_license_key: response must NOT echo the value; body={body_of(r)!r}")

    # 3. A baseline auth secret stays write-protected (default-deny).
    r = put_config("http_api_tokens", '"x"')
    if "403" not in status(r):
        raise TestFailure(f"PUT http_api_tokens: expected 403 (protected), got {status(r)!r}; resp={r!r}")

    # 4. The redaction sentinel is refused (round-trip guard).
    r = put_config("etc_geoip_license_key", '"<redacted>"')
    if "400" not in status(r):
        raise TestFailure(f"PUT etc_geoip_license_key=<redacted>: expected 400, got {status(r)!r}; resp={r!r}")


def test_http_phase2_cmd_disconnect(staging_dir: Path, proc=None):
    """Phase 2 PR-1 of #82: cmd_disconnect plugin migrates to HTTP.

    The plugin keeps the existing +disconnect ADC chat-cmd unchanged
    AND additionally registers DELETE /v1/users/{sid}. Both call into
    a shared do_disconnect helper. This test exercises the HTTP path
    only - the ADC +disconnect cmd is covered by its own test history.

    Coverage:
    - Login a real ADC user (dummy/test), capture SID.
    - DELETE /v1/users/{sid} with admin token + reason body -> 200 +
      envelope { ok:true, data:{ action:"disconnect", sid, nick, reason } }
      (Phase-2 normalised shape per #200 / HTTP_API.md §7.1.1).
    - ADC connection drops shortly after (the kick is asynchronous to
      the HTTP response but happens within the request handler tick).
    - Subsequent DELETE on the same SID -> 404 E_NOT_FOUND.
    - DELETE on a never-online SID (AAAA sentinel) -> 404.
    - Idempotency: a second DELETE with the SAME X-Idempotency-Key
      within TTL replays the cached 200 (handler not re-invoked,
      audit log not re-emitted - the cache is the audit-deduplication
      mechanism).
    - /v1/endpoints catalog now lists DELETE /v1/users/{sid}.
    """
    # Re-discover the admin token from the bootstrap file (fresh each run).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Log in an ADC user, grab their SID, kick via DELETE.
    with _logged_in_user() as (adc, sid, _reader):
        if len(sid) != 4:
            raise TestFailure(f"unexpected SID length: {sid!r}")

        # 2. DELETE /v1/users/{sid} with reason body.
        body = b'{"reason":"smoke test kick"}'
        req = (
            b"DELETE /v1/users/" + sid.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(f"DELETE /v1/users/{sid}: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        # Phase-2 envelope normalisation (#200): write-endpoint
        # responses carry `action:"<verb>"` instead of a per-
        # endpoint verb-boolean (pre-#200 was {disconnected:true,...}).
        if '"action":"disconnect"' not in b.replace(" ", ""):
            raise TestFailure(f"DELETE /v1/users/{{sid}}: expected action:disconnect; body={b!r}")
        # The nick may be auto-prefixed by the level tag (e.g.
        # "[HUBOWNER]dummy"); substring-match is enough.
        if '"nick":"' not in b or "dummy" not in b:
            raise TestFailure(f"DELETE /v1/users/{{sid}}: expected nick containing 'dummy'; body={b!r}")
        if '"reason":"smoketestkick"' not in b.replace(" ", ""):
            raise TestFailure(f"DELETE /v1/users/{{sid}}: reason missing or wrong; body={b!r}")

        # 3. ADC connection drops. The hub sends ISTA 230 then closes.
        _assert_adc_drops(adc)

    # 4. Subsequent DELETE on the same SID -> 404 (user offline now).
    req2 = (
        b"DELETE /v1/users/" + sid.encode("ascii") + b" HTTP/1.1\r\n"
        + auth +
        b"\r\n"
    )
    r = _http_roundtrip(req2)
    if "404" not in status(r):
        raise TestFailure(
            f"second DELETE /v1/users/{sid} (user offline): expected 404, got {status(r)!r}"
        )
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"second DELETE: expected E_NOT_FOUND; resp={r!r}")

    # 5. DELETE on a never-online SID -> 404 (sanity).
    r = _http_roundtrip(b"DELETE /v1/users/AAAA HTTP/1.1\r\n" + auth + b"\r\n")
    if "404" not in status(r):
        raise TestFailure(f"DELETE /v1/users/AAAA: expected 404, got {status(r)!r}")

    # 6. Idempotency: log in a fresh user, kick once with idem-key,
    # second DELETE with SAME key replays the cached 200 (not 404)
    # even though the user is offline now.
    with _logged_in_user() as (adc2, sid2, _reader):
        idem_key = b"smoke-idem-" + sid2.encode("ascii")
        body = b'{"reason":"idem cached"}'
        req3 = (
            b"DELETE /v1/users/" + sid2.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"X-Idempotency-Key: " + idem_key + b"\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req3)
        if "200 OK" not in status(r):
            raise TestFailure(f"idem DELETE first call: expected 200, got {status(r)!r}")
        first_body = body_of(r)

        # Wait for the ADC drop so the second call is unambiguously
        # a cache replay (not a coincidental race).
        _assert_adc_drops(adc2)

        # Second call with SAME idem key: user is offline now. Without
        # the cache this would be 404. With the cache it MUST replay
        # the original 200.
        r = _http_roundtrip(req3)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem DELETE replay: expected cached 200, got {status(r)!r}; "
                f"the idempotency cache did not replay"
            )
        if body_of(r) != first_body:
            raise TestFailure(
                "idem DELETE replay body differs from first call - cache stored wrong payload"
            )

    # 7. /v1/endpoints catalog includes DELETE /v1/users/{sid}
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"DELETE"' not in b or '"/v1/users/{sid}"' not in b:
        raise TestFailure(
            f"catalog missing DELETE /v1/users/{{sid}} after Phase 2 PR-1; body={b!r}"
        )

    # 8. Schema validation: reason > 256 chars -> 400 E_BAD_INPUT.
    #    Confirms the request_schema declared on the route is
    #    actually wired into dispatch. User must STILL be online -
    #    the validation failed before the handler ran.
    with _logged_in_user() as (adc3, sid3, _reader):
        long_reason = "x" * 300
        bigbody = ('{"reason":"' + long_reason + '"}').encode("ascii")
        req4 = (
            b"DELETE /v1/users/" + sid3.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(bigbody)).encode("ascii") + b"\r\n"
            b"\r\n" + bigbody
        )
        r = _http_roundtrip(req4)
        if "400" not in status(r):
            raise TestFailure(
                f"reason >256 chars: expected 400, got {status(r)!r}"
            )
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(
                f"reason >256 chars: expected E_BAD_INPUT code; body={body_of(r)!r}"
            )
        _assert_adc_alive(adc3)


def test_http_phase2_cmd_redirect(staging_dir: Path, proc=None):
    """Phase 2 PR-2 of #82: cmd_redirect plugin migrates to HTTP.

    Coexist with the +redirect ADC chat-cmd via a shared do_redirect
    helper, same pattern as PR-1. The HTTP body carries an optional
    `url` field; missing/empty falls back to cfg `cmd_redirect_url`.

    Coverage:
    - POST /v1/users/{sid}/redirect with explicit URL -> 200 +
      { action:"redirect", sid, nick, url } envelope. ADC drops.
      (Phase-2 normalised shape per #200 / HTTP_API.md §7.1.1.)
    - POST without url -> 200 (falls back to cfg default).
    - POST on offline SID -> 404 E_NOT_FOUND.
    - POST without auth -> 401.
    - URL > 1024 chars -> 400 E_BAD_INPUT.
    - /v1/endpoints catalog lists POST /v1/users/{sid}/redirect.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Login + redirect with explicit url.
    with _logged_in_user() as (adc, sid, _reader):
        body = b'{"url":"adc://newhub.example:5000"}'
        req = (
            b"POST /v1/users/" + sid.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"POST /v1/users/{sid}/redirect: expected 200, got {status(r)!r}; resp={r!r}"
            )
        b = body_of(r)
        # Phase-2 envelope normalisation (#200): see cmd_disconnect
        # smoke for context.
        if '"action":"redirect"' not in b.replace(" ", ""):
            raise TestFailure(f"redirect: expected action:redirect; body={b!r}")
        if '"url":"adc://newhub.example:5000"' not in b.replace(" ", ""):
            raise TestFailure(f"redirect: url not echoed; body={b!r}")
        # ADC should drop (IQUI RD + kill).
        _assert_adc_drops(adc)

    # 2. Login + redirect WITHOUT url body -> falls back to cfg
    #    default. The cfg default in examples/cfg/cfg.tbl is non-
    #    empty so this MUST succeed (200) rather than 400.
    with _logged_in_user() as (_adc2, sid2, _reader):
        req2 = (
            b"POST /v1/users/" + sid2.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        r = _http_roundtrip(req2)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"POST .../redirect (no body, cfg default): expected 200, got {status(r)!r}; resp={r!r}"
            )

    # 3. POST on offline SID -> 404.
    body3 = b'{"url":"adc://x:1"}'
    req3 = (
        b"POST /v1/users/AAAA/redirect HTTP/1.1\r\n"
        + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body3)).encode("ascii") + b"\r\n"
        b"\r\n" + body3
    )
    r = _http_roundtrip(req3)
    if "404" not in status(r):
        raise TestFailure(f"POST .../AAAA/redirect: expected 404, got {status(r)!r}; resp={r!r}")

    # 4. No auth -> 401.
    r = _http_roundtrip(
        b"POST /v1/users/AAAA/redirect HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    )
    if "401" not in status(r):
        raise TestFailure(f"POST .../redirect no-auth: expected 401, got {status(r)!r}")

    # 5. Overlong url -> 400 (schema reject; user must NOT be kicked).
    with _logged_in_user() as (adc3, sid3, _reader):
        long_url = "adc://" + ("x" * 1100) + ":5000"
        bigbody = ('{"url":"' + long_url + '"}').encode("ascii")
        req5 = (
            b"POST /v1/users/" + sid3.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(bigbody)).encode("ascii") + b"\r\n"
            b"\r\n" + bigbody
        )
        r = _http_roundtrip(req5)
        if "400" not in status(r):
            raise TestFailure(
                f"overlong url: expected 400, got {status(r)!r}"
            )
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(f"overlong url: expected E_BAD_INPUT; body={body_of(r)!r}")
        _assert_adc_alive(adc3)

    # 6. Catalog now lists POST /v1/users/{sid}/redirect.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"POST"' not in b or '"/v1/users/{sid}/redirect"' not in b:
        raise TestFailure(
            f"catalog missing POST /v1/users/{{sid}}/redirect; body={b!r}"
        )

    # 7. Non-ADC URL scheme -> 400 (schema pattern reject). Defence-
    #    in-depth against an admin token redirecting users to a
    #    non-hub URL (javascript:, http://evil/, file:///).
    with _logged_in_user() as (adc4, sid4, _reader):
        badbody = b'{"url":"http://evil.example/"}'
        req7 = (
            b"POST /v1/users/" + sid4.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(badbody)).encode("ascii") + b"\r\n"
            b"\r\n" + badbody
        )
        r = _http_roundtrip(req7)
        if "400" not in status(r):
            raise TestFailure(
                f"non-ADC scheme: expected 400 (pattern reject), got {status(r)!r}"
            )
        _assert_adc_alive(adc4)

    # 8. Idempotency replay: send the same POST twice with the same
    #    X-Idempotency-Key. First call kicks. Second call MUST replay
    #    the cached 200 even though the user is offline now (would
    #    otherwise be 404).
    with _logged_in_user() as (adc5, sid5, _reader):
        idem_key = b"redirect-idem-" + sid5.encode("ascii")
        body8 = b'{"url":"adc://idem.test:5000"}'
        req8 = (
            b"POST /v1/users/" + sid5.encode("ascii") + b"/redirect HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"X-Idempotency-Key: " + idem_key + b"\r\n"
            b"Content-Length: " + str(len(body8)).encode("ascii") + b"\r\n"
            b"\r\n" + body8
        )
        r = _http_roundtrip(req8)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem POST first call: expected 200, got {status(r)!r}"
            )
        first_body = body_of(r)
        # Wait for ADC drop so the second call cannot coincidentally
        # see the user still online.
        _assert_adc_drops(adc5)
        # Second call with same idem-key: user offline, but cache MUST
        # replay the original 200.
        r = _http_roundtrip(req8)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"idem POST replay: expected cached 200, got {status(r)!r}; "
                f"the idempotency cache did not replay"
            )
        if body_of(r) != first_body:
            raise TestFailure(
                "idem POST replay body differs from first call - cache stored wrong payload"
            )


def test_http_phase2_cmd_gag(staging_dir: Path, proc=None):
    """Phase 2 PR-3 of #82: cmd_gag plugin migrates to HTTP.

    First Phase-2 plugin with persistent state (gag list survives
    +reload via scripts/data/cmd_gag.tbl). Two endpoints:

    - POST /v1/users/{sid}/gag (body { mode, duration_minutes? })
    - DELETE /v1/users/{sid}/gag

    Same coexist pattern as PR-1 / PR-2: ADC `+gag` cmd unchanged,
    HTTP endpoints registered via util_http.http_register_user_action.
    The ADC user is NOT kicked (gag suppresses outbound chat, not the
    session) so the smoke uses _assert_adc_alive between phases.

    Coverage:
    - POST mute with no duration -> 200 + envelope w/ action:"gag",
      mode:"mute", no expires_at; user stays online (gag does not kick).
    - POST again on same user -> 409 E_CONFLICT.
    - POST invalid mode -> 400 (schema enum reject).
    - DELETE -> 200 + envelope w/ action:"ungag", previous_mode.
    - DELETE again -> 404 E_NOT_FOUND.
    - POST kennylize with duration_minutes=30 -> 200 + expires_at
      field set, ISO 8601 format.
    - POST shadowmute on fresh user -> 200.
    - Catalog lists POST + DELETE /v1/users/{sid}/gag.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post_gag(sid: str, body: bytes) -> str:
        req = (
            b"POST /v1/users/" + sid.encode("ascii") + b"/gag HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        return _http_roundtrip(req)

    def delete_gag(sid: str) -> str:
        req = (
            b"DELETE /v1/users/" + sid.encode("ascii") + b"/gag HTTP/1.1\r\n"
            + auth +
            b"\r\n"
        )
        return _http_roundtrip(req)

    # 1. POST mute (no duration) + 200 + user stays alive + DELETE flow.
    with _logged_in_user() as (adc, sid, _reader):
        # 1a. Fresh POST -> 200 + correct envelope.
        r = post_gag(sid, b'{"mode":"mute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag mute: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"action":"gag"' not in b.replace(" ", ""):
            raise TestFailure(f"gag: expected action:gag; body={b!r}")
        if '"mode":"mute"' not in b.replace(" ", ""):
            raise TestFailure(f"gag: expected mode:mute; body={b!r}")
        if '"expires_at"' in b:
            raise TestFailure(f"gag (no duration): expires_at must be absent; body={b!r}")

        # 1b. Gag does NOT kick - user must still be online.
        _assert_adc_alive(adc)

        # 1c. Re-POST -> 409 Conflict (already gagged).
        r = post_gag(sid, b'{"mode":"mute"}')
        if "409" not in status(r):
            raise TestFailure(f"re-POST .../gag: expected 409, got {status(r)!r}")
        if '"E_CONFLICT"' not in body_of(r):
            raise TestFailure(f"re-POST .../gag: expected E_CONFLICT; resp={r!r}")

        # 1d. Invalid mode -> 400 (schema enum reject).
        r = post_gag(sid, b'{"mode":"flaschenpost"}')
        if "400" not in status(r):
            raise TestFailure(f"invalid mode: expected 400, got {status(r)!r}")
        if '"E_BAD_INPUT"' not in body_of(r):
            raise TestFailure(f"invalid mode: expected E_BAD_INPUT; resp={r!r}")

        # 1e. DELETE -> 200 with previous_mode.
        r = delete_gag(sid)
        if "200 OK" not in status(r):
            raise TestFailure(f"DELETE .../gag: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"action":"ungag"' not in b.replace(" ", ""):
            raise TestFailure(f"ungag: expected action:ungag; body={b!r}")
        if '"previous_mode":"mute"' not in b.replace(" ", ""):
            raise TestFailure(f"ungag: expected previous_mode:mute; body={b!r}")

        # 1f. DELETE again -> 404.
        r = delete_gag(sid)
        if "404" not in status(r):
            raise TestFailure(f"re-DELETE .../gag: expected 404, got {status(r)!r}")
        if '"E_NOT_FOUND"' not in body_of(r):
            raise TestFailure(f"re-DELETE .../gag: expected E_NOT_FOUND; resp={r!r}")

        # 1g. Sanity: user still alive after the whole flow.
        _assert_adc_alive(adc)

    # 2. POST kennylize with duration_minutes=30 -> envelope carries
    #    duration_minutes + expires_at (ISO 8601). Verify the
    #    timestamp format roughly (YYYY-MM-DDTHH:MM:SSZ).
    with _logged_in_user() as (adc2, sid2, _reader):
        r = post_gag(sid2, b'{"mode":"kennylize","duration_minutes":30}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag kennylize+30min: expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        if '"duration_minutes":30' not in b.replace(" ", ""):
            raise TestFailure(f"gag w/ duration: expected duration_minutes:30; body={b!r}")
        m = re.search(r'"expires_at":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"', b)
        if not m:
            raise TestFailure(f"gag w/ duration: expires_at not in ISO 8601 form; body={b!r}")
        _assert_adc_alive(adc2)
        # Cleanup (otherwise the gag persists in cmd_gag.tbl across
        # later harness invocations on the same staging dir).
        r = delete_gag(sid2)
        if "200 OK" not in status(r):
            raise TestFailure(f"cleanup DELETE: expected 200, got {status(r)!r}")

    # 3. POST shadowmute on fresh user -> 200 + clean up.
    with _logged_in_user() as (adc3, sid3, _reader):
        r = post_gag(sid3, b'{"mode":"shadowmute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"POST .../gag shadowmute: expected 200, got {status(r)!r}")
        if '"mode":"shadowmute"' not in body_of(r).replace(" ", ""):
            raise TestFailure(f"shadowmute: mode missing in envelope; resp={r!r}")
        _assert_adc_alive(adc3)
        r = delete_gag(sid3)
        if "200 OK" not in status(r):
            raise TestFailure(f"cleanup shadowmute DELETE: expected 200, got {status(r)!r}")

    # 4. Catalog now lists POST + DELETE /v1/users/{sid}/gag.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/users/{sid}/gag"' not in b:
        raise TestFailure(f"catalog missing /v1/users/{{sid}}/gag; body={b!r}")
    # Catalog includes both POST and DELETE entries on the same path.
    if b.count('"/v1/users/{sid}/gag"') < 2:
        raise TestFailure(f"catalog should list BOTH POST and DELETE /v1/users/{{sid}}/gag; body={b!r}")

    # 5. Persistence: POST creates a gag entry, and the on-disk
    #    scripts/data/cmd_gag.tbl must contain the user's firstnick.
    #    A subsequent DELETE removes it. This verifies the disk-
    #    write side of persistence; the re-load path
    #    (util.loadtable(gag_path) at plugin onStart) is unchanged
    #    from pre-PR-3 and shared with every other persist-on-disk
    #    plugin in the codebase, so a full restart cycle here would
    #    only cover surface already covered by Phase-7 user.tbl
    #    persistence tests. A dedicated hub-restart-and-survive
    #    test is a worthwhile Phase-2 polish item but deferred to
    #    keep PR-3 small.
    gag_tbl_path = staging_dir / "scripts" / "data" / "cmd_gag.tbl"
    with _logged_in_user() as (adc, sid, _reader):
        r = post_gag(sid, b'{"mode":"mute"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"persistence POST: expected 200, got {status(r)!r}")
        if not gag_tbl_path.exists():
            raise TestFailure(f"persistence: cmd_gag.tbl not written at {gag_tbl_path}")
        # The serialised entry must include the user's firstnick.
        # dummy may be auto-prefixed by level (e.g. "[HUBOWNER]dummy"),
        # but the firstnick is the registered nick which IS plain "dummy".
        contents = gag_tbl_path.read_text(encoding="utf-8")
        if 'user_nick = "dummy"' not in contents:
            raise TestFailure(
                f"persistence: cmd_gag.tbl after POST missing user_nick "
                f"entry; contents={contents!r}"
            )
        # Clean up + verify the disk-write of removal too.
        r = delete_gag(sid)
        if "200 OK" not in status(r):
            raise TestFailure(f"persistence cleanup DELETE: expected 200, got {status(r)!r}")
        contents = gag_tbl_path.read_text(encoding="utf-8")
        if 'user_nick = "dummy"' in contents:
            raise TestFailure(
                f"persistence: cmd_gag.tbl after DELETE still has entry; "
                f"contents={contents!r}"
            )


def test_http_phase2_cmd_ban(staging_dir: Path, proc=None):
    """Phase 2 PR-4 of #82: cmd_ban plugin migrates to HTTP.

    Last bundled-plugin migration of Phase 2. Largest plugin (779 LoC)
    with the most complex target shape: bans key by nick / cid / ip
    (and a transient `sid` resolve-then-store-by-nick path), not a
    single {sid}. Hence raw `hub.http_register` registrations rather
    than the util_http SID helper.

    Four endpoints:
    - GET    /v1/bans                 (= +ban show)
    - GET    /v1/bans/history[?nick=] (= +ban showhis)
    - POST   /v1/bans                 (= +ban ...)
    - DELETE /v1/bans/{id}            (= +unban; index from GET /v1/bans)

    Coverage:
    - POST sid + duration + reason -> 200 envelope w/ action:"ban",
      target_nick, expires_at, id. ADC user dropped (ISTA 232 + TL).
    - GET /v1/bans lists the entry with the same id + remaining_seconds.
    - GET /v1/bans/history?nick=dummy returns the history entry.
    - POST cid blind-add (target not online) -> 200 (no offline lookup).
    - POST nick unknown (not online, not registered) -> 404.
    - POST invalid target_type -> 400 (schema enum reject).
    - DELETE /v1/bans/{id} -> 200 envelope w/ action:"unban", removed.
    - DELETE /v1/bans/99 -> 404 E_NOT_FOUND.
    - DELETE /v1/bans/foo -> 400 E_BAD_INPUT (not an integer).
    - Persistence: scripts/data/cmd_ban_bans.tbl + cmd_ban_history.tbl
      reflect POST + DELETE.
    - /v1/endpoints catalog lists all four routes.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post_ban(body: bytes) -> str:
        req = (
            b"POST /v1/bans HTTP/1.1\r\n"
            + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )
        return _http_roundtrip(req)

    def delete_ban(id_str: str) -> str:
        req = (
            b"DELETE /v1/bans/" + id_str.encode("ascii") + b" HTTP/1.1\r\n"
            + auth +
            b"\r\n"
        )
        return _http_roundtrip(req)

    def get_bans() -> str:
        return _http_roundtrip(b"GET /v1/bans HTTP/1.1\r\n" + auth + b"\r\n")

    def get_history(nick: str = "") -> str:
        path = b"/v1/bans/history"
        if nick:
            path += b"?nick=" + nick.encode("ascii")
        return _http_roundtrip(b"GET " + path + b" HTTP/1.1\r\n" + auth + b"\r\n")

    # Pre-flight: ban list empty on a fresh staging dir.
    r = get_bans()
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans pre-flight: expected 200, got {status(r)!r}")
    if '"bans":[]' not in body_of(r).replace(" ", ""):
        raise TestFailure(
            f"GET /v1/bans pre-flight: expected empty list, got {body_of(r)!r}"
        )

    bans_tbl = staging_dir / "scripts" / "data" / "cmd_ban_bans.tbl"
    history_tbl = staging_dir / "scripts" / "data" / "cmd_ban_history.tbl"

    # 1. POST sid + duration + reason. The ADC user should be dropped.
    with _logged_in_user() as (adc, sid, _reader):
        body = (
            b'{"target_type":"sid","target":"' + sid.encode("ascii")
            + b'","duration_minutes":60,"reason":"smoke ban test"}'
        )
        r = post_ban(body)
        if "200 OK" not in status(r):
            raise TestFailure(f"POST /v1/bans (sid): expected 200, got {status(r)!r}; resp={r!r}")
        b = body_of(r)
        # Strengthening over the PR-1/2/3 string-contains pattern: also
        # assert the success-envelope `"ok":true` is present, so a 200
        # status with a malformed body (e.g. an error envelope leaked
        # via a router bug) is caught instead of false-passing on the
        # action substring alone.
        if '"ok":true' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: success envelope missing 'ok:true'; body={b!r}")
        if '"action":"ban"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: action missing; body={b!r}")
        if '"id":1' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: expected id:1; body={b!r}")
        if '"duration_minutes":60' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: duration mismatch; body={b!r}")
        if '"reason":"smokebantest"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: reason missing/wrong; body={b!r}")
        m = re.search(r'"expires_at":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"', b)
        if not m:
            raise TestFailure(f"POST /v1/bans: expires_at not ISO 8601; body={b!r}")
        # target_nick should be the registered firstnick ("dummy").
        if '"target_nick":"dummy"' not in b.replace(" ", ""):
            raise TestFailure(f"POST /v1/bans: target_nick should be 'dummy'; body={b!r}")

        # ADC drops (ISTA 232 + TL3600). The kick happens within the
        # same hub tick as the HTTP handler return.
        _assert_adc_drops(adc)

    # 2. GET /v1/bans now lists the entry at id=1.
    r = get_bans()
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans after add: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"id":1' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: id=1 missing; body={b!r}")
    if '"nick":"dummy"' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: nick=dummy missing; body={b!r}")
    if '"remaining_seconds":' not in b.replace(" ", ""):
        raise TestFailure(f"GET /v1/bans: remaining_seconds missing; body={b!r}")

    # 3. GET /v1/bans/history?nick=dummy lists the history entry.
    r = get_history("dummy")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/bans/history?nick=dummy: expected 200, got {status(r)!r}")
    b = body_of(r)
    if '"dummy"' not in b:
        raise TestFailure(f"GET history: dummy not in body; body={b!r}")
    if '"state":"active"' not in b.replace(" ", ""):
        raise TestFailure(f"GET history: expected state:active; body={b!r}")

    # 3b. Unfiltered history returns the same nick.
    r = get_history()
    if '"dummy"' not in body_of(r):
        raise TestFailure(f"GET history (no filter): missing dummy; body={body_of(r)!r}")

    # 4. Persistence: bans.tbl + history.tbl on disk reflect the POST.
    if not bans_tbl.exists():
        raise TestFailure(f"persistence: {bans_tbl} not written")
    if not history_tbl.exists():
        raise TestFailure(f"persistence: {history_tbl} not written")
    contents_bans = bans_tbl.read_text(encoding="utf-8")
    if 'nick = "dummy"' not in contents_bans:
        raise TestFailure(
            f"persistence: cmd_ban_bans.tbl missing dummy entry; contents={contents_bans!r}"
        )

    # 5. DELETE /v1/bans/1 -> 200 + envelope w/ action:"unban", removed.
    r = delete_ban("1")
    if "200 OK" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/1: expected 200, got {status(r)!r}; resp={r!r}")
    b = body_of(r)
    if '"ok":true' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: success envelope missing 'ok:true'; body={b!r}")
    if '"action":"unban"' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: action missing; body={b!r}")
    if '"removed":' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: removed snapshot missing; body={b!r}")
    if '"nick":"dummy"' not in b.replace(" ", ""):
        raise TestFailure(f"DELETE /v1/bans/1: removed.nick=dummy missing; body={b!r}")

    # 5b. Persistence: bans.tbl no longer contains dummy after the DELETE.
    contents_bans = bans_tbl.read_text(encoding="utf-8")
    if 'nick = "dummy"' in contents_bans:
        raise TestFailure(
            f"persistence: cmd_ban_bans.tbl still has dummy after DELETE; contents={contents_bans!r}"
        )

    # 6. DELETE /v1/bans/1 again -> 404 (no entry at index).
    r = delete_ban("1")
    if "404" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/1 (empty list): expected 404, got {status(r)!r}")
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"DELETE second: expected E_NOT_FOUND; resp={r!r}")

    # 7. DELETE /v1/bans/foo -> 400 (not an integer).
    r = delete_ban("foo")
    if "400" not in status(r):
        raise TestFailure(f"DELETE /v1/bans/foo: expected 400, got {status(r)!r}")
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(f"DELETE foo: expected E_BAD_INPUT; resp={r!r}")

    # 8. POST cid blind-add. cid lookup hits no online user; cmd_ban
    #    writes the ban entry anyway (matches ADC behaviour). Use a
    #    plausible 39-char base32 CID-looking string; the hub does not
    #    validate the format on input.
    cid_blind = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    body = (
        b'{"target_type":"cid","target":"' + cid_blind.encode("ascii")
        + b'","duration_minutes":5,"reason":"blind add"}'
    )
    r = post_ban(body)
    if "200 OK" not in status(r):
        raise TestFailure(f"POST /v1/bans (cid blind): expected 200, got {status(r)!r}; resp={r!r}")
    b = body_of(r)
    # target_nick should be absent (no online resolve), but the entry
    # still lands at id=1 since the bans list was empty after step 5.
    if '"id":1' not in b.replace(" ", ""):
        raise TestFailure(f"POST cid blind: expected id:1; body={b!r}")
    if '"target_nick"' in b:
        raise TestFailure(f"POST cid blind: target_nick should be absent; body={b!r}")

    # Cleanup blind-add so subsequent tests start clean.
    r = delete_ban("1")
    if "200 OK" not in status(r):
        raise TestFailure(f"cleanup DELETE cid blind: expected 200, got {status(r)!r}")

    # 9. POST nick unknown -> 404 (not online, not registered).
    body = b'{"target_type":"nick","target":"nobody-known-nick","duration_minutes":5}'
    r = post_ban(body)
    if "404" not in status(r):
        raise TestFailure(f"POST nick unknown: expected 404, got {status(r)!r}")
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(f"POST nick unknown: expected E_NOT_FOUND; resp={r!r}")

    # 10. POST invalid target_type -> 400 (schema enum reject).
    body = b'{"target_type":"frob","target":"x","duration_minutes":5}'
    r = post_ban(body)
    if "400" not in status(r):
        raise TestFailure(f"POST invalid target_type: expected 400, got {status(r)!r}")
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(f"POST invalid type: expected E_BAD_INPUT; resp={r!r}")

    # 11. POST reason > 256 chars -> 400 (schema max_length reject).
    long_reason = "x" * 300
    body = (
        b'{"target_type":"ip","target":"10.0.0.1","duration_minutes":5,"reason":"'
        + long_reason.encode("ascii") + b'"}'
    )
    r = post_ban(body)
    if "400" not in status(r):
        raise TestFailure(f"POST reason >256: expected 400, got {status(r)!r}")

    # 12. /v1/endpoints catalog lists all four cmd_ban routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    for needed in ('"/v1/bans"', '"/v1/bans/history"', '"/v1/bans/{id}"'):
        if needed not in b:
            raise TestFailure(f"catalog missing {needed!r}; body={b!r}")


def test_cmd_ban_permanent_http(staging_dir: Path, proc=None):
    """cmd_ban v0.44: POST /v1/bans {permanent:true} bans forever (#444).

    HTTP mirror of the ADC `+ban ... permanent` keyword. Uses an ip
    blind-add (no online user needed), so this is self-contained. The
    entry stores a real `permanent = true` marker (time 0), never a
    magic negative, and carries NO expires_at.

    Provable pre-fix (CLAUDE.md §1a.7): pre-v0.44 the handler does not
    read body.permanent and the request_schema does not declare it. The
    validator ignores unknown body fields (it iterates the schema, not
    the body), so pre-fix the POST creates a NORMAL timed ban - the
    response has expires_at set and no `permanent` field. Asserting the
    response and the GET entry carry `"permanent": true` and NO
    expires_at therefore fails pre-fix.

    Shares the staging hub with the other /v1/bans tests; cleans up with
    DELETE so the ban list is empty again for anything downstream.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def nospace(s):
        return s.replace(" ", "")

    # 1. POST a permanent ip ban.
    body = b'{"target_type":"ip","target":"198.51.100.44","permanent":true,"reason":"permhttp"}'
    req = (
        b"POST /v1/bans HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
    )
    r = _http_roundtrip(req)
    if "200 OK" not in status(r):
        raise TestFailure(f"POST permanent ban: expected 200, got {status(r)!r} body={body_of(r)!r}")
    rb = nospace(body_of(r))
    if '"permanent":true' not in rb:
        raise TestFailure(
            f"POST permanent ban response missing '\"permanent\":true'. Pre-fix the "
            f"handler ignores body.permanent and creates a normal timed ban: {body_of(r)!r}"
        )
    if '"expires_at"' in rb:
        raise TestFailure(
            f"POST permanent ban response must not carry expires_at (a permanent ban "
            f"never expires): {body_of(r)!r}"
        )

    # 2. GET /v1/bans - the stored entry is permanent, no expires_at.
    r = _http_roundtrip(b"GET /v1/bans HTTP/1.1\r\n" + auth + b"\r\n")
    gb = nospace(body_of(r))
    if '"permanent":true' not in gb:
        raise TestFailure(f"GET /v1/bans: permanent entry not flagged permanent: {body_of(r)!r}")
    if '"ip":"198.51.100.44"' not in gb:
        raise TestFailure(f"GET /v1/bans: permanent ip entry missing: {body_of(r)!r}")

    # 3. Persisted table carries the marker across a hypothetical reload.
    bans_tbl = staging_dir / "scripts" / "data" / "cmd_ban_bans.tbl"
    persisted = bans_tbl.read_text(encoding="utf-8", errors="replace")
    if "permanent" not in persisted or "true" not in persisted:
        raise TestFailure(
            f"cmd_ban_bans.tbl did not persist the permanent marker: {persisted[:600]!r}"
        )

    # 4. Clean up: find the id and DELETE it, leaving an empty list.
    import re as _re
    m = _re.search(r'"id"\s*:\s*(\d+)[^}]*198\.51\.100\.44', body_of(r)) \
        or _re.search(r'198\.51\.100\.44[^}]*"id"\s*:\s*(\d+)', body_of(r))
    ban_id = m.group(1) if m else "1"
    r = _http_roundtrip(
        b"DELETE /v1/bans/" + ban_id.encode("ascii") + b" HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(f"DELETE permanent ban id={ban_id}: expected 200, got {status(r)!r}")
    r = _http_roundtrip(b"GET /v1/bans HTTP/1.1\r\n" + auth + b"\r\n")
    if '"bans":[]' not in nospace(body_of(r)):
        raise TestFailure(f"ban list not empty after cleanup DELETE: {body_of(r)!r}")


def test_http_phase3_cmd_restart(staging_dir: Path, proc=None):
    """Phase 3 PR-1 of #82 / #225: cmd_restart plugin migrates to HTTP.

    Coexist pattern (same as Phase 2): the existing ADC +restart cmd
    is unchanged, the new POST /v1/restart endpoint is added in
    onStart. Both call the shared `do_restart()` helper.

    This test covers ONLY the rejection paths. The success path
    (X-Confirm: yes + valid body) is deliberately NOT exercised,
    because firing the restart would arm the exit timer and tear
    down the smoke hub before subsequent tests
    (test_inf_integer_clamps, BLOM / ZLIF / etc.) can run. The
    success-path code is exercised in production every time an
    operator types +restart.

    Coverage:
    - POST /v1/restart without X-Confirm header -> 400
      E_CONFIRMATION_REQUIRED (router-side gate per §4.6).
    - POST /v1/restart with X-Confirm: no -> 400 (router rejects
      anything that is not the literal "yes").
    - POST /v1/restart with oversized `message` field
      (>1024 chars) -> 400 E_BAD_INPUT (request_schema validator).
      X-Confirm IS set on this case to prove the schema check
      runs even after the X-Confirm gate clears.
    - /v1/endpoints catalog now lists POST /v1/restart.

    The hub MUST stay alive after every assertion: `in_progress`
    is only set when do_restart actually runs, which never happens
    on the reject paths.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Missing X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/restart without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 2. X-Confirm with non-"yes" value -> still 400.
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: no\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart with X-Confirm: no: expected 400, got {status(r)!r}"
        )

    # 3. Oversized `message` field with X-Confirm: yes -> 400 E_BAD_INPUT.
    # Confirms the request_schema is wired (max_length=1024).
    long_msg = "x" * 1100
    body = ('{"message":"' + long_msg + '"}').encode("ascii")
    req = (
        b"POST /v1/restart HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/restart oversized message: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/restart oversized message: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists POST /v1/restart.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/restart"' not in b:
        raise TestFailure(f"catalog missing /v1/restart; body={b!r}")


def test_http_phase3_cmd_shutdown(staging_dir: Path, proc=None):
    """Phase 3 PR-2 of #82 / #225: cmd_shutdown plugin migrates to HTTP.

    Mirror of test_http_phase3_cmd_restart. Same rejection-only
    coverage rationale: firing the shutdown would tear down the
    smoke hub before downstream tests can run, so the success path
    is exercised in production every time an operator types
    `+shutdown`.

    Coverage:
    - POST /v1/shutdown without X-Confirm header -> 400
      E_CONFIRMATION_REQUIRED (router-side gate per §4.6).
    - POST /v1/shutdown with X-Confirm: no -> 400.
    - POST /v1/shutdown with oversized `message` field
      (>1024 chars) + X-Confirm: yes -> 400 E_BAD_INPUT
      (request_schema validator).
    - /v1/endpoints catalog now lists POST /v1/shutdown.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Missing X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/shutdown without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 2. X-Confirm with non-"yes" value -> still 400.
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: no\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown with X-Confirm: no: expected 400, got {status(r)!r}"
        )

    # 3. Oversized `message` field with X-Confirm: yes -> 400 E_BAD_INPUT.
    long_msg = "x" * 1100
    body = ('{"message":"' + long_msg + '"}').encode("ascii")
    req = (
        b"POST /v1/shutdown HTTP/1.1\r\n"
        + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"\r\n" + body
    )
    r = _http_roundtrip(req)
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/shutdown oversized message: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/shutdown oversized message: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists POST /v1/shutdown.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/shutdown"' not in b:
        raise TestFailure(f"catalog missing /v1/shutdown; body={b!r}")


def test_http_phase3_cmd_errors(staging_dir: Path, proc=None):
    """Phase 3 PR-3 of #82 / #225: cmd_errors plugin migrates to HTTP.

    Read-only endpoint, admin scope. Pattern-setter for log-tail
    endpoints (Phase 3 PR-4 etc_cmdlog mirrors).

    Coverage:
    - Pre-seed log/error.log with known lines.
    - GET /v1/log/error -> 200 + envelope { ok:true, data:{ lines:
      [<all_lines>], returned, total_lines } }.
    - GET /v1/log/error?lines=2 -> 200 + last 2 lines only,
      returned=2, total_lines=N.
    - GET /v1/log/error?lines=invalid -> 200, falls back to default
      (no rejection per §6.4 clamping rule).
    - GET /v1/log/error?lines=99999 -> 200, clamped to 1000.
    - Anonymous GET (no Authorization header) -> 401.
    - /v1/endpoints catalog lists GET /v1/log/error.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # Seed log/error.log with 5 distinct lines. The hub may also
    # write to this file independently; assertions below check
    # SHAPE not exact content beyond "our seeded lines are visible".
    log_path = staging_dir / "log" / "error.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    seed = [
        "smoke seed line 1",
        "smoke seed line 2",
        "smoke seed line 3",
        "smoke seed line 4",
        "smoke seed line 5",
    ]
    with log_path.open("a", encoding="utf-8") as f:
        for line in seed:
            f.write(line + "\n")

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/log/error HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/log/error: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET default lines -> 200, lines array includes
    # all our seeded lines.
    r = _http_roundtrip(b"GET /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/error: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/log/error: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    lines = data.get("lines") or []
    total = data.get("total_lines")
    returned = data.get("returned")
    if not isinstance(lines, list) or not isinstance(total, int) or not isinstance(returned, int):
        raise TestFailure(
            f"GET /v1/log/error: malformed data shape; body={body_of(r)!r}"
        )
    if returned != len(lines):
        raise TestFailure(
            f"GET /v1/log/error: returned ({returned}) != len(lines) ({len(lines)})"
        )
    for needle in seed:
        if needle not in lines:
            raise TestFailure(
                f"GET /v1/log/error: seeded line {needle!r} missing; "
                f"got {lines!r}"
            )

    # 3. ?lines=2 -> returned=2, last two lines.
    r = _http_roundtrip(b"GET /v1/log/error?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("returned") != 2 or len(data.get("lines") or []) != 2:
        raise TestFailure(
            f"GET /v1/log/error?lines=2: expected returned=2; body={body_of(r)!r}"
        )

    # 4. ?lines=invalid -> falls back to default, returns 200.
    r = _http_roundtrip(b"GET /v1/log/error?lines=notanumber HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/error?lines=invalid: expected 200, got {status(r)!r}"
        )

    # 5. ?lines=99999 -> clamped to 1000 internally; returned <= 1000.
    r = _http_roundtrip(b"GET /v1/log/error?lines=99999 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    if returned is None or returned > 1000:
        raise TestFailure(
            f"GET /v1/log/error?lines=99999: returned={returned} not clamped; "
            f"body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists GET /v1/log/error.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/error"' not in b:
        raise TestFailure(f"catalog missing /v1/log/error; body={b!r}")


def test_http_phase3_etc_cmdlog(staging_dir: Path, proc=None):
    """Phase 3 PR-4 of #82 / #225: etc_cmdlog plugin migrates to HTTP.

    Mirror of Phase 3 PR-3 (cmd_errors). Read-only endpoint, admin
    scope. Same shape: lines / returned / total_lines.

    Coverage:
    - Pre-seed log/cmd.log with known lines.
    - GET /v1/log/cmd -> 200, seeded lines visible.
    - GET /v1/log/cmd?lines=2 -> 200, returned=2.
    - Anonymous -> 401.
    - /v1/endpoints catalog lists GET /v1/log/cmd.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    log_path = staging_dir / "log" / "cmd.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    seed = [
        "cmdlog seed line A",
        "cmdlog seed line B",
        "cmdlog seed line C",
    ]
    with log_path.open("a", encoding="utf-8") as f:
        for line in seed:
            f.write(line + "\n")

    # 1. Anonymous -> 401.
    r = _http_roundtrip(b"GET /v1/log/cmd HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/log/cmd: expected 401, got {status(r)!r}"
        )

    # 2. Default lines -> 200, all seeded lines visible.
    r = _http_roundtrip(b"GET /v1/log/cmd HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/log/cmd: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    lines = data.get("lines") or []
    for needle in seed:
        if needle not in lines:
            raise TestFailure(
                f"GET /v1/log/cmd: seeded line {needle!r} missing; got {lines!r}"
            )
    if data.get("returned") != len(lines):
        raise TestFailure(
            f"GET /v1/log/cmd: returned != len(lines); body={body_of(r)!r}"
        )

    # 3. ?lines=2 -> exactly 2 returned (last two of file's tail).
    r = _http_roundtrip(b"GET /v1/log/cmd?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("returned") != 2 or len(data.get("lines") or []) != 2:
        raise TestFailure(
            f"GET /v1/log/cmd?lines=2: expected returned=2; body={body_of(r)!r}"
        )

    # 4. /v1/endpoints catalog lists GET /v1/log/cmd.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/cmd"' not in b:
        raise TestFailure(f"catalog missing /v1/log/cmd; body={b!r}")


def test_http_phase3_etc_log_cleaner(staging_dir: Path, proc=None):
    """Phase 3 PR-5 of #82 / #225: etc_log_cleaner plugin migrates
    to HTTP.

    Write endpoint (DELETE), admin scope. Truncates a known log
    file via the API and asserts the file shrinks to 0 bytes.

    Coverage:
    - Pre-seed log/error.log with known content.
    - DELETE /v1/log/error -> 200, action:"log-cleared",
      bytes_before > 0.
    - Verify file on disk is now 0 bytes.
    - DELETE /v1/log/unknown -> 400 E_BAD_INPUT.
    - DELETE /v1/log/error AGAIN -> 200, bytes_before=0 (already
      truncated, idempotent).
    - Anonymous DELETE -> 401.
    - /v1/endpoints catalog lists DELETE /v1/log/{name}.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    log_path = staging_dir / "log" / "error.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write("log-cleaner-smoke marker line\n")
    size_before = log_path.stat().st_size
    if size_before == 0:
        raise TestFailure(f"failed to seed {log_path}: still 0 bytes")

    # 1. Anonymous -> 401.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE /v1/log/error: expected 401, got {status(r)!r}"
        )

    # 2. DELETE /v1/log/error -> 200, action + bytes_before > 0.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/error: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"DELETE /v1/log/error: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if data.get("action") != "log-cleared":
        raise TestFailure(
            f"DELETE /v1/log/error: expected action=log-cleared; "
            f"body={body_of(r)!r}"
        )
    if data.get("name") != "error":
        raise TestFailure(
            f"DELETE /v1/log/error: expected name=error; body={body_of(r)!r}"
        )
    if not isinstance(data.get("bytes_before"), int) or data["bytes_before"] <= 0:
        raise TestFailure(
            f"DELETE /v1/log/error: expected bytes_before > 0; "
            f"body={body_of(r)!r}"
        )

    # 3. File on disk is now 0 bytes.
    size_after = log_path.stat().st_size if log_path.exists() else 0
    if size_after != 0:
        raise TestFailure(
            f"DELETE /v1/log/error: file still has {size_after} bytes "
            f"after truncate (path={log_path})"
        )

    # 4. Unknown name -> 400 E_BAD_INPUT.
    r = _http_roundtrip(b"DELETE /v1/log/notalog HTTP/1.1\r\n" + auth + b"\r\n")
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/notalog: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"DELETE /v1/log/notalog: expected E_BAD_INPUT; "
            f"body={body_of(r)!r}"
        )

    # 5. Idempotent re-clean -> 200, bytes_before=0.
    r = _http_roundtrip(b"DELETE /v1/log/error HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/log/error (idempotent): expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("bytes_before") != 0:
        raise TestFailure(
            f"DELETE /v1/log/error (idempotent): expected bytes_before=0; "
            f"body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists DELETE /v1/log/{name}.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/log/{name}"' not in b:
        raise TestFailure(f"catalog missing /v1/log/{{name}}; body={b!r}")


def test_http_phase4_etc_chatlog(staging_dir: Path, proc=None):
    """Phase 4 PR-1 of #82 / #249: etc_chatlog plugin migrates to HTTP.

    Read scope. Mirror of Phase 3 PR-3 (cmd_errors) for the
    tail-style shape, but read on the chat-history buffer instead
    of an on-disk log file.

    Coverage:
    - Anonymous GET (no Authorization header) -> 401.
    - Authenticated GET -> 200 with envelope { ok:true, data:{
      lines:[{timestamp, nick, message}, ...], returned, total_lines } }.
    - GET ?lines=2 -> returned <= 2 (the in-memory buffer may have
      fewer entries on a fresh hub; clamp upward, not exact).
    - GET ?lines=invalid -> 200, falls back to default per §6.4.
    - GET ?lines=99999 -> 200, clamped to min(cfg max_lines, 1000).
      On a fresh-staging hub cfg ships max_lines=200, so the
      effective bound is 200 AND `returned <= total_lines` (clamp-
      to-buffer-size invariant).
    - /v1/endpoints catalog lists GET /v1/chatlog.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/chatlog HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/chatlog: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET -> 200 + valid envelope shape.
    r = _http_roundtrip(b"GET /v1/chatlog HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/chatlog: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/chatlog: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    lines = data.get("lines")
    total = data.get("total_lines")
    returned = data.get("returned")
    if not isinstance(lines, list) or not isinstance(total, int) or not isinstance(returned, int):
        raise TestFailure(
            f"GET /v1/chatlog: malformed data shape; body={body_of(r)!r}"
        )
    if returned != len(lines):
        raise TestFailure(
            f"GET /v1/chatlog: returned ({returned}) != len(lines) ({len(lines)})"
        )
    # Each entry (if any) must carry the structured shape.
    for entry in lines:
        if not isinstance(entry, dict):
            raise TestFailure(
                f"GET /v1/chatlog: entry not an object; got {entry!r}"
            )
        for key in ("timestamp", "nick", "message"):
            if key not in entry:
                raise TestFailure(
                    f"GET /v1/chatlog: entry missing {key!r}; got {entry!r}"
                )

    # 3. ?lines=2 -> returned <= 2 (buffer may have fewer entries).
    r = _http_roundtrip(b"GET /v1/chatlog?lines=2 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    if returned is None or returned > 2:
        raise TestFailure(
            f"GET /v1/chatlog?lines=2: expected returned<=2; body={body_of(r)!r}"
        )

    # 4. ?lines=invalid -> falls back to default, returns 200.
    r = _http_roundtrip(b"GET /v1/chatlog?lines=notanumber HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/chatlog?lines=invalid: expected 200, got {status(r)!r}"
        )

    # 5. ?lines=99999 -> clamped to min(cfg etc_chatlog_max_lines,
    # HTTP_MAX_LINES=1000). The default cfg ships max_lines=200,
    # so on a fresh-staging hub `returned` must be <= 200 AND <=
    # data['total_lines'] (clamp-to-buffer-size invariant). The
    # weaker `<= 1000` assertion would pass trivially on a stock
    # cfg and not exercise the cap, so anchor against both bounds.
    r = _http_roundtrip(b"GET /v1/chatlog?lines=99999 HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    returned = data.get("returned")
    total = data.get("total_lines")
    if returned is None or returned > 200:
        raise TestFailure(
            f"GET /v1/chatlog?lines=99999: returned={returned} not clamped "
            f"to cfg max_lines=200; body={body_of(r)!r}"
        )
    if total is not None and returned > total:
        raise TestFailure(
            f"GET /v1/chatlog?lines=99999: returned={returned} > "
            f"total_lines={total}; body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists GET /v1/chatlog.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/chatlog"' not in b:
        raise TestFailure(f"catalog missing /v1/chatlog; body={b!r}")


def test_http_phase4_etc_records(staging_dir: Path, proc=None):
    """Phase 4 PR-2 of #82 / #249: etc_records plugin migrates to HTTP.

    Two endpoints: GET /v1/records (read) for the snapshot, DELETE
    /v1/records (admin) for the reset. Reset re-samples live state
    immediately so the post-reset GET returns non-zero `count` (the
    dummy + smoke client connections push max_users up).

    Coverage:
    - Anonymous GET -> 401.
    - Authenticated GET -> 200 + envelope { hub_share, max_users,
      top_sharer } with the documented sub-object shapes.
    - Anonymous DELETE -> 401.
    - Authenticated DELETE -> 200 + envelope { action }.
    - Post-DELETE GET -> 200 (route still serves; reset() rebind
      did not orphan the closure - reference_lua_plugin_exports
      rebind-safety check).
    - /v1/endpoints catalog lists both routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/records HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/records: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET -> 200 + valid envelope shape.
    r = _http_roundtrip(b"GET /v1/records HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/records: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/records: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    for top in ("hub_share", "max_users", "top_sharer"):
        if not isinstance(data.get(top), dict):
            raise TestFailure(
                f"GET /v1/records: missing/non-object {top!r}; body={body_of(r)!r}"
            )
    if not isinstance(data["hub_share"].get("total_bytes"), int):
        raise TestFailure(
            f"GET /v1/records: hub_share.total_bytes not int; body={body_of(r)!r}"
        )
    if not isinstance(data["max_users"].get("count"), int):
        raise TestFailure(
            f"GET /v1/records: max_users.count not int; body={body_of(r)!r}"
        )
    if not isinstance(data["top_sharer"].get("nick"), str):
        raise TestFailure(
            f"GET /v1/records: top_sharer.nick not str; body={body_of(r)!r}"
        )
    if not isinstance(data["top_sharer"].get("share_bytes"), int):
        raise TestFailure(
            f"GET /v1/records: top_sharer.share_bytes not int; body={body_of(r)!r}"
        )

    # 3. Anonymous DELETE -> 401.
    r = _http_roundtrip(b"DELETE /v1/records HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE /v1/records: expected 401, got {status(r)!r}"
        )

    # 4. Authenticated DELETE -> 200 + action envelope.
    r = _http_roundtrip(b"DELETE /v1/records HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/records: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"DELETE /v1/records: ok=false; body={body_of(r)!r}")
    if (parsed.get("data") or {}).get("action") != "records-reset":
        raise TestFailure(
            f"DELETE /v1/records: expected action=records-reset; "
            f"body={body_of(r)!r}"
        )

    # 5. Post-DELETE GET -> 200, valid envelope, AND must actually
    # be reading from the rebound table. `reset()` reseeds the
    # counters to 0 (#618 normalised the hub_share seed from a
    # vestigial 1 to 0), then immediately calls hubshare() +
    # onliners(). If the GET handler closed over the OLD records
    # table by-reference rather than the upvalue, the post-reset
    # read would crash or return a non-int - so a valid int
    # total_bytes from a 200 envelope proves the rebind survived
    # (the reference_lua_plugin_exports regression-guard). The
    # value is >= 0 (0 when the connected smoke clients advertise
    # no share, which they do not; max_users.count still rises via
    # onliners()).
    r = _http_roundtrip(b"GET /v1/records HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/records (post-reset): expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(
            f"GET /v1/records (post-reset): ok=false; body={body_of(r)!r}"
        )
    post_total = (parsed.get("data") or {}).get("hub_share", {}).get("total_bytes")
    if not isinstance(post_total, int) or post_total < 0:
        raise TestFailure(
            f"GET /v1/records (post-reset): expected hub_share.total_bytes "
            f">= 0 (reset() seeds 0 then re-samples); got {post_total!r}; "
            f"body={body_of(r)!r}"
        )

    # 6. /v1/endpoints catalog lists both routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/records"' not in b:
        raise TestFailure(f"catalog missing /v1/records; body={b!r}")


def test_http_phase4_etc_blacklist(staging_dir: Path, proc=None):
    """Phase 4 PR-3 of #82 / #249: etc_blacklist plugin migrates to HTTP.

    Two endpoints: GET /v1/blacklist (read) lists all blacklisted
    nicks, DELETE /v1/blacklist/{nick} (admin) removes one.

    Self-seeding: registers a throwaway nick via POST /v1/registered
    then delreg's it with a reason via DELETE /v1/registered/{nick}
    (which cmd_delreg's `blacklist_add` records in the blacklist
    file). The test is order-independent - it does not rely on any
    prior test's side effects.

    Coverage:
    - Anonymous GET -> 401.
    - Authenticated GET -> 200 + envelope; entries contains the
      seeded nick with the expected by + reason fields.
    - Anonymous DELETE -> 401.
    - DELETE on a never-existed nick -> 404 (idempotent 200 would
      mask typos).
    - DELETE seeded nick -> 200 + `removed` snapshot.
    - DELETE seeded nick AGAIN -> 404 (entry is gone).
    - Post-DELETE GET -> seeded nick is NOT in entries (file write
      actually persisted, not just in-memory state).
    - /v1/endpoints catalog lists both routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    target = "smoke_pr3_bl_target"
    seed_reason = "smoke PR-3 blacklist seed"

    # Seed step a: register the target nick.
    create_body = (
        b'{"nick":"' + target.encode("ascii") + b'","level":10}'
    )
    r = _http_roundtrip(
        b"POST /v1/registered HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n"
        b"\r\n" + create_body
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PR-3 seed: POST /v1/registered (target={target!r}): "
            f"expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )

    # Seed step b: delreg with reason; cmd_delreg's blacklist_add
    # writes the entry we will GET + DELETE below.
    delreg_body = (
        b'{"reason":"' + seed_reason.encode("ascii") + b'"}'
    )
    r = _http_roundtrip(
        ("DELETE /v1/registered/" + target + " HTTP/1.1\r\n").encode("ascii")
        + auth + b"X-Confirm: yes\r\n"
        + b"Content-Type: application/json\r\n"
        + b"Content-Length: " + str(len(delreg_body)).encode("ascii") + b"\r\n"
        + b"\r\n" + delreg_body
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PR-3 seed: DELETE /v1/registered/{target}: "
            f"expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/blacklist HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/blacklist: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET -> 200; entries contains smoke_pr4_renamed.
    r = _http_roundtrip(b"GET /v1/blacklist HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/blacklist: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/blacklist: ok=false; body={body_of(r)!r}")
    entries = (parsed.get("data") or {}).get("entries")
    if not isinstance(entries, list):
        raise TestFailure(
            f"GET /v1/blacklist: entries not a list; body={body_of(r)!r}"
        )
    found = None
    for entry in entries:
        if entry.get("nick") == target:
            found = entry
            break
    if not found:
        raise TestFailure(
            f"GET /v1/blacklist: target {target!r} not found in entries; "
            f"got {entries!r}"
        )
    for key in ("blacklisted_at", "by", "reason"):
        if key not in found:
            raise TestFailure(
                f"GET /v1/blacklist: entry missing {key!r}; got {found!r}"
            )
    if seed_reason not in found.get("reason", ""):
        raise TestFailure(
            f"GET /v1/blacklist: expected reason to contain "
            f"{seed_reason!r}; got {found!r}"
        )

    # 3. Anonymous DELETE -> 401.
    r = _http_roundtrip(
        ("DELETE /v1/blacklist/" + target + " HTTP/1.1\r\n\r\n").encode("ascii")
    )
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE /v1/blacklist/{target}: expected 401, "
            f"got {status(r)!r}"
        )

    # 4. DELETE never-existed nick -> 404.
    r = _http_roundtrip(
        b"DELETE /v1/blacklist/never_existed_nick HTTP/1.1\r\n"
        + auth + b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/blacklist/never_existed_nick: expected 404, "
            f"got {status(r)!r}"
        )

    # 5. DELETE smoke_pr4_renamed -> 200 + removed snapshot.
    r = _http_roundtrip(
        ("DELETE /v1/blacklist/" + target + " HTTP/1.1\r\n").encode("ascii")
        + auth + b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/blacklist/{target}: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(
            f"DELETE /v1/blacklist/{target}: ok=false; body={body_of(r)!r}"
        )
    data = parsed.get("data") or {}
    if data.get("action") != "blacklist-removed":
        raise TestFailure(
            f"DELETE /v1/blacklist/{target}: expected action=blacklist-removed; "
            f"got {data!r}"
        )
    if data.get("nick") != target:
        raise TestFailure(
            f"DELETE /v1/blacklist/{target}: expected nick={target!r}; "
            f"got {data!r}"
        )
    removed = data.get("removed") or {}
    for key in ("blacklisted_at", "by", "reason"):
        if key not in removed:
            raise TestFailure(
                f"DELETE /v1/blacklist/{target}: removed missing {key!r}; "
                f"got {removed!r}"
            )

    # 6. DELETE smoke_pr4_renamed AGAIN -> 404 (entry gone).
    r = _http_roundtrip(
        ("DELETE /v1/blacklist/" + target + " HTTP/1.1\r\n").encode("ascii")
        + auth + b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/blacklist/{target} (second): expected 404 "
            f"(entry already removed), got {status(r)!r}"
        )

    # 7. Post-DELETE GET -> target is NOT in entries.
    r = _http_roundtrip(b"GET /v1/blacklist HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    entries = (parsed.get("data") or {}).get("entries") or []
    for entry in entries:
        if entry.get("nick") == target:
            raise TestFailure(
                f"GET /v1/blacklist (post-DELETE): target {target!r} still "
                f"present; got {entries!r}"
            )

    # 8. /v1/endpoints catalog lists both routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/blacklist"' not in b:
        raise TestFailure(f"catalog missing /v1/blacklist; body={b!r}")
    if '"/v1/blacklist/{nick}"' not in b:
        raise TestFailure(f"catalog missing /v1/blacklist/{{nick}}; body={b!r}")


def test_http_phase4_hub_runtime(staging_dir: Path, proc=None):
    """Phase 4 PR-4 of #82 / #249: hub_runtime plugin migrates to HTTP.

    Two endpoints: GET /v1/runtime (read) returns raw integer
    seconds for session + total, PUT /v1/runtime (admin) sets the
    persisted counter to the supplied value.

    Coverage:
    - Anonymous GET -> 401.
    - Authenticated GET -> 200 + envelope {session_seconds (int>=0),
      total_seconds (int>=0)}.
    - Anonymous PUT -> 401.
    - PUT without body -> 400 (schema-required hubruntime).
    - PUT with negative value -> 400.
    - PUT with non-integer value -> 400.
    - PUT {hubruntime: 12345} -> 200 + action envelope.
    - Post-PUT GET -> total_seconds reflects the seeded value
      (no exact equality because the 60s onTimer may fire between
      requests; assert seeded <= ts <= seeded + 120 to allow a
      single intervening tick while keeping the check tight).
    - PUT {hubruntime: 0} -> 200 (the reset shape).
    - /v1/endpoints catalog lists both routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(body_bytes):
        return _http_roundtrip(
            b"PUT /v1/runtime HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body_bytes)).encode("ascii") + b"\r\n"
            b"\r\n" + body_bytes
        )

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /v1/runtime HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/runtime: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET -> 200 + envelope shape.
    r = _http_roundtrip(b"GET /v1/runtime HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/runtime: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/runtime: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    ss = data.get("session_seconds")
    ts = data.get("total_seconds")
    if not isinstance(ss, int) or ss < 0:
        raise TestFailure(
            f"GET /v1/runtime: session_seconds not non-negative int; "
            f"body={body_of(r)!r}"
        )
    if not isinstance(ts, int) or ts < 0:
        raise TestFailure(
            f"GET /v1/runtime: total_seconds not non-negative int; "
            f"body={body_of(r)!r}"
        )

    # 3. Anonymous PUT -> 401.
    r = _http_roundtrip(b"PUT /v1/runtime HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT /v1/runtime: expected 401, got {status(r)!r}"
        )

    # 4. PUT empty body -> 400 (hubruntime required).
    r = put(b"{}")
    if "400" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime missing hubruntime: expected 400, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 5. PUT negative value -> 400.
    r = put(b'{"hubruntime":-1}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime negative: expected 400, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 6. PUT non-integer -> 400.
    r = put(b'{"hubruntime":3.14}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime float: expected 400, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 6b. PUT string -> 400 (handler's type check rejects non-number).
    r = put(b'{"hubruntime":"abc"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime string: expected 400, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 7. PUT a specific value -> 200 + action envelope.
    seeded = 12345
    r = put(b'{"hubruntime":' + str(seeded).encode("ascii") + b"}")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"PUT /v1/runtime: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if data.get("action") != "runtime-set" or data.get("hubruntime") != seeded:
        raise TestFailure(
            f"PUT /v1/runtime: unexpected envelope; body={body_of(r)!r}"
        )

    # 7b. #445: the runtime store now lives in the operator-owned
    # scripts/data/ dir, NOT the shipped core/hci.lua that every upgrade
    # clobbers. Pre-fix the store WAS core/hci.lua and
    # scripts/data/hub_runtime.tbl never existed - so this existence check
    # alone fails on the unpatched plugin (race-free: no numeric compare
    # that an intervening 60s onTimer tick could shift).
    runtime_tbl = staging_dir / "scripts" / "data" / "hub_runtime.tbl"
    if not runtime_tbl.is_file():
        raise TestFailure(
            "#445: scripts/data/hub_runtime.tbl missing after PUT - the "
            "runtime store did not move off the shipped core/hci.lua"
        )
    if "hubruntime" not in runtime_tbl.read_text(encoding="utf-8", errors="replace"):
        raise TestFailure("#445: hub_runtime.tbl present but has no hubruntime field")
    # The shipped core/hci.lua is read only as the migration source and is
    # never written; the PUT value must not have leaked into it.
    legacy = staging_dir / "core" / "hci.lua"
    if legacy.is_file() and str(seeded) in legacy.read_text(encoding="utf-8", errors="replace"):
        raise TestFailure(
            f"#445: PUT value {seeded} leaked into the shipped core/hci.lua "
            "- the store is still written there"
        )

    # 8. Post-PUT GET -> total_seconds >= seeded value (allowing
    # for an intervening 60s onTimer tick to add up to ~60s).
    r = _http_roundtrip(b"GET /v1/runtime HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    ts = (parsed.get("data") or {}).get("total_seconds")
    if not isinstance(ts, int) or ts < seeded or ts > seeded + 120:
        raise TestFailure(
            f"GET /v1/runtime (post-PUT): expected total_seconds in "
            f"[{seeded}, {seeded + 120}], got {ts!r}; body={body_of(r)!r}"
        )

    # 9. PUT 0 (the reset shape) -> 200.
    r = put(b'{"hubruntime":0}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT /v1/runtime reset shape: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 10. /v1/endpoints catalog lists both routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/runtime"' not in b:
        raise TestFailure(f"catalog missing /v1/runtime; body={b!r}")


def test_http_phase4_etc_msgmanager(staging_dir: Path, proc=None):
    """Phase 4 PR-5 of #82 / #249: etc_msgmanager plugin migrates to HTTP.

    Three endpoints:
    - GET /v1/msgmanager (read): combined blocks + settings.
    - POST /v1/msgmanager/{nick} (admin): block with mode enum.
    - DELETE /v1/msgmanager/{nick} (admin): unblock.

    Block + unblock are offline-tolerant by design (a divergence
    from ADC `+msgmanager` which requires online targets), so the
    test seeds via POST against a never-existed nick - no ADC user
    login needed.

    Coverage:
    - Anonymous GET / POST / DELETE -> 401.
    - GET pre-seed -> 200 + envelope with blocks=[] (or non-empty
      if a prior test seeded - we only assert shape, not emptiness).
    - POST without body -> 400 (missing required mode).
    - POST with invalid mode -> 400 (enum reject).
    - POST happy path -> 200 + envelope.
    - POST same nick again -> 409 (mode change requires DELETE first).
    - GET post-POST -> blocks contains our seeded entry.
    - DELETE happy path -> 200 + previous_mode snapshot.
    - DELETE same nick again -> 404.
    - DELETE never-existed nick -> 404.
    - /v1/endpoints catalog lists all three routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    target = "smoke_pr5_msg_target"

    def post(nick, body_bytes):
        return _http_roundtrip(
            ("POST /v1/msgmanager/" + nick + " HTTP/1.1\r\n").encode("ascii")
            + auth + b"Content-Type: application/json\r\n"
            + b"Content-Length: " + str(len(body_bytes)).encode("ascii") + b"\r\n"
            + b"\r\n" + body_bytes
        )

    def delete(nick, with_auth=True):
        prefix = ("DELETE /v1/msgmanager/" + nick + " HTTP/1.1\r\n").encode("ascii")
        if with_auth:
            return _http_roundtrip(prefix + auth + b"\r\n")
        return _http_roundtrip(prefix + b"\r\n")

    # 1. Anonymous calls -> 401.
    r = _http_roundtrip(b"GET /v1/msgmanager HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/msgmanager: expected 401, got {status(r)!r}"
        )
    r = _http_roundtrip(
        ("POST /v1/msgmanager/" + target + " HTTP/1.1\r\n\r\n").encode("ascii")
    )
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/msgmanager/{target}: expected 401, got {status(r)!r}"
        )
    r = delete(target, with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE /v1/msgmanager/{target}: expected 401, got {status(r)!r}"
        )

    # 2. GET pre-seed -> 200 + envelope shape.
    r = _http_roundtrip(b"GET /v1/msgmanager HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/msgmanager: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/msgmanager: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if not isinstance(data.get("blocks"), list):
        raise TestFailure(
            f"GET /v1/msgmanager: blocks not a list; body={body_of(r)!r}"
        )
    settings = data.get("settings") or {}
    for key in ("activate", "blocked_main_levels", "blocked_pm_levels"):
        if key not in settings:
            raise TestFailure(
                f"GET /v1/msgmanager: settings missing {key!r}; body={body_of(r)!r}"
            )

    # 3. POST missing body -> 400 (mode required).
    r = post(target, b"{}")
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/msgmanager/{target} missing mode: expected 400, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 4. POST invalid mode -> 400 (enum reject).
    r = post(target, b'{"mode":"not-a-mode"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/msgmanager/{target} invalid mode: expected 400, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 5. POST happy path -> 200 + envelope.
    r = post(target, b'{"mode":"main"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/msgmanager/{target}: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(
            f"POST /v1/msgmanager/{target}: ok=false; body={body_of(r)!r}"
        )
    data = parsed.get("data") or {}
    if data.get("action") != "blocked" or data.get("nick") != target or data.get("mode") != "main":
        raise TestFailure(
            f"POST /v1/msgmanager/{target}: unexpected envelope; body={body_of(r)!r}"
        )

    # 6. POST same nick again -> 409 (must DELETE first to change mode).
    r = post(target, b'{"mode":"pm"}')
    if "409" not in status(r):
        raise TestFailure(
            f"POST /v1/msgmanager/{target} duplicate: expected 409, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 7. GET post-POST -> blocks contains seeded entry.
    r = _http_roundtrip(b"GET /v1/msgmanager HTTP/1.1\r\n" + auth + b"\r\n")
    parsed = _json.loads(body_of(r))
    blocks = (parsed.get("data") or {}).get("blocks") or []
    found = None
    for entry in blocks:
        if entry.get("nick") == target:
            found = entry
            break
    if not found:
        raise TestFailure(
            f"GET /v1/msgmanager (post-POST): target {target!r} not in blocks; "
            f"got {blocks!r}"
        )
    if found.get("mode") != "main":
        raise TestFailure(
            f"GET /v1/msgmanager (post-POST): expected mode=main; got {found!r}"
        )

    # 8. DELETE happy path -> 200 + previous_mode snapshot.
    r = delete(target)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/msgmanager/{target}: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "unblocked" or data.get("nick") != target or data.get("previous_mode") != "main":
        raise TestFailure(
            f"DELETE /v1/msgmanager/{target}: unexpected envelope; body={body_of(r)!r}"
        )

    # 9. DELETE same nick again -> 404.
    r = delete(target)
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/msgmanager/{target} (second): expected 404, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 10. DELETE never-existed nick -> 404.
    r = delete("never_existed_msg_target")
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/msgmanager/never_existed: expected 404, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 11. Catalog lists all three routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/msgmanager"' not in b:
        raise TestFailure(f"catalog missing /v1/msgmanager; body={b!r}")
    if '"/v1/msgmanager/{nick}"' not in b:
        raise TestFailure(f"catalog missing /v1/msgmanager/{{nick}}; body={b!r}")


def test_http_phase4_cmd_usercleaner(staging_dir: Path, proc=None):
    """Phase 4 PR-6 of #82 / #249: cmd_usercleaner plugin migrates to HTTP.

    Five endpoints: GET + DELETE /v1/usercleaner/expired (read +
    admin), GET + DELETE /v1/usercleaner/ghosts (read + admin),
    DELETE /v1/usercleaner/orphan-comments (admin, #311). All three
    DELETEs are router-enforced X-Confirm gated (§4.6).

    Note on coverage: on a fresh hub no regged users qualify as
    expired (no `lastseen` older than cfg `expired_days=365`) or
    ghost (no never-logged-in regs older than 365 days). The test
    therefore exercises:
    - Auth (anonymous -> 401 on all 4 routes)
    - GET envelope shape (entries may be empty - acceptable, the
      shape is what matters)
    - DELETE without X-Confirm -> 400 E_CONFIRMATION_REQUIRED
      (the X-Confirm enforcement IS the BLOCKER-grade router
      wiring check; missing it would let any admin token bulk-
      delreg without a confirmation header)
    - DELETE with X-Confirm -> 200 + envelope { deleted,
      skipped_exception, skipped_protected_level } (likely empty
      arrays on a fresh hub, but the shape proves the cascade
      handler ran)
    - Catalog lists all 4 routes

    The actual cascade logic (delreg + description_del + ban.del
    + block.del) is shared verbatim with the ADC `+usercleaner
    delexpired/delghosts` cmds and is presumed correct by the
    existing plugin tests; the HTTP path just wraps the existing
    helper.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    routes = [
        ("GET", "/v1/usercleaner/expired"),
        ("DELETE", "/v1/usercleaner/expired"),
        ("GET", "/v1/usercleaner/ghosts"),
        ("DELETE", "/v1/usercleaner/ghosts"),
        ("DELETE", "/v1/usercleaner/orphan-comments"),
    ]

    # 1. Anonymous calls -> 401 on all 4 routes.
    for method, path in routes:
        r = _http_roundtrip(
            (method + " " + path + " HTTP/1.1\r\n\r\n").encode("ascii")
        )
        if "401" not in status(r):
            raise TestFailure(
                f"anonymous {method} {path}: expected 401, got {status(r)!r}"
            )

    # 2. GET expired -> 200 + envelope.
    r = _http_roundtrip(b"GET /v1/usercleaner/expired HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/usercleaner/expired: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(
            f"GET /v1/usercleaner/expired: ok=false; body={body_of(r)!r}"
        )
    data = parsed.get("data") or {}
    if not isinstance(data.get("expired_days"), int):
        raise TestFailure(
            f"GET /v1/usercleaner/expired: expired_days not int; "
            f"body={body_of(r)!r}"
        )
    if not isinstance(data.get("entries"), list):
        raise TestFailure(
            f"GET /v1/usercleaner/expired: entries not list; body={body_of(r)!r}"
        )

    # 3. GET ghosts -> 200 + envelope.
    r = _http_roundtrip(b"GET /v1/usercleaner/ghosts HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/usercleaner/ghosts: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if not isinstance(data.get("entries"), list):
        raise TestFailure(
            f"GET /v1/usercleaner/ghosts: entries not list; body={body_of(r)!r}"
        )

    # 4. DELETE expired without X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    r = _http_roundtrip(b"DELETE /v1/usercleaner/expired HTTP/1.1\r\n" + auth + b"\r\n")
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/expired without X-Confirm: expected 400, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )
    if "E_CONFIRMATION_REQUIRED" not in body_of(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/expired without X-Confirm: "
            f"expected E_CONFIRMATION_REQUIRED in body; body={body_of(r)!r}"
        )

    # 5. DELETE ghosts without X-Confirm -> 400.
    r = _http_roundtrip(b"DELETE /v1/usercleaner/ghosts HTTP/1.1\r\n" + auth + b"\r\n")
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/ghosts without X-Confirm: expected 400, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 6. DELETE expired WITH X-Confirm -> 200 + envelope.
    r = _http_roundtrip(
        b"DELETE /v1/usercleaner/expired HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/expired with X-Confirm: expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "users-cleaned" or data.get("mode") != "expired":
        raise TestFailure(
            f"DELETE /v1/usercleaner/expired: unexpected envelope; "
            f"body={body_of(r)!r}"
        )
    for key in ("deleted", "skipped_exception", "skipped_protected_level"):
        if not isinstance(data.get(key), list):
            raise TestFailure(
                f"DELETE /v1/usercleaner/expired: {key!r} not list; "
                f"body={body_of(r)!r}"
            )
    # #311: orphan-comment sweep ran as side-effect, count is integer.
    if not isinstance(data.get("orphan_comments_removed"), int):
        raise TestFailure(
            f"DELETE /v1/usercleaner/expired: orphan_comments_removed not int; "
            f"body={body_of(r)!r}"
        )

    # 7. DELETE ghosts WITH X-Confirm -> 200 + envelope.
    r = _http_roundtrip(
        b"DELETE /v1/usercleaner/ghosts HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/ghosts with X-Confirm: expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "users-cleaned" or data.get("mode") != "ghosts":
        raise TestFailure(
            f"DELETE /v1/usercleaner/ghosts: unexpected envelope; "
            f"body={body_of(r)!r}"
        )
    if not isinstance(data.get("orphan_comments_removed"), int):
        raise TestFailure(
            f"DELETE /v1/usercleaner/ghosts: orphan_comments_removed not int; "
            f"body={body_of(r)!r}"
        )

    # 8. DELETE orphan-comments without X-Confirm -> 400 (#311).
    r = _http_roundtrip(
        b"DELETE /v1/usercleaner/orphan-comments HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/orphan-comments without X-Confirm: "
            f"expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )
    if "E_CONFIRMATION_REQUIRED" not in body_of(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/orphan-comments without X-Confirm: "
            f"expected E_CONFIRMATION_REQUIRED in body; body={body_of(r)!r}"
        )

    # 9. DELETE orphan-comments WITH X-Confirm -> 200 + envelope (#311).
    r = _http_roundtrip(
        b"DELETE /v1/usercleaner/orphan-comments HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/usercleaner/orphan-comments with X-Confirm: "
            f"expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "orphan-comments-cleaned":
        raise TestFailure(
            f"DELETE /v1/usercleaner/orphan-comments: unexpected action; "
            f"body={body_of(r)!r}"
        )
    if not isinstance(data.get("orphan_comments_removed"), int):
        raise TestFailure(
            f"DELETE /v1/usercleaner/orphan-comments: orphan_comments_removed not int; "
            f"body={body_of(r)!r}"
        )

    # 10. Catalog lists all 5 routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    for path in (
        "/v1/usercleaner/expired",
        "/v1/usercleaner/ghosts",
        "/v1/usercleaner/orphan-comments",
    ):
        if ('"' + path + '"') not in b:
            raise TestFailure(f"catalog missing {path}; body={b!r}")


def test_http_phase4_etc_trafficmanager(staging_dir: Path, proc=None):
    """Phase 4 PR-7 of #82 / #249: etc_trafficmanager plugin migrates to HTTP.

    Four endpoints: GET /v1/trafficmanager/settings (read),
    GET /v1/trafficmanager/blocks (read), POST/DELETE
    /v1/trafficmanager/blocks/{nick} (admin).

    Block + unblock are offline-tolerant by design, so the test
    seeds against a never-existed nick - no ADC user login needed.

    Coverage:
    - Anonymous calls -> 401 on all 4 routes.
    - GET settings -> 200 + envelope (activate + blocked_levels +
      the 6 boolean cfg flags).
    - GET blocks pre-seed -> 200 + entries list (probably empty).
    - POST without body -> 200 (reason is optional; absent reason
      stored as msg_unknown). We assert the envelope shape.
    - POST same nick again -> 409 (already blocked).
    - GET blocks post-POST -> entries contains the seeded nick.
    - DELETE never-blocked nick -> 404.
    - DELETE seeded nick -> 200 + removed snapshot.
    - DELETE same nick again -> 404 (gone).
    - Catalog lists all 4 routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    target = "smoke_pr7_tm_target"

    # Seed: register the target at a non-autoblocked level. Level 0
    # (unreg) is in `etc_trafficmanager_blocklevel_tbl` by default,
    # so an unregistered target would trip the autoblock 409 path
    # in POST. Register at level 20 (reg) - well above the
    # autoblock threshold but below operator.
    create_body = (
        b'{"nick":"' + target.encode("ascii") + b'","level":20}'
    )
    r = _http_roundtrip(
        b"POST /v1/registered HTTP/1.1\r\n" +
        b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n" +
        b"Content-Type: application/json\r\n" +
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n" +
        b"\r\n" + create_body
    )
    if "200 OK" not in (r.split("\r\n", 1)[0]):
        # Could be a duplicate from a previous test run on the same
        # staging tree - acceptable if 409. Anything else is fatal.
        if "409" not in (r.split("\r\n", 1)[0]):
            raise TestFailure(
                f"PR-7 seed: POST /v1/registered: unexpected status "
                f"{r.split(chr(13)+chr(10), 1)[0]!r}"
            )

    def get(path):
        return _http_roundtrip(
            ("GET " + path + " HTTP/1.1\r\n").encode("ascii") + auth + b"\r\n"
        )

    def post(path, body_bytes):
        return _http_roundtrip(
            ("POST " + path + " HTTP/1.1\r\n").encode("ascii") + auth +
            b"Content-Type: application/json\r\n" +
            b"Content-Length: " + str(len(body_bytes)).encode("ascii") + b"\r\n" +
            b"\r\n" + body_bytes
        )

    def delete(path):
        return _http_roundtrip(
            ("DELETE " + path + " HTTP/1.1\r\n").encode("ascii") + auth + b"\r\n"
        )

    # 1. Anonymous calls -> 401.
    for method, path in [
        ("GET", "/v1/trafficmanager/settings"),
        ("GET", "/v1/trafficmanager/blocks"),
        ("POST", "/v1/trafficmanager/blocks/" + target),
        ("DELETE", "/v1/trafficmanager/blocks/" + target),
    ]:
        r = _http_roundtrip(
            (method + " " + path + " HTTP/1.1\r\n\r\n").encode("ascii")
        )
        if "401" not in status(r):
            raise TestFailure(
                f"anonymous {method} {path}: expected 401, got {status(r)!r}"
            )

    # 2. GET settings -> 200 + envelope shape.
    r = get("/v1/trafficmanager/settings")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/trafficmanager/settings: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    for key in ("activate", "blocked_levels", "sharecheck", "minsharecheck",
                "report_on_login", "report_on_timer", "report_to_main", "report_to_pm"):
        if key not in data:
            raise TestFailure(
                f"GET /v1/trafficmanager/settings: missing {key!r}; "
                f"body={body_of(r)!r}"
            )
    if not isinstance(data["blocked_levels"], list):
        raise TestFailure(
            f"GET /v1/trafficmanager/settings: blocked_levels not list; "
            f"body={body_of(r)!r}"
        )

    # 3. GET blocks pre-seed -> 200 + envelope.
    r = get("/v1/trafficmanager/blocks")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/trafficmanager/blocks: expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not isinstance((parsed.get("data") or {}).get("entries"), list):
        raise TestFailure(
            f"GET /v1/trafficmanager/blocks: entries not list; body={body_of(r)!r}"
        )

    # 4. POST happy path -> 200 + envelope.
    r = post("/v1/trafficmanager/blocks/" + target, b'{"reason":"smoke test block"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/trafficmanager/blocks/{target}: expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "blocked" or data.get("nick") != target:
        raise TestFailure(
            f"POST /v1/trafficmanager/blocks/{target}: unexpected envelope; "
            f"body={body_of(r)!r}"
        )
    if data.get("reason") != "smoke test block":
        raise TestFailure(
            f"POST /v1/trafficmanager/blocks/{target}: reason mismatch; "
            f"body={body_of(r)!r}"
        )
    # `by` should reflect the bearer token's label, not be empty.
    # Regression-guard for the token_label -> by-field plumbing -
    # if a future refactor breaks the path, `by` would silently
    # fall back to "http-api" and the audit trail would lose the
    # caller identity.
    if not isinstance(data.get("by"), str) or data.get("by") == "":
        raise TestFailure(
            f"POST /v1/trafficmanager/blocks/{target}: `by` not a non-empty "
            f"string; body={body_of(r)!r}"
        )

    # 5. POST same nick again -> 409.
    r = post("/v1/trafficmanager/blocks/" + target, b'{"reason":"second attempt"}')
    if "409" not in status(r):
        raise TestFailure(
            f"POST /v1/trafficmanager/blocks/{target} duplicate: expected 409, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 6. GET blocks post-POST -> entries contains seeded nick.
    r = get("/v1/trafficmanager/blocks")
    parsed = _json.loads(body_of(r))
    entries = (parsed.get("data") or {}).get("entries") or []
    found = None
    for entry in entries:
        if entry.get("nick") == target:
            found = entry
            break
    if not found:
        raise TestFailure(
            f"GET /v1/trafficmanager/blocks (post-POST): target {target!r} "
            f"not in entries; got {entries!r}"
        )
    if "smoke test block" not in (found.get("reason") or ""):
        raise TestFailure(
            f"GET /v1/trafficmanager/blocks: reason mismatch; got {found!r}"
        )

    # 7. DELETE never-blocked nick -> 404.
    r = delete("/v1/trafficmanager/blocks/never_blocked_tm_target")
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/trafficmanager/blocks/never_blocked: expected 404, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 8. DELETE seeded nick -> 200 + removed snapshot.
    r = delete("/v1/trafficmanager/blocks/" + target)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/trafficmanager/blocks/{target}: expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "unblocked" or data.get("nick") != target:
        raise TestFailure(
            f"DELETE /v1/trafficmanager/blocks/{target}: unexpected envelope; "
            f"body={body_of(r)!r}"
        )
    removed = data.get("removed") or {}
    for key in ("by", "reason", "blocked_at"):
        if key not in removed:
            raise TestFailure(
                f"DELETE /v1/trafficmanager/blocks/{target}: removed missing "
                f"{key!r}; body={body_of(r)!r}"
            )

    # 9. DELETE same nick again -> 404 (gone).
    r = delete("/v1/trafficmanager/blocks/" + target)
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/trafficmanager/blocks/{target} (second): expected "
            f"404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 10. Catalog lists all 4 routes.
    r = get("/v1/endpoints")
    b = body_of(r)
    for path in (
        "/v1/trafficmanager/settings",
        "/v1/trafficmanager/blocks",
        "/v1/trafficmanager/blocks/{nick}",
    ):
        if ('"' + path + '"') not in b:
            raise TestFailure(f"catalog missing {path}; body={b!r}")


def test_http_announce(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_mass plugin migrates to
    POST /v1/announce. Coexists with the three ADC chat-cmds
    (`+mass`, `+masshub`, `+masslvl`) - the structured body's
    `scope` field dispatches to the right helper.

    Coverage:
    - Anonymous POST -> 401.
    - POST {message, scope:"all"} -> 200 + envelope.
    - POST {message, scope:"hub"} -> 200 + envelope (no sender in
      banner, sender field still in response).
    - POST {message, scope:"level", level:N} where N is a valid
      level -> 200 + envelope with recipients field.
    - POST {message, scope:"level"} without level -> 400 E_BAD_INPUT.
    - POST {message, scope:"level", level:99999} (unknown) -> 400.
    - POST {message:"", scope:"all"} -> 400 (empty message).
    - POST {scope:"all"} missing message -> 400 (schema required).
    - POST {message, scope:"unknown"} -> 400 (schema enum reject).
    - /v1/endpoints catalog lists POST /v1/announce.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"POST /v1/announce HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = post(b'{"message":"hi","scope":"all"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/announce: expected 401, got {status(r)!r}"
        )

    # 2. scope=all success.
    r = post(b'{"message":"Smoke announce all","scope":"all"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=all: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "announce" or data.get("scope") != "all":
        raise TestFailure(
            f"POST /v1/announce scope=all: envelope mismatch; body={body_of(r)!r}"
        )
    if data.get("message") != "Smoke announce all":
        raise TestFailure(
            f"POST /v1/announce scope=all: message echoed wrong; body={body_of(r)!r}"
        )

    # 3. scope=hub success (no sender in banner; sender still in
    # response data for audit).
    r = post(b'{"message":"Smoke announce hub","scope":"hub"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("scope") != "hub":
        raise TestFailure(
            f"POST /v1/announce scope=hub: envelope mismatch; body={body_of(r)!r}"
        )

    # 4. scope=level with a valid level (10 is the default
    # registered level per the examples cfg).
    r = post(b'{"message":"Smoke level","scope":"level","level":10}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("scope") != "level" or data.get("level") != 10:
        raise TestFailure(
            f"POST /v1/announce scope=level: envelope mismatch; body={body_of(r)!r}"
        )
    if not isinstance(data.get("recipients"), int):
        raise TestFailure(
            f"POST /v1/announce scope=level: expected integer recipients; body={body_of(r)!r}"
        )

    # 5. scope=level WITHOUT level -> 400.
    r = post(b'{"message":"x","scope":"level"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level no level: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/announce scope=level no level: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 6. scope=level with unknown level -> 400.
    r = post(b'{"message":"x","scope":"level","level":99999}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce scope=level unknown: expected 400, got {status(r)!r}"
        )

    # 7. Empty message -> 400.
    r = post(b'{"message":"","scope":"all"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce empty message: expected 400, got {status(r)!r}"
        )

    # 8. Missing message (schema required) -> 400.
    r = post(b'{"scope":"all"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce missing message: expected 400, got {status(r)!r}"
        )

    # 9. Unknown scope (schema enum reject) -> 400.
    r = post(b'{"message":"x","scope":"world"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/announce unknown scope: expected 400, got {status(r)!r}"
        )

    # 10. /v1/endpoints catalog lists POST /v1/announce.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/announce"' not in b:
        raise TestFailure(f"catalog missing /v1/announce; body={b!r}")


def test_http_topic(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_topic plugin migrates to
    POST /v1/topic. Coexists with the ADC `+topic` chat-cmd.

    Coverage:
    - Anonymous POST -> 401.
    - POST {topic: "Smoke set"} -> 200 + action:topic-set + topic +
      previous.
    - POST {topic: ""} -> 200 + action:topic-reset + topic=default
      (the previous set above is "previous").
    - POST {} -> 200 + action:topic-reset (missing field = reset).
    - POST {topic: "default"} -> action:topic-set (literal value, NOT
      magic-keyword reset - HTTP path documented to differ from ADC).
    - Schema: {topic: 12345} (non-string) -> 400 E_BAD_INPUT.
    - /v1/endpoints catalog lists POST /v1/topic.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"POST /v1/topic HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = post(b"{}", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/topic: expected 401, got {status(r)!r}"
        )

    # 2. Set topic to a known value.
    r = post(b'{"topic":"Smoke set"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/topic set: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-set" or data.get("topic") != "Smoke set":
        raise TestFailure(
            f"POST /v1/topic set: unexpected envelope; body={body_of(r)!r}"
        )

    # 3. Reset via empty topic field.
    r = post(b'{"topic":""}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-reset":
        raise TestFailure(
            f"POST /v1/topic reset (empty): expected action=topic-reset; "
            f"body={body_of(r)!r}"
        )
    if data.get("previous") != "Smoke set":
        raise TestFailure(
            f"POST /v1/topic reset: expected previous='Smoke set' (the "
            f"value set in step 2); body={body_of(r)!r}"
        )

    # 4. Reset via missing topic field (empty body).
    r = post(b'{}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-reset":
        raise TestFailure(
            f"POST /v1/topic reset (missing field): expected "
            f"action=topic-reset; body={body_of(r)!r}"
        )

    # 5. Literal "default" sets the topic to the WORD "default" on
    # the HTTP path (NOT magic-keyword reset). Documented difference
    # from the ADC `+topic default` cmd.
    r = post(b'{"topic":"default"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "topic-set" or data.get("topic") != "default":
        raise TestFailure(
            f"POST /v1/topic literal default: expected action=topic-set "
            f"+ topic='default' (HTTP path differs from ADC magic-keyword); "
            f"body={body_of(r)!r}"
        )

    # 6. Schema reject: non-string topic.
    r = post(b'{"topic":12345}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/topic with non-string: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/topic non-string: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 7. /v1/endpoints catalog lists POST /v1/topic.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/topic"' not in b:
        raise TestFailure(f"catalog missing /v1/topic; body={b!r}")


def test_aliases_adc_dispatch():
    """#327: alias resolver fallback in etc_hubcommands.lua.

    Logs in as dummy (level 100, passes the etc_aliases_minlevel=80
    gate), creates an alias `h -> help` via `+addalias h help`,
    then sends `+h` and asserts the bot replies (proving that the
    resolver fallback re-dispatched to cmd_help). Without the
    resolver hop the hub would either ignore `+h` (no such
    command) or broadcast it as chat - both observable as the
    absence of an EMSG/DMSG reply from the hubbot.

    Cleans up after itself with `+delalias h` so the alias does
    not persist across test runs (cfg/aliases.tbl is saved in
    the staging dir but the same dir is reused on rerun).

    Each step uses a content-specific predicate so the post-login
    etc_dummy_warning DMSG and the etc_hubcommands `[command] %s`
    echo line (both arrive interleaved with the actual handler
    reply) are scanned past, not mistaken for the response.
    """
    def _is_chat_frame(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")

    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")

        # Multi-word BMSG bodies must ADC-escape spaces as `\s`
        # (raw spaces would terminate the body at the first space
        # and the trailing tokens would be parsed as ADC flags,
        # which is what bit the pre-v3 of this test - the handler
        # saw `+addalias` with empty params and replied with usage).

        # 1. Create the alias. etc_aliases replies "<nick> added alias 'h' -> 'help'."
        # The predicate filters past the long post-login frame storm
        # (ICMDs from etc_usercommands, motd, login info, hubowner
        # warning) and the [command] echo (which contains "alias" but
        # not "added").
        sock.sendall(f"BMSG {sid} +addalias\\sh\\shelp\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and "added" in f and "alias" in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+addalias did not confirm add: {reply!r}")

        # 2. The alias should now dispatch to cmd_help. cmd_help's
        # output is a multi-line listing that always contains the
        # word "help" (its own +help row, plus help titles of other
        # plugins). The `[command] +h` echo doesn't contain "help"
        # (only "+h"), and the dummy warning doesn't either, so a
        # content-aware predicate disambiguates regardless of
        # the order frames arrived.
        sock.sendall(f"BMSG {sid} +h\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and "help" in f and len(f) > 50,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(
                f"+h (alias for help) did not dispatch: {reply!r}"
            )

        # 3. Clean up so a re-run of the smoke harness sees a clean state.
        sock.sendall(f"BMSG {sid} +delalias\\sh\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and "removed" in f and "alias" in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+delalias did not confirm removal: {reply!r}")


def test_cmd_ban_rejects_bad_time():
    """cmd_ban v0.43: `+ban nick X <time>` must reject a time below 1.

    Pre-fix, the only time validation was `is_integer( time )`, which
    accepts negatives (-5 == math.floor(-5)). So `+ban nick X -5 reason`
    stored bantime = -300; at the target's next login the expiry check
    computed an always-negative remaining, PRUNED the entry and let them
    straight back in - the target was kicked once while the operator
    believed X was banned. Meanwhile help_desc and both lang files
    promised "negative values means ban forever", a feature removed in
    v0.15. The HTTP path has enforced min = 1 since #82; this closes the
    divergence between the two entry points.

    The new guard sits next to the is_integer check, which runs BEFORE
    the target is resolved - so a nonexistent target exercises it and no
    second client is needed:

      pre-fix : falls through to the lookup -> "User not found."
      post-fix: -> "Bantime must be 1 minute or greater."

    Asserting on the msg_badtime phrase therefore provably fails pre-fix
    (CLAUDE.md §1a.7). Step 3 is a positive control: a VALID time on the
    same nonexistent target must still reach the lookup and answer "User
    not found." - proving the guard rejects only bad input rather than
    swallowing every +ban.

    dummy is level 100 (hubowner); cmd_ban_permission gives minlevel 60,
    so the command is reachable.
    """
    # Collect frames until the hub goes quiet, then assert over the whole
    # batch. A single recv_until(predicate) is not usable here: dummy's
    # login triggers a very long ICMD storm (~300 right-click
    # registrations across the bundled plugins), and a 5s predicate scan
    # can expire while still wading through it - which looks exactly like
    # "the hub never replied". Collecting also yields a far better failure
    # message, since we can show what did arrive.
    def _collect(reader, seconds=4.0):
        frames = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                frames.append(reader.recv_until(lambda x: True, timeout=0.5))
            except TestFailure:
                break
        return frames

    def _chat_text(frames):
        return " || ".join(
            f for f in frames
            if f.startswith(("EMSG ", "DMSG ", "BMSG "))
        )

    # A nick that is neither online nor registered, so the target lookup
    # cannot succeed and nothing is ever actually banned by this test.
    target = "smoke_no_such_user_9f2a"

    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        _collect(reader, 5.0)  # let the post-login ICMD storm drain

        # Multi-word BMSG bodies must ADC-escape spaces as `\s`; raw
        # spaces would terminate the body and the rest would be parsed
        # as ADC flags. Replies come back escaped the same way, so assert
        # on single words rather than whole sentences.
        for bad_time in ("-5", "0"):
            sock.sendall(f"BMSG {sid} +ban\\snick\\s{target}\\s{bad_time}\\sspam\n".encode("utf-8"))
            got = _chat_text(_collect(reader))
            if "Bantime" not in got:
                raise TestFailure(
                    f"+ban with time={bad_time} was not rejected with the bantime "
                    f"message. Pre-fix, is_integer() accepts negatives so this fell "
                    f"through to the target lookup and answered 'User not found.' "
                    f"Chat frames seen: {got[:400]!r}"
                )
            if "not\\sfound" in got:
                raise TestFailure(
                    f"+ban with time={bad_time} reached the target lookup - the "
                    f"guard must reject before resolving a target: {got[:400]!r}"
                )

        # Positive control: a valid time must NOT be caught by the guard.
        # It has to reach the target lookup and report the unknown nick -
        # otherwise the guard would be silently rejecting every +ban and
        # the assertions above would pass for the wrong reason.
        sock.sendall(f"BMSG {sid} +ban\\snick\\s{target}\\s5\\sspam\n".encode("utf-8"))
        got = _chat_text(_collect(reader))
        if "not\\sfound" not in got:
            raise TestFailure(
                f"+ban with a valid time=5 did not reach the target lookup - the "
                f"bantime guard is over-rejecting: {got[:400]!r}"
            )
        if "Bantime" in got:
            raise TestFailure(
                f"+ban with a valid time=5 was rejected by the bantime guard: "
                f"{got[:400]!r}"
            )


def test_cmd_ban_permanent_adc():
    """cmd_ban v0.44: `+ban ... permanent` keyword bans forever (#444).

    Before v0.44 the keyword did not exist: `tonumber("permanent")` is
    nil, so `time` fell back to cmd_ban_default_time (20) and the word
    "permanent" was swallowed into the reason - a silent 20-minute ban
    with reason "permanent <rest>". v0.44 recognises `permanent` in the
    <time> slot, stores a real permanent marker (time 0), and renders
    the ban time as the msg_permanent label instead of a countdown.

    Provable pre-fix (CLAUDE.md §1a.7): the immediate `+ban` reply
    (msg_ok) carries the bantime label in its `bantime:` field.

      post-fix: bantime label = "permanent"  -> reply has no countdown
      pre-fix : bantime label = get_bantime(1200) = "0 years, 0 days,
                0 hours, 20 minutes, ..." -> reply CONTAINS "years"

    So asserting the reply contains "permanent" AND does not contain
    "years" flips: pre-fix the countdown's "years" is present and the
    assertion fails.

    Uses an ip target (blind-add, no online user needed) and unbans it
    afterwards so no state leaks to downstream tests on the shared hub.
    """
    def _collect(reader, seconds=4.0):
        frames = []
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                frames.append(reader.recv_until(lambda x: True, timeout=0.5))
            except TestFailure:
                break
        return frames

    def _chat_text(frames):
        return " || ".join(
            f for f in frames
            if f.startswith(("EMSG ", "DMSG ", "BMSG "))
        )

    # TEST-NET-3 (RFC 5737) address - never a real client.
    target_ip = "203.0.113.44"
    # A reason word that does not itself contain "years"/"minutes", so the
    # countdown-word assertion cannot be tripped by the reason text.
    reason = "permsmoke9f2a"

    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        _collect(reader, 5.0)  # let the post-login ICMD storm drain

        try:
            sock.sendall(f"BMSG {sid} +ban\\sip\\s{target_ip}\\spermanent\\s{reason}\n".encode("utf-8"))
            got = _chat_text(_collect(reader))
            if "permanent" not in got:
                raise TestFailure(
                    f"+ban ip {target_ip} permanent did not render the permanent "
                    f"label. Pre-fix, `permanent` was swallowed into the reason and "
                    f"the ban became a 20-minute countdown. Chat frames: {got[:500]!r}"
                )
            if "years" in got:
                raise TestFailure(
                    f"+ban ... permanent reply still carries a time countdown "
                    f"('years'), so the keyword was not recognised as permanent - "
                    f"it fell through to the default-time path: {got[:500]!r}"
                )
            if reason not in got:
                raise TestFailure(
                    f"+ban ... permanent reply lost the reason {reason!r}; the "
                    f"keyword parse must not eat the trailing reason: {got[:500]!r}"
                )
        finally:
            # Clean up the ip ban so the shared hub's ban list stays empty
            # for downstream tests.
            sock.sendall(f"BMSG {sid} +unban\\sip\\s{target_ip}\n".encode("utf-8"))
            _collect(reader, 2.0)


def test_blocklist_78_phase_b():
    """#78 Phase B etc_blocklist `+blocklist` admin CLI smoke.

    Exercises the dispatcher + 4 of 6 verbs (count / add / show /
    del) over an authenticated ADC session. The remaining two
    (export / import) write to disk and are covered by the unit
    test - smoke stays focused on the live ADC path.

    Sequence:
      1. Login as dummy (level 100, > etc_blocklist_oplevel=80).
      2. `+blocklist count` -> reply with "0 entries total".
      3. `+blocklist add 198.51.100.0/24 reason="smoke"` ->
         reply contains "added" + "blocklist entry". TEST-NET-3
         prefix (not loopback, not routable) so a smoke-run cannot
         accidentally block a real IP.
      4. `+blocklist count` -> "1 entries total" + "manual".
      5. `+blocklist show` -> reply contains "198.51.100.0/24".
      6. `+blocklist del 1` -> "removed" + "blocklist entry".
      7. `+blocklist count` -> "0 entries total" again (roundtrip).

    Registered in the initial TESTS list rather than the staging-
    runner block so the test runs BEFORE `_switch_to_tier_mode`
    injects `ratelimit_tiers = { strict = { msg_burst = 2 } }`
    for level 100. Under that overlay, dummy can send only 2
    BMSGs per burst; our 6-BMSG roundtrip would starve the token
    bucket and stall from step 3 onward. Keeping the test in the
    default-cfg phase avoids the rate-limit interaction entirely.

    Frames arrive with ADC space-escapes (`\\s` for space). The
    `_dcontains` predicate helper decodes that once so per-step
    predicates read as plain English content.
    """
    def _is_chat_frame(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")

    def _dcontains(f, substr):
        return substr in f.replace("\\s", " ")

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")

        # 1. count -> "0 entries total"
        sock.sendall(f"BMSG {sid} +blocklist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and _dcontains(f, "0 entries total"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist count (pre-add) did not return zero: {reply!r}")

        # 2. add TEST-NET-3 CIDR
        sock.sendall(
            f'BMSG {sid} +blocklist\\sadd\\s198.51.100.0/24\\sreason="smoke"\n'
            .encode("utf-8")
        )
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "added")
                and _dcontains(f, "blocklist entry"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist add did not confirm: {reply!r}")

        # 3. count -> "1 entries total" + "manual"
        sock.sendall(f"BMSG {sid} +blocklist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "1 entries total")
                and _dcontains(f, "manual"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist count (post-add) did not return one: {reply!r}")

        # 4. show -> includes the cidr
        sock.sendall(f"BMSG {sid} +blocklist\\sshow\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and _dcontains(f, "198.51.100.0/24"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist show did not list the entry: {reply!r}")

        # 5. del 1 -> "removed"
        sock.sendall(f"BMSG {sid} +blocklist\\sdel\\s1\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "removed")
                and _dcontains(f, "blocklist entry"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist del did not confirm: {reply!r}")

        # 6. count -> back to zero
        sock.sendall(f"BMSG {sid} +blocklist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and _dcontains(f, "0 entries total"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blocklist count (post-del) did not return zero: {reply!r}")


def test_whitelist_78_phase_b():
    """#78 allowlist Phase B etc_whitelist `+whitelist` admin CLI smoke.

    End-to-end via a real ADC login as dummy (level 100 >
    etc_whitelist_oplevel=80):

      1. The bundled hublist-pinger seed lands on the FIRST boot
         (store .tbl missing) - `+whitelist count` shows the seeded
         entries with source=pinger. This is the seed-on-missing
         validation the unit test can only mock.
      2. `+whitelist add 198.51.100.0/24 reason="smoke"` -> "added"
         (TEST-NET-3, never a real host). Capture the new id.
      3. `+whitelist count` -> seed+1 total, now also "manual".
      4. `+whitelist show` -> lists BOTH the added CIDR and a seed
         entry (142.54.190.133), proving seed + operator add coexist.
      5. `+whitelist del <id>` -> "removed".
      6. `+whitelist count` -> back to the seed-only total.

    Like the blocklist Phase B test this is registered in the initial
    TESTS list (NOT the staging-runner block) so it runs in the
    default-cfg phase, before the strict ratelimit_tiers overlay whose
    2-BMSG burst would starve this multi-BMSG roundtrip.
    """
    def _is_chat_frame(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")

    def _dcontains(f, substr):
        return substr in f.replace("\\s", " ")

    seed_n = 6    # len(BUNDLED_SEED) in scripts/etc_whitelist.lua

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")

        # 1. count -> the bundled pinger seed is present (source=pinger)
        sock.sendall(f"BMSG {sid} +whitelist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, f"{seed_n} entries total")
                and _dcontains(f, "pinger"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist count (seed) did not show the pinger seed: {reply!r}")

        # 2. add a TEST-NET-3 CIDR; capture the new entry id
        sock.sendall(
            f'BMSG {sid} +whitelist\\sadd\\s198.51.100.0/24\\sreason="smoke"\n'
            .encode("utf-8")
        )
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "added")
                and _dcontains(f, "allowlist entry"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist add did not confirm: {reply!r}")
        m = re.search(r"entry #(\d+)", reply.replace("\\s", " "))
        if not m:
            raise TestFailure(f"+whitelist add reply had no entry id: {reply!r}")
        added_id = m.group(1)

        # 3. count -> seed + 1, now also "manual"
        sock.sendall(f"BMSG {sid} +whitelist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, f"{seed_n + 1} entries total")
                and _dcontains(f, "manual"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist count (post-add) wrong total: {reply!r}")

        # 4. show -> the added CIDR AND a seed entry both appear
        sock.sendall(f"BMSG {sid} +whitelist\\sshow\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "198.51.100.0/24")
                and _dcontains(f, "142.54.190.133"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist show missing add or seed entry: {reply!r}")

        # 5. del the entry we added
        sock.sendall(f"BMSG {sid} +whitelist\\sdel\\s{added_id}\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "removed")
                and _dcontains(f, "allowlist entry"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist del did not confirm: {reply!r}")

        # 6. count -> back to the seed-only total
        sock.sendall(f"BMSG {sid} +whitelist\\scount\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f) and _dcontains(f, f"{seed_n} entries total"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+whitelist count (post-del) did not return to seed total: {reply!r}")


def test_blocklist_feeds_status():
    """#78 Phase E etc_blocklist_feeds `+blfeeds` read-only status smoke.

    override_test_ports enables the plugin with NO feed active, so this
    validates the real-hub operator surface end-to-end over an ADC
    session: the onStart command + HTTP registration, get_status, and
    format_status all run in the restricted sandbox. The fetch -> parse
    -> bulk_replace path is unit-tested with mocked responses (86
    checks); the full fetch-and-block end-to-end (a live mock feed
    server + close-on-accept) is left as a follow-up.

    Sequence:
      1. Login as dummy (level 100 > etc_blocklist_feeds_oplevel=80).
      2. `+blfeeds` -> DMSG reply with the status header + a feed row.
    """
    def _is_chat_frame(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")

    def _dcontains(f, substr):
        return substr in f.replace("\\s", " ")

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")

        sock.sendall(f"BMSG {sid} +blfeeds\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "BLOCKLIST FEEDS STATUS")
                and _dcontains(f, "[tor]"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+blfeeds did not return status: {reply!r}")


def test_proxydetect_status():
    """#78 Phase F etc_proxydetect `+proxydetect` read-only status smoke.

    override_test_ports enables the plugin with EMPTY check_levels, so
    onConnect never fires an outbound provider query (no network in CI)
    while the real-hub operator surface is validated end-to-end over an
    ADC session: the onStart command + HTTP registration, secrets.register,
    get_status and format_status all run in the restricted sandbox. The
    async lookup -> kick / store-push flow + SSRF / SID-reuse / fail-open
    guards + all three provider adapters (proxycheck / vpnapi / ipqs) are
    unit-tested with a mocked http_client / blocklist; a live mock-provider
    end-to-end is left as a follow-up.

    Sequence:
      1. Login as dummy (level 100 > etc_proxydetect_oplevel=80).
      2. `+proxydetect` -> DMSG reply with the status header + provider row.
    """
    def _is_chat_frame(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")

    def _dcontains(f, substr):
        return substr in f.replace("\\s", " ")

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")

        sock.sendall(f"BMSG {sid} +proxydetect\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: _is_chat_frame(f)
                and _dcontains(f, "PROXYDETECT STATUS")
                and _dcontains(f, "proxycheck"),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+proxydetect did not return status: {reply!r}")


def test_http_aliases(staging_dir: Path, proc=None):
    """#327: HTTP API CRUD for etc_aliases.

    Coverage:
    - Anonymous POST + DELETE -> 401.
    - GET /v1/aliases on a clean hub -> 200 + empty array.
    - POST {alias:"us",target:"usersearch"} -> 201 + envelope.
    - GET shows the new alias.
    - POST again with same alias -> 409 E_BAD_INPUT family
      (mapped from our `exists` err_code).
    - POST {alias:"xx",target:"doesnotexist"} -> 404 (no_target).
    - POST {alias:"us2",target:"usersearch"} -> 400 (bad_alias,
      digit rejected by `^%a+$` regex).
    - DELETE /v1/aliases/us -> 200 + envelope.
    - DELETE /v1/aliases/ghost -> 404 (not_found).
    - /v1/endpoints catalog lists all three routes.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"POST /v1/aliases HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    def delete(alias: str, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            ("DELETE /v1/aliases/" + alias + " HTTP/1.1\r\n").encode("ascii") + h + b"\r\n"
        )

    # 1. Anonymous gate.
    r = post(b'{"alias":"x","target":"help"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(f"anonymous POST /v1/aliases: expected 401, got {status(r)!r}")
    r = delete("x", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(f"anonymous DELETE /v1/aliases/x: expected 401, got {status(r)!r}")

    # 2. POST happy path.
    r = post(b'{"alias":"us","target":"usersearch"}')
    if "201" not in status(r):
        raise TestFailure(
            f"POST /v1/aliases create: expected 201, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "added" or data.get("alias") != "us" or data.get("target") != "usersearch":
        raise TestFailure(
            f"POST /v1/aliases create: unexpected envelope; body={body_of(r)!r}"
        )

    # 3. GET lists it.
    r = _http_roundtrip(b"GET /v1/aliases HTTP/1.1\r\n" + auth + b"\r\n")
    if "200" not in status(r):
        raise TestFailure(
            f"GET /v1/aliases: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    aliases = data.get("aliases") or []
    if not any(a.get("alias") == "us" and a.get("target") == "usersearch" for a in aliases):
        raise TestFailure(
            f"GET /v1/aliases: did not include {{us->usersearch}}; body={body_of(r)!r}"
        )

    # 4. POST duplicate -> 409.
    r = post(b'{"alias":"us","target":"help"}')
    if "409" not in status(r):
        raise TestFailure(
            f"POST /v1/aliases duplicate: expected 409, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 5. POST unknown target -> 404.
    r = post(b'{"alias":"xx","target":"doesnotexist"}')
    if "404" not in status(r):
        raise TestFailure(
            f"POST /v1/aliases unknown target: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 6. POST bad alias (digit) -> 400.
    r = post(b'{"alias":"us2","target":"usersearch"}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/aliases bad alias: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 7. DELETE happy + cleanup.
    r = delete("us")
    if "200" not in status(r):
        raise TestFailure(
            f"DELETE /v1/aliases/us: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 8. DELETE unknown -> 404.
    r = delete("ghost")
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE /v1/aliases/ghost: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 9. Catalog lists all three routes.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/aliases"' not in b:
        raise TestFailure(f"catalog missing /v1/aliases; body={b!r}")
    if '"/v1/aliases/{alias}"' not in b:
        raise TestFailure(f"catalog missing /v1/aliases/{{alias}}; body={b!r}")


def test_http_registered_users_pr1(staging_dir: Path, proc=None):
    """#82 registered-users family PR-1 (#236): cmd_reg plugin migrates
    GET /v1/registered (paginated, read), POST /v1/registered (admin),
    PATCH /v1/registered/{nick} (admin). Coexists with the ADC `+reg`
    chat-cmd.

    Coverage:
    - Anonymous GET -> 401.
    - GET /v1/registered -> 200 + envelope.data.registered[] +
      pagination sibling per §6.4.
    - GET ?limit=1 -> respects limit clamp.
    - POST missing nick -> 400 E_BAD_INPUT.
    - POST with valid body (no password) -> 200 + action:register +
      password echoed back, comment empty by default.
    - POST same nick again -> 409 E_CONFLICT (nick already regged).
    - POST with caller-supplied password -> 200 + password matches.
    - PATCH /v1/registered/{nick} {comment: "smoke"} -> 200 + action:
      patch-registered + comment="smoke".
    - PATCH with empty body -> 400 (no patchable fields).
    - PATCH unknown nick -> 404 E_NOT_FOUND.
    - GET shows the patched comment in the entry.
    - /v1/endpoints catalog lists all three routes.

    Placement note: runs BEFORE test_http_reload so the test's persisted
    users are still in-memory + on-disk when the reload tests fire. The
    reload test asserts route-table survival, not data survival.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def req(method: bytes, path: bytes, body: bytes = b"", with_auth: bool = True):
        h = auth if with_auth else b""
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + h +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous GET -> 401.
    r = req(b"GET", b"/v1/registered", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/registered: expected 401, got {status(r)!r}"
        )

    # 2. GET list -> 200 with envelope + pagination.
    r = req(b"GET", b"/v1/registered")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/registered: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/registered: ok!=true; body={body_of(r)!r}")
    if "registered" not in (parsed.get("data") or {}):
        raise TestFailure(
            f"GET /v1/registered: data.registered missing; body={body_of(r)!r}"
        )
    pag = parsed.get("pagination") or {}
    for key in ("total", "limit", "offset"):
        if key not in pag:
            raise TestFailure(
                f"GET /v1/registered: pagination missing {key!r}; body={body_of(r)!r}"
            )

    # 3. limit=1 respected.
    r = req(b"GET", b"/v1/registered?limit=1")
    parsed = _json.loads(body_of(r))
    page = parsed.get("data", {}).get("registered", [])
    if len(page) > 1:
        raise TestFailure(
            f"GET /v1/registered?limit=1: expected <=1 entries, got {len(page)}"
        )
    if parsed.get("pagination", {}).get("limit") != 1:
        raise TestFailure(
            f"GET /v1/registered?limit=1: pagination.limit != 1; body={body_of(r)!r}"
        )

    # 4. POST missing nick -> 400.
    r = req(b"POST", b"/v1/registered", b'{"level":20}')
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/registered missing nick: expected 400, got {status(r)!r}"
        )
    if '"E_BAD_INPUT"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/registered missing nick: expected E_BAD_INPUT; body={body_of(r)!r}"
        )

    # 5. POST create -> 200 + password echoed back.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_a","level":20}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/registered create: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "register" or data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"POST /v1/registered create: unexpected envelope; body={body_of(r)!r}"
        )
    if not data.get("password"):
        raise TestFailure(
            f"POST /v1/registered create: expected non-empty password; body={body_of(r)!r}"
        )

    # 6. POST same nick again -> 409.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_a","level":20}')
    if "409" not in status(r):
        raise TestFailure(
            f"POST /v1/registered duplicate: expected 409, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 7. POST with caller-supplied password.
    r = req(b"POST", b"/v1/registered",
            b'{"nick":"smoke_pr1_b","level":20,"password":"supplied_pw_xyz"}')
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("password") != "supplied_pw_xyz":
        raise TestFailure(
            f"POST /v1/registered with password: expected echo back; body={body_of(r)!r}"
        )

    # 8. PATCH comment -> 200.
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a",
            b'{"comment":"smoke test note"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PATCH /v1/registered/smoke_pr1_a: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "patch-registered" or data.get("comment") != "smoke test note":
        raise TestFailure(
            f"PATCH /v1/registered/smoke_pr1_a: unexpected envelope; body={body_of(r)!r}"
        )

    # 9. PATCH empty body -> 400 (no patchable fields).
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PATCH empty body: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 10. PATCH unknown nick -> 404.
    r = req(b"PATCH", b"/v1/registered/nonexistent_smoke_user",
            b'{"comment":"x"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PATCH unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 11. GET shows the patched comment in the entry.
    r = req(b"GET", b"/v1/registered?limit=1000")
    parsed = _json.loads(body_of(r))
    page = parsed.get("data", {}).get("registered", [])
    found = None
    for entry in page:
        if entry.get("nick") == "smoke_pr1_a":
            found = entry
            break
    if not found:
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a missing from list; body={body_of(r)!r}"
        )
    if found.get("comment") != "smoke test note":
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a comment mismatch; got {found!r}"
        )
    if found.get("level") != 20:
        raise TestFailure(
            f"GET /v1/registered: smoke_pr1_a level != 20; got {found!r}"
        )
    if "password" in found:
        raise TestFailure(
            f"GET /v1/registered: password leaked in list view; got {found!r}"
        )

    # 12. Empty-string comment clears the description entirely:
    # a follow-up GET must show comment="" for that nick (no
    # stale empty-reason record left behind).
    r = req(b"PATCH", b"/v1/registered/smoke_pr1_a", b'{"comment":""}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PATCH empty comment (clear): expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    r = req(b"GET", b"/v1/registered?limit=1000")
    parsed = _json.loads(body_of(r))
    for entry in parsed.get("data", {}).get("registered", []):
        if entry.get("nick") == "smoke_pr1_a":
            if entry.get("comment") != "":
                raise TestFailure(
                    f"GET after PATCH-empty: expected comment=''; got {entry!r}"
                )
            break

    # 13. PATCH on a bot nick -> 404 (bots are excluded from
    # /v1/registered surface; PATCH must mirror GET).
    r = req(b"PATCH", b"/v1/registered/luadch-NG",
            b'{"comment":"should not stick"}')
    # The bot's actual nick depends on cfg `hub_bot_nick`; the
    # smoke staging uses "luadch-NG" (see cfg_defaults). If the
    # name happens to differ we get 404 anyway via the
    # not-registered branch - either way the contract holds:
    # PATCH on the bot's nick must NOT return 200.
    if "200" in status(r):
        raise TestFailure(
            f"PATCH on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 14. /v1/endpoints catalog lists all three routes - precise
    # match on the PATCH /v1/registered/{nick} combination, not
    # just the path string + method letters in isolation.
    r = req(b"GET", b"/v1/endpoints")
    cat = body_of(r)
    for needle in (
        '"/v1/registered"',
        '"/v1/registered/{nick}"',
        '"register a new user',
        '"update free-form fields',
    ):
        if needle not in cat:
            raise TestFailure(f"catalog missing {needle!r}; body={cat!r}")


def test_http_registered_get_pr2(staging_dir: Path, proc=None):
    """#82 registered-users family PR-2 (#236): cmd_accinfo plugin
    migrates GET /v1/registered/{nick} (read scope). Returns the
    expanded view (= ADC `+accinfoop`) for a single registered user.
    Depends on PR-1 having created smoke_pr1_a + smoke_pr1_b in the
    same hub session.

    Coverage:
    - Anonymous GET -> 401.
    - GET /v1/registered/smoke_pr1_a -> 200 + expanded envelope
      (nick + level + level_name + by + regged_at + lastseen +
      is_online + comment + traffic_blocked + msg_blocked + ban),
      no password leak.
    - GET unknown nick -> 404 E_NOT_FOUND.
    - GET on hubbot nick -> not 200 (humans-only filter).
    - /v1/endpoints catalog lists GET /v1/registered/{nick}.

    Runs AFTER test_http_registered_users_pr1 so the created users
    exist; BEFORE test_http_reload for the same reason.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get(path: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"GET " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous -> 401.
    r = get(b"/v1/registered/smoke_pr1_a", with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /v1/registered/<nick>: expected 401, got {status(r)!r}"
        )

    # 2. Existing user -> 200 + expanded envelope.
    r = get(b"/v1/registered/smoke_pr1_a")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    for field in (
        "nick", "level", "level_name", "by", "regged_at",
        "lastseen", "is_online", "comment", "traffic_blocked",
    ):
        if field not in data:
            raise TestFailure(
                f"GET /v1/registered/smoke_pr1_a: missing {field!r}; body={body_of(r)!r}"
            )
    if data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: wrong nick echoed; body={body_of(r)!r}"
        )
    if data.get("level") != 20:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected level=20; got {data!r}"
        )
    if "password" in data:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: password leaked; body={body_of(r)!r}"
        )
    if data.get("is_online") is not False:
        raise TestFailure(
            f"GET /v1/registered/smoke_pr1_a: expected is_online=false; got {data!r}"
        )

    # 3. Unknown nick -> 404.
    r = get(b"/v1/registered/never_registered_smoke")
    if "404" not in status(r):
        raise TestFailure(
            f"GET unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )
    if '"E_NOT_FOUND"' not in body_of(r):
        raise TestFailure(
            f"GET unknown nick: expected E_NOT_FOUND; body={body_of(r)!r}"
        )

    # 4. Hubbot nick -> must not return 200 (humans-only filter).
    # The actual bot nick varies with cfg `hub_bot_nick`; we try the
    # default and fall through if it's not registered (also 404 by
    # the not-registered branch, which is the contract).
    r = get(b"/v1/registered/luadch-NG")
    if "200" in status(r):
        raise TestFailure(
            f"GET on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 5. /v1/endpoints catalog lists GET /v1/registered/{nick} with
    # the new description string (proves PR-2 registered the route).
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"expanded account info' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}} GET description; body={cat!r}"
        )


def test_http_setpass_pr3(staging_dir: Path, proc=None):
    """#82 registered-users family PR-3 (#236): cmd_setpass plugin
    migrates PUT /v1/registered/{nick}/password (admin scope).
    Coexists with the ADC `+setpass nick` chat-cmd.

    Depends on PR-1 having created smoke_pr1_a + smoke_pr1_b in the
    same hub session.

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing password -> 400 E_BAD_INPUT.
    - PUT empty password -> 400.
    - PUT password with whitespace -> 400.
    - PUT happy path -> 200 + action:password-set +
      online_notified=false (smoke_pr1_a is not online).
    - PUT same password again -> 200 (idempotent; ADC msg_nochange
      semantics intentionally NOT applied on HTTP).
    - PUT unknown nick -> 404 E_NOT_FOUND.
    - PUT on hubbot nick -> not 200 (humans-only).
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/password.

    Runs AFTER test_http_registered_get_pr2 and BEFORE
    test_http_reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT password: expected 401, got {status(r)!r}"
        )

    # 2. Missing password field -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing password: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 3. Empty password -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":""}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT empty password: expected 400, got {status(r)!r}"
        )

    # 4. Whitespace in password -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"bad password"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT password with whitespace: expected 400, got {status(r)!r}"
        )

    # 5. Happy path.
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT password: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "password-set" or data.get("nick") != "smoke_pr1_a":
        raise TestFailure(
            f"PUT password: unexpected envelope; body={body_of(r)!r}"
        )
    if data.get("online_notified") is not False:
        raise TestFailure(
            f"PUT password: expected online_notified=false (target offline); got {data!r}"
        )

    # 6. Same password again -> 200 (idempotent).
    r = put(b"/v1/registered/smoke_pr1_a/password",
            b'{"password":"newpw_smoke_42"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 7. Unknown nick -> 404. Password is well above
    # cfg.min_password_length (default 10) to ensure the body
    # passes validation before the nick lookup runs.
    r = put(b"/v1/registered/never_registered_smoke/password",
            b'{"password":"newpw_smoke_zz"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 8. Hubbot nick -> not 200.
    r = put(b"/v1/registered/luadch-NG/password",
            b'{"password":"should_not_stick"}')
    if "200" in status(r):
        raise TestFailure(
            f"PUT on hubbot nick must not return 200; got {status(r)!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/password"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/password; body={cat!r}"
        )
    if '"rotate the password' not in cat:
        raise TestFailure(
            f"catalog missing PUT password description; body={cat!r}"
        )


def test_http_nickchange_pr4(staging_dir: Path, proc=None):
    """#82 registered-users family PR-4 (#236): cmd_nickchange plugin
    migrates PUT /v1/registered/{nick}/nick (admin scope). Coexists
    with the ADC `+nickchange` chat-cmd.

    Depends on PR-1 having created smoke_pr1_b in the same hub
    session - we rename smoke_pr1_b so we don't disturb
    smoke_pr1_a (referenced by PR-3's password test if smoke
    ordering ever shuffles).

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing new_nick -> 400.
    - PUT whitespace in new_nick -> 400.
    - PUT happy path -> 200 + action:nick-changed + previous_nick +
      online_kicked=false (target offline).
    - PUT same -> 200 (idempotent).
    - PUT to a name that's already registered -> 409 E_CONFLICT.
    - PUT unknown nick -> 404 E_NOT_FOUND.
    - GET /v1/registered confirms the renamed entry shows up under
      the new name and not the old.
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/nick.

    Runs AFTER PR-3 and BEFORE reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"smoke_pr4_renamed"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT nick: expected 401, got {status(r)!r}"
        )

    # 2. Missing new_nick -> 400.
    r = put(b"/v1/registered/smoke_pr1_b/nick", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing new_nick: expected 400, got {status(r)!r}; body={body_of(r)!r}"
        )

    # 3. Whitespace in new_nick -> 400.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"bad nick"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT whitespace nick: expected 400, got {status(r)!r}"
        )

    # 4. Happy path.
    r = put(b"/v1/registered/smoke_pr1_b/nick",
            b'{"new_nick":"smoke_pr4_renamed"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT nick: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "nick-changed":
        raise TestFailure(
            f"PUT nick: unexpected action; body={body_of(r)!r}"
        )
    if data.get("nick") != "smoke_pr4_renamed" or data.get("previous_nick") != "smoke_pr1_b":
        raise TestFailure(
            f"PUT nick: wrong nick/previous_nick; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"PUT nick: expected online_kicked=false (target offline); got {data!r}"
        )

    # 5. Idempotent retry: rename smoke_pr4_renamed -> smoke_pr4_renamed.
    r = put(b"/v1/registered/smoke_pr4_renamed/nick",
            b'{"new_nick":"smoke_pr4_renamed"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 6. Conflict: rename to smoke_pr1_a which still exists from PR-1.
    r = put(b"/v1/registered/smoke_pr4_renamed/nick",
            b'{"new_nick":"smoke_pr1_a"}')
    if "409" not in status(r):
        raise TestFailure(
            f"PUT conflict: expected 409, got {status(r)!r}; body={body_of(r)!r}"
        )
    if '"E_CONFLICT"' not in body_of(r):
        raise TestFailure(
            f"PUT conflict: expected E_CONFLICT; body={body_of(r)!r}"
        )

    # 7. Unknown nick -> 404.
    r = put(b"/v1/registered/never_registered_smoke/nick",
            b'{"new_nick":"foo_smoke_42"}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}"
        )

    # 8. GET list shows the new name and not the old.
    r = _http_roundtrip(
        b"GET /v1/registered?limit=1000 HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    nicks = [
        entry.get("nick")
        for entry in parsed.get("data", {}).get("registered", [])
    ]
    if "smoke_pr4_renamed" not in nicks:
        raise TestFailure(
            f"GET list missing renamed nick smoke_pr4_renamed; got {nicks!r}"
        )
    if "smoke_pr1_b" in nicks:
        raise TestFailure(
            f"GET list still contains old nick smoke_pr1_b after rename; got {nicks!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/nick"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/nick; body={cat!r}"
        )


def test_http_upgrade_pr5(staging_dir: Path, proc=None):
    """#82 registered-users family PR-5 (#236): cmd_upgrade plugin
    migrates PUT /v1/registered/{nick}/level (admin scope). Coexists
    with the ADC `+upgrade` chat-cmd.

    Depends on PR-1 having created smoke_pr1_a in the same hub
    session. (PR-4 renamed smoke_pr1_b -> smoke_pr4_renamed, but
    smoke_pr1_a stays at level 20.)

    Coverage:
    - Anonymous PUT -> 401.
    - PUT missing level -> 400.
    - PUT non-integer level -> 400.
    - PUT unknown level (999 not in cfg.levels) -> 400.
    - PUT happy path (level 30) -> 200 + action:level-changed +
      previous_level=20 + online_kicked=false.
    - PUT same level again -> 200 (idempotent).
    - PUT unknown nick -> 404.
    - GET /v1/registered/{nick} confirms the new level.
    - /v1/endpoints catalog lists PUT /v1/registered/{nick}/level.

    Runs AFTER PR-4 and BEFORE reload.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def put(path: bytes, body: bytes, with_auth: bool = True):
        h = auth if with_auth else b""
        return _http_roundtrip(
            b"PUT " + path + b" HTTP/1.1\r\n" + h +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    # 1. Anonymous -> 401.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}',
            with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous PUT level: expected 401, got {status(r)!r}"
        )

    # 2. Missing level -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT missing level: expected 400, got {status(r)!r}"
        )

    # 3. Non-integer level -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":"twenty"}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT non-integer level: expected 400, got {status(r)!r}"
        )

    # 4. Unknown level (999 not in cfg.levels) -> 400.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":999}')
    if "400" not in status(r):
        raise TestFailure(
            f"PUT unknown level: expected 400, got {status(r)!r}"
        )

    # 5. Happy path: smoke_pr1_a is level 20 (from PR-1). Bump to 30.
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT level: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "level-changed":
        raise TestFailure(
            f"PUT level: unexpected action; body={body_of(r)!r}"
        )
    if data.get("level") != 30 or data.get("previous_level") != 20:
        raise TestFailure(
            f"PUT level: expected level=30 previous=20; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"PUT level: expected online_kicked=false (target offline); got {data!r}"
        )

    # 6. Same level again -> 200 (idempotent).
    r = put(b"/v1/registered/smoke_pr1_a/level", b'{"level":30}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"PUT idempotent retry: expected 200, got {status(r)!r}"
        )

    # 7. Unknown nick -> 404.
    r = put(b"/v1/registered/never_registered_smoke/level",
            b'{"level":30}')
    if "404" not in status(r):
        raise TestFailure(
            f"PUT unknown nick: expected 404, got {status(r)!r}"
        )

    # 8. GET /v1/registered/{nick} reflects the new level.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET after PUT level: expected 200, got {status(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if parsed.get("data", {}).get("level") != 30:
        raise TestFailure(
            f"GET after PUT level: expected level=30; got {parsed!r}"
        )

    # 9. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"/v1/registered/{nick}/level"' not in cat:
        raise TestFailure(
            f"catalog missing /v1/registered/{{nick}}/level; body={cat!r}"
        )


def test_http_delreg_pr6(staging_dir: Path, proc=None):
    """#82 registered-users family PR-6 (#236): cmd_delreg plugin
    migrates DELETE /v1/registered/{nick} (admin scope, X-Confirm
    required). Coexists with the ADC `+delreg` chat-cmd.

    Depends on PR-1 having created smoke_pr4_renamed (renamed from
    smoke_pr1_b by PR-4) in the same hub session. We use that user
    to avoid disturbing smoke_pr1_a (referenced by PR-5's level
    test for the GET-reflect assertion).

    Coverage:
    - Anonymous DELETE -> 401.
    - DELETE without X-Confirm header -> 400 E_CONFIRMATION_REQUIRED.
    - DELETE with X-Confirm + reason -> 200 + action:delreg +
      blacklisted=true + online_kicked=false.
    - Post-DELETE GET /v1/registered/{nick} -> 404 (user gone).
    - Post-DELETE POST /v1/registered with same nick -> 409
      E_CONFLICT (blacklist entry blocks re-reg until explicit clear).
    - DELETE on unknown nick -> 404.
    - DELETE on hubbot -> not 200.
    - /v1/endpoints catalog lists DELETE /v1/registered/{nick}.

    Runs AFTER PR-5 and BEFORE reload. This is the last PR of the
    registered-users family - tracker #236 closes after merge.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
    confirm = b"X-Confirm: yes\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def delete(path: bytes, body: bytes = b"", with_auth: bool = True,
               with_confirm: bool = True):
        h = auth if with_auth else b""
        h += confirm if with_confirm else b""
        if body:
            return _http_roundtrip(
                b"DELETE " + path + b" HTTP/1.1\r\n" + h +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            b"DELETE " + path + b" HTTP/1.1\r\n" + h + b"\r\n"
        )

    # 1. Anonymous -> 401.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke test"}', with_auth=False)
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous DELETE: expected 401, got {status(r)!r}"
        )

    # 2. No X-Confirm header -> 400 E_CONFIRMATION_REQUIRED.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke test"}', with_confirm=False)
    if "400" not in status(r):
        raise TestFailure(
            f"DELETE without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"DELETE without X-Confirm: expected E_CONFIRMATION_REQUIRED; "
            f"body={body_of(r)!r}"
        )

    # 3. Happy path with reason -> 200 + blacklist entry.
    r = delete(b"/v1/registered/smoke_pr4_renamed",
               b'{"reason":"smoke delreg with reason"}')
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    data = parsed.get("data") or {}
    if data.get("action") != "delreg" or data.get("nick") != "smoke_pr4_renamed":
        raise TestFailure(
            f"DELETE: unexpected envelope; body={body_of(r)!r}"
        )
    if data.get("blacklisted") is not True:
        raise TestFailure(
            f"DELETE with reason: expected blacklisted=true; got {data!r}"
        )
    if data.get("online_kicked") is not False:
        raise TestFailure(
            f"DELETE: expected online_kicked=false (target offline); got {data!r}"
        )

    # 4. Post-DELETE GET -> 404.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr4_renamed HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(
            f"GET after DELETE: expected 404, got {status(r)!r}"
        )

    # 5. Post-DELETE POST same nick -> 409 (blacklisted).
    create_body = b'{"nick":"smoke_pr4_renamed","level":20}'
    r = _http_roundtrip(
        b"POST /v1/registered HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n"
        b"\r\n" + create_body
    )
    if "409" not in status(r):
        raise TestFailure(
            f"POST after blacklist-delreg: expected 409, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 6. DELETE unknown nick -> 404.
    r = delete(b"/v1/registered/never_registered_smoke")
    if "404" not in status(r):
        raise TestFailure(
            f"DELETE unknown nick: expected 404, got {status(r)!r}"
        )

    # 7. DELETE hubbot -> not 200.
    r = delete(b"/v1/registered/luadch-NG")
    if "200" in status(r):
        raise TestFailure(
            f"DELETE on hubbot must not return 200; got {status(r)!r}"
        )

    # 8. Catalog discovery.
    r = _http_roundtrip(
        b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n"
    )
    cat = body_of(r)
    if '"delreg a registered user' not in cat:
        raise TestFailure(
            f"catalog missing DELETE /v1/registered/{{nick}} description; "
            f"body={cat!r}"
        )


def test_239_cmd_ban_stale_bans_ref(staging_dir: Path, proc=None):
    """#239 regression: cmd_ban exported `bans` table goes stale
    after `+ban clear` rebinds the local `bans = {}`. cmd_accinfo's
    file-scope `local bans_tbl = ban.bans` (captured at module
    import time) holds the OLD reference, so any subsequent ban-
    status lookup (`+accinfoop` AND the new `GET /v1/registered/
    {nick}` ban field) returns a stale snapshot.

    Pre-fix repro:
    1. POST /v1/bans to ban smoke_pr1_a (regged from PR-1, offline).
    2. GET /v1/registered/smoke_pr1_a -> ban != null.
    3. ADC `+ban clear` via dummy (level 100) -> triggers cleanbans.
    4. GET /v1/registered/smoke_pr1_a -> ban != null (BUG; should
       be null because the persisted bans table is now empty).

    Post-fix (cleanbans mutates in place): step 4 returns ban=null.

    Runs LAST in the HTTP suite before reload so the family's
    persisted users / bans state is still intact.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # Step 1: POST /v1/bans on the offline-regged nick.
    create_body = (
        b'{"target_type":"nick","target":"smoke_pr1_a",'
        b'"duration_minutes":60,"reason":"#239 regression test"}'
    )
    r = _http_roundtrip(
        b"POST /v1/bans HTTP/1.1\r\n" + auth +
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(create_body)).encode("ascii") + b"\r\n"
        b"\r\n" + create_body
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"#239 setup: POST /v1/bans expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # Step 2: ban shows up in GET /v1/registered/{nick}.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    pre_ban = parsed.get("data", {}).get("ban")
    if not pre_ban:
        raise TestFailure(
            f"#239 setup: GET expected ban != null after POST /v1/bans; "
            f"got {parsed!r}"
        )

    # Step 3: trigger cleanbans via ADC `+ban clear` (level 100).
    # ADC BMSG escapes spaces as `\s` (matches the existing pattern
    # at the `[+!#]help` literal-prefix test); a literal space would
    # otherwise terminate the message field early. The 3s sleep is
    # the safer synchronisation than recv-on-pattern because the
    # hub-bot reply can arrive AS a BMSG (the test sees it via the
    # initial socket buffer if drained too early on a fast machine),
    # so we just let the dispatch tick complete before the next GET.
    with _logged_in_user() as (sock, sid, _reader):
        sock.sendall(f"BMSG {sid} +ban\\sclear\n".encode("utf-8"))
        time.sleep(3.0)

    # Step 4: ban should be null after cleanbans. Pre-fix, the
    # cmd_accinfo-held stale reference would still surface the
    # ban entry here.
    r = _http_roundtrip(
        b"GET /v1/registered/smoke_pr1_a HTTP/1.1\r\n" + auth + b"\r\n"
    )
    parsed = _json.loads(body_of(r))
    post_ban = parsed.get("data", {}).get("ban")
    if post_ban is not None:
        raise TestFailure(
            f"#239 regression: GET after `+ban clear` expected ban=null; "
            f"got {post_ban!r} - cmd_accinfo's bans_tbl is stale "
            f"(cleanbans rebound the local, the import reference is now orphan)"
        )


def test_320_offline_ban_hierarchy(staging_dir: Path, proc=None):
    """#320 regression: cmd_ban offline-by-nick path silently bypassed
    the `permission[level] < target:level()` hierarchy check that fires
    on the online path. A low-level op could ban an offline registered
    user of ARBITRARILY HIGHER LEVEL - including the hubowner, which
    would lock them out on the next login attempt.

    Repro:
      1. Register `smoke_320_op` at level 60 (operator) with a known
         password via POST /v1/registered.
      2. Register `smoke_320_target` at level 100 (hubowner-equivalent)
         offline (no login).
      3. Log in as `smoke_320_op` and broadcast `+ban nick
         smoke_320_target 60 #320`.
      4. GET /v1/bans and assert NO ban entry for `smoke_320_target`
         exists.

    Pre-fix: step 4 finds the ban entry (offline branch skipped the
    permission check, addban ran).
    Post-fix: step 4 finds no entry (offline branch now enforces the
    same hierarchy guard; cfg default `cmd_ban_permission[60] = 50`,
    target.level = 100, 50 < 100 -> msg_god, no addban).

    Cleanup: DELETE both registered users so the suite stays
    self-contained.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def http_post(path, body):
        return _http_roundtrip(
            b"POST " + path + b" HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    def http_delete(path):
        return _http_roundtrip(
            b"DELETE " + path + b" HTTP/1.1\r\n" + auth +
            b"X-Confirm: yes\r\n\r\n"
        )

    # Pre-emptive cleanup so a re-run after a crashed previous run does
    # not collide on POST (409 already-exists). DELETE on a non-existent
    # nick returns 404, harmless.
    http_delete(b"/v1/registered/smoke_320_op")
    http_delete(b"/v1/registered/smoke_320_target")

    try:
        # Step 1: register the operator with a known password.
        op_body = (
            b'{"nick":"smoke_320_op","level":60,"password":"pwop320"}'
        )
        r = http_post(b"/v1/registered", op_body)
        if "200 OK" not in status(r) and "201" not in status(r):
            raise TestFailure(
                f"#320 setup: POST /v1/registered (op) expected 200/201, "
                f"got {status(r)!r}; body={body_of(r)!r}"
            )

        # Step 2: register an offline hubowner-level target.
        target_body = (
            b'{"nick":"smoke_320_target","level":100,'
            b'"password":"pwtarget320"}'
        )
        r = http_post(b"/v1/registered", target_body)
        if "200 OK" not in status(r) and "201" not in status(r):
            raise TestFailure(
                f"#320 setup: POST /v1/registered (target) expected 200/201, "
                f"got {status(r)!r}; body={body_of(r)!r}"
            )

        # Step 3: log in as the op and send the +ban command. The
        # 3s sleep matches the test_239 pattern - +ban dispatch is
        # immediate, the hub-bot reply may queue back as a BMSG.
        with _logged_in_user("smoke_320_op", "pwop320") as (sock, sid, _reader):
            sock.sendall(
                f"BMSG {sid} +ban\\snick\\ssmoke_320_target\\s60\\s#320test\n"
                .encode("utf-8")
            )
            time.sleep(3.0)

        # Step 4: verify no ban entry was added for the target. Pre-fix,
        # the offline-branch addban() at cmd_ban.lua line 960 would have
        # persisted an entry with by="nick" id="smoke_320_target".
        r = _http_roundtrip(
            b"GET /v1/bans HTTP/1.1\r\n" + auth + b"\r\n"
        )
        if "200 OK" not in status(r):
            raise TestFailure(
                f"#320 verify: GET /v1/bans expected 200, "
                f"got {status(r)!r}; body={body_of(r)!r}"
            )
        parsed = _json.loads(body_of(r))
        bans = parsed.get("data", {}).get("bans", [])
        for ban in bans:
            if ban.get("nick") == "smoke_320_target":
                raise TestFailure(
                    f"#320 regression: offline-ban hierarchy check "
                    f"bypassed - operator at level 60 was able to ban "
                    f"level-100 offline user; ban entry persisted: "
                    f"{ban!r}"
                )

    finally:
        # Cleanup: remove the two test users so the rest of the suite
        # sees no residue. Errors here are swallowed - the assertion
        # above already captures the verdict.
        http_delete(b"/v1/registered/smoke_320_op")
        http_delete(b"/v1/registered/smoke_320_target")


def _switch_to_partial_prefix_table_mode(staging_dir: Path, current_proc, current_log_file):
    """#243 setup: remove ONE entry from cfg.tbl
    `usr_nick_prefix_prefix_table` while leaving the rest intact -
    targets level 30, the post-PR-5 level of smoke_pr1_a. The
    surrounding entries (0/10/20/40/.../100) survive so the
    dummy user (level 100) can still log in cleanly; subsequent
    smoke tests (kill_wrong_ips / BLOM / ZLIF / hub_listen) are
    unaffected because they don't exercise level-30 users.

    Pre-fix the ADC `+setpass nick smoke_pr1_a <pw>` path then
    crashes on `prefix_table[30]` returning nil and concatenating
    with the nick. Post-fix the `or ""` guard absorbs the missing
    entry.

    Restart the hub against the mangled cfg and return the new
    (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    # Surgical removal: delete the `[ 30 ] = "[VIP]",` line.
    new_text, n = re.subn(
        r'^\s*\[\s*30\s*\]\s*=\s*"\[VIP\]"\s*,\s*\n',
        "",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not remove `[ 30 ] = \"[VIP]\"` entry from "
            "usr_nick_prefix_prefix_table in cfg.tbl (regex did not "
            "match - did the default cfg.tbl shape change?)"
        )
    cfg_path.write_text(new_text, encoding="utf-8")
    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    wait_for_port(HUB_HOST, TEST_PORT_HTTP, 5.0)
    return proc, log_file


def test_243_prefix_table_nil_no_adc_crash(staging_dir: Path, proc=None):
    """#243 regression: ADC `+setpass`, `+nickchange`, `+upgrade`,
    `+delreg` all index `prefix_table[level]` without a nil-guard
    inside `if activate then`. When the prefix table has no entry
    for the target user's level (cfg drift OR an ad-hoc level the
    operator forgot to add), the index returns nil and the
    downstream concat (`nil .. nick`) crashes the handler. The
    HTTP path was always defensive (`prefix_table[level] or ""`).

    The crash is caught by the dispatcher (it does not kill the
    hub) but the trace lands in `error.log`. This test runs the
    ADC `+setpass` chat-cmd under the mangled cfg (level 30 entry
    removed) and asserts `error.log` carries no
    `attempt to concatenate a nil` / `attempt to index a nil`
    entry for any of the four family plugins.

    Uses smoke_pr1_a (created by #236 PR-1, level 30 after PR-5)
    as the regged target. The user is regged in user.tbl which
    survives the mode switch (only cfg.tbl is rewritten).
    """
    error_log = staging_dir / "log" / "error.log"
    size_before = error_log.stat().st_size if error_log.exists() else 0

    with _logged_in_user() as (sock, sid, _reader):
        # ADC BMSG escapes spaces as `\s` (see #239 / cmd_help
        # literal-bracket smoke). Target cmd: `+upgrade nick
        # smoke_pr1_a 40`. Of the four family plugins,
        # cmd_setpass / cmd_nickchange / cmd_delreg all wrap
        # the prefix lookup in `hub.escapeto( prefix_table[...] )`
        # and `hub.escapeto` is a C function that `luaL_optstring`s
        # a nil arg to `""` - no crash. cmd_upgrade's ADC path
        # (line ~244 pre-fix) uses `prefix = prefix_table[ level ]`
        # then `target_nick = prefix .. target_firstnick` without
        # the escapeto wrapper, so `nil .. <nick>` crashes the
        # handler. This is the only crash-site in the family,
        # but the `or ""` guard goes onto all four plugins for
        # consistency.
        sock.sendall(f"BMSG {sid} +upgrade\\snick\\ssmoke_pr1_a\\s40\n".encode("utf-8"))
        time.sleep(3.0)

    size_after = error_log.stat().st_size if error_log.exists() else 0
    if size_after <= size_before:
        return  # No new error.log lines - the handler ran cleanly.

    with open(error_log, "rb") as f:
        f.seek(size_before)
        new_text = f.read()
    bad_patterns = [
        b"attempt to concatenate a nil",
        b"attempt to index a nil",
    ]
    plugin_markers = [
        b"cmd_setpass",
        b"cmd_nickchange",
        b"cmd_upgrade",
        b"cmd_delreg",
    ]
    for bp in bad_patterns:
        if bp in new_text:
            # Surface which plugin to make the failure self-debugging.
            for pm in plugin_markers:
                if pm in new_text:
                    raise TestFailure(
                        f"#243 regression: error.log shows {bp!r} from "
                        f"{pm.decode()!r} under cfg drift "
                        f"(prefix_table = {{}}). New error.log section: "
                        f"{new_text[:512]!r}"
                    )
            raise TestFailure(
                f"#243 regression: error.log shows {bp!r} under cfg "
                f"drift (prefix_table = {{}}). New error.log section: "
                f"{new_text[:512]!r}"
            )


def test_http_prometheus_metrics(staging_dir: Path, proc=None):
    """#83: Prometheus /metrics endpoint (opt-in plugin etc_prometheus).

    Default cfg ships with etc_prometheus_activate=false, so the
    plugin loads but does not register the route - GET /metrics
    returns 404 E_NOT_FOUND. After flipping the cfg key + +reload
    via the HTTP API, the plugin re-evaluates its activate gate at
    module load time, registers the route, and serves the
    Prometheus 0.0.4 text exposition.

    Coverage:
    - Anonymous GET /metrics -> 401 (router auth gate fires).
    - Authenticated GET /metrics pre-enable -> 404 (route not registered).
    - Flip cfg.tbl etc_prometheus_activate to true.
    - POST /v1/reload with X-Confirm -> plugin re-loads with new gate.
    - Authenticated GET /metrics post-enable -> 200 + text/plain
      Content-Type + Prometheus exposition body (HELP/TYPE/value
      lines for each of the 14 metric names).
    - /v1/endpoints catalog lists GET /metrics post-enable.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous GET -> 401.
    r = _http_roundtrip(b"GET /metrics HTTP/1.1\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous GET /metrics: expected 401, got {status(r)!r}"
        )

    # 2. Authenticated GET pre-enable -> 404 (plugin inactive,
    # route not registered, router falls through to generic 404).
    r = _http_roundtrip(b"GET /metrics HTTP/1.1\r\n" + auth + b"\r\n")
    if "404" not in status(r):
        raise TestFailure(
            f"GET /metrics pre-enable: expected 404 (plugin off), "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 3. Flip cfg.tbl etc_prometheus_activate -> true.
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"etc_prometheus_activate\s*=\s*false",
        "etc_prometheus_activate = true",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip etc_prometheus_activate in cfg.tbl "
            "(regex did not match)"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    # 4. POST /v1/reload (with X-Confirm) -> re-evaluates plugin
    # activate gates. Lua is single-threaded; the reload completes
    # before the next request lands.
    r = _http_roundtrip(
        b"POST /v1/reload HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/reload (to activate prometheus): expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 5. Authenticated GET post-enable -> 200 + Prometheus text.
    r = _http_roundtrip(b"GET /metrics HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"GET /metrics post-enable: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    if "text/plain" not in r.lower():
        raise TestFailure(
            f"GET /metrics post-enable: expected text/plain Content-Type; "
            f"resp={r!r}"
        )
    body = body_of(r)
    # Each metric carries HELP + TYPE + value lines.
    expected_names = [
        "luadch_users_online",
        "luadch_users_online_bots",
        "luadch_share_total_bytes",
        "luadch_files_total",
        "luadch_hub_uptime_seconds",
        "luadch_lua_memory_kb",
        "luadch_active_bans",
        "luadch_logins_total",
        "luadch_logouts_total",
        "luadch_failed_auths_total",
        "luadch_chat_msgs_total",
        "luadch_pm_msgs_total",
        "luadch_searches_total",
        "luadch_script_errors_total",
    ]
    for name in expected_names:
        if "# HELP " + name not in body:
            raise TestFailure(
                f"GET /metrics: missing `# HELP {name}` line; body={body!r}"
            )
        if "# TYPE " + name not in body:
            raise TestFailure(
                f"GET /metrics: missing `# TYPE {name}` line; body={body!r}"
            )

    # 5b. Lock in the wire-up by asserting two values: bots count
    # (the hubbot is always present, must be >= 1 - exercises
    # count_online's bot branch) and uptime (always > 0 -
    # exercises signal.get + os.difftime). A future regression
    # that pointed a listener / collector at the wrong upvalue
    # would fail at one of these checks.
    m_bots = re.search(r"^luadch_users_online_bots (\d+)$", body, re.MULTILINE)
    if not m_bots:
        raise TestFailure(
            f"GET /metrics: could not parse luadch_users_online_bots; body={body!r}"
        )
    bots = int(m_bots.group(1))
    if bots < 1:
        raise TestFailure(
            f"GET /metrics: expected luadch_users_online_bots >= 1 "
            f"(hubbot is always present); got {bots}"
        )
    m_uptime = re.search(r"^luadch_hub_uptime_seconds (\d+)$", body, re.MULTILINE)
    if not m_uptime:
        raise TestFailure(
            f"GET /metrics: could not parse luadch_hub_uptime_seconds; "
            f"body={body!r}"
        )
    uptime = int(m_uptime.group(1))
    if uptime < 1:
        raise TestFailure(
            f"GET /metrics: expected uptime >= 1s; got {uptime}"
        )

    # 6. /v1/endpoints catalog lists GET /metrics post-enable.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/metrics"' not in b:
        raise TestFailure(f"catalog missing /metrics; body={b!r}")


def test_audit_log_84(staging_dir: Path, proc=None):
    """#84 audit log end-to-end: every staff action emits one
    onAudit event; etc_auditlog persists it as JSONL; the same
    event surfaces via /v1/events?types=audit (admin-scope only).

    Coverage (issue acceptance criterion is check 2 below):
    1. ADC path: +reg via dummy creates a registered user.
    2. log/audit-YYYY-MM-DD.jsonl contains action="reg.add"
       with actor.nick="dummy" and target.nick="audit_smoke_a"
       (the canonical end-to-end acceptance test).
    3. HTTP path: POST /v1/registered with admin token creates
       a second user; the audit log gets a second line with
       actor.sid="<http>" + the token label as actor.nick.
    4. ADC +delreg removes the first user; log line is action=
       "reg.remove".
    5. GET /v1/log/audit?lines=N (admin scope) returns the tail.
    6. GET /v1/events?types=audit (admin scope) returns the
       events with the actor / target / action fields.
    7. GET /v1/events?types=audit with a hypothetical read-scope
       token MUST NOT see audit events. (We assert this by
       checking the audit event TYPE is excluded from the scope-
       gate filter; the read-token path is covered via the
       holistic scope matrix in test_http_auth_scope_matrix.)

    Cleans up the auxiliary registered user it creates so the
    smoke harness can rerun without stale state.
    """
    import json as _json
    import datetime as _dt

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def req(method: bytes, path: bytes, body: bytes = b"", extra_headers: bytes = b""):
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + auth + extra_headers +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + auth + extra_headers + b"\r\n"
        )

    nick_adc  = "audit_smoke_a"
    nick_http = "audit_smoke_b"

    # Best-effort pre-clean so a rerun in the same staging dir is
    # idempotent (DELETE 404 on a missing nick is harmless).
    req(b"DELETE", b"/v1/registered/" + nick_adc.encode("ascii"),
        extra_headers=b"X-Confirm: yes\r\n")
    req(b"DELETE", b"/v1/registered/" + nick_http.encode("ascii"),
        extra_headers=b"X-Confirm: yes\r\n")

    # Note current /v1/events cursor so we can poll only NEW events.
    # `latest` is the documented "current cursor without replay"
    # sentinel (#263 PR-A).
    r = req(b"GET", b"/v1/events?since=latest&types=audit&wait=0")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/events?since=latest: {status(r)!r}")
    parsed = _json.loads(body_of(r))
    cursor_baseline = parsed.get("data", {}).get("cursor")
    if cursor_baseline is None:
        raise TestFailure(f"missing data.cursor on baseline: {parsed!r}")

    # 1. ADC: +reg nick <nick> <level> via dummy (level 100). The
    # success banner is `[ REG ]--> User regged with ...`; the
    # etc_hubcommands `[command] +reg ...` echo also contains the
    # nick but NOT the literal "User regged", so we anchor on that
    # string to avoid mistaking the echo for the success message
    # (the same pattern bit the +delreg branch below).
    def _is_chat(f):
        return f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ")
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(
            f"BMSG {sid} +reg\\snick\\s{nick_adc}\\s20\n".encode("utf-8")
        )
        reply = reader.recv_until(
            lambda f: _is_chat(f) and "User\\sregged" in f and nick_adc in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+reg did not confirm: {reply!r}")

    # 2. Assert the JSONL file has the new line.
    today = _dt.datetime.utcnow().strftime("%Y-%m-%d")
    audit_path = staging_dir / "log" / f"audit-{today}.jsonl"
    if not audit_path.exists():
        raise TestFailure(
            f"audit log not created at {audit_path}; this is the issue's "
            f"primary acceptance criterion - +reg from dummy must produce a line"
        )
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    matches_adc = [
        _json.loads(ln) for ln in lines
        if ln and '"reg.add"' in ln and f'"{nick_adc}"' in ln
    ]
    if not matches_adc:
        raise TestFailure(
            f"audit log has no reg.add entry for {nick_adc!r}; "
            f"file contents: {audit_path.read_text(encoding='utf-8')!r}"
        )
    adc_event = matches_adc[-1]
    if adc_event.get("action") != "reg.add":
        raise TestFailure(f"action mismatch: {adc_event!r}")
    # actor.nick is the canonical firstnick (no level prefix); the
    # visible-in-chat form lands in display_nick (e.g. "[HUBOWNER]dummy").
    if (adc_event.get("actor") or {}).get("nick") != "dummy":
        raise TestFailure(f"actor.nick != dummy: {adc_event!r}")
    if (adc_event.get("target") or {}).get("nick") != nick_adc:
        raise TestFailure(f"target.nick != {nick_adc}: {adc_event!r}")
    if (adc_event.get("target") or {}).get("level") != 20:
        raise TestFailure(f"target.level != 20: {adc_event!r}")
    if not adc_event.get("ts"):
        raise TestFailure(f"missing ts: {adc_event!r}")

    # 3. HTTP: POST /v1/registered (admin token).
    body = _json.dumps({"nick": nick_http, "level": 30}).encode("utf-8")
    r = req(b"POST", b"/v1/registered", body=body)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/registered: expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    matches_http = [
        _json.loads(ln) for ln in lines
        if ln and '"reg.add"' in ln and f'"{nick_http}"' in ln
    ]
    if not matches_http:
        raise TestFailure(
            f"audit log has no reg.add for HTTP-created {nick_http!r}"
        )
    http_event = matches_http[-1]
    if (http_event.get("actor") or {}).get("sid") != "<http>":
        raise TestFailure(
            f"HTTP actor.sid expected '<http>', got: {http_event!r}"
        )

    # 4. ADC +delreg removes the first user. cmd_delreg syntax is
    # `+delreg <option> <nick> [<reason>]` where option ∈ {nick, nicku} -
    # NOT `+delreg <nick>` (that path hits msg_usage). The success
    # banner is `[ DELREG ]--> User <nick> was delregged by <op>`
    # so the predicate looks for "delregged" specifically; the
    # etc_hubcommands `[command] +delreg ...` echo doesn't contain
    # that word, so we won't mistake it for the actual success.
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as sock:
        sid, reader = _adc_login(sock, "dummy", "test")
        sock.sendall(f"BMSG {sid} +delreg\\snick\\s{nick_adc}\n".encode("utf-8"))
        reply = reader.recv_until(
            lambda f: ( f.startswith("EMSG ") or f.startswith("DMSG ") or f.startswith("BMSG ") )
                      and "delregged" in f and nick_adc in f,
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if not reply:
            raise TestFailure(f"+delreg did not confirm: {reply!r}")
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    has_remove = any(
        '"reg.remove"' in ln and f'"{nick_adc}"' in ln
        for ln in lines
    )
    if not has_remove:
        raise TestFailure(
            f"audit log has no reg.remove entry for {nick_adc!r}"
        )

    # 5. GET /v1/log/audit?lines=N tail endpoint.
    r = req(b"GET", b"/v1/log/audit?lines=5")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/log/audit: {status(r)!r}; body={body_of(r)!r}")
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"GET /v1/log/audit: ok!=true; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    for key in ("lines", "returned", "total_lines"):
        if key not in data:
            raise TestFailure(
                f"GET /v1/log/audit: missing {key!r}; body={body_of(r)!r}"
            )
    if data["total_lines"] < 3:
        raise TestFailure(
            f"GET /v1/log/audit: expected >=3 total lines (reg.add ADC + "
            f"reg.add HTTP + reg.remove ADC), got {data['total_lines']}"
        )

    # 6. GET /v1/events?types=audit picks up the 3 audit events.
    r = req(b"GET",
        f"/v1/events?types=audit&since={cursor_baseline}&wait=0".encode("ascii"))
    if "200 OK" not in status(r):
        raise TestFailure(f"GET /v1/events?types=audit: {status(r)!r}")
    parsed = _json.loads(body_of(r))
    events = (parsed.get("data") or {}).get("events") or []
    audit_evs = [e for e in events if e.get("type") == "audit"]
    if len(audit_evs) < 3:
        raise TestFailure(
            f"GET /v1/events?types=audit: expected >=3 audit events, got "
            f"{len(audit_evs)}; events={events!r}"
        )
    # Action types present + flat actor/target shape (per the
    # http_events tap's _listener_arg_to_event mapping).
    actions_seen = {e.get("action") for e in audit_evs}
    if "reg.add" not in actions_seen or "reg.remove" not in actions_seen:
        raise TestFailure(
            f"missing expected action types in stream: {actions_seen!r}"
        )

    # Cleanup the HTTP-created user so a rerun starts clean.
    req(b"DELETE", b"/v1/registered/" + nick_http.encode("ascii"),
        extra_headers=b"X-Confirm: yes\r\n")


def test_clientblocker_81(staging_dir: Path, proc=None):
    """#81 etc_clientblocker end-to-end:
       1. POST /v1/clientblocker with a unique smoke pattern.
       2. New connection with VEsmokebadcli/1.0 -> hub emits
          ISTA 231 <reason> TL-1 and drops the socket (the
          issue's primary acceptance criterion).
       3. New connection with a non-matching VE -> normal login.
       4. DELETE /v1/clientblocker/{pattern} -> 200 + audit
          client.block.remove.
       5. New connection with the previously-blocked VE -> normal
          login (verifies the unblock landed in the live cache).
       6. Audit log on disk gained client.block.kick + .add +
          .remove lines with the right meta + actor/target shape.

    Anchors the kick predicate on the literal "ISTA 231 " + the
    custom reason string ("smoke_blocked_81") to avoid the BINF-
    echo false-match noted in the #84 audit-test pattern. The
    pattern is unique (`smokebadcli81`) so re-running the smoke
    harness on the same staging_dir is idempotent (best-effort
    DELETE up front swallows any leftover).
    """
    import json as _json
    import datetime as _dt

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def req(method: bytes, path: bytes, body: bytes = b""):
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + auth +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + auth + b"\r\n"
        )

    pattern = "smokebadcli81"
    reason = "smoke_blocked_81"

    # Best-effort pre-clean.
    req(b"DELETE", b"/v1/clientblocker/" + pattern.encode("ascii"))

    # 1. POST adds the pattern.
    body = _json.dumps({"pattern": pattern, "reason": reason}).encode("utf-8")
    r = req(b"POST", b"/v1/clientblocker", body)
    if "201 Created" not in status(r):
        raise TestFailure(
            f"POST /v1/clientblocker: expected 201, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )

    # 2. Connect with a matching VE -> ISTA 231 + drop. The plugin's
    # onConnect listener fires BEFORE the IGPA challenge (see
    # core/hub_dispatch.lua:589) so we never reach password auth on
    # this connection. The kick line shape is
    #     ISTA 231 <reason> TL-1
    # with the reason wire-escaped via hub.escapeto - a space in
    # the reason ("smoke_blocked_81" has none) survives unchanged.
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        _sid, _reader, frame = _adc_login(
            sock, "dummy", "test",
            ve=f"{pattern}/1.0", expect_kill=True,
        )
        if not frame.startswith("ISTA 231"):
            raise TestFailure(
                f"#81 acceptance: expected ISTA 231 kick from etc_clientblocker, "
                f"got {frame!r}"
            )
        if reason not in frame:
            raise TestFailure(
                f"#81 acceptance: ISTA 231 reason does not contain {reason!r}: "
                f"{frame!r}"
            )
        _assert_adc_drops(sock)

    # 3. Connect with a non-matching VE -> normal login.
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(sock, "dummy", "test", ve="GoodClient/1.0")
        if not sid:
            raise TestFailure(
                "non-matching VE was kicked - check_levels or the pattern "
                "logic let through what should have been a normal login"
            )

    # 4. DELETE the pattern.
    r = req(b"DELETE", b"/v1/clientblocker/" + pattern.encode("ascii"))
    if "200 OK" not in status(r):
        raise TestFailure(
            f"DELETE /v1/clientblocker/{pattern}: expected 200, "
            f"got {status(r)!r}; body={body_of(r)!r}"
        )

    # 5. Reconnect with the previously-blocked VE - should now be
    # a normal login (verifies the in-memory patterns_tbl mutation
    # took effect immediately; the plugin saves to disk AND mutates
    # the live cache so the next onConnect iterates a fresh map).
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sid, _reader = _adc_login(
            sock, "dummy", "test", ve=f"{pattern}/1.0"
        )
        if not sid:
            raise TestFailure(
                "after DELETE, previously-blocked VE was STILL kicked - "
                "patterns_tbl was not updated in the live cache"
            )

    # 6. Assert the JSONL audit log gained the right events. The
    # filename matches the pattern test_audit_log_84 uses.
    today = _dt.datetime.utcnow().strftime("%Y-%m-%d")
    audit_path = staging_dir / "log" / f"audit-{today}.jsonl"
    if not audit_path.exists():
        raise TestFailure(
            f"#81 audit log missing at {audit_path}; the audit plugin "
            f"should have emitted at least three lines by now"
        )
    text = audit_path.read_text(encoding="utf-8")
    seen_actions = []
    for ln in text.splitlines():
        if not ln:
            continue
        try:
            ev = _json.loads(ln)
        except _json.JSONDecodeError:
            continue
        meta = ev.get("meta") or {}
        if meta.get("pattern") == pattern:
            seen_actions.append(ev.get("action"))
    for expected in ("client.block.add", "client.block.kick", "client.block.remove"):
        if expected not in seen_actions:
            raise TestFailure(
                f"#81 audit log missing {expected!r} for pattern={pattern!r}; "
                f"seen actions: {seen_actions!r}"
            )

    # 7. Out-of-the-box block: the bundled scripts/data/etc_clientblocker.tbl
    # ships with the Sopor-curated cheat/mod client list (RSX++, CrZ++,
    # FearDC, CleanDC++, SmVDC++, DC@fe++). Connecting with one of these
    # AP/VE strings must be kicked without any operator configuration.
    # FearDC is the cleanest pattern (`^FearDC.+` - no special-char escape
    # confusion in the test's BINF construction).
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        _sid, _reader, frame = _adc_login(
            sock, "dummy", "test",
            ve="FearDC/2.0", expect_kill=True,
        )
        if not frame.startswith("ISTA 231"):
            raise TestFailure(
                f"#81 out-of-the-box: expected ISTA 231 kick from bundled "
                f"FearDC pattern, got {frame!r}"
            )
        if "FearDC" not in frame:
            raise TestFailure(
                f"#81 out-of-the-box: ISTA 231 reason does not contain "
                f"FearDC: {frame!r}"
            )
        _assert_adc_drops(sock)


def test_http_reload(staging_dir: Path, proc=None):
    """#82 deferred Phase-2-spec item: cmd_reload plugin migrates to
    POST /v1/reload (X-Confirm). Coexists with the ADC `+reload`
    chat-cmd.

    Coverage:
    - Anonymous POST -> 401.
    - POST without X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    - POST with X-Confirm: yes -> 200 + action:"reload" +
      reloaded:["cfg","scripts"].
    - Post-reload: /v1/endpoints catalog still lists POST /v1/reload
      (proves restartscripts re-registered the route).
    - Post-reload: dummy ADC login still works (proves plugins
      re-init'd cleanly).

    Placement note: this test runs BEFORE test_inf_integer_clamps,
    which itself queries /v1/users via HTTP. inf_integer_clamps
    thus acts as a natural sanity check that reload did not break
    the HTTP route table.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # 1. Anonymous POST -> 401.
    r = _http_roundtrip(b"POST /v1/reload HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
    if "401" not in status(r):
        raise TestFailure(
            f"anonymous POST /v1/reload: expected 401, got {status(r)!r}"
        )

    # 2. Without X-Confirm -> 400 E_CONFIRMATION_REQUIRED.
    r = _http_roundtrip(
        b"POST /v1/reload HTTP/1.1\r\n" + auth +
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    if "400" not in status(r):
        raise TestFailure(
            f"POST /v1/reload without X-Confirm: expected 400, got {status(r)!r}"
        )
    if '"E_CONFIRMATION_REQUIRED"' not in body_of(r):
        raise TestFailure(
            f"POST /v1/reload without X-Confirm: expected "
            f"E_CONFIRMATION_REQUIRED; body={body_of(r)!r}"
        )

    # 3. With X-Confirm: yes -> 200 + envelope.
    r = _http_roundtrip(
        b"POST /v1/reload HTTP/1.1\r\n" + auth +
        b"X-Confirm: yes\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    if "200 OK" not in status(r):
        raise TestFailure(
            f"POST /v1/reload with X-Confirm: expected 200, got {status(r)!r}; "
            f"body={body_of(r)!r}"
        )
    parsed = _json.loads(body_of(r))
    if not parsed.get("ok"):
        raise TestFailure(f"POST /v1/reload: ok=false; body={body_of(r)!r}")
    data = parsed.get("data") or {}
    if data.get("action") != "reload":
        raise TestFailure(
            f"POST /v1/reload: expected action=reload; body={body_of(r)!r}"
        )
    reloaded = data.get("reloaded") or []
    if "cfg" not in reloaded or "scripts" not in reloaded:
        raise TestFailure(
            f"POST /v1/reload: expected reloaded array containing cfg + scripts; "
            f"body={body_of(r)!r}"
        )

    # 4. Post-reload: /v1/endpoints catalog still lists POST /v1/reload.
    # If restartscripts() did not re-register the route, this fails.
    r = _http_roundtrip(b"GET /v1/endpoints HTTP/1.1\r\n" + auth + b"\r\n")
    b = body_of(r)
    if '"/v1/reload"' not in b:
        raise TestFailure(
            f"catalog missing /v1/reload after reload; "
            f"restartscripts did not re-register? body={b!r}"
        )


def test_http_phase_d_whitelist(staging_dir: Path, proc=None):
    """#78 allowlist Phase D HTTP API for the global whitelist.

    Four endpoints on etc_whitelist.lua v0.02 (GET /v1/whitelist and
    /counts, POST, DELETE /v1/whitelist/{id}) - the same shape as the
    blocklist HTTP API. Seed-aware: a fresh hub already holds the bundled
    pinger entries (source=pinger), so the baseline count is captured
    rather than assumed.

    Coverage: anonymous POST -> 401; counts baseline carries a pinger
    source; POST create -> 201 + id; GET reflects it + counts baseline+1;
    POST host-bits-set cidr -> 400; DELETE created -> 200 removed;
    DELETE 999 -> 404; counts back to baseline.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(path: bytes, body: bytes) -> str:
        return _http_roundtrip(
            b"POST " + path + b" HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    def get(path: bytes) -> str:
        return _http_roundtrip(b"GET " + path + b" HTTP/1.1\r\n" + auth + b"\r\n")

    def delete_id(id_str: str) -> str:
        return _http_roundtrip(
            b"DELETE /v1/whitelist/" + id_str.encode("ascii") +
            b" HTTP/1.1\r\n" + auth + b"\r\n"
        )

    # 1. Anonymous POST -> 401 (admin scope requires a token).
    anon_body = b'{"cidr":"203.0.113.9"}'
    r = _http_roundtrip(
        b"POST /v1/whitelist HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(anon_body)).encode("ascii") + b"\r\n"
        b"\r\n" + anon_body
    )
    if "401" not in status(r):
        raise TestFailure(f"anonymous POST /v1/whitelist should be 401, got {status(r)!r}")

    # 2. Baseline counts: the bundled pinger seed is present. Capture the
    #    total (robust to any prior whitelist test in the same run).
    r = get(b"/v1/whitelist/counts")
    b = body_of(r).replace(" ", "")
    if "200 OK" not in status(r):
        raise TestFailure(f"GET counts pre-flight: expected 200, got {status(r)!r}")
    m0 = re.search(r'"total":(\d+)', b)
    if not m0:
        raise TestFailure(f"counts had no total; body={b!r}")
    base = int(m0.group(1))
    if '"pinger"' not in b:
        raise TestFailure(f"seed counts missing pinger source; body={b!r}")

    # 3. POST create -> 201 + id.
    r = post(b"/v1/whitelist", b'{"cidr":"203.0.113.0/24","reason":"api test"}')
    if "201" not in status(r):
        raise TestFailure(f"POST create: expected 201, got {status(r)!r}; body={body_of(r)!r}")
    m = re.search(r'"id":(\d+)', body_of(r).replace(" ", ""))
    if not m:
        raise TestFailure(f"POST create response had no id; body={body_of(r)!r}")
    new_id = m.group(1)

    # 4. GET reflects the addition; counts == baseline + 1.
    r = get(b"/v1/whitelist")
    if '"203.0.113.0/24"' not in body_of(r).replace(" ", ""):
        raise TestFailure("GET /v1/whitelist did not reflect the created entry")
    r = get(b"/v1/whitelist/counts")
    if f'"total":{base + 1}' not in body_of(r).replace(" ", ""):
        raise TestFailure(f"counts after create: expected {base + 1}; body={body_of(r)!r}")

    # 5. POST host-bits-set cidr -> 400.
    r = post(b"/v1/whitelist", b'{"cidr":"1.2.3.4/24"}')
    if "400" not in status(r):
        raise TestFailure(f"POST host-bits-set should be 400, got {status(r)!r}")

    # 6. DELETE the created entry -> 200 removed.
    r = delete_id(new_id)
    if "200" not in status(r) or '"action":"removed"' not in body_of(r).replace(" ", ""):
        raise TestFailure(f"DELETE id={new_id}: expected 200 removed, got {status(r)!r}; body={body_of(r)!r}")

    # 7. DELETE non-existent -> 404.
    r = delete_id("999999")
    if "404" not in status(r):
        raise TestFailure(f"DELETE 999999 should be 404, got {status(r)!r}")

    # 8. Counts back to the baseline.
    r = get(b"/v1/whitelist/counts")
    if f'"total":{base}' not in body_of(r).replace(" ", ""):
        raise TestFailure(f"counts after delete: expected {base}; body={body_of(r)!r}")


def test_http_phase_c_blocklist(staging_dir: Path, proc=None):
    """#78 Phase C HTTP API for the unified blocklist.

    Four endpoints, one plugin (etc_blocklist.lua v0.02):
      - GET    /v1/blocklist          list with filter/sort/pagination
      - GET    /v1/blocklist/counts   {total, by_source}
      - POST   /v1/blocklist          create; body {cidr, source?,
                                      stealth?, reason?, expires_at?}
      - DELETE /v1/blocklist/{id}     remove

    Coverage:
    - Pre-flight: fresh staging has 0 entries + counts.total=0
    - Anonymous POST -> 401
    - POST cidr + reason (default source=manual) -> 201; id echoed;
      GET reflects the addition; counts.total=1, by_source.manual=1
    - POST source=external -> 201 (enum accepts non-manual); GET
      ?source=external returns exactly this one
    - POST bad cidr (host-bits-set) -> 400 with engine err msg
    - POST missing cidr -> 400 E_BAD_INPUT (schema reject)
    - DELETE existing id -> 200 + removed snapshot
    - DELETE 999 -> 404 E_NOT_FOUND
    - DELETE non-integer -> 400 E_BAD_INPUT
    - Persistence: scripts/data/etc_blocklist.tbl reflects the
      surviving entries after all mutations
    - HTTP tokens bypass ADC hierarchy - a level-100 entry can be
      removed by an admin token that has no operator level
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def post(path: bytes, body: bytes) -> str:
        return _http_roundtrip(
            b"POST " + path + b" HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
            b"\r\n" + body
        )

    def get(path: bytes, use_auth: bool = True) -> str:
        req = b"GET " + path + b" HTTP/1.1\r\n"
        if use_auth:
            req += auth
        req += b"\r\n"
        return _http_roundtrip(req)

    def delete_id(id_str: str) -> str:
        return _http_roundtrip(
            b"DELETE /v1/blocklist/" + id_str.encode("ascii") +
            b" HTTP/1.1\r\n" + auth + b"\r\n"
        )

    # 1. Fresh staging: empty entries + counts.
    r = get(b"/v1/blocklist")
    if "200 OK" not in status(r):
        raise TestFailure(f"pre-flight GET /v1/blocklist: expected 200, got {status(r)!r}")
    if '"entries":[]' not in body_of(r).replace(" ", ""):
        raise TestFailure(
            f"pre-flight expected empty entries, got {body_of(r)!r}"
        )

    r = get(b"/v1/blocklist/counts")
    if "200 OK" not in status(r):
        raise TestFailure(f"pre-flight GET counts: expected 200, got {status(r)!r}")
    pre_flight_body = body_of(r).replace(" ", "")
    if '"total":0' not in pre_flight_body:
        raise TestFailure(f"pre-flight counts.total should be 0, got {body_of(r)!r}")
    # Empty by_source must wire as JSON `{}`, not `[]`. dkjson's
    # default for a Lua table with no string keys is array; the
    # plugin forces `__jsontype = "object"` so callers with typed
    # decoders don't break on fresh installs.
    if '"by_source":{}' not in pre_flight_body:
        raise TestFailure(
            f"pre-flight counts.by_source should wire as JSON object "
            f"`{{}}` (not array `[]`) on empty store; body={body_of(r)!r}"
        )

    # 2. Anonymous POST -> 401
    anon_body = b'{"cidr":"10.0.0.0/8"}'
    r = _http_roundtrip(
        b"POST /v1/blocklist HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(anon_body)).encode("ascii") +
        b"\r\n\r\n" + anon_body
    )
    if "401" not in status(r):
        raise TestFailure(f"anon POST should be 401, got {status(r)!r}")

    # 3. POST manual entry.
    r = post(b"/v1/blocklist",
        b'{"cidr":"198.51.100.0/24","reason":"smoke phase c"}')
    if "201" not in status(r):
        raise TestFailure(f"POST manual: expected 201, got {status(r)!r}; body={body_of(r)!r}")
    b = body_of(r).replace(" ", "")
    if '"ok":true' not in b:
        raise TestFailure(f"POST envelope missing ok:true; body={b!r}")
    if '"action":"added"' not in b:
        raise TestFailure(f"POST action missing; body={b!r}")
    if '"cidr":"198.51.100.0/24"' not in b:
        raise TestFailure(f"POST cidr echo missing; body={b!r}")
    if '"source":"manual"' not in b:
        raise TestFailure(f"POST default source should be manual; body={b!r}")
    m1 = re.search(r'"id":(\d+)', b)
    if not m1:
        raise TestFailure(f"POST id missing; body={b!r}")
    manual_id = m1.group(1)

    # 4. GET reflects + counts=1
    r = get(b"/v1/blocklist")
    b = body_of(r).replace(" ", "")
    if '"198.51.100.0/24"' not in b:
        raise TestFailure(f"GET after add missing entry; body={b!r}")

    r = get(b"/v1/blocklist/counts")
    b = body_of(r).replace(" ", "")
    if '"total":1' not in b:
        raise TestFailure(f"counts after add: total=1 missing; body={b!r}")
    if '"manual":1' not in b:
        raise TestFailure(f"counts.by_source.manual=1 missing; body={b!r}")

    # 5. POST source=external.
    r = post(b"/v1/blocklist",
        b'{"cidr":"192.0.2.0/24","source":"external","reason":"feed test"}')
    if "201" not in status(r):
        raise TestFailure(f"POST external: expected 201, got {status(r)!r}; body={body_of(r)!r}")

    r = get(b"/v1/blocklist?source=external")
    b = body_of(r).replace(" ", "")
    if '"192.0.2.0/24"' not in b:
        raise TestFailure(f"filtered GET source=external missing entry; body={b!r}")

    # 6. POST bad cidr (host-bits-set).
    r = post(b"/v1/blocklist", b'{"cidr":"1.2.3.4/24"}')
    if "400" not in status(r):
        raise TestFailure(f"POST bad-cidr should be 400, got {status(r)!r}; body={body_of(r)!r}")

    # 7. POST missing cidr (router schema rejects, or handler catches).
    r = post(b"/v1/blocklist", b'{"reason":"nope"}')
    if "400" not in status(r):
        raise TestFailure(f"POST missing cidr should be 400, got {status(r)!r}; body={body_of(r)!r}")

    # 8. DELETE bad id.
    r = delete_id("abc")
    if "400" not in status(r):
        raise TestFailure(f"DELETE bad id should be 400, got {status(r)!r}")

    # 9. DELETE non-existent id.
    r = delete_id("999")
    if "404" not in status(r):
        raise TestFailure(f"DELETE 999 should be 404, got {status(r)!r}")

    # 10. DELETE manual entry.
    r = delete_id(manual_id)
    if "200" not in status(r):
        raise TestFailure(f"DELETE id={manual_id}: expected 200, got {status(r)!r}; body={body_of(r)!r}")
    b = body_of(r).replace(" ", "")
    if '"action":"removed"' not in b:
        raise TestFailure(f"DELETE action missing; body={b!r}")
    if '"cidr":"198.51.100.0/24"' not in b:
        raise TestFailure(f"DELETE removed.cidr missing; body={b!r}")

    # 11. DELETE same id again -> 404 (entry gone).
    r = delete_id(manual_id)
    if "404" not in status(r):
        raise TestFailure(f"DELETE second time should be 404, got {status(r)!r}")

    # 12. Persistence: the store file exists after the mutations.
    store = staging_dir / "scripts" / "data" / "etc_blocklist.tbl"
    if not store.exists():
        raise TestFailure(
            f"scripts/data/etc_blocklist.tbl not written by HTTP mutations "
            f"({store})"
        )

    # 13. Endpoints catalog contains our two paths (the catalog
    #     keys on path, not method+path - a single path with
    #     multiple methods appears once with method-array in the
    #     entry).
    r = get(b"/v1/endpoints")
    b = body_of(r)
    for wanted in (
        '"/v1/blocklist"',
        '"/v1/blocklist/counts"',
        '"/v1/blocklist/{id}"',
    ):
        if wanted not in b:
            raise TestFailure(
                f"/v1/endpoints missing {wanted}; body={b[:400]!r}"
            )


def test_http_plugins_api(staging_dir: Path, proc=None):
    """#261 plugin-management endpoints: GET /v1/plugins (read) +
    PUT /v1/plugins/{name}/enabled (admin).

    Full toggle cycle on the table-form `etc_motd.lua` entry plus
    negative coverage (string-form 403, missing 404, bad body 400).

    State-restore caveat: PUT calls cfg.set("scripts", ...) which
    serialises the ENTIRE cfg.tbl via util.savetable. The serialised
    form uses `[ "key" ] = value` for every entry, breaking the
    bare-key regex flips that downstream tests (BLOM/ZLIF/hub_listen)
    use. To stay friendly to those, this test snapshots the original
    cfg.tbl text at start and restores it via direct file write + a
    final POST /v1/reload before returning. The semantic state
    matches (etc_motd enabled=true in both forms) - we just keep the
    on-disk format readable for the regex-based flips that follow.

    Sequence:
      1. GET baseline: etc_motd listed, manageable=true, enabled=true,
         loaded=true. cmd_help listed, manageable=false (string-form).
      2. PUT etc_motd enabled=false: 200 + reload_required:true.
      3. GET: etc_motd enabled=false (live cfg.scripts), loaded=true
         (no reload yet - reflects #261 docs: enabled flips immediately,
         loaded only flips on POST /v1/reload).
      4. POST /v1/reload.
      5. GET: etc_motd enabled=false, loaded=false.
      6. PUT etc_motd enabled=true: 200.
      7. POST /v1/reload to restore.
      8. GET: etc_motd enabled=true, loaded=true.
      9. PUT cmd_help (string-form) enabled=false: 403 E_FORBIDDEN.
     10. PUT nonexistent_xyz enabled=false: 404 E_NOT_FOUND.
     11. PUT etc_motd with missing body field: 400 E_BAD_INPUT.
     12. PUT etc_motd with non-bool enabled: 400 E_BAD_INPUT.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    # Snapshot original cfg.tbl text so we can restore the
    # bare-key format after the test mutates it via cfg.set.
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    original_cfg_text = cfg_path.read_text(encoding="utf-8")

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get_plugins():
        r = _http_roundtrip(b"GET /v1/plugins HTTP/1.1\r\n" + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET /v1/plugins: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        b = body_of(r)
        try:
            j = json.loads(b)
        except Exception as e:
            raise TestFailure(f"GET /v1/plugins: bad JSON body={b!r}: {e}")
        if not j.get("ok"):
            raise TestFailure(f"GET /v1/plugins: envelope ok != true; body={b!r}")
        plugins = j.get("data", {}).get("plugins")
        if not isinstance(plugins, list):
            raise TestFailure(f"GET /v1/plugins: data.plugins missing/not array; body={b!r}")
        return {p["name"]: p for p in plugins}

    def put_enabled(name, enabled_value, raw_body=None):
        if raw_body is None:
            raw_body = json.dumps({"enabled": enabled_value})
        body_bytes = raw_body.encode("utf-8")
        req = (
            f"PUT /v1/plugins/{name}/enabled HTTP/1.1\r\n".encode("ascii") +
            auth +
            b"Content-Type: application/json\r\n" +
            f"Content-Length: {len(body_bytes)}\r\n".encode("ascii") +
            b"\r\n" +
            body_bytes
        )
        return _http_roundtrip(req)

    def post_reload():
        req = (
            b"POST /v1/reload HTTP/1.1\r\n" +
            auth +
            b"X-Confirm: yes\r\n" +
            b"Content-Length: 0\r\n" +
            b"\r\n"
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(f"POST /v1/reload: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        # give reload time to settle: it tears down + re-runs scripts
        time.sleep(0.5)

    # 1. baseline
    plugins = get_plugins()
    motd = plugins.get("etc_motd")
    if not motd:
        raise TestFailure(f"GET /v1/plugins: etc_motd not in listing. names={list(plugins.keys())[:15]}")
    if not motd.get("manageable"):
        raise TestFailure(f"baseline: etc_motd.manageable expected true, got {motd!r}")
    if not motd.get("enabled"):
        raise TestFailure(f"baseline: etc_motd.enabled expected true, got {motd!r}")
    if not motd.get("loaded"):
        raise TestFailure(f"baseline: etc_motd.loaded expected true, got {motd!r}")
    # #635: capture the version reported for the ENABLED plugin (a real version).
    motd_version = motd.get("version")
    if not motd_version or motd_version == "unknown":
        raise TestFailure(f"baseline: etc_motd.version should be a real version, got {motd_version!r}")
    cmd_help = plugins.get("cmd_help")
    if not cmd_help:
        raise TestFailure(f"baseline: cmd_help not in listing")
    if cmd_help.get("manageable"):
        raise TestFailure(f"baseline: cmd_help.manageable expected false (string-form), got {cmd_help!r}")

    # 2. PUT disable
    r = put_enabled("etc_motd", False)
    if "200 OK" not in status(r):
        raise TestFailure(f"PUT etc_motd enabled=false: expected 200, got {status(r)!r} / body={body_of(r)!r}")
    b = body_of(r)
    j = json.loads(b)
    if not j.get("ok"):
        raise TestFailure(f"PUT etc_motd: envelope ok != true; body={b!r}")
    if j["data"].get("reload_required") is not True:
        raise TestFailure(f"PUT etc_motd: reload_required != true; body={b!r}")

    # 3. GET after PUT, before reload: enabled flips, loaded does not
    plugins = get_plugins()
    motd = plugins["etc_motd"]
    if motd.get("enabled"):
        raise TestFailure(f"after PUT(false), pre-reload: enabled expected false, got {motd!r}")
    if not motd.get("loaded"):
        raise TestFailure(f"after PUT(false), pre-reload: loaded expected still true, got {motd!r}")

    # 4. reload
    post_reload()

    # 5. GET after reload: loaded flips
    plugins = get_plugins()
    motd = plugins["etc_motd"]
    if motd.get("enabled"):
        raise TestFailure(f"after reload: enabled expected false, got {motd!r}")
    if motd.get("loaded"):
        raise TestFailure(f"after reload: loaded expected false, got {motd!r}")
    # #635: a disabled plugin still reports its real version - the loader source-greps
    # the version even for an entry it does not load (pre-fix it hardcoded "unknown").
    if motd.get("version") != motd_version:
        raise TestFailure(f"after reload (disabled): version should stay {motd_version!r}, got {motd.get('version')!r}")

    # 6. PUT enable (restore path)
    r = put_enabled("etc_motd", True)
    if "200 OK" not in status(r):
        raise TestFailure(f"PUT etc_motd enabled=true (restore): expected 200, got {status(r)!r}")

    # 7. reload to apply restore
    post_reload()

    # 8. final state: fully restored
    plugins = get_plugins()
    motd = plugins["etc_motd"]
    if not motd.get("enabled"):
        raise TestFailure(f"after restore: enabled expected true, got {motd!r}")
    if not motd.get("loaded"):
        raise TestFailure(f"after restore: loaded expected true, got {motd!r}")

    # 9. negative: PUT on a string-form (operator-protected) entry -> 403
    r = put_enabled("cmd_help", False)
    if "403 Forbidden" not in status(r):
        raise TestFailure(f"PUT cmd_help (string-form): expected 403, got {status(r)!r}")
    b = body_of(r)
    if "E_FORBIDDEN" not in b:
        raise TestFailure(f"PUT cmd_help: missing E_FORBIDDEN code; body={b!r}")

    # 10. negative: PUT on a nonexistent plugin -> 404
    r = put_enabled("nonexistent_xyz", False)
    if "404 Not Found" not in status(r):
        raise TestFailure(f"PUT nonexistent: expected 404, got {status(r)!r}")
    b = body_of(r)
    if "E_NOT_FOUND" not in b:
        raise TestFailure(f"PUT nonexistent: missing E_NOT_FOUND code; body={b!r}")

    # 11. negative: PUT with empty body (missing enabled field) -> 400
    r = put_enabled("etc_motd", None, raw_body="{}")
    if "400 Bad Request" not in status(r):
        raise TestFailure(f"PUT etc_motd missing body: expected 400, got {status(r)!r}")
    b = body_of(r)
    if "E_BAD_INPUT" not in b:
        raise TestFailure(f"PUT etc_motd missing body: missing E_BAD_INPUT; body={b!r}")

    # 12. negative: PUT with non-boolean enabled -> 400
    r = put_enabled("etc_motd", None, raw_body='{"enabled":"yes"}')
    if "400 Bad Request" not in status(r):
        raise TestFailure(f"PUT etc_motd non-bool: expected 400, got {status(r)!r}")

    # 13. Restore the original cfg.tbl bare-key format so downstream
    # regex-based cfg flips (BLOM/ZLIF/hub_listen) keep working.
    # util.savetable serialises with `[ "key" ] = value` for every
    # entry which would not match `^blom_enabled\s*=\s*false` etc.
    # The in-memory _settings is already at the post-restore state
    # (etc_motd enabled=true), so loading the original text back is
    # functionally equivalent.
    cfg_path.write_text(original_cfg_text, encoding="utf-8")
    post_reload()    # re-read cfg.tbl so in-memory matches the disk format


def test_http_filter_sort_pr_a(staging_dir: Path, proc=None):
    """#264 PR-A: filter + sort query params on list endpoints.

    Covers /v1/users and /v1/registered (the two highest-cardinality
    endpoints + all four field types: string substring, integer
    exact/min/max, date after/before, boolean). Negative paths assert
    400 E_BAD_INPUT with the allowed-fields hint for unknown filter
    or sort params.

    Runs AFTER test_http_registered_users_pr1 (which seeds
    smoke_pr1_a + smoke_pr1_b at level 20, with smoke_pr1_a's
    comment patched to "smoke") so the filter targets are present.
    Default cfg.tbl pre-registers `dummy` at level 10.

    /v1/users coverage requires a live ADC connection - this test
    logs in `dummy` briefly, runs the filter queries, and exits.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get_json(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET {path}: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        return json.loads(body_of(r))

    def expect_400(path, expected_codeword=None):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "400 Bad Request" not in status(r):
            raise TestFailure(f"GET {path}: expected 400, got {status(r)!r}")
        b = body_of(r)
        if "E_BAD_INPUT" not in b:
            raise TestFailure(f"GET {path}: missing E_BAD_INPUT; body={b!r}")
        if expected_codeword and expected_codeword not in b:
            raise TestFailure(f"GET {path}: expected hint '{expected_codeword}' in body={b!r}")

    def post_reg(nick, level, password):
        body_bytes = json.dumps({"nick": nick, "level": level, "password": password}).encode("utf-8")
        req = (
            b"POST /v1/registered HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n" +
            f"Content-Length: {len(body_bytes)}\r\n".encode("ascii") +
            b"\r\n" + body_bytes
        )
        r = _http_roundtrip(req)
        if "200 OK" not in status(r):
            raise TestFailure(f"POST /v1/registered nick={nick}: expected 200, got {status(r)!r} / body={body_of(r)!r}")

    # /v1/registered tests (no ADC connection needed)
    # ---------------------------------------------------------------
    # Seed three test users with predictable nicks/levels so filters
    # have deterministic targets independent of which other tests
    # have run before us.
    post_reg("filter_alice", 30, "pw_alice_xyz")
    post_reg("filter_bob",   40, "pw_bob_xyz")
    post_reg("filter_carol", 30, "pw_carol_xyz")

    # 1. baseline: all three test users present
    j = get_json("/v1/registered?limit=200")
    nicks = {e["nick"] for e in j["data"]["registered"]}
    for required in ("filter_alice", "filter_bob", "filter_carol"):
        if required not in nicks:
            raise TestFailure(f"/v1/registered baseline missing {required}; got {sorted(nicks)!r}")

    # 2. nick substring filter
    j = get_json("/v1/registered?nick=filter_")
    nicks = {e["nick"] for e in j["data"]["registered"]}
    expected = {"filter_alice", "filter_bob", "filter_carol"}
    if not expected.issubset(nicks):
        raise TestFailure(f"nick=filter_ filter: missing some; got {sorted(nicks)!r}")
    for unwanted in ("dummy",):
        if unwanted in nicks:
            raise TestFailure(f"nick=filter_ filter: leaked {unwanted}; got {sorted(nicks)!r}")

    # 3. integer exact match: level=30
    j = get_json("/v1/registered?nick=filter_&level=30")
    nicks = {e["nick"] for e in j["data"]["registered"]}
    expected = {"filter_alice", "filter_carol"}
    if nicks != expected:
        raise TestFailure(f"nick=filter_&level=30: expected {expected!r}, got {sorted(nicks)!r}")

    # 4. integer range: level_min=40
    j = get_json("/v1/registered?nick=filter_&level_min=40")
    nicks = {e["nick"] for e in j["data"]["registered"]}
    if nicks != {"filter_bob"}:
        raise TestFailure(f"nick=filter_&level_min=40: expected bob only, got {sorted(nicks)!r}")

    # 5. integer range: level_max=30
    j = get_json("/v1/registered?nick=filter_&level_max=30")
    nicks = {e["nick"] for e in j["data"]["registered"]}
    if nicks != {"filter_alice", "filter_carol"}:
        raise TestFailure(f"nick=filter_&level_max=30: expected alice+carol, got {sorted(nicks)!r}")

    # 6. sort ascending (default = nick ASC) on the seeded subset
    j = get_json("/v1/registered?nick=filter_")
    ordered = [e["nick"] for e in j["data"]["registered"]]
    if ordered != ["filter_alice", "filter_bob", "filter_carol"]:
        raise TestFailure(f"default sort: expected alice/bob/carol, got {ordered!r}")

    # 7. sort descending (?sort=-nick)
    j = get_json("/v1/registered?nick=filter_&sort=-nick")
    ordered = [e["nick"] for e in j["data"]["registered"]]
    if ordered != ["filter_carol", "filter_bob", "filter_alice"]:
        raise TestFailure(f"sort=-nick: expected carol/bob/alice, got {ordered!r}")

    # 8. sort by level
    j = get_json("/v1/registered?nick=filter_&sort=level")
    levels = [e["level"] for e in j["data"]["registered"]]
    if levels != sorted(levels):
        raise TestFailure(f"sort=level: not ascending; got {levels!r}")

    # 9. pagination.total reflects FILTERED count, not unfiltered total
    j = get_json("/v1/registered?nick=filter_")
    if j["pagination"]["total"] != 3:
        raise TestFailure(f"pagination.total with nick=filter_: expected 3, got {j['pagination']!r}")

    # 10. negative: unknown filter field -> 400 with hint
    expect_400("/v1/registered?bogus_field=x", expected_codeword="allowed filters")

    # 11. negative: unknown sort field -> 400 with hint
    expect_400("/v1/registered?sort=bogus_field", expected_codeword="allowed")

    # 12. negative: invalid integer
    expect_400("/v1/registered?level=notanumber", expected_codeword="must be a number")

    # /v1/users tests (require a live ADC connection)
    # ---------------------------------------------------------------

    with _logged_in_user(nick="dummy", password="test") as (sock, sid, reader):
        # The hub prepends a level-prefix to the displayed nick (usr_nick_prefix
        # plugin), so dummy at level 100 (HUBOWNER) shows as "[HUBOWNER]dummy".
        # The filter is substring-based, so "dummy" still matches.
        def has_dummy(nicks):
            return any("dummy" in n for n in nicks)

        # 11. baseline: dummy is online (substring match accounts for the prefix)
        j = get_json("/v1/users?limit=100")
        nicks = {u["nick"] for u in j["data"]["users"]}
        if not has_dummy(nicks):
            raise TestFailure(f"/v1/users baseline missing dummy substring; got {nicks!r}")

        # 12. nick substring filter
        j = get_json("/v1/users?nick=dummy")
        nicks = [u["nick"] for u in j["data"]["users"]]
        if not has_dummy(nicks):
            raise TestFailure(f"nick=dummy filter: missing dummy substring; got {nicks!r}")
        if j["pagination"]["total"] < 1:
            raise TestFailure(f"nick=dummy filter: pagination.total < 1: {j['pagination']!r}")

        # 13. sort by nick ascending (?sort=nick)
        j = get_json("/v1/users?sort=nick")
        nicks_ord = [u["nick"] for u in j["data"]["users"]]
        if nicks_ord != sorted(nicks_ord):
            raise TestFailure(f"sort=nick: not ascending; got {nicks_ord!r}")

        # 14. negative: unknown filter field
        expect_400("/v1/users?made_up=x", expected_codeword="allowed filters")

        # 15. negative: unknown sort field
        expect_400("/v1/users?sort=made_up", expected_codeword="allowed")


def test_http_events_pr_b_longpoll(staging_dir: Path, proc=None):
    """#263 PR-B: long-poll via ?wait=<seconds>.

    Covers:
      1. wait + no matching events -> server holds the request until
         deadline; returns empty events array with cursor unchanged.
      2. wait + event arrives mid-poll -> server resolves the
         request immediately on the matching emit (event-driven
         resume via the tap chain), well before the deadline.

    Threading: long-poll is a normal HTTP GET, but the test triggers
    the event from a parallel thread so the polling socket is held
    open while the trigger thread does its work. A single-threaded
    test would serialise the two operations and miss the resume.
    """
    import threading

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    # Capture the current cursor so the long-poll's `since=` starts
    # past any backlog from earlier tests.
    r = _http_roundtrip(b"GET /v1/events?since=latest HTTP/1.1\r\n" + auth + b"\r\n")
    if "200 OK" not in status(r):
        raise TestFailure(f"baseline cursor: expected 200, got {status(r)!r}")
    baseline_cursor = json.loads(body_of(r))["data"]["cursor"]

    # ----- Test 1: deadline-driven empty resolve -----
    # Long-poll for a type that nothing in this test fires.
    t0 = time.monotonic()
    r = _http_roundtrip(
        f"GET /v1/events?since={baseline_cursor}&types=topic_changed&wait=2 HTTP/1.1\r\n".encode("ascii")
        + auth + b"\r\n",
    )
    elapsed = time.monotonic() - t0
    if "200 OK" not in status(r):
        raise TestFailure(f"deadline poll: expected 200, got {status(r)!r}")
    j = json.loads(body_of(r))
    if j["data"]["events"]:
        raise TestFailure(f"deadline poll: expected empty events, got {j['data']['events']!r}")
    if elapsed < 1.5:
        raise TestFailure(f"deadline poll: returned too fast ({elapsed:.2f}s); expected ~2s wait")
    if elapsed > 5.0:
        raise TestFailure(f"deadline poll: returned too slow ({elapsed:.2f}s); expected ~2s wait")

    # ----- Test 2: event-driven resume -----
    # Capture cursor again so the long-poll only sees the upcoming login.
    r = _http_roundtrip(b"GET /v1/events?since=latest HTTP/1.1\r\n" + auth + b"\r\n")
    cursor = json.loads(body_of(r))["data"]["cursor"]

    # Start the long-poll in a background thread; the test thread
    # triggers a login after a short delay so the long-poll has time
    # to register as a waiter first.
    longpoll_result = {}

    def do_longpoll():
        t = time.monotonic()
        resp = _http_roundtrip(
            f"GET /v1/events?since={cursor}&types=login&wait=10 HTTP/1.1\r\n".encode("ascii")
            + auth + b"\r\n",
        )
        longpoll_result["elapsed"] = time.monotonic() - t
        longpoll_result["resp"] = resp

    thread = threading.Thread(target=do_longpoll, daemon=True)
    thread.start()
    time.sleep(0.5)    # ensure the long-poll request has reached the server

    # Trigger the event - a fresh dummy login fires onLogin via the
    # firelistener chain; http_events.emit then resolves matching waiters.
    with _logged_in_user(nick="dummy", password="test") as (sock, sid, reader):
        pass    # login is enough; logout happens on context exit

    thread.join(timeout=5.0)
    if thread.is_alive():
        raise TestFailure("event-driven poll: thread still running after 5s; resume never fired")

    resp = longpoll_result.get("resp")
    if not resp:
        raise TestFailure("event-driven poll: no response captured")
    if "200 OK" not in status(resp):
        raise TestFailure(f"event-driven poll: expected 200, got {status(resp)!r}")
    j = json.loads(body_of(resp))
    if not any(ev.get("type") == "login" for ev in j["data"]["events"]):
        raise TestFailure(f"event-driven poll: no login event in resp; got {j!r}")
    # Resume should be near-instant after the login fires (sub-tick latency).
    elapsed = longpoll_result.get("elapsed", 99)
    if elapsed > 4.0:
        raise TestFailure(f"event-driven poll: resume took {elapsed:.2f}s; expected sub-second after the trigger")


def test_http_events_pr_a(staging_dir: Path, proc=None):
    """#263 PR-A: GET /v1/events polling endpoint (immediate-return).

    Covers:
      1.  Baseline: GET ?since=0 returns an envelope with
          `events` array + `cursor`.
      2.  Trigger an event: a fresh `dummy` login fires onLogin
          via the script-firelistener chain; http_events' tap
          appends a `login` event. A follow-up GET returns it.
      3.  Cursor advance: a second GET ?since=<cursor> from above
          returns no NEW events.
      4.  ?types=login filter only returns login events; ?types=
          unknown_type returns empty.
      5.  ?since=latest returns empty events + the current cursor
          (no replay).

    The PR-B long-polling (wait param + coroutine yield) is NOT
    exercised here. Buffer-overflow / cursor_lost coverage is
    deferred to PR-B - the cursor_lost branch needs many events
    to evict, which is heavy in smoke; the eviction logic is
    covered by inspection of `emit` in `core/http_events.lua`.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get_json(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET {path}: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        return json.loads(body_of(r))

    # 1. baseline shape
    j = get_json("/v1/events?since=0")
    d = j.get("data", {})
    if not isinstance(d.get("events"), list):
        raise TestFailure(f"baseline: data.events missing or not array; body={j!r}")
    if not isinstance(d.get("cursor"), int):
        raise TestFailure(f"baseline: data.cursor missing or not integer; body={j!r}")
    baseline_cursor = d["cursor"]

    # 2. trigger a login event then re-poll
    with _logged_in_user(nick="dummy", password="test") as (sock, sid, reader):
        time.sleep(0.2)    # give the firelistener tap a tick to commit
        j = get_json(f"/v1/events?since={baseline_cursor}")
        events = j["data"]["events"]
        found_login = any(
            ev.get("type") == "login" and "dummy" in (ev.get("nick") or "")
            for ev in events
        )
        if not found_login:
            raise TestFailure(
                f"login event for 'dummy' not found in events list "
                f"(since={baseline_cursor}, got {events!r})"
            )
        cursor_after_login = j["data"]["cursor"]

        # 3. cursor advance: login event NOT replayed
        j = get_json(f"/v1/events?since={cursor_after_login}")
        replayed = [
            ev for ev in j["data"]["events"]
            if ev.get("type") == "login"
            and "dummy" in (ev.get("nick") or "")
        ]
        if replayed:
            raise TestFailure(
                f"cursor advance: login event replayed; got {replayed!r}"
            )

        # 4. types= filter
        j = get_json(f"/v1/events?since=0&types=login")
        for ev in j["data"]["events"]:
            if ev.get("type") != "login":
                raise TestFailure(
                    f"types=login filter leaked type={ev.get('type')!r}"
                )

        j = get_json("/v1/events?since=0&types=unknown_type_xyz")
        if len(j["data"]["events"]) != 0:
            raise TestFailure(
                f"types=unknown: expected empty events, got {j['data']['events']!r}"
            )

    # 5. since=latest no-replay
    j = get_json("/v1/events?since=latest")
    if len(j["data"]["events"]) != 0:
        raise TestFailure(
            f"since=latest: expected empty events, got {j['data']['events']!r}"
        )
    if not isinstance(j["data"]["cursor"], int):
        raise TestFailure(f"since=latest: cursor missing")


def test_http_config_api(staging_dir: Path, proc=None):
    """#262 config-management endpoints: GET /v1/config (read) and
    PUT /v1/config/{key} (admin).

    Coverage:
      1.  GET baseline - envelope, denylist masking on http_api_tokens
          and master_key_path.
      2.  PUT live key (max_users) -> 200 + apply_status=live.
      3.  PUT reload-required key (language) -> 200 + apply_status=reload_required.
      4.  PUT restart-required key (http_port - same value to avoid disturbance)
          -> 200 + apply_status=restart_required.
      5.  PUT denylisted key (http_api_tokens) -> 403 E_FORBIDDEN.
      6.  PUT unknown key -> 404 E_NOT_FOUND.
      7.  PUT missing body field -> 400 E_BAD_INPUT.
      8.  PUT validator-rejected value (max_users = "notanumber")
          -> 400 E_BAD_INPUT with validator hint.
      9.  PUT a level-keyed map (cmd_ban_permission) - JSON string keys
          are coerced to integer keys so the level-map validator accepts
          it and it round-trips; a mixed-key map is NOT coerced (400).
      2b. #644 surgical save: a successful PUT preserves the operator's
          bare-key format + inline comments in cfg.tbl instead of the
          wholesale quoted-key comment-stripped rewrite.

    Restores the pristine cfg.tbl at the end (byte-for-byte) so downstream
    regex-based cfg flips (BLOM / ZLIF / hub_listen) keep working. Since the
    surgical save (#644) now preserves the bare-key format, that restore is
    belt-and-suspenders rather than load-bearing.
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    original_cfg_text = cfg_path.read_text(encoding="utf-8")

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get_json(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET {path}: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        return json.loads(body_of(r))

    def put_value(key, raw_body):
        body_bytes = raw_body.encode("utf-8")
        req = (
            f"PUT /v1/config/{key} HTTP/1.1\r\n".encode("ascii") +
            auth +
            b"Content-Type: application/json\r\n" +
            f"Content-Length: {len(body_bytes)}\r\n".encode("ascii") +
            b"\r\n" + body_bytes
        )
        return _http_roundtrip(req)

    try:
        # 1. baseline GET + masking
        j = get_json("/v1/config")
        cfg = j.get("data", {}).get("config")
        if not isinstance(cfg, dict):
            raise TestFailure(f"GET /v1/config: data.config missing or not dict; body={body_of(_http_roundtrip(b'GET /v1/config HTTP/1.1\\r\\n' + auth + b'\\r\\n'))!r}")
        if cfg.get("http_api_tokens") != "<redacted>":
            raise TestFailure(f"GET: http_api_tokens not masked; got {cfg.get('http_api_tokens')!r}")
        if cfg.get("master_key_path") != "<redacted>":
            raise TestFailure(f"GET: master_key_path not masked; got {cfg.get('master_key_path')!r}")
        if not cfg.get("hub_name"):
            raise TestFailure(f"GET: hub_name missing or empty; got {cfg.get('hub_name')!r}")

        # 2. PUT live key
        r = put_value("max_users", '{"value": 3000}')
        if "200 OK" not in status(r):
            raise TestFailure(f"PUT live: expected 200, got {status(r)!r} / body={body_of(r)!r}")
        j = json.loads(body_of(r))
        if j["data"].get("apply_status") != "live":
            raise TestFailure(f"PUT live: apply_status != 'live'; got {j['data']!r}")
        if j["data"].get("key") != "max_users":
            raise TestFailure(f"PUT live: key echo wrong; got {j['data']!r}")

        # 2b. #644 surgical save: the PUT must rewrite ONLY the changed value
        #     in place, preserving the operator's bare-key format and inline
        #     comments - NOT wholesale-rewrite to the canonical quoted-key,
        #     comment-stripped form. Proven RED before core/cfg_write.lua was
        #     wired into cfg.set (the wholesale save emits `[ "max_users" ] =
        #     3000` and drops every comment).
        cfg_after = cfg_path.read_text(encoding="utf-8")
        if "max_users = 3000" not in cfg_after:
            raise TestFailure(
                "surgical save: 'max_users = 3000' not written bare to cfg.tbl "
                f"(wholesale rewrite?); head={cfg_after[:160]!r}")
        if "-- max users (integer)" not in cfg_after:
            raise TestFailure(
                "surgical save: the 'max users (integer)' inline comment was "
                "stripped (comment-preserving save not active)")
        if '[ "max_users" ]' in cfg_after or '["max_users"]' in cfg_after:
            raise TestFailure(
                "surgical save: cfg.tbl was wholesale-rewritten to the "
                "canonical quoted-key form")

        # 3. PUT reload-required key
        r = put_value("language", '{"value": "en"}')
        if "200 OK" not in status(r):
            raise TestFailure(f"PUT reload: expected 200, got {status(r)!r}")
        j = json.loads(body_of(r))
        if j["data"].get("apply_status") != "reload_required":
            raise TestFailure(f"PUT reload: apply_status != 'reload_required'; got {j['data']!r}")

        # 4. PUT restart-required key - use the EXISTING test port to avoid disturbance
        r = put_value("http_port", f'{{"value": {TEST_PORT_HTTP}}}')
        if "200 OK" not in status(r):
            raise TestFailure(f"PUT restart: expected 200, got {status(r)!r}")
        j = json.loads(body_of(r))
        if j["data"].get("apply_status") != "restart_required":
            raise TestFailure(f"PUT restart: apply_status != 'restart_required'; got {j['data']!r}")

        # 5. PUT denylist -> 403
        r = put_value("http_api_tokens", '{"value": "newtoken"}')
        if "403 Forbidden" not in status(r):
            raise TestFailure(f"PUT denylist: expected 403, got {status(r)!r}")
        if "E_FORBIDDEN" not in body_of(r):
            raise TestFailure(f"PUT denylist: missing E_FORBIDDEN; body={body_of(r)!r}")

        # 6. PUT unknown key -> 404
        r = put_value("bogus_unknown_key_xyz", '{"value": 1}')
        if "404 Not Found" not in status(r):
            raise TestFailure(f"PUT unknown: expected 404, got {status(r)!r}")
        if "E_NOT_FOUND" not in body_of(r):
            raise TestFailure(f"PUT unknown: missing E_NOT_FOUND; body={body_of(r)!r}")

        # 7. PUT missing body field -> 400
        r = put_value("max_users", '{}')
        if "400 Bad Request" not in status(r):
            raise TestFailure(f"PUT empty body: expected 400, got {status(r)!r}")
        if "E_BAD_INPUT" not in body_of(r):
            raise TestFailure(f"PUT empty body: missing E_BAD_INPUT; body={body_of(r)!r}")

        # 8. PUT validator-rejected -> 400
        r = put_value("max_users", '{"value": "notanumber"}')
        if "400 Bad Request" not in status(r):
            raise TestFailure(f"PUT invalid: expected 400, got {status(r)!r}")
        if "validator rejected" not in body_of(r):
            raise TestFailure(f"PUT invalid: missing 'validator rejected' hint; body={body_of(r)!r}")

        # 9. PUT a level-keyed permission map. A JSON object always carries
        #    STRING keys ({"0":0,...}), but the cfg validator requires INTEGER
        #    keys (types_number(k) == type(k)=="number"); pre-fix the PUT 400s
        #    ("validator rejected") and level-maps were read-only over the API.
        #    config_put_handler now retries once with the keys coerced to
        #    integers. The DEFAULT values are re-sent (no semantic change): a
        #    200 proves the integer-key validator accepted the coerced map (it
        #    rejects string keys), and the readback confirms the round-trip.
        r = put_value(
            "cmd_ban_permission",
            '{"value": {"0":0,"10":0,"20":0,"30":0,"40":0,"50":0,'
            '"55":0,"60":50,"70":60,"80":70,"100":100}}',
        )
        if "200 OK" not in status(r):
            raise TestFailure(f"PUT level-map: expected 200 (int-key coercion), got {status(r)!r} / body={body_of(r)!r}")
        j = json.loads(body_of(r))
        if j["data"].get("apply_status") not in ("live", "reload_required", "restart_required"):
            raise TestFailure(f"PUT level-map: missing apply_status; got {j['data']!r}")
        got = get_json("/v1/config")["data"]["config"].get("cmd_ban_permission")
        if not isinstance(got, dict) or str(got.get("60")) != "50" or str(got.get("100")) != "100":
            raise TestFailure(f"PUT level-map: readback wrong; cmd_ban_permission={got!r}")

        # 9b. A table with any non-integer key is NOT a level-map: coercion
        #     bails and the original 400 stands - never silently rewrite a
        #     legitimately string-keyed map.
        r = put_value("cmd_ban_permission", '{"value": {"0":0,"nope":1}}')
        if "400 Bad Request" not in status(r):
            raise TestFailure(f"PUT mixed-key map: expected 400, got {status(r)!r} / body={body_of(r)!r}")
    finally:
        # Restore cfg.tbl to bare-key format so downstream
        # BLOM/ZLIF/hub_listen regex flips keep working.
        cfg_path.write_text(original_cfg_text, encoding="utf-8")


def test_http_filter_sort_pr_b(staging_dir: Path, proc=None):
    """#264 PR-B: wire-up regression for the 5 list endpoints
    migrated to `core/http_filter.lua` in this PR.

    PR-A already exercises the helper exhaustively against /v1/users
    and /v1/registered (substring + integer range + sort + 4
    negative paths). PR-B just verifies that each new endpoint is
    correctly wired by sending one unknown-filter-field query and
    asserting 400 E_BAD_INPUT with the allowed-fields hint - a
    handler that ignored unknown params (= pre-fix behaviour) would
    return 200 with the full list, so this is a tight
    pre-fix-fails / post-fix-passes signal per §1a.7.

    Covered endpoints:
      /v1/bans
      /v1/blacklist
      /v1/msgmanager
      /v1/trafficmanager/blocks
      /v1/usercleaner/expired
      /v1/usercleaner/ghosts
    """
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def expect_400(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "400 Bad Request" not in status(r):
            raise TestFailure(f"GET {path}: expected 400, got {status(r)!r} / body={body_of(r)!r}")
        b = body_of(r)
        if "E_BAD_INPUT" not in b:
            raise TestFailure(f"GET {path}: missing E_BAD_INPUT; body={b!r}")
        if "allowed filters" not in b:
            raise TestFailure(f"GET {path}: missing 'allowed filters' hint; body={b!r}")

    def expect_200_with_pagination(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET {path}: expected 200, got {status(r)!r}")
        j = json.loads(body_of(r))
        if not j.get("ok"):
            raise TestFailure(f"GET {path}: envelope ok != true; body={body_of(r)!r}")
        if not isinstance(j.get("pagination"), dict):
            raise TestFailure(f"GET {path}: pagination sibling missing; body={body_of(r)!r}")
        for k in ("total", "limit", "offset"):
            if k not in j["pagination"]:
                raise TestFailure(f"GET {path}: pagination.{k} missing; body={body_of(r)!r}")
        return j

    endpoints = [
        "/v1/bans",
        "/v1/blacklist",
        "/v1/msgmanager",
        "/v1/trafficmanager/blocks",
        "/v1/usercleaner/expired",
        "/v1/usercleaner/ghosts",
    ]
    for ep in endpoints:
        expect_200_with_pagination(ep)
        expect_400(ep + "?bogus_field_xyz=42")


class _RegserverCapture:
    """A tiny one-shot HTTP server (raw socket, own thread) that
    captures the FIRST POST body it receives and answers 202. Used to
    prove core/http_client + etc_regserver_announce actually deliver a
    non-blocking outbound POST end-to-end."""

    def __init__(self, port):
        self.port = port
        self.body = None
        self.path = None
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", port))
        self._srv.listen(1)
        self._srv.settimeout(30)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except Exception:
            return
        try:
            conn.settimeout(10)
            data = b""
            # read headers
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            self.path = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            clen = 0
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    clen = int(line.split(b":", 1)[1].strip())
            body = rest
            while len(body) < clen:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            self.body = body.decode("latin-1", "replace")
            conn.sendall(
                b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nok"
            )
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def wait(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline and self.body is None:
            time.sleep(0.25)
        return self.body

    def close(self):
        try:
            self._srv.close()
        except Exception:
            pass


def _switch_to_regserver_announce_mode(staging_dir, current_proc, current_log_file, port):
    """Enable etc_regserver_announce pointing at a loopback fake
    regserver, give the hub a real-looking hub_hostaddress so the HH
    derives, and restart. Returns (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")

    # real-looking hostaddress (the placeholder is rejected by derive_hh)
    text, n1 = re.subn(
        r'hub_hostaddress\s*=\s*"[^"]*"',
        'hub_hostaddress = "testhub.example.org"',
        text, count=1,
    )
    # Flip activate true. The example cfg.tbl now ships a settings
    # block with these keys; if it (or a future trimmed cfg) lacks
    # them they fall back to cfg_defaults, so inject after `return {`.
    text, n2 = re.subn(
        r"etc_regserver_announce_activate\s*=\s*false\s*,",
        "etc_regserver_announce_activate = true,",
        text, count=1,
    )
    if n2 == 0:
        inject = (
            '    etc_regserver_announce_activate = true,\n'
            f'    etc_regserver_announce_url = {{ "http://127.0.0.1:{port}/register" }},\n'
            '    etc_regserver_announce_retry_interval = 5,\n'
        )
        text, ni = re.subn(r"(return \{[^\n]*\n)", r"\1" + inject, text, count=1)
        if ni != 1:
            raise TestFailure("could not inject regserver keys after 'return {'")
    else:
        # keys present (the settings block) - REPLACE the url line with
        # the test loopback target (ARRAY form, to exercise the
        # multi-regserver path), and shorten the retry interval.
        text, nu = re.subn(
            r"etc_regserver_announce_url\s*=\s*[^\n]*",
            f'etc_regserver_announce_url = {{ "http://127.0.0.1:{port}/register" }},',
            text, count=1,
        )
        if nu != 1:
            raise TestFailure("could not replace etc_regserver_announce_url for the test")
        text, _ = re.subn(
            r"etc_regserver_announce_retry_interval\s*=\s*\d+[^\n]*",
            "etc_regserver_announce_retry_interval = 5,",
            text, count=1,
        )
    if n1 != 1:
        raise TestFailure("could not set hub_hostaddress for regserver test")
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, 5.0)
    return proc, log_file


def test_regserver_announce(staging_dir, capture, proc=None):
    """End-to-end: etc_regserver_announce -> core/http_client (non-
    blocking) -> loopback fake regserver. Asserts the hub POSTed an
    ADC IINF with the expected public fields, AND that the hub stayed
    responsive throughout (proving the outbound request did not block
    the single-threaded event loop)."""
    body = capture.wait(timeout=20)
    if body is None:
        raise TestFailure(
            "regserver announce: no POST received within 20s "
            "(plugin did not announce / http_client did not deliver)"
        )
    if not capture.path or "POST /register" not in capture.path:
        raise TestFailure(f"regserver announce: unexpected request line {capture.path!r}")
    # IINF body with the required + some optional public fields
    if not body.startswith("IINF "):
        raise TestFailure(f"regserver announce: body is not an IINF line: {body!r}")
    for token in ("NI", "HH", "AP", "VE"):
        if token not in body:
            raise TestFailure(f"regserver announce: IINF missing {token}; body={body!r}")
    if "HHadcs://testhub.example.org" not in body and "HHadc://testhub.example.org" not in body:
        raise TestFailure(f"regserver announce: HH not derived correctly; body={body!r}")
    if "APLuadch-NG" not in body:
        raise TestFailure(f"regserver announce: AP not Luadch-NG; body={body!r}")

    # Non-blocking proof: the hub must answer a normal ADC handshake
    # immediately (if the outbound POST had blocked the loop, the
    # announce + this check would interleave; but more importantly the
    # whole battery ran while the announce was in flight).
    with socket.create_connection((HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC) as s:
        s.sendall(b"HSUP ADBASE ADTIGR\n")
        reader = _ADCReader(s)
        reader.recv_until(lambda f: f.startswith("ISUP "))


def test_http_security_holistic_review(staging_dir: Path, proc=None):
    """#275 holistic review follow-up - Security PR regression tests.

    Each assertion fails on the unpatched code:
      1. SEC-1: PUT /v1/registered/{nick}/password body redacted in
         api_audit.log (route declares audit_redact_body=true).
         The literal password never lands on disk.
      2. SEC-1: POST /v1/registered with optional password field
         same coverage.
      3. SEC-3: unauth (401) POST body lands as `body=[skipped]`
         in api_audit.log; pre-fix the attacker-chosen sentinel
         was stored verbatim.
      4. SEC-2: POST /v1/bans with control bytes in `target`
         field gets sanitised before addban / disk / ops broadcast.
      5. SEC-5: idempotency cache is method+path scoped. A shared
         `X-Idempotency-Key` across POST /v1/announce and
         DELETE /v1/users/AAAA no longer replays the announce
         response for the DELETE.
      6. SEC-6: PUT /v1/config/http_api_burst returns
         apply_status=reload_required (ratelimit caches the value
         at init); was misclassified as `live` pre-fix.

    Runs after test_http_filter_sort_pr_b and before the cfg-drift
    mode-switch tests. Restores cfg.tbl bare-key format at the end.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    original_cfg_text = cfg_path.read_text(encoding="utf-8")

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def http_req(method: bytes, path: bytes, body: bytes = b"",
                 with_auth: bool = True, extra_headers: bytes = b""):
        h = auth if with_auth else b""
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + h + extra_headers +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + h + extra_headers + b"\r\n"
        )

    def tail_audit(lines: int = 200):
        r = http_req(b"GET", f"/v1/log/api?lines={lines}".encode("ascii"))
        if "200 OK" not in status(r):
            raise TestFailure(f"GET /v1/log/api: {status(r)!r}")
        return (_json.loads(body_of(r))).get("data", {}).get("lines") or []

    try:
        # ---- 1 + 2. SEC-1 audit_redact_body ----
        sentinel_pw_post = "S3CR3T_POSTreguser_42xQ"
        body = _json.dumps({
            "nick": "smoke_sec1_postuser",
            "level": 10,
            "password": sentinel_pw_post,
        }).encode("utf-8")
        r = http_req(b"POST", b"/v1/registered", body)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"SEC-1 POST /v1/registered: expected 200, got {status(r)!r}; "
                f"body={body_of(r)!r}"
            )

        sentinel_pw_put = "S3CR3T_PUTpassword_42xQ"
        body = _json.dumps({"password": sentinel_pw_put}).encode("utf-8")
        r = http_req(b"PUT", b"/v1/registered/smoke_sec1_postuser/password", body)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"SEC-1 PUT password: expected 200, got {status(r)!r}; "
                f"body={body_of(r)!r}"
            )

        # ---- 3. SEC-3 unauth body skip ----
        sentinel_unauth = "S3CR3T_UNAUTH_42xQ"
        body = _json.dumps({"injected": sentinel_unauth}).encode("utf-8")
        r = http_req(b"POST", b"/v1/registered", body, with_auth=False)
        if "401" not in status(r):
            raise TestFailure(
                f"SEC-3 unauth POST: expected 401, got {status(r)!r}"
            )

        lines = tail_audit(200)
        joined = "\n".join(lines)
        if sentinel_pw_post in joined:
            raise TestFailure(
                f"SEC-1: POST /v1/registered password leaked into api_audit.log; "
                f"sentinel={sentinel_pw_post!r}\nLines:\n{joined}"
            )
        if sentinel_pw_put in joined:
            raise TestFailure(
                f"SEC-1: PUT password leaked into api_audit.log; "
                f"sentinel={sentinel_pw_put!r}\nLines:\n{joined}"
            )
        if sentinel_unauth in joined:
            raise TestFailure(
                f"SEC-3: unauth body sentinel leaked into api_audit.log; "
                f"sentinel={sentinel_unauth!r}\nLines:\n{joined}"
            )
        if "body=[redacted]" not in joined:
            raise TestFailure(
                f"SEC-1: expected `body=[redacted]` in audit log "
                f"(audit_redact_body route flag did not fire):\n{joined}"
            )
        if "body=[skipped]" not in joined:
            raise TestFailure(
                f"SEC-3: expected `body=[skipped]` in audit log "
                f"(unauth body must not be stored):\n{joined}"
            )

        # ---- 4. SEC-2 cmd_ban target sanitisation ----
        # Control bytes \x01 + \x0a in the target field; pre-fix
        # they persisted into bans_tbl + ops broadcast + response.
        # Use target_type=cid - no existence check (blind-add),
        # so the test isolates the sanitisation path.
        body = _json.dumps({
            "target_type": "cid",
            "target": "smoke_sec2_badguy\x01\x0ainjected",
            "duration_minutes": 1,
        }).encode("utf-8")
        r = http_req(b"POST", b"/v1/bans", body)
        if "200 OK" not in status(r):
            raise TestFailure(
                f"SEC-2 POST /v1/bans: expected 200, got {status(r)!r}; "
                f"body={body_of(r)!r}"
            )
        j = _json.loads(body_of(r))
        target_echo = j["data"]["target"]
        for bad in ("\x01", "\x0a", "\n"):
            if bad in target_echo:
                raise TestFailure(
                    f"SEC-2: cmd_ban target retains control byte {bad!r}: "
                    f"target={target_echo!r}"
                )
        # util.strip_control_bytes replaces control bytes with `?`
        # (vs deleting them) - this is the chosen footprint-preserving
        # behaviour. The point of SEC-2 is that the original bytes
        # are gone, not that the length shrinks.
        if target_echo != "smoke_sec2_badguy??injected":
            raise TestFailure(
                f"SEC-2: unexpected sanitised target: {target_echo!r}"
            )
        # Best-effort cleanup of the ban.
        ban_id = j["data"].get("id")
        if ban_id:
            http_req(b"DELETE", f"/v1/bans/{ban_id}".encode("ascii"))

        # ---- 5. SEC-5 idempotency cache path-scoped ----
        idem_key = "smoke-sec5-shared-key-X"
        body_announce = _json.dumps({
            "message": "sec5-announce",
            "scope": "all",
        }).encode("utf-8")
        r1 = _http_roundtrip(
            b"POST /v1/announce HTTP/1.1\r\n" + auth +
            b"X-Idempotency-Key: " + idem_key.encode("ascii") + b"\r\n" +
            b"Content-Type: application/json\r\n" +
            b"Content-Length: " + str(len(body_announce)).encode("ascii") + b"\r\n\r\n" +
            body_announce
        )
        if "200 OK" not in status(r1):
            raise TestFailure(
                f"SEC-5 step1 POST /v1/announce: {status(r1)!r}; body={body_of(r1)!r}"
            )

        # Same idem key, different (method+path). Pre-fix: cache hit
        # replays the announce 200. Post-fix: cache miss -> handler
        # runs -> 404 (no such SID).
        r2 = _http_roundtrip(
            b"DELETE /v1/users/AAAA HTTP/1.1\r\n" + auth +
            b"X-Idempotency-Key: " + idem_key.encode("ascii") + b"\r\n\r\n"
        )
        if "404" not in status(r2):
            raise TestFailure(
                f"SEC-5: DELETE /v1/users/AAAA with shared idem key got "
                f"{status(r2)!r}; cache must be method+path scoped so the "
                f"announce reply is not replayed. body={body_of(r2)!r}"
            )

        # ---- 6. SEC-6 ratelimit cfg apply_status ----
        burst_body = b'{"value": 10}'
        r = _http_roundtrip(
            b"PUT /v1/config/http_api_burst HTTP/1.1\r\n" + auth +
            b"Content-Type: application/json\r\n" +
            b"Content-Length: " + str(len(burst_body)).encode("ascii") + b"\r\n\r\n" +
            burst_body
        )
        if "200 OK" not in status(r):
            raise TestFailure(
                f"SEC-6 PUT http_api_burst: {status(r)!r}; body={body_of(r)!r}"
            )
        j = _json.loads(body_of(r))
        if j["data"].get("apply_status") != "reload_required":
            raise TestFailure(
                f"SEC-6: PUT http_api_burst apply_status expected "
                f"`reload_required` (ratelimit caches the value at init); "
                f"got {j['data']!r}"
            )
    finally:
        # Best-effort cleanup of the test reguser.
        try:
            _http_roundtrip(
                b"DELETE /v1/registered/smoke_sec1_postuser HTTP/1.1\r\n" + auth +
                b"X-Confirm: yes\r\n\r\n"
            )
        except Exception:
            pass
        # Restore cfg.tbl bare-key format (PUT /v1/config/http_api_burst
        # rewrites the file via util.savetable; downstream BLOM/ZLIF/
        # hub_listen regex flips need the original format).
        cfg_path.write_text(original_cfg_text, encoding="utf-8")


def test_http_coverage_addons(staging_dir: Path, proc=None):
    """#275 holistic review follow-up: small coverage additions
    that don't merit dedicated tests.

    - COV-N3: GET /v1/users/{sid} positive case (only the 404 path
      was covered pre-#275). Uses `_logged_in_user` to seed a real
      online dummy SID and asserts the response envelope shape.
    - COV-N4: GET /v1/log/api lines=1000 + lines=1001 boundary
      (spec §6.4 + §10.1 say max 1000; pre-#275 only the trivially-
      huge `lines=99999` clamp was tested).
    - COV-5: X-Request-ID echo on a *failure* response (the COV-1
      test asserts it on the 200 path; this one also verifies the
      error path echoes).
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get(path: bytes):
        return _http_roundtrip(b"GET " + path + b" HTTP/1.1\r\n" + auth + b"\r\n")

    # ---- COV-N3: GET /v1/users/{sid} positive ----
    with _logged_in_user(nick="dummy", password="test") as (adc, sid, _reader):
        r = get(b"/v1/users/" + sid.encode("ascii"))
        if "200 OK" not in status(r):
            raise TestFailure(
                f"COV-N3: GET /v1/users/{sid} expected 200 (positive); "
                f"got {status(r)!r}; body={body_of(r)!r}"
            )
        j = _json.loads(body_of(r))
        u = j.get("data") or {}
        # Spot-check: real INF fields should land on the user payload.
        for must in ("nick", "sid", "cid"):
            if not u.get(must):
                raise TestFailure(
                    f"COV-N3: GET /v1/users/{sid} missing `{must}` field; "
                    f"data={u!r}"
                )
        if u.get("sid") != sid:
            raise TestFailure(
                f"COV-N3: GET /v1/users/{sid} sid mismatch in response: "
                f"got data.sid={u.get('sid')!r}"
            )

    # ---- COV-N4: /v1/log/api lines boundary ----
    r = get(b"/v1/log/api?lines=1000")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"COV-N4: lines=1000 (max boundary) expected 200, "
            f"got {status(r)!r}"
        )
    r = get(b"/v1/log/api?lines=1001")
    if "200 OK" not in status(r):
        raise TestFailure(
            f"COV-N4: lines=1001 (over-max, clamp) expected 200, "
            f"got {status(r)!r}"
        )
    # The router clamps lines to 1000; the response array should
    # therefore not exceed 1000 entries even when 1001 is requested.
    j = _json.loads(body_of(r))
    lines_arr = j.get("data", {}).get("lines") or []
    if len(lines_arr) > 1000:
        raise TestFailure(
            f"COV-N4: lines=1001 should clamp to 1000; got {len(lines_arr)}"
        )

    # ---- COV-5: X-Request-ID echo on an error response ----
    r = _http_roundtrip(
        b"GET /v1/no-such-route HTTP/1.1\r\n" + auth + b"\r\n"
    )
    if "404" not in status(r):
        raise TestFailure(f"COV-5 error path setup: expected 404, got {status(r)!r}")
    if "X-Request-Id" not in r and "X-Request-ID" not in r:
        raise TestFailure(
            f"COV-5: 404 response missing X-Request-ID header; resp={r!r}"
        )


def test_http_events_cursor_lost(staging_dir: Path, proc=None):
    """#275 COV-3 holistic review follow-up: /v1/events cursor_lost.

    The events ringbuffer evicts oldest entries when it grows past
    `cfg.http_events_buffer_size`. When a long-polling client returns
    with `since=` below the buffer's surviving min id, the response
    carries `cursor_lost: true` so the client knows to catch up via
    per-resource GET endpoints (spec §10 footnote `[^http-events-1]`).
    Pre-#275 NO smoke test exercised this branch.

    Coverage:
      1.  Shrink buffer cap to 16 (validator min in cfg_defaults.lua)
          via PUT /v1/config/http_events_buffer_size. Live cfg; emit
          re-reads on every call.
      2.  POST /v1/topic 20 times - each emit fires a topic_changed
          event. After the 20th emit, only the last 16 survive; the
          first 4 are evicted.
      3.  GET /v1/events?since=0 - returns `cursor_lost: true`
          because cursor 0 falls below the buffer's min surviving id.
          Also asserts the "no waiting on stale cursor" rule:
          immediate return even when wait=<seconds>.
      4.  GET /v1/events?since=<current> - returns `cursor_lost:
          false` (cursor is current, no eviction relevant).
      5.  Restore buffer cap (live cfg) and topic state (best-effort
          reset to default).
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    original_cfg_text = cfg_path.read_text(encoding="utf-8")

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def get_json(path):
        r = _http_roundtrip(f"GET {path} HTTP/1.1\r\n".encode("ascii") + auth + b"\r\n")
        if "200 OK" not in status(r):
            raise TestFailure(f"GET {path}: {status(r)!r}; body={body_of(r)!r}")
        return _json.loads(body_of(r))

    def put_json(path, body_str):
        body = body_str.encode("utf-8")
        r = _http_roundtrip(
            f"PUT {path} HTTP/1.1\r\n".encode("ascii") + auth +
            b"Content-Type: application/json\r\n" +
            f"Content-Length: {len(body)}\r\n".encode("ascii") +
            b"\r\n" + body
        )
        if "200" not in status(r):
            raise TestFailure(f"PUT {path}: {status(r)!r}; body={body_of(r)!r}")
        return _json.loads(body_of(r))

    def post_json(path, body_str):
        body = body_str.encode("utf-8")
        r = _http_roundtrip(
            f"POST {path} HTTP/1.1\r\n".encode("ascii") + auth +
            b"Content-Type: application/json\r\n" +
            f"Content-Length: {len(body)}\r\n".encode("ascii") +
            b"\r\n" + body
        )
        if "200" not in status(r):
            raise TestFailure(f"POST {path}: {status(r)!r}; body={body_of(r)!r}")
        return _json.loads(body_of(r))

    try:
        # 1. shrink buffer cap. Validator minimum is 16 (per
        # cfg_defaults.lua) - the smallest legal value still proves
        # the eviction path; combined with a 20-event burst it's
        # enough to push the cursor_lost branch.
        put_json("/v1/config/http_events_buffer_size", '{"value": 16}')

        # 2. burst 20 topic_changed events
        for i in range(20):
            post_json("/v1/topic", f'{{"topic": "cursor-lost-test-{i}"}}')
        time.sleep(0.2)    # let the emit calls commit

        # 3. since=0 -> cursor_lost true (buffer min id >> 0)
        j = get_json("/v1/events?since=0&wait=0")
        d = j["data"]
        if d.get("cursor_lost") is not True:
            raise TestFailure(
                f"COV-3: since=0 with cap=3 after 6 emits expected "
                f"cursor_lost=true; got {d!r}"
            )

        # Even with wait=2s the spec says no-waiting-on-stale-cursor
        # (immediate return). Re-issue with wait=2 and time it; should
        # NOT hold for ~2s.
        t0 = time.time()
        j2 = get_json("/v1/events?since=0&wait=2")
        elapsed = time.time() - t0
        if elapsed > 1.0:
            raise TestFailure(
                f"COV-3: since=0 cursor-lost with wait=2 held connection "
                f"{elapsed:.2f}s; spec mandates immediate return on stale "
                f"cursor"
            )
        if j2["data"].get("cursor_lost") is not True:
            raise TestFailure(
                f"COV-3: wait=2 stale cursor still expected cursor_lost=true; "
                f"got {j2['data']!r}"
            )

        # 4. since=<current> -> cursor_lost false (cursor is current)
        current = d["cursor"]
        j = get_json(f"/v1/events?since={current}&wait=0")
        if j["data"].get("cursor_lost"):
            raise TestFailure(
                f"COV-3: since=cursor (caught up) should NOT report "
                f"cursor_lost; got {j['data']!r}"
            )
    finally:
        # Restore buffer size to default (1000). live cfg so no reload.
        try:
            put_json("/v1/config/http_events_buffer_size", '{"value": 1000}')
        except Exception:
            pass
        # Best-effort: reset topic to default (empty body resets).
        try:
            post_json("/v1/topic", '{}')
        except Exception:
            pass
        # PUT to /v1/config/http_events_buffer_size rewrites cfg.tbl
        # via util.savetable. Restore original text so downstream
        # regex flips (BLOM / ZLIF / hub_listen) keep working.
        cfg_path.write_text(original_cfg_text, encoding="utf-8")


def test_http_auth_scope_matrix(staging_dir: Path, proc=None):
    """#275 COV-1 holistic review follow-up: auth scope matrix.

    The router's `_token_scope_ok` gate at `core/http_router.lua`
    rejects a `read`-scope token attempting an `admin`-scoped
    endpoint with 403 E_FORBIDDEN. Pre-#275 NO smoke test exercised
    this branch - a regression downgrading the scope check would
    have shipped silently. This test uses the smoke `SMOKE_READ_TOKEN`
    fixture (injected alongside the bootstrap admin token in
    `_switch_to_http_active_mode`) to drive both positive (read
    succeeds on read endpoints) and negative (read 403s on admin
    endpoints) paths.

    Also asserts the `X-Request-ID` response header (#275 COV-5) -
    spec §6.5 mandates echo but no test was checking it.

    Coverage:
      1.  Read token on a read endpoint - 200 (positive control).
      2.  Read token on a non-existent route - 404 (NOT 403; the
          router resolves the route before the scope check).
      3.  Read token on PUT /v1/config/{key} - 403.
      4.  Read token on POST /v1/bans - 403.
      5.  Read token on PUT /v1/registered/{nick}/password - 403.
      6.  Read token on PUT /v1/registered/{nick}/level - 403.
      7.  Read token on DELETE /v1/users/{sid} - 403.
      8.  Read token on POST /v1/reload - 403.
      9.  All success responses echo X-Request-ID.

    Stateless: no resource mutation; just GET + scope-rejected
    writes. Position: after holistic-security test, before the
    cfg-drift mode-switch tests.
    """
    import json as _json

    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    admin_auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"
    read_auth = b"Authorization: Bearer " + SMOKE_READ_TOKEN.encode("ascii") + b"\r\n"

    def status(resp):
        return resp.split("\r\n", 1)[0]

    def headers_of(resp):
        head = resp.split("\r\n\r\n", 1)[0]
        out = {}
        for line in head.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip().lower()] = v.strip()
        return out

    def body_of(resp):
        return resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""

    def req(method: bytes, path: bytes, body: bytes = b"",
            auth: bytes = b"", extra: bytes = b""):
        if body:
            return _http_roundtrip(
                method + b" " + path + b" HTTP/1.1\r\n" + auth + extra +
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" +
                body
            )
        return _http_roundtrip(
            method + b" " + path + b" HTTP/1.1\r\n" + auth + extra + b"\r\n"
        )

    # ---- 1. positive control: read token on read endpoint ----
    r = req(b"GET", b"/v1/version", auth=read_auth)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"COV-1 positive: read token on GET /v1/version "
            f"expected 200, got {status(r)!r}; body={body_of(r)!r}"
        )

    # ---- COV-5: X-Request-ID echo on success ----
    hdrs = headers_of(r)
    if not hdrs.get("x-request-id"):
        raise TestFailure(
            f"COV-5: GET /v1/version response missing X-Request-ID header; "
            f"headers={list(hdrs.keys())!r}"
        )

    # ---- 2. read token on non-existent route -> 404, not 403 ----
    # (router resolves route before scope gate; auth happens first so
    # the read token is recognised, but no route matches.)
    r = req(b"GET", b"/v1/this-route-does-not-exist", auth=read_auth)
    if "404" not in status(r):
        raise TestFailure(
            f"COV-1 unknown route w/ read token: expected 404, "
            f"got {status(r)!r}"
        )

    # ---- 3-8. read token on admin endpoints -> 403 ----
    admin_probes = [
        (b"PUT",    b"/v1/config/max_users",
                    b'{"value": 3000}'),
        (b"POST",   b"/v1/bans",
                    b'{"target_type":"cid","target":"ABC","duration_minutes":1}'),
        (b"PUT",    b"/v1/registered/dummy/password",
                    b'{"password":"would-not-work-anyway-2025"}'),
        (b"PUT",    b"/v1/registered/dummy/level",
                    b'{"level":10}'),
        (b"DELETE", b"/v1/users/AAAA",       b""),
        (b"POST",   b"/v1/reload",           b'{}'),
    ]
    extras_for_xconfirm = {
        b"/v1/reload": b"X-Confirm: yes\r\n",
    }
    for method, path, body in admin_probes:
        extra = extras_for_xconfirm.get(path, b"")
        r = req(method, path, body=body, auth=read_auth, extra=extra)
        if "403" not in status(r):
            raise TestFailure(
                f"COV-1: read token on {method.decode()} {path.decode()} "
                f"expected 403, got {status(r)!r}; body={body_of(r)!r}"
            )
        if "E_FORBIDDEN" not in body_of(r):
            raise TestFailure(
                f"COV-1: read token on {method.decode()} {path.decode()} "
                f"403 missing E_FORBIDDEN code; body={body_of(r)!r}"
            )

    # ---- positive control: admin token still works on an admin op ----
    # (catches the inverted-gate regression: a fix that flips the
    # comparison would 403 admin tokens too.)
    r = req(b"GET", b"/v1/endpoints", auth=admin_auth)
    if "200 OK" not in status(r):
        raise TestFailure(
            f"COV-1 inverted-gate guard: admin token on GET /v1/endpoints "
            f"expected 200, got {status(r)!r}"
        )


def test_inf_integer_clamps(staging_dir: Path, proc=None):
    """Phase 8a F-INF-2 (#219): per-field integer clamps on the user
    accessors `user:share()` / `user:files()` / `user:slots()` /
    `user:hubs()`.

    The ADC parser is deliberately permissive (`^%-?%d+$`) on integer
    fields so DC++ builds that emit the `DS-1` sentinel can still log
    in (Phase 7d / #65 / upstream luadch/luadch#241). The clamp lives
    at the accessor layer in `core/hub_user_object.lua`: negatives
    normalise to 0 and oversize values cap at a float-safe / spec-
    realistic boundary so hub-stat aggregates and the HTTP API JSON
    output cannot be poisoned.

    Test:
    1. Login dummy/test with a BINF carrying poison numerics:
       SS=-1, SF=10^18, SL=-1, HN=99999999, HR=-1, HO=10^18.
    2. The login MUST succeed (parser stays permissive - Phase 7d
       contract regression guard).
    3. Query /v1/users via HTTP and find dummy's entry by SID.
    4. Assert: share_bytes=0, share_files=2^32, slots=0,
       hubs_normal=2^16, hubs_regged=0, hubs_op=2^16.
    """
    # Re-discover bootstrap token (same pattern as phase1c).
    token_path = staging_dir / "cfg" / "api_token.first"
    bootstrap_token = None
    for line in token_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            bootstrap_token = line
            break
    if not bootstrap_token:
        raise TestFailure(f"could not parse token from {token_path}")
    auth = b"Authorization: Bearer " + bootstrap_token.encode("ascii") + b"\r\n"

    # 1. Login dummy with custom poison BINF.
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader = _ADCReader(sock)
        sock.sendall(b"HSUP ADBASE ADTIGR\n")
        reader.recv_until(lambda f: f.startswith("ISUP "))
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))

        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32} PD{pid_b32} NIdummy I40.0.0.0 SUTCP4"
            f" SS-1 SF999999999999999999 SL-1"
            f" HN99999999 HR-1 HO999999999999999999\n"
        )
        sock.sendall(binf.encode("utf-8"))

        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_b32 = gpa.split(" ", 1)[1].strip()
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        # Login must succeed. ISTA = parser-level reject -> Phase 7d
        # regression.
        final = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if final.startswith("ISTA "):
            raise TestFailure(
                f"Phase 7d (#65) regression: hub rejected BINF carrying "
                f"negative / oversize integer fields. The clamp must "
                f"live at the accessor layer, not the parser. Got: {final!r}"
            )

        # 2. Query /v1/users with the bootstrap token. Find dummy by
        #    SID.
        r = _http_roundtrip(
            b"GET /v1/users?limit=50 HTTP/1.1\r\n" + auth + b"\r\n"
        )
        status_line = r.split("\r\n", 1)[0]
        if "200 OK" not in status_line:
            raise TestFailure(
                f"/v1/users: expected 200, got {status_line!r}"
            )
        body = r.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in r else ""
        # Parse JSON properly - dkjson does not preserve key insertion
        # order so a substring slice around `"sid":"<our-sid>"` would
        # only see fields that happen to follow sid in this run's hash
        # iteration.
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise TestFailure(f"/v1/users: response not JSON: {e}; body={body!r}")
        users = data.get("data", {}).get("users", [])
        entry = next((u for u in users if u.get("sid") == sid), None)
        if entry is None:
            raise TestFailure(
                f"/v1/users: dummy entry (sid={sid!r}) not in users[]; "
                f"users={users!r}"
            )

        # 3. Per-field clamp assertions. Caps come from
        #    core/hub_user_object.lua _CAP_*.
        for key, want, label in (
            ("share_bytes",   0,           "SS=-1 -> 0"),
            ("share_files",   1 << 32,     "SF=10^18 -> 2^32"),
            ("slots",         0,           "SL=-1 -> 0"),
            ("hubs_normal",   1 << 16,     "HN=99999999 -> 2^16"),
            ("hubs_regged",   0,           "HR=-1 -> 0"),
            ("hubs_op",       1 << 16,     "HO=10^18 -> 2^16"),
        ):
            got = entry.get(key)
            if got != want:
                raise TestFailure(
                    f"F-INF-2 clamp not applied: {key}={got!r} "
                    f"(want={want}, {label}); full entry={entry!r}"
                )
    finally:
        sock.close()


def _switch_to_kill_wrong_ips_off_mode(staging_dir, current_proc, current_log_file):
    """#214 Gap 2 regression setup: stop the hub, set `kill_wrong_ips
    = false` in cfg.tbl so the next test exercises the NAT-weird-
    deployment opt-out path. The key is not in `examples/cfg/cfg.tbl`
    by default (only in `core/cfg_defaults.lua` at true), so we inject
    it before the closing brace of the cfg.tbl table. Mirrors the
    `_switch_to_http_mode` `ratelimit_perip_conn_burst` injection
    pattern (same #82 lesson: cfg keys not always present in the
    example - regex must handle both)."""
    stop_hub(current_proc, current_log_file)
    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    if re.search(r"kill_wrong_ips\s*=", text):
        new_text, n = re.subn(
            r"kill_wrong_ips\s*=\s*\w+",
            "kill_wrong_ips = false",
            text,
            count=1,
        )
    else:
        new_text, n = re.subn(
            r"^\}\s*$",
            "    kill_wrong_ips = false,  -- smoke override (#214 Gap 2 test)\n}",
            text,
            count=1,
            flags=re.MULTILINE,
        )
    if n != 1:
        raise TestFailure(
            "could not set kill_wrong_ips=false in cfg.tbl - neither "
            "the in-place substitution nor the inject-before-} pattern "
            "matched. Did the cfg.tbl format change?"
        )
    cfg_path.write_text(new_text, encoding="utf-8")
    time.sleep(1.0)
    return start_hub(staging_dir)


def test_kill_wrong_ips_off_stamps_userip(staging_dir: Path, proc=None):
    """#214 Gap 2 regression. With `kill_wrong_ips = false` (the NAT-
    weird-deployment opt-out), a BINF claiming a different IP than the
    TCP source MUST NOT broadcast the lie - the hub MUST stamp the
    verified `userip` over the wrong claim before the BINF goes out to
    other clients. Pre-fix the wrong claim was forwarded as-is, which
    let a hostile client redirect other users' CTM / RCM frames at an
    arbitrary victim address (DDoS-amplification, see #214 body +
    Wikipedia DC++ DDoS history).

    Test:
      1. Login dummy/test with `I4203.0.113.1` (RFC 5737 documentation
         range - syntactically valid IPv4, definitely not 127.0.0.1).
      2. Login MUST succeed (kill_wrong_ips=false preserves the
         user's connection - that is the whole point of the opt-out).
      3. Read the own-BINF echo. It MUST carry `I4127.0.0.1` (verified
         userip), NOT `I4203.0.113.1` (the claim).

    Falsifiable: on unpatched code the echo carries the lie, the
    final `I4203.0.113.1 in final` check raises.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        reader = _ADCReader(sock)
        sock.sendall(b"HSUP ADBASE ADTIGR\n")
        reader.recv_until(lambda f: f.startswith("ISUP "))
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))

        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32} PD{pid_b32} NIdummy"
            f" I4203.0.113.1 SUTCP4\n"
        )
        sock.sendall(binf.encode("utf-8"))

        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt_b32 = gpa.split(" ", 1)[1].strip()
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger("test".encode("utf-8") + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        final = reader.recv_until(
            lambda f: f.startswith(f"BINF {sid}") or f.startswith("ISTA "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        if final.startswith("ISTA "):
            raise TestFailure(
                f"#214 Gap 2: kill_wrong_ips=false should preserve the "
                f"user's connection on IP mismatch (the whole point of "
                f"the opt-out). Got ISTA: {final!r}"
            )

        # The broadcast BINF echo MUST carry the verified userip
        # (127.0.0.1), not the lie (203.0.113.1).
        if "I4127.0.0.1" not in final:
            raise TestFailure(
                f"#214 Gap 2: broadcast BINF should carry "
                f"I4127.0.0.1 (verified userip stamped over the claim) "
                f"but does not. Frame: {final!r}"
            )
        if "I4203.0.113.1" in final:
            raise TestFailure(
                f"#214 Gap 2 regression: broadcast BINF carries the "
                f"claimed wrong IP `I4203.0.113.1` (DDoS-amplification "
                f"vector - other clients would direct CTM / RCM at the "
                f"spoofed address). The unverified claim MUST be "
                f"stamped over with userip before broadcast. "
                f"Frame: {final!r}"
            )
    finally:
        sock.close()


def _switch_to_blom_mode(staging_dir: Path, current_proc, current_log_file):
    """Phase 8 S5 (#147 T2.2) setup: stop the hub, flip
    `blom_enabled = false` to `true` in cfg.tbl so the next test
    exercises ADC-EXT BLOM hash-search routing. Keeps default k=6,
    h=16, m=32768 (4 KiB filter). Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"blom_enabled\s*=\s*false",
        "blom_enabled = true",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip blom_enabled in cfg.tbl"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


# BLOM bloom-filter parameters that must match the cfg defaults
# (cfg_defaults.lua blom_k / blom_h / blom_m). The smoke harness
# does not parse the live cfg back out; if the hub's defaults
# change, update these constants alongside.
BLOM_K = 6
BLOM_H = 16
BLOM_M = 32768


def _blom_insert(filter_bytes: bytes, tth: bytes,
                 k: int = BLOM_K, h: int = BLOM_H, m: int = BLOM_M) -> bytes:
    """Insert a single 24-byte TTH into a bloom filter byte array.
    Mirrors the bit-extraction in core/bloom.lua / the spec
    (section 3.20): per-iteration read h bits starting at bit i*h
    from the TTH as little-endian unsigned int, modulo m, set that
    bit (LSB-first per byte). Returns the updated filter bytes."""
    if len(tth) != 24:
        raise ValueError(f"TTH must be 24 bytes, got {len(tth)}")
    bps = h // 8
    out = bytearray(filter_bytes)
    for i in range(k):
        pos = 0
        for j in range(bps):
            pos |= tth[i * bps + j] << (8 * j)
        pos %= m
        out[pos // 8] |= 1 << (pos % 8)
    return bytes(out)


def test_blom_roundtrip(staging_dir: Path, proc=None):
    """Phase 8 S5 (#147 T2.2) BLOM hash-search routing roundtrip.

    Single-user scenario (the hub's broadcast routing iterates ALL
    NORMAL-state humans including the sender, so a search the
    sender issues is echoed back if-and-only-if the bloom filter
    permits - the perfect oracle for filter routing without
    needing a second logged-in user, which is non-trivial in the
    pre-seeded smoke harness):

      A logs in as dummy advertising ADBLOM in HSUP, receives the
      hub's HGET, uploads HSND + a binary filter with ONE known
      TTH inserted. Then:
        - hash-search BSCH for the inserted TTH -> A receives echo
        - hash-search BSCH for a DIFFERENT TTH  -> no echo (filter
          stripped it)
        - keyword-search BSCH (no TR)           -> A receives echo
          regardless of the filter (load-bearing spec-trap regression)

    Validates: SUP advertise of ADBLOM, hub-initiated HGET, the
    counted-binary capture stage in iostream + the HSND handler,
    per-user filter storage on the user object, the hash-vs-keyword
    routing decision in core/hub.lua's incoming() B-class branch.
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    in_filter_tth = secrets.token_bytes(24)
    not_in_filter_tth = secrets.token_bytes(24)
    filter_blob = bytes(BLOM_M // 8)
    filter_blob = _blom_insert(filter_blob, in_filter_tth)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        # ---- HSUP advertising ADBLOM
        sock.sendall(b"HSUP ADBASE ADTIGR ADBLOM\n")
        reader = _ADCReader(sock)
        isup = reader.recv_until(lambda f: f.startswith("ISUP "))
        if "ADBLOM" not in isup:
            raise TestFailure(
                f"hub did not advertise ADBLOM in plain SUP; got {isup!r}"
            )
        isid = reader.recv_until(lambda f: f.startswith("ISID "))
        sid = isid.split(" ", 1)[1].strip()
        reader.recv_until(lambda f: f.startswith("IINF "))

        # ---- full login as dummy
        pid = secrets.token_bytes(24)
        cid = _b32_encode(_tiger.tiger(pid))
        sock.sendall((
            f"BINF {sid} ID{cid} PD{_b32_encode(pid)}"
            f" NIdummy I40.0.0.0 SUTCP4\n"
        ).encode("utf-8"))
        gpa = reader.recv_until(lambda f: f.startswith("IGPA "))
        salt = _b32_decode(gpa.split(" ", 1)[1].strip())
        resp = _tiger.tiger(b"test" + salt)
        sock.sendall(f"HPAS {_b32_encode(resp)}\n".encode("utf-8"))
        reader.recv_until(lambda f: f.startswith(f"BINF {sid}"))

        # ---- hub now sends HGET. Read + validate.
        hget = reader.recv_until(lambda f: f.startswith("HGET "),
                                  timeout=PROTOCOL_TIMEOUT_SEC)
        if " blom " not in hget or f" {BLOM_M // 8} " not in hget:
            raise TestFailure(
                f"hub HGET does not match BLOM defaults; got {hget!r}"
            )
        if f"BK{BLOM_K}" not in hget or f"BH{BLOM_H}" not in hget:
            raise TestFailure(
                f"hub HGET missing BK/BH params; got {hget!r}"
            )

        # ---- reply with HSND header + binary filter blob
        sock.sendall(
            f"HSND blom / 0 {BLOM_M // 8}\n".encode("utf-8") + filter_blob
        )
        # Brief settle: the counted-binary stage's callback installs
        # the filter object on the user object. Sub-tick latency.
        time.sleep(0.5)

        # ---- hash-search for TTH IN the filter; expect echo back.
        tr_in = _b32_encode(in_filter_tth)
        sock.sendall(f"BSCH {sid} TR{tr_in}\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith(f"BSCH {sid} ") and f"TR{tr_in}" in f,
            timeout=PROTOCOL_TIMEOUT_SEC * 2,
        )

        # ---- hash-search for TTH NOT in the filter; expect NO echo.
        # The per-user filter installs ASYNCHRONOUSLY after the HSND
        # counted-binary upload, and _blom_filter_check FAILS OPEN when no
        # filter is installed yet (routes the search) - deliberate defence
        # in depth, but indistinguishable from a real leak. The positive
        # control above passes EITHER WAY (installed -> contains=true ->
        # send; not-yet -> fail-open -> send), so it does NOT prove the
        # filter is live. The not-in-filter DROP is the only observable
        # proof the filter is installed AND consulted, so POLL for it
        # rather than trust a fixed settle - the fixed 0.5s raced on a
        # loaded CI runner and fail-opened this negative case (#147 T2.2
        # flake: "bloom filter not consulted").
        tr_out = _b32_encode(not_in_filter_tth)
        deadline = time.monotonic() + 8.0
        consulted = False
        last_seen = None
        while time.monotonic() < deadline:
            sock.sendall(f"BSCH {sid} TR{tr_out}\n".encode("utf-8"))
            try:
                last_seen = reader.recv_until(
                    lambda f: f.startswith(f"BSCH {sid} ") and f"TR{tr_out}" in f,
                    timeout=1.0,
                )
                # reached the user: the filter is not consulted yet (still
                # installing) -> wait a moment and retry.
                time.sleep(0.3)
            except TestFailure:
                # timed out waiting for the echo -> the search was DROPPED
                # -> filter is installed and consulted. Done.
                consulted = True
                break
        if not consulted:
            raise TestFailure(
                "hash-search for TTH not in filter still reached the user "
                f"after 8s (bloom filter not consulted?); got {last_seen!r}"
            )

        # ---- keyword-search (no TR); expect echo regardless of filter.
        # This is the LOAD-BEARING spec-trap regression: the filter
        # must NOT be consulted on keyword searches because the bits
        # for a plain-text keyword are by definition not set.
        sock.sendall(f"BSCH {sid} ANbloomkeywordtest\n".encode("utf-8"))
        reader.recv_until(
            lambda f: f.startswith(f"BSCH {sid} ") and "ANbloomkeywordtest" in f,
            timeout=PROTOCOL_TIMEOUT_SEC * 2,
        )

    finally:
        sock.close()


def _switch_to_zlif_mode(staging_dir: Path, current_proc, current_log_file):
    """Phase 8 S4b (#147 T3.2) setup: stop the hub, flip
    `zlif_enabled = false` to `true` in cfg.tbl so the next test
    exercises ADC-EXT ZLIF stream compression. `zlif_over_tls` stays
    false - we test the plain-ADC path only (the TLS gate is a
    separate flag, and TLS+ZLIF has a documented CRIME-class
    concern). Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r"zlif_enabled\s*=\s*false",
        "zlif_enabled = true",
        text,
        count=1,
    )
    if n != 1:
        raise TestFailure(
            "could not flip zlif_enabled in cfg.tbl - is the key present in "
            "examples/cfg/cfg.tbl with default false?"
        )
    cfg_path.write_text(new_text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_zlif_roundtrip(staging_dir: Path, proc=None):
    """Phase 8 S4b: ADC-EXT ZLIF full roundtrip. With zlif_enabled =
    true and the client advertising ADZLIF in HSUP, the hub:

      - advertises ADZLIF in its ISUP response (plain frames)
      - sends `IZON\\n` as the last plain frame
      - deflate(Z_SYNC_FLUSH)s every subsequent outbound byte

    The test client decompresses inbound after the IZON boundary
    using Python's stdlib zlib (incremental, matches the Z_SYNC_FLUSH
    cadence). It does NOT send its own BZON, so its outbound stays
    plain - this exercises the asymmetric per-direction nature of
    ZLIF (hub compresses outbound; client outbound is plain).
    Validates: SUP advertise, IZON emission, outbound deflate stage
    installation, full ADC login flow over compression, +help reply
    routed back through deflate."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sock.sendall(b"HSUP ADBASE ADTIGR ADZLIF\n")

        # Read uncompressed bytes until the IZON\n boundary. Anything
        # before IZON is plain ADC; the moment we see IZON, the hub
        # has switched its outbound to deflate.
        buf = b""
        deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"IZON\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    f"timed out waiting for IZON; got {buf!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    f"connection closed before IZON arrived; got {buf!r}"
                )
            buf += chunk

        plain, compressed_tail = buf.split(b"IZON\n", 1)

        # 1. SUP advertise check.
        if b"ADZLIF" not in plain:
            raise TestFailure(
                f"hub did not advertise ADZLIF in plain SUP; got {plain!r}"
            )

        # 2. ISID parse out of plain frames.
        sid = None
        for f in plain.split(b"\n"):
            if f.startswith(b"ISID "):
                sid = f.split(b" ", 1)[1].decode("ascii")
                break
        if not sid:
            raise TestFailure(f"no ISID in plain SUP frames; got {plain!r}")

        # 3. From here on the hub's stream is zlib (Z_SYNC_FLUSH).
        decomp = zlib.decompressobj()
        decoded = bytearray()
        comp_buf = bytearray(compressed_tail)

        def pump_recv(needle: bytes, timeout=PROTOCOL_TIMEOUT_SEC):
            """Read+decompress until `needle` (bytes) appears in
            `decoded`, or timeout."""
            end = time.monotonic() + timeout
            while needle not in decoded:
                if comp_buf:
                    decoded.extend(decomp.decompress(bytes(comp_buf)))
                    del comp_buf[:]
                    if needle in decoded:
                        return
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TestFailure(
                        f"ZLIF timed out waiting for {needle!r}; "
                        f"decoded so far: {bytes(decoded)!r}"
                    )
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    raise TestFailure(
                        f"connection closed mid-ZLIF; decoded "
                        f"{bytes(decoded)!r}"
                    )
                comp_buf.extend(chunk)

        # 4. Send BINF for dummy/test (client outbound stays plain -
        # we did not BZON the hub).
        pid_bytes = secrets.token_bytes(24)
        cid_b32 = _b32_encode(_tiger.tiger(pid_bytes))
        pid_b32 = _b32_encode(pid_bytes)
        binf = (
            f"BINF {sid}"
            f" ID{cid_b32}"
            f" PD{pid_b32}"
            f" NIdummy"
            f" I40.0.0.0"
            f" SUTCP4\n"
        )
        sock.sendall(binf.encode("utf-8"))

        # 5. Hub responds IGPA <salt>, compressed.
        pump_recv(b"IGPA ")
        idx = decoded.index(b"IGPA ")
        nl = decoded.index(b"\n", idx)
        gpa = decoded[idx:nl].decode("ascii")
        salt_b32 = gpa.split(" ", 1)[1]
        salt_bytes = _b32_decode(salt_b32)
        response = _tiger.tiger(b"test" + salt_bytes)
        sock.sendall(f"HPAS {_b32_encode(response)}\n".encode("utf-8"))

        # 6. Login completes when the hub echoes our own BINF.
        pump_recv(f"BINF {sid}".encode("ascii"))

        # 7. Send +help BMSG and expect a chat reply (hubbot E/IMSG).
        sock.sendall(f"BMSG {sid} +help\n".encode("utf-8"))
        pump_recv(b"MSG ", timeout=PROTOCOL_TIMEOUT_SEC * 2)

        # 8. Now flip the CLIENT outbound to compression too so the
        # hub's inbound inflate stage gets exercised end-to-end
        # against real zlib (the unit test only mocks zlib). The
        # security review correctly flagged that the unit test
        # cannot catch a real-zlib Z_SYNC_FLUSH boundary / buffering
        # bug; this assertion covers the hub-inbound inflate path in
        # CI.
        #
        # Drain all pending hub bytes first (the +help reply from
        # step 7 may still be arriving in MSG fragments) so the
        # post-BZON marker check below cannot match a stale frame.
        sock.settimeout(0.5)
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            comp_buf.extend(chunk)
        if comp_buf:
            decoded.extend(decomp.decompress(bytes(comp_buf)))
            del comp_buf[:]
        boundary = len(decoded)

        # Send `BZON <sid>` uncompressed (last plain client frame),
        # then a single TCP write that bundles the compressed BMSG
        # right after the ZON `\n` - this is the same-TCP-segment
        # case S4a's pipeline reshape exists to handle. If the hub
        # mis-frames the post-ZON tail (i.e. pre-S4a behaviour), the
        # +zlif_compose-test command never reaches the hub command
        # dispatcher and the assertion below times out.
        comp = zlib.compressobj()
        compressed = (
            comp.compress(f"BMSG {sid} +help\n".encode("utf-8"))
            + comp.flush(zlib.Z_SYNC_FLUSH)
        )
        zon_then_compressed = f"BZON {sid}\n".encode("utf-8") + compressed
        sock.sendall(zon_then_compressed)

        # Wait for a NEW MSG to appear AFTER the drain boundary. With
        # the boundary anchored on a true zero-pending state, any
        # MSG past it must be the reply to our compressed +help.
        end = time.monotonic() + PROTOCOL_TIMEOUT_SEC * 2
        while True:
            if comp_buf:
                decoded.extend(decomp.decompress(bytes(comp_buf)))
                del comp_buf[:]
            if decoded.find(b"MSG ", boundary) != -1:
                break
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    "ZLIF inbound inflate: client compressed BZON + BMSG "
                    "+help did not produce a new hub reply; possible "
                    "mid-segment reshape regression or adc_parse rejecting "
                    "BZON. "
                    f"Decoded after boundary: "
                    f"{bytes(decoded[boundary:])!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    "ZLIF inbound: hub closed during compressed "
                    "BMSG roundtrip"
                )
            comp_buf.extend(chunk)

    finally:
        sock.close()


def test_zlif_pre_hsup_zon_rejected(staging_dir: Path, proc=None):
    """Phase 8 S4b security gate (security review BLOCKER B1): a
    `BZON` arriving BEFORE the HSUP handshake completes must be
    rejected with ISTA 240 + connection close, NOT silently install
    an inflate stage on a connection whose peer identity has not yet
    been negotiated. Runs under zlif_enabled = true to prove the
    state gate fires regardless of the operator cfg.

    Pre-fix (no `userstate == "protocol"` check): the hub installed
    inflate inbound, the client's plain follow-up bytes triggered a
    zlib Z_DATA_ERROR, the connection closed without any ISTA. This
    test specifically asserts the ISTA 240 marker which only the
    fix emits."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        sock.sendall(b"BZON AAAA\n")    # pre-HSUP - sid is bogus, irrelevant
        buf = b""
        end = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"\n" not in buf and time.monotonic() < end:
            sock.settimeout(end - time.monotonic())
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        if b"ISTA 240" not in buf:
            raise TestFailure(
                f"pre-HSUP BZON: expected ISTA 240 close marker; got {buf!r}"
            )
    finally:
        sock.close()


def test_blom_zlif_combined(staging_dir: Path, proc=None):
    """#192 combined-mode regression: with BOTH `blom_enabled = true`
    AND `zlif_enabled = true` the hub MUST advertise ADBLOM + ADZLIF,
    install inflate on the inbound pipeline when the client BZONs,
    splice the BLOM counted-binary capture BEFORE the ADC-line framer
    (i.e. AFTER inflate) when HSND arrives, and build the bloom
    filter from the DECOMPRESSED filter bytes. Pre-fix (Phase-8 S5
    inframer_prepend semantic) this test FAILS: counted sits in
    front of inflate, captures raw deflated noise, the bloom filter
    bits are random -> hash-search for an inserted TTH gets dropped
    (false negative).

    Runs in the same dual-flag hub state the preceding ZLIF tests
    set up (`blom_enabled = true` persisted from the BLOM mode
    switch, `zlif_enabled = true` from the ZLIF switch; the cfg
    mutex from Phase-8 S5 has been removed)."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    in_filter_tth = secrets.token_bytes(24)
    not_in_filter_tth = secrets.token_bytes(24)
    filter_blob = bytes(BLOM_M // 8)
    filter_blob = _blom_insert(filter_blob, in_filter_tth)

    sock = socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    )
    try:
        # ---- HSUP advertising BOTH ADBLOM + ADZLIF
        sock.sendall(b"HSUP ADBASE ADTIGR ADBLOM ADZLIF\n")

        # Read uncompressed bytes until IZON\n - the hub switches its
        # OUTBOUND to deflate after IZON. ADBLOM / ADZLIF / ISID /
        # IINF all arrive in the plain prefix.
        buf = b""
        deadline = time.monotonic() + PROTOCOL_TIMEOUT_SEC
        while b"IZON\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TestFailure(
                    f"combined: timed out waiting for IZON; got {buf!r}"
                )
            sock.settimeout(remaining)
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise TestFailure(
                    f"combined: connection closed before IZON; got {buf!r}"
                )
            buf += chunk

        plain, compressed_tail = buf.split(b"IZON\n", 1)
        if b"ADBLOM" not in plain:
            raise TestFailure(
                f"combined: hub did not advertise ADBLOM; got {plain!r}"
            )
        if b"ADZLIF" not in plain:
            raise TestFailure(
                f"combined: hub did not advertise ADZLIF; got {plain!r}"
            )
        sid = None
        for f in plain.split(b"\n"):
            if f.startswith(b"ISID "):
                sid = f.split(b" ", 1)[1].decode("ascii")
                break
        if not sid:
            raise TestFailure(
                f"combined: no ISID in plain SUP frames; got {plain!r}"
            )

        decomp = zlib.decompressobj()
        decoded = bytearray()
        comp_buf = bytearray(compressed_tail)

        def pump_recv(needle: bytes, timeout=PROTOCOL_TIMEOUT_SEC):
            end = time.monotonic() + timeout
            while needle not in decoded:
                if comp_buf:
                    decoded.extend(decomp.decompress(bytes(comp_buf)))
                    del comp_buf[:]
                    if needle in decoded:
                        return
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TestFailure(
                        f"combined: timed out waiting for {needle!r}; "
                        f"decoded so far: {bytes(decoded)!r}"
                    )
                sock.settimeout(remaining)
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    raise TestFailure(
                        f"combined: connection closed mid-stream; "
                        f"decoded {bytes(decoded)!r}"
                    )
                comp_buf.extend(chunk)

        # ---- BINF (plain client outbound; client has not BZON'd yet)
        pid = secrets.token_bytes(24)
        cid = _b32_encode(_tiger.tiger(pid))
        sock.sendall((
            f"BINF {sid} ID{cid} PD{_b32_encode(pid)}"
            f" NIdummy I40.0.0.0 SUTCP4\n"
        ).encode("utf-8"))

        # IGPA arrives compressed (hub outbound is now deflated).
        pump_recv(b"IGPA ")
        idx = decoded.index(b"IGPA ")
        nl = decoded.index(b"\n", idx)
        gpa = decoded[idx:nl].decode("ascii")
        salt = _b32_decode(gpa.split(" ", 1)[1])
        resp = _tiger.tiger(b"test" + salt)
        sock.sendall(f"HPAS {_b32_encode(resp)}\n".encode("utf-8"))

        # Login completes when the hub echoes our BINF.
        pump_recv(f"BINF {sid}".encode("ascii"))

        # Hub sends HGET after login (compressed).
        pump_recv(b"HGET ")
        idx = decoded.index(b"HGET ")
        nl = decoded.index(b"\n", idx)
        hget = decoded[idx:nl].decode("ascii")
        if " blom " not in hget:
            raise TestFailure(
                f"combined: HGET shape wrong (expected blom); got {hget!r}"
            )

        # ---- Switch CLIENT outbound to compression: BZON plain, then
        # all subsequent client bytes are deflate(Z_SYNC_FLUSH). The
        # hub installs inflate on inbound when BZON arrives. After
        # that, the next HSND header + binary blob both pass through
        # the hub's inflate stage. The BLOM HSND handler calls
        # insert_before_terminal(counted), splicing counted BETWEEN
        # inflate and adcline so the binary blob is captured
        # POST-INFLATE (decompressed) - the #192 fix point.
        sock.sendall(f"BZON {sid}\n".encode("utf-8"))

        # SINGLE compressobj for the whole post-BZON client-to-hub
        # stream. The hub's inflate stage holds one zlib state across
        # pushes - a fresh compressobj per message would insert a new
        # zlib prefix mid-stream and crash the inflate state.
        comp = zlib.compressobj()

        # HSND header + filter blob: both compressed together so the
        # hub's inflate sees them as one stream. The hub's HSND
        # dispatch will surface the header, splice counted, and the
        # binary tail (already in adcline's residual post-inflate)
        # gets routed through counted via insert_before_terminal's
        # residual transfer.
        hsnd = f"HSND blom / 0 {BLOM_M // 8}\n".encode("utf-8")
        payload = hsnd + filter_blob
        sock.sendall(
            comp.compress(payload) + comp.flush(zlib.Z_SYNC_FLUSH)
        )

        # Brief settle for the counted-stage callback to install the
        # filter on the user object.
        time.sleep(0.5)

        # ---- hash-search for TTH IN the filter; expect echo.
        # Same compressobj continues the stream.
        tr_in = _b32_encode(in_filter_tth)
        bsch = f"BSCH {sid} TR{tr_in}\n".encode("utf-8")
        sock.sendall(comp.compress(bsch) + comp.flush(zlib.Z_SYNC_FLUSH))
        pump_recv(f"BSCH {sid} TR{tr_in}".encode("ascii"),
                  timeout=PROTOCOL_TIMEOUT_SEC * 2)

        # ---- hash-search for TTH NOT in filter; expect NO echo.
        # If the #192 fix is wrong (counted captured deflated noise),
        # the bloom filter bits are random and the "inserted" TTH
        # search above usually MISSES the filter -> the test fails
        # there. This second assert covers the path where the random
        # bits happen to set the in_filter bit pattern.
        # Poll for the not-in-filter DROP - same async-install / fail-open
        # reasoning as test_blom_roundtrip: a not-yet-installed filter
        # fail-opens and echoes the search, so the fixed 0.5s settle above
        # is not a reliable gate. Re-send over the same compress stream and
        # look ONLY at bytes produced AFTER each send (decoded[mark:]) so an
        # earlier fail-open echo does not permanently trip the check.
        tr_out = _b32_encode(not_in_filter_tth)
        echo_marker = f"BSCH {sid} ".encode("ascii") + f"TR{tr_out}".encode("ascii")
        deadline = time.monotonic() + 8.0
        consulted = False
        while time.monotonic() < deadline:
            mark = len(decoded)
            sock.sendall(
                comp.compress(f"BSCH {sid} TR{tr_out}\n".encode("utf-8"))
                + comp.flush(zlib.Z_SYNC_FLUSH)
            )
            window = time.monotonic() + 1.0
            saw_echo = False
            while time.monotonic() < window:
                if comp_buf:
                    decoded.extend(decomp.decompress(bytes(comp_buf)))
                    del comp_buf[:]
                if echo_marker in bytes(decoded[mark:]):
                    saw_echo = True
                    break
                sock.settimeout(0.2)
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                comp_buf.extend(chunk)
            if not saw_echo:
                consulted = True    # this send was DROPPED -> filter live + consulted
                break
            time.sleep(0.3)
        if not consulted:
            raise TestFailure(
                "combined: hash-search for not-in-filter TTH still reached "
                "the user after 8s; the BLOM filter was not built from "
                "decompressed bytes (insert_before_terminal regression) or "
                "was never installed."
            )

    finally:
        sock.close()


def _switch_to_public_hub_mode(staging_dir: Path, current_proc, current_log_file):
    """#162 setup: stop the hub, flip reg_only to false in cfg.tbl,
    restart. Required so the next test exercises the
    `(not _cfg_reg_only) and adccmd:hasparam "ADPING"` branch in
    core/hub_dispatch.lua's HSUP handler - the branch that ADC pingers
    (hublist scrapers) actually hit. Returns the new (proc, log_file)."""
    stop_hub(current_proc, current_log_file)

    cfg_path = staging_dir / "cfg" / "cfg.tbl"
    text = cfg_path.read_text(encoding="utf-8")
    text, n = re.subn(
        r"^\s*reg_only\s*=\s*true\s*,",
        "    reg_only = false,",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise TestFailure(
            "could not flip reg_only to false in cfg.tbl - the setting "
            "line was not found in the staging tree"
        )
    cfg_path.write_text(text, encoding="utf-8")

    time.sleep(1.0)
    proc, log_file = start_hub(staging_dir)
    return proc, log_file


def test_ping_hsup_branch_emits_pingsup_response(staging_dir: Path, proc=None):
    """#162 regression: an ADC pinger sending HSUP with the ADPING flag
    against a public (reg_only=false) hub must receive the PING-IINF
    response from core/hub_dispatch.lua's _protocol.HSUP. Pre-fix the
    HSUP handler hit `pairs( _normalstatesids )` with `pairs` not
    imported into the module locals, raising the sandbox guard and
    silently failing the incoming() function - the pinger saw zero
    frames and timed out.

    Three assertions:
    1. ISUP from the hub advertises ADPING (proves the pinger branch
       at hub_dispatch.lua:220 fired, not the regular non-PING branch).
    2. IINF carries the T1.3 aggregate fields (SS, SF) that are only
       computed inside the buggy pairs() loop.
    3. The hub's error.log gained no `attempt to read undeclared var`
       entries during this connection (would catch the regression even
       if some future change made the pingsup string format-tolerate
       a missing field).
    """
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)

    error_log = staging_dir / "log" / "error.log"
    before = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""

    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sock.sendall(b"HSUP ADBASE ADTIGR ADPING\n")
        reader = _ADCReader(sock)
        try:
            isup = reader.recv_until(lambda f: f.startswith("ISUP "))
            reader.recv_until(lambda f: f.startswith("ISID "))
            iinf = reader.recv_until(lambda f: f.startswith("IINF "))
        except TestFailure as e:
            raise TestFailure(
                f"public hub did not respond to HSUP ADPING (regression "
                f"of #162 'pairs undeclared'); error: {e}"
            ) from e

    if "ADPING" not in isup:
        raise TestFailure(
            f"ISUP did not advertise ADPING - the pinger branch in "
            f"hub_dispatch.lua:220 did not fire. Got: {isup!r}"
        )

    # T1.3 (#147) added SS / SF aggregate fields to the PING-IINF. The
    # SS field on a freshly-started empty hub will be SS0; the
    # regular non-PING IINF does not carry SS at all. Presence of SS
    # is the smoking-gun signal that the aggregator loop ran.
    if " SS" not in iinf:
        raise TestFailure(
            f"PING-IINF did not include the SS aggregate from T1.3 - the "
            f"aggregator loop at hub_dispatch.lua:233 did not run. "
            f"Got: {iinf!r}"
        )

    after = error_log.read_text(encoding="utf-8", errors="replace") if error_log.exists() else ""
    new_lines = after[len(before):]
    if "attempt to read undeclared var" in new_lines:
        raise TestFailure(
            f"hub emitted a sandbox-undeclared-var error during the "
            f"PING handshake (regression of #162). New error.log "
            f"content: {new_lines!r}"
        )


def _ping_uc(host: str, port: int) -> int:
    """Open a fresh connection, run the hublist-pinger HSUP handshake
    (ADPING flag), read the PING-IINF and return its UC field as an int.

    Requires the hub to be in public mode (reg_only=false) - the PING
    branch in hub_dispatch.lua's HSUP handler only fires there. The
    _pingsup template (core/hub.lua) is `... UC%s SS%s SF%s ...`, so UC
    is a space-delimited named param. Capture an optional leading
    minus too, so a #179-style _user_count underflow surfaces as a
    clear "UC=-N" assertion failure rather than a no-match error."""
    with socket.create_connection(
        (host, port), timeout=PROTOCOL_TIMEOUT_SEC
    ) as sock:
        sock.sendall(b"HSUP ADBASE ADTIGR ADPING\n")
        reader = _ADCReader(sock)
        reader.recv_until(lambda f: f.startswith("ISUP "))
        reader.recv_until(lambda f: f.startswith("ISID "))
        iinf = reader.recv_until(lambda f: f.startswith("IINF "))
    m = re.search(r"\bUC(-?\d+)\b", iinf)
    if not m:
        raise TestFailure(
            f"PING-IINF carried no UC field; got: {iinf!r}"
        )
    return int(m.group(1))


def test_ping_uc_excludes_bots_empty_hub(staging_dir: Path, proc=None):
    """#179 tier 1: on a freshly-started public hub with zero humans
    connected, PING UC must be 0.

    The hub always runs at least the mandatory hubbot (created via
    regbot -> _normalstatesids) plus the example-cfg RegChat/OpChat
    bots. Pre-fix UC = tablesize(_normalstatesids) counted those bots,
    so an empty hub advertised UC>=1 to hublist scrapers. Post-fix UC =
    _get_user_count() (humans-only) = 0."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 0:
        raise TestFailure(
            f"empty hub advertised UC={uc} to a hublist pinger; expected "
            f"0. Bots are leaking into the PING user count (#179)."
        )


def test_ping_uc_excludes_bots_one_human(staging_dir: Path, proc=None):
    """#179 tier 2 (the strong one): with exactly one human logged in
    and N bots online, PING UC must be 1, not 1+N.

    Differentiates all three wrong behaviours at once: counts bots
    (UC=1+N), is hard-wired 0 (UC=0), or counts everything. Only the
    correct humans-only counter yields exactly 1."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as human:
        sid, _reader = _adc_login(human, "dummy", "test")
        if not sid:
            raise TestFailure("setup login failed; cannot assert UC")
        # Second, independent connection performs the pinger handshake
        # while the human above stays in NORMAL state.
        uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 1:
        raise TestFailure(
            f"one human + bots online but PING UC={uc}; expected exactly "
            f"1. Bots are still inflating the hublist user count (#179)."
        )


def test_ping_uc_survives_reload(staging_dir: Path, proc=None):
    """#179 tier 3: PING UC must stay correct across a +reload.

    +reload -> hub.restartscripts() -> killscripts(), which bot.kill()s
    every bot. Each bot.kill() reaches disconnect()'s
    `if userstate == "normal"` block (bot.state() hard-returns
    "normal") and, without the symmetry guard in core/hub.lua, runs
    `_user_count = _user_count - 1` for an entity that never
    incremented it. Re-created bots take login()'s if-bot branch and
    never re-increment. So pre-guard, one +reload underflows
    _user_count by the bot count and the externally advertised UC goes
    negative/garbage.

    One human (dummy, level 100) stays connected across the reload, so
    the correct post-reload UC is exactly 1."""
    wait_for_port(HUB_HOST, TEST_PORT_PLAIN, START_TIMEOUT_SEC)
    with socket.create_connection(
        (HUB_HOST, TEST_PORT_PLAIN), timeout=PROTOCOL_TIMEOUT_SEC
    ) as human:
        sid, reader = _adc_login(human, "dummy", "test")
        if not sid:
            raise TestFailure("setup login failed; cannot assert UC")
        human.sendall(f"BMSG {sid} +reload\n".encode("utf-8"))
        # cmd_reload sends its "Configuration reloaded." confirmation
        # only AFTER hub.restartscripts() has run, so receiving any
        # private reply means killscripts() (the underflow path) is
        # already done.
        reader.recv_until(
            lambda f: f.startswith("EMSG ") or f.startswith("DMSG "),
            timeout=PROTOCOL_TIMEOUT_SEC,
        )
        uc = _ping_uc(HUB_HOST, TEST_PORT_PLAIN)
    if uc != 1:
        raise TestFailure(
            f"after +reload with one human online PING UC={uc}; "
            f"expected exactly 1. _user_count underflowed on bot "
            f"teardown during killscripts() (#179)."
        )


def test_canonical_socket_layout(staging_dir: Path):
    """Closes #88: LuaSocket and LuaSec install in the canonical layout
    so plugins can `require "socket.http"` / `require "ssl.https"` per
    the standard Lua convention.

    Static path-existence check - if the CMake install rules drift back
    to the flat luadch-2.x bundling, http.lua's own internal
    `require "socket.url"` would fail and any HTTP-using plugin breaks.
    """
    expected = [
        # LuaSocket entrypoint + top-level helpers
        "lib/luasocket/lua/socket.lua",
        "lib/luasocket/lua/mime.lua",
        "lib/luasocket/lua/ltn12.lua",
        # LuaSocket submodules (require "socket.X")
        "lib/luasocket/lua/socket/http.lua",
        "lib/luasocket/lua/socket/url.lua",
        "lib/luasocket/lua/socket/headers.lua",
        # LuaSec entrypoint + submodules
        "lib/luasec/lua/ssl.lua",
        "lib/luasec/lua/ssl/https.lua",
        "lib/luasec/lua/ssl/options.lua",
        # SLAXML XML parser (used by ptx_RSSFeedWatch and any future
        # XML-consuming plugin in luadch-ng/scripts)
        "lib/slaxml/slaxml.lua",
    ]
    missing = [p for p in expected if not (staging_dir / p).exists()]
    if missing:
        raise TestFailure(
            "canonical LuaSocket / LuaSec layout incomplete; missing:\n  "
            + "\n  ".join(missing)
        )


def test_sandbox_os_clock_whitelisted(staging_dir: Path):
    """Closes #325: the curated `_os_safe` shim in core/scripts.lua
    must expose `clock` alongside the existing time / date / difftime
    triad. The companion `luadch-ng/scripts` plugin ptx_freshstuff (and
    any future 3rd-party plugin using `os.clock()` for stopwatch-style
    output) hits `attempt to call a nil value (field 'clock')` at
    onStart otherwise.

    Falsifiable: pre-fix the shim definition lists only time / date /
    difftime; this static-source check asserts the literal
    `clock = os.clock` entry is present in the shim block. Pre-fix
    fails, post-fix passes.
    """
    scripts_lua = staging_dir / "core" / "scripts.lua"
    if not scripts_lua.exists():
        raise TestFailure(f"core/scripts.lua not found at {scripts_lua}")
    text = scripts_lua.read_text(encoding="utf-8")
    # Match _os_safe = { ... clock = os.clock ... } as a single block.
    # The pattern is tolerant of order / whitespace inside the block
    # but anchored on the shim's variable name so an unrelated
    # `clock = os.clock` elsewhere can't satisfy it.
    pattern = re.compile(
        r"local\s+_os_safe\s*=\s*\{[^}]*\bclock\s*=\s*os\.clock\b[^}]*\}",
        re.DOTALL,
    )
    if not pattern.search(text):
        raise TestFailure(
            "core/scripts.lua: curated `_os_safe` shim is missing "
            "the `clock = os.clock` entry (#325)"
        )


def test_no_script_errors(log_path: Path, error_log_path: Path = None):
    """
    Plugin-load smoke: scan the hub's stdout AND the on-disk error.log
    for "script error:" lines. core/scripts.lua emits exactly that
    prefix when a plugin fails to load or a listener throws.

    Phase 8a-2 (issue #121): error_log_path was added because the
    captured hub stdout in `log_path` only carries C-level prints from
    the hub binary - Lua-side `out.error()` writes to log/error.log on
    disk. Pre-fix, this test silently passed even when plugins were
    raising on every login because the negative-test fuzz suite did
    not surface those errors anywhere stdout could see them.
    """
    bad_lines = []

    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        bad_lines.extend(
            (str(log_path), line)
            for line in text.splitlines()
            if "script error:" in line
        )
    else:
        raise TestFailure(f"hub log not found at {log_path}")

    if error_log_path is not None and error_log_path.exists():
        text = error_log_path.read_text(encoding="utf-8", errors="replace")
        bad_lines.extend(
            (str(error_log_path), line)
            for line in text.splitlines()
            if "script error:" in line
        )

    if bad_lines:
        sample = "\n  ".join(f"[{src}] {line}" for src, line in bad_lines[:5])
        raise TestFailure(
            f"hub emitted {len(bad_lines)} script error line(s):\n  {sample}"
        )


def test_event_loop_backend_logged(staging_dir: Path):
    """Regression guard for the event-loop backend and its socket ceiling.

    hub.loop() logs one boot line naming the luasocket event-loop backend and
    the ceiling on how many sockets the single event loop can watch. The line
    (and the assertion) differ by platform:

      - POSIX poll backend (#310): "event loop backend: poll (socket ceiling
        ...)". poll() takes a variable-length pollfd array, so there is NO
        fixed FD_SETSIZE cap; the ceiling is the process fd limit (hub/hub.c
        raises RLIMIT_NOFILE at boot). This test REQUIRES the poll line on the
        Linux leg, which fails pre-fix: the old select.c backend logged the
        "select() capacity (FD_SETSIZE)" line instead and had no _EVENTBACKEND.
      - Windows select backend (#416): "select() capacity (FD_SETSIZE): N
        sockets". select.c raises "too many sockets" at n >= FD_SETSIZE; the
        Winsock default 64 crashed the hub at ~64 sockets, so the Windows build
        must define FD_SETSIZE=1024. Assert N >= 1024 (unchanged by #310).

    Goes through the real hub because a standalone require('socket') under msys2
    lua hits the bundled-liblua ABI clash (see smoke.yml). Reads event.log
    (out.put's target, persisted open-append-close per line; the harness sets
    log_events=true) - not smoke-hub.log, whose stdout is block-buffered and
    lost when the hub is terminated at teardown."""
    log_path = staging_dir / "log" / "event.log"
    if not log_path.exists():
        raise TestFailure(
            f"event.log not found at {log_path}; the smoke harness must "
            f"enable log_events in the cfg.tbl override for this assertion"
        )
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if sys.platform.startswith("win"):
        m = re.search(r"select\(\) capacity \(FD_SETSIZE\): (\d+) sockets", text)
        if not m:
            raise TestFailure(
                "event.log has no 'select() capacity (FD_SETSIZE): N sockets' "
                "line - the Windows select backend should log it once at startup"
            )
        cap = int(m.group(1))
        if cap < 1024:
            raise TestFailure(
                f"select() FD_SETSIZE capacity is {cap}, expected >= 1024 - the "
                f"Windows luasocket build must define FD_SETSIZE=1024; the default "
                f"64 crashes the event loop at ~64 sockets (#416)"
            )
    else:
        if not re.search(r"event loop backend: poll", text):
            raise TestFailure(
                "event.log has no 'event loop backend: poll' line - the POSIX "
                "luasocket build must use the poll() event-loop backend (#310); "
                "pre-fix it logged 'select() capacity (FD_SETSIZE)' instead"
            )


# -----------------------------------------------------------------------------
# Test orchestration
# -----------------------------------------------------------------------------

TESTS = [
    ("hub binds plain + TLS ports", test_hub_binds_ports),
    ("plain ADC handshake", test_plain_handshake),
    ("TLS ADC handshake", test_tls_handshake),
    ("plain ADC full login (dummy/test)", test_full_login_plain),
    ("TLS ADC full login (dummy/test)", test_full_login_tls),
    ("botflag: show_as_bot ORs CT bot bit (#571)", test_botflag_ct_bit),
    ("+cmd routing (post-login +help)", test_command_routing),
    ("alias resolver fallback dispatch (#327)", test_aliases_adc_dispatch),
    ("cmd_ban rejects bantime < 1", test_cmd_ban_rejects_bad_time),
    ("cmd_ban permanent keyword (#444)", test_cmd_ban_permanent_adc),
    ("blocklist admin CLI (#78 Phase B)", test_blocklist_78_phase_b),
    ("whitelist admin CLI + pinger seed (#78 allowlist Phase B)", test_whitelist_78_phase_b),
    ("blocklist feeds status (#78 Phase E)", test_blocklist_feeds_status),
    ("proxydetect status (#78 Phase F)", test_proxydetect_status),
    ("S1: fragmented frame reassembled (phase8-io)", test_s1_fragmented_frame_reassembled),
    ("S1: two frames in one segment (phase8-io)", test_s1_two_frames_one_segment),
    ("literal [+!#] bracket hint + no-arg-echo (#137)", test_literal_bracket_command_hint),
    ("BINF without I4/I6 accepted (#161)", test_binf_without_i4_or_i6_accepted),
    ("BINF with both I4 and I6 accepted (#147 T3.1 HBRI)", test_binf_with_both_i4_and_i6_accepted),
    ("BINF unverified secondary family stripped (#214 Gap 1)", test_binf_secondary_family_stripped),
    ("HBRI success: side-channel validates secondary (#214)", test_hbri_success),
    ("HBRI discovery: placeholder I6:: discovered via getpeername (#291)", test_hbri_discovery_placeholder),
    ("HBRI concrete address mismatch rejected (#291)", test_hbri_concrete_mismatch_rejected),
    ("HBRI post-login: secondary in a NORMAL-state INF validated (#286)", test_hbri_postlogin_success),
    ("HBRI post-login failure: secondary stays stripped (#286)", test_hbri_postlogin_failure_stays_stripped),
    ("HBRI post-login: no re-solicit within cooldown (#286)", test_hbri_postlogin_no_resolicit_cooldown),
    ("HBRI timeout: unvalidated secondary stays stripped (#214)", test_hbri_timeout),
    ("HBRI unknown token rejected (#214)", test_hbri_unknown_token),
    ("HBRI disconnect mid-validation cleans up (#214)", test_hbri_disconnect_cleanup),
    ("HBRI not solicited for client without secondary (#214)", test_hbri_no_secondary_no_solicit),
    ("HBRI wrong-family side-channel rejected (#294)", test_hbri_wrong_family_rejected),
    ("HBRI v6-main / v4-secondary direction (#294)", test_hbri_v4_secondary_direction),
    ("HBRI post-login disconnect mid-validation cleans up (#294)", test_hbri_postlogin_disconnect_cleanup),
    ("HBRI post-login concrete mismatch rejected (#294)", test_hbri_postlogin_concrete_mismatch_rejected),
    ("post-login INF with I4 silent-stripped (#222)", test_post_login_i4_silent_stripped),
    ("CSPRNG salts are unique across connections", test_csprng_salt_uniqueness),
    ("per-IP connection cap refuses overflow", test_perip_connection_cap),
    # Phase 8a-2 negative-test fuzz suite (issue #121). Each test feeds
    # malformed input and checks the hub does not crash; the canary at
    # the end and test_no_script_errors at the end of the run together
    # detect any failure.
    ("neg: BINF with negative numerics", test_neg_inf_negative_numerics),
    ("neg: BINF with oversize numerics", test_neg_inf_oversize_numerics),
    ("neg: BINF with invalid IPv4", test_neg_inf_invalid_ipv4),
    ("neg: BINF with invalid IPv6", test_neg_inf_invalid_ipv6),
    ("neg: BINF with overlong nick", test_neg_inf_overlong_nick),
    ("neg: BINF with overlong description", test_neg_inf_overlong_description),
    ("neg: BINF with malformed UTF-8 nick", test_neg_inf_malformed_utf8_nick),
    ("neg: BINF missing required ID/PID", test_neg_inf_missing_required_fields),
    ("neg: 30 repeated BINFs in one connection", test_neg_repeated_binf_burst),
    ("neg: command before handshake", test_neg_command_before_handshake),
    ("neg: HPAS before BINF", test_neg_hpas_before_binf),
    ("neg: post-login oversized BMSG", test_neg_post_login_oversized_msg),
    ("neg: post-login oversized BSCH", test_neg_post_login_oversized_search),
    ("neg: post-login BSCH burst", test_neg_post_login_search_burst),
    ("neg: post-login DMSG burst (#80 PM bucket)", test_neg_post_login_pm_burst),
    ("neg: post-login BINF burst (#80 INF bucket)", test_neg_post_login_inf_burst),
    ("neg: post-login DCTM burst (#80 CTM bucket)", test_neg_post_login_ctm_burst),
    ("neg: post-login DRCM burst (#80 CTM bucket)", test_neg_post_login_rcm_burst),
    ("neg: post-login NATT burst (#147 T1.1)", test_neg_post_login_natt_burst),
    ("post-login DRES/FRES listener chain (#160)", test_post_login_search_result_listener_chain),
    ("HQUI from client closes cleanly (#147 T1.7)", test_hqui_from_client_honored),
    ("neg: canary - hub still alive after fuzz battery", test_neg_canary_hub_alive),
]


def run_tests(staging_dir: Path):
    log_path = staging_dir / "log" / "smoke-hub.log"
    error_log_path = staging_dir / "log" / "error.log"
    failed = []
    for name, fn in TESTS:
        try:
            fn()
        except Exception as e:
            log(f"FAIL  {name}: {e}")
            failed.append(name)
        else:
            log(f"PASS  {name}")

    # #480: drive a real +backup now and assert a sealed artifact lands on
    # disk. Needs staging_dir for the file check, so it runs here (main hub
    # still up) rather than in the no-arg TESTS list.
    try:
        test_backup_now(staging_dir)
    except Exception as e:
        log(f"FAIL  +backup now writes an encrypted artifact (#480): {e}")
        failed.append("+backup now writes an encrypted artifact (#480)")
    else:
        log("PASS  +backup now writes an encrypted artifact (#480)")

    # State-of-disk tests run after the protocol tests so any post-login
    # save (HPAS lastconnect update) has had a chance to land.
    try:
        test_canonical_socket_layout(staging_dir)
    except Exception as e:
        log(f"FAIL  canonical LuaSocket / LuaSec layout: {e}")
        failed.append("canonical LuaSocket / LuaSec layout")
    else:
        log("PASS  canonical LuaSocket / LuaSec layout")

    try:
        test_sandbox_os_clock_whitelisted(staging_dir)
    except Exception as e:
        log(f"FAIL  sandbox _os_safe.clock whitelisted (#325): {e}")
        failed.append("sandbox _os_safe.clock whitelisted (#325)")
    else:
        log("PASS  sandbox _os_safe.clock whitelisted (#325)")

    try:
        test_cert_autogen_first_boot(staging_dir)
    except Exception as e:
        log(f"FAIL  cert auto-gen on first boot: {e}")
        failed.append("cert auto-gen on first boot")
    else:
        log("PASS  cert auto-gen on first boot")

    try:
        test_setpass_preserves_encryption(staging_dir)
    except Exception as e:
        log(f"FAIL  +setpass preserves encryption: {e}")
        failed.append("+setpass preserves encryption")
    else:
        log("PASS  +setpass preserves encryption")

    try:
        test_usertbl_encrypted_at_rest(staging_dir)
    except Exception as e:
        log(f"FAIL  user.tbl encrypted at rest: {e}")
        failed.append("user.tbl encrypted at rest")
    else:
        log("PASS  user.tbl encrypted at rest")

    try:
        test_usertbl_bak_atomic_refresh(staging_dir)
    except Exception as e:
        log(f"FAIL  user.tbl.bak atomic refresh: {e}")
        failed.append("user.tbl.bak atomic refresh")
    else:
        log("PASS  user.tbl.bak atomic refresh")

    try:
        test_neg_inf_nick_escape_space_rejected(staging_dir)
    except Exception as e:
        log(f"FAIL  neg: BINF NI with \\s escape rejected (#265): {e}")
        failed.append("neg: BINF NI with \\s escape rejected (#265)")
    else:
        log("PASS  neg: BINF NI with \\s escape rejected (#265)")

    try:
        test_neg_inf_nick_escape_newline_rejected(staging_dir)
    except Exception as e:
        log(f"FAIL  neg: BINF NI with \\n escape rejected (#265): {e}")
        failed.append("neg: BINF NI with \\n escape rejected (#265)")
    else:
        log("PASS  neg: BINF NI with \\n escape rejected (#265)")

    try:
        test_neg_unknown_escape_discarded(staging_dir)
    except Exception as e:
        log(f"FAIL  neg: unknown ADC escape \\q discarded (#419): {e}")
        failed.append("neg: unknown ADC escape \\q discarded (#419)")
    else:
        log("PASS  neg: unknown ADC escape \\q discarded (#419)")

    try:
        test_neg_trailing_backslash_discarded(staging_dir)
    except Exception as e:
        log(f"FAIL  neg: trailing backslash discarded (#419): {e}")
        failed.append("neg: trailing backslash discarded (#419)")
    else:
        log("PASS  neg: trailing backslash discarded (#419)")

    try:
        test_valid_escaped_backslash_not_discarded(staging_dir)
    except Exception as e:
        log(f"FAIL  pos: valid escaped backslash NOT discarded (#419): {e}")
        failed.append("pos: valid escaped backslash NOT discarded (#419)")
    else:
        log("PASS  pos: valid escaped backslash NOT discarded (#419)")

    # The plugin-load test reads the hub log, so it runs after all
    # protocol tests have had a chance to exercise the listeners.
    try:
        test_no_script_errors(log_path, error_log_path)
    except Exception as e:
        log(f"FAIL  no script errors in log: {e}")
        failed.append("no script errors in log")
    else:
        log("PASS  no script errors in log")

    try:
        test_event_loop_backend_logged(staging_dir)
    except Exception as e:
        log(f"FAIL  event loop backend logged (#310/#416): {e}")
        failed.append("event loop backend logged (#310/#416)")
    else:
        log("PASS  event loop backend logged (#310/#416)")

    return failed


def test_port_in_use_message(source_install: Path, proc=None, keep_staging=False):
    """A second hub started with ports the running first hub already holds
    must log a clear operator-facing "port ... already in use - change the
    port in cfg/cfg.tbl" message (core/hub.lua add_server_handler). Uses a
    SEPARATE install dir staged from the pristine source (so nothing about
    the same-dir single-instance lock is involved) pointed at the SAME
    test ports as the live shared hub.

    The assertion is on the NEW guidance phrase, not just "already in use":
    on Linux the raw luasocket bind error ("...bind: address already in
    use") is logged pre-fix too, so a naive "already in use" check would
    false-pass. Provably fails pre-fix: on Windows the second hub's
    pre-bind SO_REUSEADDR let it silently re-bind the port (no failure, no
    message); on Linux the bind failed but only the cryptic line was
    logged, never the actionable guidance this asserts."""
    if proc is None or proc.poll() is not None:
        raise TestFailure("precondition failed: the first hub is not running")

    second_staging = stage_install(source_install)
    second = None
    second_log = None
    try:
        override_test_ports(second_staging)   # same TEST_PORT_* as the shared hub
        for stale in ("servercert.pem", "serverkey.pem", "cacert.pem", "cakey.pem"):
            (second_staging / "certs" / stale).unlink(missing_ok=True)
        second, second_log = start_hub(second_staging)

        # The guidance goes to error.log via out.error (log_errors=true by
        # default). "change the port in cfg/cfg.tbl" is unique to the new
        # message - absent from the pre-fix cryptic luasocket line.
        err_log = second_staging / "log" / "error.log"
        needle = "change the port in cfg/cfg.tbl"
        deadline = time.monotonic() + PORT_IN_USE_TIMEOUT_SEC
        found = False
        while time.monotonic() < deadline:
            if err_log.exists():
                text = err_log.read_text(encoding="utf-8", errors="replace")
                if needle in text:
                    found = True
                    break
            if second.poll() is not None:
                break   # process died; one more read below then fail
            time.sleep(0.2)
        if not found:
            tail = ""
            if err_log.exists():
                tail = err_log.read_text(encoding="utf-8", errors="replace")[-1000:]
            raise TestFailure(
                "second hub did not log the clear port-in-use guidance "
                f"({needle!r}); error.log tail:\n{tail!r}"
            )
    finally:
        if second is not None:
            stop_hub(second, second_log)
        if keep_staging:
            log(f"second-hub staging kept at {second_staging.parent}")
        else:
            shutil.rmtree(second_staging.parent, ignore_errors=True)


def _start_second_hub(staging_dir: Path):
    """Spawn a SECOND hub against the same staging tree, capturing its
    own stdout/stderr to log/second-instance.log. Deliberately does NOT
    reuse start_hub(): that opens the shared log/smoke-hub.log in "wb"
    mode and would truncate the first (running) hub's log."""
    binary = staging_dir / ("Luadch.exe" if sys.platform == "win32" else "luadch")
    out_path = staging_dir / "log" / "second-instance.log"
    out = open(out_path, "wb")
    proc = subprocess.Popen(
        [str(binary)],
        cwd=str(staging_dir.parent),
        stdout=out,
        stderr=subprocess.STDOUT,
    )
    return proc, out, out_path


def test_single_instance_lock(staging_dir: Path, proc=None):
    """A second hub launched against the same install tree must refuse to
    start: the single-instance lock in hub.c (flock on unix, exclusive
    CreateFile on Windows) makes it exit non-zero with an "already
    running" message, and the first instance keeps running untouched.
    Guards against two hubs sharing cfg/user.tbl/master.key/logs and
    corrupting them via interleaved saves.

    Provably fails pre-fix: without the launcher guard the second process
    either boots a full second hub (on Windows SO_REUSEADDR lets it
    re-bind the ports -> wait() times out) or dies on a bind error with
    no single-instance message - neither matches the assertions here."""
    if proc is None or proc.poll() is not None:
        raise TestFailure("precondition failed: the first hub is not running")

    second, second_out, second_log_path = _start_second_hub(staging_dir)
    try:
        try:
            rc = second.wait(timeout=SINGLE_INSTANCE_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            raise TestFailure(
                f"second hub did not exit within {SINGLE_INSTANCE_TIMEOUT_SEC}s; "
                "the single-instance guard is missing (two instances ran "
                "concurrently)"
            )
    finally:
        # Never leave a stray second process behind, even on assert paths.
        # Swallow a second TimeoutExpired on the reap so it cannot mask the
        # real TestFailure or orphan the process.
        if second.poll() is None:
            second.kill()
            try:
                second.wait(timeout=STOP_TIMEOUT_SEC)
            except subprocess.TimeoutExpired:
                pass
        second_out.close()

    if rc == 0:
        raise TestFailure("second hub exited 0; expected a non-zero refusal")

    text = second_log_path.read_text(encoding="utf-8", errors="replace")
    if "already running" not in text:
        raise TestFailure(
            "second hub exited non-zero but its log lacks the single-instance "
            f"refusal message; log was:\n{text!r}"
        )

    # The rejected second start must not disturb the running first hub.
    if proc.poll() is not None:
        raise TestFailure(
            f"first hub died (rc={proc.poll()}) after the second start attempt; "
            "the guard must not disturb the already-running instance"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "install_dir",
        type=Path,
        help="path to a built+installed luadch tree (e.g. build/install/luadch)",
    )
    parser.add_argument(
        "--keep-staging",
        action="store_true",
        help="leave the temp staging dir on disk for inspection after the run",
    )
    args = parser.parse_args()

    if not args.install_dir.is_dir():
        log(f"ERROR  install dir not found: {args.install_dir}")
        return 2

    staging_dir = stage_install(args.install_dir.resolve())
    proc = None
    log_file = None
    try:
        override_test_ports(staging_dir)
        seed_dummy_botflag(staging_dir)   # #571: flag dummy for test_botflag_ct_bit
        # As of v3.1.6 the hub auto-generates a self-signed P-256
        # ECDSA cert on first boot via core/cert_bootstrap.lua when
        # no cert exists. Default cfg.tbl ships TLS-only (#77).
        #
        # Wipe any leftover cert/key the install tree may carry from
        # earlier manual testing - the staging copy needs to start
        # without certs so the auto-gen path actually runs and
        # test_cert_autogen_first_boot has something to assert.
        for stale in ("servercert.pem", "serverkey.pem",
                      "cacert.pem", "cakey.pem"):
            (staging_dir / "certs" / stale).unlink(missing_ok=True)
        proc, log_file = start_hub(staging_dir)
        failed = run_tests(staging_dir)

        # Port-in-use guidance: with the shared hub still holding the test
        # ports, a second hub (separate dir, same ports) must log a clear
        # "change the port in cfg/cfg.tbl" message. Runs BEFORE the
        # plaintext switch below stops the shared hub.
        try:
            test_port_in_use_message(
                args.install_dir.resolve(), proc=proc,
                keep_staging=args.keep_staging,
            )
        except Exception as e:
            log(f"FAIL  port-in-use guidance on second hub: {e}")
            failed.append("port-in-use guidance on second hub")
        else:
            log("PASS  port-in-use guidance on second hub")

        # Single-instance lock: with the shared hub still running, a
        # second launch against the same tree must be refused by the
        # hub.c guard. Runs BEFORE the plaintext-mode switch below stops
        # this hub (it needs a live first instance holding the lock).
        try:
            test_single_instance_lock(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  single-instance lock refuses second start: {e}")
            failed.append("single-instance lock refuses second start")
        else:
            log("PASS  single-instance lock refuses second start")

        # #480 PR-B: backup -> --restore round-trip on its own staged tree
        # (real AES-256-GCM decrypt through the binary). Independent of the
        # shared hub above; stages + tears down its own install.
        try:
            test_backup_restore_roundtrip(
                args.install_dir.resolve(), keep_staging=args.keep_staging,
            )
        except Exception as e:
            log(f"FAIL  backup -> restore round-trip (#480 PR-B): {e}")
            failed.append("backup -> restore round-trip (#480 PR-B)")
        else:
            log("PASS  backup -> restore round-trip (#480 PR-B)")

        # #128 plaintext-mode test runs AFTER the regular battery
        # because cfg_secret.init() reads encrypt_usertbl once at
        # startup, so we have to stop + restart with a flipped cfg.
        # The setup helper returns the new (proc, log_file) so the
        # finally block below stops the right hub regardless of
        # whether the assertions raise.
        try:
            proc, log_file = _switch_to_plaintext_mode(
                staging_dir, proc, log_file
            )
            test_usertbl_plaintext_when_disabled(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  user.tbl plaintext mode when disabled: {e}")
            failed.append("user.tbl plaintext mode when disabled")
        else:
            log("PASS  user.tbl plaintext mode when disabled")

        # #80 PR4 tier-overlay test: same restart pattern as plaintext
        # mode. We inject a strict tier for level 100 (dummy) so that
        # sending more than burst BMSGs gets throttled at the hub
        # before the broadcast fan-out, proving the overlay path
        # actually replaces the global msg_burst=10 scalar.
        try:
            proc, log_file = _switch_to_tier_mode(
                staging_dir, proc, log_file
            )
            test_ratelimit_tier_msg_throttle(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ratelimit tier overlay throttles BMSG: {e}")
            failed.append("ratelimit tier overlay throttles BMSG")
        else:
            log("PASS  ratelimit tier overlay throttles BMSG")

        # #162 regression test: switch to a public (reg_only=false) hub
        # and verify the ADC PING HSUP branch in hub_dispatch.lua emits
        # ISUP+ADPING and the T1.3 PING-IINF without sandbox errors.
        # Pre-fix, `pairs` was not imported into the dispatcher module
        # so the aggregator loop crashed and pingers saw silent
        # timeouts.
        try:
            proc, log_file = _switch_to_public_hub_mode(
                staging_dir, proc, log_file
            )
            test_ping_hsup_branch_emits_pingsup_response(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ADC PING HSUP emits pingsup response (#162): {e}")
            failed.append("ADC PING HSUP emits pingsup response (#162)")
        else:
            log("PASS  ADC PING HSUP emits pingsup response (#162)")

        # #179: hublist PING UC must exclude bots. Reuses the public-hub
        # mode left active by the #162 test (no extra restart). Tier 1
        # MUST run first - it asserts an empty hub (no humans connected
        # yet) advertises UC0.
        try:
            test_ping_uc_excludes_bots_empty_hub(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC excludes bots, empty hub (#179): {e}")
            failed.append("PING UC excludes bots, empty hub (#179)")
        else:
            log("PASS  PING UC excludes bots, empty hub (#179)")

        try:
            test_ping_uc_excludes_bots_one_human(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC excludes bots, one human (#179): {e}")
            failed.append("PING UC excludes bots, one human (#179)")
        else:
            log("PASS  PING UC excludes bots, one human (#179)")

        try:
            test_ping_uc_survives_reload(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  PING UC survives +reload (#179): {e}")
            failed.append("PING UC survives +reload (#179)")
        else:
            log("PASS  PING UC survives +reload (#179)")

        # #107 dual-stack same-port: flip the v6 ports in cfg.tbl to
        # the same number as the v4 ports and confirm both listeners
        # bind under the new (port, family)-keyed _server registry.
        # Pre-fix the second addserver() call hit the existence check
        # on the port and refused to bind.
        try:
            proc, log_file = _switch_to_dual_stack_same_port_mode(
                staging_dir, proc, log_file
            )
            test_dual_stack_same_port_binds(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  dual-stack same-port binding (#107): {e}")
            failed.append("dual-stack same-port binding (#107)")
        else:
            log("PASS  dual-stack same-port binding (#107)")

        # #231: regression test that the HTTP listener does NOT bind
        # when cfg.tbl http_api_tokens is empty. Flips http_port to
        # the test port, leaves tokens empty, starts hub. Hub writes
        # cfg/api_token.first sample but refuses to bind the listener.
        # This setup also leaves the cfg.tbl in the state expected by
        # _switch_to_http_mode below (http_port + bursts already set).
        try:
            proc, log_file = _switch_to_http_no_tokens_mode(
                staging_dir, proc, log_file
            )
            test_http_no_tokens_means_no_listener(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  http_port set + tokens empty = no listener (#231): {e}")
            failed.append("http_port set + tokens empty = no listener (#231)")
        else:
            log("PASS  http_port set + tokens empty = no listener (#231)")

        # Phase 8 S3 (#82): enable the local HTTP API and exercise the
        # hardened framer + /health router. _switch_to_http_mode now
        # injects the sample token from api_token.first into cfg.tbl
        # http_api_tokens (the operator's documented activation step
        # per #231) before restarting the hub.
        try:
            proc, log_file = _switch_to_http_mode(
                staging_dir, proc, log_file
            )
            test_http_health_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP /health roundtrip + hardening (#82 S3): {e}")
            failed.append("HTTP /health roundtrip + hardening (#82 S3)")
        else:
            log("PASS  HTTP /health roundtrip + hardening (#82 S3)")

        # Phase 1c of #82: the four core read endpoints + rate-limit
        # + per-prefix failed-auth wiring. Shares the same hub
        # instance as the /health roundtrip above (HTTP listener is
        # already up). Idempotency cache semantics are exercised by
        # the unit test (no write endpoint yet to cover smoke-side).
        try:
            test_http_phase1c_endpoints(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 1c endpoints + limits (#82): {e}")
            failed.append("HTTP API Phase 1c endpoints + limits (#82)")
        else:
            log("PASS  HTTP API Phase 1c endpoints + limits (#82)")

        # #178: editable redacted secrets via a masked PUT /v1/config, with the
        # hub's own auth/crypto secrets staying write-protected (default-deny).
        try:
            test_http_config_editable_secrets(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API editable secrets (#178): {e}")
            failed.append("HTTP API editable secrets (#178)")
        else:
            log("PASS  HTTP API editable secrets (#178)")

        # Phase 2 PR-1 of #82 / #198: cmd_disconnect plugin migrated
        # to DELETE /v1/users/{sid}. Logs in a real ADC user, kicks
        # via HTTP, asserts the ADC connection drops + idempotency
        # cache replays the kick response.
        try:
            test_http_phase2_cmd_disconnect(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_disconnect (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_disconnect (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_disconnect (#82 / #198)")

        # Phase 2 PR-2 of #82 / #198: cmd_redirect plugin migrated
        # to POST /v1/users/{sid}/redirect. Same hub instance.
        try:
            test_http_phase2_cmd_redirect(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_redirect (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_redirect (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_redirect (#82 / #198)")

        # Phase 2 PR-3 of #82 / #198: cmd_gag plugin migrated to
        # POST + DELETE /v1/users/{sid}/gag. First plugin migration
        # with persistent state (scripts/data/cmd_gag.tbl).
        try:
            test_http_phase2_cmd_gag(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_gag (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_gag (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_gag (#82 / #198)")

        # Phase 2 PR-4 of #82 / #198: cmd_ban plugin migrated to
        # /v1/bans, /v1/bans/history, /v1/bans/{id}. Last bundled-
        # plugin migration of Phase 2. Raw hub.http_register (not
        # util_http SID helper) since cmd_ban targets are
        # nick / cid / ip, not a single {sid}.
        try:
            test_http_phase2_cmd_ban(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 2 cmd_ban (#82 / #198): {e}")
            failed.append("HTTP API Phase 2 cmd_ban (#82 / #198)")
        else:
            log("PASS  HTTP API Phase 2 cmd_ban (#82 / #198)")

        # #444: POST /v1/bans {permanent:true} - permanent-ban HTTP mirror.
        try:
            test_cmd_ban_permanent_http(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  cmd_ban permanent HTTP (#444): {e}")
            failed.append("cmd_ban permanent HTTP (#444)")
        else:
            log("PASS  cmd_ban permanent HTTP (#444)")

        # Phase 3 PR-1 of #82 / #225: cmd_restart plugin migrated to
        # POST /v1/restart (X-Confirm required). Rejection-only
        # coverage - firing the restart would tear down the smoke hub
        # before downstream tests can run, so the success path is left
        # to production usage. Shares the HTTP listener that's already
        # up.
        try:
            test_http_phase3_cmd_restart(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_restart (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_restart (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_restart (#82 / #225)")

        # Phase 3 PR-2 of #82 / #225: cmd_shutdown plugin migrated to
        # POST /v1/shutdown (X-Confirm required). Rejection-only
        # coverage - firing the shutdown would tear down the smoke
        # hub before downstream tests can run. Shares the HTTP
        # listener.
        try:
            test_http_phase3_cmd_shutdown(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_shutdown (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_shutdown (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_shutdown (#82 / #225)")

        # Phase 3 PR-3 of #82 / #225: cmd_errors plugin migrated to
        # GET /v1/log/error?lines=N. Read-only log-tail endpoint;
        # pattern-setter for PR-4 etc_cmdlog. Shares the HTTP
        # listener.
        try:
            test_http_phase3_cmd_errors(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 cmd_errors (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 cmd_errors (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 cmd_errors (#82 / #225)")

        # Phase 3 PR-4 of #82 / #225: etc_cmdlog plugin migrated to
        # GET /v1/log/cmd?lines=N. Mirror of PR-3 (cmd_errors).
        try:
            test_http_phase3_etc_cmdlog(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 etc_cmdlog (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 etc_cmdlog (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 etc_cmdlog (#82 / #225)")

        # Phase 3 PR-5 of #82 / #225: etc_log_cleaner plugin migrated
        # to DELETE /v1/log/{name}. Truncates a log file via the API
        # and verifies the on-disk size. Shares the HTTP listener.
        try:
            test_http_phase3_etc_log_cleaner(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 3 etc_log_cleaner (#82 / #225): {e}")
            failed.append("HTTP API Phase 3 etc_log_cleaner (#82 / #225)")
        else:
            log("PASS  HTTP API Phase 3 etc_log_cleaner (#82 / #225)")

        # Phase 4 PR-1 of #82 / #249: etc_chatlog plugin migrated to
        # GET /v1/chatlog?lines=N. Read scope, tail-style mirror of
        # Phase 3 PR-3 (cmd_errors) over the in-memory chat-history
        # buffer.
        try:
            test_http_phase4_etc_chatlog(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_chatlog (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_chatlog (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_chatlog (#82 / #249)")

        # Phase 4 PR-2 of #82 / #249: etc_records plugin migrated to
        # GET + DELETE /v1/records. GET snapshot + DELETE-reset that
        # rebinds the file-local records upvalue (regression-guard
        # for the reference_lua_plugin_exports rebind hazard).
        try:
            test_http_phase4_etc_records(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_records (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_records (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_records (#82 / #249)")

        # Phase 4 PR-3 of #82 / #249: etc_blacklist plugin migrated to
        # GET /v1/blacklist + DELETE /v1/blacklist/{nick}. Self-seeds
        # via POST /v1/registered + DELETE /v1/registered/{nick} with
        # X-Confirm + reason, so it is order-independent of the
        # registered-users family tests further down the runner.
        try:
            test_http_phase4_etc_blacklist(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_blacklist (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_blacklist (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_blacklist (#82 / #249)")

        # Phase 4 PR-4 of #82 / #249: hub_runtime plugin migrated to
        # GET + PUT /v1/runtime. GET returns raw integer seconds for
        # session + total; PUT generalises ADC's reset-only verb to
        # "set runtime to N" via body {hubruntime: int >= 0}.
        try:
            test_http_phase4_hub_runtime(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 hub_runtime (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 hub_runtime (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 hub_runtime (#82 / #249)")

        # Phase 4 PR-5 of #82 / #249: etc_msgmanager plugin migrated
        # to GET /v1/msgmanager + POST/DELETE /v1/msgmanager/{nick}.
        # Combined GET (blocks + settings) + offline-tolerant block
        # / unblock by firstnick.
        try:
            test_http_phase4_etc_msgmanager(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_msgmanager (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_msgmanager (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_msgmanager (#82 / #249)")

        # Phase 4 PR-6 of #82 / #249: cmd_usercleaner plugin migrated
        # to GET/DELETE /v1/usercleaner/{expired,ghosts}. Both DELETEs
        # require X-Confirm (router-enforced via _xconfirm_required).
        try:
            test_http_phase4_cmd_usercleaner(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 cmd_usercleaner (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 cmd_usercleaner (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 cmd_usercleaner (#82 / #249)")

        # Phase 4 PR-7 of #82 / #249: etc_trafficmanager plugin
        # migrated to GET /v1/trafficmanager/{settings,blocks} +
        # POST/DELETE /v1/trafficmanager/blocks/{nick}. Offline-
        # tolerant block + unblock; 409 on already-blocked.
        try:
            test_http_phase4_etc_trafficmanager(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Phase 4 etc_trafficmanager (#82 / #249): {e}")
            failed.append("HTTP API Phase 4 etc_trafficmanager (#82 / #249)")
        else:
            log("PASS  HTTP API Phase 4 etc_trafficmanager (#82 / #249)")

        # #82 deferred Phase-2-spec: cmd_mass migrated to
        # POST /v1/announce. All three scope variants + schema /
        # validator rejects + catalog.
        try:
            test_http_announce(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_mass (#82): {e}")
            failed.append("HTTP API cmd_mass (#82)")
        else:
            log("PASS  HTTP API cmd_mass (#82)")

        # #82 deferred Phase-2-spec: cmd_topic migrated to
        # POST /v1/topic. Set + reset + schema-reject + catalog.
        # Runs before reload (which clears the topic_tbl state via
        # restartscripts).
        try:
            test_http_topic(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_topic (#82): {e}")
            failed.append("HTTP API cmd_topic (#82)")
        else:
            log("PASS  HTTP API cmd_topic (#82)")

        # #327: etc_aliases CRUD over /v1/aliases. Anonymous gate +
        # create + list + duplicate-409 + bad-target-404 +
        # bad-alias-400 + delete + delete-404 + catalog.
        try:
            test_http_aliases(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API etc_aliases (#327): {e}")
            failed.append("HTTP API etc_aliases (#327)")
        else:
            log("PASS  HTTP API etc_aliases (#327)")

        # #82 registered-users family PR-1 (#236): cmd_reg migrated to
        # GET / POST /v1/registered + PATCH /v1/registered/{nick}.
        # Pagination + create + duplicate-409 + caller-pw + patch +
        # password-not-leaked + catalog. Runs BEFORE reload so the
        # created users are still in-memory when reload fires (reload
        # asserts route-table survival, not data survival).
        try:
            test_http_registered_users_pr1(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_reg (#82 / #236 PR-1): {e}")
            failed.append("HTTP API cmd_reg (#82 / #236 PR-1)")
        else:
            log("PASS  HTTP API cmd_reg (#82 / #236 PR-1)")

        # #82 registered-users family PR-2 (#236): cmd_accinfo
        # migrated to GET /v1/registered/{nick}. Requires PR-1's
        # smoke_pr1_a + smoke_pr1_b reg-users to exist in this hub
        # session, so this slot must follow PR-1's test.
        try:
            test_http_registered_get_pr2(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_accinfo (#82 / #236 PR-2): {e}")
            failed.append("HTTP API cmd_accinfo (#82 / #236 PR-2)")
        else:
            log("PASS  HTTP API cmd_accinfo (#82 / #236 PR-2)")

        # #82 registered-users family PR-3 (#236): cmd_setpass
        # migrated to PUT /v1/registered/{nick}/password.
        try:
            test_http_setpass_pr3(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_setpass (#82 / #236 PR-3): {e}")
            failed.append("HTTP API cmd_setpass (#82 / #236 PR-3)")
        else:
            log("PASS  HTTP API cmd_setpass (#82 / #236 PR-3)")

        # #82 registered-users family PR-4 (#236): cmd_nickchange
        # migrated to PUT /v1/registered/{nick}/nick. Renames
        # smoke_pr1_b (created by PR-1) so PR-3's smoke_pr1_a is
        # unaffected.
        try:
            test_http_nickchange_pr4(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_nickchange (#82 / #236 PR-4): {e}")
            failed.append("HTTP API cmd_nickchange (#82 / #236 PR-4)")
        else:
            log("PASS  HTTP API cmd_nickchange (#82 / #236 PR-4)")

        # #82 registered-users family PR-5 (#236): cmd_upgrade
        # migrated to PUT /v1/registered/{nick}/level.
        try:
            test_http_upgrade_pr5(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_upgrade (#82 / #236 PR-5): {e}")
            failed.append("HTTP API cmd_upgrade (#82 / #236 PR-5)")
        else:
            log("PASS  HTTP API cmd_upgrade (#82 / #236 PR-5)")

        # #82 registered-users family PR-6 (#236): cmd_delreg
        # migrated to DELETE /v1/registered/{nick} with X-Confirm.
        # Targets smoke_pr4_renamed (PR-4 renamed smoke_pr1_b ->
        # smoke_pr4_renamed) so PR-5's smoke_pr1_a stays intact.
        # Last PR of the family; tracker #236 closes after merge.
        try:
            test_http_delreg_pr6(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_delreg (#82 / #236 PR-6): {e}")
            failed.append("HTTP API cmd_delreg (#82 / #236 PR-6)")
        else:
            log("PASS  HTTP API cmd_delreg (#82 / #236 PR-6)")

        # #239: cmd_ban exported bans table goes stale after the
        # `+ban clear` rebind; cmd_accinfo's import-time bans_tbl
        # snapshot keeps surfacing the old ban entry. Repros via
        # ADC `+ban clear` + GET /v1/registered/{nick}. Runs after
        # the family so smoke_pr1_a still exists.
        try:
            test_239_cmd_ban_stale_bans_ref(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  cmd_ban stale bans ref (#239): {e}")
            failed.append("cmd_ban stale bans ref (#239)")
        else:
            log("PASS  cmd_ban stale bans ref (#239)")

        # #320: cmd_ban offline-by-nick path silently bypassed the
        # hierarchy check that fires on the online path; a low-level
        # op could ban a higher-level offline user (incl. hubowner).
        # Repros via two POST /v1/registered + an ADC `+ban` from the
        # low-level op + GET /v1/bans to verify no entry was added.
        # Self-cleaning so it can run anywhere in the HTTP family.
        try:
            test_320_offline_ban_hierarchy(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  cmd_ban offline hierarchy bypass (#320): {e}")
            failed.append("cmd_ban offline hierarchy bypass (#320)")
        else:
            log("PASS  cmd_ban offline hierarchy bypass (#320)")

        # #83: Prometheus /metrics opt-in plugin. Default-off in
        # cfg, so first GET /metrics returns 404. Test flips
        # etc_prometheus_activate=true in cfg.tbl and triggers
        # +reload via the HTTP API to re-evaluate the plugin's
        # activate gate. Placed BEFORE test_http_reload so the
        # prometheus-side reload is its own self-contained
        # exercise rather than mixed into the cmd_reload test.
        try:
            test_http_prometheus_metrics(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API Prometheus /metrics (#83): {e}")
            failed.append("HTTP API Prometheus /metrics (#83)")
        else:
            log("PASS  HTTP API Prometheus /metrics (#83)")

        # #82 deferred Phase-2-spec: cmd_reload migrated to
        # POST /v1/reload (X-Confirm). Exercises both reject + success
        # paths. Placed last in the HTTP suite so reload-fires
        # naturally followed by inf_integer_clamps (which queries
        # /v1/users) acting as a route-survival sanity check.
        try:
            test_http_reload(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API cmd_reload (#82): {e}")
            failed.append("HTTP API cmd_reload (#82)")
        else:
            log("PASS  HTTP API cmd_reload (#82)")

        # #84 audit log end-to-end: +reg via ADC + POST via HTTP +
        # +delreg via ADC -> three lines in log/audit-YYYY-MM-DD.jsonl
        # + same three events on GET /v1/events?types=audit + tail
        # via GET /v1/log/audit?lines=N. The first check (ADC +reg
        # produces a log line) IS the issue's primary acceptance
        # criterion. Runs after test_http_reload so the route table
        # is known-good - the audit endpoints depend on the same
        # plugin sandbox having re-registered post-reload.
        try:
            test_audit_log_84(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  audit log end-to-end (#84): {e}")
            failed.append("audit log end-to-end (#84)")
        else:
            log("PASS  audit log end-to-end (#84)")

        # #81 etc_clientblocker end-to-end: HTTP POST adds a unique
        # smoke pattern, a connection with VE matching the pattern
        # gets ISTA 231 + dropped (the issue acceptance criterion),
        # a non-matching VE logs in normally, HTTP DELETE removes
        # the pattern, the previously-blocked VE is now allowed,
        # and the audit JSONL gained the .add/.kick/.remove triplet
        # with the right meta.pattern. Runs after test_audit_log_84
        # so the same audit log file is exercised by both checks.
        try:
            test_clientblocker_81(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  client blocker end-to-end (#81): {e}")
            failed.append("client blocker end-to-end (#81)")
        else:
            log("PASS  client blocker end-to-end (#81)")

        # #78 Phase C HTTP API for the unified blocklist. Four
        # endpoints (GET list, GET counts, POST, DELETE); anon-auth
        # sanity check + happy path per verb + bad-cidr / missing-
        # cidr / bad-id / not-found rejections + persistence check
        # on scripts/data/etc_blocklist.tbl + endpoints-catalog
        # sanity. Uses HTTP (not BMSG) so ratelimit_tier overlay is
        # irrelevant here.
        try:
            test_http_phase_c_blocklist(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API blocklist (#78 Phase C): {e}")
            failed.append("HTTP API blocklist (#78 Phase C)")
        else:
            log("PASS  HTTP API blocklist (#78 Phase C)")

        try:
            test_http_phase_d_whitelist(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API whitelist (#78 allowlist Phase D): {e}")
            failed.append("HTTP API whitelist (#78 allowlist Phase D)")
        else:
            log("PASS  HTTP API whitelist (#78 allowlist Phase D)")

        # #261 plugin-management endpoints: GET /v1/plugins (read) +
        # PUT /v1/plugins/{name}/enabled (admin). Full toggle cycle on
        # the table-form etc_motd entry + negative coverage (403 on
        # string-form, 404 on missing, 400 on bad body). Triggers two
        # POST /v1/reload calls so it must run AFTER test_http_reload
        # which has stricter pre-conditions on idempotency state.
        try:
            test_http_plugins_api(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API plugins (#261): {e}")
            failed.append("HTTP API plugins (#261)")
        else:
            log("PASS  HTTP API plugins (#261)")

        # #264 PR-A: filter + sort query params on /v1/users +
        # /v1/registered. Runs after registered_users_pr1 (which seeds
        # smoke_pr1_a / _b) and plugins_api (which has its own cfg.tbl
        # restore semantics). Logs in a fresh dummy session for the
        # /v1/users portion.
        try:
            test_http_filter_sort_pr_a(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API filter+sort PR-A (#264): {e}")
            failed.append("HTTP API filter+sort PR-A (#264)")
        else:
            log("PASS  HTTP API filter+sort PR-A (#264)")

        # #262 config-management endpoints: GET /v1/config (read)
        # + PUT /v1/config/{key} (admin). Covers denylist masking,
        # apply-status classification, and the four negative paths.
        # Restores cfg.tbl bare-key format at the end (matches the
        # #261 plugins-api test pattern).
        try:
            test_http_config_api(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API config (#262): {e}")
            failed.append("HTTP API config (#262)")
        else:
            log("PASS  HTTP API config (#262)")

        # #263 PR-A: GET /v1/events polling. Triggers a dummy login
        # to verify the firelistener-tap captures real events,
        # then exercises since=/types=/latest semantics.
        try:
            test_http_events_pr_a(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API events PR-A (#263): {e}")
            failed.append("HTTP API events PR-A (#263)")
        else:
            log("PASS  HTTP API events PR-A (#263)")

        # #263 PR-B: long-poll via ?wait=<seconds>. Tests the
        # deadline-driven empty resolve (tick) AND the event-driven
        # resume (emit notifies waiters). Uses a Python thread to
        # trigger the login while the long-poll socket is held open.
        try:
            test_http_events_pr_b_longpoll(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API events PR-B long-poll (#263): {e}")
            failed.append("HTTP API events PR-B long-poll (#263)")
        else:
            log("PASS  HTTP API events PR-B long-poll (#263)")

        # #264 PR-B: wire-up regression for the 5 list endpoints
        # newly migrated to core/http_filter.lua. PR-A already
        # exercised the helper exhaustively; PR-B just confirms each
        # new wire (bans/blacklist/msgmanager/trafficmanager/
        # usercleaner expired+ghosts) sends an unknown-filter-field
        # query through the helper and gets 400 instead of the
        # pre-fix silent-ignore 200.
        try:
            test_http_filter_sort_pr_b(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API filter+sort PR-B (#264): {e}")
            failed.append("HTTP API filter+sort PR-B (#264)")
        else:
            log("PASS  HTTP API filter+sort PR-B (#264)")

        # #275 holistic review - Security PR regression tests:
        # audit_redact_body redaction, unauth body skip, cmd_ban
        # target sanitisation, idempotency cache path-scoping,
        # ratelimit cfg apply_status classification.
        try:
            test_http_security_holistic_review(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API holistic review security (#275): {e}")
            failed.append("HTTP API holistic review security (#275)")
        else:
            log("PASS  HTTP API holistic review security (#275)")

        # #275 COV-1 / COV-5 holistic review follow-up - Coverage PR:
        # auth scope matrix (read token on admin endpoints -> 403) +
        # X-Request-ID echo assertion. Uses SMOKE_READ_TOKEN fixture
        # injected at active-mode setup time.
        try:
            test_http_auth_scope_matrix(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API auth scope matrix (#275 COV-1): {e}")
            failed.append("HTTP API auth scope matrix (#275 COV-1)")
        else:
            log("PASS  HTTP API auth scope matrix (#275 COV-1)")

        # #275 COV-3 holistic review follow-up - Coverage PR:
        # /v1/events cursor_lost path + no-waiting-on-stale-cursor
        # rule. Shrinks buffer to 16 (validator min), bursts 20
        # topic_changed events, asserts cursor_lost=true and immediate
        # return on wait=2.
        try:
            test_http_events_cursor_lost(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API events cursor_lost (#275 COV-3): {e}")
            failed.append("HTTP API events cursor_lost (#275 COV-3)")
        else:
            log("PASS  HTTP API events cursor_lost (#275 COV-3)")

        # #275 COV-N3 / COV-N4 / COV-5 - small coverage additions:
        # GET /v1/users/{sid} positive + /v1/log/api lines boundary
        # + X-Request-ID echo on the error path.
        try:
            test_http_coverage_addons(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  HTTP API coverage addons (#275): {e}")
            failed.append("HTTP API coverage addons (#275)")
        else:
            log("PASS  HTTP API coverage addons (#275)")

        # Phase 8a F-INF-2 (#219): per-field integer clamps on user
        # accessors. Logs in with poison BINF (SS-1 / SF=10^18 / SL-1
        # / HN/HR/HO out-of-range) and asserts the /v1/users JSON
        # serialisation shows clamped values. Doubles as a Phase 7d
        # (#65) regression guard: login MUST succeed (parser stays
        # permissive). Shares the HTTP listener that's already up.
        try:
            test_inf_integer_clamps(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  F-INF-2 integer clamps on user accessors (#219): {e}")
            failed.append("F-INF-2 integer clamps on user accessors (#219)")
        else:
            log("PASS  F-INF-2 integer clamps on user accessors (#219)")

        # #243: cfg drift - `usr_nick_prefix_activate=true` AND
        # `usr_nick_prefix_prefix_table={}` previously crashed the
        # ADC `+setpass / +nickchange / +upgrade / +delreg` paths
        # on `prefix_table[level]` nil-concat. Family-wide sweep
        # added `or ""` index guards. Runs as a mode-switch since
        # cfg.tbl gets rewritten; subsequent kill_wrong_ips /
        # BLOM / ZLIF tests don't depend on prefix_table content,
        # so they compose fine on top of the cleared table.
        try:
            proc, log_file = _switch_to_partial_prefix_table_mode(
                staging_dir, proc, log_file
            )
            test_243_prefix_table_nil_no_adc_crash(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  prefix_table nil cfg-drift no ADC crash (#243): {e}")
            failed.append("prefix_table nil cfg-drift no ADC crash (#243)")
        else:
            log("PASS  prefix_table nil cfg-drift no ADC crash (#243)")

        # #214 Gap 2: flip kill_wrong_ips=false (the NAT-weird opt-out)
        # and verify the hub stamps the verified userip over a
        # mismatched primary-IP claim before broadcasting the BINF.
        # Falsifiable: pre-#214 the lie was forwarded as-is. The
        # cfg flip persists for subsequent tests, which is fine -
        # no currently-registered downstream test sends a mismatching
        # primary-IP claim from 127.0.0.1, so the opt-out has no
        # observable effect on BLOM / ZLIF / combined / hub_listen.
        try:
            proc, log_file = _switch_to_kill_wrong_ips_off_mode(
                staging_dir, proc, log_file
            )
            test_kill_wrong_ips_off_stamps_userip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  kill_wrong_ips=false stamps userip (#214 Gap 2): {e}")
            failed.append("kill_wrong_ips=false stamps userip (#214 Gap 2)")
        else:
            log("PASS  kill_wrong_ips=false stamps userip (#214 Gap 2)")

        # Phase 8 S5 (#147 T2.2): enable BLOM and exercise hash-search
        # routing + the keyword-search broadcast regression. Runs
        # BEFORE the ZLIF tests so BLOM does not have to coexist
        # with hub-side outbound deflate (which would force the test
        # client to inflate the HGET frame).
        try:
            proc, log_file = _switch_to_blom_mode(
                staging_dir, proc, log_file
            )
            test_blom_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  BLOM hash-search routing roundtrip (#147 T2.2): {e}")
            failed.append("BLOM hash-search routing roundtrip (#147 T2.2)")
        else:
            log("PASS  BLOM hash-search routing roundtrip (#147 T2.2)")

        # Phase 8 S4b (#147 T3.2): flip zlif_enabled on, run a full
        # ADC login + +help reply over zlib-compressed inbound. Last
        # test because the cfg mutation is non-trivial and no later
        # test should depend on the post-ZLIF hub state.
        try:
            proc, log_file = _switch_to_zlif_mode(
                staging_dir, proc, log_file
            )
            test_zlif_roundtrip(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ZLIF stream compression roundtrip (#147 T3.2): {e}")
            failed.append("ZLIF stream compression roundtrip (#147 T3.2)")
        else:
            log("PASS  ZLIF stream compression roundtrip (#147 T3.2)")

        # Security review B1 follow-up: pre-HSUP BZON must be rejected
        # with ISTA 240, not silently install the inflate stage on an
        # un-identified peer.
        try:
            test_zlif_pre_hsup_zon_rejected(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  ZLIF pre-HSUP ZON rejected (S4b B1): {e}")
            failed.append("ZLIF pre-HSUP ZON rejected (S4b B1)")
        else:
            log("PASS  ZLIF pre-HSUP ZON rejected (S4b B1)")

        # #192 combined-mode regression: with both blom_enabled=true
        # and zlif_enabled=true (the persistent post-ZLIF cfg state)
        # the hub MUST splice the BLOM counted-binary capture BEFORE
        # the ADC-line framer (i.e. AFTER inflate). Pre-fix the
        # counted stage was prepended and saw raw deflated bytes,
        # producing a corrupt filter -> false-negative routing.
        try:
            test_blom_zlif_combined(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  BLOM+ZLIF combined-mode routing (#192): {e}")
            failed.append("BLOM+ZLIF combined-mode routing (#192)")
        else:
            log("PASS  BLOM+ZLIF combined-mode routing (#192)")

        # etc_regserver_announce end-to-end: non-blocking outbound
        # POST via core/http_client to a loopback fake regserver.
        # Runs before the hub_listen test (which restricts the bind).
        capture = None
        try:
            capture = _RegserverCapture(TEST_PORT_REGSERVER)
            proc, log_file = _switch_to_regserver_announce_mode(
                staging_dir, proc, log_file, TEST_PORT_REGSERVER
            )
            test_regserver_announce(staging_dir, capture, proc=proc)
        except Exception as e:
            log(f"FAIL  regserver announce (http_client e2e): {e}")
            failed.append("regserver announce (http_client e2e)")
        else:
            log("PASS  regserver announce (http_client e2e)")
        finally:
            if capture is not None:
                capture.close()

        # #423: hub_bot_email=true + a hub_email carrying a backslash - the
        # hub-bot EM field must be escaped, else (since #419) the hub discards
        # its own hub-bot INF. Runs before hub_listen (which is truly last).
        try:
            proc, log_file = _switch_to_hubbot_email_mode(
                staging_dir, proc, log_file
            )
            test_hubbot_email_escaped(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  hub-bot EM field escaped (#423): {e}")
            failed.append("hub-bot EM field escaped (#423)")
        else:
            log("PASS  hub-bot EM field escaped (#423)")

        # #186: hub_listen must actually restrict the bind address
        # (last test - mutates hub_listen + blanks v6; nothing after).
        try:
            proc, log_file = _switch_to_hub_listen_loopback_mode(
                staging_dir, proc, log_file
            )
            test_hub_listen_honored(staging_dir, proc=proc)
        except Exception as e:
            log(f"FAIL  hub_listen honored / loopback-only (#186): {e}")
            failed.append("hub_listen honored / loopback-only (#186)")
        else:
            log("PASS  hub_listen honored / loopback-only (#186)")
    finally:
        if proc is not None:
            stop_hub(proc, log_file)
        if not args.keep_staging:
            shutil.rmtree(staging_dir.parent, ignore_errors=True)
        else:
            log(f"staging kept at {staging_dir.parent}")

    if failed:
        log(f"FAILED  {len(failed)} test(s): {', '.join(failed)}")
        return 1
    log("OK  all tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
