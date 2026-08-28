# Installing luadch

This document covers **post-build deployment** — what to do once
[BUILDING.md](BUILDING.md) has produced a `build/install/luadch/`
directory. For configuring the hub afterwards, see
[CONFIGURATION.md](CONFIGURATION.md).

---

## What you have after a build

`cmake --install build` produces a self-contained directory:

```
build/install/luadch/
├── luadch          (Linux) or Luadch.exe (Windows) — the hub binary
├── liblua.so       (Linux) or lua.dll (Windows)
├── libssl-3-x64.dll, libcrypto-3-x64.dll        (Windows only)
├── lib/                                          bundled Lua/C dependency modules
├── core/           Lua core modules
├── scripts/        bundled command / bot / utility scripts
├── cfg/            cfg.tbl, user.tbl, and other default templates
├── certs/          TLS cert generation helpers
├── lang/           hub-side language files
├── docs/           embedded docs
└── log/            empty; the hub writes here at runtime
```

The directory is portable — copy it anywhere on a target machine and
run from there. There are no absolute path assumptions in the build.

---

## Linux deployment

### Where to put the install directory

Conventional choices:

| Path                  | When to pick it                                       |
|-----------------------|-------------------------------------------------------|
| `/opt/luadch/`        | Single hub on a dedicated server                      |
| `/srv/luadch/`        | Same as above, FHS-recommended for served data        |
| `~/luadch/`           | Per-user hub (no root needed)                         |
| `/var/luadch/<name>/` | Multiple hubs sharing a host                          |

```sh
# As root, deploy to /opt
sudo cp -r build/install/luadch /opt/
sudo chown -R luadch:luadch /opt/luadch    # see "service user" below
```

### Service user

Run the hub as an unprivileged user, never as root. Create one:

```sh
sudo useradd --system --home-dir /opt/luadch --shell /usr/sbin/nologin luadch
```

### File permissions

The two configuration tables hold credentials and registration state.
Tighten their permissions so other local users on the host cannot read
them:

```sh
sudo chmod 600 /opt/luadch/cfg/user.tbl    # accounts (incl. the dummy default password)
sudo chmod 600 /opt/luadch/cfg/cfg.tbl     # may hold bot passwords / API tokens / passphrases
```

The `log/` directory must be writable by the service user:

```sh
sudo chmod 750 /opt/luadch/log
```

Everything else (`core/`, `scripts/`, `lib/`, …) can stay read-only for
the service user — the hub does not modify its own code at runtime.

### systemd unit

Drop this into `/etc/systemd/system/luadch.service`:

```ini
[Unit]
Description=Luadch ADC Hub
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=luadch
Group=luadch
WorkingDirectory=/opt/luadch
ExecStart=/opt/luadch/luadch
Restart=on-failure
RestartSec=5

# Hardening (optional but recommended)
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/luadch/log /opt/luadch/cfg /opt/luadch/scripts/data
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`WorkingDirectory=` is optional - the hub anchors its own runtime
paths to the binary's directory at startup (Phase 6b / issue #12),
so it works regardless of the CWD systemd hands it. We still set it
explicitly above for clarity and so the unit reads the same on older
releases that did require it.

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now luadch
sudo systemctl status luadch
```

### Logs

The hub writes to `log/` inside the install directory. systemd captures
stdout / stderr separately via journald:

```sh
sudo journalctl -u luadch -f          # live
sudo journalctl -u luadch --since today
```

### Network / firewall

- TCP **5001** - TLS ADC (`adcs://`), the default listener.
- TCP **5000** - plain ADC (`adc://`), bound **only if you enable `tcp_ports`**. Fresh installs are TLS-only (`tcp_ports = {}`), so 5000 is not listening by default.

Open whichever you actually use. For a public hub, you almost certainly
only want TLS:

```sh
# UFW
sudo ufw allow 5001/tcp

# firewalld
sudo firewall-cmd --add-port=5001/tcp --permanent
sudo firewall-cmd --reload
```

If your hub is behind NAT, port-forward the same port to the host.

---

## Windows deployment

### Where to put the install directory

`C:\luadch\` or `D:\luadch\` works. The hub's only requirement is that
its working directory at launch time is the install root.

### Run as a service

Windows does not natively run console executables as services. Use
[NSSM](https://nssm.cc/) (the Non-Sucking Service Manager):

```cmd
:: install
nssm install luadch C:\luadch\Luadch.exe
nssm set luadch AppDirectory C:\luadch
nssm set luadch DisplayName "Luadch ADC Hub"
nssm set luadch Description "DC++ ADC hub server"
nssm set luadch Start SERVICE_AUTO_START
nssm set luadch AppStdout C:\luadch\log\stdout.log
nssm set luadch AppStderr C:\luadch\log\stderr.log

:: start it
nssm start luadch
```

Manage afterwards via `services.msc` or `nssm restart luadch` etc.

### Windows Defender / firewall

Allow the binary on the firewall the first time you run it
(`netsh advfirewall firewall add rule name="Luadch ADCS" dir=in
action=allow protocol=TCP localport=5001`). If Defender quarantines
`Luadch.exe` on a corporate-managed machine, add a path exclusion for
`C:\luadch\`.

---

## Backups

What is worth backing up:

| Path                       | Why                                    |
|----------------------------|----------------------------------------|
| `cfg/cfg.tbl`              | hub configuration, edited by you       |
| `cfg/user.tbl`             | registered users + password-equivalents (cleartext-equivalent as ADC requires; encrypted at rest - see SECURITY.md) |
| `cfg/user.tbl.bak`         | rolling backup the hub maintains itself|
| `scripts/data/*.tbl`       | per-script state (bans, chatlog, etc.) |
| `certs/cacert.pem`, `serverkey.pem`, `servercert.pem` | TLS keys; users will see a different keyprint after a regen |

Everything else (`core/`, `scripts/*.lua`, `lib/`, `lang/`) reproduces
from a fresh build.

Rsync-style nightly backup script template (a simple *unencrypted* mirror -
note it copies `user.tbl` and `master.key` together, the exact bundling
[`docs/SECURITY.md`](SECURITY.md) warns about):

```sh
#!/bin/sh
set -eu
DST=/var/backups/luadch
mkdir -p "$DST"
rsync -a --delete /opt/luadch/cfg/        "$DST"/cfg/
rsync -a --delete /opt/luadch/certs/      "$DST"/certs/
rsync -a --delete /opt/luadch/scripts/data/ "$DST"/scripts-data/
```

For an encrypted, rotating backup with an offline restore, prefer the built-in
backup feature instead: [`docs/BACKUP.md`](BACKUP.md) (`+backup`, AES-256-GCM
`.ldbk` artifacts, `./luadch --restore`).

---

## Updating the hub

When you pull new code and rebuild:

```sh
# 1. New build
git pull
cmake --build build -j$(nproc)
cmake --install build              # writes to build/install/luadch/

# 2. Stop the running hub
sudo systemctl stop luadch

# 3. Replace the read-only parts only - keep cfg/, certs/, scripts/data/,
#    scripts/lang/, log/
sudo rsync -a --delete \
    --exclude='/cfg/' --exclude='/certs/' --exclude='/log/' \
    --exclude='/scripts/data/' --exclude='/scripts/lang/' \
    build/install/luadch/ /opt/luadch/

# 4. Restart
sudo systemctl start luadch
```

The exclude list is the contract: those are the directories the
running hub considers state, and the new build's defaults must not
clobber them. `scripts/lang/` holds operator-editable translations and
MOTD text (owned by you / Weblate post-migration), so it is excluded too.

> **⚠️ `--delete` removes any custom plugin under `scripts/` that is not
> present in the new build.** If you drop your own `.lua` files into
> `scripts/`, either add an `--exclude` for each, or exclude `scripts/`
> wholesale and hand-merge bundled-plugin updates - the same auto-sync
> contract the Docker image follows (see [DOCKER.md](DOCKER.md)).

If a release notes mentions a `cfg/cfg.tbl` migration, copy any new
keys from `build/install/luadch/cfg/cfg.tbl` into `/opt/luadch/cfg/cfg.tbl`
manually before restarting.

---

## Verifying the install

Once running:

```sh
# port bound?
ss -tln | grep -E ':500[01]'

# hub responding to ADC handshake?
# Default installs are TLS-only on 5001, so speak TLS:
printf 'HSUP ADBASE ADTIGR\n' | openssl s_client -quiet -connect 127.0.0.1:5001 2>/dev/null | head
# Expect: ISUP ... / ISID ... / IINF ...
# Plain 5000 only exists if you enabled tcp_ports; then the nc form works:
#   printf 'HSUP ADBASE ADTIGR\n' | nc -q1 127.0.0.1 5000 | head

# active sessions (after first connect)
grep -c "init.lua" /opt/luadch/log/*.log    # rough heartbeat
```

Then point an ADC client (e.g. AirDC++) at `adcs://your.host:5001` (TLS,
the default) - or `adc://your.host:5000` (plain) only if you enabled
`tcp_ports` - and log in as `dummy` / `test` for the first time. Read [CONFIGURATION.md](CONFIGURATION.md) for the
register-yourself / delete-dummy steps **before** opening the hub to
real users.
