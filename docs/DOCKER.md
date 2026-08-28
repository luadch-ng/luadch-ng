# Running luadch in Docker

The official image is built from this repo's [`docker/Dockerfile`](../docker/Dockerfile)
and published to GitHub Container Registry on every release tag, on
`master` push, and on `dev` push:

| Tag pattern | Source |
|---|---|
| `ghcr.io/luadch-ng/luadch-ng:vX.Y.Z` | exact release |
| `ghcr.io/luadch-ng/luadch-ng:vX.Y`   | latest patch in `vX.Y` line |
| `ghcr.io/luadch-ng/luadch-ng:vX`     | latest minor in `vX` line |
| `ghcr.io/luadch-ng/luadch-ng:latest` | latest released `vX.Y.Z` |
| `ghcr.io/luadch-ng/luadch-ng:master` | bleeding-edge (post-merge, pre-release) |
| `ghcr.io/luadch-ng/luadch-ng:dev`    | rolling `dev` branch - next-merge candidate, the testhub image |

Available platforms: `linux/amd64`, `linux/arm64`.

- 🛡️ [Security model](#security-model)
- 🚀 [First-time setup](#first-time-setup)
- 📁 [Mount layout](#mount-layout)
- ⚙️ [Configuration changes](#configuration-changes)
- 💾 [Backups](#backups)
- 🔐 [TLS-only deployments](#tls-only-deployments)
- 🌐 [IPv6](#ipv6)
- 🔄 [Updating](#updating)
- 🔧 [Troubleshooting](#troubleshooting)
- 🏗️ [Building the image yourself](#building-the-image-yourself)

---

## Security model

The image runs as the unprivileged user `luadch` (UID/GID 1000) -
**never as root**, no `s6-overlay`, no `gosu` drop-priv step. Operators
who want host bind-mount files owned by their own UID override at run
time with `--user $(id -u):$(id -g)` (or the `user:` key in compose).

The `/defaults` tree shipped in the image is world-readable so the
entrypoint can copy from it under any `--user` override.

## First-time setup

```sh
git clone https://github.com/luadch-ng/luadch-ng.git
cd luadch-ng
cp .env.example .env
# adjust PUID / PGID in .env if `id -u` on your host is not 1000

mkdir -p cfg scripts certs log secrets
docker compose up -d
```

On first start the container's entrypoint will:

1. **Seed empty mounts** from `/defaults`: `cfg/`, `scripts/`, `certs/`
   are populated from the bundled defaults if you mounted them empty.
   If `cfg/` is only *partially* populated (e.g. the hub already wrote
   `cfg/geoip/` or a `blocklist-export`), a missing `cfg.tbl` / `user.tbl`
   is still restored from the defaults - add-only, so your own edits are
   never overwritten.
2. **Auto-generate a TLS cert** in-hub (`core/cert_bootstrap.lua`, #77) as
   a self-signed P-256 ECDSA pair if none exists.
3. **Log the keyprint** so you can build the `adcs://` URL.

Pull the keyprint from the logs:

```sh
docker compose logs luadch | grep keyprint
# [entrypoint] TLS keyprint (SHA256, base32):  4OVZAB...
# [entrypoint] share with users as:  adcs://<your-host>:5001/?kp=SHA256/4OVZAB...
```

Replace `<your-host>` with the hostname / IP your users will connect
to. The `kp=SHA256/...` parameter is the trust anchor in the DC++
ecosystem - clients pin against it instead of validating a CA chain.

### First login

```
Nick:     dummy
Password: test
Address:  adcs://127.0.0.1:5001/?kp=SHA256/<as logged>   (TLS, the default)
          adc://127.0.0.1:5000                            (plain, only if you enabled tcp_ports)
```

After login, register yourself, delete the bootstrap account, reload:

```
+reg <yournick> 100
+delreg dummy
+reload
```

See [`docs/CONFIGURATION.md`](CONFIGURATION.md) for the full first-run
walk-through.

## Mount layout

The compose file sets up five bind mounts:

| Host path | Container path | Purpose |
|---|---|---|
| `./cfg/`     | `/opt/luadch/cfg/`     | Hub settings (`cfg.tbl`), encrypted user database (`user.tbl`) |
| `./scripts/` | `/opt/luadch/scripts/` | Plugin scripts. Seeded with the bundled set; you can drop in custom plugins or override individual files. |
| `./certs/`   | `/opt/luadch/certs/`   | TLS server cert + key. Replace with your own to skip the auto-generated self-signed pair. |
| `./log/`     | `/opt/luadch/log/`     | Hub log files (`error.log`, `cmd.log`, ...). Also mirrored to `docker logs` via the entrypoint. |
| `./secrets/` | `/secrets/`            | AES master key for at-rest `user.tbl` encryption (cfg key `master_key_path`). Kept separate from `./cfg/` so backup tooling can split them. |

The `./secrets/` separation is the F-AUTH-1 threat-model recommendation
in [`docs/SECURITY.md`](SECURITY.md): the encrypted backup of `user.tbl`
should not live alongside the AES key that decrypts it.

## Configuration changes

Edit `cfg/cfg.tbl` on the host with your favourite editor. Then either:

```sh
docker compose restart luadch
```

or, in the hub itself (after logging in as a level-100 user):

```
+reload
```

`+reload` is faster (no TCP listener restart) and what you'll usually
want for non-network-port changes.

## Backups

Full guide: [`docs/BACKUP.md`](BACKUP.md). The Docker essentials:

- **Enable it:** add `{ "etc_backup.lua", enabled = true }` to the `scripts`
  list in `cfg/cfg.tbl`, then set the passphrase in the service's
  `environment:` (it must reach the container - `.env` alone does not):
  ```yaml
  environment:
    - LUADCH_ETC_BACKUP_PASSPHRASE=${LUADCH_ETC_BACKUP_PASSPHRASE}
  ```
  Restart the container. `+backup status` should show "ready".
- **Where they land:** `./cfg/backups/` on the host (default `etc_backup_dir =
  "cfg/backups"`, inside the already-mounted `./cfg`). No extra volume needed.
- **Off-site:** the hub only writes locally - mirror `./cfg/backups/` to a
  remote yourself (rclone/restic/cron). BACKUP.md has an rclone walkthrough.
- **Restore** (hub stopped, one-shot container; the passphrase env and args are
  forwarded automatically):
  ```sh
  docker compose stop luadch
  docker compose run --rm luadch --restore cfg/backups/<file>.ldbk --verify
  docker compose run --rm luadch --restore cfg/backups/<file>.ldbk --force
  docker compose up -d luadch
  ```
  If your `master_key_path` is on the `./secrets/` mount (the recommended
  layout), add `--master-key-path /secrets/master.key` - restore refuses an
  out-of-tree path from the manifest unless you name it explicitly.

## TLS-only deployments

Once your users are on `adcs://` URLs, drop the plain port:

```yaml
ports:
  # - "5000:5000"   # commented out
  - "5001:5001"
```

Or restrict the plain port to localhost only (useful for `+!#` admin
tooling that can't speak TLS):

```yaml
ports:
  - "127.0.0.1:5000:5000"
  - "5001:5001"
```

## IPv6

Two pieces have to line up: the **container** has to have a v6 stack,
and the **hub** has to actually listen on v6.

### Step 1 - enable IPv6 in the Docker daemon

`/etc/docker/daemon.json`:

```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:dead:beef::/48",
  "ip6tables": true
}
```

`ip6tables: true` is the critical key - without it the iptables NAT
rules that publish a port to `0.0.0.0:5001` are not mirrored to the
v6 stack, and `[::]:5001` traffic is dropped before it reaches the
container.

```sh
sudo systemctl restart docker
```

### Step 2 - enable IPv6 on the compose-managed network

The daemon's `fixed-cidr-v6` only applies to the default `bridge`
network. Compose creates its own (`<project>_default`) and that one
defaults to v4-only. Add a `networks:` block to `docker-compose.yml`:

```yaml
networks:
  default:
    enable_ipv6: true
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
        - subnet: fd00:cafe:beef::/64
```

The two subnets are independent - the v4 ULA stays for v4 networking,
the v6 ULA gives containers a globally-unique-but-not-routable v6
address that the host's `ip6tables` NAT translates inbound and outbound.

After editing, re-create the network:

```sh
docker compose down
docker network rm "$(basename "$(pwd)")_default"   # or: docker network ls + rm by name
docker compose up -d

# verify the container picked up a v6 address
docker compose exec luadch ip -6 addr show
```

You should see an `eth0` line with an `fd00:cafe:beef:...` address.

### Step 3 - configure the hub to listen on v6

The hub's `cfg/cfg.tbl` has **separate port arrays** for v4 and v6.
Since v3.2.x ([`core/server.lua`](../core/server.lua) registry is
`(port, family)`-keyed, [#107](https://github.com/luadch-ng/luadch-ng/issues/107)),
the same port number can serve both stacks - HTTP/80-style
dual-stack:

```lua
tcp_ports      = { 5000 },     -- plain v4
ssl_ports      = { 5001 },     -- TLS   v4
tcp_ports_ipv6 = { 5000 },     -- plain v6 (same port as v4)
ssl_ports_ipv6 = { 5001 },     -- TLS   v6 (same port as v4)
```

`docker-compose.yml` then publishes two ports instead of four:

```yaml
ports:
  - "5000:5000"
  - "5001:5001"
```

The historical 5000/5001/5002/5003 split (one port per family) is
still accepted if you prefer it; existing deployments do not need
to change.

For TLS-only deployments drop `5000`. Modern DC++ clients (AirDC++)
understand `adcs://hub.example.com:5001` and reach the hub on whatever
stack matches the client's connectivity - only ONE URL needs to be
published.

If you prefer the historical separate-port layout (`ssl_ports = { 5001
}`, `ssl_ports_ipv6 = { 5003 }`) it still works unchanged; you then
publish `adcs://hub.example.com:5001` for v4 and
`adcs://hub.example.com:5003` for v6.

### Step 4 - DNS

Add an `AAAA` record for your hostname pointing at the host's global
IPv6 address (not Docker's internal ULA - your host's outward-facing
v6, the one in `ip -6 addr show eth0` with `scope global`).

If using Cloudflare DNS: keep proxy mode **off** (gray cloud). The
orange-cloud proxy is HTTP-only and will silently mangle ADC
traffic.

```sh
# verify both records resolve
dig A     hub.example.com +short
dig AAAA  hub.example.com +short
```

### Step 5 - test

From a v6-enabled box (or any free port-checker):

```sh
nc -6 -zv hub.example.com 5001
# Connection ... succeeded
```

[Hurricane Electric's port checker](https://ipv6.he.net/portinfo.php)
is the easy web-based path if you don't have v6 connectivity locally.

### Alternative: `network_mode: host`

If you don't want to bother with the daemon.json + compose networks
setup, switch to host networking - the container shares the host's
network stack directly:

```yaml
services:
  luadch:
    image: ghcr.io/luadch-ng/luadch-ng:latest
    network_mode: host
    user: "${PUID:-1000}:${PGID:-1000}"
    # no ports: section in host mode
    volumes:
      - ./cfg:/opt/luadch/cfg
      ...
```

Trade-off: no network isolation between the container and the host.
For a hub running as the box's main service, that's usually fine.
Bonus: UFW rules apply normally (Docker's port-publishing iptables
rules don't get involved).

## Updating

> **⚠️ Always back up first.** Operator-owned state lives in `cfg/`
> (including per-plugin config `cfg/<name>.tbl`, e.g. `cfg/webhooks.tbl`),
> `scripts/lang/`, `scripts/data/`, `certs/`, and `secrets/`. None of
> these are touched by an image upgrade, but a clean snapshot is the
> safety net for any production hub.
>
> ```sh
> tar -czf "luadch-backup-$(date +%F).tar.gz" cfg scripts certs secrets
> ```

Pull the new image and recreate the container; mounts persist:

```sh
docker compose pull
docker compose up -d
```

For `vX.Y.Z` releases pin the tag in `docker-compose.yml` so you don't
get unexpected jumps:

```yaml
image: ghcr.io/luadch-ng/luadch-ng:v3.1.15
```

### What gets updated automatically

The container's entrypoint **auto-syncs the bundled top-level
`scripts/*.lua` files** from the image to your mounted `scripts/`
directory on every start. Bug-fixes we ship in plugin code reach
your hub on the next image pull without manual action.

In addition, **new bundled `scripts/lang/<lng>/*.json` files are
add-only**: language files that don't exist on your mount get copied
in (creating the language subdir as needed), but existing translations
are NEVER overwritten. This way a release that adds i18n to a previously
English-only plugin reaches non-English operators without them having to
chase down the new `de/<name>.json` / `fr/<name>.json` files manually,
while any operator-customized translations stay intact.

What is **not** touched:

| Path | Reason |
|---|---|
| `cfg/cfg.tbl` | Your settings; new defaults are merged at runtime via the `cfg.get()` fallback path |
| `cfg/user.tbl`, `cfg/user.tbl.bak` | User database |
| `scripts/lang/<lng>/*.json` (existing) | Your translations / MOTD customizations stay; only NEW bundled language files are added |
| `scripts/data/*.tbl` | Plugin runtime state (bans, regs, caches) |
| `cfg/<name>.tbl` (e.g. `cfg/webhooks.tbl`) | Per-plugin operator settings |
| `scripts/<your-custom>.lua` | Custom plugins keep their distinct filenames - the auto-sync only touches files that exist in the image's `/defaults/scripts/` |
| `certs/*` | TLS keys |
| `secrets/master.key` | AES master key |

The entrypoint logs each updated file:

```
[entrypoint] auto-synced bundled script: cmd_nickchange.lua
[entrypoint] auto-synced 1 bundled scripts from /defaults
[entrypoint] auto-added new bundled lang file: de/usr_nick_length.json
[entrypoint] auto-added 1 new bundled lang files from /defaults
```

If a bundled script's content matches what's already on disk, it is
skipped (idempotent on restart). Lang files are likewise skipped
when they already exist, regardless of content.

### Opting out of auto-sync

If you have hand-patched a bundled script and want to preserve those
edits across image upgrades, set in your `.env`:

```
LUADCH_AUTOSYNC_SCRIPTS=0
```

The toggle disables both the `scripts/*.lua` overwrite-on-diff sync
and the `scripts/lang/*` add-only sync. Image bug-fixes and new
language files stop reaching your hub automatically. You will need
to copy them manually:

```sh
# Diff: which bundled scripts in your mount differ from the new image
docker compose exec luadch sh -c '
    for f in /defaults/scripts/*.lua; do
        n=$(basename "$f")
        cmp -s "$f" "/opt/luadch/scripts/$n" 2>/dev/null \
            || echo "differs: $n"
    done
'

# Find: which bundled lang files are missing on your mount
docker compose exec luadch sh -c '
    for f in /defaults/scripts/lang/*/*.json; do
        rel=${f#/defaults/scripts/lang/}          # <lng>/<name>.json
        [ -e "/opt/luadch/scripts/lang/$rel" ] || echo "missing: $rel"
    done
'

# Apply a single file
docker compose exec luadch \
    cp /defaults/scripts/cmd_nickchange.lua /opt/luadch/scripts/
docker compose restart luadch
```

The recommended pattern for plugin customization is to **add a custom
filename** rather than editing a bundled file. With that pattern the
auto-sync is harmless and you can leave it ON.

### Updating `scripts/lang/<lng>/*.json` after a release that changed translations

Translation files (and other `scripts/<subdir>/` content) are never
auto-synced because they typically contain operator-customized strings
(e.g. your MOTD). When a release changes a bundled translation key
that you have not customized, the in-script `lang.foo or "<fallback>"`
pattern keeps the hub running on the hardcoded fallback - you just
miss the new translation until you sync.

To sync a specific lang file, diff against the image and merge what
matters:

```sh
# Show your file vs the image's
docker compose exec luadch \
    diff /opt/luadch/scripts/lang/en/etc_motd.json \
         /defaults/scripts/lang/en/etc_motd.json

# Apply the image version (will overwrite your customizations!)
docker compose exec luadch \
    cp /defaults/scripts/lang/en/etc_motd.json /opt/luadch/scripts/lang/en/
docker compose restart luadch
```

Release notes call out lang/data file changes explicitly when they
happen so you know to sync.

## Troubleshooting

### Permission denied on bind mounts

Symptom: container exits with `cannot create '/opt/luadch/log/...':
Permission denied`.

Cause: host directory not owned by the runtime UID. The image runs as
1000:1000 by default; if your host user is 1001 the bind-mount
directories are 1001-owned and the container user can't write to them.

Fix:

```sh
# either set PUID/PGID to your host user
echo "PUID=$(id -u)"  >> .env
echo "PGID=$(id -g)" >> .env
docker compose up -d

# or chown the dirs to the container's default 1000
sudo chown -R 1000:1000 cfg scripts certs log secrets
```

### Lost the keyprint

The entrypoint logs the keyprint on every start; restart the container
to see it again:

```sh
docker compose restart luadch
docker compose logs luadch --tail 20 | grep keyprint
```

Or compute it directly from the cert on the host:

```sh
openssl x509 -in certs/servercert.pem -noout -fingerprint -sha256 \
  | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f' \
  | xxd -r -p | base32 | tr -d '='
```

### `docker logs` shows nothing after a while

The hub writes to `log/error.log` and `log/cmd.log` on disk; the
entrypoint forwards them via `tail -F`. If you `docker compose
restart`, you'll see the most recent lines plus everything written
afterwards. The on-disk log files persist independently in `./log/`.

### Self-signed cert rejected by my client

DC++ clients trust by **keyprint**, not by CA chain. If your client is
complaining about an unverified cert, check that the `adcs://` URL you
gave it actually includes the `?kp=SHA256/<hash>` suffix. Without it
the client falls back to PKI validation which a self-signed cert
won't pass.

If you already replaced the cert with one from a public CA, drop the
keyprint suffix from the URL.

### Container shows `unhealthy`

The HEALTHCHECK probes a single port with `nc -z`. It defaults to
**5001**, the TLS-only default listener. If you changed the hub's
listen port - running plain-only on 5000 (`tcp_ports = { 5000 }`, ssl
disabled) or a custom port - the probe hits a dead port and the
container reports `unhealthy` even though the hub serves fine. Point
the probe at your actual port:

```yaml
environment:
  - LUADCH_HEALTHCHECK_PORT=5000
```

(or in `.env`, then make sure the variable is listed in the service's
`environment:` block - an `.env` entry alone only does compose
interpolation, it does not reach the container). `docker inspect -f
'{{.State.Health.Status}}' luadch` should read `healthy` within the
`--interval` window after the next `docker compose up -d`.

## Building the image yourself

```sh
docker build -f docker/Dockerfile -t luadch:dev .
docker run --rm -d --name luadch-dev \
  --user $(id -u):$(id -g) \
  -p 5000:5000 -p 5001:5001 \
  -v "$(pwd)/dev/cfg:/opt/luadch/cfg" \
  -v "$(pwd)/dev/scripts:/opt/luadch/scripts" \
  -v "$(pwd)/dev/certs:/opt/luadch/certs" \
  -v "$(pwd)/dev/log:/opt/luadch/log" \
  -v "$(pwd)/dev/secrets:/secrets" \
  luadch:dev
```

For multi-arch test builds, set up `buildx` and target the platforms
your release would publish:

```sh
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -f docker/Dockerfile -t luadch:dev .
```
