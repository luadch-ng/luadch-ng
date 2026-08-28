# luadch-ng
[![License](https://img.shields.io/badge/license-GPLv3.0-blueviolet.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20ARM-orange.svg)](docs/BUILDING.md)
[![Lua](https://img.shields.io/badge/lua-5.4.8-blue.svg)](https://www.lua.org/)
[![Release](https://img.shields.io/github/v/release/luadch-ng/luadch-ng.svg)](https://github.com/luadch-ng/luadch-ng/releases/latest)
[![GHCR](https://img.shields.io/badge/ghcr.io-amd64%20%7C%20arm64-blue?logo=docker)](https://github.com/luadch-ng/luadch-ng/pkgs/container/luadch-ng)
[![Translation status](https://translate.dcvault.net/widget/luadch-ng/svg-badge.svg)](https://translate.dcvault.net/engage/luadch-ng/)

A modernised fork of [luadch](https://github.com/luadch/luadch), an ADC(S) hub for the [Direct Connect](https://dcvault.net/docs/basics/what-is-direct-connect) network. Originally by **blastbeat** and **pulsar**. Check out our [Support Hub](https://dcvault.net/docs/community/support-hub) or [Support Forum](https://forum.dcvault.net) if you have any questions or problems, or just to chat.

Help us translate Luadch-ng into your language. Visit our [Translation Hub](https://translate.dcvault.net/projects/luadch-ng/)

🔴🔴 **REPO RENAMED `luadch` → `luadch-ng` - the Docker image moved from `ghcr.io/luadch-ng/luadch` to `ghcr.io/luadch-ng/luadch-ng`.**

🔴🔴 **BETA SOFTWARE - Version 3.2.0 not released yet. Use 3.1 for stable release**

## Features in 3.2

- 📜 Full ADC hub protocol support, TLS 1.3, ADCS-only
- 🥷 Private only & public hub features
- ↔️ IPv4 & IPv6 dual-stack (*HBRI for active mode NAT traversal)
- 🔒 Hardened by default - plugin sandbox, rate limits
- 🐍 Lua 5.4.8 scripting API + lots of bundled plugins
- 🪶 Low footprint (~ 30 MB RAM), ARM-ready
- ⚡ HTTP API - full REST management (users, bans, config, plugins, logs)
- 📥 Simple Webhook System
- 💬 Multilanguage support (i18n)
- 🛡️ Blocklist engine + external feeds (Tor, Spamhaus, AbuseIPDB)
- 🌍 GeoIP country/ASN policy + in-hub MaxMind auto-update
- 🕵️ Proxy/VPN/Tor detection
- 📦 Encrypted backup & restore system
- 📊 Prometheus metrics + polled event stream
- 🐳 Prebuilt binaries Windows, Linux + multi-arch Docker Image

*[HBRI](https://forum.dcvault.net/t/hbri-ipv4-ipv6-verification-for-hybrid-hubs/22) is not an official ADC specification and was proposed as a protocol extension in DCBase in 2012. AirDC++ implemented this in its client in 2013.


## ToDo
- 🌐 Web interface for hub management (in progress in the companion repo `luadch-ng-webui`; backed by this hub's HTTP + webhook management API, but not part of this repo's release)

## Quick Start

### Docker (recommended)
```bash
git clone https://github.com/luadch-ng/luadch-ng.git
cd luadch-ng
cp .env.example .env   # Adjust PUID/PGID if `id -u` != 1000
docker compose up -d
```
Multi-arch image (`ghcr.io/luadch-ng/luadch-ng:latest`), runs as an unprivileged user. Upon first startup, a self-signed TLS certificate is generated, and the keyprint for the `adcs://` URL is logged.

### Prebuilt binaries
Linux (x86_64 + aarch64) and Windows x86_64 builds are included with every [release](https://github.com/luadch-ng/luadch-ng/releases/latest) - just unzip and run. OpenWRT routers get a ready-to-install `.apk` for three common arches; see the [OpenWRT section](docs/BUILDING.md#-openwrt-routers) of the build guide.

### From source
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cmake --install build
cd build/install/luadch && ./luadch
```

Then connect to `adcs://127.0.0.1:5001` using an ADC client (e.g., AirDC++), and log in with `dummy` / `test`. Getting started: [CONFIGURATION.md](docs/CONFIGURATION.md).

## Documentation

[Building](docs/BUILDING.md) · [Installing](docs/INSTALLING.md) · [Configuration](docs/CONFIGURATION.md) · [Scripts](docs/SCRIPTS.md) · [Security](docs/SECURITY.md) · [Docker](docs/DOCKER.md) · [Plugin API](docs/PLUGIN_API.md)

## Links

- 💬 [DCVault Forum](https://forum.dcvault.net)
- 🐦 [Support Hub](https://dcvault.net/docs/community/support-hub)
- 📧 [DCVault Wiki](https://dcvault.net)

## Credits and Acknowledgements

Conceptual credit goes to **[@blastbeat](https://github.com/blasti)** and **[@pulsar](https://github.com/pulsar-de)**, the original authors. This fork only modernizes and extends their foundation.

A special thank you goes to the following users who helped me during development by suggesting improvements and finding bugs:
- [@Sopor](https://github.com/Sopor)
- [@Kcchouette](https://github.com/Kcchouette)

## Contribution

Any help or pull request is welcome. Please open an issue for bugs or improvements.

## AI-Transparency

This fork uses Claude Code to help with analyzing, planning, and writing code.

## License

GPLv3.0 — see [LICENSE](LICENSE).
