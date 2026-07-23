# spr-opencanary

A polished [OpenCanary](https://github.com/thinkst/opencanary) honeypot plugin for
[SPR](https://github.com/spr-networks/super). It places a believable decoy appliance on the
SPR LAN, records every interaction, and turns OpenCanary's configuration and event stream
into an appliance-style dashboard built with [`spr-plugin-ui`](https://github.com/spr-networks/spr-plugin-ui).

## Features

- Live health, 24-hour activity, unique-source, and active-service metrics
- Filterable incident feed with service facets and an hourly activity chart
- 18 configurable decoys: FTP, SSH, HTTP/S, Telnet, MySQL, Microsoft SQL, MongoDB,
  Redis, RDP, VNC, Git, HTTP proxy, SNMP, NTP, SIP, TFTP, and TCP banner
- NAS appliance, Linux server, Windows server, and network appliance presets
- Generic, Slack, and Microsoft Teams webhooks; the secret URL is never returned by the API
- Webhooks send attacker events only; startup and service-registration chatter stays local
- Ignore-list support for trusted IP addresses and CIDRs
- Optional PFW-managed LAN destination and port mapping
- OpenCanary process controls and SPR topology integration
- Responsive light/dark UI that inherits SPR's theme through `spr-plugin-ui`

The default appliance is `172.30.119.2` and enables FTP (21), SSH (22), HTTP (80), MySQL
(3306), and Redis (6379). All SPR LAN devices can reach the decoys so unexpected connections
can be observed. Choose ports that do not collide with the router or other LAN services.

## Install from SPR

1. Open **Plugins** in the SPR UI and choose **+ New Plugin**.
2. Enter `https://github.com/spr-networks/spr-opencanary`.
3. Open **spr-opencanary** from the navigation after installation.
4. Select a service preset, configure notifications if desired, and save.

## Present the canary on the LAN

Open **LAN presence** in the plugin to publish an OpenCanary listener at a destination and port
chosen for LAN clients. This optional feature requires the SPR Programmable Firewall (PFW)
extension.

The initial mapping uses `192.168.0.0/16` as PFW's `Client.SrcIP`, presents a user-selected
destination such as `192.168.2.253` on TCP port `8080`, and translates it to OpenCanary at
`172.30.119.2:80`. Additional TCP or UDP mappings can publish more enabled listeners at the same
destination—for example, `2222 → 22` for SSH. The plugin creates one managed PFW flow per row. In
PFW terms, the selected address and presented port are `OriginalDst` and `OriginalDstPort`; the
container address and enabled listener are `Dst` and `DstPort`. The source CIDR, presented
destination, protocols, and ports are editable.

The flows apply to LAN client traffic and do not publish the canary on the WAN. Choose a
destination and presented ports that are not already used by real LAN services. Removing LAN
presence deletes only the flows managed by this plugin.

## Architecture and security

The plugin uses a dedicated Docker bridge named `spr-opencanary` with a static appliance
address. No ports are published to the host. The plugin manifest declares the stable KVM
device MAC and requests `lan`, `wan`, and `dns` policies from SPR's plugin manager. LAN
reachability makes the honeypot useful, while WAN/DNS let configured webhook destinations
receive alerts.

When LAN presence is enabled, PFW performs destination and port translation from the configured
client-facing address to the container bridge address. OpenCanary continues to run only in its
isolated Docker network; the plugin does not use host networking, add container privileges, or
publish Docker ports.

A small Go control plane validates the friendly configuration, writes the upstream
OpenCanary JSON, supervises the Python daemon, parses its bounded rotating event log, serves the
bundled UI, and exposes the topology. The control plane is available only through
`/state/plugins/spr-opencanary-krun/socket.sock`, which SPR authenticates and proxies.

- The container root filesystem is read-only; only plugin config and state are persistent.
- All capabilities are dropped before adding the narrow set needed to bind low ports, open
  packet sockets for supported UDP decoys, and drop OpenCanary to `nobody:nogroup`.
- `no-new-privileges` is enabled and the daemon runs unprivileged after binding listeners.
- Config writes are atomic and mode `0600`; webhook URLs remain write-only through the API.
- Detection history rotates at 20 MiB with two backups to bound persistent disk usage.
- OpenCanary lifecycle records remain in the local rotating log but are filtered from webhooks.
- API request bodies are size-limited and reject unknown fields.
- The UI contains no external scripts, fonts, analytics, or CDN dependencies.
- Attacker passwords are not returned by the plugin API or displayed in the UI.

OpenCanary's Linux portscan module and SMB module are intentionally omitted: portscan is not
supported in the upstream Docker deployment model, while SMB requires additional system
services and host integration that conflict with this plugin's contained threat model.

## API

SPR proxies these endpoints at `/plugins/spr-opencanary/...` over the plugin Unix socket.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/status` | Daemon state, version, canary IP, service count, and event metrics |
| `GET` | `/config` | Redacted, UI-safe configuration |
| `PUT` | `/config` | Validate, persist, regenerate upstream config, and restart OpenCanary |
| `POST` | `/daemon` | `start`, `stop`, or `restart` the OpenCanary process |
| `GET` | `/events` | Events and aggregate metrics; accepts `limit`, `service`, and `q` |
| `DELETE` | `/events` | Clear the local event history |
| `GET` | `/topology` | SPR topology nodes and edges for the canary appliance |
| `GET` | `/healthz` | Control-plane liveness |

Persistent files live below:

- `/configs/plugins/spr-opencanary/config.json` — friendly plugin configuration
- `/configs/plugins/spr-opencanary/opencanary.conf` — generated upstream configuration
- `/state/plugins/spr-opencanary/events.jsonl` — OpenCanary rotating JSON event stream
- `/state/plugins/spr-opencanary/daemon.log` — daemon diagnostics
- `/state/plugins/spr-opencanary/certs/` — generated HTTPS decoy certificate and key

## Development

```bash
# Backend unit tests and static analysis
cd code
go test ./...
go vet ./...

# Frontend production bundle
cd ../frontend
yarn install --frozen-lockfile
yarn bundle

# Compose and complete container build
cd ..
docker compose config --quiet
docker compose build
```

Or run all repository checks with `./test.sh`. Build inputs are pinned in
`reproducible.env`; Python runtime dependencies are pinned in `requirements.lock`.

## Upstream and license

The image installs OpenCanary **0.9.8** from the upstream Python package. OpenCanary is
copyright Thinkst Applied Research and distributed under its own BSD-3-Clause license. This
SPR integration is MIT licensed; see [LICENSE](LICENSE).
