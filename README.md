# Relay Hub (POC)

Self-hosted multi-VPN hub for parking / CPO fleets.

**Project page:** [GitHub Pages](https://knaps151.github.io/Relay-Hub/) · **Source:** this repository

> Do not commit `.env`, SQLite under `data/`, PKI/`vpn/`, or real WireGuard private keys. Only `.env.example` (placeholder defaults) belongs in git.

**One access model for every site:** virtual subnets `10.101.X.0/24` and a device cheat sheet.  
**Transports:** Tailscale (Headscale), WireGuard, OpenVPN — pick per site (or change later).  
**Access modes:**

| Mode | Use when |
|------|----------|
| **Gateway** | Site router brings a whole LAN (Teltonika / Linux). Hub 1:1 NETMAPs `10.101.X` ↔ site LAN. |
| **Direct device** | Single host (Pi, cloud VM, charger). WireGuard runs on the device; no router NETMAP. |

Engineers connect to the hub (WireGuard) and reach sites via virtual IPs on the cheat sheet.

## Quick start (local)

```bash
cp .env.example .env   # already present if you cloned this tree
docker compose up -d --build
```

Wait ~30s for Headscale bootstrap + OpenVPN PKI, then open:

- Dashboard: http://127.0.0.1:8000  
- Password: `relay` (from `.env` `ADMIN_PASSWORD`)
- Headscale: http://127.0.0.1:8080

First login walks through settings (UI URL, Headscale URL, WG/OpenVPN endpoints, base CIDR).

### Ngrok (dashboard + Headscale control over 4G)

```bash
# Terminal A — UI
ngrok http 8000

# Terminal B — Headscale (clients need a reachable login-server)
ngrok http 8080
```

Paste the ngrok URLs into **Settings** as `public_ui_url` and `headscale_url`.  
Keep `wg_endpoint` / `openvpn_endpoint` as LAN or VPS addresses — **not** the ngrok HTTP URL.

WireGuard is UDP; plain `ngrok http` cannot carry it. For remote WG/OpenVPN, use a VPS or UDP/TCP port forwards.

## Create sites

1. **Add site** → **Gateway** or **Direct device**
2. Choose VPN (direct devices are always WireGuard)
3. Site gets the next `10.101.X.0/24`
4. Install credentials from the site page:
   - **Download .conf / .ovpn** (session-auth)
   - **3‑min cloud install link** (WireGuard): mint a public URL, then on the host:
     ```bash
     curl -fsSL 'https://relay.example/d/TOKEN/install.sh' | sudo bash
     ```
     Link expires after 3 minutes. Installs `wireguard-tools`, writes `/etc/wireguard/wg0.conf`, enables `wg-quick@wg0`.
   - Tailscale: copy join command / refresh pre-auth key
   - Gateway WireGuard: Teltonika UCI script also available

Site-side NETMAP helper (optional if hub NETMAP is enough): [`scripts/site-netmap-example.sh`](scripts/site-netmap-example.sh)

Local ICMP enrichment dry-run (home LAN, no Relay DB): [`scripts/scan-lan-local.py`](scripts/scan-lan-local.py)

## Fleet / site management

- Edit name, region, local LAN, notes, and **VPN protocol** (issues new credentials)
- **Disable / enable** (disabled WireGuard peers are removed from the hub)
- **Delete** from fleet or site page
- **Rotate / re-issue** credentials without changing site index / virtual subnet
- Catalogues: regions, tech device types, equipment types
- Engineers: multi-device (phone / laptop / tablet) WireGuard profiles + Connected view

## Hub LAN auto-scan

When a **gateway** site is **Online**, **Scan LAN** ping-sweeps `10.101.X.0/24` through the tunnel, auto-adds new hosts, and enriches with reverse DNS + light TCP ports (label / type / admin port). Additive only. Direct sites are skipped.

Requires hub NETMAP + a site path that forwards into the LAN (Teltonika/Linux works; consumer UniFi VPN Client is a poor fit for inbound LAN access).

## Compose services

| Service | Role |
|---------|------|
| `api` | FastAPI dashboard + provisioning + status poller (also bootstraps Headscale user/API key) |
| `headscale` | Self-hosted Tailscale control server |
| `openvpn` | TCP OpenVPN server + shared PKI volume |
| `caddy` | Optional HTTPS (`--profile caddy`) |

### Dry-run on Docker Desktop (macOS)

Default `.env` sets `WG_DRY_RUN=1` and `NFT_DRY_RUN=1` so the API still generates configs without kernel WG/nftables.  
On a Linux VPS set both to `0`.

### VPS + Let's Encrypt

```bash
# .env
HTTP_ONLY=0
RELAY_DOMAIN=relay.example.co.uk
WG_DRY_RUN=0
NFT_DRY_RUN=0
WG_ENDPOINT=relay.example.co.uk:51820
OPENVPN_ENDPOINT=relay.example.co.uk:1194
HEADSCALE_URL=https://relay.example.co.uk/headscale
PUBLIC_UI_URL=https://relay.example.co.uk

# Point DNS A record, open 80/443/51820/udp/1194/tcp, then:
docker compose -f docker-compose.yml -f docker-compose.vps.yml --profile caddy up -d --build
```

VPS overlay (`docker-compose.vps.yml`) runs API + Caddy on host networking so WireGuard UDP handshakes work.

Update `headscale/config.yaml` `server_url` to the public Headscale URL before clients join.

## Host requirements

See [`scripts/host-requirements.md`](scripts/host-requirements.md).

## JSON API

The JSON API is available at `/api/*` endpoints. Authentication is required via either:
- **Session cookie**: Log in via the web UI
- **Bearer token**: Set `API_TOKEN` in `.env` and use `Authorization: Bearer <token>` header

### API Endpoints

**Sites:**
- `GET /api/sites` — List all sites
- `POST /api/sites` — Create a site (body: `{"name": "...", "vpn_type": "wireguard|tailscale|openvpn", "local_subnet": "192.168.1.0/24", "access_mode": "gateway|direct"}`)
- `GET /api/sites/{id}` — Get a site
- `DELETE /api/sites/{id}` — Delete a site

**Devices:**
- `GET /api/sites/{id}/devices` — List devices for a site
- `POST /api/sites/{id}/devices` — Add a device (body: `{"label": "...", "local_ip": "192.168.1.50"}`)
- `DELETE /api/sites/{site_id}/devices/{device_id}` — Delete a device
- `POST /api/sites/{id}/scan-lan` — Hub ICMP sweep of the site virtual subnet; auto-adds new hosts (gateway site + online tunnel)

**Public (token, 3 minutes):**
- `GET /d/{token}` — Raw VPN config (WireGuard / OpenVPN / Teltonika)
- `GET /d/{token}/install.sh` — Linux WireGuard installer (`curl | sudo bash`)

**Engineers:**
- `GET /api/engineers` — List all engineers
- `POST /api/engineers` — Create an engineer (body: `{"name": "John Smith"}`)
- `GET /api/engineers/{id}` — Get an engineer
- `POST /api/engineers/{id}/enable` — Enable engineer access
- `POST /api/engineers/{id}/disable` — Disable engineer access
- `DELETE /api/engineers/{id}` — Delete an engineer

**Utilities:**
- `POST /api/preview-virtual-ip` — Preview virtual IP translation (body: `{"local_ip": "...", "local_subnet": "...", "virtual_subnet": "..."}`)

Interactive API docs are available at `/docs` (requires authentication).

### Example

```bash
# With API token
curl -H "Authorization: Bearer your-token" http://127.0.0.1:8000/api/sites

# Create a WireGuard site
curl -X POST -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Site 1", "vpn_type": "wireguard", "local_subnet": "192.168.1.0/24"}' \
  http://127.0.0.1:8000/api/sites

# Direct device (Pi / cloud VM)
curl -X POST -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab Pi", "vpn_type": "wireguard", "access_mode": "direct"}' \
  http://127.0.0.1:8000/api/sites
```

## POC status

**Working well**
- Hub on DigitalOcean + HTTPS
- Engineer phone/laptop WireGuard → hub
- Direct-device WireGuard (Pi / Linux) + 3‑min `curl | sudo bash` install
- Site edit / disable / delete / rotate credentials
- Hub NETMAP + LAN scan (when site path forwards into LAN)
- Catalogues + multi-device engineers

**Weak / deferred**
- Consumer UniFi as gateway VPN client (inbound LAN access is awkward)
- Full site LAN via UniFi — prefer Teltonika or a Linux edge box
- Scheduled / background LAN scan
- Hostname/MAC enrichment on hub path
- Multi-hub redundancy, engineer RBAC

## Suggested next steps

1. **Gateway path that matches the product** — Teltonika (or Linux + NETMAP) site bring-up checklist; document “don’t use UniFi VPN Client for gateway”
2. **Hardening** — one-time use on temp install tokens (optional), rate limits, audit of `/d/` downloads already started
3. **Fleet polish** — filter disabled sites, clearer Online/handshake age, bulk actions
4. **Ops** — backup `/data` SQLite + PKI volume; document restore
5. **Pilot** — 1–2 real parking sites on WireGuard gateway + engineer phones on 4G
