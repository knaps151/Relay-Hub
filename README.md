# ParkTech Relay (POC)

Self-hosted multi-VPN hub for parking / CPO fleets.

**One access model for every site:** virtual subnets `10.101.X.0/24` and a device cheat sheet.  
**Three transports:** Tailscale (Headscale), WireGuard, OpenVPN — pick per site.

## Quick start (local)

```bash
cp .env.example .env   # already present if you cloned this tree
docker compose up -d --build
```

Wait ~30s for Headscale bootstrap + OpenVPN PKI, then open:

- Dashboard: http://127.0.0.1:8000  
- Password: `parktech` (from `.env` `ADMIN_PASSWORD`)
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

1. **Add site** → choose Tailscale / WireGuard / OpenVPN  
2. Site gets the next `10.101.X.0/24` from the shared allocator  
3. Cheat sheet maps `192.168.1.Y` → `10.101.X.Y` the same way for every VPN type  
4. Download join artifacts:
   - Tailscale: copy `tailscale up --login-server=...` command  
   - WireGuard: download `.conf`  
   - OpenVPN: download `.ovpn`

Site-side NETMAP helper: [`scripts/site-netmap-example.sh`](scripts/site-netmap-example.sh)

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

### Hub LAN auto-scan (gateway WireGuard)

When a **gateway** site (WireGuard, OpenVPN, or Tailscale) shows **Online**, the site detail page has **Scan LAN**. The hub ping-sweeps that site’s `10.101.X.0/24` virtual subnet through the live tunnel path and auto-adds responsive hosts that are not already on the cheat sheet. New rows are enriched with reverse DNS (when available) and a light TCP port probe to set a better **label**, **device type**, and **admin port** (e.g. RTSP → camera). Re-scan is additive only — no duplicates, nothing removed for hosts that did not reply. Direct-device sites are skipped (no LAN). MAC/ARP is not used on the hub path (tunnel next-hop only).

**Verify on DigitalOcean / Linux VPS** (real tunnels, host networking):

1. Connect a gateway site router so the fleet row is Online.
2. Open the site → **Scan LAN** (or `POST /api/sites/{id}/scan-lan`).
3. Confirm new cheat-sheet rows for live LAN hosts; run Scan again and confirm no duplicates.

On macOS with `WG_DRY_RUN=1` the button still appears when `online` is set, but pings will not reach site LANs unless real routing exists — use the VPS for a real scan.

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
- `POST /api/sites` — Create a site (body: `{"name": "...", "vpn_type": "wireguard|tailscale|openvpn", "local_subnet": "192.168.1.0/24"}`)
- `GET /api/sites/{id}` — Get a site
- `DELETE /api/sites/{id}` — Delete a site

**Devices:**
- `GET /api/sites/{id}/devices` — List devices for a site
- `POST /api/sites/{id}/devices` — Add a device (body: `{"label": "...", "local_ip": "192.168.1.50"}`)
- `DELETE /api/sites/{site_id}/devices/{device_id}` — Delete a device
- `POST /api/sites/{id}/scan-lan` — Hub ICMP sweep of the site virtual subnet; auto-adds new hosts (gateway site + online tunnel)

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
```

## POC scope

Included: multi-VPN site model, shared virtual IPs, fleet UI, Headscale join keys, WG `.conf`, OpenVPN `.ovpn`, status polling, Compose packaging, JSON API, engineer management.

Later (not in this POC): linked multi-node hubs / single dashboard redundancy, engineer RBAC, `install.sh` wizard.
