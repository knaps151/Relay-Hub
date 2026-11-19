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
docker compose --profile caddy up -d --build
```

Update `headscale/config.yaml` `server_url` to the public Headscale URL before clients join.

## Host requirements

See [`scripts/host-requirements.md`](scripts/host-requirements.md).

## POC scope

Included: multi-VPN site model, shared virtual IPs, fleet UI, Headscale join keys, WG `.conf`, OpenVPN `.ovpn`, status polling, Compose packaging.

Later (not in this POC): linked multi-node hubs / single dashboard redundancy, engineer RBAC, `install.sh` wizard.
