# Host requirements (WireGuard + OpenVPN + NETMAP)

## Linux VPS / Linux Docker host (recommended for real tunnels)

- Kernel WireGuard (`wireguard` module or `wireguard-tools`)
- `nftables` (or `iptables` fallback) for 1:1 NETMAP
- `/dev/net/tun` available to containers
- Capabilities: `NET_ADMIN` (Compose already requests this)
- Open ports:
  - `8000/tcp` — dashboard (or `80/443` with Caddy profile)
  - `8080/tcp` — Headscale control (or via reverse proxy / ngrok)
  - `51820/udp` — WireGuard
  - `1194/tcp` — OpenVPN (TCP 443-style profile uses 1194 in POC; remap as needed)

## Docker Desktop (macOS) — local UI / Tailscale control plane

- Dashboard + Headscale work well
- Kernel WireGuard / nftables inside Linux VM are limited; keep `WG_DRY_RUN=1` and `NFT_DRY_RUN=1`
- Still generate `.conf` / `.ovpn` and test peers against a Linux VPS hub later
- Use ngrok for `PUBLIC_UI_URL` / `HEADSCALE_URL` when joining phones over 4G

## OpenVPN container

- Shares PKI volume with the API (`/vpn`)
- API issues client certs into that volume; OpenVPN serves TCP 1194
- Status file: `/vpn/openvpn-status.log`
