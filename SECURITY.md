# Security notes (public repo)

## Safe to publish
- Application source, templates, Compose files, `.env.example`
- Docs / GitHub Pages under `docs/`
- Placeholder defaults (`ADMIN_PASSWORD=parktech` for local dry-run only)

## Never commit
- `.env` (real `ADMIN_PASSWORD`, `API_TOKEN`, endpoints)
- `data/` databases and runtime state
- OpenVPN PKI / `vpn/` / `*.ovpn` with live certs
- WireGuard private keys, pre-auth keys, or production configs
- Customer site inventories or access logs

## Before going public
1. Confirm `git status` is clean and `git secrets` / history has no past `.env` commits
2. Rotate any password or key that ever lived in chat, screenshots, or a shared droplet
3. Keep production dashboards off the marketing page (share demos privately if needed)
4. On any public VPS: set a strong `ADMIN_PASSWORD`, `HTTP_ONLY=0` behind HTTPS, and prefer `API_TOKEN` for automation
