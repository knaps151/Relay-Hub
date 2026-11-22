"""Short-lived public download links for site VPN configs (cloud/Pi curl install)."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import Site, TempDownloadToken

DEFAULT_TTL_SECONDS = 180  # 3 minutes


def mint_temp_download(
    db: Session,
    site: Site,
    *,
    kind: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_downloads: int = 1,  # Single-use by default
) -> TempDownloadToken:
    kind = kind.strip().lower()
    if kind not in {"wireguard", "openvpn", "teltonika"}:
        raise ValueError("kind must be wireguard, openvpn, or teltonika")
    if kind == "wireguard" and site.vpn_type != "wireguard":
        raise ValueError("Site is not WireGuard")
    if kind == "openvpn" and site.vpn_type != "openvpn":
        raise ValueError("Site is not OpenVPN")
    if kind == "teltonika" and (site.vpn_type != "wireguard" or getattr(site, "access_mode", "gateway") == "direct"):
        raise ValueError("Teltonika script is for WireGuard gateway sites only")

    # Drop expired rows opportunistically
    db.execute(delete(TempDownloadToken).where(TempDownloadToken.expires_at < datetime.utcnow()))

    row = TempDownloadToken(
        token=secrets.token_urlsafe(24),
        site_id=site.id,
        kind=kind,
        expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds),
        max_downloads=max_downloads,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_valid_token(db: Session, token: str) -> TempDownloadToken | None:
    """Get token if valid (not expired, not exhausted)."""
    row = db.get(TempDownloadToken, token)
    if not row:
        return None
    if row.expires_at < datetime.utcnow():
        db.delete(row)
        db.commit()
        return None
    # Check if max downloads reached
    max_dl = row.max_downloads if row.max_downloads is not None else 1
    if row.download_count >= max_dl:
        return None
    return row


def consume_token(db: Session, row: TempDownloadToken) -> bool:
    """Consume a download from the token. Returns True if successful, False if exhausted."""
    max_dl = row.max_downloads if row.max_downloads is not None else 1
    if row.download_count >= max_dl:
        return False
    row.download_count = int(row.download_count or 0) + 1
    db.commit()
    # Delete token if exhausted
    if row.download_count >= max_dl:
        db.delete(row)
        db.commit()
    return True


def touch_download(db: Session, row: TempDownloadToken) -> None:
    """Legacy function - use consume_token instead."""
    consume_token(db, row)


def public_conf_url(public_base: str, token: str) -> str:
    return f"{public_base.rstrip('/')}/d/{token}"


def public_install_url(public_base: str, token: str) -> str:
    return f"{public_base.rstrip('/')}/d/{token}/install.sh"


def linux_install_one_liner(public_base: str, token: str) -> str:
    url = public_install_url(public_base, token)
    return f"curl -fsSL '{url}' | sudo bash"


def render_wireguard_install_script(conf: str, *, iface: str = "wg0") -> str:
    """Bash installer that writes the conf and enables wg-quick."""
    marker = f"WGCONF_{secrets.token_hex(8)}"
    return f"""#!/bin/bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run with sudo (or: curl … | sudo bash)" >&2
  exit 1
fi
export DEBIAN_FRONTEND=noninteractive
if ! command -v wg >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq wireguard wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y wireguard-tools
  else
    echo "Install wireguard-tools manually, then re-run." >&2
    exit 1
  fi
fi
install -d -m 700 /etc/wireguard
cat > /etc/wireguard/{iface}.conf <<'{marker}'
{conf.rstrip()}
{marker}
chmod 600 /etc/wireguard/{iface}.conf
systemctl enable --now "wg-quick@{iface}"
wg show "{iface}" || true
echo "WireGuard {iface} is up."
"""
