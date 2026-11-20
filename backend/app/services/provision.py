from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import HubState, SettingsRow, Site, SiteDevice
from app.services import headscale as hs
from app.services import netmap, openvpn, wireguard
from app.services.subnets import allocate_virtual_subnet, default_gateway_virtual_ip, virtual_ip_for_local

logger = logging.getLogger(__name__)


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:48] or "site"


def get_or_create_settings(db: Session) -> SettingsRow:
    row = db.get(SettingsRow, 1)
    if row:
        return row
    cfg = get_settings()
    row = SettingsRow(
        id=1,
        operator_name="ParkTech Operator",
        public_ui_url=cfg.public_ui_url,
        headscale_url=cfg.headscale_url,
        wg_endpoint=cfg.wg_endpoint,
        openvpn_endpoint=cfg.openvpn_endpoint,
        base_cidr=cfg.default_base_cidr,
        setup_completed=False,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def ensure_hub_wireguard_keys(db: Session) -> HubState:
    hub = db.get(HubState, 1)
    if hub and hub.wg_private_key and hub.wg_public_key:
        return hub
    priv, pub = wireguard.generate_keypair()
    if not hub:
        hub = HubState(id=1)
        db.add(hub)
    hub.wg_private_key = priv
    hub.wg_public_key = pub
    db.commit()
    db.refresh(hub)
    try:
        wireguard.ensure_hub_interface(priv)
    except Exception as exc:
        logger.warning("WG hub interface setup: %s", exc)
    return hub


def create_site(
    db: Session,
    *,
    name: str,
    vpn_type: str,
    local_subnet: str | None = None,
    site_code: str | None = None,
    region: str | None = None,
    access_mode: str = "gateway",
    device_label: str | None = None,
    device_admin_port: int | None = None,
) -> Site:
    access_mode = (access_mode or "gateway").strip().lower()
    if access_mode not in {"gateway", "direct"}:
        raise ValueError("access_mode must be gateway or direct")

    if access_mode == "direct":
        vpn_type = "wireguard"
    elif vpn_type not in {"tailscale", "wireguard", "openvpn"}:
        raise ValueError("vpn_type must be tailscale, wireguard, or openvpn")

    settings = get_or_create_settings(db)
    cfg = get_settings()
    code = site_code or slugify(name)
    # ensure unique
    existing = db.scalar(select(Site).where(Site.site_code == code))
    if existing:
        code = f"{code}-{int(datetime.utcnow().timestamp()) % 10000}"

    site_index, virtual_subnet = allocate_virtual_subnet(db, settings.base_cidr)

    if access_mode == "direct":
        # Identity mapping: no customer LAN; device address is virtual .1
        local_subnet = virtual_subnet
    else:
        local_subnet = local_subnet or cfg.default_local_subnet

    site = Site(
        name=name,
        site_code=code,
        vpn_type=vpn_type,
        access_mode=access_mode,
        region=(region or "").strip(),
        site_index=site_index,
        virtual_subnet=virtual_subnet,
        local_subnet=local_subnet,
    )

    if vpn_type == "tailscale":
        client = hs.HeadscaleClient()
        user = cfg.headscale_user
        site.ts_user = user
        try:
            site.ts_preauth_key = client.create_preauth_key(user, reusable=False, expiration_days=365)
        except Exception as exc:
            logger.exception("Headscale preauth failed")
            site.notes = f"Headscale preauth pending: {exc}"
            site.ts_preauth_key = None

    elif vpn_type == "wireguard":
        hub = ensure_hub_wireguard_keys(db)
        priv, pub = wireguard.generate_keypair()
        site.wg_private_key = priv
        site.wg_public_key = pub
        site.wg_hub_public_key = hub.wg_public_key
        if access_mode == "direct":
            # Device lives at the virtual IP itself (no separate 10.100.0.x tunnel addr)
            device_ip = default_gateway_virtual_ip(virtual_subnet)
            site.wg_tunnel_ip = f"{device_ip}/32"
            allowed = f"{device_ip}/32"
            try:
                wireguard.set_peer(pub, allowed)
                netmap.sync_routes_for_wireguard(f"{device_ip}/32", cfg.wg_interface)
            except Exception as exc:
                logger.warning("WG peer apply (direct): %s", exc)
        else:
            # Tunnel address in hub WG pool 10.100.0.0/24
            site.wg_tunnel_ip = f"10.100.0.{10 + site_index}/32"
            try:
                wireguard.set_peer(pub, f"{virtual_subnet}, {site.wg_tunnel_ip.split('/')[0]}/32")
                netmap.apply_site_netmap(virtual_subnet, local_subnet)
                netmap.sync_routes_for_wireguard(virtual_subnet, cfg.wg_interface)
            except Exception as exc:
                logger.warning("WG peer apply: %s", exc)

    elif vpn_type == "openvpn":
        cn = f"site-{code}"[:60]
        site.ovpn_common_name = cn
        site.ovpn_client_ip = openvpn.next_client_ip(site_index)
        try:
            if openvpn.pki_ready():
                openvpn.issue_client(cn, site.ovpn_client_ip, virtual_subnet)
            else:
                site.notes = "OpenVPN PKI not ready yet — regenerate config from site page once openvpn is up"
        except Exception as exc:
            logger.warning("OpenVPN issue client: %s", exc)
            site.notes = f"OpenVPN pending: {exc}"

    db.add(site)
    db.commit()
    db.refresh(site)

    if access_mode == "direct":
        device_ip = default_gateway_virtual_ip(virtual_subnet)
        add_device(
            db,
            site,
            label=(device_label or name).strip() or "Direct device",
            device_type="direct",
            local_ip=device_ip,
            admin_port=device_admin_port if device_admin_port is not None else 80,
        )
    else:
        # Seed a default router device for the cheat sheet
        add_device(
            db,
            site,
            label="Cabinet Router",
            device_type="router",
            local_ip=str(ipaddress.ip_network(local_subnet).network_address + 1),
            admin_port=80,
        )
    return site


def add_device(
    db: Session,
    site: Site,
    *,
    label: str,
    device_type: str,
    local_ip: str,
    admin_port: int | None = None,
) -> SiteDevice:
    vip = virtual_ip_for_local(site.virtual_subnet, local_ip, site.local_subnet)
    device = SiteDevice(
        site_id=site.id,
        label=label,
        device_type=device_type,
        local_ip=local_ip,
        virtual_ip=vip,
        admin_port=admin_port,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def wireguard_client_conf(db: Session, site: Site) -> str:
    settings = get_or_create_settings(db)
    if not site.wg_private_key or not site.wg_hub_public_key or not site.wg_tunnel_ip:
        raise ValueError("Site is not a WireGuard site with keys")
    if getattr(site, "access_mode", "gateway") == "direct":
        # Device address is the ParkTech virtual IP; reach hub + engineer pool
        allowed = "10.100.0.0/22"
    else:
        # Gateway router: hub WG net only (LAN stays local; NETMAP on hub)
        allowed = "10.100.0.0/24"
    return wireguard.render_client_conf(
        client_private_key=site.wg_private_key,
        client_address=site.wg_tunnel_ip,
        hub_public_key=site.wg_hub_public_key,
        hub_endpoint=settings.wg_endpoint,
        allowed_ips=allowed,
    )


def teltonika_uci_script(db: Session, site: Site) -> str:
    """Generate Teltonika RutOS UCI script for WireGuard site setup."""
    from app.services.teltonika import render_teltonika_uci

    settings = get_or_create_settings(db)
    if site.vpn_type != "wireguard":
        raise ValueError("Teltonika config only available for WireGuard sites")
    if getattr(site, "access_mode", "gateway") == "direct":
        raise ValueError("Teltonika config is for gateway sites only (direct devices use WireGuard .conf)")
    if not site.wg_private_key or not site.wg_hub_public_key or not site.wg_tunnel_ip:
        raise ValueError("Site is not a WireGuard site with keys")

    return render_teltonika_uci(
        site_private_key=site.wg_private_key,
        site_tunnel_ip=site.wg_tunnel_ip,
        hub_public_key=site.wg_hub_public_key,
        hub_endpoint=settings.wg_endpoint,
        virtual_subnet=site.virtual_subnet,
        local_subnet=site.local_subnet,
    )


def openvpn_client_conf(site: Site) -> str:
    if not site.ovpn_common_name:
        raise ValueError("Not an OpenVPN site")
    if not openvpn.pki_ready():
        raise RuntimeError("OpenVPN PKI not ready")
    # Re-issue to refresh endpoint from settings
    openvpn.issue_client(site.ovpn_common_name, site.ovpn_client_ip or "10.100.1.10", site.virtual_subnet)
    return openvpn.read_client_ovpn(site.ovpn_common_name)


def tailscale_join_cmd(db: Session, site: Site) -> str:
    settings = get_or_create_settings(db)
    key = site.ts_preauth_key or "<missing-preauth-key>"
    return hs.join_command(settings.headscale_url, key, site.virtual_subnet)


def _clear_wireguard_peer(site: Site) -> None:
    if site.wg_public_key:
        try:
            wireguard.remove_peer(site.wg_public_key)
        except Exception as exc:
            logger.warning("remove WG peer %s: %s", site.site_code, exc)


def _provision_vpn_for_site(db: Session, site: Site) -> None:
    """(Re)create VPN credentials for the site's current vpn_type. Keeps virtual_subnet."""
    cfg = get_settings()
    settings = get_or_create_settings(db)
    vpn_type = site.vpn_type
    access_mode = getattr(site, "access_mode", "gateway") or "gateway"

    if vpn_type == "tailscale":
        client = hs.HeadscaleClient()
        user = cfg.headscale_user
        site.ts_user = user
        try:
            site.ts_preauth_key = client.create_preauth_key(user, reusable=False, expiration_days=365)
            site.notes = None
        except Exception as exc:
            logger.exception("Headscale preauth failed")
            site.notes = f"Headscale preauth pending: {exc}"
            site.ts_preauth_key = None
        site.wg_private_key = None
        site.wg_public_key = None
        site.wg_hub_public_key = None
        site.wg_tunnel_ip = None
        site.ovpn_common_name = None
        site.ovpn_client_ip = None

    elif vpn_type == "wireguard":
        hub = ensure_hub_wireguard_keys(db)
        priv, pub = wireguard.generate_keypair()
        site.wg_private_key = priv
        site.wg_public_key = pub
        site.wg_hub_public_key = hub.wg_public_key
        site.ts_preauth_key = None
        site.ts_node_id = None
        site.ts_node_name = None
        site.ovpn_common_name = None
        site.ovpn_client_ip = None
        if access_mode == "direct":
            device_ip = default_gateway_virtual_ip(site.virtual_subnet)
            site.wg_tunnel_ip = f"{device_ip}/32"
            allowed = f"{device_ip}/32"
            try:
                wireguard.set_peer(pub, allowed)
                netmap.sync_routes_for_wireguard(allowed, cfg.wg_interface)
            except Exception as exc:
                logger.warning("WG peer apply (direct): %s", exc)
        else:
            site.wg_tunnel_ip = f"10.100.0.{10 + site.site_index}/32"
            try:
                wireguard.set_peer(pub, f"{site.virtual_subnet}, {site.wg_tunnel_ip.split('/')[0]}/32")
                netmap.apply_site_netmap(site.virtual_subnet, site.local_subnet)
                netmap.sync_routes_for_wireguard(site.virtual_subnet, cfg.wg_interface)
            except Exception as exc:
                logger.warning("WG peer apply: %s", exc)

    elif vpn_type == "openvpn":
        cn = f"site-{site.site_code}"[:60]
        site.ovpn_common_name = cn
        site.ovpn_client_ip = openvpn.next_client_ip(site.site_index)
        site.wg_private_key = None
        site.wg_public_key = None
        site.wg_hub_public_key = None
        site.wg_tunnel_ip = None
        site.ts_preauth_key = None
        try:
            if openvpn.pki_ready():
                openvpn.issue_client(cn, site.ovpn_client_ip, site.virtual_subnet)
                site.notes = None
            else:
                site.notes = "OpenVPN PKI not ready yet — regenerate config from site page once openvpn is up"
        except Exception as exc:
            logger.warning("OpenVPN issue client: %s", exc)
            site.notes = f"OpenVPN pending: {exc}"
    else:
        raise ValueError("vpn_type must be tailscale, wireguard, or openvpn")


def update_site(
    db: Session,
    site: Site,
    *,
    name: str | None = None,
    region: str | None = None,
    local_subnet: str | None = None,
    notes: str | None = None,
) -> Site:
    if name is not None:
        site.name = name.strip() or site.name
    if region is not None:
        site.region = region.strip()
    if notes is not None:
        site.notes = notes.strip() or None
    if local_subnet is not None and local_subnet.strip():
        new_local = local_subnet.strip()
        if new_local != site.local_subnet and getattr(site, "access_mode", "gateway") == "gateway":
            site.local_subnet = new_local
            # Refresh NETMAP if WireGuard gateway
            if site.vpn_type == "wireguard" and site.enabled:
                try:
                    netmap.apply_site_netmap(site.virtual_subnet, site.local_subnet)
                    netmap.sync_routes_for_wireguard(site.virtual_subnet, get_settings().wg_interface)
                except Exception as exc:
                    logger.warning("NETMAP refresh after local_subnet change: %s", exc)
            # Remap device virtual IPs to match new local host offsets
            for device in list(site.devices):
                try:
                    device.virtual_ip = virtual_ip_for_local(
                        site.virtual_subnet, device.local_ip, site.local_subnet
                    )
                except ValueError:
                    pass
    db.commit()
    db.refresh(site)
    return site


def set_site_enabled(db: Session, site: Site, enabled: bool) -> Site:
    site.enabled = bool(enabled)
    if not site.enabled:
        site.online = False
        if site.vpn_type == "wireguard":
            _clear_wireguard_peer(site)
    elif site.vpn_type == "wireguard" and site.wg_public_key and site.wg_tunnel_ip:
        # Re-add peer on enable
        try:
            if getattr(site, "access_mode", "gateway") == "direct":
                device_ip = site.wg_tunnel_ip.split("/")[0]
                wireguard.set_peer(site.wg_public_key, f"{device_ip}/32")
            else:
                wireguard.set_peer(
                    site.wg_public_key,
                    f"{site.virtual_subnet}, {site.wg_tunnel_ip.split('/')[0]}/32",
                )
                netmap.apply_site_netmap(site.virtual_subnet, site.local_subnet)
        except Exception as exc:
            logger.warning("re-enable WG peer: %s", exc)
    db.commit()
    db.refresh(site)
    return site


def change_site_vpn(db: Session, site: Site, vpn_type: str) -> Site:
    """Switch protocol and issue fresh credentials. Virtual subnet / devices kept."""
    vpn_type = (vpn_type or "").strip().lower()
    if getattr(site, "access_mode", "gateway") == "direct":
        vpn_type = "wireguard"
    if vpn_type not in {"tailscale", "wireguard", "openvpn"}:
        raise ValueError("vpn_type must be tailscale, wireguard, or openvpn")
    if site.vpn_type == vpn_type:
        # Same type: rotate credentials
        if site.vpn_type == "wireguard":
            _clear_wireguard_peer(site)
        _provision_vpn_for_site(db, site)
        db.commit()
        db.refresh(site)
        return site

    if site.vpn_type == "wireguard":
        _clear_wireguard_peer(site)
    site.vpn_type = vpn_type
    site.online = False
    _provision_vpn_for_site(db, site)
    db.commit()
    db.refresh(site)
    return site


def delete_site(db: Session, site: Site) -> None:
    if site.vpn_type == "wireguard":
        _clear_wireguard_peer(site)
    db.delete(site)
    db.commit()


def reconcile_wireguard_peers(db: Session) -> None:
    hub = ensure_hub_wireguard_keys(db)
    if hub.wg_private_key:
        try:
            wireguard.ensure_hub_interface(hub.wg_private_key)
        except Exception as exc:
            logger.debug("ensure hub iface: %s", exc)
    sites = db.scalars(select(Site).where(Site.vpn_type == "wireguard")).all()
    cfg = get_settings()
    for site in sites:
        if not getattr(site, "enabled", True):
            if site.wg_public_key:
                try:
                    wireguard.remove_peer(site.wg_public_key)
                except Exception:
                    pass
            continue
        if not site.wg_public_key or not site.wg_tunnel_ip:
            continue
        try:
            if getattr(site, "access_mode", "gateway") == "direct":
                device_ip = site.wg_tunnel_ip.split("/")[0]
                allowed = f"{device_ip}/32"
                wireguard.set_peer(site.wg_public_key, allowed)
                netmap.sync_routes_for_wireguard(allowed, cfg.wg_interface)
            else:
                allowed = f"{site.virtual_subnet}, {site.wg_tunnel_ip.split('/')[0]}/32"
                wireguard.set_peer(site.wg_public_key, allowed)
                netmap.apply_site_netmap(site.virtual_subnet, site.local_subnet)
                netmap.sync_routes_for_wireguard(site.virtual_subnet, cfg.wg_interface)
        except Exception as exc:
            logger.debug("reconcile peer %s: %s", site.site_code, exc)


def poll_site_status(db: Session) -> None:
    cfg = get_settings()
    now = datetime.utcnow()

    # Tailscale
    try:
        client = hs.HeadscaleClient()
        nodes = client.list_nodes(user=cfg.headscale_user) if client.ready() else []
    except Exception as exc:
        logger.debug("headscale poll: %s", exc)
        nodes = []

    ts_sites = db.scalars(select(Site).where(Site.vpn_type == "tailscale")).all()
    for site in ts_sites:
        if not getattr(site, "enabled", True):
            site.online = False
            continue
        node = None
        for n in nodes:
            name = (n.get("name") or n.get("givenName") or "").lower()
            if site.site_code.lower() in name or (site.ts_node_name and site.ts_node_name.lower() == name):
                node = n
                break
        if not node and nodes and len(ts_sites) == 1 and len(nodes) == 1:
            node = nodes[0]
        if node:
            site.ts_node_id = str(node.get("id") or node.get("Id") or "")
            site.ts_node_name = node.get("name") or node.get("givenName")
            online = client.node_online(node) if "client" in dir() else bool(node.get("online"))
            # If online field missing, treat presence as online for POC
            if "online" not in node and "Online" not in node:
                online = True
            else:
                online = bool(node.get("online") or node.get("Online"))
            site.online = online
            if online:
                site.last_seen = now
        else:
            site.online = False

    # WireGuard
    handshakes = {p.public_key: p for p in wireguard.parse_handshakes()}
    for site in db.scalars(select(Site).where(Site.vpn_type == "wireguard")).all():
        if not getattr(site, "enabled", True):
            site.online = False
            continue
        peer = handshakes.get(site.wg_public_key or "")
        if peer and peer.latest_handshake:
            site.last_handshake = peer.latest_handshake
            site.online = wireguard.handshake_is_online(peer.latest_handshake)
            if site.online:
                site.last_seen = peer.latest_handshake
        else:
            # Dry-run / no handshake data
            if cfg.wg_dry_run:
                continue
            site.online = False

    # OpenVPN
    connected = openvpn.connected_clients()
    for site in db.scalars(select(Site).where(Site.vpn_type == "openvpn")).all():
        if not getattr(site, "enabled", True):
            site.online = False
            continue
        cn = site.ovpn_common_name or ""
        if cn in connected:
            site.online = True
            site.last_seen = connected[cn]
        else:
            site.online = False

    db.commit()
