"""Direct device site provisioning (no router / NETMAP)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import SiteDevice
from app.services.provision import create_site, wireguard_client_conf
from app.services.subnets import default_gateway_virtual_ip


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Avoid touching real wg/nft during unit tests
    monkeypatch.setenv("WG_DRY_RUN", "1")
    monkeypatch.setenv("NFT_DRY_RUN", "1")
    from app.config import get_settings

    get_settings.cache_clear()

    yield session
    session.close()
    get_settings.cache_clear()


def test_create_direct_site_allocates_virtual_ip_and_device(db_session):
    site = create_site(
        db_session,
        name="Depot charger",
        vpn_type="openvpn",  # forced to wireguard for direct
        access_mode="direct",
        device_label="Charger A",
        device_admin_port=8080,
    )

    assert site.access_mode == "direct"
    assert site.vpn_type == "wireguard"
    assert site.local_subnet == site.virtual_subnet
    device_ip = default_gateway_virtual_ip(site.virtual_subnet)
    assert site.wg_tunnel_ip == f"{device_ip}/32"
    assert site.wg_private_key and site.wg_public_key

    devices = db_session.query(SiteDevice).filter_by(site_id=site.id).all()
    assert len(devices) == 1
    assert devices[0].label == "Charger A"
    assert devices[0].device_type == "direct"
    assert devices[0].virtual_ip == device_ip
    assert devices[0].local_ip == device_ip
    assert devices[0].admin_port == 8080


def test_direct_wireguard_conf_uses_virtual_address(db_session):
    site = create_site(
        db_session,
        name="Solo cam",
        vpn_type="wireguard",
        access_mode="direct",
    )
    conf = wireguard_client_conf(db_session, site)
    device_ip = default_gateway_virtual_ip(site.virtual_subnet)
    assert f"Address = {device_ip}/32" in conf
    assert "AllowedIPs = 10.100.0.0/22" in conf
    assert "DNS =" not in conf
    assert ", " not in conf.split("AllowedIPs =", 1)[1].split("\n", 1)[0]


def test_gateway_wireguard_conf_includes_dns_for_unifi(db_session):
    site = create_site(
        db_session,
        name="UniFi Site",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="10.0.0.0/24",
    )
    conf = wireguard_client_conf(db_session, site)
    assert "DNS = 1.1.1.1" in conf
    assert "AllowedIPs = 10.100.0.0/22" in conf


def test_gateway_site_unchanged_defaults(db_session):
    site = create_site(
        db_session,
        name="North Street",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="192.168.1.0/24",
    )
    assert site.access_mode == "gateway"
    assert site.local_subnet == "192.168.1.0/24"
    assert site.wg_tunnel_ip.startswith("10.100.0.")
    devices = db_session.query(SiteDevice).filter_by(site_id=site.id).all()
    assert any(d.device_type == "router" for d in devices)
