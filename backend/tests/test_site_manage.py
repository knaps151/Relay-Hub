"""Site edit, disable, VPN change, delete."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.services.provision import (
    change_site_vpn,
    create_site,
    delete_site,
    set_site_enabled,
    update_site,
)


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    monkeypatch.setenv("WG_DRY_RUN", "1")
    monkeypatch.setenv("NFT_DRY_RUN", "1")
    from app.config import get_settings

    get_settings.cache_clear()
    yield session
    session.close()
    get_settings.cache_clear()


def test_update_site_meta(db_session):
    site = create_site(
        db_session,
        name="Old",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="192.168.1.0/24",
        region="South",
    )
    update_site(db_session, site, name="New Name", region="North", notes="hello")
    assert site.name == "New Name"
    assert site.region == "North"
    assert site.notes == "hello"


def test_disable_and_enable(db_session):
    site = create_site(
        db_session,
        name="Gate",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="10.0.0.0/24",
    )
    site.online = True
    db_session.commit()
    set_site_enabled(db_session, site, False)
    assert site.enabled is False
    assert site.online is False
    set_site_enabled(db_session, site, True)
    assert site.enabled is True


def test_change_vpn_openvpn_to_wireguard(db_session):
    site = create_site(
        db_session,
        name="Proto",
        vpn_type="openvpn",
        access_mode="gateway",
        local_subnet="10.0.0.0/24",
    )
    virt = site.virtual_subnet
    change_site_vpn(db_session, site, "wireguard")
    assert site.vpn_type == "wireguard"
    assert site.virtual_subnet == virt
    assert site.wg_public_key
    assert site.wg_tunnel_ip


def test_delete_site(db_session):
    site = create_site(
        db_session,
        name="Gone",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="10.0.0.0/24",
    )
    sid = site.id
    delete_site(db_session, site)
    assert db_session.get(type(site), sid) is None
