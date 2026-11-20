"""Tests for hub LAN auto-scan."""

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Site, SiteDevice
from app.services.lan_scan import scan_and_add_devices
from app.services.provision import add_device, create_site


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


def _gateway_site(db, *, online: bool = True) -> Site:
    site = create_site(
        db,
        name="Scan Site",
        vpn_type="wireguard",
        access_mode="gateway",
        local_subnet="192.168.1.0/24",
    )
    site.online = online
    db.commit()
    db.refresh(site)
    return site


class TestScanGuards:
    def test_refuses_offline(self, db_session):
        site = _gateway_site(db_session, online=False)
        with patch("app.services.lan_scan.parse_handshakes", return_value=[]):
            with pytest.raises(ValueError, match="offline"):
                scan_and_add_devices(db_session, site)

    def test_refuses_direct(self, db_session):
        site = create_site(
            db_session,
            name="Direct",
            vpn_type="wireguard",
            access_mode="direct",
        )
        site.online = True
        db_session.commit()
        with pytest.raises(ValueError, match="gateway"):
            scan_and_add_devices(db_session, site)

    def test_refuses_non_wireguard(self, db_session):
        site = Site(
            name="TS Site",
            site_code="ts-site",
            vpn_type="tailscale",
            access_mode="gateway",
            site_index=9,
            virtual_subnet="10.101.9.0/24",
            local_subnet="192.168.1.0/24",
            online=True,
        )
        db_session.add(site)
        db_session.commit()
        with pytest.raises(ValueError, match="WireGuard"):
            scan_and_add_devices(db_session, site)


def _noop_enrich(items, **_kwargs):
    """Skip real DNS/port probes in unit tests unless a test patches richer data."""
    from app.services.host_enrich import HostEnrichment

    return {
        vip: HostEnrichment(
            ip=vip,
            label=f"Discovered host {local}",
            device_type="generic",
        )
        for vip, local in items
    }


class TestScanAdd:
    def test_adds_responsive_hosts(self, db_session):
        site = _gateway_site(db_session)
        vip_a = f"10.101.{site.site_index}.50"
        vip_b = f"10.101.{site.site_index}.60"

        def fake_ping(ip: str) -> bool:
            return ip in {vip_a, vip_b}

        with patch("app.services.lan_scan.parse_handshakes", return_value=[]):
            with patch("app.services.lan_scan._ping_host", side_effect=fake_ping):
                with patch("app.services.lan_scan.enrich_hosts", side_effect=_noop_enrich):
                    result = scan_and_add_devices(db_session, site)

        assert result.probed == 254
        assert result.responsive == 2
        assert len(result.added) == 2
        labels = {d.label for d in result.added}
        assert "Discovered host 192.168.1.50" in labels
        assert "Discovered host 192.168.1.60" in labels
        assert all(d.device_type == "generic" for d in result.added)
        assert {d.virtual_ip for d in result.added} == {vip_a, vip_b}

    def test_uses_enrichment_for_label_type_port(self, db_session):
        from app.services.host_enrich import HostEnrichment

        site = _gateway_site(db_session)
        vip = f"10.101.{site.site_index}.50"

        def fake_ping(ip: str) -> bool:
            return ip == vip

        def fake_enrich(items, **_kwargs):
            return {
                vip: HostEnrichment(
                    ip=vip,
                    hostname="yard-cam.local",
                    open_ports=[80, 554],
                    device_type="camera",
                    admin_port=80,
                    label="yard-cam",
                )
            }

        with patch("app.services.lan_scan.parse_handshakes", return_value=[]):
            with patch("app.services.lan_scan._ping_host", side_effect=fake_ping):
                with patch("app.services.lan_scan.enrich_hosts", side_effect=fake_enrich):
                    result = scan_and_add_devices(db_session, site)

        assert len(result.added) == 1
        device = result.added[0]
        assert device.label == "yard-cam"
        assert device.device_type == "camera"
        assert device.admin_port == 80
        assert device.local_ip == "192.168.1.50"

    def test_skips_existing(self, db_session):
        site = _gateway_site(db_session)
        existing = add_device(
            db_session,
            site,
            label="Camera",
            device_type="camera",
            local_ip="192.168.1.50",
        )
        vip = existing.virtual_ip

        def fake_ping(ip: str) -> bool:
            return ip == vip

        with patch("app.services.lan_scan.parse_handshakes", return_value=[]):
            with patch("app.services.lan_scan._ping_host", side_effect=fake_ping):
                with patch("app.services.lan_scan.enrich_hosts", side_effect=_noop_enrich):
                    result = scan_and_add_devices(db_session, site)

        assert result.responsive == 1
        assert result.skipped_existing == 1
        assert result.added == []
        cameras = (
            db_session.query(SiteDevice)
            .filter_by(site_id=site.id, label="Camera")
            .all()
        )
        assert len(cameras) == 1

    def test_no_duplicates_on_rescan(self, db_session):
        site = _gateway_site(db_session)
        vip = f"10.101.{site.site_index}.10"

        def fake_ping(ip: str) -> bool:
            return ip == vip

        with patch("app.services.lan_scan.parse_handshakes", return_value=[]):
            with patch("app.services.lan_scan._ping_host", side_effect=fake_ping):
                with patch("app.services.lan_scan.enrich_hosts", side_effect=_noop_enrich):
                    first = scan_and_add_devices(db_session, site)
                    second = scan_and_add_devices(db_session, site)

        assert len(first.added) == 1
        assert second.added == []
        assert second.skipped_existing == 1
        discovered = (
            db_session.query(SiteDevice)
            .filter_by(site_id=site.id, virtual_ip=vip)
            .count()
        )
        assert discovered == 1
