"""Tests for Engineer management (Issue #4)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from unittest.mock import patch, MagicMock

from app.db import Base
from app.models import Engineer, HubState
from app.services.engineers import (
    ENGINEER_START_IP,
    ENGINEER_SUBNET,
    create_engineer,
    delete_engineer,
    disable_engineer,
    enable_engineer,
    next_engineer_ip,
    render_engineer_conf,
)


@pytest.fixture
def db_session():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def db_with_hub(db_session):
    """Database session with hub state configured."""
    hub = HubState(
        id=1,
        wg_private_key="aHViLXByaXZhdGUta2V5LWZvci10ZXN0aW5n",
        wg_public_key="aHViLXB1YmxpYy1rZXktZm9yLXRlc3Rpbmc=",
    )
    db_session.add(hub)
    db_session.commit()
    return db_session


class TestEngineerIP:
    def test_first_engineer_gets_start_ip(self, db_session):
        """First engineer should get IP at ENGINEER_START_IP."""
        ip = next_engineer_ip(db_session)
        assert ip == f"10.100.2.{ENGINEER_START_IP}"

    def test_sequential_ip_allocation(self, db_session):
        """Sequential engineers should get sequential IPs."""
        # Create first engineer
        eng1 = Engineer(
            name="Engineer 1",
            wg_private_key="key1",
            wg_public_key="pub1",
            assigned_ip="10.100.2.10/32",
        )
        db_session.add(eng1)
        db_session.commit()

        ip = next_engineer_ip(db_session)
        assert ip == "10.100.2.11"

    def test_reuses_deleted_ip(self, db_session):
        """Should reuse IPs from deleted engineers."""
        # Create engineers at .10 and .12
        eng1 = Engineer(
            name="Engineer 1",
            wg_private_key="key1",
            wg_public_key="pub1",
            assigned_ip="10.100.2.10/32",
        )
        eng2 = Engineer(
            name="Engineer 2",
            wg_private_key="key2",
            wg_public_key="pub2",
            assigned_ip="10.100.2.12/32",
        )
        db_session.add_all([eng1, eng2])
        db_session.commit()

        # Next IP should be .11 (the gap)
        ip = next_engineer_ip(db_session)
        assert ip == "10.100.2.11"

    def test_respects_reserved_range(self, db_session):
        """IPs before ENGINEER_START_IP should not be allocated."""
        # Even with no engineers, should not use .1-.9
        ip = next_engineer_ip(db_session)
        host = int(ip.split(".")[-1])
        assert host >= ENGINEER_START_IP


class TestCreateEngineer:
    @patch("app.services.engineers.wireguard.generate_keypair")
    @patch("app.services.engineers.wireguard.set_peer")
    @patch("app.services.engineers.ensure_hub_wireguard_keys")
    def test_create_engineer_generates_keys(
        self, mock_ensure_hub, mock_set_peer, mock_generate, db_session
    ):
        """Creating an engineer should generate a keypair."""
        mock_generate.return_value = ("private-key", "public-key")
        mock_ensure_hub.return_value = MagicMock()

        engineer = create_engineer(db_session, name="Test Engineer")

        assert engineer.wg_private_key == "private-key"
        assert engineer.wg_public_key == "public-key"
        assert engineer.name == "Test Engineer"
        assert engineer.enabled is True

    @patch("app.services.engineers.wireguard.generate_keypair")
    @patch("app.services.engineers.wireguard.set_peer")
    @patch("app.services.engineers.ensure_hub_wireguard_keys")
    def test_create_engineer_adds_peer(
        self, mock_ensure_hub, mock_set_peer, mock_generate, db_session
    ):
        """Creating an engineer should add a WireGuard peer."""
        mock_generate.return_value = ("private-key", "public-key")
        mock_ensure_hub.return_value = MagicMock()

        create_engineer(db_session, name="Test Engineer")

        mock_set_peer.assert_called_once()
        call_args = mock_set_peer.call_args
        assert call_args[0][0] == "public-key"  # Public key
        assert "10.100.2" in call_args[0][1]  # AllowedIPs


class TestEnableDisable:
    @patch("app.services.engineers.wireguard.set_peer")
    def test_enable_adds_peer(self, mock_set_peer, db_session):
        """Enabling an engineer should add their peer."""
        eng = Engineer(
            name="Test",
            wg_private_key="priv",
            wg_public_key="pub",
            assigned_ip="10.100.2.10/32",
            enabled=False,
        )
        db_session.add(eng)
        db_session.commit()

        enable_engineer(db_session, eng)

        assert eng.enabled is True
        mock_set_peer.assert_called()

    @patch("app.services.engineers.wireguard.remove_peer")
    def test_disable_removes_peer(self, mock_remove_peer, db_session):
        """Disabling an engineer should remove their peer."""
        eng = Engineer(
            name="Test",
            wg_private_key="priv",
            wg_public_key="pub",
            assigned_ip="10.100.2.10/32",
            enabled=True,
        )
        db_session.add(eng)
        db_session.commit()

        disable_engineer(db_session, eng)

        assert eng.enabled is False
        mock_remove_peer.assert_called_with("pub")


class TestDeleteEngineer:
    @patch("app.services.engineers.wireguard.remove_peer")
    def test_delete_removes_peer(self, mock_remove_peer, db_session):
        """Deleting an engineer should remove their peer."""
        eng = Engineer(
            name="Test",
            wg_private_key="priv",
            wg_public_key="pub",
            assigned_ip="10.100.2.10/32",
            enabled=True,
        )
        db_session.add(eng)
        db_session.commit()
        eng_id = eng.id

        delete_engineer(db_session, eng)

        mock_remove_peer.assert_called_with("pub")
        assert db_session.get(Engineer, eng_id) is None


class TestEngineerConf:
    def test_conf_contains_required_fields(self, db_with_hub):
        """Engineer config should contain all required WireGuard fields."""
        from app.models import SettingsRow

        settings = SettingsRow(id=1, wg_endpoint="vpn.example.com:51820")
        db_with_hub.add(settings)
        db_with_hub.commit()

        eng = Engineer(
            name="Test Engineer",
            wg_private_key="dGVzdC1wcml2YXRlLWtleQ==",
            wg_public_key="dGVzdC1wdWJsaWMta2V5",
            assigned_ip="10.100.2.15/32",
        )
        db_with_hub.add(eng)
        db_with_hub.commit()

        conf = render_engineer_conf(db_with_hub, eng)

        assert "[Interface]" in conf
        assert "[Peer]" in conf
        assert "PrivateKey = dGVzdC1wcml2YXRlLWtleQ==" in conf
        assert "Address = 10.100.2.15/32" in conf
        assert "Endpoint = vpn.example.com:51820" in conf
        assert "10.101.0.0/16" in conf  # Site subnets
        assert "10.100.0.0/22" in conf  # Hub transit networks


class TestEngineerEndpoints:
    """Test engineer endpoints require authentication."""

    def test_engineers_list_requires_auth(self):
        """Engineers list should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/engineers", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_engineer_conf_requires_auth(self):
        """Engineer config download should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/engineers/1/wireguard.conf", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")
