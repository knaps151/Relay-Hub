"""Tests for Access Log feature (Issue #11)."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import AccessEvent, Engineer, Site
from app.main import app


class TestAccessEventModel:
    """Test AccessEvent model and audit service."""

    @pytest.fixture
    def db_session(self):
        """Create a test database session."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        yield session
        session.close()

    def test_record_creates_event(self, db_session):
        """record() should create an access event."""
        from app.services.audit import record

        with patch("app.services.audit.logger"):
            event = record(
                db_session,
                kind="login",
                actor_type="admin",
                actor_name="Admin",
                source_ip="192.168.1.100",
            )

        assert event.id is not None
        assert event.kind == "login"
        assert event.actor_type == "admin"
        assert event.source_ip == "192.168.1.100"
        assert event.timestamp is not None

    def test_record_login(self, db_session):
        """record_login() should create a login event."""
        from app.services.audit import record_login

        with patch("app.services.audit.logger"):
            event = record_login(db_session, source_ip="10.0.0.1")

        assert event.kind == "login"
        assert event.actor_type == "admin"
        assert event.source_ip == "10.0.0.1"

    def test_prune_old_events(self, db_session):
        """prune_old_events() should delete events older than retention."""
        from app.services.audit import record, prune_old_events

        with patch("app.services.audit.logger"):
            # Create an old event
            old_event = record(db_session, kind="login", actor_name="Admin")
            old_id = old_event.id  # Save ID before deletion
            old_event.timestamp = datetime.utcnow() - timedelta(days=100)
            db_session.commit()

            # Create a recent event
            recent_event = record(db_session, kind="login", actor_name="Admin")
            recent_id = recent_event.id  # Save ID

            # Prune with 90-day retention
            deleted = prune_old_events(db_session, retention_days=90)

        assert deleted == 1
        # Old event should be gone
        assert db_session.get(AccessEvent, old_id) is None
        # Recent event should still exist
        assert db_session.get(AccessEvent, recent_id) is not None

    def test_get_recent_events_filtering(self, db_session):
        """get_recent_events() should filter by site_id and kind."""
        from app.services.audit import record, get_recent_events

        with patch("app.services.audit.logger"):
            # Create events for different sites
            record(db_session, kind="login", actor_name="Admin", site_id=1)
            record(db_session, kind="config_download", actor_name="Admin", site_id=1)
            record(db_session, kind="login", actor_name="Admin", site_id=2)

        # Filter by site_id
        site1_events = get_recent_events(db_session, site_id=1)
        assert len(site1_events) == 2

        # Filter by kind
        login_events = get_recent_events(db_session, kind="login")
        assert len(login_events) == 2

        # Filter by both
        site1_logins = get_recent_events(db_session, site_id=1, kind="login")
        assert len(site1_logins) == 1


class TestAccessLogRoutes:
    """Test access log UI routes require authentication."""

    def test_connected_page_requires_auth(self):
        """Connected page should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/connected", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_access_log_page_requires_auth(self):
        """Access log page should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/access-log", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_csv_export_requires_auth(self):
        """CSV export should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/access-log/export.csv", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")


class TestAccessLogAPI:
    """Test access log JSON API endpoints."""

    def test_api_access_events_requires_auth(self):
        """Access events API should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/access-events")
        assert response.status_code == 401

    def test_api_sessions_requires_auth(self):
        """Sessions API should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/sessions")
        assert response.status_code == 401


class TestSessionsService:
    """Test sessions service."""

    @pytest.fixture
    def db_session(self):
        """Create a test database session."""
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        yield session
        session.close()

    def test_live_session_dataclass(self):
        """LiveSession dataclass should work correctly."""
        from app.services.sessions import LiveSession

        session = LiveSession(
            actor_type="engineer",
            actor_id=1,
            actor_name="Test Engineer",
            vpn_type="wireguard",
            endpoint="1.2.3.4:51820",
            last_handshake=datetime.utcnow(),
            transfer_rx=1024,
            transfer_tx=2048,
        )

        assert session.actor_type == "engineer"
        assert session.actor_id == 1
        assert session.vpn_type == "wireguard"
        assert session.transfer_rx == 1024

    def test_clear_state_cache(self):
        """clear_state_cache() should clear the in-memory state."""
        from app.services.sessions import _last_online_state, clear_state_cache

        # Add some state
        _last_online_state["test:1"] = True
        _last_online_state["test:2"] = False

        # Clear it
        clear_state_cache()

        # Should be empty
        assert len(_last_online_state) == 0


class TestAuditRecordingIntegration:
    """Test that audit recording functions are correct."""

    def test_record_config_download(self):
        """record_config_download should create proper event."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        # Create a mock site
        site = Site(
            id=1,
            name="Test Site",
            site_code="test",
            vpn_type="wireguard",
            site_index=0,
            virtual_subnet="10.101.0.0/24",
            local_subnet="192.168.1.0/24",
        )
        db.add(site)
        db.commit()

        from app.services.audit import record_config_download

        with patch("app.services.audit.logger"):
            event = record_config_download(db, site=site, config_type="wireguard.conf", source_ip="1.2.3.4")

        assert event.kind == "config_download"
        assert event.site_id == 1
        assert event.source_ip == "1.2.3.4"
        assert "wireguard.conf" in event.detail
        db.close()
