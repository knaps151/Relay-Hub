"""Tests for security features (Issue #2)."""

import pytest
from unittest.mock import patch

from app.config import Settings


class TestSecurityWarning:
    def test_insecure_config_default_password_production(self):
        """Warning should appear when default password is used in production mode."""
        with patch("app.main.get_settings") as mock_settings:
            mock_settings.return_value = Settings(
                admin_password="relay",
                http_only=False,  # Production mode
            )
            from app.main import _is_insecure_config, _security_warning

            assert _is_insecure_config() is True
            warning = _security_warning()
            assert warning is not None
            assert "default password" in warning.lower() or "relay" in warning

    def test_secure_config_custom_password(self):
        """No warning when custom password is used."""
        with patch("app.main.get_settings") as mock_settings:
            mock_settings.return_value = Settings(
                admin_password="secure-password-123",
                http_only=False,
            )
            from app.main import _is_insecure_config, _security_warning

            assert _is_insecure_config() is False
            assert _security_warning() is None

    def test_secure_config_http_only_mode(self):
        """No warning in HTTP_ONLY mode even with default password."""
        with patch("app.main.get_settings") as mock_settings:
            mock_settings.return_value = Settings(
                admin_password="relay",
                http_only=True,  # Development mode
            )
            from app.main import _is_insecure_config, _security_warning

            assert _is_insecure_config() is False
            assert _security_warning() is None


class TestSchemaUpgrade:
    def test_schema_upgrade_idempotent(self):
        """Schema upgrades should be idempotent."""
        from sqlalchemy import create_engine, inspect
        from sqlalchemy.orm import sessionmaker

        from app.db import Base, run_schema_upgrades

        # Create an in-memory database
        engine = create_engine("sqlite:///:memory:")

        # Create tables
        Base.metadata.create_all(engine)

        # Get initial table names
        inspector = inspect(engine)
        initial_tables = set(inspector.get_table_names())

        # Run schema upgrades twice - should be idempotent
        with patch("app.db.engine", engine):
            run_schema_upgrades()
            run_schema_upgrades()

        # Verify tables still exist
        inspector = inspect(engine)
        final_tables = set(inspector.get_table_names())
        assert initial_tables == final_tables


class TestAuthRequirements:
    """Test that sensitive routes require authentication."""

    def test_wireguard_conf_requires_auth(self):
        """WireGuard config download should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        # Try to access without auth - should redirect to login
        response = client.get("/sites/1/wireguard.conf", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_openvpn_conf_requires_auth(self):
        """OpenVPN config download should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/sites/1/client.ovpn", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_site_detail_requires_auth(self):
        """Site detail page should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/sites/1", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_refresh_tailscale_key_requires_auth(self):
        """Refreshing Tailscale preauth key should require authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app, raise_server_exceptions=False)

        response = client.post("/sites/1/tailscale/refresh-key", follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_healthz_does_not_require_auth(self):
        """Health check should be accessible without authentication."""
        from fastapi.testclient import TestClient
        from app.main import app

        client = TestClient(app)

        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"ok": True}
