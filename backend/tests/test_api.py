"""Tests for JSON API endpoints (Issue #5)."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from app.main import app


class TestAPIAuth:
    """Test API authentication requirements."""

    def test_api_sites_requires_auth(self):
        """API endpoints should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/sites")
        assert response.status_code == 401
        assert "Authentication required" in response.json()["detail"]

    def test_api_engineers_requires_auth(self):
        """Engineer API endpoints should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/engineers")
        assert response.status_code == 401

    def test_api_accepts_bearer_token(self):
        """API should accept valid bearer token."""
        client = TestClient(app, raise_server_exceptions=False)

        with patch("app.api.get_settings") as mock_settings:
            from app.config import Settings
            mock_settings.return_value = Settings(api_token="test-token-12345")

            response = client.get(
                "/api/sites",
                headers={"Authorization": "Bearer test-token-12345"},
            )
            # Should not be 401 (auth should pass)
            # May be 500 due to database issues in test, but not 401
            assert response.status_code != 401

    def test_api_rejects_invalid_token(self):
        """API should reject invalid bearer token."""
        client = TestClient(app, raise_server_exceptions=False)

        with patch("app.api.get_settings") as mock_settings:
            from app.config import Settings
            mock_settings.return_value = Settings(api_token="correct-token")

            response = client.get(
                "/api/sites",
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert response.status_code == 401

    def test_api_rejects_empty_token_config(self):
        """API should reject token auth when API_TOKEN is not configured."""
        client = TestClient(app, raise_server_exceptions=False)

        with patch("app.api.get_settings") as mock_settings:
            from app.config import Settings
            mock_settings.return_value = Settings(api_token="")  # Empty token

            response = client.get(
                "/api/sites",
                headers={"Authorization": "Bearer any-token"},
            )
            assert response.status_code == 401

    def test_api_accepts_session_cookie(self):
        """API should accept valid session cookie."""
        client = TestClient(app, raise_server_exceptions=False)

        # Login first to get session cookie
        client.post("/login", data={"password": "parktech"})

        # Now try API with session
        response = client.get("/api/sites")
        # Should not be 401
        assert response.status_code != 401


class TestAPISites:
    """Test site API endpoints."""

    def test_create_site_validates_vpn_type(self):
        """Creating a site with invalid VPN type should fail."""
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login", data={"password": "parktech"})

        response = client.post(
            "/api/sites",
            json={
                "name": "Test Site",
                "vpn_type": "invalid",
                "local_subnet": "192.168.1.0/24",
            },
        )
        assert response.status_code == 400


class TestAPIEngineers:
    """Test engineer API endpoints."""

    def test_engineer_endpoints_exist(self):
        """Engineer API endpoints should be registered."""
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login", data={"password": "parktech"})

        # List endpoint should respond (may be empty list or error, but not 404)
        response = client.get("/api/engineers")
        assert response.status_code != 404


class TestVirtualIPPreview:
    """Test virtual IP preview endpoint."""

    def test_preview_virtual_ip_requires_auth(self):
        """Preview endpoint should require authentication."""
        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/preview-virtual-ip",
            json={
                "local_ip": "192.168.1.50",
                "local_subnet": "192.168.1.0/24",
                "virtual_subnet": "10.101.5.0/24",
            },
        )
        assert response.status_code == 401

    def test_preview_virtual_ip_calculates_correctly(self):
        """Preview should return correct virtual IP."""
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login", data={"password": "parktech"})

        response = client.post(
            "/api/preview-virtual-ip",
            json={
                "local_ip": "192.168.1.50",
                "local_subnet": "192.168.1.0/24",
                "virtual_subnet": "10.101.5.0/24",
            },
        )
        assert response.status_code == 200
        assert response.json()["virtual_ip"] == "10.101.5.50"

    def test_preview_handles_different_host_numbers(self):
        """Preview should handle various host numbers."""
        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login", data={"password": "parktech"})

        # Test .1 (router)
        response = client.post(
            "/api/preview-virtual-ip",
            json={
                "local_ip": "192.168.1.1",
                "local_subnet": "192.168.1.0/24",
                "virtual_subnet": "10.101.10.0/24",
            },
        )
        assert response.status_code == 200
        assert response.json()["virtual_ip"] == "10.101.10.1"

        # Test .254
        response = client.post(
            "/api/preview-virtual-ip",
            json={
                "local_ip": "192.168.1.254",
                "local_subnet": "192.168.1.0/24",
                "virtual_subnet": "10.101.10.0/24",
            },
        )
        assert response.status_code == 200
        assert response.json()["virtual_ip"] == "10.101.10.254"
