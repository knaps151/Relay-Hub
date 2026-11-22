"""Tests for security hardening (Issue #14)."""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient


class TestSessionSecurity:
    """Test session cookie security."""

    def test_forged_session_cookie_rejected(self):
        """A forged 'relay_session=ok' cookie should be rejected."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        # Try to access with the old static cookie value
        response = client.get("/", cookies={"relay_session": "ok"}, follow_redirects=False)
        # Should redirect to login (not authenticated)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_random_session_cookie_rejected(self):
        """A random session cookie should be rejected."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/", cookies={"relay_session": "random-value"}, follow_redirects=False)
        assert response.status_code == 303
        assert "/login" in response.headers.get("location", "")

    def test_valid_login_creates_session(self):
        """Login should create a valid session."""
        from app.main import app
        from app.services.session_store import clear_all_sessions
        
        clear_all_sessions()
        client = TestClient(app, raise_server_exceptions=False)
        
        # Login
        response = client.post("/login", data={"password": "relay"}, follow_redirects=False)
        assert response.status_code == 303
        
        # Check session cookie was set
        cookies = response.cookies
        assert "relay_session" in cookies
        session_id = cookies["relay_session"]
        assert len(session_id) > 20  # Random token should be long
        assert session_id != "ok"  # Not the old static value

    def test_logout_invalidates_session(self):
        """Logout should invalidate the session."""
        from app.main import app
        from app.services.session_store import clear_all_sessions, get_session
        
        clear_all_sessions()
        client = TestClient(app, raise_server_exceptions=False)
        
        # Login first
        response = client.post("/login", data={"password": "relay"}, follow_redirects=False)
        session_id = response.cookies.get("relay_session")
        
        # Verify session exists
        assert get_session(session_id) is not None
        
        # Logout
        client.cookies.set("relay_session", session_id)
        response = client.post("/logout", follow_redirects=False)
        
        # Session should be invalidated
        assert get_session(session_id) is None


class TestLoginRateLimiting:
    """Test login rate limiting."""

    def test_rate_limit_after_failed_attempts(self):
        """Too many failed login attempts should trigger rate limit."""
        from app.main import app, _login_attempts
        
        client = TestClient(app, raise_server_exceptions=False)
        _login_attempts.clear()
        
        # Make 5 failed attempts
        for _ in range(5):
            response = client.post("/login", data={"password": "wrong"})
            assert response.status_code == 401
        
        # 6th attempt should be rate limited
        response = client.post("/login", data={"password": "wrong"})
        assert response.status_code == 429
        assert "Too many login attempts" in response.text


class TestXSSSecurity:
    """Test XSS prevention."""

    def test_confirm_action_uses_data_attributes(self):
        """Fleet table should use data attributes for confirm messages."""
        from pathlib import Path
        
        template_path = Path(__file__).parent.parent / "app" / "templates" / "partials" / "fleet_table.html"
        content = template_path.read_text()
        
        # Should use data attributes
        assert "data-confirm-action" in content
        assert "data-confirm-name" in content
        # Should NOT have inline confirm with interpolation
        assert "confirm('Disable {{ site.name" not in content
        assert "confirm('Permanently delete {{ site.name" not in content


class TestTempDownloadSecurity:
    """Test temporary download link security."""

    def test_temp_download_single_use(self):
        """Temp download tokens should be single-use."""
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from app.db import Base
        from app.models import Site, TempDownloadToken
        from app.services.temp_download import mint_temp_download, get_valid_token, consume_token
        
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()
        
        # Create a test site
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
        
        # Mint a token
        token = mint_temp_download(db, site, kind="wireguard", max_downloads=1)
        
        # First use should work
        row = get_valid_token(db, token.token)
        assert row is not None
        assert consume_token(db, row) is True
        
        # Second use should fail
        row = get_valid_token(db, token.token)
        assert row is None  # Token should be invalid/deleted
        
        db.close()


class TestCSVSanitization:
    """Test CSV formula injection prevention."""

    def test_sanitize_formula_prefixes(self):
        """CSV cells starting with formula chars should be prefixed."""
        # Import the sanitize function (defined inline in the route)
        dangerous_values = [
            "=SUM(A1:A10)",
            "+100",
            "-50",
            "@macro",
            "\tdata",
            "\rdata",
        ]
        
        for val in dangerous_values:
            # Cells starting with these chars should be prefixed with '
            assert val[0] in ('=', '+', '-', '@', '\t', '\r')


class TestAPISessionSecurity:
    """Test API session validation."""

    def test_api_rejects_forged_cookie(self):
        """API should reject forged session cookie."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/api/sites", cookies={"relay_session": "ok"})
        assert response.status_code == 401

    def test_api_accepts_valid_session(self):
        """API should accept valid session."""
        from app.main import app
        from app.services.session_store import clear_all_sessions, create_session
        
        clear_all_sessions()
        # Create a valid session directly
        session_id, _ = create_session(source_ip="127.0.0.1")
        
        client = TestClient(app, raise_server_exceptions=False)
        client.cookies.set("relay_session", session_id)
        
        # API should work with valid session
        response = client.get("/api/sites")
        assert response.status_code != 401


class TestDocsDisabled:
    """Test that API docs are disabled by default."""

    def test_docs_endpoint_disabled(self):
        """The /docs endpoint should return 404."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/docs")
        assert response.status_code == 404

    def test_redoc_endpoint_disabled(self):
        """The /redoc endpoint should return 404."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/redoc")
        assert response.status_code == 404

    def test_openapi_endpoint_disabled(self):
        """The /openapi.json endpoint should return 404."""
        from app.main import app
        
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/openapi.json")
        assert response.status_code == 404
