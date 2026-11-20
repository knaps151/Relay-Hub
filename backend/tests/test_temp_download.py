"""Short-lived public download links."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.services.provision import create_site
from app.services.temp_download import get_valid_token, mint_temp_download, render_wireguard_install_script


@pytest.fixture
def db_session(monkeypatch):
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
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


def test_mint_and_expire(db_session):
    site = create_site(
        db_session,
        name="Cloud Box",
        vpn_type="wireguard",
        access_mode="direct",
    )
    row = mint_temp_download(db_session, site, kind="wireguard", ttl_seconds=180)
    assert get_valid_token(db_session, row.token) is not None
    row.expires_at = datetime.utcnow() - timedelta(seconds=1)
    db_session.commit()
    assert get_valid_token(db_session, row.token) is None


def test_install_script_contains_conf():
    script = render_wireguard_install_script(
        "[Interface]\nPrivateKey = abc\nAddress = 10.101.0.1/32\n"
    )
    assert "wg-quick@" in script
    assert "PrivateKey = abc" in script
    assert script.startswith("#!/bin/bash")


def test_invalid_token_returns_none(db_session):
    assert get_valid_token(db_session, "nope") is None
