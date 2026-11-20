"""Catalogues + engineer multi-device."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.services.catalogues import (
    list_equipment_types,
    list_regions,
    list_tech_device_types,
    seed_catalogues,
)
from app.services.engineers import (
    create_engineer,
    create_engineer_device,
    migrate_legacy_engineer_devices,
    next_engineer_ip,
    render_engineer_device_conf,
)
from app.models import Engineer


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
    seed_catalogues(session)
    yield session
    session.close()
    get_settings.cache_clear()


def test_seed_catalogues(db_session):
    assert any(r.slug == "london" for r in list_regions(db_session))
    assert any(t.slug == "phone" for t in list_tech_device_types(db_session))
    assert any(t.slug == "router" for t in list_equipment_types(db_session))


def test_engineer_multi_device_ips(db_session):
    eng = create_engineer(db_session, name="Alex")
    phone = next(t for t in list_tech_device_types(db_session) if t.slug == "phone")
    laptop = next(t for t in list_tech_device_types(db_session) if t.slug == "laptop")

    d1 = create_engineer_device(db_session, eng, label="iPhone", tech_device_type_id=phone.id)
    d2 = create_engineer_device(db_session, eng, label="MacBook", tech_device_type_id=laptop.id)

    assert d1.assigned_ip != d2.assigned_ip
    assert d1.wg_public_key != d2.wg_public_key
    conf = render_engineer_device_conf(db_session, d1)
    assert "Address =" in conf
    assert "DNS =" not in conf


def test_migrate_legacy_engineer(db_session):
    eng = Engineer(
        name="Legacy",
        wg_private_key="priv",
        wg_public_key="pub",
        assigned_ip="10.100.2.10/32",
        enabled=True,
    )
    db_session.add(eng)
    db_session.commit()
    migrate_legacy_engineer_devices(db_session)
    db_session.refresh(eng)
    assert len(eng.devices) == 1
    assert eng.devices[0].assigned_ip == "10.100.2.10/32"
    # idempotent
    migrate_legacy_engineer_devices(db_session)
    db_session.refresh(eng)
    assert len(eng.devices) == 1
