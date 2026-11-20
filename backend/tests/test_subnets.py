"""Tests for subnet allocation (Issue #1)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db import Base
from app.models import Site
from app.services.subnets import (
    MAX_SITE_INDEX,
    allocate_virtual_subnet,
    local_ip_for_virtual,
    next_site_index,
    parse_base_cidr,
    virtual_ip_for_local,
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


class TestNextSiteIndex:
    def test_first_index_is_zero(self, db_session):
        """First site should get index 0."""
        assert next_site_index(db_session) == 0

    def test_sequential_allocation(self, db_session):
        """Indices should be allocated sequentially when no gaps."""
        # Create sites with indices 0, 1, 2
        for i in range(3):
            site = Site(
                name=f"Site {i}",
                site_code=f"site-{i}",
                vpn_type="wireguard",
                site_index=i,
                virtual_subnet=f"10.101.{i}.0/24",
            )
            db_session.add(site)
        db_session.commit()

        assert next_site_index(db_session) == 3

    def test_reuses_deleted_index(self, db_session):
        """Deleting site 1 and creating a new site should reuse index 1."""
        # Create sites 0, 1, 2
        sites = []
        for i in range(3):
            site = Site(
                name=f"Site {i}",
                site_code=f"site-{i}",
                vpn_type="wireguard",
                site_index=i,
                virtual_subnet=f"10.101.{i}.0/24",
            )
            db_session.add(site)
            sites.append(site)
        db_session.commit()

        # Delete site 1
        db_session.delete(sites[1])
        db_session.commit()

        # Next index should be 1 (the gap)
        assert next_site_index(db_session) == 1

    def test_reuses_lowest_gap(self, db_session):
        """Should return the lowest unused index when there are multiple gaps."""
        # Create sites with indices 0, 2, 4 (gaps at 1, 3)
        for i in [0, 2, 4]:
            site = Site(
                name=f"Site {i}",
                site_code=f"site-{i}",
                vpn_type="wireguard",
                site_index=i,
                virtual_subnet=f"10.101.{i}.0/24",
            )
            db_session.add(site)
        db_session.commit()

        # Should return 1 (lowest gap)
        assert next_site_index(db_session) == 1

    def test_refuses_past_254(self, db_session):
        """Creating a 256th site (index 255) should raise a clear error."""
        # Create 255 sites (indices 0-254)
        for i in range(255):
            site = Site(
                name=f"Site {i}",
                site_code=f"site-{i}",
                vpn_type="wireguard",
                site_index=i,
                virtual_subnet=f"10.101.{i}.0/24",
            )
            db_session.add(site)
        db_session.commit()

        # Attempting to get next index should raise an error
        with pytest.raises(ValueError) as exc_info:
            next_site_index(db_session)

        assert "No free site indices available" in str(exc_info.value)
        assert "10.101.255.0/24 is reserved" in str(exc_info.value)

    def test_max_index_is_254(self):
        """MAX_SITE_INDEX should be 254 (255 is reserved)."""
        assert MAX_SITE_INDEX == 254


class TestAllocateVirtualSubnet:
    def test_allocates_correct_subnet(self, db_session):
        """Should allocate the correct /24 from the base CIDR."""
        site_index, subnet = allocate_virtual_subnet(db_session, "10.101.0.0/16")
        assert site_index == 0
        assert subnet == "10.101.0.0/24"

    def test_sequential_subnets(self, db_session):
        """Sequential allocations should get sequential subnets."""
        # Allocate first
        idx1, sub1 = allocate_virtual_subnet(db_session, "10.101.0.0/16")
        site = Site(
            name="Site 0",
            site_code="site-0",
            vpn_type="wireguard",
            site_index=idx1,
            virtual_subnet=sub1,
        )
        db_session.add(site)
        db_session.commit()

        # Allocate second
        idx2, sub2 = allocate_virtual_subnet(db_session, "10.101.0.0/16")
        assert idx2 == 1
        assert sub2 == "10.101.1.0/24"


class TestVirtualIpForLocal:
    def test_basic_mapping(self):
        """Basic 1:1 mapping should work."""
        result = virtual_ip_for_local(
            virtual_subnet="10.101.5.0/24",
            local_ip="192.168.1.100",
            local_subnet="192.168.1.0/24",
        )
        assert result == "10.101.5.100"

    def test_router_ip(self):
        """Router (.1) should map correctly."""
        result = virtual_ip_for_local(
            virtual_subnet="10.101.5.0/24",
            local_ip="192.168.1.1",
            local_subnet="192.168.1.0/24",
        )
        assert result == "10.101.5.1"

    def test_reverse_mapping(self):
        local = local_ip_for_virtual(
            virtual_subnet="10.101.5.0/24",
            virtual_ip="10.101.5.100",
            local_subnet="192.168.1.0/24",
        )
        assert local == "192.168.1.100"

    def test_round_trip(self):
        vip = virtual_ip_for_local("10.101.2.0/24", "10.0.0.50", "10.0.0.0/24")
        assert vip == "10.101.2.50"
        assert local_ip_for_virtual("10.101.2.0/24", vip, "10.0.0.0/24") == "10.0.0.50"
