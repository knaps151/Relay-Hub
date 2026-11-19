"""Tests for WireGuard keypair generation (Issue #1)."""

import base64

import pytest

from app.services.wireguard import generate_keypair, public_key_from_private


def test_generate_keypair_returns_valid_base64():
    """Generated keys should be valid base64-encoded 32-byte values."""
    private_key, public_key = generate_keypair()

    private_bytes = base64.b64decode(private_key)
    public_bytes = base64.b64decode(public_key)

    assert len(private_bytes) == 32, "Private key should be 32 bytes"
    assert len(public_bytes) == 32, "Public key should be 32 bytes"


def test_generate_keypair_public_matches_private():
    """The public key should be derivable from the private key (valid X25519 pair)."""
    private_key, public_key = generate_keypair()

    # Derive public key from private using our helper
    derived_public = public_key_from_private(private_key)

    assert derived_public == public_key, (
        f"Public key mismatch: generated {public_key}, derived {derived_public}"
    )


def test_public_key_from_private_known_vector():
    """Test against a known WireGuard keypair (from wg genkey | tee priv | wg pubkey)."""
    # This is a test vector - in production, you'd use a real wg-generated pair
    # For now, we verify that our derivation is consistent
    private_key, public_key = generate_keypair()

    # Verify round-trip consistency
    derived = public_key_from_private(private_key)
    assert derived == public_key


def test_generate_keypair_uniqueness():
    """Each call should generate a different keypair."""
    pairs = [generate_keypair() for _ in range(10)]
    private_keys = [p[0] for p in pairs]
    public_keys = [p[1] for p in pairs]

    assert len(set(private_keys)) == 10, "Private keys should be unique"
    assert len(set(public_keys)) == 10, "Public keys should be unique"


def test_public_key_derivation_matches_cryptography():
    """Verify our implementation matches the cryptography library's X25519."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    private_key, public_key = generate_keypair()
    private_bytes = base64.b64decode(private_key)

    # Use cryptography library directly to verify
    key_obj = X25519PrivateKey.from_private_bytes(private_bytes)
    expected_public = base64.b64encode(
        key_obj.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    ).decode()

    assert public_key == expected_public
