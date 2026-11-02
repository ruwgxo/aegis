# aegis/hybrid/kdf.py
# HKDF combining ECDH and ML-KEM-1024 shared secrets into a single AES-256 key.
# Intended goal: the key stays secret if EITHER the classical OR the PQC exchange holds.
# See derive() for why this combiner does not yet meet that goal robustly.

from __future__ import annotations

import os

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# output key length: 32 bytes = AES-256
KEY_LEN = 32


class KDFError(Exception):
    pass


def derive(
    ecdh_shared_secret: bytes,
    kyber_shared_secret: bytes,
    salt: bytes | None = None,
    info: bytes = b'aegis-hybrid-v1',
) -> bytes:
    """
    Derive a 256-bit AES key from ECDH and ML-KEM-1024 shared secrets via HKDF-SHA256.

    Both secrets are XOR-combined before HKDF extraction. The intent is that the key
    stays secret unless BOTH ECDH P-256 AND ML-KEM-1024 are broken. This combiner does
    not bind the key to the KEM ciphertext or either party's public keys, which standard
    hybrid constructions (concatenating the secrets with that context, as in the IETF
    hybrid TLS design or X-Wing) do, so it should not be relied on as a robust combiner.

    Args:
        ecdh_shared_secret:   32-byte output of ECDH P-256 exchange
        kyber_shared_secret:  32-byte output of ML-KEM-1024 decapsulation
        salt:                 optional random salt (fresh per session recommended)
        info:                 context string binding key to protocol version

    Returns:
        32-byte AES-256 symmetric key
    """
    if len(ecdh_shared_secret) == 0 or len(kyber_shared_secret) == 0:
        raise KDFError('Shared secrets must not be empty')

    # XOR-combine: hides the key while the two secrets are independent, but nothing binds
    # them to the exchange that produced them (see the docstring).
    # Pad shorter secret with zeros to match lengths before XOR.
    l = max(len(ecdh_shared_secret), len(kyber_shared_secret))
    a = ecdh_shared_secret.ljust(l, b'\x00')
    b = kyber_shared_secret.ljust(l, b'\x00')
    combined = bytes(x ^ y for x, y in zip(a, b))

    if salt is None:
        salt = os.urandom(32)

    hkdf = HKDF(
        algorithm=SHA256(),
        length=KEY_LEN,
        salt=salt,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(combined)


def derive_with_salt(
    ecdh_shared_secret: bytes,
    kyber_shared_secret: bytes,
    info: bytes = b'aegis-hybrid-v1',
) -> tuple[bytes, bytes]:
    """
    Derive key and return (key, salt) so the salt can be transmitted to the peer.
    Peer calls derive() with the same salt to reproduce the same key.
    """
    salt = os.urandom(32)
    key = derive(ecdh_shared_secret, kyber_shared_secret, salt=salt, info=info)
    return key, salt
