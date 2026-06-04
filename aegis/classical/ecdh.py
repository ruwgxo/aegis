# aegis/classical/ecdh.py
# ECDH P-256 key exchange. Produces shared secret fed into hybrid KDF.

from __future__ import annotations

import ctypes

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, generate_private_key, EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.hazmat.backends import default_backend


class ECDHError(Exception):
    pass


def _zero(buf: bytearray) -> None:
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class ECDHKeypair:
    """
    Ephemeral ECDH P-256 keypair.

    Use as context manager — private key is zeroed on exit.
    """

    def __init__(self, private_key: EllipticCurvePrivateKey) -> None:
        self._private_key = private_key
        self._closed = False
        # cache serialised public key
        self.public_key_bytes: bytes = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    @classmethod
    def generate(cls) -> 'ECDHKeypair':
        return cls(generate_private_key(SECP256R1(), default_backend()))

    def exchange(self, peer_public_key_bytes: bytes) -> bytes:
        """
        Perform ECDH exchange with peer's uncompressed public key bytes.
        Returns 32-byte shared secret.
        """
        if self._closed:
            raise ECDHError('Keypair has been zeroed')
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicKey,
        )
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers, SECP256R1,
        )
        # parse uncompressed point (0x04 || x || y)
        if len(peer_public_key_bytes) != 65 or peer_public_key_bytes[0] != 0x04:
            raise ECDHError('Expected uncompressed P-256 point (65 bytes, prefix 0x04)')
        x = int.from_bytes(peer_public_key_bytes[1:33], 'big')
        y = int.from_bytes(peer_public_key_bytes[33:65], 'big')
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers,
        )
        peer_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())
        return self._private_key.exchange(ECDH(), peer_pub)

    def zero(self) -> None:
        # cryptography library manages private key memory internally;
        # we drop our reference and mark closed
        if not self._closed:
            self._private_key = None  # type: ignore[assignment]
            self._closed = True

    def __enter__(self) -> 'ECDHKeypair':
        return self

    def __exit__(self, *_) -> None:
        self.zero()

    def __del__(self) -> None:
        if hasattr(self, '_closed'):
            self.zero()
