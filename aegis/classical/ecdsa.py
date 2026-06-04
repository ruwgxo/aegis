# aegis/classical/ecdsa.py
# ECDSA P-256 sign/verify. Dual-signed with ML-DSA-87 in hybrid mode.

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, SECP256R1, generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class ECDSAError(Exception):
    pass


class VerificationError(ECDSAError):
    pass


class ECDSAKeypair:
    """ECDSA P-256 keypair for signing."""

    def __init__(self) -> None:
        self._private_key = generate_private_key(SECP256R1(), default_backend())
        self._closed = False
        self.public_key_bytes: bytes = self._private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    @classmethod
    def generate(cls) -> 'ECDSAKeypair':
        return cls()

    def sign(self, message: bytes) -> bytes:
        """Sign message. Returns DER-encoded signature."""
        if self._closed:
            raise ECDSAError('Keypair has been zeroed')
        return self._private_key.sign(message, ECDSA(SHA256()))

    def verify(self, message: bytes, signature: bytes) -> None:
        """Verify against own public key. Raises VerificationError on failure."""
        verify_with_public_key(self.public_key_bytes, message, signature)

    def zero(self) -> None:
        if not self._closed:
            self._private_key = None  # type: ignore[assignment]
            self._closed = True

    def __enter__(self) -> 'ECDSAKeypair':
        return self

    def __exit__(self, *_) -> None:
        self.zero()

    def __del__(self) -> None:
        if hasattr(self, '_closed'):
            self.zero()


def verify_with_public_key(public_key_bytes: bytes, message: bytes, signature: bytes) -> None:
    """
    Stateless verify given raw uncompressed public key bytes.
    Raises VerificationError on failure.
    """
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers, SECP256R1,
    )
    if len(public_key_bytes) != 65 or public_key_bytes[0] != 0x04:
        raise ECDSAError('Expected uncompressed P-256 point (65 bytes)')
    x = int.from_bytes(public_key_bytes[1:33], 'big')
    y = int.from_bytes(public_key_bytes[33:65], 'big')
    pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(default_backend())
    try:
        pub.verify(signature, message, ECDSA(SHA256()))
    except InvalidSignature as exc:
        raise VerificationError('ECDSA P-256 signature verification failed') from exc
