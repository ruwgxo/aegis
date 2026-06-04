# aegis/pqc/dilithium.py
# ML-DSA-87 (FIPS 204 — formerly Dilithium-5) digital signatures.
# Wraps liboqs-python. Zeros secret key material on close.

from __future__ import annotations

import ctypes
import oqs


ALG = 'ML-DSA-87'


class DilithiumError(Exception):
    pass


class VerificationError(DilithiumError):
    pass


def _zero(buf: bytearray) -> None:
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class DilithiumKeypair:
    """
    ML-DSA-87 keypair with explicit zeroing of secret key.

    Use as context manager:
        with DilithiumKeypair.generate() as kp:
            sig = kp.sign(message)
            kp.verify(message, sig)
    """

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self.public_key: bytes = public_key
        self._secret_key = bytearray(secret_key)
        self._closed = False

    @classmethod
    def generate(cls) -> 'DilithiumKeypair':
        with oqs.Signature(ALG) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
        return cls(pk, sk)

    @classmethod
    def from_secret_key(cls, public_key: bytes, secret_key: bytes) -> 'DilithiumKeypair':
        return cls(public_key, secret_key)

    def sign(self, message: bytes) -> bytes:
        """Sign message. Returns signature bytes."""
        if self._closed:
            raise DilithiumError('Keypair has been zeroed')
        with oqs.Signature(ALG, bytes(self._secret_key)) as sig:
            return sig.sign(message)

    def verify(self, message: bytes, signature: bytes) -> None:
        """
        Verify signature against own public key.
        Raises VerificationError on failure.
        """
        verify_with_public_key(self.public_key, message, signature)

    def zero(self) -> None:
        if not self._closed:
            _zero(self._secret_key)
            self._closed = True

    def __enter__(self) -> 'DilithiumKeypair':
        return self

    def __exit__(self, *_) -> None:
        self.zero()

    def __del__(self) -> None:
        if hasattr(self, '_closed'):
            self.zero()


def verify_with_public_key(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Stateless verify. Raises VerificationError on failure."""
    with oqs.Signature(ALG) as sig:
        valid = sig.verify(message, signature, public_key)
    if not valid:
        raise VerificationError('ML-DSA-87 signature verification failed')
