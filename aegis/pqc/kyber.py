# aegis/pqc/kyber.py
# ML-KEM-1024 (FIPS 203 — formerly Kyber-1024) key encapsulation mechanism.
# Wraps liboqs-python. Zeros all key material on close.

from __future__ import annotations

import ctypes
import oqs


ALG = 'ML-KEM-1024'


class KyberError(Exception):
    pass


def _zero(buf: bytearray) -> None:
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class KyberKeypair:
    """
    ML-KEM-1024 keypair with explicit zeroing.

    Use as context manager:
        with KyberKeypair.generate() as kp:
            ct, ss = kp.encapsulate()
    """

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self.public_key_bytes: bytes = public_key
        self._secret_key = bytearray(secret_key)
        self._closed = False

    @classmethod
    def generate(cls) -> 'KyberKeypair':
        with oqs.KeyEncapsulation(ALG) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
        return cls(pk, sk)

    @classmethod
    def from_secret_key(cls, public_key: bytes, secret_key: bytes) -> 'KyberKeypair':
        return cls(public_key, secret_key)

    def encapsulate(self) -> tuple[bytes, bytes]:
        """
        Encapsulate using own public key.
        Returns (ciphertext, shared_secret). shared_secret is 32 bytes.
        """
        if self._closed:
            raise KyberError('Keypair has been zeroed')
        with oqs.KeyEncapsulation(ALG) as kem:
            ct, ss = kem.encap_secret(self.public_key_bytes)
        return ct, ss

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate ciphertext using secret key.
        Returns shared_secret (32 bytes).
        """
        if self._closed:
            raise KyberError('Keypair has been zeroed')
        with oqs.KeyEncapsulation(ALG, bytes(self._secret_key)) as kem:
            ss = kem.decap_secret(ciphertext)
        return ss

    def zero(self) -> None:
        if not self._closed:
            _zero(self._secret_key)
            self._closed = True

    def __enter__(self) -> 'KyberKeypair':
        return self

    def __exit__(self, *_) -> None:
        self.zero()

    def __del__(self) -> None:
        if hasattr(self, '_closed'):
            self.zero()


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Stateless encapsulate. Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(ALG) as kem:
        ct, ss = kem.encap_secret(public_key)
    return ct, ss


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Stateless decapsulate. Returns shared_secret."""
    with oqs.KeyEncapsulation(ALG, secret_key) as kem:
        ss = kem.decap_secret(ciphertext)
    return ss
