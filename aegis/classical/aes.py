# aegis/classical/aes.py
# AES-256-GCM authenticated encryption with proper nonce handling.
# Never reuses nonces. Zeros key material after use via context manager.

from __future__ import annotations

import os
import ctypes
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32       # 256 bits
NONCE_SIZE = 12     # 96 bits — GCM standard
TAG_SIZE = 16       # 128-bit authentication tag


class AESError(Exception):
    pass

class KeySizeError(AESError):
    pass

class DecryptionError(AESError):
    pass


@dataclass(frozen=True)
class Ciphertext:
    nonce: bytes        # 12 bytes
    data: bytes         # ciphertext || tag (GCM bundles tag at end)
    aad: Optional[bytes] = None


def _zero(buf: bytearray) -> None:
    """Overwrite buffer contents with zeros."""
    ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class AESKey:
    """
    AES-256 key with explicit zeroing on close.

    Use as context manager:
        with AESKey.generate() as key:
            ct = key.encrypt(plaintext)
    """

    def __init__(self, raw: bytes) -> None:
        if len(raw) != KEY_SIZE:
            raise KeySizeError(f'AES key must be {KEY_SIZE} bytes, got {len(raw)}')
        self._key = bytearray(raw)
        self._closed = False

    @classmethod
    def generate(cls) -> 'AESKey':
        return cls(os.urandom(KEY_SIZE))

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'AESKey':
        return cls(raw)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> Ciphertext:
        """Fresh random nonce per call — never reuses."""
        if self._closed:
            raise AESError('Key has been zeroed and cannot be used')
        nonce = os.urandom(NONCE_SIZE)
        aesgcm = AESGCM(bytes(self._key))
        data = aesgcm.encrypt(nonce, plaintext, aad)
        return Ciphertext(nonce=nonce, data=data, aad=aad)

    def decrypt(self, ct: Ciphertext) -> bytes:
        """Raises DecryptionError on auth failure or zeroed key."""
        if self._closed:
            raise AESError('Key has been zeroed and cannot be used')
        aesgcm = AESGCM(bytes(self._key))
        try:
            return aesgcm.decrypt(ct.nonce, ct.data, ct.aad)
        except Exception as exc:
            raise DecryptionError('Decryption or authentication failed') from exc

    def zero(self) -> None:
        if not self._closed:
            _zero(self._key)
            self._closed = True

    def __enter__(self) -> 'AESKey':
        return self

    def __exit__(self, *_) -> None:
        self.zero()

    def __del__(self) -> None:
        if hasattr(self, '_closed'):
            self.zero()


def encrypt(key_bytes: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Ciphertext:
    """Stateless encrypt — zeros key internally."""
    with AESKey.from_bytes(key_bytes) as key:
        return key.encrypt(plaintext, aad)


def decrypt(key_bytes: bytes, ct: Ciphertext) -> bytes:
    """Stateless decrypt — zeros key internally."""
    with AESKey.from_bytes(key_bytes) as key:
        return key.decrypt(ct)


def serialize(ct: Ciphertext) -> bytes:
    """Wire format: nonce (12) || ciphertext||tag."""
    return ct.nonce + ct.data


def deserialize(raw: bytes, aad: Optional[bytes] = None) -> Ciphertext:
    if len(raw) < NONCE_SIZE + TAG_SIZE:
        raise AESError(f'Too short to be valid ciphertext: {len(raw)} bytes')
    return Ciphertext(nonce=raw[:NONCE_SIZE], data=raw[NONCE_SIZE:], aad=aad)
