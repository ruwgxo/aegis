# aegis/hybrid/session.py
# Hybrid session management with automatic 24h key rotation.

from __future__ import annotations

import os
import time
import uuid
from typing import Optional

from aegis.classical.ecdh import ECDHKeypair
from aegis.classical.ecdsa import ECDSAKeypair
from aegis.classical.aes import AESKey, serialize, deserialize
from aegis.pqc.kyber import KyberKeypair
from aegis.pqc.dilithium import DilithiumKeypair
from aegis.hybrid.kdf import derive

DEFAULT_TTL = 24 * 60 * 60


class SessionError(Exception):
    pass

class SessionExpiredError(SessionError):
    pass

class SessionNotReadyError(SessionError):
    pass


class SessionKeys:
    def __init__(self, aes_key: bytes, salt: bytes, ttl: float) -> None:
        self.aes_key = aes_key
        self.salt = salt
        self.created_at = time.time()
        self.ttl = ttl

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) >= self.ttl

    def seconds_remaining(self) -> float:
        return max(0.0, self.ttl - (time.time() - self.created_at))

    def zero(self) -> None:
        import ctypes
        buf = bytearray(self.aes_key)
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


class Session:
    """
    Hybrid quantum-safe session.

    Alice (initiator):
        session = Session.create()
        hs = session.initiate()            # send to Bob
        session.complete(bob_response)     # receive from Bob
        wire = session.encrypt(b'hello')

    Bob (responder):
        session = Session.create()
        response = session.respond(alice_hs)
        pt = session.decrypt(wire)
    """

    def __init__(self, ttl: float = DEFAULT_TTL) -> None:
        self.session_id = str(uuid.uuid4())
        self.ttl = ttl
        self._ready = False
        self._ecdh = ECDHKeypair.generate()
        self._kyber = KyberKeypair.generate()
        self._ecdsa = ECDSAKeypair.generate()
        self._dilithium = DilithiumKeypair.generate()
        self._keys: Optional[SessionKeys] = None
        self._rotation_count = 0

    @classmethod
    def create(cls, ttl: float = DEFAULT_TTL) -> 'Session':
        return cls(ttl=ttl)

    def initiate(self) -> dict:
        return {
            'session_id':    self.session_id,
            'ecdh_pub':      self._ecdh.public_key_bytes.hex(),
            'kyber_pub':     self._kyber.public_key_bytes.hex(),
            'ecdsa_pub':     self._ecdsa.public_key_bytes.hex(),
            'dilithium_pub': self._dilithium.public_key.hex(),
        }

    def respond(self, initiator_hs: dict) -> dict:
        ecdh_pub  = bytes.fromhex(initiator_hs['ecdh_pub'])
        kyber_pub = bytes.fromhex(initiator_hs['kyber_pub'])
        ecdh_ss   = self._ecdh.exchange(ecdh_pub)
        import oqs
        with oqs.KeyEncapsulation('ML-KEM-1024') as kem:
            kyber_ct, kyber_ss = kem.encap_secret(kyber_pub)
        salt    = os.urandom(32)
        aes_key = derive(ecdh_ss, kyber_ss, salt=salt)
        self._keys = SessionKeys(aes_key=aes_key, salt=salt, ttl=self.ttl)
        self._ready = True
        return {
            'session_id':    initiator_hs['session_id'],
            'ecdh_pub':      self._ecdh.public_key_bytes.hex(),
            'kyber_ct':      kyber_ct.hex(),
            'salt':          salt.hex(),
            'ecdsa_pub':     self._ecdsa.public_key_bytes.hex(),
            'dilithium_pub': self._dilithium.public_key.hex(),
        }

    def complete(self, responder_hs: dict) -> None:
        ecdh_pub = bytes.fromhex(responder_hs['ecdh_pub'])
        kyber_ct = bytes.fromhex(responder_hs['kyber_ct'])
        salt     = bytes.fromhex(responder_hs['salt'])
        ecdh_ss  = self._ecdh.exchange(ecdh_pub)
        kyber_ss = self._kyber.decapsulate(kyber_ct)
        aes_key  = derive(ecdh_ss, kyber_ss, salt=salt)
        self._keys = SessionKeys(aes_key=aes_key, salt=salt, ttl=self.ttl)
        self._ready = True

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        self._check_ready()
        if self._keys.is_expired():
            self._rotate()
        with AESKey.from_bytes(self._keys.aes_key) as k:
            return serialize(k.encrypt(plaintext, aad=aad))

    def decrypt(self, wire: bytes, aad: Optional[bytes] = None) -> bytes:
        self._check_ready()
        if self._keys.is_expired():
            raise SessionExpiredError('Session key expired — peer must rotate')
        with AESKey.from_bytes(self._keys.aes_key) as k:
            return k.decrypt(deserialize(wire, aad=aad))

    def sign(self, data: bytes) -> dict:
        return {
            'ecdsa':     self._ecdsa.sign(data).hex(),
            'dilithium': self._dilithium.sign(data).hex(),
        }

    def verify(self, data: bytes, signatures: dict) -> None:
        self._ecdsa.verify(data, bytes.fromhex(signatures['ecdsa']))
        self._dilithium.verify(data, bytes.fromhex(signatures['dilithium']))

    def rotate_now(self) -> None:
        self._rotate()

    def status(self) -> dict:
        return {
            'session_id':        self.session_id,
            'ready':             self._ready,
            'rotation_count':    self._rotation_count,
            'ttl_seconds':       self.ttl,
            'seconds_remaining': self._keys.seconds_remaining() if self._keys else None,
            'expired':           self._keys.is_expired() if self._keys else None,
        }

    def close(self) -> None:
        if self._keys:
            self._keys.zero()
        self._ecdh.zero()
        self._kyber.zero()
        self._ecdsa.zero()
        self._dilithium.zero()
        self._ready = False

    def __enter__(self) -> 'Session':
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def _check_ready(self) -> None:
        if not self._ready:
            raise SessionNotReadyError('Call complete() or respond() first')

    def _rotate(self) -> None:
        old_salt = self._keys.salt if self._keys else os.urandom(32)
        if self._keys:
            self._keys.zero()
        self._ecdh = ECDHKeypair.generate()
        self._kyber = KyberKeypair.generate()
        new_salt = os.urandom(32)
        aes_key = derive(old_salt, os.urandom(32), salt=new_salt, info=b'aegis-rotation-v1')
        self._keys = SessionKeys(aes_key=aes_key, salt=new_salt, ttl=self.ttl)
        self._rotation_count += 1
