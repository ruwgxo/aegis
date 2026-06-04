# tests/test_session.py

import os
import time
import pytest
from aegis.hybrid.session import Session, SessionExpiredError, SessionNotReadyError


def _pair(ttl=3600):
    alice = Session.create(ttl=ttl)
    bob   = Session.create(ttl=ttl)
    alice.complete(bob.respond(alice.initiate()))
    return alice, bob


class TestHandshake:
    def test_both_ready(self):
        alice, bob = _pair()
        assert alice._ready and bob._ready

    def test_same_key(self):
        alice, bob = _pair()
        assert alice._keys.aes_key == bob._keys.aes_key

    def test_encrypt_before_handshake_raises(self):
        with pytest.raises(SessionNotReadyError):
            Session.create().encrypt(b'x')


class TestEncryptDecrypt:
    def test_roundtrip(self):
        alice, bob = _pair()
        assert bob.decrypt(alice.encrypt(b'hello')) == b'hello'

    def test_both_directions(self):
        alice, bob = _pair()
        assert bob.decrypt(alice.encrypt(b'a->b')) == b'a->b'
        assert alice.decrypt(bob.encrypt(b'b->a')) == b'b->a'

    def test_multiple_messages(self):
        alice, bob = _pair()
        for i in range(20):
            msg = f'msg {i}'.encode()
            assert bob.decrypt(alice.encrypt(msg)) == msg

    def test_empty(self):
        alice, bob = _pair()
        assert bob.decrypt(alice.encrypt(b'')) == b''

    def test_large(self):
        alice, bob = _pair()
        data = os.urandom(1024 * 1024)
        assert bob.decrypt(alice.encrypt(data)) == data

    def test_tampered_fails(self):
        from aegis.classical.aes import DecryptionError
        alice, bob = _pair()
        wire = alice.encrypt(b'secret')
        with pytest.raises(DecryptionError):
            bob.decrypt(bytes([wire[0] ^ 0xFF]) + wire[1:])

    def test_wrong_session_fails(self):
        from aegis.classical.aes import DecryptionError
        alice, bob = _pair()
        carol, dave = _pair()
        with pytest.raises(DecryptionError):
            carol.decrypt(alice.encrypt(b'not for you'))


class TestRotation:
    def test_manual_rotate_changes_key(self):
        alice, bob = _pair()
        before = alice._keys.aes_key
        alice.rotate_now()
        assert alice._keys.aes_key != before
        assert alice._rotation_count == 1

    def test_expired_decrypt_raises(self):
        alice = Session.create(ttl=0.01)
        bob   = Session.create(ttl=0.01)
        alice.complete(bob.respond(alice.initiate()))
        wire = alice.encrypt(b'msg')
        time.sleep(0.02)
        with pytest.raises(SessionExpiredError):
            bob.decrypt(wire)


class TestSigning:
    def test_sign_verify(self):
        s = Session.create()
        sigs = s.sign(b'payload')
        s.verify(b'payload', sigs)

    def test_wrong_data_fails(self):
        from aegis.classical.ecdsa import VerificationError
        s = Session.create()
        sigs = s.sign(b'correct')
        with pytest.raises(VerificationError):
            s.verify(b'wrong', sigs)


class TestStatus:
    def test_before_handshake(self):
        s = Session.create()
        assert s.status()['ready'] is False

    def test_after_handshake(self):
        alice, bob = _pair()
        st = alice.status()
        assert st['ready'] is True
        assert st['seconds_remaining'] > 0


class TestContextManager:
    def test_close_on_exit(self):
        alice, bob = _pair()
        with alice:
            pass
        assert alice._ready is False
