# tests/test_pqc.py
# Tests for ML-KEM-1024 and ML-DSA-87 wrappers.

import pytest
from aegis.pqc.kyber import KyberKeypair, encapsulate, decapsulate, KyberError
from aegis.pqc.dilithium import DilithiumKeypair, verify_with_public_key, VerificationError


class TestKyberKEM:

    def test_encap_decap_roundtrip(self):
        with KyberKeypair.generate() as kp:
            ct, ss_enc = kp.encapsulate()
            ss_dec = kp.decapsulate(ct)
        assert ss_enc == ss_dec

    def test_shared_secret_length(self):
        with KyberKeypair.generate() as kp:
            ct, ss = kp.encapsulate()
        assert len(ss) == 32

    def test_two_encaps_different_ciphertext(self):
        with KyberKeypair.generate() as kp:
            ct1, ss1 = kp.encapsulate()
            ct2, ss2 = kp.encapsulate()
        assert ct1 != ct2
        assert ss1 != ss2

    def test_wrong_key_decap_gives_different_secret(self):
        with KyberKeypair.generate() as kp1, KyberKeypair.generate() as kp2:
            ct, ss_correct = kp1.encapsulate()
            ss_wrong = kp2.decapsulate(ct)
        # ML-KEM is designed to return a random-looking value on failure, not raise
        assert ss_correct != ss_wrong

    def test_stateless_encap_decap(self):
        with KyberKeypair.generate() as kp:
            pk = kp.public_key_bytes
            sk = bytes(kp._secret_key)
        ct, ss_enc = encapsulate(pk)
        ss_dec = decapsulate(sk, ct)
        assert ss_enc == ss_dec

    def test_zeroed_keypair_raises(self):
        kp = KyberKeypair.generate()
        kp.zero()
        with pytest.raises(KyberError):
            kp.encapsulate()
        with pytest.raises(KyberError):
            kp.decapsulate(b'\x00' * 32)

    def test_context_manager_zeros_on_exit(self):
        with KyberKeypair.generate() as kp:
            pass
        assert kp._closed is True


class TestDilithiumSignatures:

    def test_sign_verify_roundtrip(self):
        msg = b'aegis test message'
        with DilithiumKeypair.generate() as kp:
            sig = kp.sign(msg)
            kp.verify(msg, sig)  # must not raise

    def test_wrong_message_fails(self):
        with DilithiumKeypair.generate() as kp:
            sig = kp.sign(b'correct message')
            with pytest.raises(VerificationError):
                kp.verify(b'wrong message', sig)

    def test_tampered_signature_fails(self):
        with DilithiumKeypair.generate() as kp:
            sig = kp.sign(b'message')
            bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            with pytest.raises(VerificationError):
                kp.verify(b'message', bad_sig)

    def test_wrong_public_key_fails(self):
        with DilithiumKeypair.generate() as kp1, DilithiumKeypair.generate() as kp2:
            sig = kp1.sign(b'message')
            with pytest.raises(VerificationError):
                verify_with_public_key(kp2.public_key, b'message', sig)

    def test_zeroed_keypair_cannot_sign(self):
        from aegis.pqc.dilithium import DilithiumError
        kp = DilithiumKeypair.generate()
        kp.zero()
        with pytest.raises(DilithiumError):
            kp.sign(b'anything')

    def test_context_manager_zeros_on_exit(self):
        with DilithiumKeypair.generate() as kp:
            pass
        assert kp._closed is True
