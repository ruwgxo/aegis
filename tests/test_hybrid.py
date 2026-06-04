# tests/test_hybrid.py
# Integration tests: full hybrid encrypt/decrypt cycle.
# ECDH + ML-KEM-1024 → HKDF → AES-256-GCM

import pytest
from aegis.classical.ecdh import ECDHKeypair
from aegis.classical.ecdsa import ECDSAKeypair, VerificationError as ECDSAVerificationError
from aegis.classical.aes import AESKey, DecryptionError
from aegis.pqc.kyber import KyberKeypair
from aegis.pqc.dilithium import DilithiumKeypair, VerificationError as DilithiumVerificationError
from aegis.hybrid.kdf import derive, derive_with_salt


class TestHybridKDF:

    def test_derive_deterministic_with_same_salt(self):
        ecdh_ss = b'\xaa' * 32
        kyber_ss = b'\xbb' * 32
        salt = b'\xcc' * 32
        k1 = derive(ecdh_ss, kyber_ss, salt=salt)
        k2 = derive(ecdh_ss, kyber_ss, salt=salt)
        assert k1 == k2

    def test_derive_output_length(self):
        key = derive(b'\xaa' * 32, b'\xbb' * 32, salt=b'\xcc' * 32)
        assert len(key) == 32

    def test_different_ecdh_secret_different_key(self):
        salt = b'\xcc' * 32
        k1 = derive(b'\xaa' * 32, b'\xbb' * 32, salt=salt)
        k2 = derive(b'\x11' * 32, b'\xbb' * 32, salt=salt)
        assert k1 != k2

    def test_different_kyber_secret_different_key(self):
        salt = b'\xcc' * 32
        k1 = derive(b'\xaa' * 32, b'\xbb' * 32, salt=salt)
        k2 = derive(b'\xaa' * 32, b'\x22' * 32, salt=salt)
        assert k1 != k2

    def test_derive_with_salt_returns_key_and_salt(self):
        key, salt = derive_with_salt(b'\xaa' * 32, b'\xbb' * 32)
        assert len(key) == 32
        assert len(salt) == 32

    def test_derive_with_salt_reproducible(self):
        ecdh_ss = b'\xaa' * 32
        kyber_ss = b'\xbb' * 32
        key, salt = derive_with_salt(ecdh_ss, kyber_ss)
        key2 = derive(ecdh_ss, kyber_ss, salt=salt)
        assert key == key2


class TestFullHybridCycle:
    """
    Full encrypt/decrypt using real ECDH + ML-KEM-1024 + HKDF + AES-256-GCM.
    Simulates Alice (sender) and Bob (receiver).
    """

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b'hybrid quantum-safe message'

        # Bob generates long-term keypairs
        bob_ecdh = ECDHKeypair.generate()
        bob_kyber = KyberKeypair.generate()

        # Alice: ephemeral ECDH + encapsulate Kyber
        alice_ecdh = ECDHKeypair.generate()
        ecdh_ss = alice_ecdh.exchange(bob_ecdh.public_key_bytes)
        kyber_ct, kyber_ss = bob_kyber.encapsulate()

        # Alice derives session key
        session_key, salt = derive_with_salt(ecdh_ss, kyber_ss)

        # Alice encrypts
        with AESKey.from_bytes(session_key) as aes:
            ct = aes.encrypt(plaintext)

        # Bob: ECDH exchange from his side
        bob_ecdh_ss = bob_ecdh.exchange(alice_ecdh.public_key_bytes)
        bob_kyber_ss = bob_kyber.decapsulate(kyber_ct)

        # Bob derives same session key
        bob_session_key = derive(bob_ecdh_ss, bob_kyber_ss, salt=salt)

        assert bob_session_key == session_key  # keys must match

        # Bob decrypts
        with AESKey.from_bytes(bob_session_key) as aes:
            recovered = aes.decrypt(ct)

        assert recovered == plaintext

    def test_tampered_kyber_ciphertext_breaks_key(self):
        bob_ecdh = ECDHKeypair.generate()
        bob_kyber = KyberKeypair.generate()
        alice_ecdh = ECDHKeypair.generate()

        ecdh_ss = alice_ecdh.exchange(bob_ecdh.public_key_bytes)
        kyber_ct, kyber_ss = bob_kyber.encapsulate()
        session_key, salt = derive_with_salt(ecdh_ss, kyber_ss)

        with AESKey.from_bytes(session_key) as aes:
            ct = aes.encrypt(b'secret')

        # tamper Kyber ciphertext
        bad_kyber_ct = bytes([kyber_ct[0] ^ 0xFF]) + kyber_ct[1:]
        bob_ecdh_ss = bob_ecdh.exchange(alice_ecdh.public_key_bytes)
        bob_kyber_ss = bob_kyber.decapsulate(bad_kyber_ct)  # ML-KEM returns garbage, not raises
        bad_key = derive(bob_ecdh_ss, bob_kyber_ss, salt=salt)

        assert bad_key != session_key
        with AESKey.from_bytes(bad_key) as aes:
            with pytest.raises(DecryptionError):
                aes.decrypt(ct)

    def test_dual_signature_roundtrip(self):
        message = b'signed hybrid message'

        with ECDSAKeypair.generate() as ecdsa_kp:
            with DilithiumKeypair.generate() as dsa_kp:
                ecdsa_sig = ecdsa_kp.sign(message)
                dsa_sig = dsa_kp.sign(message)

                # both verify
                ecdsa_kp.verify(message, ecdsa_sig)
                dsa_kp.verify(message, dsa_sig)

    def test_dual_signature_tamper_classical(self):
        message = b'signed message'
        with ECDSAKeypair.generate() as kp:
            sig = kp.sign(message)
            bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            with pytest.raises(ECDSAVerificationError):
                kp.verify(message, bad_sig)

    def test_dual_signature_tamper_pqc(self):
        message = b'signed message'
        with DilithiumKeypair.generate() as kp:
            sig = kp.sign(message)
            bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
            with pytest.raises(DilithiumVerificationError):
                kp.verify(message, bad_sig)
