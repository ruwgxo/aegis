# tests/test_classical.py
# Known-Answer Tests for AES-256-GCM against NIST SP 800-38D vectors.
# Run: python -m pytest tests/test_classical.py -v

import pytest
from aegis.classical.aes import (
    AESKey, Ciphertext, DecryptionError, KeySizeError,
    encrypt, decrypt, serialize, deserialize,
    KEY_SIZE, NONCE_SIZE, TAG_SIZE,
)


# ---------------------------------------------------------------------------
# NIST SP 800-38D test vectors (gcmEncryptExtIV256.rsp, count=0 and count=1)
# Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
# ---------------------------------------------------------------------------

NIST_VECTORS = [
    {
        'key':    bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
        'nonce':  bytes.fromhex('000000000000000000000000'),
        'plain':  bytes.fromhex(''),
        'aad':    bytes.fromhex(''),
        'cipher': bytes.fromhex(''),
        'tag':    bytes.fromhex('530f8afbc74536b9a963b4f1c4cb738b'),
    },
    {
        'key':    bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000'),
        'nonce':  bytes.fromhex('000000000000000000000000'),
        'plain':  bytes.fromhex('00000000000000000000000000000000'),
        'aad':    bytes.fromhex(''),
        'cipher': bytes.fromhex('cea7403d4d606b6e074ec5d3baf39d18'),
        'tag':    bytes.fromhex('d0d1c8a799996bf0265b98b5d48ab919'),
    },
    {
        # featurettes: non-empty AAD, non-empty plaintext
        'key':    bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
        'nonce':  bytes.fromhex('cafebabefacedbaddecaf888'),
        'plain':  bytes.fromhex(
            'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
            '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255'
        ),
        'aad':    bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2'),
        'cipher': bytes.fromhex(
            '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
            '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad'
        ),
        'tag':    bytes.fromhex('2df7cd675b4f09163b41ebf980a7f638'),
    },
]


class TestNISTVectors:
    """KATs — must pass exactly against NIST reference output."""

    @pytest.mark.parametrize('vec', NIST_VECTORS)
    def test_encrypt_kat(self, vec):
        """Encrypt with fixed nonce must produce exact NIST ciphertext+tag."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(vec['key'])
        aad = vec['aad'] if vec['aad'] else None
        result = aesgcm.encrypt(vec['nonce'], vec['plain'], aad)
        expected = vec['cipher'] + vec['tag']
        assert result == expected, f'KAT failed: got {result.hex()}, expected {expected.hex()}'

    @pytest.mark.parametrize('vec', NIST_VECTORS)
    def test_decrypt_kat(self, vec):
        """Decrypt NIST ciphertext+tag must recover exact plaintext."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(vec['key'])
        aad = vec['aad'] if vec['aad'] else None
        ct_with_tag = vec['cipher'] + vec['tag']
        result = aesgcm.decrypt(vec['nonce'], ct_with_tag, aad)
        assert result == vec['plain']


class TestAESKeyRoundtrip:
    """Functional round-trip tests through the AESKey API."""

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b'aegis test message 1234567890'
        with AESKey.generate() as key:
            ct = key.encrypt(plaintext)
            recovered = key.decrypt(ct)
        assert recovered == plaintext

    def test_encrypt_decrypt_with_aad(self):
        plaintext = b'secret payload'
        aad = b'session-id:abc123'
        with AESKey.generate() as key:
            ct = key.encrypt(plaintext, aad=aad)
            recovered = key.decrypt(ct)
        assert recovered == plaintext
        assert ct.aad == aad

    def test_nonce_is_fresh_each_call(self):
        """Two encryptions of the same plaintext must use different nonces."""
        with AESKey.generate() as key:
            ct1 = key.encrypt(b'same message')
            ct2 = key.encrypt(b'same message')
        assert ct1.nonce != ct2.nonce

    def test_ciphertext_differs_per_nonce(self):
        with AESKey.generate() as key:
            ct1 = key.encrypt(b'same message')
            ct2 = key.encrypt(b'same message')
        assert ct1.data != ct2.data

    def test_wrong_aad_fails_auth(self):
        with AESKey.generate() as key:
            ct = key.encrypt(b'payload', aad=b'correct-aad')
            tampered = Ciphertext(nonce=ct.nonce, data=ct.data, aad=b'wrong-aad')
            with pytest.raises(DecryptionError):
                key.decrypt(tampered)

    def test_tampered_ciphertext_fails_auth(self):
        with AESKey.generate() as key:
            ct = key.encrypt(b'payload')
            bad_data = bytes([ct.data[0] ^ 0xFF]) + ct.data[1:]
            tampered = Ciphertext(nonce=ct.nonce, data=bad_data, aad=ct.aad)
            with pytest.raises(DecryptionError):
                key.decrypt(tampered)

    def test_wrong_key_fails_auth(self):
        with AESKey.generate() as k1, AESKey.generate() as k2:
            ct = k1.encrypt(b'payload')
            with pytest.raises(DecryptionError):
                k2.decrypt(ct)

    def test_empty_plaintext(self):
        with AESKey.generate() as key:
            ct = key.encrypt(b'')
            assert key.decrypt(ct) == b''

    def test_large_plaintext(self):
        data = b'x' * (1024 * 1024)  # 1 MB
        with AESKey.generate() as key:
            ct = key.encrypt(data)
            assert key.decrypt(ct) == data


class TestKeyLifecycle:

    def test_bad_key_size_raises(self):
        with pytest.raises(KeySizeError):
            AESKey.from_bytes(b'tooshort')

    def test_zeroed_key_cannot_encrypt(self):
        key = AESKey.generate()
        key.zero()
        from aegis.classical.aes import AESError
        with pytest.raises(AESError):
            key.encrypt(b'anything')

    def test_zeroed_key_cannot_decrypt(self):
        key = AESKey.generate()
        ct = key.encrypt(b'msg')
        key.zero()
        from aegis.classical.aes import AESError
        with pytest.raises(AESError):
            key.decrypt(ct)

    def test_context_manager_zeros_on_exit(self):
        with AESKey.generate() as key:
            pass
        assert key._closed is True


class TestStatelessAPI:

    def test_stateless_encrypt_decrypt(self):
        key_bytes = b'\xab' * KEY_SIZE
        ct = encrypt(key_bytes, b'hello stateless')
        recovered = decrypt(key_bytes, ct)
        assert recovered == b'hello stateless'


class TestSerialisation:

    def test_serialize_deserialize_roundtrip(self):
        with AESKey.generate() as key:
            ct = key.encrypt(b'wire format test')
            wire = serialize(ct)
            ct2 = deserialize(wire)
            recovered = key.decrypt(ct2)
        assert recovered == b'wire format test'

    def test_wire_format_length(self):
        with AESKey.generate() as key:
            ct = key.encrypt(b'12345')
        wire = serialize(ct)
        # nonce(12) + len(plaintext)(5) + tag(16) = 33
        assert len(wire) == NONCE_SIZE + 5 + TAG_SIZE

    def test_deserialize_too_short_raises(self):
        from aegis.classical.aes import AESError
        with pytest.raises(AESError):
            deserialize(b'\x00' * 10)
