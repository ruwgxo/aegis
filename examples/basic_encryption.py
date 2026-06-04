# examples/basic_encryption.py
# End-to-end hybrid quantum-safe encryption using Aegis.
# Shows the full flow: keygen → encap → KDF → AES encrypt → decrypt.

from aegis.classical.ecdh import ECDHKeypair
from aegis.classical.ecdsa import ECDSAKeypair
from aegis.classical.aes import AESKey, serialize, deserialize
from aegis.pqc.kyber import KyberKeypair
from aegis.pqc.dilithium import DilithiumKeypair
from aegis.hybrid.kdf import derive_with_salt, derive


def run():
    print('Aegis — Hybrid Quantum-Safe Encryption Demo\n')

    plaintext = b'This message is safe against both classical and quantum adversaries.'
    print(f'Plaintext : {plaintext.decode()}\n')

    # --- Bob's long-term keypairs (receiver) ---
    print('Generating Bob keypairs...')
    bob_ecdh    = ECDHKeypair.generate()
    bob_kyber   = KyberKeypair.generate()
    bob_ecdsa   = ECDSAKeypair.generate()
    bob_dsa     = DilithiumKeypair.generate()
    print('  ECDH P-256       ✓')
    print('  ML-KEM-1024      ✓')
    print('  ECDSA P-256      ✓')
    print('  ML-DSA-87        ✓\n')

    # --- Alice sends to Bob ---
    print('Alice encrypting...')
    alice_ecdh = ECDHKeypair.generate()

    # key agreement
    ecdh_ss            = alice_ecdh.exchange(bob_ecdh.public_key_bytes)
    kyber_ct, kyber_ss = bob_kyber.encapsulate()

    # hybrid KDF
    session_key, salt  = derive_with_salt(ecdh_ss, kyber_ss)
    print(f'  Session key : {session_key.hex()[:32]}...')

    # encrypt
    with AESKey.from_bytes(session_key) as aes:
        ct = aes.encrypt(plaintext)

    # sign (dual: classical + PQC)
    wire = serialize(ct)
    ecdsa_sig = bob_ecdsa.sign(wire)
    dsa_sig   = bob_dsa.sign(wire)
    print(f'  Ciphertext  : {wire.hex()[:32]}...')
    print('  Signed with ECDSA P-256 + ML-DSA-87  ✓\n')

    # --- Bob receives ---
    print('Bob decrypting...')

    # verify signatures
    bob_ecdsa.verify(wire, ecdsa_sig)
    bob_dsa.verify(wire, dsa_sig)
    print('  Signatures verified  ✓')

    # recreate session key
    bob_ecdh_ss    = bob_ecdh.exchange(alice_ecdh.public_key_bytes)
    bob_kyber_ss   = bob_kyber.decapsulate(kyber_ct)
    bob_session_key = derive(bob_ecdh_ss, bob_kyber_ss, salt=salt)

    assert bob_session_key == session_key

    # decrypt
    ct2 = deserialize(wire)
    with AESKey.from_bytes(bob_session_key) as aes:
        recovered = aes.decrypt(ct2)

    print(f'  Recovered : {recovered.decode()}\n')
    assert recovered == plaintext
    print('Done ✓')


if __name__ == '__main__':
    run()
