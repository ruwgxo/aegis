# Aegis

**Hybrid quantum-safe encryption for Python.**

Combines classical cryptography (AES-256-GCM, ECDH P-256, ECDSA P-256) with post-quantum algorithms (ML-KEM-1024, ML-DSA-87) in an experimental hybrid construction. End-to-end security also depends on the protocol limitations below.

**Author:** Raghav Dinesh | [github.com/ruwgxo](https://github.com/ruwgxo) | MIT License

---

## Security Status

This is an experimental implementation, not a production secure-channel protocol.
The cryptographic primitives are combined in the code, but the current session
API has important limitations:

- Handshake keys are exchanged without peer authentication or transcript signatures.
- Random encryption nonces do not provide replay detection; no replay cache exists.
- Rotation generates local keys without a peer re-handshake, so peers lose key agreement.
- `Session.verify()` uses the session's own signing keys, not a stored peer identity.
- Clearing a mutable copy does not guarantee erasure of the original Python key bytes.
- The KDF XOR-combines the ECDH and ML-KEM shared secrets and does not bind the key to
  the KEM ciphertext or either party's public keys. Standard hybrid designs concatenate
  the secrets and include that context, so this combiner should not be relied on.

The quickstart demonstrates a basic round trip only. Authenticated handshakes,
peer-coordinated rotation, replay protection, and key lifecycle handling require
further implementation and review before deployment.

## Algorithms

- **Classical:** AES-256-GCM, ECDH P-256, ECDSA P-256
- **Post-quantum:** ML-KEM-1024 (FIPS 203, formerly Kyber-1024), ML-DSA-87 (FIPS 204, formerly Dilithium-5)
- **Key derivation:** HKDF-SHA256 combining both shared secrets

## Install

```bash
pip install cryptography liboqs-python
```

> `liboqs-python` requires native liboqs binaries.
> macOS: `brew install liboqs` — Linux: see [liboqs install guide](https://github.com/open-quantum-safe/liboqs)

## Quickstart

```python
from aegis.hybrid.session import Session

# Alice
alice = Session.create()
hs = alice.initiate()           # send to Bob

# Bob
bob = Session.create()
response = bob.respond(hs)      # send back to Alice

# Alice completes handshake
alice.complete(response)

# Encrypt / decrypt
wire = alice.encrypt(b'quantum-safe message')
plain = bob.decrypt(wire)       # b'quantum-safe message'
```

See `examples/basic_encryption.py` for a full end-to-end demo.

## Performance

Not yet measured. `benchmarks/performance.py` is on the TODO list below; figures
will be published with the hardware, library versions and script that produced them.

## Project Status

**Pre-alpha.** Cryptographic primitives and an experimental session API are implemented. Not production-ready.

### Done

- `aegis/classical/` — AES-256-GCM, ECDH P-256, ECDSA P-256
- `aegis/pqc/` — ML-KEM-1024, ML-DSA-87
- `aegis/hybrid/kdf.py` — HKDF combining both shared secrets
- `aegis/hybrid/session.py` — experimental session lifecycle, local key rotation, dual signing
- `tests/` — 64 tests passing (classical primitives including AES-256-GCM NIST KATs, PQC, hybrid KDF and session)
- `examples/basic_encryption.py`

### TODO (v0.1.0-alpha)

```
aegis/utils/nonce.py           nonce management + cache
aegis/utils/secure_memory.py   mlock, secure allocator
aegis/keys/manager.py          key lifecycle: generate, store, rotate, revoke
aegis/keys/rotation.py         automated rotation scheduler
examples/secure_channel.py     full channel demo with forward secrecy
examples/key_rotation.py       rotation demo
benchmarks/performance.py      overhead vs classical baseline
pyproject.toml                 packaging metadata
README — install + quickstart  (this file, update on release)
```

## Testing

```bash
pip install pytest
PYTHONPATH=. python -m pytest tests/ -v
```

## License

MIT © 2025 Raghav Dinesh
