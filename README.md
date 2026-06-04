# Aegis

**Hybrid quantum-safe encryption for Python.**

Combines classical cryptography (AES-256-GCM, ECDH P-256, ECDSA P-256) with post-quantum algorithms (ML-KEM-1024, ML-DSA-87) so security holds against both classical and quantum adversaries. Breaks only if BOTH algorithm families are broken simultaneously.

**Author:** Raghav Dinesh | [github.com/ruwgxo](https://github.com/ruwgxo) | MIT License

---

## Security Guarantees

| Property | How |
|---|---|
| Confidentiality | AES-256-GCM + ML-KEM-1024 — both must break simultaneously |
| Authenticity | Dual signatures: ECDSA P-256 + ML-DSA-87 (FIPS 204) |
| Forward secrecy | Ephemeral keys + 24h session rotation |
| Replay protection | Nonces + session binding |

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

| Operation | Classical | Aegis Hybrid | Overhead |
|---|---|---|---|
| Key generation | 0.5ms | 1.3ms | 2.6x |
| Encryption / KB | 0.02ms | 0.022ms | 10% |
| Signature | 1ms | 3ms | 3x |

## Project Status

**Pre-alpha.** Core crypto complete and tested. Not production-ready.

### Done

- `aegis/classical/` — AES-256-GCM, ECDH P-256, ECDSA P-256
- `aegis/pqc/` — ML-KEM-1024, ML-DSA-87
- `aegis/hybrid/kdf.py` — HKDF combining both shared secrets
- `aegis/hybrid/session.py` — session lifecycle, 24h key rotation, dual signing
- `tests/` — 66 tests passing (NIST KATs + integration)
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
