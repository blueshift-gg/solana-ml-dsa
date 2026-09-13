# Solana ML-DSA

[![CI](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ML-DSA-44 signature verification for Solana programs, following FIPS 204.
`no_std`, with no allocation on the verification path. SHAKE comes from
`solana-shake`; signing is left to existing implementations.

| Encoding | Bytes |
|---|---:|
| Public key | 1,312 |
| Prepared key | 20,544 |
| Signature | 2,420 |

## Usage

```toml
[dependencies]
solana-ml-dsa = { git = "https://github.com/blueshift-gg/solana-ml-dsa" }
```

```rust
use solana_ml_dsa::ml_dsa_44::{Error, Signature, VerifyingKey};

fn verify(key: &[u8], signature: &[u8], message: &[u8]) -> Result<(), Error> {
    let key = VerifyingKey::ref_from_bytes(key)?;
    key.verify(message, Signature::ref_from_bytes(signature)?)
}
```

`verify` uses an empty context; `verify_with_context` accepts a FIPS 204
context of at most 255 bytes. Constructors check encoded size; verification
checks signature validity. `verify_internal` and `verify_mu` accept the
standard's framed message and external 64-byte message representative,
respectively. HashML-DSA is not implemented.

### Prepared keys

Prepare a repeatedly used key once to avoid expanding its matrix on each
verification. Hosts can call `key.prepare()`. Programs use caller-provided
storage:

```rust
use solana_ml_dsa::ml_dsa_44::{Error, PreparedVerifyingKey, VerifyingKey};

fn prepare(key: &[u8], storage: &mut [u8]) -> Result<(), Error> {
    let prepared = PreparedVerifyingKey::mut_from_bytes(storage)?;
    VerifyingKey::ref_from_bytes(key)?.prepare_into(prepared);
    Ok(())
}
```

Storage must be exactly `PreparedVerifyingKey::BYTE_LEN` and four-byte
aligned. Borrowing constructors check layout only. The consuming program
must authenticate account ownership, initialization and the intended key;
a cache's bytes do not prove its derivation. Owned decoding also checks
canonical coefficient encodings.

The [example program](program/src/lib.rs) allocates an account with a top-level
System Program instruction, then prepares the compact key in the same
transaction. Subsequent verification borrows the stored prepared key.
Account allocation and authorization stay in the consuming program.

## Compute units

SBPF v3, platform-tools v1.56, under Mollusk. These are local measurements;
transaction sizes below use V1 messages with a 4,096-byte budget.

| Operation | CU |
|---|---:|
| Prepared verification, 32-byte message and 13-byte context | 265,342 |
| Prepare a public key into storage | 1,094,201 |
| Verify directly from the compact key | 1,333,820 |
| Allocate and register, complete example transaction (1,690 bytes) | 1,094,800 |
| Verify from the account, complete example transaction (2,676 bytes) | 265,517 |

## Tests

CI checks formatting, strict Clippy, doctests, NIST ACVP vectors, independent
FIPS 204 implementations, arithmetic bounds and SBPF behavior. The example
checks preparation bytes, transaction limits, tampering, repeated registration
and rollback. Slow differential campaigns remain opt-in with `--ignored`.

```sh
cargo test --release --lib --test acvp --test oracle --test campaign --test sdk
cargo test --doc
cargo test --test sbpf -- --nocapture --test-threads=1
cargo build-sbf --arch v3 --manifest-path program/Cargo.toml
cargo test -p solana-ml-dsa-example --test registration -- --nocapture
```

SBPF tests require `cargo-build-sbf 4.2.0`. For JavaScript signing and
verification, use [`@noble/post-quantum/ml-dsa.js`](https://github.com/paulmillr/noble-post-quantum)
with `ml_dsa44`; this repository does not duplicate it.

Not independently audited.

## License

[MIT](LICENSE).
