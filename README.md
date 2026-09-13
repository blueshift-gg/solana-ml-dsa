# Solana ML-DSA

[![CI](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ML-DSA-44 signature verification for Solana programs ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)).
`no_std`, with no allocation during verification.

| Public key | Prepared key | Signature |
|---:|---:|---:|
| 1,312 bytes | 20,544 bytes | 2,420 bytes |

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

Use `verify_with_context` when signing with a nonempty FIPS 204 context.
For JavaScript signing, use Noble's [`ml_dsa44`](https://github.com/paulmillr/noble-post-quantum).

### Prepared keys

Prepare a key once and store it in an account to make repeated verification cheaper:

```rust
use solana_ml_dsa::ml_dsa_44::{Error, PreparedVerifyingKey, VerifyingKey};

fn prepare(key: &[u8], storage: &mut [u8]) -> Result<(), Error> {
    let prepared = PreparedVerifyingKey::mut_from_bytes(storage)?;
    VerifyingKey::ref_from_bytes(key)?.prepare_into(prepared);
    Ok(())
}
```

Storage must be `PreparedVerifyingKey::BYTE_LEN` bytes and four-byte aligned.
Only use prepared bytes initialized by your program for the intended key.

The [example program](program/src/lib.rs) registers a key and verifies signatures
from its account. Its [test](program/tests/registration.rs) shows account creation
and registration in one transaction.

## Compute units

Measured on SBPF v3; [benchmarks](tests/sbpf.rs).

| Operation | CU |
|---|---:|
| Prepare a key | 1,094,201 |
| Verify with a prepared key | 265,342 |
| Verify with a compact key | 1,333,820 |

## Tests

```sh
cargo test --release --lib --test acvp --test oracle --test campaign --test sdk
cargo test --doc
cargo test --test sbpf -- --nocapture --test-threads=1
cargo build-sbf --arch v3 --manifest-path program/Cargo.toml
cargo test -p solana-ml-dsa-example --test registration
```

SBPF tests use `cargo-build-sbf 4.2.0`. Not independently audited.

## License

[MIT](LICENSE).
