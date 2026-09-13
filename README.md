# Solana ML-DSA

[![CI](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml/badge.svg)](https://github.com/blueshift-gg/solana-ml-dsa/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/blueshift-gg/solana-ml-dsa/blob/main/LICENSE)

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
    let key = VerifyingKey::<false>::ref_from_bytes(key)?;
    key.verify(message, Signature::ref_from_bytes(signature)?)
}
```

Use `verify_with_context` when signing with a nonempty FIPS 204 context.
For JavaScript signing, use Noble's [`ml_dsa44`](https://github.com/paulmillr/noble-post-quantum).

`VerifyingKey::<false>` uses SHAKE128/256. Select `VerifyingKey::<true>` for
TurboSHAKE128/256 with domain `0x1f`; preparation carries that choice into
`PreparedVerifyingKey<true>`. This variant requires matching key generation and
signing and is not FIPS 204 or compatible with Noble's unmodified `ml_dsa44`.
The [test-vector generator](tests/fixtures/turbo.mjs) shows the matching Noble changes.

### Prepared keys

Prepare a key once and store it in an account to make repeated verification cheaper:

```rust
use solana_ml_dsa::ml_dsa_44::{Error, PreparedVerifyingKey, VerifyingKey};

fn prepare(key: &[u8], storage: &mut [u8]) -> Result<(), Error> {
    let prepared = PreparedVerifyingKey::<false>::mut_from_bytes(storage)?;
    VerifyingKey::<false>::ref_from_bytes(key)?.prepare_into(prepared);
    Ok(())
}
```

Storage must be `PreparedVerifyingKey::<false>::BYTE_LEN` bytes and four-byte aligned.
Only use prepared bytes initialized by your program for the intended key.

The [example program](program/src/lib.rs) registers a key and verifies signatures
from its account. Its [test](program/tests/registration.rs) shows account creation
and registration in one transaction.
Tags `0`/`1` create and verify with SHAKE; `2`/`3` use TurboSHAKE. The account
header binds the mode at creation.

## Compute units

Measured on SBPF v3; [benchmarks](tests/sbpf.rs).

| Operation | SHAKE CU | TurboSHAKE CU |
|---|---:|---:|
| Prepare a key | 1,089,630 | 667,260 |
| Verify with a prepared key | 261,344 | 219,199 |
| Verify with a compact key | 1,330,684 | 866,158 |

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

[MIT](https://github.com/blueshift-gg/solana-ml-dsa/blob/main/LICENSE).
