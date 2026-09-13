//! Differential safety campaign. Every verdict the verifier gives is
//! compared with two independent implementations of FIPS 204, `fips204`
//! (Rust) and PQClean through `pqcrypto-mldsa` (C), on inputs chosen to be
//! hostile rather than random: every single-bit flip of a signature and of a
//! public key, hint encodings mutated while staying well formed, garbage
//! keys and signatures, and context and message lengths at every SHAKE
//! block boundary. The heavy runs are ignored by default:
//!
//! ```sh
//! cargo test --release --test campaign -- --ignored --nocapture
//! ```

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};
use pqcrypto_mldsa::mldsa44;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use solana_ml_dsa::ml_dsa_44::{
    Error, PUBLIC_KEY_LEN, PreparedVerifyingKey, SIGNATURE_LEN, Signature, VerifyingKey,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Lengths at and around the SHAKE256 block boundary, for `μ = H(tr ‖ 0 ‖
/// |ctx| ‖ ctx ‖ msg)`: `tr` is 64 bytes, so the first block holds 70 more.
const LENGTHS: [usize; 12] = [0, 1, 31, 32, 33, 69, 70, 71, 135, 136, 137, 1000];

struct Key {
    pk: [u8; PUBLIC_KEY_LEN],
    prepared: PreparedVerifyingKey,
    rust: ml_dsa_44::PublicKey,
    c: mldsa44::PublicKey,
}

impl Key {
    fn from_bytes(pk: [u8; PUBLIC_KEY_LEN]) -> Key {
        Key {
            pk,
            prepared: VerifyingKey::<false>::from_bytes(&pk).prepare(),
            rust: ml_dsa_44::PublicKey::try_from_bytes(pk).unwrap(),
            c: mldsa44::PublicKey::from_bytes(&pk).unwrap(),
        }
    }

    /// The three verdicts on one input; asserts they agree and returns ours.
    fn agree(&self, ctx: &[u8], msg: &[u8], sig: &[u8; SIGNATURE_LEN], what: &str) -> bool {
        let ours = self
            .prepared
            .verify_with_context(msg, ctx, Signature::ref_from_bytes(sig).unwrap())
            .is_ok();
        let raw = VerifyingKey::<false>::from_bytes(&self.pk)
            .verify_with_context(msg, ctx, Signature::ref_from_bytes(sig).unwrap())
            .is_ok();
        assert_eq!(ours, raw, "{what}: prepared vs raw key");
        let rust = self.rust.verify(msg, sig, ctx);
        let c = mldsa44::verify_detached_signature_ctx(
            &mldsa44::DetachedSignature::from_bytes(sig).unwrap(),
            msg,
            ctx,
            &self.c,
        )
        .is_ok();
        assert_eq!(ours, rust, "{what}: ours vs fips204");
        assert_eq!(ours, c, "{what}: ours vs PQClean");
        ours
    }
}

fn rust_keypair() -> (Key, ml_dsa_44::PrivateKey) {
    let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
    (Key::from_bytes(pk.into_bytes()), sk)
}

fn rust_sign(sk: &ml_dsa_44::PrivateKey, ctx: &[u8], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    sk.try_sign(msg, ctx).unwrap()
}

fn c_keypair() -> (Key, mldsa44::SecretKey) {
    let (pk, sk) = mldsa44::keypair();
    (Key::from_bytes(pk.as_bytes().try_into().unwrap()), sk)
}

fn c_sign(sk: &mldsa44::SecretKey, ctx: &[u8], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    mldsa44::detached_sign_ctx(msg, ctx, sk)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// A key prepared at compile time is byte for byte the key prepared at
/// run time.
static COMPILE_TIME_KEY: PreparedVerifyingKey = {
    let mut key = PreparedVerifyingKey::<false>::ZERO;
    VerifyingKey::<false>::from_bytes(include_bytes!("fixtures/campaign.pk"))
        .prepare_into(&mut key);
    key
};

#[test]
fn compile_time_preparation_equals_run_time_preparation() {
    let pk = VerifyingKey::<false>::from_bytes(include_bytes!("fixtures/campaign.pk"));
    let runtime = pk.prepare();
    assert_eq!(COMPILE_TIME_KEY.as_bytes()[..], runtime.as_bytes()[..]);
}

#[test]
fn boundary_lengths_verify_and_agree() {
    let (key, sk) = rust_keypair();
    for &ctx_len in &[0usize, 1, 69, 70, 71, 135, 254, 255] {
        for &msg_len in &LENGTHS {
            let ctx = vec![0xA5u8; ctx_len];
            let msg = vec![0x5Au8; msg_len];
            let sig = rust_sign(&sk, &ctx, &msg);
            assert!(key.agree(&ctx, &msg, &sig, &format!("ctx {ctx_len} msg {msg_len}")));
        }
    }
    // A context above 255 bytes is an error, not a signature failure.
    let sig = rust_sign(&sk, b"", b"");
    assert_eq!(
        key.prepared.verify_with_context(
            b"",
            &[0u8; 256],
            Signature::ref_from_bytes(&sig).unwrap()
        ),
        Err(Error::ContextTooLong)
    );
}

#[test]
#[ignore]
fn signatures_from_both_references_verify() {
    let mut rng = Rng(0x0102_0304_0506_0708);
    let (rust_key, rust_sk) = rust_keypair();
    let (c_key, c_sk) = c_keypair();
    for i in 0..5000 {
        let ctx_len = if i % 7 == 0 {
            LENGTHS[i % LENGTHS.len()].min(255)
        } else {
            rng.below(256)
        };
        let msg_len = if i % 5 == 0 {
            LENGTHS[i % LENGTHS.len()]
        } else {
            rng.below(700)
        };
        let ctx = rng.bytes(ctx_len);
        let msg = rng.bytes(msg_len);
        let sig = rust_sign(&rust_sk, &ctx, &msg);
        assert!(rust_key.agree(&ctx, &msg, &sig, &format!("fips204 signature {i}")));
        let sig = c_sign(&c_sk, &ctx, &msg);
        assert!(c_key.agree(&ctx, &msg, &sig, &format!("PQClean signature {i}")));
        // Cross-signer: a signature under one key never verifies under the other.
        assert!(!rust_key.agree(&ctx, &msg, &sig, &format!("cross {i}")));
    }
}

#[test]
#[ignore]
fn every_single_bit_flip_of_a_signature_is_rejected_by_all() {
    let mut rng = Rng(0x1112_1314_1516_1718);
    let (key, sk) = rust_keypair();
    for s in 0..3 {
        let ctx_len = rng.below(40);
        let ctx = rng.bytes(ctx_len);
        let msg_len = rng.below(200);
        let msg = rng.bytes(msg_len);
        let sig = rust_sign(&sk, &ctx, &msg);
        assert!(key.agree(&ctx, &msg, &sig, "unmodified"));
        for byte in 0..SIGNATURE_LEN {
            for bit in 0..8 {
                let mut flipped = sig;
                flipped[byte] ^= 1 << bit;
                assert!(!key.agree(
                    &ctx,
                    &msg,
                    &flipped,
                    &format!("sig {s} byte {byte} bit {bit}")
                ));
            }
        }
    }
}

#[test]
#[ignore]
fn every_single_bit_flip_of_a_public_key_is_rejected_by_all() {
    let mut rng = Rng(0x2122_2324_2526_2728);
    let (key, sk) = rust_keypair();
    let ctx = rng.bytes(20);
    let msg = rng.bytes(100);
    let sig = rust_sign(&sk, &ctx, &msg);
    assert!(key.agree(&ctx, &msg, &sig, "unmodified"));
    for byte in 0..PUBLIC_KEY_LEN {
        for bit in 0..8 {
            let mut pk = key.pk;
            pk[byte] ^= 1 << bit;
            let flipped = Key::from_bytes(pk);
            assert!(!flipped.agree(&ctx, &msg, &sig, &format!("pk byte {byte} bit {bit}")));
        }
    }
}

/// Well-formed hint blocks that differ from the signature's: an index
/// dropped, an index added, an index moved by one, an index shifted between
/// neighbouring polynomials. All must be rejected, and all three verifiers
/// must say so.
#[test]
#[ignore]
fn well_formed_hint_mutations_are_rejected_by_all() {
    let mut rng = Rng(0x3132_3334_3536_3738);
    let (key, sk) = rust_keypair();
    let mut mutations = 0;
    for s in 0..300 {
        let ctx = rng.bytes(8);
        let msg = rng.bytes(64);
        let sig = rust_sign(&sk, &ctx, &msg);
        let hints = &sig[SIGNATURE_LEN - 84..];
        let counts: [usize; 4] = core::array::from_fn(|i| hints[80 + i] as usize);
        let lists: Vec<Vec<u8>> = (0..4)
            .map(|i| hints[if i == 0 { 0 } else { counts[i - 1] }..counts[i]].to_vec())
            .collect();
        let with = |lists: &[Vec<u8>]| -> [u8; SIGNATURE_LEN] {
            let mut out = sig;
            let block = &mut out[SIGNATURE_LEN - 84..];
            block.fill(0);
            let mut k = 0;
            for (i, list) in lists.iter().enumerate() {
                for &idx in list {
                    block[k] = idx;
                    k += 1;
                }
                block[80 + i] = k as u8;
            }
            out
        };
        assert_eq!(with(&lists), sig, "repacking is the identity");
        for i in 0..4 {
            // Drop each index.
            for j in 0..lists[i].len() {
                let mut l = lists.clone();
                l[i].remove(j);
                assert!(!key.agree(&ctx, &msg, &with(&l), &format!("sig {s} drop {i}/{j}")));
                mutations += 1;
            }
            // Move each index by ±1 where the order stays strict.
            for j in 0..lists[i].len() {
                for delta in [-1i16, 1] {
                    let v = lists[i][j] as i16 + delta;
                    if !(0..256).contains(&v) {
                        continue;
                    }
                    let mut l = lists.clone();
                    l[i][j] = v as u8;
                    if l[i].windows(2).all(|w| w[0] < w[1]) {
                        assert!(!key.agree(
                            &ctx,
                            &msg,
                            &with(&l),
                            &format!("sig {s} move {i}/{j}")
                        ));
                        mutations += 1;
                    }
                }
            }
            // Add an index in the first gap, if ω allows.
            if counts[3] < 80 {
                let mut l = lists.clone();
                let free = (0..=255u8).find(|v| !l[i].contains(v)).unwrap();
                l[i].push(free);
                l[i].sort_unstable();
                assert!(!key.agree(&ctx, &msg, &with(&l), &format!("sig {s} add {i}")));
                mutations += 1;
            }
            // Shift the last index of polynomial i to the front of i + 1.
            if i < 3
                && let Some(&last) = lists[i].last()
                && lists[i + 1].first().is_none_or(|&f| f > last)
            {
                let mut l = lists.clone();
                l[i].pop();
                l[i + 1].insert(0, last);
                assert!(!key.agree(&ctx, &msg, &with(&l), &format!("sig {s} shift {i}")));
                mutations += 1;
            }
        }
    }
    println!("hint mutations checked: {mutations}");
    assert!(mutations > 10_000);
}

#[test]
#[ignore]
fn garbage_keys_and_signatures_never_panic_and_agree() {
    let mut rng = Rng(0x4142_4344_4546_4748);
    let (real, sk) = rust_keypair();
    for i in 0..3000 {
        let ctx_len = rng.below(16);
        let ctx = rng.bytes(ctx_len);
        let msg_len = rng.below(64);
        let msg = rng.bytes(msg_len);
        // Garbage signature under a real key.
        let garbage: [u8; SIGNATURE_LEN] = rng.bytes(SIGNATURE_LEN).try_into().unwrap();
        assert!(!real.agree(&ctx, &msg, &garbage, &format!("garbage sig {i}")));
        // Real signature under a garbage key, and garbage under garbage.
        let pk: [u8; PUBLIC_KEY_LEN] = rng.bytes(PUBLIC_KEY_LEN).try_into().unwrap();
        let junk = Key::from_bytes(pk);
        let sig = rust_sign(&sk, &ctx, &msg);
        assert!(!junk.agree(&ctx, &msg, &sig, &format!("real sig, garbage key {i}")));
        assert!(!junk.agree(&ctx, &msg, &garbage, &format!("garbage on garbage {i}")));
        // Structured garbage: a valid signature with its z region randomised,
        // its hint region zeroed, or its commitment randomised.
        let mut z_random = sig;
        z_random[32..32 + 2304].copy_from_slice(&rng.bytes(2304));
        assert!(!real.agree(&ctx, &msg, &z_random, &format!("random z {i}")));
        let mut no_hints = sig;
        no_hints[SIGNATURE_LEN - 84..].fill(0);
        assert!(!real.agree(&ctx, &msg, &no_hints, &format!("zero hints {i}")));
        let mut c_random = sig;
        c_random[..32].copy_from_slice(&rng.bytes(32));
        assert!(!real.agree(&ctx, &msg, &c_random, &format!("random commitment {i}")));
    }
}
