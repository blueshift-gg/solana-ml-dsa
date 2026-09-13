//! Differential tests against the `fips204` crate (an independent, ACVP-
//! tested FIPS 204 implementation): fresh keys, random messages and context
//! strings, and bit flips in every part of the signature, message and
//! context. Also the hint-encoding rejections (FIPS 204 Algorithm 21) that
//! ACVP does not isolate: repeated indices, decreasing indices, a hint
//! count above ω, nonzero padding, and an index count that goes backwards.

use fips204::ml_dsa_44;
use fips204::traits::{SerDes, Signer, Verifier};
use solana_ml_dsa::ml_dsa_44::{
    Error, PreparedVerifyingKey, SIGNATURE_LEN, Signature, VerifyingKey,
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

fn keypair() -> (VerifyingKey, ml_dsa_44::PrivateKey) {
    let (pk, sk) = ml_dsa_44::try_keygen().unwrap();
    (VerifyingKey::from_bytes(&(pk.into_bytes())), sk)
}

fn prepared(pk: &VerifyingKey) -> PreparedVerifyingKey {
    pk.prepare()
}

fn sign(sk: &ml_dsa_44::PrivateKey, ctx: &[u8], msg: &[u8]) -> Signature {
    Signature::from_bytes(&(sk.try_sign(msg, ctx).unwrap()))
}

fn m_prime(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = vec![0, ctx.len() as u8];
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    m
}

#[test]
fn accepts_fips204_signatures_on_all_interfaces() {
    let mut rng = Rng(0x243f_6a88_85a3_08d3);
    for round in 0..8 {
        let (pk, sk) = keypair();
        let key = prepared(&pk);
        for _ in 0..4 {
            let ctx_len = rng.below(256);
            let ctx = rng.bytes(ctx_len);
            let msg_len = rng.below(600);
            let msg = rng.bytes(msg_len);
            let sig = sign(&sk, &ctx, &msg);
            assert_eq!(
                key.verify_with_context(&msg, &ctx, &sig),
                Ok(()),
                "round {round}"
            );
            assert_eq!(key.verify_internal(&m_prime(&ctx, &msg), &sig), Ok(()));
            // The empty message and the empty context are valid inputs.
            let sig = sign(&sk, &[], &[]);
            assert_eq!(key.verify_with_context(&[], &[], &sig), Ok(()));
        }
    }
}

#[test]
fn rejects_a_context_longer_than_255_bytes() {
    let (pk, sk) = keypair();
    let key = prepared(&pk);
    let sig = sign(&sk, b"ctx", b"msg");
    assert_eq!(
        key.verify_with_context(b"msg", &[0u8; 256], &sig),
        Err(Error::ContextTooLong)
    );
}

#[test]
fn rejects_every_single_bit_flip_the_reference_rejects() {
    let mut rng = Rng(0x1319_8a2e_0370_7344);
    let (pk, sk) = keypair();
    let ctx = b"solana-ml-dsa oracle".to_vec();
    let msg = rng.bytes(200);
    let sig = sign(&sk, &ctx, &msg);
    let key = prepared(&pk);
    let reference = ml_dsa_44::PublicKey::try_from_bytes(pk.to_bytes()).unwrap();

    // Signature: one flip in each region (c̃, each z polynomial, hint
    // indices, hint counts) plus random positions.
    let mut positions = vec![0, 31, 32, 600, 1200, 1800, 2335, 2336, 2400, 2416, 2419];
    for _ in 0..40 {
        positions.push(rng.below(SIGNATURE_LEN));
    }
    for pos in positions {
        let mut bytes = sig.to_bytes();
        bytes[pos] ^= 1 << rng.below(8);
        let ours = key
            .verify_with_context(&msg, &ctx, &Signature::from_bytes(&bytes))
            .is_ok();
        let theirs = reference.verify(&msg, &bytes, &ctx);
        assert_eq!(ours, theirs, "signature byte {pos}");
        assert!(!ours, "signature byte {pos}: flip accepted");
    }
    for pos in [0, 100, 199] {
        let mut m = msg.clone();
        m[pos] ^= 0x80;
        assert_eq!(
            key.verify_with_context(&m, &ctx, &sig),
            Err(Error::InvalidSignature),
            "message byte {pos}"
        );
        assert!(!reference.verify(&m, &sig.to_bytes(), &ctx));
    }
    let mut c = ctx.clone();
    c[3] ^= 1;
    assert_eq!(
        key.verify_with_context(&msg, &c, &sig),
        Err(Error::InvalidSignature)
    );
    assert!(
        key.verify_with_context(&msg, &ctx[..ctx.len() - 1], &sig)
            .is_err()
    );
    // A key with one flipped bit is a different key.
    let mut k = pk.to_bytes();
    k[40] ^= 1;
    assert_eq!(
        prepared(&VerifyingKey::from_bytes(&k)).verify_with_context(&msg, &ctx, &sig),
        Err(Error::InvalidSignature)
    );
}

/// Builds a hint block with the given per-polynomial index lists, exactly
/// as FIPS 204 Algorithm 20 packs a valid one, then lets the caller break it.
fn hint_block(lists: &[Vec<u8>; 4]) -> [u8; 84] {
    let mut h = [0u8; 84];
    let mut k = 0;
    for (i, list) in lists.iter().enumerate() {
        for &idx in list {
            h[k] = idx;
            k += 1;
        }
        h[80 + i] = k as u8;
    }
    h
}

#[test]
fn rejects_malformed_hint_encodings() {
    // Find a signature with at least two hints in polynomial 0 so the
    // malformations below are reachable, and record its structure.
    let (pk, sk) = keypair();
    let key = prepared(&pk);
    let ctx = b"hints";
    let msg = b"hint encoding rules";
    let mut sig = sign(&sk, ctx, msg);
    let mut counts = [0u8; 4];
    loop {
        counts.copy_from_slice(&sig.to_bytes()[SIGNATURE_LEN - 4..]);
        if counts[0] >= 2 && counts[3] < 80 {
            break;
        }
        sig = sign(&sk, ctx, msg);
    }
    assert_eq!(key.verify_with_context(msg, ctx, &sig), Ok(()));
    let hints: [u8; 84] = sig.to_bytes()[SIGNATURE_LEN - 84..].try_into().unwrap();
    let mut lists: [Vec<u8>; 4] = Default::default();
    let mut k = 0usize;
    for i in 0..4 {
        lists[i] = hints[k..counts[i] as usize].to_vec();
        k = counts[i] as usize;
    }
    assert_eq!(
        hint_block(&lists),
        hints,
        "repacking a valid hint block is the identity"
    );

    let with_hints = |h: [u8; 84]| {
        let mut bytes = sig.to_bytes();
        bytes[SIGNATURE_LEN - 84..].copy_from_slice(&h);
        key.verify_with_context(msg, ctx, &Signature::from_bytes(&bytes))
    };

    // Repeated index (CVE-2026-24850 in ml-dsa < 0.1.1).
    let mut l = lists.clone();
    l[0].insert(1, l[0][0]);
    assert_eq!(
        with_hints(hint_block(&l)),
        Err(Error::InvalidSignature),
        "repeated index"
    );
    // Decreasing index.
    let mut l = lists.clone();
    l[0].swap(0, 1);
    assert_eq!(
        with_hints(hint_block(&l)),
        Err(Error::InvalidSignature),
        "decreasing index"
    );
    // Count going backwards between polynomials.
    let mut h = hints;
    h[81] = h[80].saturating_sub(1);
    assert_eq!(
        with_hints(h),
        Err(Error::InvalidSignature),
        "count decreases"
    );
    // Count above ω.
    let mut h = hints;
    h[83] = 81;
    assert_eq!(
        with_hints(h),
        Err(Error::InvalidSignature),
        "count above omega"
    );
    // Nonzero padding after the last index.
    let mut h = hints;
    h[counts[3] as usize] = 1;
    assert_eq!(
        with_hints(h),
        Err(Error::InvalidSignature),
        "nonzero padding"
    );
    // A moved hint (same count, different index) changes w1 and fails.
    let mut l = lists.clone();
    let last = l[0].len() - 1;
    l[0][last] = l[0][last].wrapping_add(1);
    if l[0].len() < 2 || l[0][last] > l[0][last - 1] {
        assert_eq!(
            with_hints(hint_block(&l)),
            Err(Error::InvalidSignature),
            "moved hint"
        );
    }
}

#[test]
fn account_form_round_trips_and_verifies() {
    let (pk, sk) = keypair();
    let sig = sign(&sk, b"account", b"prepared in place");
    let direct = pk.prepare();
    // A 4-byte aligned buffer, as account data is on chain.
    let mut words = vec![0u32; PreparedVerifyingKey::BYTE_LEN / 4];
    let bytes: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            words.as_mut_ptr() as *mut u8,
            PreparedVerifyingKey::BYTE_LEN,
        )
    };
    let in_place = PreparedVerifyingKey::mut_from_bytes(bytes).unwrap();
    pk.prepare_into(in_place);
    assert_eq!(in_place.as_bytes()[..], direct.as_bytes()[..]);
    let borrowed = PreparedVerifyingKey::ref_from_bytes(bytes).unwrap();
    assert_eq!(
        borrowed.verify_with_context(b"prepared in place", b"account", &sig),
        Ok(())
    );
    assert!(
        PreparedVerifyingKey::ref_from_bytes(&bytes[1..]).is_err(),
        "wrong length"
    );
    let mut longer = vec![0u32; PreparedVerifyingKey::BYTE_LEN / 4 + 1];
    let misaligned: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(
            (longer.as_mut_ptr() as *mut u8).add(2),
            PreparedVerifyingKey::BYTE_LEN,
        )
    };
    assert!(
        PreparedVerifyingKey::ref_from_bytes(misaligned).is_err(),
        "misaligned"
    );
}
