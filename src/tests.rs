//! Defining properties of every transcribed or derived constant, and the
//! reference arithmetic each departure from PQClean is pinned against.

use crate::ml_dsa_44::PreparedVerifyingKey;
use crate::ntt::{PLANTARD, ZETAS};
use crate::params::*;
use crate::reduce::{QINV64, plantard};
use crate::rounding::w1_coefficient;

/// PQClean `montgomery_reduce`, the reference the Plantard pins compare
/// against. The `(uint64_t)a * QINV` truncation to `int32_t` is spelled
/// out as `as u32 as i32`.
fn montgomery_reduce(a: i64) -> i64 {
    let t = (a as u64).wrapping_mul(QINV as u64) as u32 as i32;
    (a - (t as i64) * Q) >> 32
}

fn modpow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    let mut acc = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = acc * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    acc
}

fn centred(x: i64) -> i64 {
    let q = Q;
    let r = x.rem_euclid(q);
    if r > q / 2 { r - q } else { r }
}

#[test]
fn q_is_prime_of_the_stated_form() {
    assert_eq!(Q, (1 << 23) - (1 << 13) + 1);
    let q = Q as u64;
    let mut d = 2;
    while d * d <= q {
        assert_ne!(q % d, 0, "Q divisible by {d}");
        d += 1;
    }
}

#[test]
fn root_of_unity_has_order_512() {
    let q = Q as u64;
    assert_eq!(modpow(ROOT_OF_UNITY as u64, 512, q), 1);
    assert_ne!(modpow(ROOT_OF_UNITY as u64, 256, q), 1);
}

#[test]
fn zetas_are_montgomery_root_powers_in_bit_reversed_order() {
    let q = Q as u64;
    let mont = modpow(2, 32, q);
    assert_eq!(ZETAS[0], 0, "index 0 is unused");
    for (i, &z) in ZETAS.iter().enumerate().skip(1) {
        let brv = (i as u8).reverse_bits() as u64;
        let expected = modpow(ROOT_OF_UNITY as u64, brv, q) * mont % q;
        assert_eq!(z.rem_euclid(q as i64) as u64, expected, "zetas[{i}]");
        assert!(z.unsigned_abs() < Q as u64, "zetas[{i}] not centred");
    }
}

#[test]
fn montgomery_constants() {
    assert_eq!(
        (Q as u32).wrapping_mul(QINV as u32),
        1,
        "QINV·Q ≡ 1 mod 2^32"
    );
    assert_eq!(MONT, centred(1i64 << 32), "MONT ≡ 2^32 mod Q, centred");
    // The inverse transform's scaling constant satisfies f·256 ≡ 2^64 (mod Q).
    let q = Q as u64;
    assert_eq!(
        crate::ml_dsa_44::INVNTT_SCALE as u64 * 256 % q,
        modpow(2, 64, q)
    );
}

#[test]
fn derived_parameters_and_sizes() {
    assert_eq!(GAMMA2, 95_232);
    assert_eq!((Q - 1) % 88, 0);
    assert_eq!(BETA, TAU as i64 * ETA);
    assert_eq!(GAMMA1, 1 << 17);
    assert_eq!((Q - 1) / (2 * GAMMA2), 44, "w1 coefficients lie in [0, 43]");
    // bitlen(Q − 1) − D = 23 − 13 = 10 bits per t1 coefficient.
    assert_eq!(POLYT1_PACKEDBYTES, 32 * (23 - D as usize));
    // bitlen(γ1 − 1) + 1 = 18 bits per z coefficient.
    assert_eq!(POLYZ_PACKEDBYTES, 32 * 18);
    // 6 bits per w1 coefficient.
    assert_eq!(POLYW1_PACKEDBYTES, 32 * 6);
    assert_eq!(PUBLIC_KEY_LEN, 1312);
    assert_eq!(SIGNATURE_LEN, 2420);
    assert_eq!(CTILDEBYTES, 2 * 128 / 8, "2λ bits");
    assert_eq!(POLYVECH_PACKEDBYTES, 84);
}

/// FIPS 204 Algorithm 36, `Decompose`, in integers.
fn decompose_reference(r: i64) -> (i64, i64) {
    let q = Q;
    let alpha = 2 * GAMMA2;
    let r_plus = r.rem_euclid(q);
    // r0 = r+ mod± α, in (−α/2, α/2].
    let mut r0 = r_plus.rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    if r_plus - r0 == q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / alpha, r0)
    }
}

/// FIPS 204 Algorithm 40 on top of Algorithm 36.
fn use_hint_reference(h: bool, r: i64) -> i64 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose_reference(r);
    match (h, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1).rem_euclid(m),
        (true, false) => (r1 - 1).rem_euclid(m),
    }
}

#[test]
fn w1_coefficient_matches_the_standard_on_every_representative() {
    for a in 0..Q {
        assert_eq!(
            w1_coefficient(a, false),
            use_hint_reference(false, a),
            "a = {a}, h = 0"
        );
        assert_eq!(
            w1_coefficient(a, true),
            use_hint_reference(true, a),
            "a = {a}, h = 1"
        );
    }
}

#[test]
fn norm_check_matches_absolute_value() {
    let bound = GAMMA1 - BETA;
    for a in -(1 << 18)..=(1 << 18) {
        assert_eq!(
            crate::poly::norm_at_least(a, bound),
            a.abs() >= bound,
            "a = {a}"
        );
    }
}

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

#[test]
fn qinv64_inverts_q_modulo_2_64() {
    assert_eq!((Q as u64).wrapping_mul(QINV64), 1);
}

/// Every Plantard twiddle is congruent to the reference's Montgomery
/// twiddle product over the whole admitted input range, and lands in the
/// theorem's output range `[−(q+1)/2, q/2)`, i.e. up to `(q−1)/2` inclusive.
#[test]
fn plantard_twiddles_match_montgomery_twiddles() {
    let bound = Q << 8;
    let mut x = 0x0123_4567_89ab_cdefu64;
    for k in 1..N {
        for i in 0..2000 {
            let a = match i {
                0 => -bound,
                1 => bound,
                2 => 0,
                _ => (xorshift(&mut x) % (2 * bound as u64 + 1)) as i64 - bound,
            };
            let ours = plantard(a, PLANTARD[k]);
            let reference = montgomery_reduce(ZETAS[k] * a);
            assert_eq!((ours - reference).rem_euclid(Q), 0, "k = {k}, a = {a}");
            assert!(
                (-(Q + 1) / 2..=(Q - 1) / 2).contains(&ours),
                "k = {k}, a = {a}: {ours}"
            );
            let neg = plantard(a, PLANTARD[k].wrapping_neg());
            let reference = montgomery_reduce(-ZETAS[k] * a);
            assert_eq!(
                (neg - reference).rem_euclid(Q),
                0,
                "negated k = {k}, a = {a}"
            );
        }
    }
}

/// The Plantard reduction of a 64-bit accumulator is `c · (−2^-64) mod Q`
/// in range, over the accumulator's admitted range.
#[test]
fn plantard_reduction_is_congruent() {
    let bound = ((Q as i128) * (Q as i128)) << 16;
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for i in 0..200_000 {
        let c: i128 = match i {
            0 => -bound,
            1 => bound,
            _ => ((xorshift(&mut x) as u128) % (2 * bound as u128 + 1)) as i128 - bound,
        };
        let c = c as i64;
        let r = plantard(c, QINV64);
        // r · (−2^64) ≡ c (mod Q)
        let lhs = (r as i128 * -(1i128 << 64)).rem_euclid(Q as i128);
        assert_eq!(lhs, (c as i128).rem_euclid(Q as i128), "c = {c}");
        assert!((-(Q + 1) / 2..=(Q - 1) / 2).contains(&r), "c = {c}: {r}");
    }
}

/// FIPS 204 Algorithm 41 / PQClean `ntt`, the loop the unrolled transform
/// was written out from.
fn ntt_reference(a: &mut [i64; N]) {
    let mut k = 0;
    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
            for j in start..start + len {
                let t = montgomery_reduce(zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// FIPS 204 Algorithm 42 / PQClean `invntt_tomont`.
fn invntt_reference(a: &mut [i64; N]) {
    let mut k = 256;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            k -= 1;
            let zeta = -ZETAS[k];
            for j in start..start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce(zeta * a[j + len]);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for v in a.iter_mut() {
        *v = montgomery_reduce(41978 * *v);
    }
}

/// The unrolled transforms agree with the looped reference (FIPS 204
/// Algorithms 41 and 42) coefficient by coefficient modulo Q, and their
/// outputs respect the bounds the verifier relies on.
#[test]
fn unrolled_transforms_are_congruent_to_the_reference_loops() {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..200 {
        let mut a = [0i64; N];
        for v in a.iter_mut() {
            *v = (xorshift(&mut x) % (2 * GAMMA1 as u64)) as i64 - GAMMA1;
        }
        let mut u = a;
        let mut r = a;
        crate::ntt::ntt(&mut u);
        ntt_reference(&mut r);
        for k in 0..N {
            assert_eq!((u[k] - r[k]).rem_euclid(Q), 0, "forward, k = {k}");
            assert!(u[k].abs() < 1 << 27, "forward bound, k = {k}");
        }
        // Inverse inputs below Q in absolute value, the transform's contract.
        let mut a = [0i64; N];
        for v in a.iter_mut() {
            *v = (xorshift(&mut x) % (2 * Q as u64 - 1)) as i64 - (Q - 1);
        }
        let mut u = a;
        let mut r = a;
        crate::ntt::invntt(&mut u);
        for v in u.iter_mut() {
            *v = montgomery_reduce(crate::ml_dsa_44::INVNTT_SCALE * *v);
        }
        invntt_reference(&mut r);
        for k in 0..N {
            assert_eq!((u[k] - r[k]).rem_euclid(Q), 0, "inverse, k = {k}");
        }
    }
}

/// Interval arithmetic over the reference schedule (the written-out
/// transforms perform the same butterflies, in an order that changes no
/// value): every Plantard input must lie within `±Q·2^8`, the inverse
/// output within `reduce32`'s domain, and the row accumulator within the
/// Plantard reduction's `Q^2·2^16`, for every signature encoding, valid or
/// not.
#[test]
fn every_bound_the_arithmetic_relies_on_holds() {
    const PLANTARD_IN: i64 = Q << 8;
    const PLANTARD_OUT: (i64, i64) = (-(Q + 1) / 2, (Q - 1) / 2);
    const REDUCE32_IN: i64 = (1 << 31) - (1 << 22) - 1;
    type Interval = (i64, i64);

    fn forward(mut a: [Interval; N]) -> [Interval; N] {
        let mut len = 128;
        while len > 0 {
            let mut start = 0;
            while start < N {
                for j in start..start + len {
                    let (lo, hi) = a[j + len];
                    assert!(
                        -PLANTARD_IN <= lo && hi <= PLANTARD_IN,
                        "forward len {len} j {j}"
                    );
                    let t = PLANTARD_OUT;
                    a[j + len] = (a[j].0 - t.1, a[j].1 - t.0);
                    a[j] = (a[j].0 + t.0, a[j].1 + t.1);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        a
    }

    fn inverse(mut a: [Interval; N]) -> [Interval; N] {
        let mut len = 1;
        while len < N {
            let mut start = 0;
            while start < N {
                for j in start..start + len {
                    let (t, u) = (a[j], a[j + len]);
                    let diff = (t.0 - u.1, t.1 - u.0);
                    assert!(
                        -PLANTARD_IN <= diff.0 && diff.1 <= PLANTARD_IN,
                        "inverse len {len} j {j}: {diff:?}"
                    );
                    a[j] = (t.0 + u.0, t.1 + u.1);
                    a[j + len] = PLANTARD_OUT;
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        a
    }

    // z from any 18-bit encoding, c from SampleInBall.
    let z_hat = forward([(GAMMA1 - (1 << 18) + 1, GAMMA1); N]);
    let c_hat = forward([(-1, 1); N]);
    let z_max = z_hat
        .iter()
        .map(|&(lo, hi)| lo.abs().max(hi.abs()))
        .max()
        .unwrap();
    let c_max = c_hat
        .iter()
        .map(|&(lo, hi)| lo.abs().max(hi.abs()))
        .max()
        .unwrap();
    let acc_max = (4 * (Q - 1) as i128 * z_max as i128) + (Q - 1) as i128 * c_max as i128;
    assert!(
        acc_max <= ((Q as i128) * (Q as i128)) << 16,
        "row accumulator {acc_max}"
    );

    let w = inverse([PLANTARD_OUT; N]);
    for (k, &(lo, hi)) in w.iter().enumerate() {
        assert!(
            -REDUCE32_IN <= lo && hi <= REDUCE32_IN,
            "inverse output {k}: ({lo}, {hi})"
        );
    }
}

/// Plantard over its whole admitted input range, for the twiddle constant
/// of largest magnitude and for the reduction constant. Slow; run with
/// `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn plantard_exhaustive_on_extreme_constants() {
    let bound = Q << 8;
    let k = (1..N)
        .max_by_key(|&k| (PLANTARD[k] as i64).unsigned_abs())
        .unwrap();
    let mut a = -bound;
    while a <= bound {
        let r = plantard(a, PLANTARD[k]);
        assert!(
            (-(Q + 1) / 2..=(Q - 1) / 2).contains(&r),
            "twiddle a = {a}: {r}"
        );
        assert_eq!(
            r.rem_euclid(Q),
            montgomery_reduce(ZETAS[k] * a).rem_euclid(Q),
            "twiddle a = {a}"
        );
        let r = plantard(a, QINV64);
        assert!(
            (-(Q + 1) / 2..=(Q - 1) / 2).contains(&r),
            "reduction a = {a}: {r}"
        );
        // r · (−2^64) ≡ a (mod Q)
        let lhs = (r as i128 * -(1i128 << 64)).rem_euclid(Q as i128);
        assert_eq!(lhs, (a as i128).rem_euclid(Q as i128), "reduction a = {a}");
        a += 1;
    }
}

/// The table-scaling constant multiplies by `−f` modulo Q over the inputs
/// registration feeds it.
#[test]
fn table_scaling_constant_multiplies_by_minus_f() {
    let m = crate::reduce::plantard_constant(-crate::ml_dsa_44::INVNTT_SCALE);
    let mut x = 0x1234_5678_9abc_def1u64;
    for i in 0..200_000 {
        let a = match i {
            0 => 0,
            1 => Q - 1,
            2 => -(1 << 26),
            3 => 1 << 26,
            _ => (xorshift(&mut x) % (1u64 << 27)) as i64 - (1 << 26),
        };
        let r = crate::reduce::caddq(plantard(a, m));
        let expected =
            (a as i128 * -(crate::ml_dsa_44::INVNTT_SCALE as i128)).rem_euclid(Q as i128) as i64;
        assert_eq!(r, expected, "a = {a}");
    }
}

/// A row borrowed from bytes is exactly one row, at a 4-byte boundary.
#[test]
fn row_from_bytes_checks_length_and_alignment() {
    let mut buf = [0u8; PreparedVerifyingKey::ROW_BYTE_LEN + 8];
    let aligned = (buf.as_ptr() as usize).next_multiple_of(4) - buf.as_ptr() as usize;
    assert!(
        PreparedVerifyingKey::borrow_row_mut(
            &mut buf[aligned..aligned + PreparedVerifyingKey::ROW_BYTE_LEN]
        )
        .is_ok()
    );
    assert!(
        PreparedVerifyingKey::borrow_row_mut(
            &mut buf[aligned + 1..aligned + 1 + PreparedVerifyingKey::ROW_BYTE_LEN]
        )
        .is_err()
    );
    assert!(
        PreparedVerifyingKey::borrow_row_mut(
            &mut buf[aligned..aligned + PreparedVerifyingKey::ROW_BYTE_LEN - 4]
        )
        .is_err()
    );
    assert_eq!(
        K * PreparedVerifyingKey::ROW_BYTE_LEN + TRBYTES,
        PreparedVerifyingKey::BYTE_LEN
    );
    assert_eq!(
        PreparedVerifyingKey::PUBLIC_KEY_HASH_OFFSET + TRBYTES,
        PreparedVerifyingKey::BYTE_LEN
    );
}

mod exact;
