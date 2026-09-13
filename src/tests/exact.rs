//! Exact oracle for the optimised row pipeline. Every departure from the
//! reference (64-bit storage, written-out merged transforms, Plantard
//! arithmetic, one reduction per row, the `−f` tables, the fused tail) is
//! checked here against plain modular arithmetic in `i128` from the FIPS
//! 204 definitions, on random inputs and on boundary inputs no valid
//! signature produces: the packed `w1Encode` bytes must be identical.

extern crate std;

use std::{vec, vec::Vec};

use crate::codec;
use crate::ml_dsa_44::PreparedVerifyingKey;
use crate::params::{BETA, GAMMA1, GAMMA2, K, L, N, Q, TAU};
use crate::poly::Poly;

const F: i128 = 41978;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn modq(x: i128) -> i128 {
    x.rem_euclid(Q as i128)
}

fn pow(mut b: i128, mut e: u64) -> i128 {
    let mut r = 1;
    b = modq(b);
    while e > 0 {
        if e & 1 == 1 {
            r = modq(r * b);
        }
        b = modq(b * b);
        e >>= 1;
    }
    r
}

/// FIPS 204 Algorithm 41 in exact arithmetic (bit-reversed output order).
fn ntt_exact(a: &[i128; N]) -> [i128; N] {
    let mut a = *a;
    let mut m = 0usize;
    let mut len = 128;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            m += 1;
            let zeta = pow(1753, (m as u8).reverse_bits() as u64);
            for j in start..start + len {
                let t = modq(zeta * a[j + len]);
                a[j + len] = modq(a[j] - t);
                a[j] = modq(a[j] + t);
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    a
}

/// FIPS 204 Algorithm 42 in exact arithmetic, including the `1/256`.
fn invntt_exact(a: &[i128; N]) -> [i128; N] {
    let mut a = *a;
    let mut m = 256usize;
    let mut len = 1;
    while len < N {
        let mut start = 0;
        while start < N {
            m -= 1;
            let zeta = modq(-pow(1753, (m as u8).reverse_bits() as u64));
            for j in start..start + len {
                let t = a[j];
                a[j] = modq(t + a[j + len]);
                a[j + len] = modq(zeta * (t - a[j + len]));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    let inv256 = pow(256, Q as u64 - 2);
    a.map(|v| modq(v * inv256))
}

/// Algorithm 36.
fn decompose(r: i128) -> (i128, i128) {
    let alpha = 2 * GAMMA2 as i128;
    let mut r0 = r.rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    if r - r0 == Q as i128 - 1 {
        (0, r0 - 1)
    } else {
        ((r - r0) / alpha, r0)
    }
}

/// Algorithm 40.
fn use_hint(h: bool, r: i128) -> i128 {
    let m = (Q as i128 - 1) / (2 * GAMMA2 as i128);
    let (r1, r0) = decompose(r);
    match (h, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1).rem_euclid(m),
        (true, false) => (r1 - 1).rem_euclid(m),
    }
}

/// Exact `w1Encode(UseHint(h, INTT(Σ_j a_j ∘ NTT(z_j) − NTT(c) ∘ t)))`.
fn reference_row(
    a: &[[i128; N]; L],
    z: &[[i128; N]; L],
    c: &[i128; N],
    t: &[i128; N],
    bits: &[u64; 4],
) -> [u8; 192] {
    let z_hat: Vec<[i128; N]> = z.iter().map(ntt_exact).collect();
    let c_hat = ntt_exact(c);
    let mut acc = [0i128; N];
    for k in 0..N {
        let mut s = 0;
        for j in 0..L {
            s += a[j][k] * z_hat[j][k];
        }
        acc[k] = modq(s - c_hat[k] * t[k]);
    }
    let w = invntt_exact(&acc);
    let mut out = [0u8; 192];
    for i in 0..N / 4 {
        let w1: Vec<u8> = (0..4)
            .map(|d| {
                let k = 4 * i + d;
                use_hint((bits[k / 64] >> (k % 64)) & 1 == 1, w[k]) as u8
            })
            .collect();
        out[3 * i] = w1[0] | (w1[1] << 6);
        out[3 * i + 1] = (w1[1] >> 2) | (w1[2] << 4);
        out[3 * i + 2] = (w1[2] >> 4) | (w1[3] << 2);
    }
    out
}

/// The crate's pipeline on the same inputs: tables scaled by `−f`, `z`
/// through `z_unpack` (from packed 18-bit fields) and `ntt`, `c` through
/// `ntt`, then `row_lazy`, `invntt`, `finish_row`.
fn optimised_row(
    a: &[[i128; N]; L],
    z_packed: &[[u8; 576]; L],
    c: &[i128; N],
    t: &[i128; N],
    bits: &[u64; 4],
) -> [u8; 192] {
    let scale = |v: i128| modq(v * -F) as u32;
    let mut row = [[0u32; PreparedVerifyingKey::ROW]; N];
    for k in 0..N {
        for j in 0..L {
            row[k][j] = scale(a[j][k]);
        }
        row[k][L] = scale(t[k]);
    }
    let mut z_hat = [Poly::ZERO; L];
    for j in 0..L {
        // A bound of γ1 + 1 admits every encodable coefficient: the oracle
        // covers the arithmetic, not the norm check.
        let _ = z_hat[j].z_unpack(&z_packed[j], GAMMA1 + 1);
        z_hat[j].ntt();
    }
    let mut c_hat = Poly::ZERO;
    for (dst, &src) in c_hat.c.iter_mut().zip(c) {
        *dst = src as i64;
    }
    c_hat.ntt();
    let mut w = Poly::ZERO;
    w.row_lazy(&row, [&z_hat[0], &z_hat[1], &z_hat[2], &z_hat[3]], &c_hat);
    w.invntt();
    let mut out = [0u8; 192];
    w.finish_row(bits, &mut out);
    out
}

/// Packs `z` coefficients (each in `(−γ1, γ1]`) as `γ1 − z` in 18-bit fields.
fn pack_z(z: &[i128; N]) -> [u8; 576] {
    let mut out = [0u8; 576];
    for i in 0..N / 4 {
        let f: Vec<u64> = (0..4)
            .map(|d| (GAMMA1 as i128 - z[4 * i + d]) as u64)
            .collect();
        let lo = f[0] | (f[1] << 18) | (f[2] << 36) | (f[3] << 54);
        out[9 * i..9 * i + 8].copy_from_slice(&lo.to_le_bytes());
        out[9 * i + 8] = (f[3] >> 10) as u8;
    }
    out
}

fn random_case(rng: &mut Rng, z_bound: i128, extreme_tables: bool) -> ([u8; 192], [u8; 192]) {
    let a: [[i128; N]; L] = core::array::from_fn(|_| {
        core::array::from_fn(|_| {
            if extreme_tables {
                Q as i128 - 1
            } else {
                rng.below(Q as u64) as i128
            }
        })
    });
    let t: [i128; N] = core::array::from_fn(|_| {
        if extreme_tables {
            Q as i128 - 1
        } else {
            rng.below(Q as u64) as i128
        }
    });
    // The encoding carries z ∈ [−γ1 + 1, γ1]: fields are γ1 − z in 18 bits.
    let z: [[i128; N]; L] = core::array::from_fn(|_| {
        core::array::from_fn(|_| {
            if z_bound == 0 {
                0
            } else {
                rng.below(2 * z_bound as u64) as i128 - (z_bound - 1)
            }
        })
    });
    let mut c = [0i128; N];
    for _ in 0..TAU {
        loop {
            let i = rng.below(N as u64) as usize;
            if c[i] == 0 {
                c[i] = if rng.below(2) == 0 { 1 } else { -1 };
                break;
            }
        }
    }
    let bits: [u64; 4] = core::array::from_fn(|_| rng.next());
    let z_packed: [[u8; 576]; L] = core::array::from_fn(|j| pack_z(&z[j]));
    (
        reference_row(&a, &z, &c, &t, &bits),
        optimised_row(&a, &z_packed, &c, &t, &bits),
    )
}

#[test]
fn random_rows_match_exact_arithmetic() {
    let mut rng = Rng(0x6a09_e667_f3bc_c908);
    for i in 0..40 {
        let (reference, ours) = random_case(&mut rng, GAMMA1 as i128 - BETA as i128 - 1, false);
        assert_eq!(reference, ours, "case {i}");
    }
}

#[test]
fn boundary_rows_match_exact_arithmetic() {
    let mut rng = Rng(0xbb67_ae85_84ca_a73b);
    // z at the largest magnitude the encoding carries, tables at Q − 1:
    // every bound in the crate's arithmetic is exercised at its edge.
    for i in 0..8 {
        let (reference, ours) = random_case(&mut rng, GAMMA1 as i128, true);
        assert_eq!(reference, ours, "extreme case {i}");
    }
    // z = 0: the row is −c ∘ t alone.
    let (reference, ours) = random_case(&mut rng, 0, false);
    assert_eq!(reference, ours, "zero z");
}

#[test]
fn hint_bitmap_matches_the_encoding() {
    // A hint block with indices in every polynomial maps to the bits the
    // exact oracle reads.
    let mut hints = [0u8; 84];
    let lists: [Vec<u8>; K] = [vec![0, 1, 255], vec![7], vec![], vec![3, 64, 128, 200]];
    let mut k = 0;
    for (i, list) in lists.iter().enumerate() {
        for &idx in list {
            hints[k] = idx;
            k += 1;
        }
        hints[80 + i] = k as u8;
    }
    let counts = codec::hint_counts(&hints).unwrap();
    for (i, list) in lists.iter().enumerate() {
        let bits = codec::hint_bitmap(&hints, &counts, i);
        for idx in 0..N {
            let set = (bits[idx / 64] >> (idx % 64)) & 1 == 1;
            assert_eq!(set, list.contains(&(idx as u8)), "poly {i}, index {idx}");
        }
    }
}

/// The heavy run: run with `cargo test --release --test exact -- --ignored`.
#[test]
#[ignore]
fn exact_oracle_campaign() {
    let mut rng = Rng(0x3c6e_f372_fe94_f82b);
    for i in 0..20_000 {
        let (reference, ours) = random_case(&mut rng, GAMMA1 as i128 - BETA as i128 - 1, false);
        assert_eq!(reference, ours, "random case {i}");
    }
    for i in 0..2_000 {
        let (reference, ours) = random_case(&mut rng, GAMMA1 as i128, true);
        assert_eq!(reference, ours, "extreme case {i}");
    }
}
