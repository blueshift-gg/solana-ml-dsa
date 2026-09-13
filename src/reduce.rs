//! Reduction modulo Q on 64-bit coefficients. `reduce32` and `caddq` are
//! PQClean `reduce.c`; products are reduced by Plantard multiplication
//! (Huang, Zhang, Zhao, Liu, Cheung, Koç, Chen, *Improved Plantard
//! Arithmetic for Lattice-based Cryptography*, TCHES 2022, with the 2024 and
//! 2026 corrections) instead of the reference's Montgomery reduction, which
//! `tests.rs` keeps as the oracle. Coefficients are `i64` in memory: SBPF
//! zero-extends 32-bit loads and sign extension costs two instructions per
//! multiply.

use crate::params::{Q, QINV};

/// For `a ≤ 2^31 − 2^22 − 1`, `r ≡ a (mod Q)` with `|r| ≤ 6283008`.
#[inline(always)]
pub const fn reduce32(a: i64) -> i64 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Adds Q if `a` is negative.
#[inline(always)]
pub const fn caddq(a: i64) -> i64 {
    a + ((a >> 63) & Q)
}

/// `Q^-1 mod 2^64`: one Newton step `x ← x·(2 − Q·x)` on `QINV`.
pub const QINV64: u64 = {
    let x = QINV as u64;
    x.wrapping_mul(2u64.wrapping_sub((Q as u64).wrapping_mul(x)))
};

/// Improved Plantard multiplication (Algorithm 10, Theorem 1) with word
/// size `l = 32` and `α = 8`, admitted by `Q < 2^(l − α − 1) = 2^23`.
/// `b_qinv = b · Q^-1 mod 2^64` is precomputed for the constant operand.
/// For `|a|, |b| ≤ Q · 2^8`: `r ≡ a · b · (−2^-64) (mod Q)` and
/// `−(Q+1)/2 ≤ r < Q/2`. With `b_qinv = QINV64` it is the Plantard
/// reduction (Algorithm 13): for `|c| ≤ Q^2 · 2^16`, `r ≡ c · (−2^-64)`.
#[inline(always)]
pub const fn plantard(a: i64, b_qinv: u64) -> i64 {
    const ALPHA: i64 = 1 << 8;
    let r = a.wrapping_mul(b_qinv as i64) >> 32;
    ((r + ALPHA) * Q) >> 32
}

/// `a · b mod Q` as a standard representative. Compile-time only: the
/// 128-bit remainder is a software routine on SBPF.
pub const fn mul_mod(a: i64, b: i64) -> i64 {
    ((a as i128 * b as i128).rem_euclid(Q as i128)) as i64
}

/// The Plantard constant for multiplying by `m`: `b · Q^-1 mod 2^64` with
/// `b ≡ −m · 2^64 (mod Q)` centred, so that `plantard(a, plantard_constant(m))
/// ≡ a · m`. Compile-time only.
pub const fn plantard_constant(m: i64) -> u64 {
    let mut b = mul_mod(-m, mul_mod(1 << 32, 1 << 32));
    if b > Q / 2 {
        b -= Q;
    }
    (b as u64).wrapping_mul(QINV64)
}
