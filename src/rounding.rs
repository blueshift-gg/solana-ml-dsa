//! `UseHint ∘ Decompose` for `γ2 = (Q − 1) / 88`, FIPS 204 Algorithms 36
//! and 40, pinned against their definitions on every representative and
//! both hint values in `tests.rs`.

use crate::params::GAMMA2;

/// The `w1` coefficient of a standard representative `a` under hint `h`.
///
/// `a1` is PQClean's high-bits estimate `⌊(⌊(a + 127) / 128⌋ · 11275 +
/// 2^23) / 2^24⌋ ∈ [0, 44]`, exact except that 44 stands for the wrap
/// `r+ − r0 = Q − 1`, where Decompose yields `(0, r0 − 1)` with a negative
/// low part. Otherwise the low part is `a − a1 · 2γ2 ∈ (−γ2, γ2]`, so its
/// sign needs no reduction. UseHint then moves `a1` by one modulo 44 in the
/// direction of the low part's sign.
#[inline(always)]
pub const fn w1_coefficient(a: i64, hint: bool) -> i64 {
    let mut a1 = (a + 127) >> 7;
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    let mut positive = a - a1 * 2 * GAMMA2 > 0;
    if a1 == 44 {
        a1 = 0;
        positive = false;
    }
    if !hint {
        a1
    } else if positive {
        if a1 == 43 { 0 } else { a1 + 1 }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}
