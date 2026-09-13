//! Polynomials in `Z_Q[x]/(x^256 + 1)`, the routines verification and key
//! preparation need, after PQClean `poly.c`. Every routine is a `const fn`
//! writing in place, so preparation runs at compile time and no polynomial
//! is returned by value into a frame. A polynomial is 2 KB.

use crate::ml_dsa_44::PreparedRow;
use crate::ntt;
use crate::params::{
    CTILDEBYTES, D, GAMMA1, N, POLYT1_PACKEDBYTES, POLYW1_PACKEDBYTES, POLYZ_PACKEDBYTES, Q, TAU,
};
use crate::reduce::{QINV64, caddq, plantard, reduce32};
use crate::rounding::w1_coefficient;
use solana_shake::Shake;

/// 256 coefficients.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Poly {
    /// Coefficients, in the range the producing routine documents.
    pub c: [i64; N],
}

/// `|a| ≥ bound` for `|a| < 2^62`, as one unsigned compare: `a + bound − 1`
/// lies in `[0, 2·bound − 1)` exactly when `−bound < a < bound`, and wraps
/// below zero otherwise. Pinned against `|a| ≥ bound` in `tests.rs`.
#[inline(always)]
pub(crate) const fn norm_at_least(a: i64, bound: i64) -> bool {
    debug_assert!(bound > 0 && bound < 1 << 62);
    (a + bound - 1) as u64 >= (2 * bound - 1) as u64
}

/// Byte `i` of a little-endian lane view, FIPS 202 byte order.
#[inline(always)]
const fn byte(lanes: &[u64], i: usize) -> u8 {
    (lanes[i / 8] >> (8 * (i % 8))) as u8
}

impl Poly {
    /// All coefficients zero.
    pub const ZERO: Poly = Poly { c: [0; N] };

    pub const fn ntt(&mut self) {
        ntt::ntt(&mut self.c);
    }

    pub const fn invntt(&mut self) {
        ntt::invntt(&mut self.c);
    }

    /// `RejNTTPoly` (FIPS 204 Algorithm 30): uniform coefficients in
    /// `[0, Q)` from `SHAKE128(seed ‖ nonce)`, 23-bit candidates from
    /// consecutive 3-byte groups of the output. A 168-byte block is 21 lanes,
    /// i.e. seven groups of three lanes holding eight candidates each; the
    /// candidates are cut out of the lanes with constant shifts, in the
    /// same order as the byte stream.
    pub const fn uniform<const TURBO: bool>(&mut self, seed: &[u8], nonce: u16) {
        const MASK: u64 = 0x7F_FFFF;
        let mut s = Shake::<128, TURBO>::new();
        s.absorb(seed);
        s.absorb(&nonce.to_le_bytes());
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut ctr = 0;
        loop {
            let lanes = s.rate_lanes();
            let mut g = 0;
            while g < Shake::<128, TURBO>::RATE / 24 {
                let l0 = lanes[3 * g];
                let l1 = lanes[3 * g + 1];
                let l2 = lanes[3 * g + 2];
                // Eight candidates, each tried in turn; `ctr < N` holds
                // whenever a candidate is stored because the loop returns
                // the moment `ctr` reaches N.
                macro_rules! take {
                    ($t:expr) => {{
                        let t = $t & MASK;
                        if t < Q as u64 {
                            self.c[ctr] = t as i64;
                            ctr += 1;
                            if ctr == N {
                                return;
                            }
                        }
                    }};
                }
                take!(l0);
                take!(l0 >> 24);
                take!((l0 >> 48) | (l1 << 16));
                take!(l1 >> 8);
                take!(l1 >> 32);
                take!((l1 >> 56) | (l2 << 8));
                take!(l2 >> 16);
                take!(l2 >> 40);
                g += 1;
            }
            s.permute();
        }
    }

    /// `SampleInBall` (Algorithm 29): τ coefficients in `{−1, 1}`, the
    /// rest zero, from `SHAKE256(c̃)`.
    pub const fn challenge<const TURBO: bool>(&mut self, seed: &[u8; CTILDEBYTES]) {
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(seed);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut signs = s.rate_lanes()[0];
        let mut pos = 8;
        *self = Poly::ZERO;
        let mut i = N - TAU;
        while i < N {
            let b = loop {
                if pos >= Shake::<256, TURBO>::RATE {
                    s.permute();
                    pos = 0;
                }
                let b = byte(s.rate_lanes(), pos) as usize;
                pos += 1;
                if b <= i {
                    break b;
                }
            };
            self.c[i] = self.c[b];
            self.c[b] = 1 - 2 * (signs & 1) as i64;
            signs >>= 1;
            i += 1;
        }
    }

    /// `t1 · 2^d` from 10-bit fields (the shift folded into the unpack).
    pub const fn t1_unpack_shifted(&mut self, a: &[u8]) {
        debug_assert!(a.len() == POLYT1_PACKEDBYTES);
        let mut i = 0;
        while i < N / 4 {
            let b = 5 * i;
            let f0 = (a[b] as u32 | (a[b + 1] as u32) << 8) & 0x3FF;
            let f1 = ((a[b + 1] as u32) >> 2 | (a[b + 2] as u32) << 6) & 0x3FF;
            let f2 = ((a[b + 2] as u32) >> 4 | (a[b + 3] as u32) << 4) & 0x3FF;
            let f3 = ((a[b + 3] as u32) >> 6 | (a[b + 4] as u32) << 2) & 0x3FF;
            self.c[4 * i] = (f0 as i64) << D;
            self.c[4 * i + 1] = (f1 as i64) << D;
            self.c[4 * i + 2] = (f2 as i64) << D;
            self.c[4 * i + 3] = (f3 as i64) << D;
            i += 1;
        }
    }

    /// `z` from 18-bit little-endian fields (four per nine bytes, at bit
    /// offsets 0, 18, 36, 54), mapped to `γ1 − field`; returns true if some
    /// coefficient has absolute value `≥ bound` (the reference's `chknorm`).
    pub const fn z_unpack(&mut self, a: &[u8], bound: i64) -> bool {
        debug_assert!(a.len() == POLYZ_PACKEDBYTES);
        let mut bad = false;
        let mut rest = a;
        let mut i = 0;
        while i < N / 4 {
            let Some((eight, tail)) = rest.split_first_chunk::<8>() else {
                break;
            };
            let lo = u64::from_le_bytes(*eight);
            let hi = tail[0] as u64;
            rest = tail.split_at(1).1;
            let c0 = GAMMA1 - (lo & 0x3FFFF) as i64;
            let c1 = GAMMA1 - ((lo >> 18) & 0x3FFFF) as i64;
            let c2 = GAMMA1 - ((lo >> 36) & 0x3FFFF) as i64;
            let c3 = GAMMA1 - (((lo >> 54) | (hi << 10)) & 0x3FFFF) as i64;
            self.c[4 * i] = c0;
            self.c[4 * i + 1] = c1;
            self.c[4 * i + 2] = c2;
            self.c[4 * i + 3] = c3;
            bad |= norm_at_least(c0, bound)
                || norm_at_least(c1, bound)
                || norm_at_least(c2, bound)
                || norm_at_least(c3, bound);
            i += 1;
        }
        bad
    }

    /// Standard representatives of `c[k] · m`, written into column `col`
    /// of a prepared row; `m_plantard` is [`plantard_constant`]`(m)`. A
    /// Plantard product rather than a `mod Q` of a 128-bit product: on
    /// SBPF a 128-bit division is a software routine, and registration
    /// does this 5,120 times. Inputs are the sampled matrix entries in
    /// `[0, Q)` or `NTT(t1 · 2^d)` outputs below `2^26`, within Plantard's
    /// `Q · 2^8`.
    pub const fn freeze_scaled_into(&self, m_plantard: u64, row: &mut PreparedRow, col: usize) {
        let mut k = 0;
        while k < N {
            row[k][col] = caddq(plantard(self.c[k], m_plantard)) as u32;
            k += 1;
        }
    }

    /// One row of `Â∘ẑ − ĉ∘t̂1` from its prepared row, reduced once:
    /// `self[k] ≡ (Σ_j row[k][j]·z[j][k] − c[k]·row[k][4]) · (−2^-64)`, in
    /// `[−(Q+1)/2, Q/2)`.
    ///
    /// The reference reduces each product; reduction is linear modulo Q, so
    /// reducing the sum is congruent up to a constant factor the prepared
    /// tables absorb. `a` and `t` are standard representatives, `z` and `c`
    /// transform outputs below 2^27, so the sum is below 2^53, within the
    /// reduction's `Q^2 · 2^16`.
    pub const fn row_lazy(&mut self, row: &PreparedRow, z: [&Poly; 4], c: &Poly) {
        #[inline(always)]
        const fn at(row: &PreparedRow, z: [&Poly; 4], c: &Poly, k: usize) -> i64 {
            let r = &row[k];
            let acc = r[0] as i64 * z[0].c[k]
                + r[1] as i64 * z[1].c[k]
                + r[2] as i64 * z[2].c[k]
                + r[3] as i64 * z[3].c[k]
                - c.c[k] * r[4] as i64;
            plantard(acc, QINV64)
        }
        let mut k = 0;
        while k < N {
            self.c[k] = at(row, z, c, k);
            self.c[k + 1] = at(row, z, c, k + 1);
            self.c[k + 2] = at(row, z, c, k + 2);
            self.c[k + 3] = at(row, z, c, k + 3);
            k += 4;
        }
    }

    /// `self[k] += a[k] · z[k]` in 64 bits, no reduction: one matrix
    /// polynomial's contribution to a row, for the raw-key path that expands
    /// `Â` one polynomial at a time. `a` is a sampled polynomial in `[0, Q)`,
    /// `z` a transform output below 2^26 in absolute value; four such terms
    /// and the `t1` term stay below 2^52.
    pub const fn add_products(&mut self, a: &Poly, z: &Poly) {
        let mut k = 0;
        while k < N {
            self.c[k] += a.c[k] * z.c[k];
            k += 1;
        }
    }

    /// `self[k] -= c[k] · t[k]` in 64 bits: the `ĉ ∘ t̂1` term of a row.
    pub const fn sub_products(&mut self, c: &Poly, t: &Poly) {
        let mut k = 0;
        while k < N {
            self.c[k] -= c.c[k] * t.c[k];
            k += 1;
        }
    }

    /// Reduce an accumulated row into the inverse transform's input, with
    /// the factor the prepared tables carry applied here instead:
    /// `self[k] ← plantard(plantard(self[k], QINV64), m_plantard)`, i.e.
    /// `self[k] · (−2^-64) · m`. With `m = −f` this is congruent to the
    /// prepared-key row (`PreparedVerifyingKey`), in `[−(Q+1)/2, Q/2)`.
    pub const fn reduce_row(&mut self, m_plantard: u64) {
        let mut k = 0;
        while k < N {
            self.c[k] = plantard(plantard(self.c[k], QINV64), m_plantard);
            k += 1;
        }
    }

    /// `w1Encode(UseHint(h, w))` for one row in one pass; `reduce32` then
    /// `caddq` make each inverse-transform output a standard representative
    /// first. The reference runs these as separate passes; the values are
    /// the same.
    pub const fn finish_row(&self, bits: &[u64; 4], out: &mut [u8; POLYW1_PACKEDBYTES]) {
        let mut i = 0;
        while i < N / 4 {
            let k = 4 * i;
            let word = bits[k / 64] >> (k % 64);
            let w0 = w1_coefficient(caddq(reduce32(self.c[k])), word & 1 == 1);
            let w1 = w1_coefficient(caddq(reduce32(self.c[k + 1])), (word >> 1) & 1 == 1);
            let w2 = w1_coefficient(caddq(reduce32(self.c[k + 2])), (word >> 2) & 1 == 1);
            let w3 = w1_coefficient(caddq(reduce32(self.c[k + 3])), (word >> 3) & 1 == 1);
            out[3 * i] = w0 as u8 | (w1 << 6) as u8;
            out[3 * i + 1] = (w1 >> 2) as u8 | (w2 << 4) as u8;
            out[3 * i + 2] = (w2 >> 4) as u8 | (w3 << 2) as u8;
            i += 1;
        }
    }
}
