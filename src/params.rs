//! ML-DSA-44 parameters, FIPS 204 Table 1 and the packed sizes of §7.2, as
//! PQClean `params.h` writes them. Each value is pinned by a defining
//! property in `tests.rs`, so a transcription slip fails a test rather than
//! a signature.

/// Seed length `ρ`, and `SHAKE128` seed of `ExpandA`.
pub const SEEDBYTES: usize = 32;
/// `μ`, the message representative, 512 bits.
pub const CRHBYTES: usize = 64;
/// `tr = H(pk)`, 512 bits.
pub const TRBYTES: usize = 64;
/// Ring degree.
pub const N: usize = 256;
/// `q = 2^23 − 2^13 + 1`.
pub const Q: i64 = 8_380_417;
/// Dropped bits of `t`.
pub const D: u32 = 13;
/// `ζ`, a 512th root of unity modulo `q`.
#[cfg(test)]
pub const ROOT_OF_UNITY: i64 = 1753;

/// Rows of `A`.
pub const K: usize = 4;
/// Columns of `A`.
pub const L: usize = 4;
/// Secret coefficient bound `η`.
#[cfg(test)]
pub const ETA: i64 = 2;
/// Nonzero coefficients of the challenge `c`.
pub const TAU: usize = 39;
/// `β = τ · η`.
pub const BETA: i64 = 78;
/// `γ1`, the `y` coefficient range.
pub const GAMMA1: i64 = 1 << 17;
/// `γ2`, the low-order rounding range.
pub const GAMMA2: i64 = (Q - 1) / 88;
/// Maximum number of hint ones.
pub const OMEGA: usize = 80;
/// `c̃`, `2λ` bits.
pub const CTILDEBYTES: usize = 32;

/// `t1` polynomial, 10 bits per coefficient.
pub const POLYT1_PACKEDBYTES: usize = 320;
/// `z` polynomial, 18 bits per coefficient.
pub const POLYZ_PACKEDBYTES: usize = 576;
/// `w1` polynomial, 6 bits per coefficient.
pub const POLYW1_PACKEDBYTES: usize = 192;
/// Hint vector: `ω` indices and `k` counts.
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;

/// `ρ ‖ t1`: 1312 bytes.
pub const PUBLIC_KEY_LEN: usize = SEEDBYTES + K * POLYT1_PACKEDBYTES;
/// `c̃ ‖ z ‖ h`: 2420 bytes.
pub const SIGNATURE_LEN: usize = CTILDEBYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;
/// FIPS 204 Algorithm 2/3: the context string is at most 255 bytes.
pub const CONTEXT_MAX_LEN: usize = 255;

/// `2^32 mod q`, centred (PQClean `reduce.h`).
#[cfg(test)]
pub const MONT: i64 = -4_186_625;
/// `q^-1 mod 2^32` (PQClean `reduce.h`).
pub const QINV: i64 = 58_728_449;
