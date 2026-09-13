//! Hint decoding (FIPS 204 Algorithm 21, as PQClean `unpack_sig`): the
//! checks that make the encoding unique, then a bitmap per polynomial, so
//! hints never become polynomials.

use crate::params::{K, OMEGA, POLYVECH_PACKEDBYTES};

/// Validates the 84-byte hint block and returns the cumulative index counts
/// per polynomial, or `None` for a malformed encoding.
pub fn hint_counts(hints: &[u8; POLYVECH_PACKEDBYTES]) -> Option<[u8; K]> {
    let mut counts = [0u8; K];
    let mut k = 0usize;
    for i in 0..K {
        let end = hints[OMEGA + i] as usize;
        if end < k || end > OMEGA {
            return None;
        }
        for j in k..end {
            // Coefficients are ordered for strong unforgeability.
            if j > k && hints[j] <= hints[j - 1] {
                return None;
            }
        }
        counts[i] = end as u8;
        k = end;
    }
    // Extra indices are zero for strong unforgeability.
    if hints[k..OMEGA].iter().any(|&b| b != 0) {
        return None;
    }
    Some(counts)
}

/// The hint bits of polynomial `i` as a 256-bit map.
pub fn hint_bitmap(hints: &[u8; POLYVECH_PACKEDBYTES], counts: &[u8; K], i: usize) -> [u64; 4] {
    let start = if i == 0 { 0 } else { counts[i - 1] as usize };
    let mut bits = [0u64; 4];
    for &idx in &hints[start..counts[i] as usize] {
        bits[idx as usize / 64] |= 1 << (idx % 64);
    }
    bits
}
