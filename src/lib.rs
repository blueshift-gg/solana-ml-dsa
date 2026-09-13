#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, unsafe_code)]

mod codec;
mod ntt;
mod params;
mod poly;
mod reduce;
mod rounding;
#[cfg(test)]
mod tests;

/// ML-DSA-44 (FIPS 204) parameter set and its verification types.
pub mod ml_dsa_44;

/// Signature verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The context string exceeds 255 bytes (FIPS 204 Algorithm 3).
    ContextTooLong,
    /// An encoded value or output buffer has the wrong length.
    InvalidLength,
    /// A prepared coefficient is not a canonical representative modulo Q.
    InvalidEncoding,
    /// Prepared storage must be aligned to four bytes.
    InvalidAlignment,
    /// A prepared row index must be in `0..4`.
    InvalidRow,
    /// The signature does not verify under the key, or is malformed.
    InvalidSignature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ContextTooLong => "context exceeds 255 bytes",
            Self::InvalidLength => "invalid byte length",
            Self::InvalidEncoding => "noncanonical prepared coefficient",
            Self::InvalidAlignment => "prepared storage must be four-byte aligned",
            Self::InvalidRow => "prepared row index must be in 0..4",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

impl core::error::Error for Error {}
