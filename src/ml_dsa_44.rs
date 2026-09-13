//! ML-DSA-44 (FIPS 204): 1,312-byte public keys and 2,420-byte signatures.
//! Other parameter sets are not accepted by these types.
//! `TURBO = true` replaces SHAKE128/256 with TurboSHAKE128/256, domain `0x1f`.
//! That variant requires matching key generation and signing; it is not FIPS 204.

pub use crate::Error;
use crate::params::{
    BETA, CRHBYTES, CTILDEBYTES, GAMMA1, K, L, N, POLYT1_PACKEDBYTES, POLYVECH_PACKEDBYTES,
    POLYW1_PACKEDBYTES, POLYZ_PACKEDBYTES, SEEDBYTES, TRBYTES,
};
pub use crate::params::{CONTEXT_MAX_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::poly::Poly;
use crate::{codec, reduce};
use solana_shake::Shake;

/// `f = 2^64 / 256 mod Q`, the reference's final inverse-NTT multiplier
/// (`mont^2 / 256` in PQClean); the prepared tables carry `−f`.
pub(crate) const INVNTT_SCALE: i64 = 41978;
/// Plantard constant for scaling a table entry by `−f`.
const NEG_F_PLANTARD: u64 = reduce::plantard_constant(-INVNTT_SCALE);

/// `ρ ‖ t1`, 1312 bytes.
/// `TURBO` selects SHAKE (`false`, the default) or TurboSHAKE (`true`).
/// The encoding does not identify the choice; the protocol must bind it to the key.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VerifyingKey<const TURBO: bool = false>([u8; PUBLIC_KEY_LEN]);

/// `c̃ ‖ z ‖ h`, 2420 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signature([u8; SIGNATURE_LEN]);

/// What verification needs from a public key, computed once: `Â =
/// ExpandA(ρ)` and `NTT(t1 · 2^d)` scaled by `−f`, and `tr = H(pk, 64)`.
/// 20,544 bytes, 4-byte aligned, no padding; an account holds these bytes.
/// `TURBO` must match the key that produced the cache and is not encoded in it.
///
/// The scaling: the reference reduces each row product by Montgomery
/// (`× 2^-32`) and ends its inverse transform with `× f · 2^-32`; this
/// verifier reduces the row sum by Plantard (`× −2^-64`) and skips the
/// final pass. `−f · (−2^-64) = 2^-32 · f · 2^-32`, and the transform is
/// linear, so the row is the reference's `w` modulo Q.
///
/// Row `i` is stored coefficient-major, `rows[i][k] = (Â_i0[k], …, Â_i3[k],
/// t̂1_i[k])`, so a row's five operands at one coefficient are read
/// through one pointer.
#[repr(C)]
pub struct PreparedVerifyingKey<const TURBO: bool = false> {
    /// `−f · (Â_i0, Â_i1, Â_i2, Â_i3, NTT(t1_i · 2^d))[k]`, standard
    /// representatives.
    #[doc(hidden)]
    pub(crate) rows: [PreparedRow; K],
    tr: [u8; TRBYTES],
}

/// One prepared row: five operands at each of 256 coefficients.
pub type PreparedRow = [[u32; L + 1]; N];

const PREPARED_KEY_LEN: usize = core::mem::size_of::<PreparedVerifyingKey>();

impl<const TURBO: bool> PreparedVerifyingKey<TURBO> {
    /// Operands per coefficient: the four matrix columns and t1.
    pub const ROW: usize = L + 1;

    /// Decode an owned cache on a host, checking its coefficient representation.
    /// This does not authenticate its derivation from a public key.
    #[cfg(not(target_os = "solana"))]
    pub fn from_bytes(bytes: &[u8; PREPARED_KEY_LEN]) -> Result<Self, Error> {
        let mut out = Self::ZERO;
        for (value, bytes) in out
            .rows
            .iter_mut()
            .flatten()
            .flatten()
            .zip(bytes[..Self::PUBLIC_KEY_HASH_OFFSET].as_chunks::<4>().0)
        {
            *value = u32::from_le_bytes(*bytes);
            if *value >= crate::params::Q as u32 {
                return Err(Error::InvalidEncoding);
            }
        }
        out.tr
            .copy_from_slice(&bytes[Self::PUBLIC_KEY_HASH_OFFSET..]);
        Ok(out)
    }

    /// Copy and decode a prepared cache after checking its exact length.
    #[cfg(not(target_os = "solana"))]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes.try_into().map_err(|_| Error::InvalidLength)?)
    }

    /// Byte length of the prepared form, excluding any caller-owned account header.
    pub const BYTE_LEN: usize = PREPARED_KEY_LEN;

    /// The all-zero value to [`VerifyingKey::prepare_into`].
    pub const ZERO: Self = Self {
        rows: [[[0; L + 1]; N]; K],
        tr: [0; TRBYTES],
    };

    /// Prepares a public key by value. Hosts only: a 20 KB return value
    /// does not fit an SBPF frame; there, use a `static` with
    /// [`VerifyingKey::prepare_into`].
    #[cfg(not(target_os = "solana"))]
    const fn prepare(pk: &VerifyingKey<TURBO>) -> PreparedVerifyingKey<TURBO> {
        let mut out = Self::ZERO;
        Self::prepare_into(pk, &mut out);
        out
    }

    /// Byte length of one row of the prepared form.
    pub const ROW_BYTE_LEN: usize = core::mem::size_of::<PreparedRow>();

    /// Byte offset of the public-key hash (`tr`), after the prepared coefficient rows.
    pub const PUBLIC_KEY_HASH_OFFSET: usize = K * Self::ROW_BYTE_LEN;

    /// Prepares a public key in place (FIPS 204 `ExpandA`, `NTT(t1 · 2^d)`,
    /// `tr`), e.g. into an account borrowed with
    /// [`mut_from_bytes`](Self::mut_from_bytes).
    const fn prepare_into(pk: &VerifyingKey<TURBO>, out: &mut PreparedVerifyingKey<TURBO>) {
        let mut i = 0;
        while i < K {
            Self::prepare_row(pk, i, &mut out.rows[i]);
            i += 1;
        }
        out.tr = pk.public_key_hash();
    }

    /// Row `i` of the prepared form: `Â_i0, …, Â_i3` from `ExpandA(ρ)` and
    /// `NTT(t1_i · 2^d)`, scaled by `−f`. One polynomial lives in this
    /// frame, so an account can be filled a row at a time as it grows.
    const fn prepare_row(pk: &VerifyingKey<TURBO>, i: usize, row: &mut PreparedRow) {
        let (rho, t1_bytes) = pk.0.split_at(SEEDBYTES);
        let mut p = Poly::ZERO;
        let mut j = 0;
        while j < L {
            p.uniform::<TURBO>(rho, ((i << 8) + j) as u16);
            p.freeze_scaled_into(NEG_F_PLANTARD, row, j);
            j += 1;
        }
        let (_, rest) = t1_bytes.split_at(i * POLYT1_PACKEDBYTES);
        let (chunk, _) = rest.split_at(POLYT1_PACKEDBYTES);
        p.t1_unpack_shifted(chunk);
        p.ntt();
        p.freeze_scaled_into(NEG_F_PLANTARD, row, L);
    }

    /// Borrows one row from account data, for
    /// [`VerifyingKey::prepare_row_into`]. Returns an error if the length is not
    /// [`ROW_BYTE_LEN`](Self::ROW_BYTE_LEN) or the start is not 4-byte aligned.
    #[allow(unsafe_code)]
    pub fn borrow_row_mut(bytes: &mut [u8]) -> Result<&mut PreparedRow, Error> {
        if bytes.len() != Self::ROW_BYTE_LEN {
            return Err(Error::InvalidLength);
        }
        if !(bytes.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::InvalidAlignment);
        }
        // SAFETY: length and alignment checked; every bit pattern is a
        // valid `[u32; _]` array, and the borrow is exclusive.
        Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut PreparedRow) })
    }

    /// Borrows a prepared key from account data. Returns an error if the length is
    /// not [`BYTE_LEN`](Self::BYTE_LEN) or the start is not 4-byte aligned.
    ///
    /// This checks the memory layout only. The caller must ensure these
    /// bytes came from [`VerifyingKey::prepare_into`] with the same `TURBO`
    /// choice, and authenticate the account's ownership and initialization.
    #[allow(unsafe_code)]
    pub fn ref_from_bytes(bytes: &[u8]) -> Result<&PreparedVerifyingKey<TURBO>, Error> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(Error::InvalidLength);
        }
        if !(bytes.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::InvalidAlignment);
        }
        // SAFETY: length and alignment checked; every bit pattern is a
        // valid `PreparedVerifyingKey` (only `u32` and `u8` fields, no padding).
        Ok(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    /// Mutable form of [`ref_from_bytes`](Self::ref_from_bytes), for
    /// [`VerifyingKey::prepare_into`].
    #[allow(unsafe_code)]
    pub fn mut_from_bytes(bytes: &mut [u8]) -> Result<&mut PreparedVerifyingKey<TURBO>, Error> {
        if bytes.len() != Self::BYTE_LEN {
            return Err(Error::InvalidLength);
        }
        if !(bytes.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::InvalidAlignment);
        }
        // SAFETY: as in `ref_from_bytes`; the borrow is exclusive.
        Ok(unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) })
    }

    /// The prepared key as bytes, e.g. to write into an account.
    #[allow(unsafe_code)]
    pub fn as_bytes(&self) -> &[u8; PREPARED_KEY_LEN] {
        // SAFETY: `repr(C)` with no padding; every byte is initialised.
        unsafe { &*(self as *const Self as *const [u8; PREPARED_KEY_LEN]) }
    }

    /// Borrow the 64-byte public-key hash (`tr = H(pk, 64)` in FIPS 204).
    pub fn public_key_hash(&self) -> &[u8; TRBYTES] {
        &self.tr
    }
}

/// `w += ExpandA(ρ)_{nonce} ∘ z`, the matrix polynomial living only in this
/// frame.
#[inline(never)]
fn matrix_term<const TURBO: bool>(w: &mut Poly, rho: &[u8], nonce: u16, z: &Poly) {
    let mut a = Poly::ZERO;
    a.uniform::<TURBO>(rho, nonce);
    w.add_products(&a, z);
}

/// `w −= ĉ ∘ NTT(t1_i · 2^d)`, the `t1` polynomial living only in this frame.
#[inline(never)]
fn t1_term<const TURBO: bool>(w: &mut Poly, pk: &VerifyingKey<TURBO>, i: usize, c_hat: &Poly) {
    let start = SEEDBYTES + i * POLYT1_PACKEDBYTES;
    let mut t = Poly::ZERO;
    t.t1_unpack_shifted(&pk.0[start..start + POLYT1_PACKEDBYTES]);
    t.ntt();
    w.sub_products(c_hat, &t);
}

impl<const TURBO: bool> VerifyingKey<TURBO> {
    /// Verify a message with an empty FIPS 204 context.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify_with_context(message, &[], signature)
    }

    /// Verify a message with the algorithm's native context (at most 255 bytes).
    /// Expands the compact key during verification; use preparation for repeated checks.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        signature.verify_with_key(self, context, message)
    }

    /// Verify caller-formatted `M′` (FIPS 204 Algorithm 8).
    /// The caller is responsible for domain separation and context framing.
    pub fn verify_internal(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(&self.public_key_hash());
        s.absorb(message);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut mu = [0; CRHBYTES];
        s.squeeze(&mut mu);
        self.verify_mu(&mu, signature)
    }

    /// ExternalMu-ML-DSA verification. The caller must correctly bind `μ` to this key and message.
    pub fn verify_mu(&self, mu: &[u8; CRHBYTES], signature: &Signature) -> Result<(), Error> {
        signature.verify_mu_with_key(self, mu)
    }

    /// Prepare by value on a host. On Solana, use [`Self::prepare_into`].
    #[cfg(not(target_os = "solana"))]
    pub const fn prepare(&self) -> PreparedVerifyingKey<TURBO> {
        PreparedVerifyingKey::<TURBO>::prepare(self)
    }

    /// Expand into caller-owned storage without a large return value or heap allocation.
    pub const fn prepare_into(&self, out: &mut PreparedVerifyingKey<TURBO>) {
        PreparedVerifyingKey::<TURBO>::prepare_into(self, out);
    }

    /// Prepare one of four rows. An invalid index leaves the output unchanged.
    pub const fn prepare_row_into(&self, index: usize, out: &mut PreparedRow) -> Result<(), Error> {
        if index >= K {
            return Err(Error::InvalidRow);
        }
        PreparedVerifyingKey::<TURBO>::prepare_row(self, index, out);
        Ok(())
    }

    /// Compute the 64-byte public-key hash (`tr = H(pk, 64)`, FIPS 204 Algorithm 6 line 9).
    pub const fn public_key_hash(&self) -> [u8; TRBYTES] {
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(&self.0);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut tr = [0u8; TRBYTES];
        s.squeeze(&mut tr);
        tr
    }

    /// Encoded byte length.
    pub const BYTE_LEN: usize = PUBLIC_KEY_LEN;

    /// Copy a fixed-size encoding. This does not authenticate the key.
    pub const fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Self {
        Self(*bytes)
    }

    /// Copy an exactly sized encoding, rejecting any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_bytes(
            bytes.try_into().map_err(|_| Error::InvalidLength)?,
        ))
    }

    /// Borrow encoded bytes without copying. Verification checks cryptographic validity.
    #[allow(unsafe_code)]
    pub fn ref_from_bytes(bytes: &[u8]) -> Result<&Self, Error> {
        let bytes: &[u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        // SAFETY: `repr(transparent)` over the checked byte array, aligned to one byte.
        Ok(unsafe { &*(bytes as *const [u8; PUBLIC_KEY_LEN] as *const Self) })
    }

    /// Borrow the encoding without copying.
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// Copy the encoding into an owned byte array.
    pub const fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Consume the value and return its encoding.
    pub const fn into_bytes(self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }
}

impl<const TURBO: bool> PreparedVerifyingKey<TURBO> {
    /// Verify a message with an empty FIPS 204 context, using the cached key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify_with_context(message, &[], signature)
    }

    /// Verify with the algorithm's native context, using the cached key.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &Signature,
    ) -> Result<(), Error> {
        signature.verify(self, context, message)
    }

    /// Verify caller-formatted `M′`. The caller supplies all domain-separation framing.
    pub fn verify_internal(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        signature.verify_internal(self, message)
    }

    /// ExternalMu-ML-DSA verification; the caller correctly binds `μ` to the key and message.
    pub fn verify_mu(&self, mu: &[u8; CRHBYTES], signature: &Signature) -> Result<(), Error> {
        signature.verify_mu(self, mu)
    }

    /// Borrow a cached row without copying it. The index is in `0..4`.
    pub fn row(&self, index: usize) -> Option<&PreparedRow> {
        self.rows.get(index)
    }

    /// Copy the prepared storage encoding on a host; use [`Self::as_bytes`] on Solana.
    #[cfg(not(target_os = "solana"))]
    pub fn to_bytes(&self) -> [u8; PREPARED_KEY_LEN] {
        *self.as_bytes()
    }
}

impl<const TURBO: bool> TryFrom<&[u8]> for VerifyingKey<TURBO> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes)
    }
}

impl Signature {
    /// Encoded byte length.
    pub const BYTE_LEN: usize = SIGNATURE_LEN;

    /// Copy a fixed-size encoding. This does not authenticate the signature.
    pub const fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self(*bytes)
    }

    /// Copy an exactly sized encoding, rejecting any other length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_bytes(
            bytes.try_into().map_err(|_| Error::InvalidLength)?,
        ))
    }

    /// Borrow encoded bytes without copying. Verification checks cryptographic validity.
    #[allow(unsafe_code)]
    pub fn ref_from_bytes(bytes: &[u8]) -> Result<&Self, Error> {
        let bytes: &[u8; SIGNATURE_LEN] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        // SAFETY: `repr(transparent)` over the checked byte array, aligned to one byte.
        Ok(unsafe { &*(bytes as *const [u8; SIGNATURE_LEN] as *const Self) })
    }

    /// Borrow the encoding without copying.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    /// Copy the encoding into an owned byte array.
    pub const fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }

    /// Consume the value and return its encoding.
    pub const fn into_bytes(self) -> [u8; SIGNATURE_LEN] {
        self.0
    }

    /// FIPS 204 Algorithm 3 from the public key itself, with no prepared
    /// key: `ExpandA` runs during verification, one matrix polynomial at a
    /// time, so no frame holds more than one polynomial. About 1.3M CU on
    /// SBPF, of which the standard's 90 Keccak permutations (`ExpandA` and
    /// `tr`) are 890K. Sending both the key and signature requires a V1
    /// transaction; the caller must also budget for its accounts and message.
    fn verify_with_key<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        ctx: &[u8],
        msg: &[u8],
    ) -> Result<(), Error> {
        if ctx.len() > CONTEXT_MAX_LEN {
            return Err(Error::ContextTooLong);
        }
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(&pk.public_key_hash());
        s.absorb(&[0, ctx.len() as u8]);
        s.absorb(ctx);
        s.absorb(msg);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut mu = [0u8; CRHBYTES];
        s.squeeze(&mut mu);
        self.verify_mu_with_key(pk, &mu)
    }

    /// ExternalMu-ML-DSA from the public key itself; see
    /// [`verify_with_key`](Self::verify_with_key).
    #[inline(never)]
    fn verify_mu_with_key<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
    ) -> Result<(), Error> {
        let counts = codec::hint_counts(self.hints()).ok_or(Error::InvalidSignature)?;
        let mut z0 = Poly::ZERO;
        self.z_hat(0, &mut z0)?;
        self.raw_with_z1(pk, mu, &counts, &z0)
    }

    /// FIPS 204 Algorithm 3, `ML-DSA.Verify`: verifies `msg` under `ctx`,
    /// with `M′ = 0x00 ‖ |ctx| ‖ ctx ‖ msg`.
    fn verify<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        ctx: &[u8],
        msg: &[u8],
    ) -> Result<(), Error> {
        if ctx.len() > CONTEXT_MAX_LEN {
            return Err(Error::ContextTooLong);
        }
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(&key.tr);
        s.absorb(&[0, ctx.len() as u8]);
        s.absorb(ctx);
        s.absorb(msg);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut mu = [0u8; CRHBYTES];
        s.squeeze(&mut mu);
        self.verify_mu(key, &mu)
    }

    /// FIPS 204 Algorithm 8, `ML-DSA.Verify_internal`: verifies the
    /// caller-formatted `M′`.
    fn verify_internal<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        m_prime: &[u8],
    ) -> Result<(), Error> {
        let mut s = Shake::<256, TURBO>::new();
        s.absorb(&key.tr);
        s.absorb(m_prime);
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut mu = [0u8; CRHBYTES];
        s.squeeze(&mut mu);
        self.verify_mu(key, &mu)
    }

    /// ExternalMu-ML-DSA: verifies against a precomputed
    /// `μ = H(tr ‖ M′, 64)`.
    #[inline(never)]
    fn verify_mu<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
    ) -> Result<(), Error> {
        let counts = codec::hint_counts(self.hints()).ok_or(Error::InvalidSignature)?;
        let mut z0 = Poly::ZERO;
        self.z_hat(0, &mut z0)?;
        self.with_z1(key, mu, &counts, &z0)
    }

    fn c_tilde(&self) -> &[u8; CTILDEBYTES] {
        self.0[..CTILDEBYTES].try_into().unwrap()
    }

    fn hints(&self) -> &[u8; POLYVECH_PACKEDBYTES] {
        self.0[SIGNATURE_LEN - POLYVECH_PACKEDBYTES..]
            .try_into()
            .unwrap()
    }

    /// `NTT(z_j)` into `out`, after the norm check `‖z_j‖∞ < γ1 − β`.
    fn z_hat(&self, j: usize, out: &mut Poly) -> Result<(), Error> {
        let start = CTILDEBYTES + j * POLYZ_PACKEDBYTES;
        if out.z_unpack(&self.0[start..start + POLYZ_PACKEDBYTES], GAMMA1 - BETA) {
            return Err(Error::InvalidSignature);
        }
        out.ntt();
        Ok(())
    }

    // One polynomial per SBPF frame: `verify_mu*` owns `NTT(z_0)`,
    // each `with_z*` level owns `NTT(z_j)`,
    // `rows` owns `NTT(c)`, each `row` owns its `w`. `#[inline(never)]`
    // keeps the frames apart under LTO.

    #[inline(never)]
    fn with_z1<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
    ) -> Result<(), Error> {
        let mut z1 = Poly::ZERO;
        self.z_hat(1, &mut z1)?;
        self.with_z2(key, mu, counts, z0, &z1)
    }

    #[inline(never)]
    fn with_z2<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
        z1: &Poly,
    ) -> Result<(), Error> {
        let mut z2 = Poly::ZERO;
        self.z_hat(2, &mut z2)?;
        self.with_z3(key, mu, counts, z0, z1, &z2)
    }

    #[inline(never)]
    fn with_z3<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
        z1: &Poly,
        z2: &Poly,
    ) -> Result<(), Error> {
        let mut z3 = Poly::ZERO;
        self.z_hat(3, &mut z3)?;
        self.rows(key, mu, counts, [z0, z1, z2, &z3])
    }

    /// Row `i` of `w1 = UseHint(h, INTT(Â∘ẑ − ĉ∘t̂1))`, absorbed into the
    /// running `H(μ ‖ w1Encode(w1))`.
    #[inline(never)]
    fn row<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        counts: &[u8; K],
        z: [&Poly; L],
        c_hat: &Poly,
        i: usize,
        s: &mut Shake<256, TURBO>,
    ) {
        let mut w = Poly::ZERO;
        w.row_lazy(&key.rows[i], z, c_hat);
        w.invntt();
        let mut packed = [0u8; POLYW1_PACKEDBYTES];
        w.finish_row(&codec::hint_bitmap(self.hints(), counts, i), &mut packed);
        s.absorb(&packed);
    }

    #[inline(never)]
    fn raw_with_z1<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
    ) -> Result<(), Error> {
        let mut z1 = Poly::ZERO;
        self.z_hat(1, &mut z1)?;
        self.raw_with_z2(pk, mu, counts, z0, &z1)
    }

    #[inline(never)]
    fn raw_with_z2<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
        z1: &Poly,
    ) -> Result<(), Error> {
        let mut z2 = Poly::ZERO;
        self.z_hat(2, &mut z2)?;
        self.raw_with_z3(pk, mu, counts, z0, z1, &z2)
    }

    #[inline(never)]
    fn raw_with_z3<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z0: &Poly,
        z1: &Poly,
        z2: &Poly,
    ) -> Result<(), Error> {
        let mut z3 = Poly::ZERO;
        self.z_hat(3, &mut z3)?;
        self.raw_rows(pk, mu, counts, [z0, z1, z2, &z3])
    }

    /// `c̃ = H(μ ‖ w1Encode(w1))` row by row, expanding `Â` as it goes.
    #[inline(never)]
    fn raw_rows<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z: [&Poly; L],
    ) -> Result<(), Error> {
        let mut c_hat = Poly::ZERO;
        c_hat.challenge::<TURBO>(self.c_tilde());
        c_hat.ntt();

        let mut s = Shake::<256, TURBO>::new();
        s.absorb(mu);
        for i in 0..K {
            self.raw_row(pk, counts, z, &c_hat, i, &mut s);
        }
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut c2 = [0u8; CTILDEBYTES];
        s.squeeze(&mut c2);
        if c2 == *self.c_tilde() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Row `i` from the public key: `Σ_j ExpandA(ρ)_ij ∘ ẑ_j − ĉ ∘ NTT(t1_i ·
    /// 2^d)`, each term computed in its own frame, then the same reduction,
    /// inverse transform and tail as the prepared-key row.
    #[inline(never)]
    fn raw_row<const TURBO: bool>(
        &self,
        pk: &VerifyingKey<TURBO>,
        counts: &[u8; K],
        z: [&Poly; L],
        c_hat: &Poly,
        i: usize,
        s: &mut Shake<256, TURBO>,
    ) {
        let (rho, _) = pk.0.split_at(SEEDBYTES);
        let mut w = Poly::ZERO;
        for (j, zj) in z.iter().enumerate() {
            matrix_term::<TURBO>(&mut w, rho, ((i << 8) + j) as u16, zj);
        }
        t1_term(&mut w, pk, i, c_hat);
        w.reduce_row(NEG_F_PLANTARD);
        w.invntt();
        let mut packed = [0u8; POLYW1_PACKEDBYTES];
        w.finish_row(&codec::hint_bitmap(self.hints(), counts, i), &mut packed);
        s.absorb(&packed);
    }

    /// `c̃ = H(μ ‖ w1Encode(w1))`, row by row.
    #[inline(never)]
    fn rows<const TURBO: bool>(
        &self,
        key: &PreparedVerifyingKey<TURBO>,
        mu: &[u8; CRHBYTES],
        counts: &[u8; K],
        z: [&Poly; L],
    ) -> Result<(), Error> {
        let mut c_hat = Poly::ZERO;
        c_hat.challenge::<TURBO>(self.c_tilde());
        c_hat.ntt();

        let mut s = Shake::<256, TURBO>::new();
        s.absorb(mu);
        for i in 0..K {
            self.row(key, counts, z, &c_hat, i, &mut s);
        }
        let mut s = s.finalize_with_domain::<0x1f>();
        let mut c2 = [0u8; CTILDEBYTES];
        s.squeeze(&mut c2);
        if c2 == *self.c_tilde() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl<const TURBO: bool> AsRef<[u8]> for VerifyingKey<TURBO> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
#[cfg(not(target_os = "solana"))]
impl<const TURBO: bool> TryFrom<&[u8]> for PreparedVerifyingKey<TURBO> {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_slice(bytes)
    }
}

impl From<Signature> for [u8; SIGNATURE_LEN] {
    fn from(signature: Signature) -> Self {
        signature.into_bytes()
    }
}
