use super::VerifyingKey;

use crate::{sm2_sign, FieldBytes, NonZeroScalar, PublicKey, Scalar, SecretKey};
use core::fmt::{self, Debug};
use elliptic_curve::subtle::{Choice, ConstantTimeEq};
use signature::{
    hazmat::{PrehashSigner, RandomizedPrehashSigner},
    rand_core::CryptoRngCore,
    Error, KeypairRef, RandomizedSigner, Result, Signer,
};

use alloy_primitives::Signature;

/// SM2 secret key used for signing messages and producing signatures.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for signing:
///
/// - [`Signer`]: sign a message using this key
/// - [`PrehashSigner`]: sign the low-level raw output bytes of a message digest
#[derive(Clone)]
pub struct SigningKey {
    /// Secret key.
    secret_scalar: NonZeroScalar,

    /// Verifying key for this signing key.
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Create signing key from a signer's secret key.
    pub fn new(secret_key: &SecretKey) -> Result<Self> {
        Self::from_nonzero_scalar(secret_key.to_nonzero_scalar())
    }

    /// Parse signing key from big endian-encoded bytes.
    pub fn from_bytes(bytes: &FieldBytes) -> Result<Self> {
        Self::from_slice(bytes)
    }

    /// Parse signing key from big endian-encoded byte slice containing a secret
    /// scalar value.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let secret_scalar = NonZeroScalar::try_from(slice).map_err(|_| Error::new())?;
        Self::from_nonzero_scalar(secret_scalar)
    }

    /// Create a signing key from a non-zero scalar.
    pub fn from_nonzero_scalar(secret_scalar: NonZeroScalar) -> Result<Self> {
        let public_key = PublicKey::from_secret_scalar(&secret_scalar);
        let verifying_key = VerifyingKey::new(public_key);
        Ok(Self { secret_scalar, verifying_key })
    }

    /// Serialize as bytes.
    pub fn to_bytes(&self) -> FieldBytes {
        self.secret_scalar.to_bytes()
    }

    /// Borrow the secret [`NonZeroScalar`] value for this key.
    ///
    /// # ⚠️ Warning
    ///
    /// This value is key material.
    ///
    /// Please treat it with the care it deserves!
    pub fn as_nonzero_scalar(&self) -> &NonZeroScalar {
        &self.secret_scalar
    }

    /// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`].
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

//
// `*Signer` trait impls.
//

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> Result<Signature> {
        sign_prehash_ffi(&self.secret_scalar, prehash)
    }
}

impl RandomizedPrehashSigner<Signature> for SigningKey {
    fn sign_prehash_with_rng(
        &self,
        _rng: &mut impl CryptoRngCore,
        prehash: &[u8],
    ) -> Result<Signature> {
        sign_prehash_ffi(&self.secret_scalar, prehash)
    }
}

impl RandomizedSigner<Signature> for SigningKey {
    fn try_sign_with_rng(&self, rng: &mut impl CryptoRngCore, msg: &[u8]) -> Result<Signature> {
        let hash = self.verifying_key.hash_msg(msg);
        self.sign_prehash_with_rng(rng, &hash)
    }
}

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature> {
        let hash = self.verifying_key.hash_msg(msg);
        self.sign_prehash(&hash)
    }
}

//
// Other trait impls
//

impl AsRef<VerifyingKey> for SigningKey {
    fn as_ref(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl ConstantTimeEq for SigningKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secret_scalar.ct_eq(&other.secret_scalar)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("verifying_key", &self.verifying_key)
            .finish_non_exhaustive()
    }
}

/// Constant-time comparison
impl Eq for SigningKey {}
impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.ct_eq(other).into()
    }
}

impl KeypairRef for SigningKey {
    type VerifyingKey = VerifyingKey;
}

// Compute a signature.
pub(crate) fn sign_prehash_ffi(secret_scalar: &Scalar, prehash: &[u8]) -> Result<Signature> {
    unsafe {
        let mut sig = [0u8; 65];
        let privkey = secret_scalar.to_bytes();
        let result = sm2_sign(sig.as_mut_ptr(), prehash.as_ptr(), privkey.as_ptr());
        if result == 0 {
            Signature::from_raw_array(&sig).map_err(|_| Error::new())
        } else {
            Err(Error::new())
        }
    }
}
