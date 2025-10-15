use crate::{
    sm2_recover_pubkey, sm2_verify_signature, AffinePoint, EncodedPoint, Hash, PublicKey, Sm2,
};
use alloy_primitives::PrimitiveSignature as Signature;
use elliptic_curve::sec1::ToEncodedPoint;
use signature::{hazmat::PrehashVerifier, Error, Result, Verifier};
use sm3::{digest::Digest, Sm3};

/// SM2 public key used for verifying signature are valid for a given
/// message.
///
/// ## Usage
///
/// The [`signature`] crate defines the following traits which are the
/// primary API for verifying:
///
/// - [`Verifier`]: verify a message against a provided key and signature
/// - [`PrehashVerifier`]: verify the low-level raw output bytes of a message digest
///
/// # `serde` support
///
/// When the `serde` feature of this crate is enabled, it provides support for
/// serializing and deserializing ECDSA signatures using the `Serialize` and
/// `Deserialize` traits.
///
/// The serialization leverages the encoding used by the [`PublicKey`] type,
/// which is a binary-oriented ASN.1 DER encoding.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Signer's public key.
    public_key: PublicKey,
}

impl VerifyingKey {
    /// Initialize [`VerifyingKey`] from a signer's public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Initialize [`VerifyingKey`] from a SEC1-SEC1-encoded public key.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let public_key = PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::new())?;
        Ok(Self::new(public_key))
    }

    /// Initialize [`VerifyingKey`] from an affine point.
    ///
    /// Returns an [`Error`] if the given affine point is the additive identity
    /// (a.k.a point at infinity).
    pub fn from_affine(affine: AffinePoint) -> Result<Self> {
        let public_key = PublicKey::from_affine(affine).map_err(|_| Error::new())?;
        Ok(Self::new(public_key))
    }

    /// Borrow the inner [`AffinePoint`] for this public key.
    pub fn as_affine(&self) -> &AffinePoint {
        self.public_key.as_affine()
    }

    /// Convert this [`VerifyingKey`] into the
    /// `Elliptic-Curve-Point-to-Octet-String` encoding described in
    /// SEC 1: Elliptic Curve Cryptography (Version 2.0) section 2.3.3
    /// (page 10).
    ///
    /// <http://www.secg.org/sec1-v2.pdf>
    pub fn to_sec1_bytes(&self) -> Box<[u8]> {
        self.public_key.to_sec1_bytes()
    }

    /// Compute message hash `e` according to [draft-shen-sm2-ecdsa § 5.2.1]
    ///
    /// [draft-shen-sm2-ecdsa § 5.2.1]: https://datatracker.ietf.org/doc/html/draft-shen-sm2-ecdsa-02#section-5.2.1
    pub(crate) fn hash_msg(&self, msg: &[u8]) -> Hash {
        Sm3::new().chain_update(msg).finalize()
    }

    /// Recover a [`VerifyingKey`] from the given `prehash` of a message, the
    /// signature over that prehashed message, and a [`RecoveryId`]. Compared to
    /// `recover_from_prehash`, this function skips verification with the
    /// recovered key.
    pub fn recover_from_prehash(prehash: &[u8], signature: &Signature) -> Result<Self> {
        if signature.as_bytes().len() != 65 || prehash.len() != 32 {
            return Err(Error::new());
        }
        unsafe {
            let mut sig = signature.as_bytes();
            if sig[64] >= 27 {
                sig[64] = sig[64] - 27
            }
            let mut pubkey = [0u8; 65];
            pubkey[0] = 4;
            let result =
                sm2_recover_pubkey(pubkey[1..].as_mut_ptr(), prehash.as_ptr(), sig.as_ptr());
            if result == 0 {
                Self::from_sec1_bytes(&pubkey)
                    .map(|vk| vk.verify_prehash(prehash, signature).map(|_| Ok(vk))?)?
            } else {
                Err(Error::new())
            }
        }
    }
}

//
// `*Verifier` triat impls.
//

impl PrehashVerifier<Signature> for VerifyingKey {
    fn verify_prehash(&self, prehash: &[u8], signature: &Signature) -> Result<()> {
        unsafe {
            let pubkey = self.to_encoded_point(false).to_bytes();
            let sig = signature.as_bytes();
            let result =
                sm2_verify_signature(pubkey[1..].as_ptr(), prehash.as_ptr(), sig[..64].as_ptr());
            if result == 0 {
                Ok(())
            } else {
                Err(Error::new())
            }
        }
    }
}

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<()> {
        let hash = self.hash_msg(msg);
        self.verify_prehash(&hash, signature)
    }
}

//
// Other trait impls
//

impl AsRef<AffinePoint> for VerifyingKey {
    fn as_ref(&self) -> &AffinePoint {
        self.as_affine()
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(verifying_key: VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl From<&VerifyingKey> for PublicKey {
    fn from(verifying_key: &VerifyingKey) -> PublicKey {
        verifying_key.public_key
    }
}

impl ToEncodedPoint<Sm2> for VerifyingKey {
    fn to_encoded_point(&self, compress: bool) -> EncodedPoint {
        self.as_affine().to_encoded_point(compress)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloy_primitives::{hex, PrimitiveSignature as Signature};

    #[test]
    fn test_recover_pubkey() {
        let sig: Signature = "92a56743436e2ad0b4979e14137527d2728f983a8e6e2e0a60aa7df164c6ae61bc70e60fd62fc9eb77cd313cb2709fee1f0e94962dbf6c8a5f39e79908c5c67900".parse().unwrap();
        let hash = hex::decode_to_array::<_, 32>(
            "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268",
        )
        .unwrap();
        let result = VerifyingKey::recover_from_prehash(&hash, &sig);
        let _ = result.unwrap();
    }
}
