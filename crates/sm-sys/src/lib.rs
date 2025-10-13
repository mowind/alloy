#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(missing_docs)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub use elliptic_curve::{self, bigint::U256};
pub use sm2::{AffinePoint, ProjectivePoint, Scalar};

pub mod dsa;

/// Order of SM2's elliptic curve group (i.e. scalar modulus) serialized as
/// hexadecimal.
const ORDER_HEX: &str = "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123";

type Hash = sm3::digest::Output<sm3::Sm3>;

/// SM2 elliptic curve.
pub type Sm2 = sm2::Sm2;

/// Compressed SEC1-encoded curve point.
pub type CompressedPoint = sm2::CompressedPoint;

/// SEC1 encoded point.
pub type EncodedPoint = sm2::EncodedPoint;

/// SM2 field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or
/// scalar).
pub type FieldBytes = sm2::FieldBytes;

/// Non-zero scalar field element.
pub type NonZeroScalar = sm2::NonZeroScalar;

/// SM2 public key: wrapper type for an elliptic curve point.
pub type PublicKey = sm2::PublicKey;

/// SM2 secret key: wrapper point for a secret scalar.
pub type SecretKey = sm2::SecretKey;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{hex, B512};
    use dsa::SigningKey;
    use elliptic_curve::sec1::ToEncodedPoint;
    use signature::{Signer, Verifier};

    #[test]
    fn test_generate() {
        unsafe {
            let mut privkey = [0u8, 32];
            let mut pubkey = [0u8, 64];
            let res = sm2_genKey(privkey.as_mut_ptr(), pubkey.as_mut_ptr());
            assert_eq!(res, 0);
        }
    }

    #[test]
    fn test_ffi_sign() {
        unsafe {
            let privkey = hex::decode_to_array::<_, 32>(
                "003993f2c614021fa2e1e76b69c7f6c927d6a6475da22ad69ad39e00e9ca8d30",
            )
            .unwrap();
            let hash = hex::decode_to_array::<_, 32>(
                "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268",
            )
            .unwrap();
            let mut sig = [0u8; 65];
            let result = sm2_sign(sig.as_mut_ptr(), hash.as_ptr(), privkey.as_ptr());
            assert_eq!(result, 0);
            println!("sig: {:?}", hex::encode(sig));

            //let sig1 = hex::decode_to_array::<_,64>("37003761b409390f90978337f2754080b06a6cde3af23d220ad290027406bae016a12f4f71e91fa6676a453ac1d4a91490baa735eee645527da753fb961e66dd").unwrap();
            let pubkey = hex::decode_to_array::<_, 64>("41c0bc030628a6cd4a23cef98b8e99c93e84c48fabbb5e314963229deaff3c6ba1e8b701732e5d50d6a7da8b07bb28b9cae89c49c9a16c955073eed356ad6759").unwrap();
            let r1 = sm2_verify_signature(pubkey.as_ptr(), hash.as_ptr(), sig[..64].as_ptr());
            assert_eq!(r1, 0);
        }
    }

    #[test]
    fn test_sign() {
        let array = hex::decode_to_array::<_, 32>(
            "003993f2c614021fa2e1e76b69c7f6c927d6a6475da22ad69ad39e00e9ca8d30",
        )
        .unwrap();
        let signing_key = SigningKey::from_slice(&array).unwrap();
        let sig = signing_key.try_sign(b"hello").unwrap();
        println!("signature: {}", sig);

        let pubkey =
            B512::from_slice(&signing_key.verifying_key().to_encoded_point(false).as_bytes()[1..]);
        println!("public key: {}", pubkey);

        let verifying_key = signing_key.verifying_key();
        let result = verifying_key.verify(b"hello", &sig);
        let _ = result.unwrap();
    }
}
