#[allow(missing_docs)]
mod error;
pub use error::SmSignerError;

mod signer;

pub use signer::{
    public_key_to_address, raw_public_key_to_address, secret_key_to_address, SmSigner,
};
pub use sm_sys::{
    dsa::{Signature, SigningKey, VerifyingKey},
    hash_msg as sm3_hash, FieldBytes, SecretKey, Sm2,
};

#[cfg(test)]
mod tests {
    use super::*;
}
