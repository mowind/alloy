use alloy_primitives::hex;
use k256::ecdsa;
use thiserror::Error;

/// Error thrown by [`SmSigner`](crate::SmSigner).
#[derive(Debug, Error)]
pub enum SmSignerError {
    /// [`ecdsa`] error.
    #[error(transparent)]
    EcdsaError(#[from] ecdsa::Error),
    /// [`hex`](mod@hex) error.
    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
    /// [`std::io`] error.
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// [`eth_keystore`] error.
    #[cfg(feature = "keystore")]
    #[error(transparent)]
    EthKeystoreError(#[from] eth_keystore::KeystoreError),
}
