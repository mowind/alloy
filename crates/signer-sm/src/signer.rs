use super::SmSignerError;
use alloy_consensus::SignableTransaction;
use alloy_network::{impl_into_wallet, TxSigner, TxSignerSync};
use alloy_primitives::{hex, Address, ChainId, Signature, B256, B512};
use alloy_signer::{sign_transaction_with_chain_id, Result, Signer, SignerSync};
use alloy_sm_sys::{
    dsa::{signature::hazmat::PrehashSigner, SigningKey, VerifyingKey},
    hash_msg, FieldBytes, SecretKey as SmSecretKey,
};
use async_trait::async_trait;
use elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa;
use rand::{CryptoRng, Rng};
use std::str::FromStr;

use std::fmt;

#[cfg(feature = "keystore")]
use std::path::Path;

/// Converts an SM2 private key to its corresponding Ethereum Address.
#[inline]
fn secret_key_to_address(secret_key: &SigningKey) -> Address {
    public_key_to_address(secret_key.verifying_key())
}

/// Converts an SM2 public key to its corresponding Ethereum Address.
fn public_key_to_address(pubkey: &VerifyingKey) -> Address {
    let affine = pubkey.as_ref();
    let encoded = affine.to_encoded_point(false);
    raw_public_key_to_address(&encoded.as_bytes()[1..])
}

/// Convert a raw, uncompressed public key to its corresponding Ethereum address.
///
/// ### Warning
///
/// This method **does not** verify that the public key is valid. It is the
/// caller's responsibility to pass a valid public key. Passing an invalid
/// public key will produce an unspendable output.
///
/// # Panics
///
/// This function panics if the input is not **exactly** 64 bytes.
#[inline]
#[track_caller]
fn raw_public_key_to_address(pubkey: &[u8]) -> Address {
    assert_eq!(pubkey.len(), 64, "raw public key must be 64 bytes");
    let digest = hash_msg(pubkey);
    Address::from_slice(&digest[12..])
}

#[derive(Clone)]
pub struct SmSigner {
    /// The signer's key.
    pub(crate) signing_key: SigningKey,
    /// The signer's address.
    pub(crate) address: Address,
    /// The signer's chain ID (for EIP-155).
    pub(crate) chain_id: Option<ChainId>,
}

impl fmt::Debug for SmSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SmSigner")
            .field("chain_id", &self.chain_id)
            .field("pubkey", &hex::encode(self.public_key()))
            .field("address", &self.address())
            .finish()
    }
}

impl SmSigner {
    /// Creates an new [`SmSigner`] instance from a [`SigningKey`].
    ///
    /// This can also be used to create a [`SmSigner`] from a [`SecretKey`](SmSecretKey).
    /// See also the `From` implementations.
    #[inline]
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let address = secret_key_to_address(&signing_key);
        Self { signing_key, address, chain_id: None }
    }

    /// Creates a new [`SmSigner`] instance from a raw scalar serialized as a [`B256`] byte
    /// array.
    ///
    /// This is identical to [`from_field_bytes`](Self::from_field_bytes).
    #[inline]
    pub fn from_bytes(bytes: &B256) -> Result<Self, ecdsa::Error> {
        Self::from_field_bytes((&bytes.0).into())
    }

    /// Creates a new [`SmSigner`] instance from a raw scalar serialized as a [`FieldBytes`] byte
    /// array.
    #[inline]
    pub fn from_field_bytes(bytes: &FieldBytes) -> Result<Self, ecdsa::Error> {
        SigningKey::from_bytes(bytes).map(Self::from_signing_key)
    }

    /// Creates a new [`SmSigner`] instance from a raw scalar serialized as a byte slice.
    ///
    /// Byte slices shorter than the field size (32 bytes) are handled by zero padding the input.
    #[inline]
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ecdsa::Error> {
        SigningKey::from_slice(bytes).map(Self::from_signing_key)
    }

    /// Convenience function that return this signer's ethereum public key as a [`B512`] byte
    /// array.
    #[inline]
    pub fn public_key(&self) -> B512 {
        B512::from_slice(&self.signing_key.verifying_key().to_encoded_point(false).as_bytes()[1..])
    }

    /// Returns this signer's key.
    #[inline]
    pub const fn signing_key(&self) -> &SigningKey {
        return &self.signing_key;
    }

    /// Returns this signer's address.
    #[inline]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Returns this signer's chain ID.
    #[inline]
    pub const fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
}

#[cfg(feature = "keystore")]
impl SmSigner {
    /// Decrypt an encrypted JSON from the provided path to constrct a [`SmSigner`] instance
    #[inline]
    pub fn decrypt_keystore<P, S>(keypath: P, password: S) -> Result<Self, SmSignerError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let secret = eth_keystore::decrypt_key(keypath, password)?;
        Ok(Self::from_slice(&secret)?)
    }

    /// Creates a new encrypted JSON with the provided private key and password and stores it in the
    /// provided directory. Returns a tuple (LocalSigner, String) of the signer instance for the
    /// keystore with its random UUID. Accepts an optional name for the keystore file. If `None`,
    /// the keystore is stored as the stringified UUID.
    #[inline]
    pub fn encrypt_keystore<P, R, B, S>(
        keypath: P,
        rng: &mut R,
        pk: B,
        password: S,
        name: Option<&str>,
    ) -> Result<(Self, String), SmSignerError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        B: AsRef<[u8]>,
        S: AsRef<[u8]>,
    {
        let pk = pk.as_ref();
        let uuid = eth_keystore::encrypt_key(keypath, rng, pk, password, name)?;
        Ok((Self::from_slice(pk)?, uuid))
    }
}

impl PartialEq for SmSigner {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key.to_bytes().eq(&other.signing_key.to_bytes())
            && self.address == other.address
            && self.chain_id == other.chain_id
    }
}

impl From<SigningKey> for SmSigner {
    fn from(value: SigningKey) -> Self {
        Self::from_signing_key(value)
    }
}

impl From<SmSecretKey> for SmSigner {
    fn from(value: SmSecretKey) -> Self {
        Self::from_signing_key(SigningKey::new(&value).unwrap())
    }
}

impl From<&SmSecretKey> for SmSigner {
    fn from(value: &SmSecretKey) -> Self {
        Self::from_signing_key(SigningKey::new(&value).unwrap())
    }
}

impl FromStr for SmSigner {
    type Err = SmSignerError;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let array = hex::decode_to_array::<_, 32>(src)?;
        Ok(Self::from_slice(&array)?)
    }
}

#[cfg_attr(target_family="wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl Signer for SmSigner {
    #[inline]
    async fn sign_hash(&self, hash: &B256) -> Result<Signature> {
        self.sign_hash_sync(hash)
    }

    #[inline]
    fn address(&self) -> Address {
        self.address
    }

    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id()
    }

    #[inline]
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id
    }
}

impl SignerSync for SmSigner {
    #[inline]
    fn sign_hash_sync(&self, hash: &B256) -> Result<Signature> {
        Ok(self.signing_key.sign_prehash(hash.as_ref())?.into())
    }

    #[inline]
    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id()
    }
}

#[cfg_attr(target_family="wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl TxSigner<Signature> for SmSigner {
    fn address(&self) -> Address {
        self.address
    }

    #[doc(alias = "sign_tx")]
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy_signer::Result<Signature> {
        let hash = hash_msg(tx.encoded_for_signing().as_slice());
        sign_transaction_with_chain_id!(self, tx, self.sign_hash_sync(&hash))
    }
}

impl TxSignerSync<Signature> for SmSigner {
    fn address(&self) -> Address {
        self.address
    }

    #[doc(alias = "sign_tx_sync")]
    fn sign_transaction_sync(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> alloy_signer::Result<Signature> {
        let hash = hash_msg(tx.encoded_for_signing().as_slice());
        sign_transaction_with_chain_id!(self, tx, self.sign_hash_sync(&hash))
    }
}

impl_into_wallet!(SmSigner);

#[cfg(test)]
mod test {
    use super::*;
    use alloy_consensus::TxLegacy;
    use alloy_primitives::{address, U256};

    #[tokio::test]
    async fn signs_tx() {
        async fn sign_tx_test(tx: &mut TxLegacy, chain_id: Option<ChainId>) -> Result<Signature> {
            let mut before = tx.clone();
            let sig = sign_dyn_tx_test(tx, chain_id).await?;
            if let Some(chain_id) = chain_id {
                assert_eq!(tx.chain_id, Some(chain_id), "chain ID was not set");
                before.chain_id = Some(chain_id);
            }
            assert_eq!(*tx, before);
            Ok(sig)
        }

        async fn sign_dyn_tx_test(
            tx: &mut dyn SignableTransaction<Signature>,
            chain_id: Option<ChainId>,
        ) -> Result<Signature> {
            let mut signer: SmSigner =
                "003993f2c614021fa2e1e76b69c7f6c927d6a6475da22ad69ad39e00e9ca8d30".parse().unwrap();
            signer.set_chain_id(chain_id);

            let sig = signer.sign_transaction_sync(tx)?;
            let sighash = hash_msg(tx.encoded_for_signing().as_slice());
            assert_eq!(
                public_key_to_address(
                    &VerifyingKey::recover_from_prehash(sighash.as_slice(), &sig).unwrap()
                ),
                signer.address()
            );

            Ok(sig)
        }

        let mut tx = TxLegacy {
            to: address!("F0109fC8DF283027b6285cc889F5aA624EaC1F55").into(),
            value: U256::from(1_000_000_000),
            gas_limit: 2_000_000,
            nonce: 0,
            gas_price: 21_000_000_000,
            input: Default::default(),
            chain_id: None,
        };
        let _ = sign_tx_test(&mut tx, None).await.unwrap();
    }

    #[test]
    fn parse_pk() {
        let s = "003993f2c614021fa2e1e76b69c7f6c927d6a6475da22ad69ad39e00e9ca8d30";
        let _pk: SmSigner = s.parse().unwrap();
    }

    #[test]
    fn parse_short_key() {
        let s = "003993f2c614021fa2e1e76b69c7f6c927d6a6475da22ad69ad39e00e9ca8d3";
        assert!(s.len() < 64);
        let _pk = s.parse::<SmSigner>().unwrap_err();
    }
}
