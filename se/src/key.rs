//! # Types for keys

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::VerifyingKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::PUBLIC_KEY_LENGTH;

/// Prefix bytes (tag) to indicate a full public key.
pub const TAG_PUBKEY_FULL: u8 = 0x04;

/// Prefix bytes to indicate Ed25519 multibase encoding.
pub const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

/// Prefix bytes to indicate X25519 multibase encoding.
pub const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// Alias for multi-base encoded string.
pub type MultiKey = String;

/// A secret key that can be used to compute a single `SharedSecret` or to
/// sign a payload.
///
/// The [`SecretKey::shared_secret`] method consumes and then wipes the secret
/// key. The compiler statically checks that the resulting secret is used at most
/// once.
///
/// With no serialization methods, the [`SecretKey`] can only be generated in a
/// usable form from a new instance.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl From<[u8; 32]> for SecretKey {
    fn from(val: [u8; 32]) -> Self {
        Self(val)
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let decoded = Base64UrlUnpadded::decode_vec(val)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| anyhow!("invalid key"))?;
        Ok(Self::from(bytes))
    }
}

impl TryFrom<&String> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(val: &String) -> Result<Self, Self::Error> {
        Self::try_from(val.as_str())
    }
}

impl SecretKey {
    /// Derive a shared secret from the secret key and the sender's public key
    /// to produce a [`SecretKey`].
    ///
    /// # Errors
    /// LATER: document errors
    pub fn shared_secret(self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
        // x25519
        if sender_public.y.is_none() {
            let sender_public = x25519_dalek::PublicKey::from(sender_public.to_bytes());
            let secret = x25519_dalek::StaticSecret::from(self.0);
            let shared_secret = secret.diffie_hellman(&sender_public);
            return Ok(SharedSecret(shared_secret.to_bytes()));
        }

        // secp256k1
        let aes_key = ecies::utils::decapsulate(&sender_public.try_into()?, &self.try_into()?)
            .map_err(|e| anyhow!("issue decapsulating: {e}"))?;
        Ok(SharedSecret(aes_key))
    }
}

impl TryFrom<SecretKey> for ecies::SecretKey {
    type Error = anyhow::Error;

    fn try_from(val: SecretKey) -> anyhow::Result<Self> {
        Self::parse(&val.0).map_err(|e| anyhow!("issue parsing secret key: {e}"))
    }
}

/// A shared secret key that can be used to encrypt and decrypt messages.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Return the shared secret as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the shared secret as a byte array.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// The public key of the key pair used in encryption.
#[derive(Clone, Copy)]
pub struct PublicKey {
    x: [u8; 32],
    y: Option<[u8; 32]>,
}

impl PublicKey {
    /// Return the public key as an array of bytes.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let Some(y) = &self.y else {
            return self.x.to_vec();
        };

        let mut key = [0; 65];
        key[0] = TAG_PUBKEY_FULL;
        key[1..33].copy_from_slice(&self.x);
        key[33..65].copy_from_slice(y);
        key.to_vec()
    }

    /// Return the public key as a byte array.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.x
    }

    /// Parse a public key from a byte slice.
    ///
    /// # Errors
    /// LATER: document errors
    pub fn from_slice(val: &[u8]) -> anyhow::Result<Self> {
        Self::try_from(val)
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(val: [u8; 32]) -> Self {
        Self { x: val, y: None }
    }
}

impl From<[u8; 65]> for PublicKey {
    fn from(val: [u8; 65]) -> Self {
        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(&val[1..33]);
        y.copy_from_slice(&val[33..65]);
        Self { x, y: Some(y) }
    }
}

impl From<x25519_dalek::PublicKey> for PublicKey {
    fn from(val: x25519_dalek::PublicKey) -> Self {
        Self {
            x: val.to_bytes(),
            y: None,
        }
    }
}

impl From<ecies::PublicKey> for PublicKey {
    fn from(val: ecies::PublicKey) -> Self {
        let key: [u8; 65] = val.serialize();
        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(&key[1..33]);
        y.copy_from_slice(&key[33..65]);
        Self { x, y: Some(y) }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: &[u8]) -> anyhow::Result<Self> {
        if val.len() == 32 {
            let mut x = [0; 32];
            x.copy_from_slice(&val[0..32]);
            return Ok(Self { x, y: None });
        }

        if val.len() == 65 {
            let mut x = [0; 32];
            let mut y = [0; 32];
            x.copy_from_slice(&val[1..33]);
            y.copy_from_slice(&val[33..65]);
            return Ok(Self { x, y: Some(y) });
        }

        Err(anyhow!("invalid public key length"))
    }
}
impl TryFrom<Vec<u8>> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: Vec<u8>) -> anyhow::Result<Self> {
        Self::try_from(val.as_slice())
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let decoded = Base64UrlUnpadded::decode_vec(val)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| anyhow!("invalid key"))?;
        Ok(Self::from(bytes))
    }
}

impl TryFrom<&String> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: &String) -> Result<Self, Self::Error> {
        Self::try_from(val.as_str())
    }
}

impl From<PublicKey> for x25519_dalek::PublicKey {
    fn from(val: PublicKey) -> Self {
        Self::from(val.x)
    }
}

impl TryFrom<PublicKey> for ecies::PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: PublicKey) -> anyhow::Result<Self> {
        let key: [u8; 65] =
            val.to_vec().try_into().map_err(|_| anyhow!("issue converting public key to array"))?;
        Self::parse(&key).map_err(|e| anyhow!("issue parsing public key: {e}"))
    }
}

/// Derive a `X25519` public key from an `Ed25519` public key.
/// 
/// # Errors
/// If the provided input is the wrong length or cannot be converted to an
/// Ed25519 verifying key an error will be returned.
pub fn derive_x25519(ed25519_pubkey: &[u8]) -> anyhow::Result<Vec<u8>> {
    let verifier_bytes: [u8; PUBLIC_KEY_LENGTH] =
        ed25519_pubkey.try_into().map_err(|_| anyhow!("unable to coerce vec to slice"))?;
    let verifier = VerifyingKey::from_bytes(&verifier_bytes)?;
    let x25519_bytes = verifier.to_montgomery().to_bytes();
    Ok(x25519_bytes.to_vec())
}
