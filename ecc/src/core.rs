//! # Primitive Cryptography Types

use std::fmt::Display;
use std::str::FromStr;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
pub use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

// use crate::sign::Algorithm;

/// Prefix bytes (tag) to indicate a full public key.
pub const TAG_PUBKEY_FULL: u8 = 0x04;

/// Prefix bytes to indicate Ed25519 multibase encoding.
pub const ED25519_CODEC: [u8; 2] = [0xed, 0x01];

/// Prefix bytes to indicate X25519 multibase encoding.
pub const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// Alias for multi-base encoded string.
pub type MultiKey = String;

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    #[serde(rename = "OKP")]
    Okp,

    /// Elliptic curve key pair
    #[serde(rename = "EC")]
    Ec,

    /// Octet string
    #[serde(rename = "oct")]
    Oct,
}

/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum Curve {
    /// Ed25519 signature (DSA) key pairs.
    #[default]
    Ed25519,

    /// X25519 function (encryption) key pairs.
    X25519,

    /// secp256k1 curve.
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,

    /// secp256r1 curve.
    P256,
}

impl Curve {
    /// Generate a new key for the given key type.
    pub fn generate(&self) -> Vec<u8> {
        match self {
            Self::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
                signing_key.as_bytes().to_vec()
            }
            Self::X25519 => {
                let secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                secret_key.to_bytes().to_vec()
            }
            Self::Es256K => {
                let (secret_key, _) = ecies::utils::generate_keypair();
                secret_key.serialize().to_vec()
            }
            Self::P256 => {
                let secret_key = p256::SecretKey::random(&mut OsRng);
                secret_key.to_bytes().to_vec()
            }
        }
    }
}

impl Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::X25519 => write!(f, "X25519"),
            Self::Es256K => write!(f, "ES256K"),
            Self::P256 => write!(f, "P256"),
        }
    }
}

/// A secret key that can be used to compute a single `SharedSecret` or to
/// sign a payload.
///
/// The [`SecretKey::shared_secret`] method consumes and then wipes the secret
/// key. The compiler statically checks that the resulting secret is used at most
/// once.
///
/// With no serialization methods, the [`SecretKey`] can only be generated in a
/// usable form from a new instance.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop, Deserialize, Serialize)]
pub struct SecretKey([u8; SECRET_KEY_LENGTH]);

impl SecretKey {
    /// Return the shared secret as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Return the shared secret as a byte array.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }

    /// Derive a shared secret from the secret key and the sender's public key
    /// to produce a [`SecretKey`].
    ///
    /// # Errors
    /// LATER: document errors
    pub fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
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

impl From<[u8; SECRET_KEY_LENGTH]> for SecretKey {
    fn from(val: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self(val)
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(val: &[u8]) -> Result<Self> {
        if val.len() != SECRET_KEY_LENGTH {
            return Err(anyhow!("invalid secret key length"));
        }

        let mut buf = [0; SECRET_KEY_LENGTH];
        buf.copy_from_slice(&val[0..SECRET_KEY_LENGTH]);
        Ok(Self(buf))
    }
}

impl TryFrom<Vec<u8>> for SecretKey {
    type Error = anyhow::Error;

    fn try_from(val: Vec<u8>) -> Result<Self> {
        Self::try_from(val.as_slice())
    }
}

impl FromStr for SecretKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = Base64UrlUnpadded::decode_vec(s)?;
        let bytes: [u8; SECRET_KEY_LENGTH] =
            decoded.try_into().map_err(|_| anyhow!("invalid key"))?;
        Ok(Self::from(bytes))
    }
}

impl TryFrom<&SecretKey> for ecies::SecretKey {
    type Error = anyhow::Error;

    fn try_from(key: &SecretKey) -> Result<Self, Self::Error> {
        Self::parse(&key.0).map_err(|e| anyhow!("issue parsing secret key: {e}"))
    }
}

impl TryFrom<&SecretKey> for ecdsa::SigningKey<k256::Secp256k1> {
    type Error = anyhow::Error;

    fn try_from(key: &SecretKey) -> Result<Self, Self::Error> {
        Self::from_slice(&key.0).map_err(|e| anyhow!("issue parsing secret key: {e}"))
    }
}

impl TryFrom<&SecretKey> for ed25519_dalek::SigningKey {
    type Error = anyhow::Error;

    fn try_from(key: &SecretKey) -> Result<Self, Self::Error> {
        Ok(Self::from_bytes(&key.0))
    }
}

impl TryFrom<&SecretKey> for x25519_dalek::StaticSecret {
    type Error = anyhow::Error;

    fn try_from(key: &SecretKey) -> Result<Self, Self::Error> {
        Ok(Self::from(key.0))
    }
}

/// A shared secret key that can be used to encrypt and decrypt messages.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret([u8; SECRET_KEY_LENGTH]);

impl SharedSecret {
    /// Return the shared secret as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        &self.0
    }

    /// Return the shared secret as a byte array.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.0
    }
}

/// The public key of the key pair used in encryption.
#[derive(Clone, Copy, Debug)]
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
    pub fn from_slice(val: &[u8]) -> Result<Self> {
        Self::try_from(val)
    }

    /// Provide an empty public key.
    #[must_use]
    pub const fn empty() -> Self {
        Self { x: [0; 32], y: None }
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

impl From<ed25519_dalek::VerifyingKey> for PublicKey {
    fn from(val: ed25519_dalek::VerifyingKey) -> Self {
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

    fn try_from(val: &[u8]) -> Result<Self> {
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

    fn try_from(val: Vec<u8>) -> Result<Self> {
        Self::try_from(val.as_slice())
    }
}

impl TryFrom<(&[u8], &[u8])> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(val: (&[u8], &[u8])) -> Result<Self> {
        if val.0.len() != 32 || val.1.len() != 32 {
            return Err(anyhow!("invalid public key length"));
        }

        let mut x = [0; 32];
        let mut y = [0; 32];
        x.copy_from_slice(val.0);
        y.copy_from_slice(val.1);
        Ok(Self { x, y: Some(y) })
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

    fn try_from(val: PublicKey) -> Result<Self> {
        let key: [u8; 65] =
            val.to_vec().try_into().map_err(|_| anyhow!("issue converting public key to array"))?;
        Self::parse(&key).map_err(|e| anyhow!("issue parsing public key: {e}"))
    }
}

impl TryFrom<PublicKey> for ecdsa::VerifyingKey<k256::Secp256k1> {
    type Error = anyhow::Error;

    fn try_from(val: PublicKey) -> Result<Self> {
        let y = val.y.ok_or_else(|| anyhow!("'y' is invalid"))?;
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut val.x.to_vec());
        sec1.append(&mut y.to_vec());
        Self::from_sec1_bytes(&sec1).map_err(|e| anyhow!("unable to build verifying key: {e}"))
    }
}

impl TryFrom<PublicKey> for ed25519_dalek::VerifyingKey {
    type Error = anyhow::Error;

    fn try_from(val: PublicKey) -> Result<Self> {
        Self::from_bytes(&val.x).map_err(|e| anyhow!("unable to build verifying key: {e}"))
    }
}

/// Derive an `X25519` public key from an `Ed25519` public key.
///
/// # Errors
/// If the provided input is the wrong length or cannot be converted to an
/// Ed25519 verifying key an error will be returned.
pub fn x_derive_x25519_public(ed25519_pubkey: &PublicKey) -> Result<PublicKey> {
    let verifier_bytes: [u8; 32] = ed25519_pubkey.x;
    let verifier = ed25519_dalek::VerifyingKey::from_bytes(&verifier_bytes)?;
    let x25519_bytes = verifier.to_montgomery().to_bytes();
    PublicKey::from_slice(&x25519_bytes)
}

/// Derive an `X25519` shared secret from a static secret and an `Ed25519`
/// public key.
///
/// # Errors
/// If the provided input is the wrong length or cannot be inferred as an
/// Ed25519 signing key an error will be returned.
pub fn x_derive_x25519_secret(
    secret: &[u8; SECRET_KEY_LENGTH], ed25519_pubkey: &PublicKey,
) -> Result<SharedSecret> {
    // EdDSA signing key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);

    // derive X25519 secret for Diffie-Hellman from Ed25519 secret
    let hash = sha2::Sha512::digest(signing_key.as_bytes());
    let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
    hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
    let secret_key = x25519_dalek::StaticSecret::from(hashed);

    let secret_key = SecretKey::from(secret_key.to_bytes());
    secret_key.shared_secret(*ed25519_pubkey)
}

/// Derive an `X25519` public key from a static secret that is covertable to an
/// `Ed25519` signing key.
#[must_use]
pub fn x_derive_x25519_public_from_secret(secret: &[u8; SECRET_KEY_LENGTH]) -> PublicKey {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    let derived_public =
        x25519_dalek::PublicKey::from(signing_key.verifying_key().to_montgomery().to_bytes());
    PublicKey::from(derived_public)
}
