//! # Signing and Encryption Utilities
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.

mod encryption;
mod key;
mod signing;

use std::fmt::Display;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
pub use encryption::{AlgAlgorithm, EncAlgorithm, Encrypted, EncryptedCek, Receiver};
pub use key::{
    ED25519_CODEC, MultiKey, PublicKey, SecretKey, SharedSecret, TAG_PUBKEY_FULL, X25519_CODEC,
    derive_x25519_public, derive_x25519_public_from_secret, derive_x25519_secret,
};
pub use signing::{Algorithm, Signer};

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
