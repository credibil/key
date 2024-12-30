#![feature(let_chains)]

//! # Data Security for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.

pub mod cose;
pub mod jose;

use std::future::{Future, IntoFuture};

use serde::{Deserialize, Serialize};

pub use crate::jose::jwa::Algorithm;
pub use crate::jose::jwe::{PublicKey, SharedSecret};
pub use crate::jose::jwk::PublicKeyJwk;
pub use crate::jose::jws::Jws;
pub use crate::jose::jwt::Jwt;

/// The `SecOps` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait KeyOps: Send + Sync {
    /// Signer provides digital signing function.
    ///
    /// The `controller` parameter uniquely identifies the controller of the
    /// private key used in the signing operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be created.
    fn signer(&self, controller: &str) -> anyhow::Result<impl Signer>;

    /// Receiver provides data encryption/decryption functionality.
    ///
    /// The `controller` parameter uniquely identifies the controller of the
    /// private key used in the signing operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the encryptor cannot be created.
    fn receiver(&self, controller: &str) -> anyhow::Result<impl Receiver>;
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// The public key of the key pair used in signing. The possibility of key
    /// rotation mean this key should only be referenced at the point of signing.
    fn public_key(&self) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// Signature algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    ///
    /// Async and fallible because the client may need to access key information
    /// to construct the method reference.
    fn verification_method(&self) -> impl Future<Output = anyhow::Result<String>> + Send;
}

/// Encryptor is used by implementers to provide decryption-related functions.
pub trait Receiver: Send + Sync {
    /// Receiver's public key.
    fn public_key(&self) -> PublicKey;

    /// Receiver's public key identifier.
    fn key_id(&self) -> String;

    /// Derive the receiver's shared secret used for decrypting (or used
    /// directly) for the Content Encryption Key.
    fn shared_secret(
        &self, sender_public: PublicKey,
    ) -> impl Future<Output = anyhow::Result<SharedSecret>> + Send;
}

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
    /// Ed25519 curve
    #[default]
    Ed25519,

    /// secp256k1 curve
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,
}
