//! # JSON Object Signing and Encryption (JOSE) Proofs
//!
//! This crate provides common utilities for the Credibil project and is not
//! intended to be used directly.
//!
//! [JOSE] proofs are enveloping proofs for Credentials based on JWT [RFC7519],
//! JWS [RFC7515], and JWK [RFC7517].
//!
//! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
//! recommendation defines a "bridge" between these and the Verifiable
//! Credentials Data Model v2.0, specifying the suitable header claims, media
//! types, etc.
//!
//! In the case of JOSE, the Credential is the "payload". This is preceded by a
//! suitable header whose details are specified by Securing Verifiable
//! Credentials using JOSE and COSE for the usage of JWT. These are encoded,
//! concatenated, and signed, to be transferred in a compact form by one entity
//! to an other (e.g., sent by the holder to the verifier). All the intricate
//! details on signatures, encryption keys, etc., are defined by the IETF
//! specifications; see Example 6 for a specific case.
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! ```json
//! {
//!   "vp_token": "eyJI...",
//!   "presentation_submission": {...}
//! }
//! ```
//!
//! [JOSE]: https://datatracker.ietf.org/wg/jose/about
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517
//! [RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose
//! [OpenID4VP]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

mod jwa;
pub mod jwe;
mod jwk;
mod jws;
mod jwt;

use std::future::{Future, IntoFuture};

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub use jwa::Algorithm;
pub use jwk::{ED25519_CODEC, MultiKey, PublicKeyJwk, X25519_CODEC};
pub use jws::{
    Jws, JwsBuilder, Protected, Signature, decode_jws, encode_jws,
};
pub use jwt::Jwt;

/// The type of Proof-of-Possession public key to use in key binding.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeyBinding {
    /// A public key JWK.
    Jwk(PublicKeyJwk),

    /// A public key Key ID.
    Kid(String),

    /// A URL to a JWK Set and Key ID referencing a public key within the set.
    Jku {
        /// The URL of the JWK Set.
        jku: String,

        /// The Key ID of a public key.
        kid: String,
    },
}

impl Default for KeyBinding {
    fn default() -> Self {
        Self::Kid(String::new())
    }
}

impl From<PublicKeyJwk> for KeyBinding {
    fn from(jwk: PublicKeyJwk) -> Self {
        Self::Jwk(jwk)
    }
}
impl From<String> for KeyBinding {
    fn from(kid: String) -> Self {
        Self::Kid(kid)
    }
}
impl From<(String, String)> for KeyBinding {
    fn from((jku, kid): (String, String)) -> Self {
        Self::Jku { jku, kid }
    }
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
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// The verifying key (public key) from the signing keypair.
    ///
    /// The possibility of key rotation mean this key should only be referenced
    /// at the point of verifying a signature.
    fn verifying_key(&self) -> impl Future<Output = Result<Vec<u8>>> + Send;

    /// Signature algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;
}

/// A Receiver (Recipient) is required to decrypt an encrypted message.
pub trait Receiver: Send + Sync {
    /// The Receiver's public key identifier used to identify the recipient in
    /// a multi-recipient JWE
    ///
    /// For example, `did:example:alice#key-id`.
    fn key_id(&self) -> String;

    /// Derive the receiver's shared secret used for decrypting (or direct use)
    /// for the Content Encryption Key.
    ///
    /// `[SecretKey]` wraps the receiver's private key to provide the key
    /// derivation functionality using ECDH-ES. The resultant `[SharedSecret]`
    /// is used in decrypting the JWE ciphertext.
    ///
    /// `[SecretKey]` supports both X25519 and secp256k1 private keys.
    ///
    /// # Errors
    /// LATER: document errors
    ///
    /// # Example
    ///
    /// This example derives a shared secret from an X25519 private key.
    ///
    /// ```rust,ignore
    /// use rand::rngs::OsRng;
    /// use x25519_dalek::{StaticSecret, PublicKey};
    ///
    /// struct KeyStore {
    ///     secret: StaticSecret,
    /// }
    ///
    /// impl KeyStore {
    ///     fn new() -> Self {
    ///         Self {
    ///             secret: StaticSecret::random_from_rng(OsRng),
    ///         }
    ///     }
    /// }
    ///
    /// impl Receiver for KeyStore {
    ///    fn key_id(&self) -> String {
    ///         "did:example:alice#key-id".to_string()
    ///    }
    ///
    /// async fn shared_secret(&self, sender_public: PublicKey) -> Result<jwe::SharedSecret> {
    ///     let secret_key = SecretKey::from(self.secret.to_bytes());
    ///     secret_key.shared_secret(sender_public)
    /// }
    /// ```
    fn shared_secret(
        &self, sender_public: jwe::PublicKey,
    ) -> impl Future<Output = Result<jwe::SharedSecret>> + Send;
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
