//! # JSON Object Signing and Encryption (JOSE) Proofs
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

pub mod jwa;
pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;

use std::fmt::Display;

pub use jwe::{EncryptionAlgorithm, Jwe};
pub use jwk::PublicKeyJwk;
pub use jws::Jws;
use serde::{Deserialize, Serialize};

/// The JWS `typ` header parameter.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Type {
    /// General purpose JWT type.
    #[default]
    #[serde(rename = "jwt")]
    Jwt,

    /// JWT `typ` for Wallet's Proof of possession of key material.
    #[serde(rename = "openid4vci-proof+jwt")]
    Openid4VciProofJwt,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    OauthAuthzReqJwt,
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The type of public key material for the JWT.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyType {
    /// Contains the key ID. If the Credential is bound to a DID, the kid refers
    /// to a DID URL which identifies a particular key in the DID Document
    /// that the Credential should bound to. Alternatively, may refer to a
    /// key inside a JWKS.
    #[serde(rename = "kid")]
    KeyId(String),

    /// Contains the key material the new Credential shall be bound to.
    #[serde(rename = "jwk")]
    Jwk(PublicKeyJwk),
}

impl Default for KeyType {
    fn default() -> Self {
        Self::KeyId(String::new())
    }
}

/// The compression algorithm applied to the plaintext before encryption.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Zip {
    /// DEFLATE compression algorithm.
    #[default]
    #[serde(rename = "DEF")]
    Deflate,
}
