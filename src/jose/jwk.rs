//! # JSON Web Key (JWK)
//!
//! A JWK ([RFC7517]) is a JSON representation of a cryptographic key.  
//! Additionally, a JWK Set (JWKS) is used to represent a set of JWKs.
//!
//! See [RFC7517] for more detail.
//!
//! TODO:
//! Support:
//! (key) type: `EcdsaSecp256k1VerificationKey2019` | `JsonWebKey2020` |
//!     `Ed25519VerificationKey2020` | `Ed25519VerificationKey2018` |
//!     `X25519KeyAgreementKey2019`
//! crv: `Ed25519` | `secp256k1` | `P-256` | `P-384` | `P-521`
//!
//! JWK Thumbprint [RFC7638]
//! It is RECOMMENDED that JWK kid values are set to the public key fingerprint:
//!  - create SHA-256 hash of UTF-8 representation of JSON from {crv,kty,x,y}
//!
//! For example:
//!  - JSON: `{"crv":"Ed25519","kty":"OKP","x":"
//!    11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
//!  - SHA-256: `90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89`
//!  - base64url JWK Thumbprint: `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`
//!
//! [RFC7638]: https://www.rfc-editor.org/rfc/rfc7638
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use multibase::Base;
use serde::{Deserialize, Serialize};

use crate::jose::jwe::KeyAlgorithm;
use crate::{Curve, KeyType};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
const X25519_CODEC: [u8; 2] = [0xec, 0x01];

/// Alias for multi-base encoded string.
pub type MultiKey = String;

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKeyJwk {
    /// Key identifier.
    /// For example, "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Key type.
    pub kty: KeyType,

    /// Cryptographic curve type.
    pub crv: Curve,

    /// X coordinate.
    pub x: String,

    /// Y coordinate. Not required for `EdDSA` verification keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Algorithm intended for use with the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<KeyAlgorithm>,

    /// Use of the key.
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<KeyUse>,
}

impl PublicKeyJwk {
    /// Convert a multi-base encoded key into a JWK.
    ///
    /// # Errors
    /// LATER: document errors.
    pub fn from_multibase(key: &str) -> Result<Self> {
        let (_, key_bytes) =
            multibase::decode(key).map_err(|e| anyhow!("issue decoding key: {e}"))?;
        if key_bytes.len() - 2 != 32 {
            return Err(anyhow!("key is not 32 bytes long"));
        }
        if key_bytes[0..2] != ED25519_CODEC && key_bytes[0..2] != X25519_CODEC{
            return Err(anyhow!("not Ed25519"));
        }

        Ok(Self {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(&key_bytes[2..]),
            ..Self::default()
        })
    }

    /// Convert a JWK into a multi-base encoded key.
    ///
    /// # Errors
    /// LATER: document errors.
    pub fn to_multibase(&self) -> Result<String> {
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&ED25519_CODEC);
        key_bytes.extend_from_slice(&Base64UrlUnpadded::decode_vec(&self.x)?);
        Ok(multibase::encode(Base::Base58Btc, &key_bytes))
    }
}

/// The intended usage of the public `KeyType`. This enum is serialized
/// `untagged`
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyUse {
    /// Public key is to be used for signature verification
    #[default]
    #[serde(rename = "sig")]
    Signature,

    /// Public key is to be used for encryption
    #[serde(rename = "enc")]
    Encryption,
}

/// A set of JWKs.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Jwks {
    /// The set of public key JWKs
    pub keys: Vec<PublicKeyJwk>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let jwk = PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: "q6rjRnEH_XK72jvB8FNBJtOl9_gDs6NW49cAz6p2sW4".to_string(),
            ..PublicKeyJwk::default()
        };

        let converted_jwk =
            PublicKeyJwk::from_multibase("z6Mkr1NtupNezZtcUAMxJ79HPex6ZTR9RnGh8xfV257ZQdss")
                .expect("should convert");
        assert_eq!(jwk, converted_jwk);

        let converted_multi = converted_jwk.to_multibase().expect("should convert");
        assert_eq!("z6Mkr1NtupNezZtcUAMxJ79HPex6ZTR9RnGh8xfV257ZQdss", converted_multi);
    }

    #[test]
    fn to_jwk() {
        let jwk = PublicKeyJwk::from_multibase("z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX")
            .expect("should convert");

        assert_eq!(
            PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: "RW-Q0fO2oECyLs4rZDZZo4p6b7pu7UF2eu9JBsktDco".to_string(),
                ..PublicKeyJwk::default()
            },
            jwk
        );
    }
}
