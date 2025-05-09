//! # JSON Web Token (JWT)
//!
//! JSON Web Token (JWT) is a compact, URL-safe means of representing
//! claims to be transferred between two parties.  The claims in a JWT
//! are encoded as a JSON object that is used as the payload of a JSON
//! Web Signature (JWS) structure or as the plaintext of a JSON Web
//! Encryption (JWE) structure, enabling the claims to be digitally
//! signed or integrity protected with a Message Authentication Code
//! (MAC) and/or encrypted.

use std::str::FromStr;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Serialize;

use crate::jws::Protected;

/// Represents a JWT as used for proof and credential presentation.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Jwt<T> {
    /// The JWT header.
    pub header: Protected,

    /// The JWT claims.
    pub claims: T,
}

impl<T> FromStr for Jwt<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 2 {
            return Err(anyhow!("invalid JWT"));
        }

        let header = Base64UrlUnpadded::decode_vec(parts[0])
            .map_err(|e| anyhow!("issue decoding header: {e}"))?;
        let header = serde_json::from_slice(&header)
            .map_err(|e| anyhow!("issue deserializing header:{e}"))?;
        let claims = Base64UrlUnpadded::decode_vec(parts[1])
            .map_err(|e| anyhow!("issue decoding claims: {e}"))?;
        let claims = serde_json::from_slice(&claims)
            .map_err(|e| anyhow!("issue deserializing claims:{e}"))?;

        Ok(Self { header, claims })
    }
}
