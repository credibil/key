use std::fmt;
use std::str::FromStr;

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_se::{PublicKey, Receiver, TAG_PUBKEY_FULL};
use serde::de::DeserializeOwned;

use crate::jwe::{Header, Jwe, KeyEncryption, Protected, ProtectedFlat, Recipients};

/// Decrypt the JWE and return the plaintext.
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
#[allow(dead_code)]
pub async fn decrypt<T>(jwe: &Jwe, receiver: &impl Receiver) -> Result<T>
where
    T: DeserializeOwned,
{
    let recipient = match &jwe.recipients {
        Recipients::One(recipient) => recipient,
        Recipients::Many { recipients } => {
            let key_id = receiver.key_id().await?;
            let Some(found) = recipients.iter().find(|r| r.header.kid == Some(key_id.clone()))
            else {
                return Err(anyhow!("no recipient found"));
            };
            found
        }
    };

    // get sender's ephemeral public key (used in key agreement)
    let mut public_key = Base64UrlUnpadded::decode_vec(&recipient.header.epk.x)
        .map_err(|e| anyhow!("issue decoding sender public key `x`: {e}"))?;

    if let Some(y) = &recipient.header.epk.y {
        let y = Base64UrlUnpadded::decode_vec(y)
            .map_err(|e| anyhow!("issue decoding sender public key `y`: {e}"))?;
        public_key.extend_from_slice(&y);
        public_key.insert(0, TAG_PUBKEY_FULL);
    }

    let sender_public = PublicKey::try_from(public_key)?;

    // derive shared_secret from recipient's private key and sender's public key
    let shared_secret = receiver.shared_secret(sender_public).await?;

    let encrypted_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
        .map_err(|e| anyhow!("issue decoding `encrypted_key`: {e}"))?;
    let iv = &recipient
        .header
        .iv
        .as_ref()
        .map(|iv| {
            Base64UrlUnpadded::decode_vec(iv).map_err(|e| anyhow!("issue decoding `iv`: {e}"))
        })
        .transpose()?;
    let tag = &recipient
        .header
        .tag
        .as_ref()
        .map(|tag| {
            Base64UrlUnpadded::decode_vec(tag).map_err(|e| anyhow!("issue decoding `tag`: {e}"))
        })
        .transpose()?;

    let cek = &recipient.header.alg.decrypt(
        &shared_secret,
        Some(&encrypted_key),
        iv.as_deref(),
        tag.as_deref(),
    )?;

    // unpack JWE
    let iv =
        Base64UrlUnpadded::decode_vec(&jwe.iv).map_err(|e| anyhow!("issue decoding `iv`: {e}"))?;
    let tag = Base64UrlUnpadded::decode_vec(&jwe.tag)
        .map_err(|e| anyhow!("issue decoding `tag`: {e}"))?;
    let aad = Base64UrlUnpadded::decode_vec(&jwe.aad)
        .map_err(|e| anyhow!("issue decoding `aad`: {e}"))?;
    let ciphertext = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)
        .map_err(|e| anyhow!("issue decoding `ciphertext`: {e}"))?;
    let enc = &jwe.protected.enc;

    let buffer = enc.decrypt(&ciphertext, cek, &iv, &aad, &tag)?;
    let deserialized = serde_json::from_slice(&buffer)?;
    Ok(deserialized)
}

/// Deserialize JWE from Compact Serialization format.
impl FromStr for Jwe {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 5 {
            return Err(anyhow!("invalid JWE"));
        }

        // unpack flattened Protected header
        let bytes = Base64UrlUnpadded::decode_vec(parts[0]).map_err(|_| fmt::Error)?;
        let protected: ProtectedFlat = serde_json::from_slice(&bytes).map_err(|_| fmt::Error)?;

        // reconstruct fields
        let enc = protected.inner.enc;
        let alg = protected.inner.alg.unwrap_or_default();
        let epk = protected.epk;

        // calculate AAD
        let protected = Protected { alg: None, enc };
        let aad_bytes = serde_json::to_vec(&protected).map_err(|_| fmt::Error)?;

        Ok(Self {
            protected,
            recipients: Recipients::One(KeyEncryption {
                header: Header {
                    alg,
                    epk,
                    ..Header::default()
                },
                encrypted_key: parts[1].to_string(),
            }),
            aad: Base64UrlUnpadded::encode_string(&aad_bytes),
            iv: parts[2].to_string(),
            ciphertext: parts[3].to_string(),
            tag: parts[4].to_string(),
            ..Self::default()
        })
    }
}

impl From<String> for Jwe {
    fn from(s: String) -> Self {
        s.parse().expect("should parse")
    }
}
