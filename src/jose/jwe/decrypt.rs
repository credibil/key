use std::fmt;
use std::str::FromStr;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use aes_kw::Kek;
use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;

use super::key;
use crate::Receiver;
use crate::jose::jwe::key::PublicKey;
use crate::jose::jwe::{
    AlgAlgorithm, Header, Jwe, KeyEncryption, Protected, ProtectedFlat, Recipients,
};

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
            let Some(found) = recipients.iter().find(|r| r.header.kid == Some(receiver.key_id()))
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
        public_key.insert(0, key::TAG_PUBKEY_FULL);
    }

    let sender_public = PublicKey::try_from(public_key)?;

    // derive shared_secret from recipient's private key and sender's public key
    let shared_secret = receiver.shared_secret(sender_public).await?;

    let cek = match recipient.header.alg {
        AlgAlgorithm::EcdhEs => shared_secret.to_bytes(),
        AlgAlgorithm::EcdhEsA256Kw => {
            let encrypted_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
                .map_err(|e| anyhow!("issue decoding `encrypted_key`: {e}"))?;

            Kek::from(shared_secret.to_bytes())
                .unwrap_vec(encrypted_key.as_slice())
                .map_err(|e| anyhow!("issue unwrapping cek: {e}"))?
                .try_into()
                .map_err(|_| anyhow!("issue unwrapping cek"))?
        }
        AlgAlgorithm::EciesEs256K => {
            let Some(base64_iv) = &recipient.header.iv else {
                return Err(anyhow!("missing `iv`"));
            };
            let Some(base64_tag) = &recipient.header.tag else {
                return Err(anyhow!("missing `iv`"));
            };

            let iv = Base64UrlUnpadded::decode_vec(base64_iv)
                .map_err(|e| anyhow!("issue decoding `iv`: {e}"))?;
            let tag = Base64UrlUnpadded::decode_vec(base64_tag)
                .map_err(|e| anyhow!("issue decoding `tag`: {e}"))?;
            let encrypted_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
                .map_err(|e| anyhow!("issue decoding `encrypted_key`: {e}"))?;

            let mut buffer = encrypted_key;
            let nonce = Nonce::from_slice(&iv);
            let tag = Tag::from_slice(&tag);

            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes()))
                .decrypt_in_place_detached(nonce, &[], &mut buffer, tag)
                .map_err(|e| anyhow!("issue decrypting: {e}"))?;

            buffer.try_into().map_err(|_| anyhow!("issue unwrapping cek"))?
        }
    };

    // unpack JWE
    let iv =
        Base64UrlUnpadded::decode_vec(&jwe.iv).map_err(|e| anyhow!("issue decoding `iv`: {e}"))?;
    let tag = Base64UrlUnpadded::decode_vec(&jwe.tag)
        .map_err(|e| anyhow!("issue decoding `tag`: {e}"))?;
    let aad = Base64UrlUnpadded::decode_vec(&jwe.aad)
        .map_err(|e| anyhow!("issue decoding `aad`: {e}"))?;
    let ciphertext = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)
        .map_err(|e| anyhow!("issue decoding `ciphertext`: {e}"))?;

    // decrypt ciphertext using CEK, iv, aad, and tag
    let mut buffer = ciphertext;

    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&cek))
        .decrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut buffer, Tag::from_slice(&tag))
        .map_err(|e| anyhow!("issue decrypting: {e}"))?;

    Ok(serde_json::from_slice(&buffer)?)
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
