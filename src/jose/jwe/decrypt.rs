use std::fmt::{self, Display};
use std::str::FromStr;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use aes_kw::Kek;
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::jose::jwe::{Header, Jwe, KeyAlgorithm, KeyEncryption, Protected, Recipients};
use crate::jose::jwk::PublicKeyJwk;
use crate::Cipher;

/// Decrypt the JWE and return the plaintext.
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
#[allow(dead_code)]
pub async fn decrypt<T: DeserializeOwned>(jwe: impl Into<&Jwe>, cipher: &impl Cipher) -> Result<T> {
    let jwe = jwe.into();

    let recipient = match &jwe.recipients {
        Recipients::One(recipient) => recipient,
        Recipients::Many { recipients } => {
            let Some(found) = recipients.iter().find(|r| r.header.kid == Some(cipher.key_id()))
            else {
                return Err(anyhow!("no recipient found"));
            };
            found
        }
    };

    // get sender's ephemeral public key (used in key agreement)
    let sender_public = Base64UrlUnpadded::decode_vec(&recipient.header.epk.x)
        .map_err(|e| anyhow!("issue decoding sender public key `x`: {e}"))?;
    let sender_public: [u8; 32] = sender_public.as_slice().try_into()?;

    // derive shared_secret from recipient's private key and sender's public key
    let shared_secret = cipher.shared_secret(sender_public).await;

    let cek = match recipient.header.alg {
        KeyAlgorithm::EcdhEs => shared_secret,
        KeyAlgorithm::EcdhEsA256Kw => {
            let encrypted_key = Base64UrlUnpadded::decode_vec(&recipient.encrypted_key)
                .map_err(|e| anyhow!("issue decoding `encrypted_key`: {e}"))?;

            Kek::from(shared_secret)
                .unwrap_vec(encrypted_key.as_slice())
                .map_err(|e| anyhow!("issue wrapping cek: {e}"))?
                .try_into()
                .map_err(|_| anyhow!("issue wrapping cek"))?
        }
        KeyAlgorithm::EciesEs256K => return Err(anyhow!("unsupported key algorithm")),
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

#[derive(Deserialize, Serialize)]
struct ProtectedFlat {
    #[serde(flatten)]
    inner: Protected,
    epk: PublicKeyJwk,
}
/// Compact Serialization. Can only be used with a single recipient.
///
/// In the JWE Compact Serialization, a JWE is represented as the concatenation:
///   base64(JWE Protected Header) + '.'
///   + base64(JWE Encrypted Key) + '.'
///   + base64(JWE Initialization Vector) + '.'
///   + base64(JWE Ciphertext) + '.'
///   + base64(JWE Authentication Tag)
impl Display for Jwe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Recipients::One(recipient) = &self.recipients else {
            return Err(fmt::Error);
        };

        // add recipient data to protected header
        let mut protected = ProtectedFlat {
            inner: self.protected.clone(),
            epk: recipient.header.epk.clone(),
        };
        protected.inner.alg = Some(recipient.header.alg.clone());

        let bytes = serde_json::to_vec(&protected).map_err(|_| fmt::Error)?;
        let protected = Base64UrlUnpadded::encode_string(&bytes);

        let encrypted_key = &recipient.encrypted_key;
        let iv = &self.iv;
        let ciphertext = &self.ciphertext;
        let tag = &self.tag;

        write!(f, "{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}")
    }
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
