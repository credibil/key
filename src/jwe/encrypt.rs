//! # JWE Builder

use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_ose::{AlgAlgorithm, Curve, EncAlgorithm, KeyType, PublicKey, PUBLIC_KEY_LENGTH};
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::jwe::{Header, Jwe, KeyEncryption, Protected, Recipients};
use crate::jwk::PublicKeyJwk;

/// Builds a JWE object using provided options.
pub struct JweBuilder<P> {
    content_algorithm: EncAlgorithm,
    key_algorithm: AlgAlgorithm,
    payload: P,
    recipients: Vec<Recipient>,
}

impl Default for JweBuilder<NoPayload> {
    fn default() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
/// Typestate generic for a JWE builder with no payload.
pub struct NoPayload;
#[doc(hidden)]
/// Typestate generic for a JWE builder with a payload.
pub struct Payload<T: Serialize + Send>(T);

/// Recipient information required when generating a JWE.
pub struct Recipient {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the public key to be used to encrypt the content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key, in bytes, for encrypting the content
    /// encryption key (CEK).
    pub public_key: PublicKey,
}

impl JweBuilder<NoPayload> {
    /// Create a new JWE builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_algorithm: EncAlgorithm::A256Gcm,
            key_algorithm: AlgAlgorithm::EcdhEs,
            payload: NoPayload,
            recipients: vec![],
        }
    }

    /// Set the payload to be encrypted.
    pub fn payload<T: Serialize + Send>(self, payload: T) -> JweBuilder<Payload<T>> {
        JweBuilder {
            content_algorithm: self.content_algorithm,
            key_algorithm: self.key_algorithm,
            payload: Payload(payload),
            recipients: self.recipients,
        }
    }
}

impl<P> JweBuilder<P> {
    /// The content encryption algorithm to use to encrypt the payload.
    #[must_use]
    pub const fn content_algorithm(mut self, algorithm: EncAlgorithm) -> Self {
        self.content_algorithm = algorithm;
        self
    }

    /// The key management algorithm to use for encrypting the JWE CEK.
    #[must_use]
    pub const fn key_algorithm(mut self, algorithm: AlgAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// Add key encryption material for a JWE recipient.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The fully qualified key ID of the public key to be used
    ///   to encrypt the content encryption key (CEK). For example,
    ///   `did:example:abc#encryption-key-id`.
    ///
    /// * `public_key` - The recipient's public key, in bytes, for encrypting
    ///   the content.
    #[must_use]
    pub fn add_recipient(mut self, key_id: impl Into<String>, public_key: PublicKey) -> Self {
        self.recipients.push(Recipient {
            key_id: key_id.into(),
            public_key,
        });
        self
    }
}

impl<T: Serialize + Send> JweBuilder<Payload<T>> {
    /// Build the JWE.
    ///
    /// # Errors
    /// LATER: add error docs
    pub fn build(self) -> Result<Jwe> {
        if self.recipients.is_empty() {
            return Err(anyhow!("no recipients set"));
        }

        // generate CEK and encrypt for each recipient
        let recipients = self.recipients.as_slice();
        let key_encrypter: &dyn KeyEncypter = match self.key_algorithm {
            AlgAlgorithm::EcdhEs => {
                if recipients.len() != 1 {
                    return Err(anyhow!("ECDH-ES requires a single recipient"));
                }
                &EcdhEs::try_from(&recipients[0])?
            }
            AlgAlgorithm::EcdhEsA256Kw => &EcdhEsA256Kw::from(recipients),
            AlgAlgorithm::EciesEs256K => &EciesEs256K::from(recipients),
        };

        // encrypt content
        let protected = Protected {
            enc: self.content_algorithm.clone(),
            alg: None,
        };
        let aad = serde_json::to_vec(&protected)?;

        let payload = serde_json::to_vec(&self.payload.0)?;
        let encrypted = self.content_algorithm.encrypt(
            &payload,
            &key_encrypter.cek(),
            &aad,
        )?;

        Ok(Jwe {
            protected,
            recipients: key_encrypter.recipients()?,
            aad: Base64UrlUnpadded::encode_string(&aad),
            iv: Base64UrlUnpadded::encode_string(&encrypted.iv),
            tag: Base64UrlUnpadded::encode_string(&encrypted.tag),
            ciphertext: Base64UrlUnpadded::encode_string(&encrypted.ciphertext),
            ..Jwe::default()
        })
    }
}

// Trait to accommodate for differences in the way key encryption is handled for
// each Key Management Algorithm ("alg" parameter).
trait KeyEncypter {
    // Generate a Content Encryption Key (CEK) for the JWE.
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH];

    // Generate the key encryption material for the JWE recipients.
    fn recipients(&self) -> Result<Recipients>;
}

// ----------------
// ECDH-ES
// ----------------
#[derive(Zeroize, ZeroizeOnDrop)]
struct EcdhEs {
    ephemeral_public: [u8; PUBLIC_KEY_LENGTH],
    cek: [u8; PUBLIC_KEY_LENGTH],
}

impl TryFrom<&Recipient> for EcdhEs {
    type Error = anyhow::Error;
    fn try_from(recipient: &Recipient) -> Result<Self, Self::Error> {
        let init_cek = AlgAlgorithm::EcdhEs.generate();
        let enc_cek = AlgAlgorithm::EcdhEs.encrypt(
            &init_cek,
            &recipient.public_key,
        )?;

        if enc_cek.encrypted_key.len() != PUBLIC_KEY_LENGTH {
            return Err(anyhow!("unexpected encrypted key length"));
        }
        let mut cek_bytes = [0; PUBLIC_KEY_LENGTH];
        cek_bytes.copy_from_slice(&enc_cek.encrypted_key);

        Ok(Self {
            ephemeral_public: enc_cek.ephemeral_public.to_bytes(),
            cek: cek_bytes,
        })
    }
}

impl KeyEncypter for EcdhEs {
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let key_encryption = KeyEncryption {
            header: Header {
                alg: AlgAlgorithm::EcdhEs,
                kid: None,
                epk: PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&self.ephemeral_public),
                    ..PublicKeyJwk::default()
                },
                ..Header::default()
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&[0; PUBLIC_KEY_LENGTH]),
        };

        Ok(Recipients::One(key_encryption))
    }
}

// ----------------
// ECDH-ES+A256KW
// ----------------
#[derive(Zeroize, ZeroizeOnDrop)]
struct EcdhEsA256Kw<'a> {
    #[zeroize(skip)]
    recipients: &'a [Recipient],
    cek: [u8; PUBLIC_KEY_LENGTH],
}

impl<'a> From<&'a [Recipient]> for EcdhEsA256Kw<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: AlgAlgorithm::EcdhEsA256Kw.generate(),
        }
    }
}

impl KeyEncypter for EcdhEsA256Kw<'_> {
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];
        for r in self.recipients {
            recipients.push(ecdh_a256kw(&self.cek, r)?);
        }
        Ok(Recipients::Many { recipients })
    }
}

// ----------------
// ECIES-ES256K (example code only)
// ----------------
#[derive(Zeroize, ZeroizeOnDrop)]
struct EciesEs256K<'a> {
    #[zeroize(skip)]
    recipients: &'a [Recipient],
    cek: [u8; PUBLIC_KEY_LENGTH],
}

impl<'a> From<&'a [Recipient]> for EciesEs256K<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: AlgAlgorithm::EciesEs256K.generate(),
        }
    }
}

impl KeyEncypter for EciesEs256K<'_> {
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];
        for r in self.recipients {
            recipients.push(ecies_es256k(&self.cek, r)?);
        }
        Ok(Recipients::Many { recipients })
    }
}

/// Encrypt the content encryption key (CEK)for the specified recipient using
/// ECDH-ES+A256KW.
///
/// # Errors
/// LATER: add error docs
pub fn ecdh_a256kw(cek: &[u8; PUBLIC_KEY_LENGTH], recipient: &Recipient) -> Result<KeyEncryption> {
    let enc_cek = AlgAlgorithm::EcdhEsA256Kw.encrypt(
        cek,
        &recipient.public_key,
    )?;
    Ok(KeyEncryption {
        header: Header {
            alg: AlgAlgorithm::EcdhEsA256Kw,
            kid: Some(recipient.key_id.clone()),
            epk: PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(&enc_cek.ephemeral_public.to_bytes()),
                ..PublicKeyJwk::default()
            },
            ..Header::default()
        },
        encrypted_key: Base64UrlUnpadded::encode_string(&enc_cek.encrypted_key),
    })
}

/// Encrypt the content encryption key (CEK)for the specified recipient using
/// ECIES-ES256K.
///
/// # Errors
/// LATER: add error docs
pub fn ecies_es256k(cek: &[u8; PUBLIC_KEY_LENGTH], recipient: &Recipient) -> Result<KeyEncryption> {
    let enc_cek = AlgAlgorithm::EciesEs256K.encrypt(
        cek,
        &recipient.public_key,
    )?;

    // Use to_vec to get the full long (65-byte) public key
    let ephemeral_public = enc_cek.ephemeral_public.to_vec();

    Ok(KeyEncryption {
        header: Header {
            alg: AlgAlgorithm::EciesEs256K,
            kid: Some(recipient.key_id.clone()),
            epk: PublicKeyJwk {
                kty: KeyType::Ec,
                crv: Curve::Es256K,
                x: Base64UrlUnpadded::encode_string(&ephemeral_public[1..33]),
                y: Some(Base64UrlUnpadded::encode_string(&ephemeral_public[33..65])),
                ..PublicKeyJwk::default()
            },
            iv: enc_cek.iv.map(|iv| Base64UrlUnpadded::encode_string(&iv)),
            tag: enc_cek.tag.map(|tag| Base64UrlUnpadded::encode_string(&tag)),
        },
        encrypted_key: Base64UrlUnpadded::encode_string(&enc_cek.encrypted_key),
    })
}
