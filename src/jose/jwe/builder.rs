//! # JWE Builder

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm}; //, Nonce, Tag};
// use aes_gcm::aes::cipher::consts::U12;
use aes_kw::Kek;
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::{ContentAlgorithm, Header, Jwe, KeyAlgorithm, KeyEncryption, Protected, Recipients};
use crate::jose::jwk::PublicKeyJwk;
use crate::{Curve, KeyType};

/// Builds a JWE object using provided options.
pub struct JweBuilder<P, R> {
    content_algorithm: Option<ContentAlgorithm>,
    key_algorithm: Option<KeyAlgorithm>,
    payload: P,
    pub(crate) recipients: R,
}

impl Default for JweBuilder<NoPayload, NoRecipients> {
    fn default() -> Self {
        Self::new()
    }
}

#[doc(hidden)]
/// Typestate generic for a JWE builder with no payload.
pub struct NoPayload;
#[doc(hidden)]
/// Typestate generic for a JWE builder with a payload.
pub struct WithPayload<'a, T: Serialize + Send>(&'a T);

#[doc(hidden)]
/// Typestate generic for a JWE builder with no recipients.
pub struct NoRecipients;
#[doc(hidden)]
/// Typestate generic for a JWE builder with recipients.
pub struct WithRecipients(pub Vec<Recipient>);

/// Recipient information required when generating a JWE.
pub struct Recipient {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the public key to be used to encrypt the content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key, in bytes, for encrypting the content
    /// encryption key (CEK).
    pub public_key: [u8; 32],
}

impl JweBuilder<NoPayload, NoRecipients> {
    /// Create a new JWE builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_algorithm: None,
            key_algorithm: None,
            payload: NoPayload,
            recipients: NoRecipients,
        }
    }
}

impl<P, R> JweBuilder<P, R> {
    /// The content encryption algorithm to use to encrypt the payload.
    #[must_use]
    pub const fn content_algorithm(mut self, algorithm: ContentAlgorithm) -> Self {
        self.content_algorithm = Some(algorithm);
        self
    }

    /// The key management algorithm to use for encrypting the JWE CEK.
    #[must_use]
    pub const fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = Some(algorithm);
        self
    }
}

impl<P> JweBuilder<P, NoRecipients> {
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
    pub fn add_recipient(
        self, key_id: impl Into<String>, public_key: [u8; 32],
    ) -> JweBuilder<P, WithRecipients> {
        let recipient = Recipient {
            key_id: key_id.into(),
            public_key,
        };

        JweBuilder {
            content_algorithm: self.content_algorithm,
            key_algorithm: self.key_algorithm,
            payload: self.payload,
            recipients: WithRecipients(vec![recipient]),
        }
    }
}

impl<P> JweBuilder<P, WithRecipients> {
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
    pub fn add_recipient(mut self, key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        let recipient = Recipient {
            key_id: key_id.into(),
            public_key,
        };
        self.recipients.0.push(recipient);
        self
    }
}

impl<R> JweBuilder<NoPayload, R> {
    /// Set the payload to be encrypted.
    pub fn payload<T: Serialize + Send>(self, payload: &T) -> JweBuilder<WithPayload<'_, T>, R> {
        JweBuilder {
            content_algorithm: self.content_algorithm,
            key_algorithm: self.key_algorithm,
            payload: WithPayload(payload),
            recipients: self.recipients,
        }
    }
}

impl<T: Serialize + Send> JweBuilder<WithPayload<'_, T>, WithRecipients> {
    fn encrypt(&self, encrypter: &mut impl Algorithm) -> Result<Jwe> {
        let protected = Protected {
            enc: ContentAlgorithm::A256Gcm,
            alg: None,
        };
        let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);

        let cek = encrypter.cek();

        // encrypt plaintext
        let mut buffer = serde_json::to_vec(self.payload.0)?;
        let tag = Aes256Gcm::new(&cek.into())
            .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
            .map_err(|e| anyhow!("issue encrypting: {e}"))?;

        // zero-ized key
        let recipients = encrypter.recipients()?;

        Ok(Jwe {
            protected,
            unprotected: None,
            recipients,
            iv: Base64UrlUnpadded::encode_string(&iv),
            ciphertext: Base64UrlUnpadded::encode_string(&buffer),
            tag: Base64UrlUnpadded::encode_string(&tag),
            aad,
        })
    }

    /// Build the JWE.
    ///
    /// # Errors
    /// LATER: add error docs
    pub fn build(self) -> Result<Jwe> {
        if self.recipients.0.len() == 1 {
            let mut alg= EcdhEs::from(&self);
            self.encrypt(&mut alg)
        } else {
            let mut alg = EcdhEsA256Kw::from(&self);
            self.encrypt(&mut alg)
        }
    }
}

trait Algorithm {
    fn cek(&mut self) -> [u8; 32];

    fn recipients(&self) -> Result<Recipients>;
}

// ECDH-ES key management algorithm
struct EcdhEs<'a, T: Serialize + Send> {
    builder: &'a JweBuilder<WithPayload<'a, T>, WithRecipients>,
    ephemeral_public: PublicKey,
}

impl<'a, T: Serialize + Send> From<&'a JweBuilder<WithPayload<'a, T>, WithRecipients>>
    for EcdhEs<'a, T>
{
    fn from(builder: &'a JweBuilder<WithPayload<'a, T>, WithRecipients>) -> Self {
        EcdhEs {
            builder,
            ephemeral_public: PublicKey::from([0; 32]),
        }
    }
}

impl<T: Serialize + Send> Algorithm for EcdhEs<'_, T> {
    fn cek(&mut self) -> [u8; 32] {
        let recipients = &self.builder.recipients.0;

        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        self.ephemeral_public = PublicKey::from(&ephemeral_secret);

        ephemeral_secret.diffie_hellman(&PublicKey::from(recipients[0].public_key)).to_bytes()
    }

    fn recipients(&self) -> Result<Recipients> {
        let encrypted_key = [0; 32];

        let key_encryption = KeyEncryption {
            header: Header {
                alg: KeyAlgorithm::EcdhEs,
                kid: None,
                epk: PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(self.ephemeral_public.as_bytes()),
                    ..PublicKeyJwk::default()
                },
                apu: None,
                apv: None,
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
        };

        Ok(Recipients::One(key_encryption))
    }
}

// ECDH-ES+A256KW key management algorithm
struct EcdhEsA256Kw<'a, T: Serialize + Send> {
    builder: &'a JweBuilder<WithPayload<'a, T>, WithRecipients>,
    cek: [u8; 32],
}

impl<'a, T: Serialize + Send> From<&'a JweBuilder<WithPayload<'a, T>, WithRecipients>>
    for EcdhEsA256Kw<'a, T>
{
    fn from(builder: &'a JweBuilder<WithPayload<'a, T>, WithRecipients>) -> Self {
        EcdhEsA256Kw {
            builder,
            cek: [0; 32],
        }
    }
}

impl<T: Serialize + Send> Algorithm for EcdhEsA256Kw<'_, T> {
    fn cek(&mut self) -> [u8; 32] {
        let cek = Aes256Gcm::generate_key(&mut OsRng);
        self.cek = cek.into();
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let recipients = &self.builder.recipients.0;
        let mut encrypted_ceks = vec![];

        for r in recipients {
            // derive shared secret
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = PublicKey::from(&ephemeral_secret);
            let shared_key = ephemeral_secret.diffie_hellman(&PublicKey::from(r.public_key));

            // encrypt (wrap) CEK
            let encrypted_key = Kek::from(*shared_key.as_bytes())
                .wrap_vec(&self.cek)
                .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;

            encrypted_ceks.push(KeyEncryption {
                header: Header {
                    alg: KeyAlgorithm::EcdhEsA256Kw,
                    kid: Some(r.key_id.clone()),
                    epk: PublicKeyJwk {
                        kty: KeyType::Okp,
                        crv: Curve::Ed25519,
                        x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
                        ..PublicKeyJwk::default()
                    },
                    apu: None,
                    apv: None,
                },
                encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
            });
        }

        Ok(Recipients::Many {
            recipients: encrypted_ceks,
        })
    }
}
