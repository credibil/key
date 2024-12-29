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
    fn encrypt(&self, alg: &mut impl Algorithm) -> Result<Jwe> {
        let protected = Protected {
            enc: ContentAlgorithm::A256Gcm,
            alg: None,
        };
        let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);

        let cek = alg.cek();

        // encrypt plaintext
        let mut buffer = serde_json::to_vec(self.payload.0)?;
        let tag = Aes256Gcm::new(&cek.into())
            .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
            .map_err(|e| anyhow!("issue encrypting: {e}"))?;

        // zero-ized key
        let recipients = alg.recipients()?;

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
        let recipients = self.recipients.0.as_slice();

        if recipients.len() == 1 {
            self.encrypt(&mut EcdhEs::from(recipients))
        } else {
            self.encrypt(&mut EcdhEsA256Kw::from(recipients))
        }
    }
}

// Trait to allow for differences encryption process for different Key
// Management Algorithms ("alg" parameter).
trait Algorithm {
    // Generate a Content Encryption Key (CEK) for the JWE.
    fn cek(&mut self) -> [u8; 32];

    // Generate the key encryption material for the JWE recipients.
    fn recipients(&self) -> Result<Recipients>;
}

// ----------------
// ECDH-ES
// ----------------
struct EcdhEs {
    recipient_public: [u8; 32],
    ephemeral_public: [u8; 32],
}

impl From<&[Recipient]> for EcdhEs {
    fn from(recipients: &[Recipient]) -> Self {
        Self {
            recipient_public: recipients[0].public_key,
            ephemeral_public: [0; 32],
        }
    }
}

impl Algorithm for EcdhEs {
    fn cek(&mut self) -> [u8; 32] {
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        self.ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
        ephemeral_secret.diffie_hellman(&PublicKey::from(self.recipient_public)).to_bytes()
    }

    fn recipients(&self) -> Result<Recipients> {
        let key_encryption = KeyEncryption {
            header: Header {
                alg: KeyAlgorithm::EcdhEs,
                kid: None,
                epk: PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(&self.ephemeral_public),
                    ..PublicKeyJwk::default()
                },
                ..Header::default()
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&[0; 32]),
        };

        Ok(Recipients::One(key_encryption))
    }
}

// ----------------
// ECDH-ES+A256KW
// ----------------
struct EcdhEsA256Kw<'a> {
    recipients: &'a [Recipient],
    cek: [u8; 32],
}

impl<'a> From<&'a [Recipient]> for EcdhEsA256Kw<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: [0; 32],
        }
    }
}

impl Algorithm for EcdhEsA256Kw<'_> {
    fn cek(&mut self) -> [u8; 32] {
        let cek = Aes256Gcm::generate_key(&mut OsRng);
        self.cek = cek.into();
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];

        for r in self.recipients {
            // derive shared secret
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = PublicKey::from(&ephemeral_secret);
            let shared_key = ephemeral_secret.diffie_hellman(&PublicKey::from(r.public_key));

            // encrypt (wrap) CEK
            let encrypted_key = Kek::from(*shared_key.as_bytes())
                .wrap_vec(&self.cek)
                .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;

            recipients.push(KeyEncryption {
                header: Header {
                    alg: KeyAlgorithm::EcdhEsA256Kw,
                    kid: Some(r.key_id.clone()),
                    epk: PublicKeyJwk {
                        kty: KeyType::Okp,
                        crv: Curve::Ed25519,
                        x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
                        ..PublicKeyJwk::default()
                    },
                    ..Header::default()
                },
                encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
            });
        }

        Ok(Recipients::Many { recipients })
    }
}

// ----------------
// ECIES-ES256K (example code only)
// ----------------
// TODO: implement ECIES-ES256K
struct EciesSecp256k1<'a> {
    recipients: &'a [Recipient],
    cek: [u8; 32],
}

impl<'a> From<&'a [Recipient]> for EciesSecp256k1<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: [0; 32],
        }
    }
}

use ecies::consts::{AEAD_TAG_LENGTH, NONCE_LENGTH, UNCOMPRESSED_PUBLIC_KEY_SIZE};

impl Algorithm for EciesSecp256k1<'_> {
    fn cek(&mut self) -> [u8; 32] {
        let cek = Aes256Gcm::generate_key(&mut OsRng);
        self.cek = cek.into();
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];

        for r in self.recipients {
            // FIXME: replace with actual public key
            let public_key = [0; 65];

            // encrypt CEK using ECIES derived shared secret
            let encrypted = ecies::encrypt(&public_key, &self.cek)?;
            if encrypted.len() != UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_LENGTH + AEAD_TAG_LENGTH {
                return Err(anyhow!("invalid encrypted key length"));
            }

            // extract components
            let (ephemeral_public, remaining) = encrypted.split_at(UNCOMPRESSED_PUBLIC_KEY_SIZE);
            let (_iv, remaining) = remaining.split_at(NONCE_LENGTH);
            let (_tag, encrypted_key) = remaining.split_at(AEAD_TAG_LENGTH);

            // ----------------------------------------------------------------
            // The following code is the longer route to the same result.
            // ----------------------------------------------------------------
            // derive shared secret
            // let (ephemeral_secret, ephemeral_public) = ecies::utils::generate_keypair();
            // let shared_key = ecies::utils::encapsulate(
            //     &ephemeral_secret,
            //     &ecies::PublicKey::parse(&public_key)?,
            // )?;

            // encrypt (wrap) CEK
            // let iv = Aes256Gcm::generate_nonce(&mut OsRng);
            // let mut buffer = self.cek;
            // let tag = Aes256Gcm::new(&shared_key.into())
            //     .encrypt_in_place_detached(&iv, &[], &mut buffer)
            //     .map_err(|e| anyhow!("issue encrypting: {e}"))?;

            // x and y are 32 bytes each
            // let ephemeral_public = ephemeral_public.serialize();
            // ----------------------------------------------------------------

            recipients.push(KeyEncryption {
                header: Header {
                    alg: KeyAlgorithm::EcdhEsA256Kw,
                    kid: Some(r.key_id.clone()),
                    epk: PublicKeyJwk {
                        kty: KeyType::Ec,
                        crv: Curve::Es256K,
                        x: Base64UrlUnpadded::encode_string(&ephemeral_public[1..33]),
                        y: Some(Base64UrlUnpadded::encode_string(&ephemeral_public[33..65])),
                        ..PublicKeyJwk::default()
                    },
                    // iv: Some(Base64UrlUnpadded::encode_string(&iv)),
                    // tag: Some(Base64UrlUnpadded::encode_string(&tag)),
                    ..Header::default()
                },
                encrypted_key: Base64UrlUnpadded::encode_string(encrypted_key),
            });
        }

        Ok(Recipients::Many { recipients })
    }
}
