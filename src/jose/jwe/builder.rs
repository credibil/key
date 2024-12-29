//! # JWE Builder

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm}; //, Nonce, Tag};
// use aes_gcm::aes::cipher::consts::U12;
use aes_kw::Kek;
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::XChaCha20Poly1305;
use ecies::consts::{AEAD_TAG_LENGTH, NONCE_LENGTH, UNCOMPRESSED_PUBLIC_KEY_SIZE};
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{ContentAlgorithm, Header, Jwe, KeyAlgorithm, KeyEncryption, Protected, Recipients};
use crate::jose::jwk::PublicKeyJwk;
use crate::{Curve, KeyType};

/// Builds a JWE object using provided options.
pub struct JweBuilder<P, R> {
    content_algorithm: ContentAlgorithm,
    key_algorithm: KeyAlgorithm,
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
            content_algorithm: ContentAlgorithm::A256Gcm,
            key_algorithm: KeyAlgorithm::EcdhEs,
            payload: NoPayload,
            recipients: NoRecipients,
        }
    }
}

impl<P, R> JweBuilder<P, R> {
    /// The content encryption algorithm to use to encrypt the payload.
    #[must_use]
    pub const fn content_algorithm(mut self, algorithm: ContentAlgorithm) -> Self {
        self.content_algorithm = algorithm;
        self
    }

    /// The key management algorithm to use for encrypting the JWE CEK.
    #[must_use]
    pub const fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = algorithm;
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
    /// Build the JWE.
    ///
    /// # Errors
    /// LATER: add error docs
    pub fn build(self) -> Result<Jwe> {
        let recipients = self.recipients.0.as_slice();

        // select key management algorithm
        match self.key_algorithm {
            KeyAlgorithm::EcdhEs => {
                if recipients.len() != 1 {
                    return Err(anyhow!("too many recipients for ECDH-ES without A256KW"));
                }
                self.encrypt(&EcdhEs::from(recipients))
            }
            KeyAlgorithm::EcdhEsA256Kw => self.encrypt(&EcdhEsA256Kw::from(recipients)),
            KeyAlgorithm::EciesEs256K => self.encrypt(&EciesEs256K::from(recipients)),
        }
    }

    fn encrypt(&self, alg: &impl Algorithm) -> Result<Jwe> {
        let mut jwe = Jwe {
            protected: Protected {
                enc: self.content_algorithm.clone(),
                alg: None,
            },
            recipients: alg.recipients()?,
            ..Jwe::default()
        };

        let aad = serde_json::to_vec(&jwe.protected)?;
        jwe.aad = Base64UrlUnpadded::encode_string(&aad);

        // encrypt plaintext
        let mut buffer = serde_json::to_vec(self.payload.0)?;

        // select content encryption algorithm
        let (nonce, tag) = match self.content_algorithm {
            ContentAlgorithm::A256Gcm => {
                let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());
                let tag = Aes256Gcm::new(&alg.cek().into())
                    .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
                    .map_err(|e| anyhow!("issue encrypting: {e}"))?;
                (nonce.to_vec(), tag.to_vec())
            }
            ContentAlgorithm::XChaCha20Poly1305 => {
                let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
                let tag = XChaCha20Poly1305::new(&alg.cek().into())
                    .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
                    .map_err(|e| anyhow!("issue encrypting: {e}"))?;
                (nonce.to_vec(), tag.to_vec())
            }
        };

        jwe.iv = Base64UrlUnpadded::encode_string(&nonce);
        jwe.tag = Base64UrlUnpadded::encode_string(&tag);
        jwe.ciphertext = Base64UrlUnpadded::encode_string(&buffer);

        Ok(jwe)
    }
}

// Trait to allow for differences encryption process for different Key
// Management Algorithms ("alg" parameter).
trait Algorithm {
    // Generate a Content Encryption Key (CEK) for the JWE.
    fn cek(&self) -> [u8; 32];

    // Generate the key encryption material for the JWE recipients.
    fn recipients(&self) -> Result<Recipients>;
}

// ----------------
// ECDH-ES
// ----------------
#[derive(Zeroize, ZeroizeOnDrop)]
struct EcdhEs {
    ephemeral_public: [u8; 32],
    cek: [u8; 32],
}

impl From<&[Recipient]> for EcdhEs {
    fn from(recipients: &[Recipient]) -> Self {
        // generate CEK using ECDH-ES
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret).to_bytes();
        let cek =
            ephemeral_secret.diffie_hellman(&PublicKey::from(recipients[0].public_key)).to_bytes();

        Self {
            ephemeral_public,
            cek,
        }
    }
}

impl Algorithm for EcdhEs {
    fn cek(&self) -> [u8; 32] {
        self.cek
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
#[derive(Zeroize, ZeroizeOnDrop)]
struct EcdhEsA256Kw<'a> {
    #[zeroize(skip)]
    recipients: &'a [Recipient],
    cek: [u8; 32],
}

impl<'a> From<&'a [Recipient]> for EcdhEsA256Kw<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: Aes256Gcm::generate_key(&mut rand::thread_rng()).into(),
        }
    }
}

impl Algorithm for EcdhEsA256Kw<'_> {
    fn cek(&self) -> [u8; 32] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];

        for r in self.recipients {
            // derive shared secret
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = PublicKey::from(&ephemeral_secret);
            let shared_secret = ephemeral_secret.diffie_hellman(&PublicKey::from(r.public_key));

            // encrypt (wrap) CEK
            let encrypted_key = Kek::from(*shared_secret.as_bytes())
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
#[derive(Zeroize, ZeroizeOnDrop)]
struct EciesEs256K<'a> {
    #[zeroize(skip)]
    recipients: &'a [Recipient],
    cek: [u8; 32],
}

impl<'a> From<&'a [Recipient]> for EciesEs256K<'a> {
    fn from(recipients: &'a [Recipient]) -> Self {
        Self {
            recipients,
            cek: Aes256Gcm::generate_key(&mut rand::thread_rng()).into(),
        }
    }
}

impl Algorithm for EciesEs256K<'_> {
    fn cek(&self) -> [u8; 32] {
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
            // // derive shared secret
            // let (ephemeral_secret, ephemeral_public) = ecies::utils::generate_keypair();
            // let shared_secret = ecies::utils::encapsulate(
            //     &ephemeral_secret,
            //     &ecies::PublicKey::parse(&public_key)?,
            // )?;
            //
            // // encrypt (wrap) CEK
            // let iv = Aes256Gcm::generate_nonce(&mut OsRng);
            // let mut buffer = self.cek;
            // let tag = Aes256Gcm::new(&shared_secret.into())
            //     .encrypt_in_place_detached(&iv, &[], &mut buffer)
            //     .map_err(|e| anyhow!("issue encrypting: {e}"))?;

            // // x and y are 32 bytes each
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
