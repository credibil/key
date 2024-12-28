//! # JWE Builder

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key}; //, Nonce, Tag};
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
    recipients: R,
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
    pub fn new() -> Self {
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
    pub fn content_algorithm(mut self, algorithm: ContentAlgorithm) -> Self {
        self.content_algorithm = Some(algorithm);
        self
    }

    /// The key management algorithm to use for encrypting the JWE CEK.
    pub fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
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
    pub fn add_recipient(
        mut self, key_id: impl Into<String>, public_key: [u8; 32],
    ) -> JweBuilder<P, WithRecipients> {
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
    pub fn payload<'a, T: Serialize + Send>(
        self, payload: &'a T,
    ) -> JweBuilder<WithPayload<'a, T>, R> {
        JweBuilder {
            content_algorithm: self.content_algorithm,
            key_algorithm: self.key_algorithm,
            payload: WithPayload(payload),
            recipients: self.recipients,
        }
    }
}

impl<'a, T: Serialize + Send> JweBuilder<WithPayload<'a, T>, WithRecipients> {
    pub fn encrypt_one(&self) -> Result<Jwe> {
        let recipients = &self.recipients.0;
        let recipient = &recipients[0];

        // generate a CEK to encrypt payload
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // when using Direct Key Agreement, the CEK is the ECDH shared secret
        let recipient_public = PublicKey::from(recipient.public_key);
        let cek = ephemeral_secret.diffie_hellman(&recipient_public);

        let protected = Protected {
            enc: ContentAlgorithm::A256Gcm,
            alg: None,
        };
        let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);

        // encrypt plaintext using the CEK, initialization vector, and AAD
        // - generates ciphertext and a JWE Authentication Tag
        let mut buffer = serde_json::to_vec(self.payload.0)?;
        let key = Key::<Aes256Gcm>::from_slice(cek.as_bytes());
        let tag = Aes256Gcm::new(key)
            .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
            .map_err(|e| anyhow!("issue encrypting: {e}"))?;

        // recipient header
        let key_encryption = KeyEncryption {
            header: Header {
                alg: KeyAlgorithm::EcdhEs,
                kid: None,
                epk: PublicKeyJwk {
                    kty: KeyType::Okp,
                    crv: Curve::Ed25519,
                    x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
                    ..PublicKeyJwk::default()
                },
                apu: None,
                apv: None,
            },
            encrypted_key: Base64UrlUnpadded::encode_string(&[0; 32]),
        };

        Ok(Jwe {
            protected,
            unprotected: None,
            recipients: Recipients::One(key_encryption),
            iv: Base64UrlUnpadded::encode_string(&iv),
            ciphertext: Base64UrlUnpadded::encode_string(&buffer),
            tag: Base64UrlUnpadded::encode_string(&tag),
            aad,
        })
    }

    pub fn encrypt_many(&self) -> Result<Jwe> {
        let recipients = &self.recipients.0;

        let protected = Protected {
            enc: ContentAlgorithm::A256Gcm,
            alg: None,
        };
        let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
        let iv = Aes256Gcm::generate_nonce(&mut OsRng);
        let cek = Aes256Gcm::generate_key(&mut OsRng);

        // encrypt plaintext using the CEK, initialization vector, and AAD
        let mut buffer = serde_json::to_vec(self.payload.0)?;
        let tag = Aes256Gcm::new(&cek)
            .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
            .map_err(|e| anyhow!("issue encrypting: {e}"))?;

        // encrypt CEK per recipient using ECDH-ES+AES256GCM
        let mut encrypted_ceks = vec![];
        for r in recipients {
            // recipient public key
            let public_key = PublicKey::from(r.public_key);
            // let public_bytes: [u8; 32] = (*recipient).try_into()?;
            // let public_key = PublicKey::from(public_bytes);

            // derive shared secret using ECDH-ES
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = PublicKey::from(&ephemeral_secret);
            let shared_key = ephemeral_secret.diffie_hellman(&public_key);

            // wrap CEK using shared secret and Aes256KW
            let wrapped_key = Kek::from(*shared_key.as_bytes())
                .wrap_vec(&cek)
                .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;
            let encrypted_key = Base64UrlUnpadded::encode_string(&wrapped_key);

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
                encrypted_key,
            });
        }

        Ok(Jwe {
            protected,
            unprotected: None,
            recipients: Recipients::Many {
                recipients: encrypted_ceks,
            },
            iv: Base64UrlUnpadded::encode_string(&iv),
            ciphertext: Base64UrlUnpadded::encode_string(&buffer),
            tag: Base64UrlUnpadded::encode_string(&tag),
            aad,
        })
    }

    /// Build the JWE.
    pub fn build(self) -> Result<Jwe> {
        if self.recipients.0.len() == 1 {
            self.encrypt_one()
        } else {
            self.encrypt_many()
        }
    }
}

/// Encrypt plaintext and return a JWE.
///
/// N.B. We currently only support ECDH-ES key agreement and A256GCM
/// content encryption.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: &T, recipient: &Recipient) -> Result<Jwe> {
    // generate a CEK to encrypt payload
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // when using Direct Key Agreement, the CEK is the ECDH shared secret
    let recipient_public = PublicKey::from(recipient.public_key);
    let cek = ephemeral_secret.diffie_hellman(&recipient_public);

    let protected = Protected {
        enc: ContentAlgorithm::A256Gcm,
        alg: None,
    };
    let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);

    // encrypt plaintext using the CEK, initialization vector, and AAD
    // - generates ciphertext and a JWE Authentication Tag
    let mut buffer = serde_json::to_vec(plaintext)?;
    let key = Key::<Aes256Gcm>::from_slice(cek.as_bytes());
    let tag = Aes256Gcm::new(key)
        .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    // recipient header
    let key_encryption = KeyEncryption {
        header: Header {
            alg: KeyAlgorithm::EcdhEs,
            kid: None,
            epk: PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
                ..PublicKeyJwk::default()
            },
            apu: None,
            apv: None,
        },
        encrypted_key: Base64UrlUnpadded::encode_string(&[0; 32]),
    };

    Ok(Jwe {
        protected,
        unprotected: None,
        recipients: Recipients::One(key_encryption),
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&buffer),
        tag: Base64UrlUnpadded::encode_string(&tag),
        aad,
    })
}

/// Encrypt plaintext and return a JWE.
///
/// # Errors
/// LATER: document errors
pub fn encrypt2<T: Serialize + Send>(plaintext: &T, recipients: &[Recipient]) -> Result<Jwe> {
    let protected = Protected {
        enc: ContentAlgorithm::A256Gcm,
        alg: None,
    };
    let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);
    let cek = Aes256Gcm::generate_key(&mut OsRng);

    // encrypt plaintext using the CEK, initialization vector, and AAD
    let mut buffer = serde_json::to_vec(plaintext)?;
    let tag = Aes256Gcm::new(&cek)
        .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    // encrypt CEK per recipient using ECDH-ES+AES256GCM
    let mut encrypted_ceks = vec![];
    for r in recipients {
        // recipient public key
        let public_key = PublicKey::from(r.public_key);
        // let public_bytes: [u8; 32] = (*recipient).try_into()?;
        // let public_key = PublicKey::from(public_bytes);

        // derive shared secret using ECDH-ES
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared_key = ephemeral_secret.diffie_hellman(&public_key);

        // wrap CEK using shared secret and Aes256KW
        let wrapped_key = Kek::from(*shared_key.as_bytes())
            .wrap_vec(&cek)
            .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;
        let encrypted_key = Base64UrlUnpadded::encode_string(&wrapped_key);

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
            encrypted_key,
        });
    }

    Ok(Jwe {
        protected,
        unprotected: None,
        recipients: Recipients::Many {
            recipients: encrypted_ceks,
        },
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&buffer),
        tag: Base64UrlUnpadded::encode_string(&tag),
        aad,
    })
}
