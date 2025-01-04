//! # JWE Builder

use aes_gcm::aead::KeyInit;
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm};
// use aes_gcm::aes::cipher::consts::U12;
use aes_kw::Kek;
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::XChaCha20Poly1305;
// use ecies::consts::{AEAD_TAG_LENGTH, NONCE_LENGTH, UNCOMPRESSED_PUBLIC_KEY_SIZE};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::EphemeralSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::jose::jwe::{
    ContentAlgorithm, Header, Jwe, KeyAlgorithm, KeyEncryption, Protected, PublicKey, Recipients,
};
use crate::jose::jwk::PublicKeyJwk;
use crate::{Curve, KeyType};

/// Builds a JWE object using provided options.
pub struct JweBuilder<P> {
    content_algorithm: ContentAlgorithm,
    key_algorithm: KeyAlgorithm,
    payload: P,
    pub(crate) recipients: Vec<Recipient>,
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
pub struct WithPayload<'a, T: Serialize + Send>(&'a T);

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
            content_algorithm: ContentAlgorithm::A256Gcm,
            key_algorithm: KeyAlgorithm::EcdhEs,
            payload: NoPayload,
            recipients: vec![],
        }
    }
}

impl<P> JweBuilder<P> {
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

impl JweBuilder<NoPayload> {
    /// Set the payload to be encrypted.
    pub fn payload<T: Serialize + Send>(self, payload: &T) -> JweBuilder<WithPayload<'_, T>> {
        JweBuilder {
            content_algorithm: self.content_algorithm,
            key_algorithm: self.key_algorithm,
            payload: WithPayload(payload),
            recipients: self.recipients,
        }
    }
}

impl<T: Serialize + Send> JweBuilder<WithPayload<'_, T>> {
    /// Build the JWE.
    ///
    /// # Errors
    /// LATER: add error docs
    pub fn build(self) -> Result<Jwe> {
        if self.recipients.is_empty() {
            return Err(anyhow!("no recipients provided"));
        }

        let recipients = self.recipients.as_slice();

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

impl From<&[Recipient]> for EcdhEs {
    fn from(recipients: &[Recipient]) -> Self {
        // generate CEK using ECDH-ES
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret).to_bytes();
        let cek = ephemeral_secret.diffie_hellman(&recipients[0].public_key.into()).to_bytes();

        Self {
            ephemeral_public,
            cek,
        }
    }
}

impl Algorithm for EcdhEs {
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
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
            cek: Aes256Gcm::generate_key(&mut rand::thread_rng()).into(),
        }
    }
}

impl Algorithm for EcdhEsA256Kw<'_> {
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];

        for r in self.recipients {
            // derive shared secret
            let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
            let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
            let shared_secret = ephemeral_secret.diffie_hellman(&r.public_key.into());

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
    cek: [u8; PUBLIC_KEY_LENGTH],
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
    fn cek(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cek
    }

    fn recipients(&self) -> Result<Recipients> {
        let mut recipients = vec![];

        for r in self.recipients {
            // ----------------------------------------------------------------
            // Using the `ecies` library's top-level `encrypt`.
            // ----------------------------------------------------------------
            // encrypt CEK using ECIES derived shared secret
            // let encrypted = ecies::encrypt(&r.public_key.to_vec(), &self.cek)?;
            // if encrypted.len()
            //     != UNCOMPRESSED_PUBLIC_KEY_SIZE
            //         + NONCE_LENGTH
            //         + AEAD_TAG_LENGTH
            //         + ENCRYPTED_KEY_LENGTH
            // {
            //     return Err(anyhow!("invalid encrypted key length"));
            // }

            // // extract components
            // let (ephemeral_public, remaining) = encrypted.split_at(UNCOMPRESSED_PUBLIC_KEY_SIZE);
            // let (iv, remaining) = remaining.split_at(NONCE_LENGTH);
            // let (tag, encrypted_key) = remaining.split_at(AEAD_TAG_LENGTH);
            // ----------------------------------------------------------------

            // derive shared secret
            let (ephemeral_secret, ephemeral_public) = ecies::utils::generate_keypair();
            let shared_secret =
                ecies::utils::encapsulate(&ephemeral_secret, &r.public_key.try_into()?)?;

            // encrypt (wrap) CEK
            let iv = Aes256Gcm::generate_nonce(&mut OsRng);
            let mut encrypted_key = self.cek;
            let tag = Aes256Gcm::new(&shared_secret.into())
                .encrypt_in_place_detached(&iv, &[], &mut encrypted_key)
                .map_err(|e| anyhow!("issue encrypting: {e}"))?;

            // tagged secp256k1 uncompressed public key is 65 bytes
            let ephemeral_public = ephemeral_public.serialize();

            recipients.push(KeyEncryption {
                header: Header {
                    alg: KeyAlgorithm::EciesEs256K,
                    kid: Some(r.key_id.clone()),
                    epk: PublicKeyJwk {
                        kty: KeyType::Ec,
                        crv: Curve::Es256K,
                        x: Base64UrlUnpadded::encode_string(&ephemeral_public[1..33]),
                        y: Some(Base64UrlUnpadded::encode_string(&ephemeral_public[33..65])),
                        ..PublicKeyJwk::default()
                    },
                    iv: Some(Base64UrlUnpadded::encode_string(&iv)),
                    tag: Some(Base64UrlUnpadded::encode_string(&tag)),
                },
                encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
            });
        }

        Ok(Recipients::Many { recipients })
    }
}
