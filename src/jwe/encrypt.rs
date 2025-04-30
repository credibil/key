//! # JWE Builder

use aes_gcm::aead::KeyInit;
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm};
use aes_kw::Kek;
use anyhow::{Result, anyhow};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_ose::{AlgAlgorithm, Curve, EncAlgorithm, KeyType, PublicKey};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use rand::rngs::OsRng;
use serde::Serialize;
use x25519_dalek::EphemeralSecret;
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
                &EcdhEs::from(&recipients[0])
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

impl From<&Recipient> for EcdhEs {
    fn from(recipient: &Recipient) -> Self {
        // generate CEK using ECDH-ES
        let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret).to_bytes();
        let cek = ephemeral_secret.diffie_hellman(&recipient.public_key.into()).to_bytes();

        Self {
            ephemeral_public,
            cek,
        }
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
            cek: Aes256Gcm::generate_key(&mut rand::thread_rng()).into(),
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
            cek: Aes256Gcm::generate_key(&mut rand::thread_rng()).into(),
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
    // derive shared secret
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient.public_key.into());

    // encrypt (wrap) CEK
    let encrypted_key = Kek::from(*shared_secret.as_bytes())
        .wrap_vec(cek)
        .map_err(|e| anyhow!("issue wrapping cek: {e}"))?;

    Ok(KeyEncryption {
        header: Header {
            alg: AlgAlgorithm::EcdhEsA256Kw,
            kid: Some(recipient.key_id.clone()),
            epk: PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
                ..PublicKeyJwk::default()
            },
            ..Header::default()
        },
        encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
    })
}

/// Encrypt the content encryption key (CEK)for the specified recipient using
/// ECIES-ES256K.
///
/// # Errors
/// LATER: add error docs
pub fn ecies_es256k(cek: &[u8; PUBLIC_KEY_LENGTH], recipient: &Recipient) -> Result<KeyEncryption> {
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
        ecies::utils::encapsulate(&ephemeral_secret, &recipient.public_key.try_into()?)
            .map_err(|e| anyhow!("issue encapsulating: {e}"))?;

    // encrypt (wrap) CEK
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut encrypted_key = *cek;
    let tag = Aes256Gcm::new(&shared_secret.into())
        .encrypt_in_place_detached(&iv, &[], &mut encrypted_key)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    // tagged secp256k1 uncompressed public key is 65 bytes
    let ephemeral_public = ephemeral_public.serialize();

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
            iv: Some(Base64UrlUnpadded::encode_string(&iv)),
            tag: Some(Base64UrlUnpadded::encode_string(&tag)),
        },
        encrypted_key: Base64UrlUnpadded::encode_string(&encrypted_key),
    })
}
