//! # JSON Web Encryption (JWE)
//!
//! JWE ([RFC7516]) specifies how encrypted content can be represented using
//! JSON. See JWA ([RFC7518]) for more on the cyptographic algorithms and
//! identifiers used.
//!
//! See also:
//!
//! - <https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms>
//! - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE ([ECDH])
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
//! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml
//! [ECDH]: https://tools.ietf.org/html/rfc8037

//! # Example
//!
//! Reference JSON for ECDH/A256GCM from specification
//! (<https://www.rfc-editor.org/rfc/rfc7518#appendix-C>):
//!
//!```json
//! {
//!     "alg":"ECDH-ES",
//!     "enc":"A256GCM",
//!     "apu":"QWxpY2U",
//!     "apv":"Qm9i",
//!     "epk": {
//!          "kty":"EC",
//!          "crv":"P-256",
//!          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//!          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
//!     }
//! }
//! ```

// TODO: investigate PartyUInfo and PartyVInfo more thoroughly
// The ephemeral public key for the Agreement is stored alongside the wrapped
// per-file key. The KDF is Concatenation Key Derivation Function (Approved
// Alternative 1) as described in 5.8.1 of NIST SP 800-56A. AlgorithmID is
// omitted. PartyUInfo and PartyVInfo are the ephemeral and static public keys,
// respectively. SHA256 is used as the hashing function.

mod decrypt;
mod encrypt;
mod key;

use anyhow::{bail, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::encrypt::{
    a256gcm, ecdh_a256kw, ecies_es256k, xchacha20_poly1305, Encrypted, JweBuilder, NoPayload,
    Payload, Recipient,
};
pub use self::key::{PublicKey, SecretKey, SharedSecret};
use crate::jose::jwk::PublicKeyJwk;
use crate::Receiver;

/// Encrypt plaintext using the defaults of A256GCM content encryption and
/// ECDH-ES key agreement algorithms.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: T, recipient_public: PublicKey) -> Result<Jwe> {
    JweBuilder::new()
        .content_algorithm(ContentAlgorithm::A256Gcm)
        .key_algorithm(KeyAlgorithm::EcdhEs)
        .payload(plaintext)
        .add_recipient("", recipient_public)
        .build()
}

/// Decrypt the JWE and return the plaintext.
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt<T: DeserializeOwned>(jwe: &Jwe, receiver: &impl Receiver) -> Result<T> {
    decrypt::decrypt(jwe, receiver).await
}

/// In JWE JSON serialization, one or more of the JWE Protected Header, JWE
/// Shared Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be
/// present.
///
/// In this case, the members of the JOSE Header are the union of the members of
/// the JWE Protected header, JWE Shared Unprotected Header, and JWE
/// Per-Recipient Unprotected Header values that are present.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwe {
    /// JWE protected header.
    pub protected: Protected,

    /// Shared unprotected header as a JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<Value>,

    /// The Recipients array contains information specific to each recipient.
    #[serde(flatten)]
    pub recipients: Recipients,

    /// AAD value, base64url encoded. Not used for JWE Compact Serialization.
    pub aad: String,

    /// Initialization vector (nonce), as a base64Url encoded string.
    pub iv: String,

    /// Ciphertext, as a base64Url encoded string.
    pub ciphertext: String,

    /// Authentication tag resulting from the encryption, as a base64Url encoded
    /// string.
    pub tag: String,
}

impl Jwe {
    /// Compact Serialization for single-recipient JWEs.
    ///
    /// # Errors
    /// Returns an error if the JWE does not contain a single recipient or if
    /// the JWE cannot be serialized.
    pub fn encode(&self) -> Result<String> {
        let Recipients::One(recipient) = &self.recipients else {
            bail!("compact serialization requires a single recipient");
        };

        // add recipient data to protected header
        let mut protected = ProtectedFlat {
            inner: self.protected.clone(),
            epk: recipient.header.epk.clone(),
        };
        protected.inner.alg = Some(recipient.header.alg.clone());

        let bytes = serde_json::to_vec(&protected)?;
        let protected = Base64UrlUnpadded::encode_string(&bytes);

        let encrypted_key = &recipient.encrypted_key;
        let iv = &self.iv;
        let ciphertext = &self.ciphertext;
        let tag = &self.tag;

        Ok(format!("{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}"))
    }
}

/// Phe JWE Shared Protected header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Protected {
    /// Identifies the algorithm used to encrypt or determine the value of the
    /// content encryption key (CEK).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<KeyAlgorithm>,

    /// The algorithm used to perform authenticated encryption on the plaintext
    /// to produce the ciphertext and the Authentication Tag. MUST be an AEAD
    /// algorithm.
    pub enc: ContentAlgorithm,
}

#[derive(Deserialize, Serialize)]
struct ProtectedFlat {
    #[serde(flatten)]
    inner: Protected,
    epk: PublicKeyJwk,
}

/// JWE serialization is affected by the number of recipients. In the case of a
/// single recipient, the flattened JWE JSON Serialization syntax is used to
/// streamline the JWE.
///
/// The "recipients" member is flattened into the top-level JSON object instead
/// of being nested within the "recipients" member.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Recipients {
    /// Single recipient (uses flattened JWE JSON syntax).
    One(KeyEncryption),

    /// Multiple recipients (nested JWE JSON syntax).
    Many {
        /// The Recipients array contains information specific to each
        /// recipient. Fields with values shared by all recipients (via Header
        /// fields) may be empty.
        recipients: Vec<KeyEncryption>,
    },
}

impl Default for Recipients {
    fn default() -> Self {
        Self::One(KeyEncryption::default())
    }
}

/// Contains key encryption information specific to a recipient.
///
/// MUST be present with exactly one array element per recipient, even if some
/// or all of the array element values are the empty JSON object "{}".
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct KeyEncryption {
    /// JWE Per-Recipient Unprotected Header.
    pub header: Header,

    /// The recipient's JWE Encrypted Key, as a base64Url encoded string.
    pub encrypted_key: String,
}

/// The JWE Recipient header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Identifies the algorithm used to encrypt or determine the value of the
    /// content encryption key (CEK).
    pub alg: KeyAlgorithm,

    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the public key used to encrypt the content encryption key (CEK).
    pub kid: Option<String>,

    /// The ephemeral public key created by the originator for use in key
    /// agreement algorithms.
    pub epk: PublicKeyJwk,

    /// The initialization vector used when ECIES-ES256K key management
    /// algorithm is used to encrypt the CEK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,

    /// The authentication tag used when ECIES-ES256K key management
    /// algorithm is used to encrypt the CEK.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// The algorithm used to perform authenticated content encryption. That is,
/// encrypting the plaintext to produce the ciphertext and the Authentication
/// Tag. MUST be an AEAD algorithm.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ContentAlgorithm {
    /// AES GCM using a 256-bit key.
    #[default]
    #[serde(rename = "A256GCM")]
    A256Gcm,

    /// XChaCha20-Poly1305 is a competitive alternative to AES-256-GCM because
    /// it’s fast and constant-time without hardware acceleration (resistent
    /// to cache-timing attacks). It also has longer nonce length to alleviate
    /// the risk of birthday attacks when nonces are generated randomly.
    #[serde(rename = "XChacha20+Poly1305")]
    XChaCha20Poly1305,
}

/// The algorithm used to encrypt (key encryption) or derive (key agreement)
/// the value of the shared content encryption key (CEK).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral-Static key agreement using
    /// Concat KDF.
    ///
    /// Uses Direct Key Agreement — a key agreement algorithm is used to agree
    /// upon the CEK value.
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
    ///
    /// Uses Key Agreement with Key Wrapping — a Key Management Mode in which
    /// a key agreement algorithm is used to agree upon a symmetric key used
    /// to encrypt the CEK value to the intended recipient using a symmetric
    /// key wrapping algorithm.
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    /// Elliptic Curve Integrated Encryption Scheme for secp256k1.
    /// Uses AES 256 GCM and HKDF-SHA256.
    #[serde(rename = "ECIES-ES256K")]
    EciesEs256K,
}

/// The compression algorithm applied to the plaintext before encryption.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Zip {
    /// DEFLATE compression algorithm.
    #[default]
    #[serde(rename = "DEF")]
    Deflate,
}

#[cfg(test)]
mod test {
    use ed25519_dalek::PUBLIC_KEY_LENGTH;
    use rand::rngs::OsRng;
    use sha2::Digest;

    use super::*;

    // Use top-level encrypt method to shortcut using the builder
    #[tokio::test]
    async fn simple() {
        let key_store = X25519::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = encrypt(&plaintext, public_key).expect("should encrypt");
        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // Compact serialization/deserialization
    #[tokio::test]
    async fn compact() {
        let key_store = X25519::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = encrypt(&plaintext, public_key).expect("should encrypt");

        // serialize/deserialize
        let compact_jwe = jwe.encode().expect("should encode jwe");
        let jwe: Jwe = compact_jwe.parse().expect("should parse");

        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn default() {
        let key_store = X25519::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ecdh_es_a256kw() {
        let key_store = X25519::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = JweBuilder::new()
            .content_algorithm(ContentAlgorithm::A256Gcm)
            .key_algorithm(KeyAlgorithm::EcdhEsA256Kw)
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ed25519() {
        let key_store = Ed25519::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // derive X25519 keypair from Ed25519 keypair (reverse of XEdDSA)
    // XEdDSA resources:
    // - https://signal.org/docs/specifications/xeddsa
    // - https://github.com/Zentro/lambx
    // - https://codeberg.org/SpotNuts/xeddsa
    #[test]
    fn edx25519() {
        const ALICE_SECRET: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";
        const ALICE_PUBLIC: &str = "RW-Q0fO2oECyLs4rZDZZo4p6b7pu7UF2eu9JBsktDco";

        let alice_secret: [u8; PUBLIC_KEY_LENGTH] =
            Base64UrlUnpadded::decode_vec(ALICE_SECRET).unwrap().try_into().unwrap();
        let alice_public: [u8; PUBLIC_KEY_LENGTH] =
            Base64UrlUnpadded::decode_vec(ALICE_PUBLIC).unwrap().try_into().unwrap();

        let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::thread_rng());
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

        // SENDER: diffie-hellman using Alice public -> montgomery
        let alice_verifier = ed25519_dalek::VerifyingKey::from_bytes(&alice_public).unwrap();
        let alice_montgomery = alice_verifier.to_montgomery();
        let ephemeral_dh = ephemeral_secret.diffie_hellman(&alice_montgomery.to_bytes().into());

        // RECEIVER: diffie-hellman using ephemeral public
        let hash = sha2::Sha512::digest(&alice_secret);
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let alice_x_secret = x25519_dalek::StaticSecret::from(hashed);
        let alice_dh = alice_x_secret.diffie_hellman(&ephemeral_public);

        assert_eq!(ephemeral_dh.as_bytes(), alice_dh.as_bytes());
    }

    #[tokio::test]
    async fn ecies_es256k() {
        let key_store = Es256k::new();
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = PublicKey::from(key_store.public_key);

        let jwe = JweBuilder::new()
            .content_algorithm(ContentAlgorithm::A256Gcm)
            .key_algorithm(KeyAlgorithm::EciesEs256K)
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // // two-step encryption -> get intermediate ciphertext work product
    // #[tokio::test]
    // async fn two_step() {
    //     let key_store = X25519::new();
    //     let plaintext = "The true sign of intelligence is not knowledge but imagination.";
    //     let public_key = PublicKey::from(key_store.public_key);

    //     let mut builder =
    //         JweBuilder::new().key_algorithm(KeyAlgorithm::EcdhEsA256Kw).payload(&plaintext);
    //     let jwe = builder.encrypt().expect("should encrypt");

    //     let jwe = builder
    //         .add_recipient("did:example:alice#key-id", public_key)
    //         .build()
    //         .expect("should build");

    //     let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");
    //     assert_eq!(plaintext, decrypted);
    // }

    // Basic key store for testing
    struct X25519 {
        public_key: x25519_dalek::PublicKey,
        secret_key: x25519_dalek::StaticSecret,
    }

    impl X25519 {
        fn new() -> Self {
            let secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public_key = x25519_dalek::PublicKey::from(&secret_key).into();

            Self {
                public_key,
                secret_key,
            }
        }
    }

    impl Receiver for X25519 {
        fn key_id(&self) -> String {
            "did:example:alice#key-id".to_string()
        }

        async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
            let secret_key = SecretKey::from(self.secret_key.to_bytes());
            secret_key.shared_secret(sender_public)
        }
    }

    // Basic key store for testing
    struct Es256k {
        public_key: ecies::PublicKey,
        secret_key: ecies::SecretKey,
    }

    impl Es256k {
        fn new() -> Self {
            let (secret_key, public_key) = ecies::utils::generate_keypair();
            Self {
                public_key,
                secret_key,
            }
        }
    }

    impl Receiver for Es256k {
        fn key_id(&self) -> String {
            "did:example:alice#key-id".to_string()
        }

        async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
            let secret: [u8; PUBLIC_KEY_LENGTH] = self.secret_key.serialize();
            let secret_key = SecretKey::try_from(secret).expect("should convert");
            secret_key.shared_secret(sender_public)
        }
    }

    // Basic key store for testing
    struct Ed25519 {
        public_key: x25519_dalek::PublicKey,
        secret_key: x25519_dalek::StaticSecret,
    }

    impl Ed25519 {
        fn new() -> Self {
            // Ed25519 keypair
            let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let verifying_key = signing_key.verifying_key();

            // derive X25519 keypair from Ed25519 keypair
            let hash = sha2::Sha512::digest(signing_key.as_bytes());
            let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
            hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);

            let secret_key = x25519_dalek::StaticSecret::from(hashed);
            let public_key =
                x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());

            Self {
                public_key,
                secret_key,
            }
        }
    }

    impl Receiver for Ed25519 {
        fn key_id(&self) -> String {
            "did:example:alice#key-id".to_string()
        }

        async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
            let secret_key = SecretKey::from(self.secret_key.to_bytes());
            secret_key.shared_secret(sender_public)
        }
    }
}
