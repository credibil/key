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

use anyhow::{Result, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_ecc::{AlgAlgorithm, EncAlgorithm, PublicKey};
pub use decrypt::{decrypt, decrypt_bytes};
use encrypt::JweBuilder;
pub use encrypt::{Recipient, ecdh_a256kw, ecies_es256k};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwk::PublicKeyJwk;

/// Encrypt plaintext using the defaults of A256GCM content encryption and
/// ECDH-ES key agreement algorithms where the payload is a JSON-serializable
/// object.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: T, recipient_public: PublicKey) -> Result<Jwe> {
    JweBuilder::new()
        .content_algorithm(EncAlgorithm::A256Gcm)
        .key_algorithm(AlgAlgorithm::EcdhEs)
        .payload(plaintext)
        .add_recipient("", recipient_public)
        .build()
}

/// Encrypt plaintext using the defaults of A256GCM content encryption and
/// ECDH-ES key agreement algorithms where the payload is bytes.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt_bytes(plaintext: &[u8], recipient_public: PublicKey) -> Result<Jwe> {
    JweBuilder::new()
        .content_algorithm(EncAlgorithm::A256Gcm)
        .key_algorithm(AlgAlgorithm::EcdhEs)
        .payload_bytes(plaintext)
        .add_recipient("", recipient_public)
        .build()
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
    pub alg: Option<AlgAlgorithm>,

    /// The algorithm used to perform authenticated encryption on the plaintext
    /// to produce the ciphertext and the Authentication Tag. MUST be an AEAD
    /// algorithm.
    pub enc: EncAlgorithm,
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
    pub alg: AlgAlgorithm,

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
    use std::sync::LazyLock;

    use anyhow::Result;
    use credibil_core::datastore::Datastore;
    use credibil_ecc::{Curve, Keyring, Receiver};
    use dashmap::DashMap;

    use super::*;

    // Use top-level encrypt method to shortcut using the builder
    #[tokio::test]
    async fn simple() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::X25519).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = encrypt(plaintext, pk).expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // Compact serialization/deserialization
    #[tokio::test]
    async fn compact() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::X25519).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = encrypt(plaintext, pk).expect("should encrypt");

        // serialize/deserialize
        let compact_jwe = jwe.encode().expect("should encode");
        let jwe: Jwe = compact_jwe.parse().expect("should parse");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn default() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::X25519).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", pk)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ecdh_es_a256kw() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::X25519).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = JweBuilder::new()
            .content_algorithm(EncAlgorithm::A256Gcm)
            .key_algorithm(AlgAlgorithm::EcdhEsA256Kw)
            .payload(&plaintext)
            .add_recipient("key-1", pk)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ed25519() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::Ed25519).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("key-1", pk)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ecies_es256k() {
        let entry = Keyring::generate(&Store, "owner", "key-1", Curve::Es256K).await.unwrap();
        let public_key = entry.public_key().await.expect("should get key");
        let pk = PublicKey::try_from(public_key).expect("should convert");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let jwe = JweBuilder::new()
            .content_algorithm(EncAlgorithm::A256Gcm)
            .key_algorithm(AlgAlgorithm::EciesEs256K)
            .payload(&plaintext)
            .add_recipient("key-1", pk)
            .build()
            .expect("should encrypt");

        let decrypted: String = decrypt(&jwe, &entry).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

    #[derive(Clone, Debug)]
    struct Store;

    impl Datastore for Store {
        async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
            let key = format!("{owner}-{partition}-{key}");
            STORE.insert(key, data.to_vec());
            Ok(())
        }

        async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
            let key = format!("{owner}-{partition}-{key}");
            let Some(bytes) = STORE.get(&key) else {
                return Ok(None);
            };
            Ok(Some(bytes.to_vec()))
        }

        async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
            let key = format!("{owner}-{partition}-{key}");
            STORE.remove(&key);
            Ok(())
        }

        async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
            let all = STORE
                .iter()
                .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
                .map(|r| (r.key().to_string(), r.value().clone()))
                .collect::<Vec<_>>();
            Ok(all)
        }
    }
}
