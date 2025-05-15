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
use credibil_se::{AlgAlgorithm, EncAlgorithm, PublicKey, Receiver};
use encrypt::JweBuilder;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwk::PublicKeyJwk;
pub use encrypt::{Recipient, ecdh_a256kw, ecies_es256k};

/// Encrypt plaintext using the defaults of A256GCM content encryption and
/// ECDH-ES key agreement algorithms.
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

/// Encrypt plaintext where the payload is in bytes.
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

/// Decrypt the JWE and return the plaintext.
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt<T>(jwe: &Jwe, receiver: &impl Receiver) -> Result<T>
where
    T: DeserializeOwned,
{
    decrypt::decrypt(jwe, receiver).await
}

/// Decrypt the JWE where the encoded payload is expected to be bytes.
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt_bytes(jwe: &Jwe, receiver: &impl Receiver) -> Result<Vec<u8>> {
    decrypt::decrypt_bytes(jwe, receiver).await
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
    use credibil_se::Curve;
    use test_kms::{Keyring, KeyringReceiver};

    use super::*;

    // Use top-level encrypt method to shortcut using the builder
    #[tokio::test]
    async fn simple() {
        let mut key_store = Keyring::new("simple").await.expect("create keyring");
        key_store.add(&Curve::X25519, "encription-key-1").await.expect("add key");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = key_store.public_key("encription-key-1").await.expect("get public key");
        let jwe = encrypt(&plaintext, public_key).expect("should encrypt");

        let receiver = KeyringReceiver::new("encription-key-1", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // Compact serialization/deserialization
    #[tokio::test]
    async fn compact() {
        let mut key_store = Keyring::new("compact").await.expect("create keyring");
        key_store.add(&Curve::X25519, "encription-key-1").await.expect("add key");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = key_store.public_key("encription-key-1").await.expect("get public key");
        let jwe = encrypt(&plaintext, public_key).expect("should encrypt");

        // serialize/deserialize
        let compact_jwe = jwe.encode().expect("should encode jwe");
        let jwe: Jwe = compact_jwe.parse().expect("should parse");

        let receiver = KeyringReceiver::new("encription-key-1", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn default() {
        let mut key_store = Keyring::new("default").await.expect("create keyring");
        key_store.add(&Curve::X25519, "encription-key-1").await.expect("add key");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key = key_store.public_key("encription-key-1").await.expect("get public key");

        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let receiver = KeyringReceiver::new("encription-key-1", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ecdh_es_a256kw() {
        let mut key_store = Keyring::new("ecdh_es_a256kw").await.expect("create keyring");
        key_store.add(&Curve::X25519, "did:example:alice#key-id").await.expect("add key");

        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key =
            key_store.public_key("did:example:alice#key-id").await.expect("get public key");

        let jwe = JweBuilder::new()
            .content_algorithm(EncAlgorithm::A256Gcm)
            .key_algorithm(AlgAlgorithm::EcdhEsA256Kw)
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let receiver = KeyringReceiver::new("did:example:alice#key-id", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ed25519() {
        let mut key_store = Keyring::new("ed25519").await.expect("create keyring");
        key_store.add(&Curve::Ed25519, "did:example:alice#key-id").await.expect("add key");
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key =
            key_store.public_key("did:example:alice#key-id").await.expect("get public key");

        let jwe = JweBuilder::new()
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let receiver = KeyringReceiver::new("did:example:alice#key-id", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }

    #[tokio::test]
    async fn ecies_es256k() {
        let mut key_store = Keyring::new("ecies_es256k").await.expect("create keyring");
        key_store.add(&Curve::Es256K, "did:example:alice#key-id").await.expect("add key");
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";
        let public_key =
            key_store.public_key("did:example:alice#key-id").await.expect("get public key");

        let jwe = JweBuilder::new()
            .content_algorithm(EncAlgorithm::A256Gcm)
            .key_algorithm(AlgAlgorithm::EciesEs256K)
            .payload(&plaintext)
            .add_recipient("did:example:alice#key-id", public_key)
            .build()
            .expect("should encrypt");

        let receiver = KeyringReceiver::new("did:example:alice#key-id", key_store.clone());
        let decrypted: String = decrypt(&jwe, &receiver).await.expect("should decrypt");
        assert_eq!(plaintext, decrypted);
    }
}
