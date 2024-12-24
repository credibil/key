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

use std::fmt::{self, Display};
use std::str::FromStr;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::jose::jwk::PublicKeyJwk;
use crate::{Cipher, Curve, KeyType};

/// Encrypt plaintext and return a JWE.
///
/// N.B. We currently only support ECDH-ES key agreement and A256GCM
/// content encryption.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: &T, recipient_public: &[u8]) -> Result<Jwe> {
    // generate a CEK to encrypt payload
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // ...when using Direct Key Agreement, the CEK is the DH shared secret
    let recipient_key: [u8; 32] = recipient_public.try_into()?;
    let recipient_public = PublicKey::from(recipient_key);
    let cek = ephemeral_secret.diffie_hellman(&recipient_public);

    // ...when using direct, the JWE Encrypted Key is an empty octet sequence
    let encrypted_key = Base64UrlUnpadded::encode_string(&[0; 32]);

    // JWE Protected Header
    let protected = Header {
        alg: CekAlgorithm::EcdhEs,
        enc: EncryptionAlgorithm::A256Gcm,
        // FIXME: set these values to something meaningful
        apu: Base64UrlUnpadded::encode_string(b"Alice"),
        apv: Base64UrlUnpadded::encode_string(b"Bob"),
        epk: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
            ..PublicKeyJwk::default()
        },
    };

    // generate initialization vector (nonce)for content encryption
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);

    // JWE Additional Authenticated Data is the encoded JWE Protected Header
    let aad = &Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);

    // encrypt plaintext using the CEK, initialization vector, and AAD
    // - generates ciphertext and a JWE Authentication Tag
    let mut buffer = serde_json::to_vec(plaintext)?;
    let key = Key::<Aes256Gcm>::from_slice(cek.as_bytes());
    let tag = Aes256Gcm::new(key)
        .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    Ok(Jwe {
        protected,
        encrypted_key,
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&buffer),
        tag: Base64UrlUnpadded::encode_string(&tag),
        ..Jwe::default()
    })
}

/// Decrypt the JWE and return the plaintext.
///
/// N.B. We currently only support ECDH-ES key agreement and A256GCM
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt<T: DeserializeOwned>(jwe: &Jwe, cipher: &impl Cipher) -> Result<T> {
    // get sender's ephemeral public key (used in key agreement)
    let sender_public = Base64UrlUnpadded::decode_vec(&jwe.protected.epk.x)
        .map_err(|e| anyhow!("issue decoding sender public key `x`: {e}"))?;
    let sender_key: [u8; 32] = sender_public.as_slice().try_into()?;
    let sender_public = x25519_dalek::PublicKey::from(sender_key);

    // compute CEK using recipient's private key and sender's public key
    let cek = cipher.diffie_hellman(sender_public.as_bytes()).await?;

    // unpack JWE
    let iv =
        Base64UrlUnpadded::decode_vec(&jwe.iv).map_err(|e| anyhow!("issue decoding `iv`: {e}"))?;
    let tag = Base64UrlUnpadded::decode_vec(&jwe.tag)
        .map_err(|e| anyhow!("issue decoding `tag`: {e}"))?;
    let aad = jwe.protected.to_string();
    let ciphertext = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)
        .map_err(|e| anyhow!("issue decoding `ciphertext`: {e}"))?;

    // decrypt ciphertext using CEK, iv, aad, and tag
    let mut buffer = ciphertext;
    let nonce = Nonce::from_slice(&iv);
    let tag = Tag::from_slice(&tag);

    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&cek))
        .decrypt_in_place_detached(nonce, aad.as_bytes(), &mut buffer, tag)
        .map_err(|e| anyhow!("issue decrypting: {e}"))?;

    Ok(serde_json::from_slice(&buffer)?)
}

/// In JWE JSON serialization, one or more of the JWE Protected Header, JWE
/// Shared Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be
/// present.
///
/// In this case, the members of the JOSE Header are the union of the members of
/// the JWE Protected Header, JWE Shared Unprotected Header, and JWE
/// Per-Recipient Unprotected Header values that are present.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwe {
    /// JWE protected header.
    pub protected: Header,

    /// Shared unprotected header as a JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<Value>,

    /// Encrypted key, as a base64Url encoded string.
    /// When using Direct Key Agreement or Direct Encryption, this will be the
    /// empty octet sequence.
    pub encrypted_key: String,

    /// AAD value, base64url encoded. Not used for JWE Compact Serialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,

    /// Initialization vector (nonce), as a base64Url encoded string.
    pub iv: String,

    /// Ciphertext, as a base64Url encoded string.
    pub ciphertext: String,

    /// Authentication tag resulting from the encryption, as a base64Url encoded
    /// string.
    pub tag: String,
    //
    // /// Recipients array contains information specific to a single
    // /// recipient.
    // recipients: Quota<Recipient>,
}

/// Compact Serialization
///     base64(JWE Protected Header) + '.'
///     + base64(JWE Encrypted Key) + '.'
///     + base64(JWE Initialization Vector) + '.'
///     + base64(JWE Ciphertext) + '.'
///     + base64(JWE Authentication Tag)
impl Display for Jwe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let protected = &self.protected.to_string();
        let encrypted_key = &self.encrypted_key;
        let iv = &self.iv;
        let ciphertext = &self.ciphertext;
        let tag = &self.tag;

        write!(f, "{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}")
    }
}

impl FromStr for Jwe {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 5 {
            return Err(anyhow!("invalid JWE"));
        }

        Ok(Self {
            protected: Header::from_str(parts[0])?,
            encrypted_key: parts[1].to_string(),
            iv: parts[2].to_string(),
            ciphertext: parts[3].to_string(),
            tag: parts[4].to_string(),
            ..Self::default()
        })
    }
}

/// Represents the JWE header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Identifies the algorithm used to encrypt or determine the value of the
    /// content encryption key (CEK).
    pub alg: CekAlgorithm,

    /// The algorithm used to perform authenticated encryption on the plaintext
    /// to produce the ciphertext and the Authentication Tag. MUST be an AEAD
    /// algorithm.
    pub enc: EncryptionAlgorithm,

    /// Key agreement `PartyUInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apu: String,

    /// Key agreement `PartyVInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apv: String,

    /// The ephemeral public key created by the originator for use in key
    /// agreement algorithms.
    pub epk: PublicKeyJwk,
}

/// Serialize Header to base64 encoded string
impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = serde_json::to_vec(&self).map_err(|_| fmt::Error)?;
        write!(f, "{}", Base64UrlUnpadded::encode_string(&bytes))
    }
}

impl FromStr for Header {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            Base64UrlUnpadded::decode_vec(s).map_err(|e| anyhow!("issue decoding header: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("issue deserializing header: {e}"))
    }
}

/// Contains information specific to a single recipient.
/// MUST be present with exactly one array element per recipient, even if some
/// or all of the array element values are the empty JSON object "{}".
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Recipient {
    /// JWE Per-Recipient Unprotected Header.
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Header>,

    /// The recipient's JWE Encrypted Key, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_key: Option<String>,
}

/// The algorithm used to encrypt (key encryption) or derive (key agreement)
/// the value of the shared content encryption key (CEK).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CekAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral-Static key agreement using
    /// Concat KDF.
    ///
    /// Uses Direct Key Agreement — a key agreement algorithm is used to agree
    /// upon the CEK value.
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    //
    // /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
    // ///
    // /// Uses Key Agreement with Key Wrapping — a Key Management Mode in which
    // /// a key agreement algorithm is used to agree upon a symmetric key used
    // /// to encrypt the CEK value to the intended recipient using a symmetric
    // /// key wrapping algorithm.
    // #[serde(rename = "ECDH-ES+A128KW")]
    // EcdhEsA128Kw,

    // /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
    // #[serde(rename = "ECDH-ES+A192KW")]
    // EcdhEsA192Kw,

    // /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
    // #[serde(rename = "ECDH-ES+A256KW")]
    // EcdhEsA256Kw,

    // /// Elliptic Curve Integrated Encryption Scheme for secp256k1.
    // /// Uses AES 256 GCM and HKDF-SHA256.
    // #[serde(rename = "ECIES-ES256K")]
    // EciesSecp256k1,
}

/// The algorithm used to perform authenticated content encryption. That is,
/// encrypting the plaintext to produce the ciphertext and the Authentication
/// Tag. MUST be an AEAD algorithm.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES GCM using a 128-bit key.
    #[default]
    #[serde(rename = "A256GCM")]
    A256Gcm,
    //
    // /// AES 256 CTR.
    // #[serde(rename = "A256CTR")]
    // Aes256Ctr,

    // /// XSalsa20-Poly1305
    // #[serde(rename = "CHACHA20_POLY1305")]
    // ChaCha20Poly1305,
}

#[cfg(test)]
mod test {
    use super::*;

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn round_trip() {
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";

        let key_store = KeyStore::new();
        let recipient_public = key_store.public_key();

        let jwe = encrypt(&plaintext, &recipient_public).expect("should encrypt");
        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");

        assert_eq!(plaintext, decrypted);
    }

    // Basic key store for testing
    struct KeyStore {
        recipient_secret: x25519_dalek::StaticSecret,
    }

    impl KeyStore {
        fn new() -> Self {
            Self {
                recipient_secret: x25519_dalek::StaticSecret::random_from_rng(&mut OsRng),
            }
        }
    }

    impl Cipher for KeyStore {
        fn public_key(&self) -> Vec<u8> {
            x25519_dalek::PublicKey::from(&self.recipient_secret).as_bytes().to_vec()
        }

        async fn diffie_hellman(&self, sender_public: &[u8]) -> Result<Vec<u8>> {
            let sender_key: [u8; 32] = sender_public.try_into()?;
            let sender_public = x25519_dalek::PublicKey::from(sender_key);
            let shared_secret = self.recipient_secret.diffie_hellman(&sender_public);
            Ok(shared_secret.as_bytes().to_vec())
        }
    }
}
