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

mod builder;

use std::fmt::{self, Display};
use std::str::FromStr;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, Nonce, Tag};
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use self::builder::{JweBuilder, NoPayload, NoRecipients, WithPayload, WithRecipients};
use crate::jose::jwk::PublicKeyJwk;
use crate::Cipher;

/// Encrypt plaintext using the defaults of A256GCM content encryption and
/// ECDH-ES key agreement algorithms.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: &T, recipient_public: &[u8; 32]) -> Result<Jwe> {
    JweBuilder::new()
        .content_algorithm(ContentAlgorithm::A256Gcm)
        .key_algorithm(KeyAlgorithm::EcdhEs)
        .payload(plaintext)
        .add_recipient("", *recipient_public)
        .build()
}

/// Decrypt the JWE and return the plaintext.
///
/// N.B. We currently only support ECDH-ES key agreement and A256GCM
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt<T: DeserializeOwned>(jwe: &Jwe, cipher: &impl Cipher) -> Result<T> {
    let Recipients::One(recipient) = &jwe.recipients else {
        return Err(anyhow!("invalid number of recipients"));
    };

    // get sender's ephemeral public key (used in key agreement)
    let sender_public = Base64UrlUnpadded::decode_vec(&recipient.header.epk.x)
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
    let ciphertext = Base64UrlUnpadded::decode_vec(&jwe.ciphertext)
        .map_err(|e| anyhow!("issue decoding `ciphertext`: {e}"))?;

    // decrypt ciphertext using CEK, iv, aad, and tag
    let mut buffer = ciphertext;
    let nonce = Nonce::from_slice(&iv);
    let tag = Tag::from_slice(&tag);

    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&cek))
        .decrypt_in_place_detached(nonce, jwe.aad.as_bytes(), &mut buffer, tag)
        .map_err(|e| anyhow!("issue decrypting: {e}"))?;

    Ok(serde_json::from_slice(&buffer)?)
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

/// Compact Serialization. Can only be used with a single recipient.
///
/// In the JWE Compact Serialization, a JWE is represented as the concatenation:
///   base64(JWE Protected Header) + '.'
///   + base64(JWE Encrypted Key) + '.'
///   + base64(JWE Initialization Vector) + '.'
///   + base64(JWE Ciphertext) + '.'
///   + base64(JWE Authentication Tag)
impl Display for Jwe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Recipients::One(recipient) = &self.recipients else {
            return Err(fmt::Error);
        };

        // add recipient data to protected header
        let mut protected = ProtectedFlat {
            inner: self.protected.clone(),
            epk: recipient.header.epk.clone(),
        };
        protected.inner.alg = Some(recipient.header.alg.clone());

        let bytes = serde_json::to_vec(&protected).map_err(|_| fmt::Error)?;
        let protected = Base64UrlUnpadded::encode_string(&bytes);

        let encrypted_key = &recipient.encrypted_key;
        let iv = &self.iv;
        let ciphertext = &self.ciphertext;
        let tag = &self.tag;

        write!(f, "{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}")
    }
}

/// Deserialize JWE from Compact Serialization format.
impl FromStr for Jwe {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 5 {
            return Err(anyhow!("invalid JWE"));
        }

        let bytes = Base64UrlUnpadded::decode_vec(parts[0]).map_err(|_| fmt::Error)?;
        let protected: ProtectedFlat = serde_json::from_slice(&bytes).map_err(|_| fmt::Error)?;
        let enc = protected.inner.enc;
        let alg = protected.inner.alg.unwrap_or_default();
        let epk = protected.epk;

        Ok(Self {
            protected: Protected {
                enc,
                ..Protected::default()
            },
            recipients: Recipients::One(KeyEncryption {
                header: Header {
                    alg,
                    epk,
                    ..Header::default()
                },
                encrypted_key: parts[1].to_string(),
            }),
            iv: parts[2].to_string(),
            ciphertext: parts[3].to_string(),
            tag: parts[4].to_string(),
            ..Self::default()
        })
    }
}

/// Phe JWE Shareed Protected header.
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
    /// Single recipient (flattened JWE JSON syntax).
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

    /// Key agreement `PartyUInfo` value, used to generate the shared key.
    /// A base64url string containing information about the producer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,

    /// Key agreement `PartyVInfo` value, used to generate the shared key.
    /// A base64url string containing information about the recipient.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,
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
    EciesSecp256k1,
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
    //
    // /// XChaCha20-Poly1305 is a competitive alternative to AES-256-GCM because
    // /// it’s fast and constant-time without hardware acceleration (resistent
    // /// to cache-timing attacks). It also has longer nonce length to alleviate
    // /// the risk of birthday attacks when nonces are generated randomly.
    // #[serde(rename = "XChacha20+Poly1305")]
    // XChacha20Poly1305,
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
    use rand::rngs::OsRng;

    use super::*;

    // Complete
    // {
    // 	"protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    // 	"unprotected": {"jku":"https://server.example.com/keys.jwks"},
    // 	"recipients":[
    //        {
    // 			"header": {"alg":"RSA1_5","kid":"2011-04-29"},
    //         	"encrypted_key":
    //          		"UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-
    //           	kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx
    //           	GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3
    //           	YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh
    //           	cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg
    //           	wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
    // 		},
    // 		{
    // 			"header": {"alg":"A128KW","kid":"7"},
    //         	"encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
    // 		}
    // 	],
    // 	"iv": "AxY8DCtDaGlsbGljb3RoZQ",
    // 	"ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    // 	"tag": "Mz-VPPyU4RlcuYv1IwIvzw"
    // }

    // Flattened
    // {
    // 	"protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
    // 	"unprotected": {"jku":"https://server.example.com/keys.jwks"},
    // 	"header": {"alg":"A128KW","kid":"7"},
    // 	"encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
    // 	"iv": "AxY8DCtDaGlsbGljb3RoZQ",
    // 	"ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
    // 	"tag": "Mz-VPPyU4RlcuYv1IwIvzw"
    // }

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn round_trip() {
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";

        let key_store = KeyStore::new();
        let public_key: [u8; 32] = key_store.public_key().try_into().expect("should convert");

        let jwe = encrypt(&plaintext, &public_key).expect("should encrypt");
        let decrypted: String = decrypt(&jwe, &key_store).await.expect("should decrypt");

        assert_eq!(plaintext, decrypted);
    }

    // round trip: encrypt and then decrypt
    #[tokio::test]
    async fn builder() {
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";

        let key_store = KeyStore::new();
        let public_key: [u8; 32] = key_store.public_key().try_into().expect("should convert");

        let jwe = JweBuilder::new()
            // .data_algorithm(ContentAlgorithm::A256Gcm)
            // .key_algorithm(KeyAlgorithm::EcdhEs)
            .payload(&plaintext)
            .add_recipient("".to_string(), public_key)
            .build()
            .expect("should encrypt");

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
