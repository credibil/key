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
use aes_kw::Kek;
use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::jose::jwk::PublicKeyJwk;
use crate::{Cipher, Curve, KeyType};

/// Recipient information required when generating a JWE.
pub struct RecipientInfo {
    /// The fully qualified key ID (e.g. did:example:abc#encryption-key-id) of
    /// the public key to be used to encrypt the content encryption key (CEK).
    pub key_id: String,

    /// The recipient's public key, in bytes, to be used to encrypt the content
    /// encryption key (CEK).
    pub public_key: [u8; 32],

    /// Optional additional information to include in the recipients header.
    pub header: Option<Value>,
}

/// Encrypt plaintext and return a JWE.
/// 
/// # Errors
/// LATER: document errors
pub fn encrypt2<T: Serialize + Send>(plaintext: &T, recipients: &[RecipientInfo]) -> Result<Jwe> {
    let protected = Protected {
        enc: DataAlgorithm::A256Gcm,
        alg: None,
        epk: None,
    };

    let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
    let cek = Aes256Gcm::generate_key(&mut OsRng);
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);

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
        let kek = Kek::from(*shared_key.as_bytes());
        let wrapped_key = kek.wrap_vec(&cek).map_err(|e| anyhow!("issue wrapping cek: {e}"))?;
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
                extra: r.header.clone(),
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

/// Encrypt plaintext and return a JWE.
///
/// N.B. We currently only support ECDH-ES key agreement and A256GCM
/// content encryption.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub fn encrypt<T: Serialize + Send>(plaintext: &T, recipient: &RecipientInfo) -> Result<Jwe> {
    // generate a CEK to encrypt payload
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // when using Direct Key Agreement, the CEK is the DH shared secret
    // let recipient_key: [u8; 32] = recipient_public.try_into()?;
    // let recipient_public = PublicKey::from(recipient_key);
    let recipient_public = PublicKey::from(recipient.public_key);
    let cek = ephemeral_secret.diffie_hellman(&recipient_public);

    let protected = Protected {
        enc: DataAlgorithm::A256Gcm,
        alg: None,
        epk: None,
    };
    let iv = Aes256Gcm::generate_nonce(&mut OsRng);
    let aad = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);

    // encrypt plaintext using the CEK, initialization vector, and AAD
    // - generates ciphertext and a JWE Authentication Tag
    let mut buffer = serde_json::to_vec(plaintext)?;
    let key = Key::<Aes256Gcm>::from_slice(cek.as_bytes());
    let tag = Aes256Gcm::new(key)
        .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    // recipient header
    let header = Header {
        alg: KeyAlgorithm::EcdhEs,
        kid: None,
        epk: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(ephemeral_public.as_bytes()),
            ..PublicKeyJwk::default()
        },
        extra: recipient.header.clone(),
        apu: None,
        apv: None,
    };

    Ok(Jwe {
        protected,
        unprotected: None,
        recipients: Recipients::One(KeyEncryption {
            header,
            // when using direct, the JWE Encrypted Key is an empty octet sequence
            encrypted_key: Base64UrlUnpadded::encode_string(&[0; 32]),
        }),
        iv: Base64UrlUnpadded::encode_string(&iv),
        ciphertext: Base64UrlUnpadded::encode_string(&buffer),
        tag: Base64UrlUnpadded::encode_string(&tag),
        aad,
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

        // add recipient "epk" to protected header
        let mut protected = self.protected.clone();
        protected.epk = Some(recipient.header.epk.clone());

        let protected = &protected.to_string();
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

        let protected = Protected::from_str(parts[0])?;
        let enc = protected.enc;
        let alg = protected.alg.unwrap_or_default();
        let epk = protected.epk.unwrap_or_default();

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
    pub enc: DataAlgorithm,

    /// The ephemeral public key created by the originator for use in key
    /// agreement algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<PublicKeyJwk>,
    //
    // /// Key agreement `PartyUInfo` value, used to generate the shared key.
    // /// Contains producer information as a base64url string.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub apu: Option<String>,

    // /// Key agreement `PartyVInfo` value, used to generate the shared key.
    // /// Contains producer information as a base64url string.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub apv: Option<String>,
}

/// Serialize Header to base64 encoded string
impl Display for Protected {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = serde_json::to_vec(&self).map_err(|_| fmt::Error)?;
        write!(f, "{}", Base64UrlUnpadded::encode_string(&bytes))
    }
}

impl FromStr for Protected {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes =
            Base64UrlUnpadded::decode_vec(s).map_err(|e| anyhow!("issue decoding header: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("issue deserializing header: {e}"))
    }
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

/// Contains information specific to a single recipient.
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

    /// Addtional, user-provided header values.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
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
pub enum DataAlgorithm {
    /// AES GCM using a 128-bit key.
    #[default]
    #[serde(rename = "A256GCM")]
    A256Gcm,

    /// AES 256 CTR.
    #[serde(rename = "A256CTR")]
    Aes256Ctr,

    /// XSalsa20-Poly1305
    #[serde(rename = "XSalsa20-Poly1305")]
    XSalsa20Poly1305,
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

        let recipient = RecipientInfo {
            key_id: "".to_string(),
            public_key,
            header: None,
        };

        let jwe = encrypt(&plaintext, &recipient).expect("should encrypt");
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
