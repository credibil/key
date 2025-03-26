//! # W3C Data Integrity Proof
//! 
//! [W3C Data Integrity 1.0 Report](https://www.w3.org/community/reports/credentials/CG-FINAL-data-integrity-20220722)

use std::convert::Infallible;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// To be verifiable, a credential must contain at least one proof mechanism,
/// and details necessary to evaluate that proof.
///
/// A proof may be external (an enveloping proof) or internal (an embedded
/// proof).
///
/// Enveloping proofs are implemented using JOSE and COSE, while embedded proofs
/// are implemented using the `Proof` object described here.
/// 
/// The `proof_value` field is required and its value is computed using a
/// cryptosuite algorithm as specified in
/// [Data Integrity EdDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-eddsa).
/// Those algorithms describe the process whereby a configuration or options
/// object is used. This is the same structure as the `proof` object without the
/// `proof_value` field. Hence the field being set as optional on this struct.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
#[allow(clippy::struct_field_names)]
pub struct Proof {
    /// An optional identifier for the proof. MUST be a URL, such as a UUID as a
    /// URN e.g. "`urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5`".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The specific proof type. MUST map to a URL. Examples include
    /// "`DataIntegrityProof`" and "`Ed25519Signature2020`". The type determines
    /// the other fields required to secure and verify the proof.
    ///
    /// When set to "`DataIntegrityProof`", the `cryptosuite` and the
    /// `proofValue` properties MUST be set.
    #[serde(rename = "type")]
    pub type_: String,

    /// The value of the cryptosuite property identifies the cryptographic
    /// suite. If subtypes are supported, it MUST be the <https://w3id.org/security#cryptosuiteString>
    /// subtype of string.
    ///
    /// For example, 'ecdsa-rdfc-2019', 'eddsa-2022'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,

    /// The reason for the proof. MUST map to a URL. The proof purpose acts as a
    /// safeguard to prevent the proof from being misused.
    pub proof_purpose: String,

    /// Used to verify the proof. MUST map to a URL. For example, a link to a
    /// public key that is used by a verifier during the verification
    /// process. e.g did:example:123456789abcdefghi#keys-1.
    pub verification_method: String,

    /// The date-time the proof was created. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// The date-time the proof expires. MUST be an XMLSCHEMA11-2 date-time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,

    /// One or more security domains in which the proof is meant to be used.
    /// MUST be either a string, or a set of strings. SHOULD be used by the
    /// verifier to ensure the proof is used in the correct security domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<OneOrMany<String>>,

    /// Used to mitigate replay attacks. SHOULD be included if a domain is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    /// Contains the data needed to verify the proof using the
    /// verificationMethod specified. MUST be a MULTIBASE-encoded binary
    /// value.
    /// 
    /// This field is required for on a proof object and should be omitted on
    /// a proof configuration object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,

    /// Each value identifies another data integrity proof that MUST verify
    /// before the current proof is processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_proof: Option<OneOrMany<String>>,

    /// Supplied by the proof creator. Can be used to increase privacy by
    /// decreasing linkability that results from deterministically generated
    /// signatures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    //---
    // /// Proof-specific additional fields.
    // #[serde(flatten)]
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub extra: Option<HashMap<String, Value>>,
}

// Unused, but required by 'option_flexvec' deserializer FromStr trait
impl FromStr for Proof {
    type Err = Infallible;

    fn from_str(_: &str) -> anyhow::Result<Self, Self::Err> {
        unimplemented!("Proof::from_str")
    }
}

/// `OneOrMany` allows serde to serialize/deserialize a single object or a set of
/// objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    /// A single object.
    One(T),
    /// A set of objects.
    Many(Vec<T>),
}

impl<T: Default> Default for OneOrMany<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T: Clone> OneOrMany<T> {
    /// Convert the quota to a vector.
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

impl<T> From<T> for OneOrMany<T> {
    fn from(value: T) -> Self {
        Self::One(value)
    }
}

impl<T> From<Vec<T>> for OneOrMany<T> {
    fn from(value: Vec<T>) -> Self {
        Self::Many(value)
    }
}
