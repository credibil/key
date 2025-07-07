//! # DID Web with Verifiable History
//!
//! The `did:webvh` method is an enhanced version of the `did:web` method that
//! includes the ability to resolve a full history of the DID document through
//! a chain of updates.
//!
//! See: <https://identity.foundation/didwebvh/next/>

mod create;
mod deactivate;
mod did;
mod resolve;
mod update;
mod verify;

use chrono::{DateTime, Utc};
pub use create::{CreateBuilder, CreateResult};
use credibil_ecc::Algorithm;
// use crate::provider::{Signer, VerifyBy};
use credibil_ecc::Signer;
use credibil_jose::PublicKeyJwk;
pub use deactivate::{DeactivateBuilder, DeactivateResult};
pub use did::*;
use multibase::Base;
pub use resolve::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
pub use update::{UpdateBuilder, UpdateResult};
use uuid::Uuid;
pub use verify::*;

use crate::Document;
use crate::proof::Binding;

/// Placeholder for the self-certifying identifier (SCID) in a DID URL.
///
/// Gets replaced by the generated SCID when constructing a DID document and
/// log entry.
pub const SCID: &str = "{SCID}";

pub(crate) const VERSION: &str = "0.5";

/// A `DidLog` is a set of log entries for a DID document.
pub type DidLog = Vec<LogEntry>;

/// `LogEntry` is an entry in the `did.jsonl` log file denoting the
/// sequential changes to a DID document.
///
/// <https://identity.foundation/didwebvh/#the-did-log-file>
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    /// DID version number starting at 1 and incrementing by one per DID
    /// version, a literal dash `-`, and the `entryHash`.
    pub version_id: String,

    /// A UTC timestamp in ISO 8601 format.
    pub version_time: DateTime<Utc>,

    /// Log entry parameters.
    pub parameters: Parameters,

    /// The resolved DID document for this version.
    pub state: Document,

    /// Signed data integrity proof.
    ///
    /// Note that in the final construction of a DID log entry, the `proof` is
    /// required. However, it is not required when constructing the hash of the
    /// log entry so is made skippable here here to support the build algorithm.
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub proof: Vec<Binding>,
}

impl LogEntry {
    /// Generate a log entry hash.
    ///
    /// # Errors
    ///
    /// Will return an error if the entry fails serialization.
    pub fn hash(&self) -> anyhow::Result<String> {
        let entry = serde_json_canonicalizer::to_string(self)?;
        let digest = sha2::Sha256::digest(entry.as_bytes());
        let hash = multibase::encode(Base::Base58Btc, digest.as_slice());
        Ok(hash)
    }

    /// Verify the hash of the log entry.
    ///
    /// # Errors
    ///
    /// Will return an error if the version ID has an unexpected format or if
    /// the hash does not match the hash computed from the previous log entry.
    pub fn verify_hash(&self, previous_version: &str) -> anyhow::Result<()> {
        let parts = self.version_id.split('-').collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("log entry version id has an unexpected format"));
        }
        let mut prev_version_entry = self.clone();
        prev_version_entry.proof = Vec::new();
        prev_version_entry.version_id = previous_version.to_string();
        let hash = prev_version_entry.hash()?;
        if hash != parts[1] {
            return Err(anyhow::anyhow!("log entry hash does not match version id"));
        }
        Ok(())
    }

    /// Construct a controller's data integrity proof for the log entry.
    ///
    /// # Errors
    ///
    /// Will return an error if the signer algorithm is not `EdDSA` or if the
    /// proof structure cannot be serialized.
    pub async fn sign(&mut self, signer: &impl Signer) -> anyhow::Result<()> {
        let proof = self.proof(signer).await?;
        self.proof.push(proof);
        Ok(())
    }

    /// Construct a proof from a DID log entry.
    ///
    /// This function can be used to construct a controller's proof or a
    /// witness's proof. For convenience, the `sign` method will construct a
    /// proof and add it to the log entry and should be used instead of this
    /// method directly for a controller's proof.
    ///
    /// # Errors
    ///
    /// Will return an error if the signer algorithm is not `EdDSA` or if the
    /// proof structure cannot be serialized.
    pub async fn proof(&self, signer: &impl Signer) -> anyhow::Result<Binding> {
        let alg = signer.algorithm().await?;
        if alg != Algorithm::EdDSA {
            return Err(anyhow::anyhow!("signing algorithm must be Ed25519 (pure EdDSA)"));
        }
        let vk = signer.verifying_key().await?;
        let multi = PublicKeyJwk::from_bytes(&vk.to_bytes())?.to_multibase()?;

        let config = Binding {
            id: Some(format!("urn:uuid:{}", Uuid::new_v4())),
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: Some("eddsa-jcs-2022".to_string()),
            verification_method: format!("did:key:{multi}#{multi}"),
            created: Some(Utc::now()),
            proof_purpose: "assertionMethod".to_string(),
            ..Binding::default()
        };
        let config_data = serde_json_canonicalizer::to_string(&config)?;
        let config_hash = sha2::Sha256::digest(config_data.as_bytes());

        let data = serde_json_canonicalizer::to_string(self)?;
        let data_hash = sha2::Sha256::digest(data.as_bytes());

        let payload_bytes = [config_hash.as_slice(), data_hash.as_slice()].concat();
        let signer = signer.sign(&payload_bytes).await;
        let value = multibase::encode(Base::Base58Btc, signer);

        let mut proof = config.clone();
        proof.proof_value = Some(value);
        Ok(proof)
    }
}

/// Parameters for a DID log entry.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    /// The `did:webvh` specification version to use when processing a DID's
    /// log file.
    pub method: String,

    /// The value of the self-certifying identifier (SCID) for this DID.
    pub scid: String,

    /// An array of public keys associated with private keys authorized to sign
    /// log entries for this DID. Multikey format.
    pub update_keys: Vec<String>,

    /// Can the DID be renamed and hosted on a different domain?
    pub portable: bool,

    /// Hashes of public keys that may be added to the update keys in subsequent
    /// key rotation operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Vec<String>>,

    /// Parameters for declaring witnesses for the DID and the process for
    /// updating the DID via collaboration with witnesses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Witness>,

    /// Indicator of whether the DID has been deactivated.
    pub deactivated: bool,

    /// Maximum time in seconds the DID should be cached before a full
    /// resolution must be performed.
    pub ttl: u64,
}

/// A list of IDs of witnesses and their contribution to verification of changes
/// to the DID document.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// The total of the weights of witnesses required to approve a change.
    pub threshold: u64,

    /// The list of witnesses and their contributing weights.
    pub witnesses: Vec<WitnessWeight>,
}

impl From<Witness> for Value {
    fn from(val: Witness) -> Self {
        serde_json::to_value(val).unwrap_or_default()
    }
}

/// The weight a witness contributes to the approval of a DID update.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WitnessWeight {
    /// The DID of the witness using the `did:key` method.
    pub id: String,

    /// The weight of the witness.
    pub weight: u64,
}

/// Entry in the `did-witness.json` file.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WitnessEntry {
    /// Version ID of the DID log entry to which the witnesses' proof applies.
    pub version_id: String,

    /// Witnesses' proof of the DID log entry using the `eddsa-jcs-2022`
    /// cryptosuite.
    pub proof: Vec<Binding>,
}
