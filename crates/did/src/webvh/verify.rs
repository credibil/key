//! Verification and validation functions for `did:webvh` log entries and
//! information referenced in the log parameters.

use anyhow::bail;
use credibil_jose::PublicKeyJwk;
use sha2::Digest;

use super::{LogEntry, Witness, WitnessEntry};
use crate::proof::Binding;

/// Verify the controller's proofs in a log entry.
///
/// Requires a DID resolver to fetch a DID document and find the verification
/// method referenced in the proof.
///
/// # Errors
/// Will return an error if any of the proofs on the log entry are invalid.
pub async fn verify_proofs(log_entry: &LogEntry) -> anyhow::Result<()> {
    if log_entry.proof.is_empty() {
        bail!("log entry has no proof");
    }

    for proof in &log_entry.proof {
        verify_proof(log_entry, proof, &ProofSigner::Controller)?;
    }
    Ok(())
}

/// Type of signer for a proof.
pub enum ProofSigner {
    /// The DID controller is the signer.
    Controller,
    /// A witness is the signer.
    Witness,
}

/// Verify a single proof for a log entry.
///
/// The proof can be on the log entry itself - that is the proof from the DID
/// controller or it could be a proof from a witness.
///
/// Requires a DID resolver to fetch a DID document and find the verification
/// method referenced in the proof.
///
/// # Errors
/// Will return an error if the proof is invalid.
pub fn verify_proof(
    log_entry: &LogEntry, proof: &Binding, signer: &ProofSigner,
) -> anyhow::Result<()> {
    let mut unsigned_entry = log_entry.clone();
    if matches!(signer, ProofSigner::Controller) {
        unsigned_entry.proof = Vec::new();
    }
    let unsigned_data = serde_json_canonicalizer::to_string(&unsigned_entry)?;
    let unsigned_hash = sha2::Sha256::digest(unsigned_data.as_bytes());

    let Some(proof_value) = &proof.proof_value else {
        bail!("proof value is missing");
    };
    if proof.type_ != "DataIntegrityProof" {
        bail!("unsupported proof type {} - must be 'DataIntegrityProof'", proof.type_);
    }
    if proof.proof_purpose != "authentication" && proof.proof_purpose != "assertionMethod" {
        bail!(
            "unsupported proof purpose {} - must be 'authentication' or 'assertionMethod",
            proof.proof_purpose
        );
    }
    if proof.cryptosuite != Some("eddsa-jcs-2022".to_string()) {
        bail!(
            "unsupported cryptosuite {} - must be 'eddsa-jcs-2022'",
            proof.cryptosuite.as_deref().unwrap_or("")
        );
    }

    let parts = proof.verification_method.split('#').collect::<Vec<&str>>();
    if parts.len() != 2 {
        bail!("verification method id has an unexpected format");
    }
    let verification_key = parts[1].to_string();

    // If we are verifying a controller's proof, the verification method public
    // key must be authorized to update log entries unless the proof is for a
    // deactivated log entry.
    if !log_entry.parameters.deactivated {
        match signer {
            ProofSigner::Controller => {
                if !log_entry.parameters.update_keys.contains(&verification_key) {
                    bail!("verification method is not authorized to update the log entry");
                }
            }
            ProofSigner::Witness => {}
        }
    }

    // Verify the signature.
    let mut config = proof.clone();
    config.proof_value = None;
    let config_data = serde_json_canonicalizer::to_string(&config)?;
    let config_hash = sha2::Sha256::digest(config_data.as_bytes());
    let payload = [config_hash.as_slice(), unsigned_hash.as_slice()].concat();
    let (base, signature) = multibase::decode(proof_value)?;
    if base != multibase::Base::Base58Btc {
        bail!("unsupported multibase encoding");
    }
    let key = PublicKeyJwk::from_multibase(&verification_key)?;
    key.verify_bytes(&payload, &signature)?;
    Ok(())
}

/// Validate a set of witness entries.
///
/// Note: This function just validates the witness entries in the log parameters
/// meet structural requiremnents. It does not verify the proofs supplied by
/// the witnesses. See `verify_witness` for that.
///
/// # Errors
///
/// Will fail if the witness threshold is zero, the witness list is empty,
/// the contribution (weight) of a witness is zero, or the sum of
/// contributions would never reach the threshold.
pub fn validate_witness(witness: &Witness) -> anyhow::Result<()> {
    if witness.threshold == 0 {
        bail!("witness threshold must be greater than zero.");
    }
    if witness.witnesses.is_empty() {
        bail!("witness witness list must not be empty.");
    }
    let mut total_weight = 0;
    for w in &witness.witnesses {
        if !w.id.starts_with("did:key:") {
            bail!("witness id must be a 'did:key:'.");
        }
        if w.weight == 0 {
            bail!("witness weight must be greater than zero.");
        }
        total_weight += w.weight;
    }
    if total_weight < witness.threshold {
        bail!("total witness weight must be greater than or equal to the threshold.");
    }
    Ok(())
}

/// Verify a set of witness entries.
///
/// Requires a resolver for the witness proof signatures.
///
/// This method will not fail if a single witness proof is invalid or a proof is
/// provided for witness that does not exist in the entry's list of witnesses.
/// Instead it will omit that witness from the total weight calculation.
///
/// # Errors
///
/// Will fail if the total weight of witness proofs does not meet the threshold.
/// Will also fail if called for a log entry that has no witness parameters.
pub async fn verify_witness(
    log_entry: &LogEntry, witnesses: &[WitnessEntry],
) -> anyhow::Result<u64> {
    let Some(witness_weights) = &log_entry.parameters.witness else {
        bail!("log entry has no witness parameters");
    };
    let mut total_weight = 0;
    for witness in witnesses {
        if witness.version_id != log_entry.version_id {
            continue;
        }
        for proof in &witness.proof {
            if matches!(verify_proof(log_entry, proof, &ProofSigner::Witness), Ok(()))
                && let Some(witness_weight) =
                    witness_weights.witnesses.iter().find(|w| w.id == proof.verification_method)
            {
                total_weight += witness_weight.weight;
            }
        }
    }
    if total_weight < witness_weights.threshold {
        bail!("total witness weight does not meet the threshold");
    }
    Ok(total_weight)
}
