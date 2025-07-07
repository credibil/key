//! Deactivate (revoke) operation for the `did:webvh` method.

use std::string::ToString;

use anyhow::bail;
use chrono::Utc;
use credibil_ecc::Signer;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::verify::validate_witness;
use super::{LogEntry, Witness};
use crate::Document;

/// Builder for deactivating a DID document and associated log entry (or 2
/// entries if there is key rotation).
pub struct DeactivateBuilder<S> {
    update_keys: Vec<String>,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    log: Vec<LogEntry>,
    doc: Document,

    signer: S,
}

/// Builder does not have a signer (can't build).
pub struct WithoutSigner;

/// Builder has a signer (can build).
pub struct WithSigner<'a, S: Signer>(pub &'a S);

impl DeactivateBuilder<WithoutSigner> {
    /// Crate a new `DeactivateBuilder` populated with the current log entries.
    ///
    /// It is assumed that the DID document is resolved from the last log entry
    /// otherwise an update operation should be used ahead of this.
    ///
    /// # Errors
    /// Will fail if the log entries are not populated.
    pub fn from(log: &[LogEntry]) -> anyhow::Result<Self> {
        let Some(last_entry) = log.last() else {
            bail!("log must not be empty.");
        };
        Ok(Self {
            update_keys: last_entry.parameters.update_keys.clone(),
            next_key_hashes: last_entry.parameters.next_key_hashes.clone(),
            witness: last_entry.parameters.witness.clone(),
            log: log.to_vec(),
            doc: last_entry.state.clone(),

            signer: WithoutSigner,
        })
    }

    /// Rotate the update keys.
    ///
    /// The new update keys provided, when hashed, must match the hash of the
    /// current next key hashes. If there are no next key hashes on the current
    /// log entry it is assumed no pre-rotation strategy is being used and the
    /// new update keys will be applied regardless.
    ///
    /// The `new_update_keys` parameter is a list of public keys whose private
    /// key counterparts are authorized to sign DID log entries. They should be
    /// provided in bytes format.
    ///
    /// The `new_next_keys` parameter is a list of public keys whose private key
    /// counterparts will be authorized to sign update operations on subsequent
    /// key rotations. They should be provided in multibase-encoded format
    /// (this function will calculate their hashes).
    ///
    /// If key pre-rotation is not required for future updates set
    /// `new_next_keys` to an empty list.
    ///
    /// # Note
    /// The new update keys must not be used to sign the new log entry. Only
    /// the current update keys should be used to sign the new log entry. This
    /// will be checked on the build operation.
    ///
    /// # Errors
    /// If the hashed new update keys do not match the current next key hashes
    /// an error is returned (unless there are no next key hashes on the
    /// current log entry - pre-rotation not required).
    pub fn rotate_keys(
        mut self, new_update_keys: &[&str], new_next_keys: &[&str],
    ) -> anyhow::Result<Self> {
        // Check the new update keys hash to the current next key hashes.
        if let Some(next_key_hashes) = &self.next_key_hashes {
            for new_key in new_update_keys {
                let digest = sha2::Sha256::digest(new_key.as_bytes());
                let hash = multibase::encode(Base::Base58Btc, digest.as_slice());
                if !next_key_hashes.contains(&hash) {
                    bail!("new update keys do not match current next key hashes.");
                }
            }
        }

        self.update_keys = new_update_keys.iter().map(ToString::to_string).collect();
        if new_next_keys.is_empty() {
            self.next_key_hashes = None;
        } else {
            self.next_key_hashes = Some(
                new_next_keys
                    .iter()
                    .map(|key| {
                        let digest = sha2::Sha256::digest(key.as_bytes());
                        multibase::encode(Base::Base58Btc, digest.as_slice())
                    })
                    .collect(),
            );
        }

        Ok(self)
    }

    /// Add a set of witnesses expected to provide proofs for this update.
    ///
    /// If this function is not called, the witness information from the last
    /// log entry will be used.
    ///
    /// To remove witnesses from this update, call the `remove_witness`
    /// function.
    ///
    /// # Errors
    ///
    /// Will fail if the witness threshold is zero, the witness list is empty,
    /// the contribution (weight) of a witness is zero, or the sum of
    /// contributions would never reach the threshold.
    pub fn witness(mut self, witness: &Witness) -> anyhow::Result<Self> {
        validate_witness(witness)?;
        self.witness = Some(witness.clone());
        Ok(self)
    }

    /// Remove witnesses from this update.
    #[must_use]
    pub fn remove_witness(mut self) -> Self {
        self.witness = None;
        self
    }

    /// Provide a signer to sign the log entry.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &S) -> DeactivateBuilder<WithSigner<'_, S>> {
        DeactivateBuilder {
            update_keys: self.update_keys,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            log: self.log,
            doc: self.doc,

            signer: WithSigner(signer),
        }
    }
}

impl<S: Signer> DeactivateBuilder<WithSigner<'_, S>> {
    /// Build the new log entry/entries.
    ///
    /// If the last log entry has a non-empty `next_key_hashes`, two log entries
    /// will be created: one to nullify the `next_key_hashes` and one to
    /// deactivate the DID.
    ///
    /// Provide a `Provable` `Signer` to construct a data integrity proof. To
    /// add more proofs, call the `sign` method on the log entry/entries after
    /// building.
    ///
    /// # Errors
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the version ID. Will also fail if the provided
    /// signer fails to sign the log entry.
    pub async fn build(&self) -> anyhow::Result<DeactivateResult> {
        let mut log = self.log.clone();
        let Some(last_entry) = log.last() else {
            bail!("log must not be empty.");
        };
        let mut last_entry = last_entry.clone();

        let mut params = last_entry.parameters.clone();
        params.update_keys.clone_from(&self.update_keys);
        params.witness.clone_from(&self.witness);

        if last_entry.parameters.next_key_hashes.is_some() {
            params.next_key_hashes = None;
            let mut entry = LogEntry {
                version_id: last_entry.version_id.clone(),
                version_time: Utc::now(),
                parameters: params.clone(),
                state: self.doc.clone(),
                proof: vec![],
            };

            let entry_hash = entry.hash()?;
            let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
            if parts.len() != 2 {
                bail!("log entry version ID has an unexpected format");
            }
            let mut version_number = parts[0].parse::<u64>()?;
            version_number += 1;
            entry.version_id = format!("{version_number}-{entry_hash}");

            entry.sign(self.signer.0).await?;
            last_entry.clone_from(&entry);
            log.push(entry);
        }

        params.update_keys = Vec::new();
        params.next_key_hashes = None;
        params.deactivated = true;
        let mut md = self.doc.did_document_metadata.clone().unwrap_or_default();
        md.updated = Some(Utc::now());
        md.deactivated = Some(true);
        let mut doc = self.doc.clone();
        doc.did_document_metadata = Some(md);

        let mut entry = LogEntry {
            version_id: last_entry.version_id.clone(),
            version_time: Utc::now(),
            parameters: params.clone(),
            state: doc.clone(),
            proof: vec![],
        };

        let entry_hash = entry.hash()?;
        let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
        if parts.len() != 2 {
            bail!("unexpected version ID format");
        }
        let mut version_number = parts[0].parse::<u64>()?;
        version_number += 1;
        entry.version_id = format!("{version_number}-{entry_hash}");

        entry.sign(self.signer.0).await?;
        log.push(entry);

        Ok(DeactivateResult {
            did: doc.id.clone(),
            document: doc,
            log,
        })
    }
}

/// Output of an `deactivate` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeactivateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log consisting of the original log appended with the
    /// entry describing the update operation.
    pub log: Vec<LogEntry>,
}
