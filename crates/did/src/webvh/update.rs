//! Update operation for the `did:webvh` method.

use anyhow::{Result, bail};
use chrono::Utc;
use credibil_ecc::Signer;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::resolve::resolve_log;
use super::verify::validate_witness;
use super::{LogEntry, Witness, WitnessEntry};
use crate::{Document, DocumentBuilder, FromDocument};

/// Builder to update a DID document and associated log entry.
///
/// Use this to construct an [`UpdateResult`].
pub struct UpdateBuilder<D, L, S> {
    document: D,
    log_entries: L,
    witness_entries: Option<Vec<WitnessEntry>>,
    portable: Option<bool>,
    witness: Option<Witness>,
    ttl: Option<u64>,
    update_keys: Option<Vec<String>>,
    next_keys: Option<Vec<String>>,
    signer: S,
}

impl Default for UpdateBuilder<NoDocument, NoLog, NoSigner> {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder does not have a document (can't build).
pub struct NoDocument;

/// Builder has a document (can build).
pub struct WithDocument(DocumentBuilder<FromDocument>);

/// Builder does not have a document (can't build).
pub struct NoLog;

/// Builder has a document (can build).
pub struct WithLog(Vec<LogEntry>);

/// Builder does not have a signer (can't build).
pub struct NoSigner;

/// Builder has a signer (can build).
pub struct WithSigner<'a, S: Signer>(pub &'a S);

impl UpdateBuilder<NoDocument, NoLog, NoSigner> {
    /// Create a new update builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            document: NoDocument,
            log_entries: NoLog,
            witness_entries: None,
            portable: None,
            witness: None,
            ttl: None,
            update_keys: None,
            next_keys: None,
            signer: NoSigner,
        }
    }
}

impl<L, S> UpdateBuilder<NoDocument, L, S> {
    /// Add the new DID document to the builder.
    ///
    /// # Errors
    ///
    /// Checks the SCID hasn't changed and the document location hasn't changed
    /// unless the original log entry allowed portability.
    #[must_use]
    pub fn document(
        self, builder: DocumentBuilder<FromDocument>,
    ) -> UpdateBuilder<WithDocument, L, S> {
        UpdateBuilder {
            document: WithDocument(builder),
            log_entries: self.log_entries,
            witness_entries: self.witness_entries,
            portable: self.portable,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: self.update_keys,
            next_keys: self.next_keys,
            signer: self.signer,
        }
    }
}

impl<D, S> UpdateBuilder<D, NoLog, S> {
    /// Current log entries.
    #[must_use]
    pub fn log_entries(self, log_entries: Vec<LogEntry>) -> UpdateBuilder<D, WithLog, S> {
        UpdateBuilder {
            document: self.document,
            log_entries: WithLog(log_entries),
            witness_entries: self.witness_entries,
            portable: self.portable,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: self.update_keys,
            next_keys: self.next_keys,
            signer: self.signer,
        }
    }
}

impl<D, L, S> UpdateBuilder<D, L, S> {
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
    #[must_use]
    pub fn rotate_keys(mut self, update_keys: &[String], next_keys: &[String]) -> Self {
        if !update_keys.is_empty() {
            self.update_keys.get_or_insert(vec![]).extend(update_keys.iter().cloned());
        }
        if !next_keys.is_empty() {
            self.next_keys.get_or_insert(vec![]).extend(next_keys.iter().cloned());
        }
        self
    }

    /// Set the DID to be portable or not. (Will inherit the current setting
    /// unless overridden here.)
    #[must_use]
    pub const fn portable(mut self, portable: bool) -> Self {
        self.portable = Some(portable);
        self
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
    #[must_use]
    pub fn witness(mut self, witness: Witness) -> Self {
        self.witness = Some(witness);
        self
    }

    // /// Remove witnesses from this update.
    // #[must_use]
    // pub fn remove_witness(mut self) -> Self {
    //     self.witness = None;
    //     self
    // }

    /// Set the permissable cache time in seconds for the DID. Will stay the
    /// same as the current log entry if not overridden here. Defaults to 0 if
    /// not previously set.
    #[must_use]
    pub const fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

impl<D, L> UpdateBuilder<D, L, NoSigner> {
    /// Add a signer to the builder.
    #[must_use]
    pub fn signer<S: Signer>(self, signer: &S) -> UpdateBuilder<D, L, WithSigner<'_, S>> {
        UpdateBuilder {
            document: self.document,
            log_entries: self.log_entries,
            witness_entries: self.witness_entries,
            portable: self.portable,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: self.update_keys,
            next_keys: self.next_keys,
            signer: WithSigner(signer),
        }
    }
}

impl<S: Signer> UpdateBuilder<WithDocument, WithLog, WithSigner<'_, S>> {
    /// Build the new log entry.
    ///
    /// Provide a `Provable` `Signer` to construct a data integrity proof. To
    /// add more proofs, call the `sign` method on the log entry after building.
    ///
    /// # Errors
    ///
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the version ID. Will also fail if the provided
    /// signer fails to sign the log entry.
    pub async fn build(self) -> Result<UpdateResult> {
        let document = self.document.0.build()?;
        let mut log_entries = self.log_entries.0;

        // validate the existing log entries by resolving the DID document
        let _ = resolve_log(&log_entries, self.witness_entries.as_deref(), None).await?;

        let Some(last_entry) = log_entries.last() else {
            bail!("log must not be empty.");
        };

        // Check the DID location hasn't changed unless the original log entry
        // allowed portability. If the location has changed, the SCID must be
        // unchanged.
        if last_entry.state.id != document.id {
            if !last_entry.parameters.portable {
                bail!("location has changed for non-portable DID.");
            }
            let parts = last_entry.state.id.split(':').collect::<Vec<&str>>();
            if parts.len() < 4 {
                bail!("invalid DID format.");
            }
            let starts_with = format!("did:webvh:{}:", parts[2]);
            if !document.id.starts_with(&starts_with) {
                bail!("SCID has changed for portable DID.");
            }
        }

        let mut params = last_entry.parameters.clone();
        if let Some(portable) = self.portable {
            params.portable = portable;
        }
        if let Some(update_keys) = &self.update_keys {
            // key rotation
            params.update_keys.clone_from(update_keys);
            if let Some(next_keys) = &self.next_keys {
                let hashes = next_keys
                    .iter()
                    .map(|key| {
                        let digest = sha2::Sha256::digest(key.as_bytes());
                        multibase::encode(Base::Base58Btc, digest.as_slice())
                    })
                    .collect();
                params.next_key_hashes = Some(hashes);
            }
        }

        if let Some(witness) = &self.witness {
            validate_witness(witness)?;
            params.witness = Some(witness.clone());
        }
        if let Some(ttl) = self.ttl {
            params.ttl = ttl;
        }

        let version_time = document
            .did_document_metadata
            .as_ref()
            .map_or_else(Utc::now, |m| m.updated.unwrap_or_else(Utc::now));
        let mut entry = LogEntry {
            version_id: last_entry.version_id.clone(),
            version_time,
            parameters: params.clone(),
            state: document.clone(),
            proof: vec![],
        };

        let entry_hash = entry.hash()?;
        let parts = last_entry.version_id.split('-').collect::<Vec<&str>>();
        if parts.len() != 2 {
            bail!("unexpected version ID format.");
        }
        let mut version_number = parts[0].parse::<u64>()?;
        version_number += 1;
        entry.version_id = format!("{version_number}-{entry_hash}");

        // Sign (adds a proof to the log entry).
        entry.sign(self.signer.0).await?;

        log_entries.push(entry);

        Ok(UpdateResult {
            did: document.id.clone(),
            document,
            log_entries,
        })
    }
}

/// Output of an `update` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UpdateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log consisting of the original log appended with the
    /// entry describing the update operation.
    pub log_entries: Vec<LogEntry>,
}
