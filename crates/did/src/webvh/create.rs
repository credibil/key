//! Create operation for the `did:webvh` method.

use anyhow::{Result, bail};
use chrono::Utc;
use credibil_ecc::Signer;
use multibase::Base;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::webvh::verify::validate_witness;
use crate::webvh::{LogEntry, Parameters, SCID, VERSION, Witness, create_did};
use crate::{Document, DocumentBuilder, FromScratch};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder<U, S, D> {
    url: String,
    portable: bool,
    next_key_hashes: Option<Vec<String>>,
    witness: Option<Witness>,
    ttl: u64,
    update_keys: U,
    signer: S,
    document: D,
}

/// Builder does not have update keys (can't build).
pub struct NoUpdateKeys;

/// Builder has update keys (can build).
pub struct WithUpdateKeys(Vec<String>);

/// Builder does not have a signer (can't build).
pub struct NoSigner;

/// Builder has a signer (can build).
pub struct WithSigner<'a, S: Signer>(pub &'a S);

/// Builder does not have a document (can't build).
pub struct NoDocument;

/// Builder has a document (can build).
pub struct WithDocument(DocumentBuilder<FromScratch>);

impl CreateBuilder<NoUpdateKeys, NoSigner, NoDocument> {
    /// Create a new `CreateBuilder`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            portable: false,
            next_key_hashes: None,
            witness: None,
            ttl: 0,
            update_keys: NoUpdateKeys,
            signer: NoSigner,
            document: NoDocument,
        }
    }

    /// Add a populated [`DocumentBuilder`] instance.
    #[must_use]
    pub fn document(
        self, builder: DocumentBuilder<FromScratch>,
    ) -> CreateBuilder<NoUpdateKeys, NoSigner, WithDocument> {
        CreateBuilder {
            url: self.url,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: NoUpdateKeys,
            signer: NoSigner,
            document: WithDocument(builder),
        }
    }
}

impl CreateBuilder<NoUpdateKeys, NoSigner, WithDocument> {
    /// Add update keys.
    ///
    /// Update keys are the multibase-encoded public keys that can be used by
    /// a controller to sign log entries for the DID.
    ///
    /// # Errors
    /// Will fail if the update keys are empty.
    #[must_use]
    pub fn update_keys(
        self, update_keys: Vec<String>,
    ) -> CreateBuilder<WithUpdateKeys, NoSigner, WithDocument> {
        CreateBuilder {
            url: self.url,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: WithUpdateKeys(update_keys),
            signer: NoSigner,
            document: self.document,
        }
    }
}

impl CreateBuilder<WithUpdateKeys, NoSigner, WithDocument> {
    /// Add a signer to the builder.
    #[must_use]
    pub fn signer<S: Signer>(
        self, signer: &S,
    ) -> CreateBuilder<WithUpdateKeys, WithSigner<'_, S>, WithDocument> {
        CreateBuilder {
            url: self.url,
            portable: self.portable,
            next_key_hashes: self.next_key_hashes,
            witness: self.witness,
            ttl: self.ttl,
            update_keys: self.update_keys,
            signer: WithSigner(signer),
            document: self.document,
        }
    }
}

impl<U, S, D> CreateBuilder<U, S, D> {
    /// Set the DID to be portable or not (defaults to not portable).
    #[must_use]
    pub const fn portable(mut self, portable: bool) -> Self {
        self.portable = portable;
        self
    }

    /// Add a next key hash to the list of next key hashes if required.
    ///
    /// Pass in the multibase-encoded public key to be used as the next key and
    /// this function will carry out the hashing and encoding before adding it
    /// to the list of next key hashes.
    #[must_use]
    pub fn next_key(mut self, next_key_multi: &str) -> Self {
        let next_digest = sha2::Sha256::digest(next_key_multi.as_bytes());
        let next_hash = multibase::encode(Base::Base58Btc, next_digest.as_slice());
        self.next_key_hashes.get_or_insert(vec![]).push(next_hash);
        self
    }

    /// Add a set of witnesses to the create operation.
    ///
    /// # Errors
    ///
    /// Will fail if the witness threshold is zero, the witness list is empty,
    /// the contribution (weight) of a witness is zero, or the sum of
    /// contributions would never reach the threshold.
    #[must_use]
    pub fn witness(mut self, witness: &Witness) -> Self {
        self.witness = Some(witness.clone());
        self
    }

    /// Set the permissable cache time in seconds for the DID. Defaults to 0 if
    /// not set here.
    #[must_use]
    pub const fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl;
        self
    }
}

impl<S: Signer> CreateBuilder<WithUpdateKeys, WithSigner<'_, S>, WithDocument> {
    /// Build the new log entry.
    ///
    /// Provide a `Provable` `Signer` to construct a data integrity proof. To
    /// add more proofs, call the `sign` method on the log entry after building.
    ///
    /// # Errors
    ///
    /// Will fail if secondary algorithms fail such as generating a hash of the
    /// log entry to calculate the `SCID` or version ID, or failing to replace
    /// the placeholder `SCID` with the calculated one. Will also fail if the
    /// provided signer fails to sign the log entry.
    pub async fn build(self) -> Result<CreateResult> {
        let did = create_did(&self.url)?;
        let document = self.document.0.build(&did)?;

        //  update keys cannot be empty.
        if self.update_keys.0.is_empty() {
            bail!("update keys must not be empty.");
        }
        if let Some(witness) = &self.witness {
            validate_witness(witness)?;
        }

        // initial log entry uses a placeholder (`{SCID}`) for the SCID value
        let initial_entry = LogEntry {
            version_id: SCID.to_string(),
            version_time: document
                .did_document_metadata
                .as_ref()
                .map_or_else(Utc::now, |m| m.created),
            parameters: Parameters {
                method: format!("did:webvh:{VERSION}"),
                scid: SCID.to_string(),
                update_keys: self.update_keys.0,
                portable: self.portable,
                next_key_hashes: self.next_key_hashes,
                witness: self.witness,
                deactivated: false,
                ttl: self.ttl,
            },
            state: document,
            proof: vec![],
        };

        // create the SCID hash from the initial log entry (using SCID
        // placeholder) and then replace SCID placeholder with a computed SCID
        let initial_hash = initial_entry.hash()?;
        let initial_json = serde_json::to_string(&initial_entry)?;
        let self_certified = initial_json.replace(SCID, &initial_hash);

        // build the actual log entry
        let mut log_entry = serde_json::from_str::<LogEntry>(&self_certified)?;
        let entry_hash = log_entry.hash()?;
        log_entry.version_id = format!("1-{entry_hash}");
        log_entry.sign(self.signer.0).await?;

        Ok(CreateResult {
            did,
            document: log_entry.state.clone(),
            log: vec![log_entry],
        })
    }
}

/// Output of a `create` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateResult {
    /// The `did:webvh` DID.
    pub did: String,

    /// The `did:webvh` document.
    pub document: Document,

    /// Version history log with the single created entry suitable for writing
    /// to a `did.jsonl` log file.
    pub log: Vec<LogEntry>,
}
