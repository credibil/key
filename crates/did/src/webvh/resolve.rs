//! # DID Web with Verifiable History Resolver
//!
//! Resolution of a DID for the `did:webvh` method.
//!
//! See: <https://identity.foundation/didwebvh/next/>

use std::vec;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use multibase::Base;
use sha2::Digest;

use super::verify::{verify_proofs, verify_witness};
use super::{LogEntry, SCID, WitnessEntry};
use crate::{Document, DocumentMetadataBuilder, QueryParams, Url};

impl Url {
    /// Convert a `did:webvh` URL to an HTTP URL pointing to the location of the
    /// DID list document (default) or another location where the root path is
    /// a conversion from the DID to an HTTP URL.
    ///
    /// # Errors
    ///
    /// Will fail if the DID URL is invalid.
    ///
    /// <https://identity.foundation/didwebvh/#the-did-to-https-transformation>
    pub fn to_webvh_http(&self) -> Result<String> {
        // 1. Remove the literal `did:webvh:` prefix from the DID URL.
        let scid_and_fqdn = self.id.clone();

        // 2. Remove the `SCID` by removing the text up to and including the
        // first `:` character.
        let Some(fqdn) = scid_and_fqdn.split_once(':').map(|x| x.1) else {
            bail!("DID is not a valid did:webvh - no SCID");
        };

        // 3. Replace `:` with `/` in the domain part of the identifier to obtain
        // the fully qualified domain name and optional path.
        let mut domain = fqdn.replace(':', "/");

        // 4. If there is no optional path, append `/.well-known` to the URL.
        if !fqdn.contains(':') {
            domain.push_str("/.well-known");
        }

        // 5. If the domain contains a port, percent-decode the colon.
        let domain = domain.replace("%3A", ":");

        // 6. Prepend `https://` to the domain to generate the URL.
        let url = format!("https://{domain}");

        // 7. Append `/did.jsonl` (default) or the specified file sub-path to
        // the URL to complete it.
        let mut fp = "/did.jsonl".to_string();
        if let Some(path) = &self.path {
            if !path.is_empty() {
                fp = path.join("/");
            }
        }
        let url = format!("{url}{fp}");

        Ok(url)
    }
}

/// Verification of the contents of the `did.jsonl` file and resolution into a
/// DID document.
///
/// To use this function, read the contents of the `did.jsonl` file into a
/// vector of `LogEntry` structs and pass to this function.
///
/// To skip verification of the witness proofs, pass `None` for the
/// `witness_proofs` parameter.
///
/// # Errors
///
/// Will fail if the log entries are invalid.
#[allow(clippy::too_many_lines)]
pub async fn resolve_log(
    log: &[LogEntry], proofs: Option<&[WitnessEntry]>, parameters: Option<&QueryParams>,
) -> Result<Document> {
    if log.is_empty() {
        bail!("log entries are empty");
    }

    let mut prev_index = 0;
    // let mut prev_version = SCID.to_string();
    let mut prev_version = log[0].parameters.scid.clone();
    let mut prev_time = DateTime::<Utc>::MIN_UTC;
    let mut doc = Document::default();
    let mut prev_next_key_hashes: Option<Vec<String>> = None;
    for i in 0..log.len() {
        // 1. Update current parameters with parameters from the entry being
        // processed.

        // 2. Verify controller proofs.
        verify_proofs(&log[i]).await?;

        // 3.1. Verify the version number is incremented by one for each entry.
        // 3.2. Verify the version number and entry hash is separated by `-`.
        let version_parts = log[i].version_id.split('-').collect::<Vec<&str>>();
        if version_parts.len() != 2 {
            bail!("log entry version id has an unexpected format");
        }
        let index = version_parts[0].parse::<u64>()?;
        if index != prev_index + 1 {
            bail!("log entries are not sequential");
        }

        // 3.3. Verify the entry hash.
        log[i].verify_hash(&prev_version)?;

        // 4. The version time must be in the past and monotonically increasing.
        if log[i].version_time > Utc::now() {
            bail!("log entry time is in the future");
        }
        if log[i].version_time <= prev_time {
            bail!(
                "log entry times are not monotonically increasing: {} -> {}",
                log[i].version_time,
                prev_time
            );
        }

        // 5. If the entry is the first one, verify the SCID.
        if i == 0 {
            let initial_string = serde_json::to_string(&log[i])?;
            let replaced = initial_string.replace(&log[i].parameters.scid, SCID);
            let mut initial_log_entry = serde_json::from_str::<LogEntry>(&replaced)?;
            initial_log_entry.version_id = SCID.to_string();
            initial_log_entry.proof = vec![];
            let hash = initial_log_entry.hash()?;
            if hash != log[i].parameters.scid {
                bail!("first log entry SCID does not match calculated hash");
            }
        }

        // 6. Record the state as the document to return (if everything else is
        // successful).
        doc = log[i].state.clone();

        // Add method-specific metadata to the document from the log parameters.
        let mut mdb = doc
            .did_document_metadata
            .as_ref()
            .map_or_else(DocumentMetadataBuilder::new, DocumentMetadataBuilder::from);
        mdb = mdb
            .additional("versionId", log[i].version_id.clone())
            .additional("versionTime", log[i].version_time.to_rfc3339())
            .additional("scid", log[i].parameters.scid.clone())
            .additional("portable", log[i].parameters.portable);
        if log[i].parameters.witness.is_some() {
            mdb = mdb.additional("witness", log[i].parameters.witness.clone());
        }
        doc.did_document_metadata = Some(mdb.build());

        // 7. If key pre-rotation is enabled, check the update keys match the
        // previous entry's next-key hashes.
        if let Some(next_key_hashes) = &prev_next_key_hashes {
            for key in &log[i].parameters.update_keys {
                let key_digest = sha2::Sha256::digest(key.as_bytes());
                let key_hash = multibase::encode(Base::Base58Btc, key_digest.as_slice());
                if !next_key_hashes.contains(&key_hash) {
                    bail!("update key not found in pre-rotation hashes");
                }
            }
        }

        // 8. Increment.
        prev_index = index;
        prev_version.clone_from(&log[i].version_id);
        prev_time.clone_from(&log[i].version_time);
        prev_next_key_hashes.clone_from(&log[i].parameters.next_key_hashes);

        // 9. Check witness proofs if provided.
        if proofs.is_some() && log[i].parameters.witness.is_some() {
            if let Some(witness_entries) = proofs {
                verify_witness(&log[i], witness_entries).await?;
            }
        }

        // Check for explicit version ID or version time request. (Otherwise
        // the latest version is returned.)
        if let Some(params) = parameters {
            if let Some(version_id) = &params.version_id {
                if *version_id == log[i].version_id {
                    break;
                }
            }
            if let Some(version_time) = &params.version_time {
                let version_time = version_time.parse::<DateTime<Utc>>()?;
                if version_time >= log[i].version_time {
                    if i < log.len() - 1 {
                        if version_time <= log[i + 1].version_time {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }
    Ok(doc)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn default_url() {
        let did =
            "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer";
        let structured_url = Url::from_str(did).expect("should parse");
        println!("structured_url: {structured_url:?}");
        let url = structured_url.to_webvh_http().expect("should serialize");
        assert_eq!(url, "https://domain.with-hyphens.computer/.well-known/did.jsonl");
    }

    #[test]
    fn path_url() {
        let did = "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer:dids:issuer";
        let structured_url = Url::from_str(did).expect("should parse");
        let url = structured_url.to_webvh_http().expect("should serialize");
        assert_eq!(url, "https://domain.with-hyphens.computer/dids/issuer/did.jsonl");
    }

    #[test]
    fn port_url() {
        let did = "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:domain.with-hyphens.computer%3A8080";
        let structured_url = Url::from_str(did).expect("should parse");
        println!("structured_url: {structured_url:?}");
        let url = structured_url.to_webvh_http().expect("should serialize");
        assert_eq!(url, "https://domain.with-hyphens.computer:8080/.well-known/did.jsonl");
    }
}
