//! # DID Key
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its
//! core, it is based on expanding a cryptographic public key into a DID
//! Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c.github.io/did-resolution>

use anyhow::{Result, bail};

use crate::{KeyFormat, Method, Resource, Url, VerificationMethod};

/// Convert a `did:key` URL into a [`VerificationMethod`] object.
///
/// # Errors
/// If the URL is not a valid `did:key` URL, an error is returned.
pub fn resolve(url: &Url) -> Result<Resource> {
    if url.method != Method::Key {
        bail!("DID is not a valid did:key: {url}");
    }
    // For did:key, the fragment is the key already multibase encoded. There is
    // no need to use a builder.
    let Some(fragment) = &url.fragment else {
        bail!("DID is not a valid did:key - there is no fragment");
    };
    let vm = VerificationMethod {
        context: None,
        id: url.resource_id(),
        controller: url.did(),
        key: KeyFormat::Multikey {
            public_key_multibase: fragment.to_string(),
        },
    };
    Ok(Resource::VerificationMethod(vm))
}
