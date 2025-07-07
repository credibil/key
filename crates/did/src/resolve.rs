//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default
//! implementations for resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::url::Url;
use crate::{Document, Service, VerificationMethod};

/// Get a resource from a DID document.
///
/// Uses the `Url` to infer the type of resource to return.
///
/// # Errors
/// Will return an error if the resource is not found in the document.
pub fn resource(url: &Url, doc: &Document) -> Result<Resource> {
    if let Some(query) = &url.query {
        if let Some(service_id) = &query.service {
            if let Some(service) = doc.service(service_id) {
                return Ok(Resource::Service(service.clone()));
            }
            bail!("service {service_id} not found in document");
        }
    }
    if url.fragment.is_none() {
        return Ok(Resource::Document(doc.clone()));
    }
    if let Some(vm) = doc.verification_method(&url.to_string()) {
        return Ok(Resource::VerificationMethod(vm.clone()));
    }
    bail!("verification method {url} not found in document")
}

/// Resource represents the DID document resource returned as a result of DID
/// dereferencing. The resource is a DID document or a subset of a DID document.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Resource {
    ///  DID `Document` resource.
    Document(Document),

    /// `VerificationMethod` resource.
    VerificationMethod(VerificationMethod),

    /// `Service` resource.
    Service(Service),
}

impl Default for Resource {
    fn default() -> Self {
        Self::VerificationMethod(VerificationMethod::default())
    }
}
