//! # Status List Endpoint

use anyhow::anyhow;
use credibil_api::{Body, Handler, Request, Response};
use credibil_did::Document;
use credibil_did::web::create_did;
use serde::{Deserialize, Serialize};

use crate::handlers::{Error, Result};
use crate::provider::Binding;

/// Used to query the document endpoint in order to return a DID document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentRequest {
    /// The URL of the DID document to retrieve.
    pub url: String,
}

/// Response containing the DID document.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocumentResponse(pub Document);

/// Document request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
async fn document(
    _owner: &str, binding: &impl Binding, request: DocumentRequest,
) -> Result<DocumentResponse> {
    let url = request.url.trim_end_matches("/did.json").trim_end_matches("/.well-known");
    let did = create_did(url)?;
    let document =
        binding.get(&did, &did).await?.ok_or_else(|| anyhow!("document not found for did"))?;
    Ok(DocumentResponse(document))
}

impl<B: Binding> Handler<DocumentResponse, B> for Request<DocumentRequest> {
    type Error = Error;

    async fn handle(self, owner: &str, key_binding: &B) -> Result<Response<DocumentResponse>> {
        Ok(document(owner, key_binding, self.body).await?.into())
    }
}

impl Body for DocumentRequest {}
