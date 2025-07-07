use anyhow::Result;

use crate::web::create_did;
use crate::{Document, DocumentBuilder, FromScratch};

/// Builder to create a new `did:webvh` document and associated DID url and log.
///
/// Use this to construct a `CreateResult`.
pub struct CreateBuilder<D> {
    url: String,
    document: D,
}

/// Builder does not have a document (can't build).
pub struct NoDocument;

/// Builder has a document (can build).
pub struct WithDocument(DocumentBuilder<FromScratch>);

impl CreateBuilder<NoDocument> {
    /// Create a new `CreateBuilder`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            document: NoDocument,
        }
    }

    /// Add a populated [`DocumentBuilder`] instance.
    #[must_use]
    pub fn document(self, builder: DocumentBuilder<FromScratch>) -> CreateBuilder<WithDocument> {
        CreateBuilder {
            url: self.url,
            document: WithDocument(builder),
        }
    }
}

impl CreateBuilder<WithDocument> {
    /// Build the `CreateResult` with the provided parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL is invalid or if the document cannot
    /// be built.
    pub fn build(self) -> Result<Document> {
        self.document.0.build(create_did(&self.url)?)
    }
}
