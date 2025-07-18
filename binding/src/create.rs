use anyhow::Result;
use credibil_did::web::CreateBuilder;
use credibil_did::{Document, DocumentBuilder, FromScratch};

use crate::provider::Binding;

/// Create a new `did:web` document and save to document store.
///
/// # Errors
///
/// Returns an error if the DID URL is invalid, if the document cannot be
/// built, or saved to the docstore.
pub async fn create(
    url: &str, builder: DocumentBuilder<FromScratch>, binding: &impl Binding,
) -> Result<Document> {
    let document = CreateBuilder::new(url).document(builder).build()?;
    Binding::put(binding, &document.id, &document).await?;
    Ok(document)
}
