//! Update operation

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_did::webvh::{UpdateBuilder, UpdateResult, resolve_log};
use credibil_did::{DocumentBuilder, KeyId, KeyPurpose, VerificationMethod};
use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

// Example options to influence the update process.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateRequest {
    // Add a verification method to the document with the specified purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<KeyPurpose>,
}

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn update(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
    Json(req): Json<UpdateRequest>,
) -> Result<AppJson<UpdateResult>, AppError> {
    let did_url = format!("http://{host}");
    tracing::debug!("updating DID log document for {did_url}, with request: {req:?}");

    let vault = state.vault;
    let signer = Keyring::entry(&vault, "issuer", "signer").await?;

    // Rotate keys
    let signer = Keyring::rotate(&vault, signer).await?;
    let verifying_key = signer.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
    let update_multi = jwk.to_multibase()?;

    let next_key = signer.next_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes())?;
    let next_multi = jwk.to_multibase()?;

    // Get a new ID key for the new verification method.
    let id_entry = Keyring::generate(&vault, "issuer", "id", Curve::Ed25519).await?;
    let verifying_key = id_entry.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
    let id_multi = jwk.to_multibase()?;

    // Resolve the latest DID document from the log and start building the
    // update.
    let mut log = state.log.lock().await;
    let Some(did_log) = log.get_log(&did_url) else {
        return Err(AppError::Status(
            StatusCode::NOT_FOUND,
            "No existing log found to update. Use create to get started.".into(),
        ));
    };
    let current_doc = resolve_log(&did_log, None, None).await?;
    let mut builder = DocumentBuilder::from(current_doc.clone());

    // Create a new verification method.
    let key_id = KeyId::Authorization(id_multi);
    let vm = VerificationMethod::build().key(update_multi.clone()).key_id(key_id.clone());

    // Add a reference-based verification method, if requested.
    if let Some(purpose) = req.add {
        match purpose {
            KeyPurpose::AssertionMethod => builder = builder.assertion_method(key_id.to_string()),
            KeyPurpose::Authentication => builder = builder.authentication(key_id.to_string()),
            KeyPurpose::CapabilityInvocation => {
                builder = builder.capability_invocation(key_id.to_string())
            }
            KeyPurpose::CapabilityDelegation => {
                builder = builder.capability_delegation(key_id.to_string())
            }
            KeyPurpose::VerificationMethod | KeyPurpose::KeyAgreement => {}
        }
    }

    builder = builder.verification_method(vm);

    // create an update log entry
    let result = UpdateBuilder::new()
        .document(builder)
        .log_entries(did_log)
        .rotate_keys(&vec![update_multi], &vec![next_multi])
        .signer(&signer)
        .build()
        .await?;

    // store the log in app state
    log.add_log(&did_url, result.log_entries.clone())?;

    Ok(AppJson(result))
}
