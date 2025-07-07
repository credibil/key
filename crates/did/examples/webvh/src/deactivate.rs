//! Deactivate operation

use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_ecc::{Keyring, NextKey, Signer};
use credibil_did::webvh::{DeactivateBuilder, DeactivateResult};
use credibil_jose::PublicKeyJwk;

use crate::state::AppState;
use crate::{AppError, AppJson};

// Handler to deactivate a DID document
#[axum::debug_handler]
pub async fn deactivate(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
) -> Result<AppJson<DeactivateResult>, AppError> {
    let did_url = format!("http://{host}");

    tracing::debug!("deactivating DID log document for {did_url}");

    let vault = state.vault;
    let signer = Keyring::entry(&vault, "issuer", "signer").await?;

    // Rotate keys
    let signer = Keyring::rotate(&vault, signer).await?;
    let verifying_key = signer.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
    let update_multi = jwk.to_multibase()?;

    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let next_key = signer.next_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes())?;
    let next_multi = jwk.to_multibase()?;

    let next_keys = vec![next_multi.clone()];
    let next_keys: Vec<&str> = next_keys.iter().map(|s| s.as_str()).collect();

    // Resolve the latest DID document from the log and start building the
    // deactivation.
    let mut log = state.log.lock().await;
    let Some(did_log) = log.get_log(&did_url) else {
        return Err(AppError::Status(
            StatusCode::NOT_FOUND,
            "No existing log found to deactivate. Use create to get started.".into(),
        ));
    };

    let result = DeactivateBuilder::from(&did_log)?
        .rotate_keys(&update_keys, &next_keys)?
        .signer(&signer)
        .build()
        .await?;

    // Store the log in app state
    log.add_log(&did_url, result.log.clone())?;

    Ok(AppJson(result))
}
