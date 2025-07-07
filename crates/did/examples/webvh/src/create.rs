//! Create operation

use axum::Json;
use axum::extract::State;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_did::webvh::{CreateBuilder, CreateResult};
use credibil_did::{DocumentBuilder, KeyId, VerificationMethod};
use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRequest;

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn create(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
    Json(_req): Json<CreateRequest>,
) -> Result<AppJson<CreateResult>, AppError> {
    tracing::debug!("creating DID log document for http://{host}");

    let vault = state.vault;
    let signer = Keyring::generate(&vault, "wvhd", "signing", Curve::Ed25519).await?;
    let verifying_key = signer.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
    let update_multi = jwk.to_multibase()?;

    let id_entry = Keyring::generate(&vault, "wvhd", "id", Curve::Ed25519).await?;
    let verifying_key = id_entry.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key.to_bytes())?;
    let id_multi = jwk.to_multibase()?;

    let next_key = signer.next_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&next_key.to_bytes())?;
    let next_multi = jwk.to_multibase()?;

    let vm = VerificationMethod::build()
        .key(update_multi.clone())
        .key_id(KeyId::Authorization(id_multi));

    tracing::debug!("keys established");

    // TODO: add other verification methods and service endpoints to the `CreateRequest`.
    let builder = DocumentBuilder::new().verification_method(vm);

    let result = CreateBuilder::new(format!("http://{host}"))
        .document(builder)
        .update_keys(vec![update_multi])
        .next_key(&next_multi)
        .signer(&signer)
        .build()
        .await?;

    // Store the log in app state
    let mut log = state.log.lock().await;
    log.add_log(format!("http://{host}"), result.log.clone())?;

    Ok(AppJson(result))
}
