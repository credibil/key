use axum::BoxError;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use axum_extra::json_lines::JsonLines;
use credibil_did::webvh::{DidLog, LogEntry, resolve_log};
use credibil_did::{Document, QueryParams};
use futures_util::Stream;

use crate::state::AppState;
use crate::{AppError, AppJson};

// Handler to read the DID log file (from memory in our case).
#[axum::debug_handler]
pub async fn read(State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>) -> Response {
    let did_url = format!("http://{host}");

    tracing::debug!("reading DID log document for {did_url}");

    let log = state.log.lock().await;
    let Some(entries) = log.get_log(&did_url) else {
        return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()).into_response();
    };

    let values = entries_as_stream(entries);
    JsonLines::new(values).into_response()
}

fn entries_as_stream(entries: DidLog) -> impl Stream<Item = Result<LogEntry, BoxError>> {
    futures_util::stream::iter(entries.into_iter().map(|entry| {
        // Convert each entry to a Result
        Ok(entry)
    }))
}

// Handler to resolve a DID document from a DID log file.
#[axum::debug_handler]
pub async fn resolve(
    State(state): State<AppState>, Query(params): Query<QueryParams>,
    TypedHeader(host): TypedHeader<Host>,
) -> Result<AppJson<Document>, AppError> {
    let did_url = format!("http://{host}");

    tracing::debug!("resolving DID document for {did_url}");

    let log = state.log.lock().await;
    let entries = log
        .get_log(&did_url)
        .ok_or_else(|| return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()))?;
    let doc = resolve_log(&entries, None, Some(&params)).await?;

    Ok(AppJson(doc))
}
