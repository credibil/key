//! # HTTP server example
//!
//! This example demonstrates a basic HTTP service implementation of the
//! `did:webvh` method using the `credibil-did` crate.

mod create;
mod deactivate;
mod log;
mod resolve;
mod state;
mod update;

use axum::Router;
use axum::extract::FromRequest;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use state::AppState;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);
    let app_state = AppState::new().await;

    let router = Router::new()
        .route("/create", post(create::create))
        .route("/.well-known/did.jsonl", get(resolve::read))
        .route("/.well-known/did.json", get(resolve::resolve))
        .route("/update", post(update::update))
        .route("/deactivate", post(deactivate::deactivate))
        .layer(cors)
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

// Custom JSON extractor to enable overriding the rejection and create our own
/// error response.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    T: Serialize,
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}

/// Custom application errors.
pub enum AppError {
    /// The request body contained invalid JSON.
    InvalidJson(JsonRejection),

    /// Status code and message error.
    Status(StatusCode, String),

    /// Unspecified application error.
    Other(anyhow::Error),
}

/// Error response.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ErrorResponse {
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidJson(rejection) => (rejection.status(), rejection.body_text()),
            Self::Status(status, message) => {
                tracing::error!("status error: {status} {message}");
                (status, message)
            }
            Self::Other(error) => {
                tracing::error!("internal server error: {}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into())
            }
        };
        (status, AppJson(ErrorResponse { message })).into_response()
    }
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        Self::InvalidJson(rejection)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}
