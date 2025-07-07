//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

mod document;

use anyhow::Error;

pub use self::document::{DocumentRequest, DocumentResponse};

/// Result type for Token Status endpoints.
type Result<T> = anyhow::Result<T, Error>;
