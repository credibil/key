//! Application state
use std::sync::Arc;

use test_utils::Vault;
use tokio::sync::Mutex;

use crate::log::Log;

#[derive(Clone)]
pub struct AppState {
    pub vault: Vault,
    pub log: Arc<Mutex<Log>>,
}

impl AppState {
    #[must_use]
    pub async fn new() -> Self {
        Self {
            vault: Vault,
            log: Arc::new(Mutex::new(Log::new())),
        }
    }
}
