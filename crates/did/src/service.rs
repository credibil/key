//! #Service
//!
//! Services are used to express ways of communicating with the DID subject or
//! associated entities.
//!
//! They can be any type of service the DID subject wants
//! to advertise, including decentralized identity management services for
//! further discovery, authentication, authorization, or interaction.
//!
//! Service information is often service specific. For example, a reference to
//! an encrypted messaging service can detail how to initiate the encrypted link
//! before messaging begins.
//!
//! Due to privacy concerns, revealing public information through services, such
//! as social media accounts, personal websites, and email addresses, is
//! discouraged.

use anyhow::{Result, anyhow};
use credibil_core::{Kind, OneMany};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Service is used to express a way of communicating with the DID subject or
/// associated entities.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// A URI unique to the service.
    pub id: String,

    /// The service type. SHOULD be registered in the DID Specification
    /// Registries.
    #[serde(rename = "type")]
    pub type_: String,

    /// One or more endpoints for the service.
    #[allow(clippy::struct_field_names)]
    pub service_endpoint: OneMany<Kind<Value>>,
}

impl Service {
    /// Create a new `ServiceBuilder` to build a service.
    #[must_use]
    pub fn build() -> ServiceBuilder {
        ServiceBuilder::new()
    }
}

/// Service builder
#[derive(Default)]
pub struct ServiceBuilder {
    id: Option<String>,
    service_type: Option<String>,
    endpoint: Option<Vec<Kind<Value>>>,
}

impl ServiceBuilder {
    /// Creates a new `ServiceBuilder` with the given service ID.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Specify how to construct the key ID.
    #[must_use]
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Specify the service type.
    #[must_use]
    pub fn service_type(mut self, service_type: impl Into<String>) -> Self {
        self.service_type = Some(service_type.into());
        self
    }

    /// Specify a string-based service endpoint.
    #[must_use]
    pub fn endpoint(mut self, endpoint: impl Into<Kind<Value>>) -> Self {
        self.endpoint.get_or_insert(vec![]).push(endpoint.into());
        self
    }

    /// Build the service.
    pub(crate) fn build(self, did: impl Into<String>) -> Result<Service> {
        let Some(id) = self.id else {
            return Err(anyhow!("no id specified"));
        };
        let Some(service_type) = self.service_type else {
            return Err(anyhow!("no type specified"));
        };
        let Some(endpoint) = self.endpoint else {
            return Err(anyhow!("no endpoints specified"));
        };
        let endpoint = if endpoint.len() == 1 {
            OneMany::One(endpoint[0].clone())
        } else {
            OneMany::Many(endpoint)
        };

        Ok(Service {
            id: format!("{}#{id}", did.into()),
            type_: service_type,
            service_endpoint: endpoint,
        })
    }
}
