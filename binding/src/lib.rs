//! # Binding

mod create;
mod handlers;
mod provider;

use std::str::FromStr;

use anyhow::{Result, anyhow};
pub use credibil_core::api::Client;
use credibil_did::{Method, Resource};
use credibil_jose::PublicKeyJwk;
pub use {credibil_did as did, credibil_ecc as ecc, credibil_jose as jose};

pub use self::create::*;
pub use self::handlers::*;
pub use self::provider::*;

/// Retrieve the JWK specified by the provided DID URL.
///
/// # Errors
///
/// TODO: Document errors
pub async fn resolve_jwk<'a>(
    url: impl Into<UrlType<'a>>, resolver: &impl Resolver,
) -> Result<PublicKeyJwk> {
    let jwk = match url.into() {
        UrlType::Did(url) => {
            let did_url = credibil_did::Url::from_str(url)?;

            let resource = match did_url.method {
                Method::Key => credibil_did::key::resolve(&did_url)?,
                Method::Web => {
                    let web_url = did_url.to_web_http();
                    let body = resolver.resolve(&web_url).await?;
                    let doc = serde_json::from_slice(&body)
                        .map_err(|e| anyhow!("failed to deserialize DID document: {e}"))?;
                    credibil_did::resource(&did_url, &doc)?
                }
                Method::WebVh => unimplemented!(),
            };

            let Resource::VerificationMethod(vm) = resource else {
                return Err(anyhow!("key binding method not found"));
            };
            vm.key.jwk()?
        }
        UrlType::Url(_) => {
            return Err(anyhow!("Only DID URLs are supported for JWK resolution"));
        }
    };

    Ok(jwk)
}

/// Represents a URL type that can either be a DID or a regular URL.
#[derive(Debug)]
pub enum UrlType<'a> {
    /// A DID URL, which is a string representation of a Decentralized Identifier.
    Did(&'a str),

    /// A regular URL, which is a string representation of a web address.
    Url(&'a str),
}

impl<'a> From<&'a str> for UrlType<'a> {
    fn from(url: &'a str) -> Self {
        if url.starts_with("did:") { Self::Did(url) } else { Self::Url(url) }
    }
}

impl<'a> From<&'a String> for UrlType<'a> {
    fn from(url: &'a String) -> Self {
        url.as_str().into()
    }
}
