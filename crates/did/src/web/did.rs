//! Helper functions for converting HTTP URLs into `did:web` DIDs.

use std::fmt::Write;

use anyhow::{Result, bail};
use url::Url;

/// Construct a `did:web` DID from a valid HTTP URL.
///
/// # Errors
///
/// Will return an error if the url is not a valid HTTP URL or a host cannot be
/// parsed.
pub fn create_did(url: &str) -> Result<String> {
    let host_and_path = parse_url(url)?;
    Ok(format!("did:web:{host_and_path}"))
}

/// Convert an HTTP URL into a host and path separated by colons suitable
/// for use in a `did:web` DID.
///
/// The provided url should be a valid HTTP URL.
///
/// Valid examples:
/// - `https://example.com`
/// - `http://example.com/custom/path/`
/// - `https://example.com:8080`
///
/// # Errors
///
/// Will return an error if the url is not a valid URL or a host cannot be
/// parsed.
fn parse_url(url: &str) -> Result<String> {
    let url = Url::parse(url)?;
    let Some(host_str) = url.host_str() else {
        bail!("no host in url");
    };

    let mut host = host_str.to_string();
    if let Some(port) = url.port() {
        let _ = write!(host, "%3A{port}");
    }
    if let Some(path) = url.path().strip_prefix('/') {
        if !path.is_empty() {
            let formatted_path = path.trim_end_matches('/');
            let formatted_path = formatted_path.replace('/', ":");
            let _ = write!(host, ":{formatted_path}");
        }
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_parser() {
        let url = "https://example.com";
        let did_url = parse_url(url).expect("should parse");
        assert_eq!(did_url, "example.com");

        let url = "http://example.com/custom/path/";
        let did_url = parse_url(url).expect("should parse");
        assert_eq!(did_url, "example.com:custom:path");

        let url = "https://example.com:8080";
        let did_url = parse_url(url).expect("should parse");
        assert_eq!(did_url, "example.com%3A8080");
    }
}
