//! Helper functions for converting HTTP URLs into `did:webvh` DIDs.

use std::fmt::Write;

use anyhow::bail;
use url::Url;

use crate::webvh::SCID;

/// Construct a default `did:webvh` DID from a URL.
///
/// The provided url should be a valid HTTP URL. See `parse_url` for more
/// information.
///
/// The output is a `did:webvh` DID with the `{SCID}` placeholder and path
/// converted from the provided HTTP URL.
///
/// # Errors
///
/// Will return an error if the url is not a valid URL or a host cannot be
/// parsed.
pub fn create_did(url: &str) -> anyhow::Result<String> {
    let host_and_path = parse_url(url)?;
    Ok(format!("did:webvh:{SCID}:{host_and_path}"))
}

/// Convert an HTTP URL into a host and path separated by colons suitable
/// for use in a `did:webvh` DID.
///
/// Does not prepend the `did:webvh:` prefix or `SCID`.
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
pub fn parse_url(url: &str) -> anyhow::Result<String> {
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
