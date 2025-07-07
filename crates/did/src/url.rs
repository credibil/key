//! Destructure DID URLs into strongly typed components.
//!
//! A DID URL is of the form
//!
//! `did:<method>:<method-specific-id>[/<path>][?<query>][#<fragment>]`.

use std::fmt::{Display, Write as _};
use std::str::FromStr;
use std::string::ToString;

use anyhow::bail;
use nom::bytes::complete::{is_not, tag, take, take_until};
use nom::combinator::{opt, rest};
use nom::error::{Error as NomError, ErrorKind};
use nom::sequence::{preceded, terminated};
use nom::{Err as NomErr, IResult, Parser};
use serde::{Deserialize, Serialize};

use super::Method;

/// Structure of a DID URL.
#[derive(Clone, Debug, Default)]
pub struct Url {
    /// DID method.
    ///
    /// Specification calls for a string. In our case this must be a method
    /// supported by this crate so we map to an enum.
    pub method: Method,

    /// Method-specific ID.
    ///
    /// This may include any information that is needed by a DID method to
    /// address a specific DID document.
    pub id: String,

    /// Path.
    ///
    /// If present, a DID path is identical to a generic URI path. It is up to
    /// the method to define how to interpret the path in order to resolve a
    /// specific DID document.
    pub path: Option<Vec<String>>,

    /// Query.
    ///
    /// If present, the query parameters refine the resolution of the specific
    /// instance (eg. version) of a DID document or other resource defined by a
    /// DID document (for example, a service endpoint).
    pub query: Option<QueryParams>,

    /// Fragment.
    ///
    /// If present, the fragment is a string that corresponds to a specific
    /// resource identifier within a DID document. Typically a serice or a
    /// verification method.
    pub fragment: Option<String>,
}

impl Display for Url {
    /// Format the URL as a specification-compliant string.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)?;
        if let Some(path) = &self.path {
            write!(f, "/{}", path.join("/"))?;
        }
        if let Some(query) = &self.query {
            write!(f, "?")?;
            let mut first = true;
            if let Some(service) = &query.service {
                write!(f, "service={service}")?;
                first = false;
            }
            if let Some(relative_ref) = &query.relative_ref {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "relativeRef={relative_ref}")?;
                first = false;
            }
            if let Some(version_id) = &query.version_id {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "versionId={version_id}")?;
                first = false;
            }
            if let Some(version_time) = &query.version_time {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "versionTime={version_time}")?;
                first = false;
            }
            if let Some(hashlink) = &query.hashlink {
                if !first {
                    write!(f, "&")?;
                }
                write!(f, "hl={hashlink}")?;
            }
        }
        if let Some(fragment) = &self.fragment {
            write!(f, "#{fragment}")?;
        }
        Ok(())
    }
}

impl FromStr for Url {
    type Err = anyhow::Error;

    /// Parse a string if possible into a strongly typed DID URL struct.
    ///
    /// Expecting a format:
    /// `did:<method>:<method-specific-id>[/<path>][?<query>][#<fragment>]`.
    ///
    /// # Errors:
    /// If the string is not a valid format or portions of the string cannot be
    /// de-serialized into the expected types, an error is returned.
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Self::parse(s)
    }
}

impl Url {
    /// Get the internal resource identifier from the DID URL.
    ///
    /// This is in the form of `did:<method>:<method-specific-id>#<fragment>`
    /// and is used to dereference a service or verification method that is
    /// internal to the DID document.
    ///
    /// Note this is unreliable as an ID if there is no fragment on the URL.
    #[must_use]
    pub fn resource_id(&self) -> String {
        let mut id = format!("did:{}:{}", self.method, self.id);
        if let Some(ref fragment) = self.fragment {
            let _ = write!(id, "#{fragment}");
        }
        id
    }

    /// Get the DID part of the URL, excluding the fragment.
    ///
    /// This is in the form of `did:<method>:<method-specific-id>`.
    #[must_use]
    pub fn did(&self) -> String {
        format!("did:{}:{}", self.method, self.id)
    }

    /// Parse a string into a DID URL if possible.
    ///
    /// # Errors
    /// If any internal parsing fails, an error is returned.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match parse_url(s) {
            Ok((_, url)) => Ok(url),
            Err(err) => {
                bail!("failed to parse DID URL: {err}");
            }
        }
    }
}

/// The DID URL syntax supports parameters in the URL query component. Adding a
/// DID parameter to a DID URL means the parameter becomes part of the
/// identifier for a resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct QueryParams {
    /// Identifies a service from the DID document by service's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// A relative URI reference that identifies a resource at a service
    /// endpoint, which is selected from a DID document by using the service
    /// parameter. MUST use URL encoding if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    pub relative_ref: Option<String>,

    /// Identifies a specific version of a DID document to be resolved (the
    /// version ID could be sequential, or a UUID, or method-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// Identifies a version timestamp of a DID document to be resolved. That
    /// is, the DID document that was valid for a DID at a certain time.
    /// An XML datetime value [XMLSCHEMA11-2] normalized to UTC 00:00:00 without
    /// sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>,

    /// A resource hash of the DID document to add integrity protection, as
    /// specified in [HASHLINK]. This parameter is non-normative.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>,
}

fn scheme(input: &str) -> IResult<&str, &str> {
    terminated(tag("did"), tag(":")).parse(input)
}

fn method(input: &str) -> IResult<&str, Method> {
    let (next, method) = take_until(":").parse(input)?;
    let method = Method::from_str(method)
        .map_err(|_| NomErr::Error(NomError::new(method, ErrorKind::TakeUntil)))?;
    let (next, _) = take(1usize).parse(next)?;
    Ok((next, method))
}

fn id(input: &str) -> IResult<&str, &str> {
    is_not("%/?#").parse(input)
}

fn port(input: &str) -> IResult<&str, u16> {
    let (next, p) = preceded(tag("%3A"), is_not("/?#")).parse(input)?;
    let p = p.parse::<u16>().map_err(|_| NomErr::Error(NomError::new(p, ErrorKind::IsNot)))?;
    Ok((next, p))
}

fn path(input: &str) -> IResult<&str, Vec<String>> {
    let (next, p) = preceded(tag("/"), is_not("?#")).parse(input)?;
    Ok((next, p.split('/').map(ToString::to_string).collect()))
}

fn query(input: &str) -> IResult<&str, QueryParams> {
    let (next, q) = preceded(tag("?"), is_not("#")).parse(input)?;
    let mut params = QueryParams::default();
    for param in q.split('&') {
        let (key, value) = param.split_once('=').unwrap_or((param, ""));
        match key {
            "service" => params.service = Some(value.to_string()),
            "relativeRef" | "relative-ref" => params.relative_ref = Some(value.to_string()),
            "versionId" => params.version_id = Some(value.to_string()),
            "versionTime" => params.version_time = Some(value.to_string()),
            "hl" => params.hashlink = Some(value.to_string()),
            _ => {}
        }
    }
    Ok((next, params))
}

fn fragment(input: &str) -> IResult<&str, &str> {
    preceded(tag("#"), rest).parse(input)
}

fn parse_url(input: &str) -> IResult<&str, Url> {
    let (next, _scheme) = scheme(input)?;
    let (next, (parsed_method, parsed_id, parsed_port, parsed_path, parsed_query, parsed_fragment)) =
        (method, id, opt(port), opt(path), opt(query), opt(fragment)).parse(next)?;
    let id = parsed_port.map_or_else(|| parsed_id.to_string(), |p| format!("{parsed_id}%3A{p}"));
    Ok((
        next,
        Url {
            method: parsed_method,
            id,
            path: parsed_path,
            query: parsed_query,
            fragment: parsed_fragment.map(str::to_string),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_url() {
        let url = Url::from_str("did:key:123456789abcdefghi#key-1").expect("should parse url");
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, None);
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi#key-1");
    }

    #[test]
    fn url_with_path() {
        let url = Url::from_str("did:key:123456789abcdefghi/path/to/resource#key-1")
            .expect("should parse url");
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(
            url.path,
            Some(vec!["path".to_string(), "to".to_string(), "resource".to_string()])
        );
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi/path/to/resource#key-1");
    }

    #[test]
    fn url_with_query() {
        let url = Url::from_str("did:key:123456789abcdefghi?service=example#key-1")
            .expect("should parse url");
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(url.path, None);
        assert_eq!(
            url.query,
            Some(QueryParams {
                service: Some("example".to_string()),
                ..Default::default()
            })
        );
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(url.to_string(), "did:key:123456789abcdefghi?service=example#key-1");
    }

    #[test]
    fn url_with_the_works() {
        let url = Url::from_str(
            "did:key:123456789abcdefghi/path/to/resource?service=example&hl=hashlink#key-1",
        )
        .expect("should parse url");
        assert_eq!(url.method, Method::Key);
        assert_eq!(url.id, "123456789abcdefghi");
        assert_eq!(
            url.path,
            Some(vec!["path".to_string(), "to".to_string(), "resource".to_string()])
        );
        assert_eq!(
            url.query,
            Some(QueryParams {
                service: Some("example".to_string()),
                hashlink: Some("hashlink".to_string()),
                ..Default::default()
            })
        );
        assert_eq!(url.fragment, Some("key-1".to_string()));
        assert_eq!(url.resource_id(), "did:key:123456789abcdefghi#key-1");
        assert_eq!(
            url.to_string(),
            "did:key:123456789abcdefghi/path/to/resource?service=example&hl=hashlink#key-1"
        );
    }

    #[test]
    fn typical_webvh_url() {
        let url = Url::from_str("did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv").expect("should parse url");
        assert_eq!(url.method, Method::WebVh);
        assert_eq!(url.id, "QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io");
        assert_eq!(url.path, None);
        assert_eq!(url.query, None);
        assert_eq!(
            url.fragment,
            Some("z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv".to_string())
        );
        assert_eq!(
            url.resource_id(),
            "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
        assert_eq!(
            url.to_string(),
            "did:webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
    }

    #[test]
    fn web_url_with_fragment() {
        let s = "did:web:credibil.io:dVYzXm5MMzNAMiQodTFKRlpaXjRCKTBOeW5jTExWNzk#key0".to_string();
        let url = Url::from_str(&s).expect("should parse url");
        assert_eq!(url.method, Method::Web);
        assert_eq!(url.id, "credibil.io:dVYzXm5MMzNAMiQodTFKRlpaXjRCKTBOeW5jTExWNzk");
        assert_eq!(url.path, None);
        assert_eq!(url.query, None);
        assert_eq!(url.fragment, Some("key0".to_string()));
    }

    //--- Parser low level tests -----------------------------------------------

    #[test]
    fn test_parse_scheme() {
        let s = "wibble:key:123456789abcdefghi#key-1";
        assert!(scheme(s).is_err());
        let s = "did:key:123456789abcdefghi#key-1";
        let (next, did) = scheme(s).expect("should parse scheme");
        assert_eq!(did, "did");
        assert_eq!(next, "key:123456789abcdefghi#key-1");
    }

    #[test]
    fn test_parse_method() {
        let s = "wibble:123456789abcdefghi#key-1";
        assert!(method(s).is_err());
        let s = "key:123456789abcdefghi#key-1";
        let (next, m) = method(s).expect("should parse method");
        assert_eq!(m, Method::Key);
        assert_eq!(next, "123456789abcdefghi#key-1");
        let s = "web:credibil.io:dVYzXm5MMzNAMiQodTFKRlpaXjRCKTBOeW5jTExWNzk#key0";
        let (next, m) = method(s).expect("should parse method");
        assert_eq!(m, Method::Web);
        assert_eq!(next, "credibil.io:dVYzXm5MMzNAMiQodTFKRlpaXjRCKTBOeW5jTExWNzk#key0");
        let s = "webvh:QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io%3A8080/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";
        let (next, m) = method(s).expect("should parse method");
        assert_eq!(m, Method::WebVh);
        assert_eq!(
            next,
            "QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io%3A8080/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
    }

    #[test]
    fn test_parse_id() {
        let s = "123456789abcdefghi#key-1";
        let (next, i) = id(s).expect("should parse id");
        assert_eq!(i, "123456789abcdefghi");
        assert_eq!(next, "#key-1");
        let s = "123456789abcdefghi/path/to/resource#key-1";
        let (next, i) = id(s).expect("should parse id");
        assert_eq!(i, "123456789abcdefghi");
        assert_eq!(next, "/path/to/resource#key-1");
        let s = "123456789abcdefghi?service=example#key-1";
        let (next, i) = id(s).expect("should parse id");
        assert_eq!(i, "123456789abcdefghi");
        assert_eq!(next, "?service=example#key-1");
        let s = "QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io%3A8080/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";
        let (next, i) = id(s).expect("should parse id");
        assert_eq!(i, "QmaJp6pmb6RUk4oaDyWQcjeqYbvxsc3kvmHWPpz7B5JwDU:credibil.io");
        assert_eq!(
            next,
            "%3A8080/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
    }

    #[test]
    fn test_parse_port() {
        let s = "?service=example#key-1";
        assert!(port(s).is_err());
        let s = "%3A8080/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";
        let (next, p) = port(s).expect("should parse port");
        assert_eq!(p, 8080);
        assert_eq!(
            next,
            "/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
    }

    #[test]
    fn test_parse_path() {
        let s = "?service=example#key-1";
        assert!(path(s).is_err());
        let s = "/path/to/resource?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";
        let (next, p) = path(s).expect("should parse path");
        assert_eq!(p, vec!["path".to_string(), "to".to_string(), "resource".to_string()]);
        assert_eq!(
            next,
            "?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv"
        );
    }

    #[test]
    fn test_parse_query() {
        let s = "#key-1";
        assert!(query(s).is_err());
        let s = "?service=example#key-1";
        let (next, q) = query(s).expect("should parse query");
        assert_eq!(q.service, Some("example".to_string()));
        assert_eq!(q.relative_ref, None);
        assert_eq!(q.version_id, None);
        assert_eq!(q.version_time, None);
        assert_eq!(q.hashlink, None);
        assert_eq!(next, "#key-1");
        let s = "?service=example&hl=hashlink#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv";
        let (next, q) = query(s).expect("should parse query");
        assert_eq!(q.service, Some("example".to_string()));
        assert_eq!(q.relative_ref, None);
        assert_eq!(q.version_id, None);
        assert_eq!(q.version_time, None);
        assert_eq!(q.hashlink, Some("hashlink".to_string()));
        assert_eq!(next, "#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6MLv");
    }

    #[test]
    fn test_parse_fragment() {
        let s = "?service=example#key-1";
        assert!(fragment(s).is_err());
        let s = "#z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6M-Lv";
        let (next, f) = fragment(s).expect("should parse fragment");
        assert_eq!(f, "z6MkijyunEqPi7hzgJirb4tQLjztCPbJeeZvXEySuzbY6M-Lv");
        assert_eq!(next, "");
    }
}
