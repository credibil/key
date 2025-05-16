//! # JSON Web Signature (JWS)
//!
//! JWS ([RFC7515]) represents content secured with digital signatures using
//! JSON-based data structures. Cryptographic algorithms and identifiers for use
//! with this specification are described in the JWA ([RFC7518]) specification.
//!
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518

use std::fmt;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::str::FromStr;

use anyhow::{Result, anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_se::{Algorithm, Curve, PublicKey, Signer};
use serde::{Deserialize, Serialize};

use crate::KeyBinding;
use crate::jwk::PublicKeyJwk;
pub use crate::jwt::Jwt;

/// Encode the provided header and claims payload and sign, returning a JWT in
/// compact JWS form.
///
/// # Errors
/// TODO: document errors
pub async fn encode_jws<T>(
    payload: &T, verification_method: &KeyBinding, signer: &impl Signer,
) -> Result<String>
where
    T: Serialize + Send + Sync,
{
    tracing::debug!("encode");

    let jws = JwsBuilder::new()
        .payload(payload)
        .add_signer(signer)
        .key_ref(verification_method)
        .build()
        .await?;
    let Some(signature) = jws.signatures.first() else {
        bail!("no signature found");
    };

    let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&signature.protected)?);
    let payload = jws.payload;
    let signature = &signature.signature;

    Ok(format!("{header}.{payload}.{signature}"))
}

// TODO: allow passing verifier into this method

/// Decode the JWT token and return the claims.
///
/// # Errors
/// TODO: document errors
pub async fn decode_jws<Fut, T>(
    compact_jws: &str, jwk_resolver: impl Fn(String) -> Fut,
) -> Result<Jwt<T>>
where
    T: for<'a> Deserialize<'a> + Send,
    Fut: Future<Output = Result<PublicKeyJwk>> + Send,
{
    tracing::debug!("decode");
    compact_jws.parse::<Jws>()?.verify(jwk_resolver).await
}

/// JWS definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Jws {
    /// The stringified CID of the DAG CBOR encoded message `descriptor` property.
    /// An empty string when JWS Unencoded Payload Option used.
    pub payload: String,

    /// JWS signatures.
    pub signatures: Vec<Signature>,
}

impl Jws {
    /// Returns a new JWS builder.
    #[must_use]
    pub fn builder() -> JwsBuilder<NoPayload, NoSigners, NoKey> {
        JwsBuilder::new()
    }

    /// Verify JWS signatures and return the JWT payload if successful.
    ///
    /// # Errors
    /// TODO: document errors
    pub async fn verify<Fut, T>(&self, jwk_resolver: impl Fn(String) -> Fut) -> Result<Jwt<T>>
    where
        T: for<'a> Deserialize<'a> + Send,
        Fut: Future<Output = Result<PublicKeyJwk>> + Send,
    {
        for signature in &self.signatures {
            let header = &signature.protected;
            let Some(kid) = header.kid() else {
                return Err(anyhow!("Missing key ID in JWS signature"));
            };

            // dereference `kid` to JWK matching key ID
            let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header)?);
            let sig = Base64UrlUnpadded::decode_vec(&signature.signature)?;

            let public_jwk = jwk_resolver(kid.to_string()).await?;
            public_jwk.verify(&format!("{header}.{}", self.payload), &sig)?;
        }

        let Some(signature) = self.signatures.first() else {
            bail!("no signature found");
        };

        Ok(Jwt {
            header: signature.protected.clone(),
            claims: self.payload()?,
        })
    }

    /// Encode the provided header and claims payload and sign, returning a JWT
    /// in compact JWS form.
    ///
    /// # Errors
    /// An error is returned if there is no signature on the JWS or if the
    /// serialization (for encoding) of the header fails.
    pub fn encode(&self) -> Result<String> {
        let Some(signature) = self.signatures.first() else {
            bail!("no signature found");
        };

        let header_bytes = serde_json::to_vec(&signature.protected)?;
        let header = Base64UrlUnpadded::encode_string(&header_bytes);
        let payload = &self.payload;
        let signature = &signature.signature;

        Ok(format!("{header}.{payload}.{signature}"))
    }

    /// Extracts the signer's DID from the `kid` of the first JWS signature.
    ///
    /// # Errors
    /// If the `kid` is not found or is invalid, an error is returned. If the
    /// format of the `kid` does not have a key fragment, an error is returned.
    pub fn did(&self) -> Result<String> {
        let Some(kid) = self.signatures[0].protected.kid() else {
            return Err(anyhow!("Invalid `kid`"));
        };
        let Some(did) = kid.split('#').next() else {
            return Err(anyhow!("Invalid DID"));
        };
        Ok(did.to_owned())
    }

    /// Deserialize payload from base64url encoded string.
    ///
    /// # Errors
    /// An error is returned if the payload cannot be decoded or deserialized.
    pub fn payload<T>(&self) -> Result<T>
    where
        T: for<'a> Deserialize<'a>,
    {
        let payload = Base64UrlUnpadded::decode_vec(&self.payload)
            .map_err(|e| anyhow!("issue decoding claims: {e}"))?;
        let claims = serde_json::from_slice(&payload)
            .map_err(|e| anyhow!("issue deserializing claims:{e}"))?;
        Ok(claims)
    }
}

impl Display for Jws {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encode().unwrap())
    }
}

impl FromStr for Jws {
    type Err = anyhow::Error;

    // TODO: cater for different key types
    fn from_str(s: &str) -> Result<Self> {
        let parts = s.split('.').collect::<Vec<&str>>();
        if parts.len() != 3 {
            bail!("invalid Compact JWS format");
        }

        // deserialize header
        let decoded = Base64UrlUnpadded::decode_vec(parts[0])
            .map_err(|e| anyhow!("issue decoding header: {e}"))?;
        let protected = serde_json::from_slice(&decoded)
            .map_err(|e| anyhow!("issue deserializing header: {e}"))?;

        Ok(Self {
            payload: parts[1].to_string(),
            signatures: vec![Signature {
                protected,
                signature: parts[2].to_string(),
            }],
        })
    }
}

/// An entry of the `signatures` array in a general JWS.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signature {
    /// The base64 url-encoded JWS protected header when the JWS protected
    /// header is non-empty. Must have `alg` and `kid` properties set.
    #[serde(with = "base64url")]
    pub protected: Protected,

    /// The base64 url-encoded JWS signature.
    pub signature: String,
}

/// JWS header.
///
/// N.B. The following headers are not included as they are unnecessary
/// for Credibil: `x5u`, `x5t`, `x5t#S256`, `cty`, `crit`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Protected {
    /// Digital signature algorithm identifier as per IANA "JSON Web Signature
    /// and Encryption Algorithms" registry.
    pub alg: Algorithm,

    /// Used to declare the media type [IANA.MediaTypes] of the JWS.
    ///
    /// [IANA.MediaTypes]: (http://www.iana.org/assignments/media-types)
    pub typ: String,

    /// The key material for the public key.
    #[serde(flatten)]
    pub key: KeyBinding,

    /// Contains a certificate (or certificate chain) corresponding to the key
    /// used to sign the JWT. This element MAY be used to convey a key
    /// attestation. In such a case, the actual key certificate will contain
    /// attributes related to the key properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// Contains an OpenID.Federation Trust Chain. This element MAY be used to
    /// convey key attestation, metadata, metadata policies, federation
    /// Trust Marks and any other information related to a specific
    /// federation, if available in the chain.
    ///
    /// When used for signature verification, `kid` MUST be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<String>,
}

impl Protected {
    /// Returns the `kid` if the key type is `Kid` or `Jku`.
    #[must_use]
    pub const fn kid(&self) -> Option<&str> {
        match &self.key {
            KeyBinding::Kid(kid) | KeyBinding::Jku { kid, .. } => Some(kid.as_str()),
            KeyBinding::Jwk(_) => None,
        }
    }

    /// Returns the `jwk` if the key is type `Jwk`.
    #[must_use]
    pub const fn jwk(&self) -> Option<&PublicKeyJwk> {
        match &self.key {
            KeyBinding::Jwk(jwk) => Some(jwk),
            _ => None,
        }
    }

    /// Returns the `jku` if the key type is `Jku`.
    #[must_use]
    pub const fn jku(&self) -> Option<&str> {
        match &self.key {
            KeyBinding::Jku { jku, .. } => Some(jku.as_str()),
            _ => None,
        }
    }
}

impl PublicKeyJwk {
    /// Verify the signature of the provided message using the JWK.
    ///
    /// # Errors
    ///
    /// Will return an error if the signature is invalid, the JWK is invalid, or
    /// the algorithm is unsupported.
    pub fn verify(&self, msg: &str, sig: &[u8]) -> Result<()> {
        match self.crv {
            Curve::Es256K => self.verify_es256k(msg.as_bytes(), sig),
            Curve::Ed25519 => self.verify_eddsa(msg.as_bytes(), sig),
            _ => bail!("unsupported DSA curve"),
        }
    }

    /// Verify the signature of the provided message in bytes using the JWK.
    ///
    /// # Errors
    ///
    /// Will return an error if the signature is invalid, the JWK is invalid, or
    /// the algorithm is unsupported.
    pub fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        match self.crv {
            Curve::Es256K => self.verify_es256k(msg, sig),
            Curve::Ed25519 => self.verify_eddsa(msg, sig),
            _ => bail!("unsupported DSA curve"),
        }
    }

    // Verify the signature of the provided message using the ES256K algorithm.
    fn verify_es256k(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        // build verifying key
        let y = self.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut Base64UrlUnpadded::decode_vec(&self.x)?);
        sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

        let vk: PublicKey = sec1.try_into()?;
        Algorithm::Es256K.verify(msg, sig, &vk)
        //Algorithm::Es256K.verify(msg, sig, &sec1)
    }

    // Verify the signature of the provided message using the EdDSA algorithm.
    fn verify_eddsa(&self, msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
        // build verifying key
        let x_bytes = Base64UrlUnpadded::decode_vec(&self.x)
            .map_err(|e| anyhow!("unable to base64 decode proof JWK 'x': {e}"))?;

        let vk: PublicKey = x_bytes.try_into()?;
        Algorithm::EdDSA.verify(msg, sig_bytes, &vk)
        //Algorithm::EdDSA.verify(msg, sig_bytes, &x_bytes)
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct JwsBuilder<P, S, K> {
    typ: String,
    payload: P,
    signers: S,
    key: K,
}

#[doc(hidden)]
/// Typestate generic for a JWS builder with no public key (cannot build).
pub struct NoKey;

#[doc(hidden)]
/// Typestate generic for a JWS builder with a public key (can build).
pub struct WithKey(KeyBinding);

#[doc(hidden)]
/// Typestate generic for a JWS builder with no payload.
pub struct NoPayload;
#[doc(hidden)]
/// Typestate generic for a JWS builder with a payload.
pub struct Payload<T: Serialize + Send>(T);

#[doc(hidden)]
/// Typestate generic for a JWS builder with no signer.
pub struct NoSigners;
#[doc(hidden)]
/// Typestate generic for a JWS builder with a signer.
pub struct Signers<'a, S: Signer>(pub Vec<&'a S>);

/// Builder for creating a permission grant.
impl JwsBuilder<NoPayload, NoSigners, NoKey> {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            typ: "jwt".into(),
            payload: NoPayload,
            signers: NoSigners,
            key: NoKey,
        }
    }
}

impl<K> JwsBuilder<NoPayload, NoSigners, K> {
    /// Set the payload to be signed.
    #[must_use]
    pub fn payload<T: Serialize + Send>(self, payload: T) -> JwsBuilder<Payload<T>, NoSigners, K> {
        JwsBuilder {
            typ: self.typ,
            payload: Payload(payload),
            signers: NoSigners,
            key: self.key,
        }
    }
}

impl<P, S, K> JwsBuilder<P, S, K> {
    /// Specify JWT `typ` header.
    #[must_use]
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = typ.into();
        self
    }

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the final
    /// build step. Can only be done if the content hasn't been signed yet.
    #[must_use]
    pub fn add_signer(self, signer: &impl Signer) -> JwsBuilder<P, Signers<impl Signer>, K> {
        JwsBuilder {
            typ: self.typ,
            payload: self.payload,
            signers: Signers(vec![signer]),
            key: self.key,
        }
    }
}

impl<P, S> JwsBuilder<P, S, NoKey> {
    /// Specify the method to use to resolve a verification key.
    #[must_use]
    pub fn key_ref(self, key: &KeyBinding) -> JwsBuilder<P, S, WithKey> {
        JwsBuilder {
            typ: self.typ,
            payload: self.payload,
            signers: self.signers,
            key: WithKey(key.clone()),
        }
    }
}

impl<T, S> JwsBuilder<Payload<T>, Signers<'_, S>, WithKey>
where
    T: Serialize + Send,
    S: Signer,
{
    /// Generate the JWS.
    ///
    /// # Errors
    /// TODO: Add errors
    pub async fn build(self) -> Result<Jws> {
        let Some(signer) = self.signers.0.first() else {
            bail!("no signers found");
        };

        let protected = Protected {
            alg: signer.algorithm().await?,
            typ: self.typ,
            key: self.key.0,
            ..Protected::default()
        };

        let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&protected)?);
        let payload = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&self.payload.0)?);
        let sig = signer.try_sign(format!("{header}.{payload}").as_bytes()).await?;

        Ok(Jws {
            payload,
            signatures: vec![Signature {
                protected,
                signature: Base64UrlUnpadded::encode_string(&sig),
            }],
        })
    }
}

mod base64url {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};

    pub fn serialize<T, S>(value: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: serde::ser::Serializer,
    {
        let bytes = serde_json::to_vec(&value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&Base64UrlUnpadded::encode_string(&bytes))
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: DeserializeOwned,
        D: serde::de::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = Base64UrlUnpadded::decode_vec(&encoded).map_err(serde::de::Error::custom)?;
        serde_json::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}
