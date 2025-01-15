//! # JSON Web Signature (JWS)
//!
//! JWS ([RFC7515]) represents content secured with digital signatures using
//! JSON-based data structures. Cryptographic algorithms and identifiers for use
//! with this specification are described in the JWA ([RFC7518]) specification.
//!
//! [RFC7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518

use std::future::Future;
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Verifier as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::jose::jwk::PublicKeyJwk;
pub use crate::jose::jwt::Jwt;
use crate::{Algorithm, Curve, Signer};

/// Encode the provided header and claims payload and sign, returning a JWT in
/// compact JWS form.
///
/// # Errors
/// TODO: document errors
pub async fn encode<T>(payload: &T, signer: &impl Signer) -> Result<String>
where
    T: Serialize + Send + Sync,
{
    tracing::debug!("encode");

    let jws = JwsBuilder::new().payload(payload).add_signer(signer).build().await?;
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
pub async fn decode<F, Fut, T>(compact_jws: &str, resolver: F) -> Result<Jwt<T>>
where
    T: DeserializeOwned + Send,
    F: Fn(String) -> Fut + Send,
    Fut: Future<Output = Result<PublicKeyJwk>> + Send,
{
    tracing::debug!("decode");

    let jws: Jws = compact_jws.parse()?;
    jws.verify(resolver).await?;

    let claims = Base64UrlUnpadded::decode_vec(&jws.payload)
        .map_err(|e| anyhow!("issue decoding claims: {e}"))?;
    let claims =
        serde_json::from_slice(&claims).map_err(|e| anyhow!("issue deserializing claims:{e}"))?;

    let Some(signature) = jws.signatures.first() else {
        bail!("no signature found");
    };

    Ok(Jwt {
        header: signature.protected.clone(),
        claims,
    })
}

/// JWS definition.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Jws {
    /// The stringified CID of the DAG CBOR encoded message `descriptor` property.
    /// An empty string when JWS Unencoded Payload Option used.
    pub payload: String,

    /// JWS signatures.
    pub signatures: Vec<Signature>,
}

impl Jws {
    /// Verify JWS signatures.
    ///
    /// # Errors
    /// TODO: document errors
    pub async fn verify<F, Fut>(&self, resolver: F) -> Result<()>
    where
        F: Fn(String) -> Fut + Send,
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

            let public_jwk = resolver(kid.to_owned()).await?;
            public_jwk.verify(&format!("{header}.{}", self.payload), &sig)?;
        }

        Ok(())
    }

    /// Encode the provided header and claims payload and sign, returning a JWT in
    /// compact JWS form.
    ///
    /// # Errors
    /// An error is returned if there is no signature on the JWS or if the
    /// serialization (for encoding) of the header fails.
    pub fn encode(&self) -> Result<String> {
        let Some(signature) = self.signatures.first() else {
            bail!("no signature found");
        };

        let header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&signature.protected)?);
        let payload = &self.payload;
        let signature = &signature.signature;

        Ok(format!("{header}.{payload}.{signature}"))
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
/// for Vercre: `jku`, `x5u`, `x5t`, `x5t#S256`, `cty`, `crit`.
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
    pub key: Key,

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
    /// Returns the `kid` if the key type is `KeyId`.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        match &self.key {
            Key::KeyId(kid) => Some(kid),
            Key::Jwk(_) => None,
        }
    }

    /// Returns the `kid` if the key is type `KeyId`.
    #[must_use]
    pub const fn jwk(&self) -> Option<&PublicKeyJwk> {
        match &self.key {
            Key::Jwk(jwk) => Some(jwk),
            Key::KeyId(_) => None,
        }
    }
}

impl PublicKeyJwk {
    /// Verify the signature of the provided message using the JWK.
    ///
    /// # Errors
    ///
    /// Will return an error if the signature is invalid, the JWK is invalid, or the
    /// algorithm is unsupported.
    pub fn verify(&self, msg: &str, sig: &[u8]) -> Result<()> {
        match self.crv {
            Curve::Es256K => self.verify_es256k(msg, sig),
            Curve::Ed25519 => self.verify_eddsa(msg, sig),
            Curve::X25519 => bail!("unsupported DSA curve"),
        }
    }

    // Verify the signature of the provided message using the ES256K algorithm.
    fn verify_es256k(&self, msg: &str, sig: &[u8]) -> Result<()> {
        use ecdsa::{Signature, VerifyingKey};
        use k256::Secp256k1;

        // build verifying key
        let y = self.y.as_ref().ok_or_else(|| anyhow!("Proof JWT 'y' is invalid"))?;
        let mut sec1 = vec![0x04]; // uncompressed format
        sec1.append(&mut Base64UrlUnpadded::decode_vec(&self.x)?);
        sec1.append(&mut Base64UrlUnpadded::decode_vec(y)?);

        let verifying_key = VerifyingKey::<Secp256k1>::from_sec1_bytes(&sec1)?;
        let signature: Signature<Secp256k1> = Signature::from_slice(sig)?;
        let normalised = signature.normalize_s().unwrap_or(signature);

        Ok(verifying_key.verify(msg.as_bytes(), &normalised)?)
    }

    // Verify the signature of the provided message using the EdDSA algorithm.
    fn verify_eddsa(&self, msg: &str, sig_bytes: &[u8]) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};

        // build verifying key
        let x_bytes = Base64UrlUnpadded::decode_vec(&self.x)
            .map_err(|e| anyhow!("unable to base64 decode proof JWK 'x': {e}"))?;
        let bytes = &x_bytes.try_into().map_err(|_| anyhow!("invalid public key length"))?;
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| anyhow!("unable to build verifying key: {e}"))?;
        let signature = Signature::from_slice(sig_bytes)
            .map_err(|e| anyhow!("unable to build signature: {e}"))?;

        verifying_key
            .verify(msg.as_bytes(), &signature)
            .map_err(|e| anyhow!("unable to verify signature: {e}"))
    }
}

/// The type of public key material for the JWT.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Key {
    /// Contains the key ID. If the Credential is bound to a DID, the kid refers
    /// to a DID URL which identifies a particular key in the DID Document
    /// that the Credential should bound to. Alternatively, may refer to a
    /// key inside a JWKS.
    #[serde(rename = "kid")]
    KeyId(String),

    /// Contains the key material the new Credential shall be bound to.
    #[serde(rename = "jwk")]
    Jwk(PublicKeyJwk),
}

impl Default for Key {
    fn default() -> Self {
        Self::KeyId(String::new())
    }
}

/// Options to use when creating a permission grant.
#[derive(Clone, Debug, Default)]
pub struct JwsBuilder<P, S> {
    jwt_type: String,
    payload: P,
    signers: S,
}

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
impl JwsBuilder<NoPayload, NoSigners> {
    /// Returns a new [`SubscribeBuilder`]
    #[must_use]
    pub fn new() -> Self {
        // set defaults
        Self {
            jwt_type: "jwt".into(),
            payload: NoPayload,
            signers: NoSigners,
        }
    }

    /// Set the payload to be signed.
    #[must_use]
    pub fn payload<T: Serialize + Send>(
        self, payload: T,
    ) -> JwsBuilder<Payload<T>, NoSigners> {
        JwsBuilder {
            jwt_type: self.jwt_type,
            payload: Payload(payload),
            signers: NoSigners,
        }
    }
}

impl<P, S> JwsBuilder<P, S> {
    /// Specify JWT `typ` header.
    #[must_use]
    pub fn jwt_type(mut self, jwt_type: impl Into<String>) -> Self {
        self.jwt_type = jwt_type.into();
        self
    }

    /// Logically (from user POV), sign the record.
    ///
    /// At this point, the builder simply captures the signer for use in the final
    /// build step. Can only be done if the content hasn't been signed yet.
    #[must_use]
    pub fn add_signer(self, signer: &impl Signer) -> JwsBuilder<P, Signers<impl Signer>> {
        JwsBuilder {
            jwt_type: self.jwt_type,
            payload: self.payload,
            signers: Signers(vec![signer]),
        }
    }
}

impl<T, S> JwsBuilder<Payload<T>, Signers<'_, S>>
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

        let verification_method = signer.verification_method().await?;
        let protected = Protected {
            alg: signer.algorithm(),
            typ: self.jwt_type,
            key: Key::KeyId(verification_method),
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
