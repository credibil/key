//! # Signing

use std::fmt::Display;

use anyhow::anyhow;
use ecdsa::signature::{Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};

/// The signing algorithm used by the signer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Algorithm {
    /// Algorithm for the secp256k1 curve
    #[serde(rename = "ES256K")]
    Es256K,

    /// Algorithm for the Ed25519 curve
    #[default]
    #[serde(rename = "EdDSA")]
    EdDSA,
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Signing
impl Algorithm {
    /// Sign a message with the given private key.
    ///
    /// # Errors
    /// Will return an error if the signature is invalid or the signing key is
    /// not correct for the type of algorithm.
    pub fn try_sign(&self, msg: &[u8], priv_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            Self::Es256K => {
                let signing_key =
                    ecdsa::SigningKey::<k256::Secp256k1>::from_bytes(priv_key.into())?;
                let signature: ecdsa::Signature::<k256::Secp256k1> = signing_key.try_sign(msg)?;
                Ok(signature.to_vec())
            }
            Self::EdDSA => {
                let pk_bytes =
                    priv_key.try_into().map_err(|_| anyhow!("invalid private key length"))?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&pk_bytes);
                let signature = signing_key.sign(msg);
                Ok(signature.to_vec())
            }
        }
    }
}

/// Verification
impl Algorithm {
    /// Verify the signature of a signed message.
    ///
    /// # Errors
    /// Will return an error if the signature is invalid or the verifying key is
    /// not correct for the type of algorithm.
    pub fn verify(&self, msg: &[u8], sig: &[u8], pub_key: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Es256K => {
                let verifying_key =
                    ecdsa::VerifyingKey::<k256::Secp256k1>::from_sec1_bytes(pub_key)?;
                let signature = ecdsa::Signature::<k256::Secp256k1>::from_slice(sig)?;
                let normalized = signature.normalize_s().unwrap_or(signature);
                Ok(verifying_key.verify(msg, &normalized)?)
            }
            Self::EdDSA => {
                let pk_bytes =
                    pub_key.try_into().map_err(|_| anyhow!("invalid public key length"))?;
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)?;
                let signature = ed25519_dalek::Signature::from_slice(sig)?;
                Ok(verifying_key.verify(msg, &signature)?)
            }
        }
    }
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// The verifying key (public key) from the signing keypair.
    ///
    /// The possibility of key rotation mean this key should only be referenced
    /// at the point of verifying a signature.
    fn verifying_key(&self) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// Signature algorithm used by the signer.
    fn algorithm(&self) -> impl Future<Output = anyhow::Result<Algorithm>> + Send;
}
