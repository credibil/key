//! # Signing

use std::fmt::Display;

use ecdsa::signature::Verifier as _;
use serde::{Deserialize, Serialize};

use crate::PublicKey;

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

/// Verifications
impl Algorithm {
    /// Verify the signature of a signed message.
    ///
    /// # Errors
    /// Will return an error if the signature is invalid or the verifying key is
    /// not correct for the type of algorithm.
    pub fn verify(&self, msg: &[u8], sig: &[u8], verifying_key: &PublicKey) -> anyhow::Result<()> {
        match self {
            Self::Es256K => {
                let vk: ecdsa::VerifyingKey<k256::Secp256k1> = (*verifying_key).try_into()?;
                // let verifying_key =
                //     ecdsa::VerifyingKey::<k256::Secp256k1>::from_sec1_bytes(verifying_key)?;
                let signature = ecdsa::Signature::<k256::Secp256k1>::from_slice(sig)?;
                let normalized = signature.normalize_s().unwrap_or(signature);
                Ok(vk.verify(msg, &normalized)?)
            }
            Self::EdDSA => {
                let vk: ed25519_dalek::VerifyingKey = (*verifying_key).try_into()?;
                // let pk_bytes =
                //     verifying_key.try_into().map_err(|_| anyhow!("invalid public key length"))?;
                // let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)?;
                let signature = ed25519_dalek::Signature::from_slice(sig)?;
                Ok(vk.verify(msg, &signature)?)
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
