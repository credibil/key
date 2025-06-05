//! Key management

use anyhow::{Result, anyhow, bail};
use credibil_core::datastore::Datastore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::{
    Algorithm, Curve, PUBLIC_KEY_LENGTH, PublicKey, Receiver, SECRET_KEY_LENGTH, SecretKey,
    SharedSecret, Signer,
};

/// Keyring trait for managing signing and encryption keys.
pub trait Keyring: Send + Sync {
    /// The type used for key entries managed by the keyring.
    type Entry: Signer + Receiver;

    /// Generate a key entry and add to the key ring.
    ///
    /// If the key already exists, it and its associated `next_key` will
    /// be replaced.
    fn generate(
        &self, owner: &str, key_id: &str, curve: Curve,
    ) -> impl Future<Output = Result<Self::Entry>> + Send;

    /// Get the specified key entry.
    fn entry(&self, owner: &str, key_id: &str) -> impl Future<Output = Result<Self::Entry>> + Send;

    /// Rotates the specified key.
    ///
    /// This will result in the active key being archived, the next key being
    /// actived, and a new `next_key` being generated.
    fn rotate(&self, owner: &str, key_id: &str)
    -> impl Future<Output = Result<Self::Entry>> + Send;
}

/// Key entry for signing and encryption operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Entry {
    key_id: String,
    curve: Curve,
    secret_key: Vec<u8>,
    next_secret_key: Vec<u8>,
}

impl Signer for Entry {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sk = self.secret_key.clone();
        let bytes: [u8; SECRET_KEY_LENGTH] =
            sk.try_into().map_err(|_| anyhow!("issue converting secret key"))?;
        let secret_key = SecretKey::from(bytes);

        match self.curve {
            Curve::Ed25519 => Algorithm::EdDSA.try_sign(msg, secret_key),
            Curve::Es256K => Algorithm::Es256K.try_sign(msg, secret_key),
            Curve::P256 => unimplemented!("P256 not yet implemented"),
            Curve::X25519 => bail!("X25519 cannot be used for signing"),
        }
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let sk = self.secret_key.clone();
        let bytes: [u8; SECRET_KEY_LENGTH] =
            sk.try_into().map_err(|_| anyhow!("cannot convert stored vec to slice"))?;

        match self.curve {
            Curve::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from(&bytes);
                Ok(signing_key.verifying_key().to_bytes().to_vec())
            }
            Curve::Es256K => {
                let secret_key = ecies::SecretKey::parse(&bytes)
                    .map_err(|_| anyhow!("cannot deserialize secret key"))?;
                let public_key = ecies::PublicKey::from_secret_key(&secret_key);
                Ok(public_key.serialize().to_vec())
            }
            Curve::P256 => unimplemented!("P256 not implemented yet"),
            Curve::X25519 => bail!("X25519 cannot be used for signing"),
        }
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        match self.curve {
            Curve::Ed25519 => Ok(Algorithm::EdDSA),
            Curve::Es256K => Ok(Algorithm::Es256K),
            Curve::P256 | Curve::X25519 => bail!("unsupported curve"),
        }
    }
}

impl Receiver for Entry {
    async fn key_id(&self) -> Result<String> {
        Ok(self.key_id.clone())
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        let sk = self.secret_key.clone();
        let bytes: [u8; SECRET_KEY_LENGTH] =
            sk.try_into().map_err(|_| anyhow!("cannot convert stored vec to slice"))?;

        match self.curve {
            Curve::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from(&bytes);
                let verifying_key = signing_key.verifying_key();
                let public_key =
                    x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());
                Ok(public_key.to_bytes().to_vec())
            }
            Curve::X25519 => {
                let secret_key = x25519_dalek::StaticSecret::from(bytes);
                let public_key = x25519_dalek::PublicKey::from(&secret_key);
                Ok(public_key.to_bytes().to_vec())
            }
            Curve::Es256K => {
                let secret_key = ecies::SecretKey::parse(&bytes)
                    .map_err(|_| anyhow!("cannot deserialize secret key"))?;
                let public_key = ecies::PublicKey::from_secret_key(&secret_key);
                Ok(public_key.serialize().to_vec())
            }
            Curve::P256 => unimplemented!("P256 not implemented yet"),
        }
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        let sk = self.secret_key.clone();
        let mut bytes: [u8; SECRET_KEY_LENGTH] =
            sk.try_into().map_err(|_| anyhow!("issue converting secret key"))?;

        // convert Ed25519 secret key to X25519.
        if matches!(self.curve, Curve::Ed25519) {
            let signing_key = ed25519_dalek::SigningKey::from(&bytes);
            let hash = Sha512::digest(signing_key.as_bytes());
            let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
            hashed.copy_from_slice(&hash[0..PUBLIC_KEY_LENGTH]);
            bytes = x25519_dalek::StaticSecret::from(hashed).to_bytes();
        }

        let secret_key = SecretKey::from(bytes);
        secret_key.shared_secret(sender_public)
    }
}

impl<T: Datastore> Keyring for T {
    type Entry = Entry;

    async fn generate(&self, owner: &str, key_id: &str, curve: Curve) -> Result<Self::Entry> {
        let entry = Entry {
            key_id: key_id.to_string(),
            curve: curve.clone(),
            secret_key: curve.generate(),
            next_secret_key: curve.generate(),
        };

        let mut data = Vec::new();
        ciborium::into_writer(&entry, &mut data).unwrap();
        Datastore::put(self, owner, "VAULT", key_id, &data).await?;

        Ok(entry)
    }

    async fn entry(&self, owner: &str, key_id: &str) -> Result<Self::Entry> {
        let Some(data) = Datastore::get(self, owner, "VAULT", key_id).await? else {
            return Err(anyhow!("could not find issuer metadata"));
        };
        ciborium::from_reader(data.as_slice()).map_err(Into::into)
    }

    async fn rotate(&self, owner: &str, key_id: &str) -> Result<Self::Entry> {
        let entry = self.entry(owner, key_id).await?;

        let new_entry = Entry {
            key_id: key_id.to_string(),
            curve: entry.curve.clone(),
            secret_key: entry.next_secret_key.clone(),
            next_secret_key: entry.curve.generate(),
        };

        let mut data = Vec::new();
        ciborium::into_writer(&entry, &mut data).unwrap();
        Datastore::put(self, owner, "VAULT", key_id, &data).await?;

        Ok(new_entry)
    }
}
