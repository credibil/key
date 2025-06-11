//! Key management

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::{Curve, PublicKey, SecretKey, SharedSecret};
use crate::encrypt::Receiver;
use crate::sign::{Algorithm, Signer};
use crate::vault::Vault;

/// Keyring trait for managing signing and encryption keys.
pub trait Keyring: Send + Sync {
    /// The type used for key entries managed by the keyring.
    type Entry: Signer + Receiver + NextKey;

    /// Generate a key entry and add to the key ring.
    ///
    /// If the key already exists, it and its associated `next_key` will
    /// be replaced.
    fn generate(
        &self, owner: &str, key_id: &str, curve: Curve,
    ) -> impl Future<Output = Result<Self::Entry>> + Send;

    /// Get the specified key entry.
    fn entry(&self, owner: &str, key_id: &str) -> impl Future<Output = Result<Self::Entry>> + Send;

    /// Rotate the specified key.
    ///
    /// This will result in the active key being archived, the next key being
    /// actived, and a new `next_key` being generated.
    fn rotate(&self, entry: Self::Entry) -> impl Future<Output = Result<Self::Entry>> + Send;

    /// List the key ids for all keyring entries.
    fn key_ids(&self, owner: &str) -> impl Future<Output = Result<Vec<String>>> + Send;
}

/// Keyring entries are required to return the public key of their next key pair.
pub trait NextKey: Send + Sync {
    /// Returns the next public key.
    fn next_key(&self) -> impl Future<Output = Result<PublicKey>> + Send;
}

/// Key entry for signing and encryption operations.
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    owner: String,
    #[zeroize(skip)]
    key_id: String,
    #[zeroize(skip)]
    curve: Curve,
    secret_key: SecretKey,
    next_secret_key: SecretKey,
}

impl Entry {
    /// Restore a previously CBOR-serialized `Entry`.
    ///
    /// # Errors
    /// Returns an error if the bytes cannot be deserialized into an `Entry`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(Into::into)
    }

    /// Serialize the entry to CBOR.
    ///
    /// # Errors
    /// Returns an error if the entry cannot be serialized to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        ciborium::into_writer(self, &mut data)
            .map_err(|e| anyhow!("issue serializing entry: {e}"))?;
        Ok(data)
    }
}

impl Signer for Entry {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self.curve {
            Curve::Ed25519 => Algorithm::EdDSA.try_sign(msg, &self.secret_key),
            Curve::Es256K => Algorithm::Es256K.try_sign(msg, &self.secret_key),
            Curve::P256 => unimplemented!("P256 not yet implemented"),
            Curve::X25519 => bail!("X25519 cannot be used for signing"),
        }
    }

    async fn verifying_key(&self) -> Result<PublicKey> {
        match self.curve {
            Curve::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::try_from(&self.secret_key)?;
                Ok(signing_key.verifying_key().into())
            }
            Curve::Es256K => {
                let secret_key = ecies::SecretKey::try_from(&self.secret_key)?;
                Ok(ecies::PublicKey::from_secret_key(&secret_key).into())
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

    async fn public_key(&self) -> Result<PublicKey> {
        match self.curve {
            Curve::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::try_from(&self.secret_key)?;
                let verifying_key = signing_key.verifying_key();
                let public_key =
                    x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());
                Ok(public_key.into())
            }
            Curve::X25519 => {
                let secret_key = x25519_dalek::StaticSecret::try_from(&self.secret_key)?;
                Ok(x25519_dalek::PublicKey::from(&secret_key).into())
            }
            Curve::Es256K => {
                let secret_key = ecies::SecretKey::try_from(&self.secret_key)?;
                Ok(ecies::PublicKey::from_secret_key(&secret_key).into())
            }
            Curve::P256 => unimplemented!("P256 not implemented yet"),
        }
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> Result<SharedSecret> {
        let secret_key = if self.curve == Curve::Ed25519 {
            // convert Ed25519 secret key to X25519.
            let signing_key = ed25519_dalek::SigningKey::try_from(&self.secret_key)?;
            let hash = Sha512::digest(signing_key.as_bytes());
            let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
            hashed.copy_from_slice(&hash[0..PUBLIC_KEY_LENGTH]);
            let bytes = x25519_dalek::StaticSecret::from(hashed).to_bytes();
            &SecretKey::from(bytes)
        } else {
            &self.secret_key
        };

        secret_key.shared_secret(sender_public)
    }
}

impl NextKey for Entry {
    /// Returns the next verifying/public key.
    async fn next_key(&self) -> Result<PublicKey> {
        match self.curve {
            Curve::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::try_from(&self.next_secret_key)?;
                Ok(signing_key.verifying_key().into())
            }
            Curve::X25519 => {
                let secret_key = x25519_dalek::StaticSecret::try_from(&self.next_secret_key)?;
                Ok(x25519_dalek::PublicKey::from(&secret_key).into())
            }
            Curve::Es256K => {
                let secret_key = ecies::SecretKey::try_from(&self.next_secret_key)?;
                Ok(ecies::PublicKey::from_secret_key(&secret_key).into())
            }
            Curve::P256 => unimplemented!("P256 not implemented yet"),
        }
    }
}

impl TryFrom<Vec<u8>> for Entry {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&value)
    }
}

impl TryFrom<Entry> for Vec<u8> {
    type Error = anyhow::Error;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        entry.to_bytes()
    }
}

impl<T: Vault> Keyring for T {
    type Entry = Entry;

    async fn generate(&self, owner: &str, key_id: &str, curve: Curve) -> Result<Self::Entry> {
        let entry = Entry {
            owner: owner.to_string(),
            key_id: key_id.to_string(),
            curve: curve.clone(),
            secret_key: curve.generate().try_into()?,
            next_secret_key: curve.generate().try_into()?,
        };
        Vault::put(self, owner, "VAULT", key_id, &entry.to_bytes()?).await?;

        Ok(entry)
    }

    async fn entry(&self, owner: &str, key_id: &str) -> Result<Self::Entry> {
        let Some(data) = Vault::get(self, owner, "VAULT", key_id).await? else {
            return Err(anyhow!("could not find issuer metadata"));
        };
        Entry::from_bytes(&data)
    }

    async fn rotate(&self, entry: Self::Entry) -> Result<Self::Entry> {
        let key_id = entry.key_id.clone();
        let owner = entry.owner.clone();

        let new_entry = Entry {
            owner,
            key_id,
            curve: entry.curve.clone(),
            secret_key: entry.next_secret_key.clone(),
            next_secret_key: entry.curve.generate().try_into()?,
        };

        Vault::put(self, &new_entry.owner, "VAULT", &new_entry.key_id, &new_entry.to_bytes()?)
            .await?;

        Ok(new_entry)
    }

    async fn key_ids(&self, owner: &str) -> Result<Vec<String>> {
        let items = Vault::get_all(self, owner, "VAULT").await?;

        let mut entries = vec![];
        for (_, bytes) in items {
            let entry = Entry::from_bytes(&bytes)?;
            entries.push(entry.key_id.clone());
        }

        Ok(entries)
    }
}
