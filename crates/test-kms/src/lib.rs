//! Basic key store for testing

mod blockstore;

use anyhow::{anyhow, bail};
use blockstore::Mockstore;
use credibil_se::{
    Algorithm, Curve, PUBLIC_KEY_LENGTH, PublicKey, Receiver, SecretKey, SharedSecret, Signer,
};
use ed25519_dalek::Signer as _;
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Key as serialized and stored to the blob store.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredKey {
    /// The elliptic curve algorithm used for key generation.
    pub curve: Curve,

    /// The key itself (private key).
    pub key: Vec<u8>,

    /// The next (private) key to use.
    /// TODO: This is over-simplified for testing purposes. Do need a next key
    /// for, say `did:webvh` but also need to be able to version keys on
    /// rotation and optionally disable key versions.
    pub next_key: Vec<u8>,
}

impl StoredKey {
    /// Serialize the key to a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).unwrap();
        buf
    }

    /// Deserialize a byte array to a `StoredKey`.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ciborium::from_reader(bytes).map_err(Into::into)
    }
}

/// An index of keys in the keyring.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct IndexEntry {
    /// Keyring owner.
    pub owner: String,

    /// Keyring partition.
    pub partition: String,

    /// Name or ID of the key.
    pub id: String,
}

/// Keyring index.
pub struct KeyringIndex(Vec<IndexEntry>);

impl Default for KeyringIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyringIndex {
    /// Create a new keyring index.
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add a new entry to the keyring index.
    pub fn add(&mut self, entry: IndexEntry) {
        self.0.push(entry);
    }

    /// Remove an entry from the keyring index.
    pub fn remove(&mut self, entry: &IndexEntry) {
        self.0.retain(|e| e != entry);
    }

    /// Serialize the keyring index to a byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(&self.0, &mut buf).unwrap();
        buf
    }

    /// Deserialize a byte array to a `KeyringIndex`.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let entries: Vec<IndexEntry> = ciborium::from_reader(bytes)?;
        Ok(Self(entries))
    }
}

/// A simple keyring that stores secret keys and their usage types in memory.
///
/// Suitable for testing only.
#[derive(Clone)]
pub struct Keyring {
    owner: String,
    blockstore: Mockstore,
}

// TODO: The API for a production keyring should include partition and optional
// version to dereference a key, not just an ID
impl Keyring {
    /// Create a new keyring and initialize a block for key indexes.
    ///
    /// # Errors
    /// Will return an error if storage of an index block fails.
    pub async fn new(owner: impl ToString) -> anyhow::Result<Self> {
        let owner = owner.to_string();
        let blockstore = Mockstore::new();
        let index = KeyringIndex::new();
        let index_bytes = index.to_bytes();
        blockstore.put(&owner, "keyring", "index", &index_bytes).await?;

        Ok(Self { owner, blockstore })
    }

    /// Add a newly generated key and a corresponding next key to the keyring.
    ///
    /// # Errors
    /// Will return an error if the storage fails or the index cannot be
    /// updated. Will also return an error if the key already exists (use
    /// `replace` instead).
    pub async fn add(&mut self, curve: &Curve, id: impl ToString) -> anyhow::Result<()> {
        if self.blockstore.exists(&self.owner, "", &id.to_string()).await? {
            bail!("key already exists");
        }
        let key_bytes = curve.generate();
        let next_key_bytes = curve.generate();
        let stored_key = StoredKey {
            curve: curve.clone(),
            key: key_bytes.clone(),
            next_key: next_key_bytes.clone(),
        };
        self.blockstore.put(&self.owner, "", &id.to_string(), &stored_key.to_bytes()).await?;

        // Update the index.
        self.add_index_entry(id).await?;

        Ok(())
    }

    /// Replace a key in the keyring with a new one. Generates a corresponding
    /// next key.
    ///
    /// # Errors
    /// Will return an error if the requested key does not exist in the keyring.
    /// (Use `add` instead).
    pub async fn replace(&mut self, id: impl ToString) -> anyhow::Result<()> {
        // Check for existence of the key
        let existing = self.blockstore.get(&self.owner, "", &id.to_string()).await?;
        let Some(existing) = existing else {
            bail!("key not found");
        };
        let existing = StoredKey::from_bytes(&existing)?;
        self.blockstore.delete(&self.owner, "", &id.to_string()).await?;
        self.add(&existing.curve, id).await
    }

    /// Add a key to the keyring with the the given ID (and its next key),
    /// replacing any existing key with the same ID.
    /// 
    /// # Errors
    /// Will return an error if the requested key cannot be added to the
    /// underlying storage.
    pub async fn add_or_replace(
        &mut self,
        curve: &Curve,
        id: impl ToString,
    ) -> anyhow::Result<()> {
        if self.blockstore.exists(&self.owner, "", &id.to_string()).await? {
            self.replace(id).await
        } else {
            self.add(curve, id).await
        }
    }

    /// Rotate all keys in the keyring.
    ///
    /// # Errors
    /// Will return an error if the storage fails, including retrieving the
    /// index.
    pub async fn rotate_all(&mut self) -> anyhow::Result<()> {
        let index_bytes = self
            .blockstore
            .get(&self.owner, "keyring", "index")
            .await?
            .ok_or(anyhow!("index not found"))?;
        let mut index = KeyringIndex::from_bytes(&index_bytes)?;
        for entry in &mut index.0 {
            let id = &entry.id;

            let current_key =
                self.blockstore.get(&self.owner, "", id).await?.ok_or(anyhow!("key not found"))?;
            let current_key = StoredKey::from_bytes(&current_key)?;
            let next_key = current_key.curve.generate();
            let new_key = StoredKey {
                curve: current_key.curve.clone(),
                key: current_key.next_key,
                next_key,
            };
            self.blockstore.delete(&self.owner, "", id).await?;
            self.blockstore.put(&self.owner, "", id, &new_key.to_bytes()).await?;
        }
        Ok(())
    }

    /// Rotate a key in the keyring.
    ///
    /// # Errors
    /// Will return an error if the requested key does not exist in the keyring.
    pub async fn rotate(&mut self, id: impl ToString) -> anyhow::Result<()> {
        let current_key = self
            .blockstore
            .get(&self.owner, "", &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let current_key = StoredKey::from_bytes(&current_key)?;
        let next_key = current_key.curve.generate();
        let new_key = StoredKey {
            curve: current_key.curve.clone(),
            key: current_key.next_key,
            next_key,
        };
        self.blockstore.delete(&self.owner, "", &id.to_string()).await?;
        self.blockstore.put(&self.owner, "", &id.to_string(), &new_key.to_bytes()).await
    }

    /// Remove a key from the keyring.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be removed from storage
    /// or the index cannot be updated.
    pub async fn remove(&mut self, id: impl ToString) -> anyhow::Result<()> {
        self.blockstore.delete(&self.owner, "", &id.to_string()).await?;
        self.remove_index_entry(id).await
    }

    /// Get a public key for encryption from the keyring with the given ID.
    ///
    /// Use `verifying_key` to get a public key for verifying a signature
    /// (assuming the key is from an appropriate curve).
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or if the public key cannot be inferred from the private key.
    pub async fn public_key(&self, id: impl ToString) -> anyhow::Result<PublicKey> {
        let stored_key = self
            .blockstore
            .get(&self.owner, "", &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        match stored_key.curve {
            Curve::Ed25519 => {
                let signing_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let signing_key = ed25519_dalek::SigningKey::from(&signing_key_bytes);
                let verifying_key = signing_key.verifying_key();
                let public_key =
                    x25519_dalek::PublicKey::from(verifying_key.to_montgomery().to_bytes());
                Ok(PublicKey::from(public_key))
            }
            Curve::X25519 => {
                let secret_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let secret_key = x25519_dalek::StaticSecret::from(secret_key_bytes);
                let public_key = x25519_dalek::PublicKey::from(&secret_key);
                Ok(PublicKey::from(public_key))
            }
            Curve::Es256K => {
                let secret_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let secret_key = ecies::SecretKey::parse(&secret_key_bytes)
                    .map_err(|_| anyhow!("cannot deserialize secret key"))?;
                let public_key = ecies::PublicKey::from_secret_key(&secret_key);
                Ok(PublicKey::from(public_key))
            }
            Curve::P256 => {
                unimplemented!("P256 not implemented yet");
            }
        }
    }

    /// Get the private key for encryption from the keyring with the given ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or cannot be converted from the stored bytes.
    pub async fn private_key(&self, id: impl ToString) -> anyhow::Result<SecretKey> {
        let stored_key = self
            .blockstore
            .get(&self.owner, "", &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        let mut secret_key_bytes: [u8; PUBLIC_KEY_LENGTH] =
            stored_key.key.try_into().map_err(|_| anyhow!("cannot convert stored vec to slice"))?;

        // If the key is Ed25519 we need to convert it to a X25519 key.
        if matches!(stored_key.curve, Curve::Ed25519) {
            let signing_key = ed25519_dalek::SigningKey::from(&secret_key_bytes);
            let hash = sha2::Sha512::digest(signing_key.as_bytes());
            let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
            hashed.copy_from_slice(&hash[0..PUBLIC_KEY_LENGTH]);

            secret_key_bytes = x25519_dalek::StaticSecret::from(hashed).to_bytes();
        }

        let secret_key = SecretKey::from(secret_key_bytes);
        Ok(secret_key)
    }

    /// Get the curve for the keyring key with the given ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage.
    pub async fn curve(&self, id: impl ToString) -> anyhow::Result<Curve> {
        let stored_key = self
            .blockstore
            .get(&self.owner, "", &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        Ok(stored_key.curve)
    }

    /// Sign a message with the keyring key with the given ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or if the key cannot be converted to a signing key (including
    /// if the key is not a signing key or the key's algorithm is not currently
    /// supported).
    pub async fn sign(&self, id: impl ToString, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let stored_key = self
            .blockstore
            .get(&self.owner, "", &id.to_string())
            .await?
            .ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        match stored_key.curve {
            Curve::Ed25519 => {
                let signing_key_bytes: [u8; PUBLIC_KEY_LENGTH] = stored_key
                    .key
                    .try_into()
                    .map_err(|_| anyhow!("cannot convert stored vec to slice"))?;
                let signing_key = ed25519_dalek::SigningKey::from(&signing_key_bytes);
                Ok(signing_key.sign(msg).to_bytes().to_vec())
            }
            Curve::X25519 => {
                bail!("X25519 cannot be used for signing");
            }
            Curve::Es256K => {
                bail!("ES256K cannot be used for signing");
            }
            Curve::P256 => {
                unimplemented!("P256 not implemented yet");
            }
        }
    }

    /// Get the verifying key for the keyring key with the given ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or if the key cannot be converted to a signing key (including
    /// if the key's algorithm is not currently supported).
    pub async fn verifying_key(&self, id: impl ToString) -> anyhow::Result<Vec<u8>> {
        self.vk(&id.to_string(), false).await
    }

    /// Get the next verifying key on key rotation for the key with the given ID.
    ///
    /// # Errors
    /// Will return an error if the requested key cannot be retrieved from
    /// storage or if the key cannot be converted to a signing key (including
    /// if the key's algorithm is not currently supported).
    pub async fn next_verifying_key(&self, id: impl ToString) -> anyhow::Result<Vec<u8>> {
        self.vk(&id.to_string(), true).await
    }

    // Get a verifying key for the keyring key with the given ID if possible.
    // Return the current or next key depending on the flag.
    async fn vk(&self, id: &str, next: bool) -> anyhow::Result<Vec<u8>> {
        let stored_key =
            self.blockstore.get(&self.owner, "", id).await?.ok_or(anyhow!("key not found"))?;
        let stored_key = StoredKey::from_bytes(&stored_key)?;
        match stored_key.curve {
            Curve::Ed25519 => {
                let signing_key_bytes: [u8; PUBLIC_KEY_LENGTH] = if next {
                    stored_key
                        .next_key
                        .try_into()
                        .map_err(|_| anyhow!("cannot convert stored vec to slice"))?
                } else {
                    stored_key
                        .key
                        .try_into()
                        .map_err(|_| anyhow!("cannot convert stored vec to slice"))?
                };
                let signing_key = ed25519_dalek::SigningKey::from(&signing_key_bytes);
                Ok(signing_key.verifying_key().to_bytes().to_vec())
            }
            Curve::X25519 => {
                bail!("X25519 cannot be used for signing");
            }
            Curve::Es256K => {
                bail!("ES256K cannot be used for signing");
            }
            Curve::P256 => {
                unimplemented!("P256 not implemented yet");
            }
        }
    }

    /// Add an entry to the keyring index.
    ///
    /// # Errors
    /// Will return an error if the index cannot be updated.
    async fn add_index_entry(&mut self, id: impl ToString) -> anyhow::Result<()> {
        let entry = IndexEntry {
            owner: self.owner.clone(),
            partition: "".to_string(),
            id: id.to_string(),
        };
        let mut index = KeyringIndex::from_bytes(
            &self
                .blockstore
                .get(&self.owner, "keyring", "index")
                .await?
                .ok_or(anyhow!("index not found"))?,
        )?;
        index.add(entry);
        self.blockstore.delete(&self.owner, "keyring", "index").await?;
        self.blockstore.put(&self.owner, "keyring", "index", &index.to_bytes()).await
    }

    /// Remove an entry from the keyring index.
    ///
    /// # Errors
    /// Will return an error if the index cannot be updated.
    async fn remove_index_entry(&mut self, id: impl ToString) -> anyhow::Result<()> {
        let entry = IndexEntry {
            owner: self.owner.clone(),
            partition: "".to_string(),
            id: id.to_string(),
        };
        let mut index = KeyringIndex::from_bytes(
            &self
                .blockstore
                .get(&self.owner, "keyring", "index")
                .await?
                .ok_or(anyhow!("index not found"))?,
        )?;
        index.remove(&entry);
        self.blockstore.delete(&self.owner, "keyring", "index").await?;
        self.blockstore.put(&self.owner, "keyring", "index", &index.to_bytes()).await
    }
}

/// A struct to manage which key in the keyring is used as the receiver's key.
/// TODO: A fuller implementation would need to include owner and partition
/// information.
pub struct KeyringReceiver {
    /// The key ID of the receiver.
    key_id: String,

    /// The keyring to use for encryption.
    keyring: Keyring,
}

impl KeyringReceiver {
    /// Create a new keyring receiver.
    #[must_use]
    pub fn new(key_id: impl ToString, keyring: Keyring) -> Self {
        Self {
            key_id: key_id.to_string(),
            keyring,
        }
    }
}

/// Receiver implementation for the keyring for encryption.
impl Receiver for KeyringReceiver {
    async fn key_id(&self) -> anyhow::Result<String> {
        Ok(self.key_id.clone())
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
        let sk = self.keyring.private_key(&self.key_id).await?;
        sk.shared_secret(sender_public)
    }
}

/// A struct to manage with key in the keyring is used for signing.
/// TODO: A fuller implementation would need to include owner and partition
/// information and would need to deal with key versions.
pub struct KeyringSigner {
    /// The key ID for the signing key.
    key_id: String,

    /// The keyring to get the key from for signing.
    keyring: Keyring,
}

impl KeyringSigner {
    /// Create a new keyring signer.
    #[must_use]
    pub fn new(key_id: impl ToString, keyring: Keyring) -> Self {
        Self {
            key_id: key_id.to_string(),
            keyring,
        }
    }
}

/// Signer implementation for the keyring for signing.
impl Signer for KeyringSigner {
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.keyring.sign(&self.key_id, msg).await
    }

    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        self.keyring.verifying_key(&self.key_id).await
    }

    async fn algorithm(&self) -> anyhow::Result<Algorithm> {
        let curve = self.keyring.curve(&self.key_id).await?;
        let algorithm = match curve {
            Curve::Ed25519 => Algorithm::EdDSA,
            Curve::Es256K => Algorithm::Es256K,
            _ => {
                bail!("unsupported algorithm for signing")
            }
        };
        Ok(algorithm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keyring_crud() {
        let mut keyring = Keyring::new("keyring_crud").await.expect("keyring created");

        // Create an Ed25519 key
        keyring.add(&Curve::Ed25519, "one").await.expect("Ed25519 key added");

        // Get the public key for the Ed25519 key.
        let _ = keyring.public_key("one").await.expect("Ed25519 key retrieved");

        // Create an X25519 key
        keyring.add(&Curve::X25519, "two").await.expect("key added");

        // Get the public key for the X25519 key.
        let _ = keyring.public_key("two").await.expect("X25519 key retrieved");

        // Create an ES256k key
        keyring.add(&Curve::Es256K, "three").await.expect("key added");

        // Get the public key for the ES256k key.
        let _ = keyring.public_key("three").await.expect("ES256k key retrieved");

        // Rotate all the keys
        keyring.rotate_all().await.expect("all keys rotated");

        // Rotate the Ed25519 key
        keyring.rotate("one").await.expect("Ed25519 key rotated");

        // Replace the X25519 key
        keyring.replace("two").await.expect("X25519 key replaced");

        // Remove the Ed25519 key
        keyring.remove("one").await.expect("Ed25519 key removed");

        // Remove the X25519 key
        keyring.remove("two").await.expect("X25519 key removed");

        // Remove the ES256k key
        keyring.remove("three").await.expect("ES256k key removed");

        // Check that the keys are removed
        assert!(keyring.public_key("one").await.is_err());
        assert!(keyring.public_key("two").await.is_err());
        assert!(keyring.public_key("three").await.is_err());
    }

    // Test that when a key is rotated, the previous next key is the current
    // key.
    #[tokio::test]
    async fn key_rotation() {
        let mut keyring = Keyring::new("key_rotation").await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "one").await.expect("key added");
        let next_verifying_key =
            keyring.next_verifying_key("one").await.expect("next verifying key retrieved");
        // Rotate the key
        keyring.rotate("one").await.expect("key rotated");
        let verifying_key = keyring.verifying_key("one").await.expect("verifying key retrieved");
        assert_eq!(next_verifying_key, verifying_key);
    }

    // Test that when all keys are rotated, the previous next key is the current
    // key.
    #[tokio::test]
    async fn all_key_rotation() {
        let mut keyring = Keyring::new("all_key_rotation").await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "one").await.expect("key added");
        keyring.add(&Curve::Ed25519, "two").await.expect("key added");
        keyring.add(&Curve::Ed25519, "three").await.expect("key added");
        let next_verifying_key1 =
            keyring.next_verifying_key("one").await.expect("next verifying key retrieved");
        let next_verifying_key2 =
            keyring.next_verifying_key("two").await.expect("next verifying key retrieved");
        let next_verifying_key3 =
            keyring.next_verifying_key("three").await.expect("next verifying key retrieved");
        // Rotate all keys
        keyring.rotate_all().await.expect("all keys rotated");
        let verifying_key1 = keyring.verifying_key("one").await.expect("verifying key retrieved");
        let verifying_key2 = keyring.verifying_key("two").await.expect("verifying key retrieved");
        let verifying_key3 = keyring.verifying_key("three").await.expect("verifying key retrieved");
        assert_eq!(next_verifying_key1, verifying_key1);
        assert_eq!(next_verifying_key2, verifying_key2);
        assert_eq!(next_verifying_key3, verifying_key3);
    }

    // Test that key replacement results in a new key.
    #[tokio::test]
    async fn key_replacement() {
        let mut keyring = Keyring::new("key_replacement").await.expect("keyring created");
        keyring.add(&Curve::Ed25519, "one").await.expect("key added");
        let verifying_key1 = keyring.verifying_key("one").await.expect("verifying key retrieved");
        keyring.replace("one").await.expect("key replaced");
        let verifying_key2 = keyring.verifying_key("one").await.expect("verifying key retrieved");
        assert_ne!(verifying_key1, verifying_key2);
    }
}
