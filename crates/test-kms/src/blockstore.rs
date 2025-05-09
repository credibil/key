//! # In-memory blockstore

use std::sync::LazyLock;

use anyhow::Result;
use blockstore::{Blockstore as _, InMemoryBlockstore};
use cid::Cid;
use multihash_codetable::MultihashDigest;
use serde::{Deserialize, Serialize};

// static START: Once = Once::new();
static BLOCKSTORE: LazyLock<InMemoryBlockstore<64>> = LazyLock::new(InMemoryBlockstore::new);

#[derive(Clone, Debug)]
pub struct Mockstore;

impl Mockstore {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn put(&self, owner: &str, partition: &str, key: &str, block: &[u8]) -> Result<()> {
        let cid = unique_cid(owner, partition, key)?;
        BLOCKSTORE.put_keyed(&cid, block).await.map_err(Into::into)
    }

    pub async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let cid = unique_cid(owner, partition, key)?;
        let Some(bytes) = BLOCKSTORE.get(&cid).await? else {
            return Ok(None);
        };
        Ok(Some(bytes))
    }

    pub async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let cid = unique_cid(owner, partition, key)?;
        Ok(BLOCKSTORE.remove(&cid).await?)
    }

    pub async fn exists(
        &self,
        owner: &str,
        partition: &str,
        key: &str,
    ) -> Result<bool> {
        let cid = unique_cid(owner, partition, key)?;
        Ok(BLOCKSTORE.has(&cid).await?)
    }
}

#[derive(Serialize, Deserialize)]
struct Identifier<'a>(&'a str, &'a str, &'a str);
const RAW: u64 = 0x55;

fn unique_cid(owner: &str, partition: &str, key: &str) -> anyhow::Result<Cid> {
    let id = Identifier(owner, partition, key);
    let mut buf = Vec::new();
    ciborium::into_writer(&id, &mut buf)?;
    let hash = multihash_codetable::Code::Sha2_256.digest(&buf);
    Ok(Cid::new_v1(RAW, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blockstore() {
        let store = Mockstore::new();
        let owner = "owner";
        let partition = "partition";
        let key = "key";
        let block = b"block data";

        // Put a block
        store.put(owner, partition, key, block).await.unwrap();

        // Get the block
        let retrieved_block = store.get(owner, partition, key).await.unwrap().unwrap();
        assert_eq!(retrieved_block.as_slice(), block);

        // Check existence
        assert!(store.exists(owner, partition, key).await.unwrap());

        // Delete the block
        store.delete(owner, partition, key).await.unwrap();

        // Check non-existence
        assert!(!store.exists(owner, partition, key).await.unwrap());
    }
}
