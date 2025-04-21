//! # CBOR
//!
//! This module provides CBOR helper functions and types.

use std::ops::Deref;

use anyhow::anyhow;
use ciborium::Value;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

/// Serialize a value to a CBOR byte vector.
///
/// # Errors
/// TODO: Document errors
pub fn to_vec<T>(value: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Deserialize a value from a CBOR byte slice.
///
/// # Errors
/// TODO: Document errors
pub fn from_slice<T>(slice: &[u8]) -> anyhow::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    ciborium::from_reader(slice).map_err(|e| anyhow!(e.to_string()))
}

/// Wrap types that require tagging with tag 24.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag24<T>(pub T);

impl<T> Deref for Tag24<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Tag24<T> {
    /// Serialize the inner value to a CBOR byte vector.
    ///
    /// # Errors
    /// TODO: Document errors
    pub fn to_cbor(&self) -> anyhow::Result<Vec<u8>> {
        to_vec(&self.0)
    }
}

impl<T> TryFrom<Value> for Tag24<T>
where
    T: for<'de> Deserialize<'de>,
{
    type Error = anyhow::Error;

    fn try_from(v: Value) -> anyhow::Result<Self> {
        match v.clone() {
            Value::Tag(24, value) => match value.as_ref() {
                Value::Bytes(bytes) => {
                    let inner: T = from_slice(bytes)?;
                    Ok(Self(inner))
                }
                _ => Err(anyhow!("invalid tag: {value:?}")),
            },
            _ => Err(anyhow!("not a tag24: {v:?}")),
        }
    }
}

impl<T: Serialize> Serialize for Tag24<T> {
    fn serialize<S: Serializer>(&self, s: S) -> anyhow::Result<S::Ok, S::Error> {
        Value::Tag(24, Box::new(Value::Bytes(to_vec(&self.0).unwrap()))).serialize(s)
    }
}

impl<'de, T> Deserialize<'de> for Tag24<T>
where
    Tag24<T>: TryFrom<ciborium::Value>,
{
    fn deserialize<D>(deserializer: D) -> anyhow::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        value.try_into().map_err(|_| de::Error::custom(format!("failed to deserialize Tag24",)))
    }
}

#[cfg(test)]
mod test {
    use super::Tag24;

    #[test]
    #[should_panic]
    // A Tag24 cannot be serialized directly into a non-cbor format as it will lose the tag.
    fn non_cbor_roundtrip() {
        let original = Tag24(String::from("some data"));
        let json = serde_json::to_vec(&original).unwrap();
        let roundtripped = serde_json::from_slice(&json).unwrap();
        assert_eq!(original, roundtripped)
    }
}
