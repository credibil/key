//! # COSE Key
//!
//! Support for `COSE_Key` as defined in [RFC9052]
//!
//! [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects

use std::collections::BTreeMap;

use anyhow::anyhow;
use ciborium::Value;
use serde::{Deserialize, Serialize};

use crate::{Curve, KeyType};

const KTY: i64 = 1;
const CRV: i64 = -1;
const X: i64 = -2;
const Y: i64 = -3;

const KTY_OKP: i64 = 1;
const KTY_EC: i64 = 2;
const CRV_ED25519: i64 = 6;
const CRV_X25519: i64 = 4;
const CRV_ES256K: i64 = 8;

/// Implements [`COSE_Key`] as defined in [RFC9052].
///
/// [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052.html#name-key-objects
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "Value", into = "Value")]
#[allow(clippy::module_name_repetitions)]
pub struct CoseKey {
    /// Key type
    pub kty: KeyType,

    /// Curve
    pub crv: Curve,

    /// Public key X
    pub x: Vec<u8>,

    /// Public key Y
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<Vec<u8>>,
}

/// Serialize `COSE_Key` to CBOR.
impl From<CoseKey> for Value {
    fn from(key: CoseKey) -> Self {
        let mut cbor = vec![
            (KTY.into(), key.kty.clone().into()),
            (CRV.into(), { key.crv.into() }),
            (X.into(), Self::Bytes(key.x)),
        ];
        if key.kty == KeyType::Ec {
            cbor.push((Y.into(), { key.y.unwrap_or_default().into() }));
        }
        Self::Map(cbor)
    }
}

/// Deserialize `COSE_Key` from CBOR.
impl TryFrom<Value> for CoseKey {
    type Error = anyhow::Error;

    fn try_from(v: Value) -> anyhow::Result<Self> {
        let Value::Map(map) = v.clone() else {
            return Err(anyhow!("Value is not a map: {v:?}"));
        };
        let mut map = map
            .into_iter()
            .map(|(k, v)| (k.as_integer().unwrap_or_else(|| 0.into()), v))
            .collect::<BTreeMap<_, _>>();

        let Some(kty) = map.remove(&KTY.into()) else {
            return Err(anyhow!("key type not found"));
        };
        let Some(crv) = map.remove(&CRV.into()) else {
            return Err(anyhow!("curve not found"));
        };
        let Some(Value::Bytes(x)) = map.remove(&X.into()) else {
            return Err(anyhow!("x coordinate not found"));
        };

        let y = if kty == KeyType::Ec.into() {
            let y = map.remove(&Y.into()).ok_or_else(|| anyhow!("y coordinate not found"))?;
            y.as_bytes().cloned()
        } else {
            None
        };

        Ok(Self {
            kty: kty.try_into()?,
            crv: crv.try_into()?,
            x,
            y,
        })
    }
}

impl From<KeyType> for Value {
    fn from(k: KeyType) -> Self {
        match k {
            KeyType::Okp => Self::Integer(KTY_OKP.into()),
            KeyType::Ec => Self::Integer(KTY_EC.into()),
            _ => unimplemented!("unsupported key type"),
        }
    }
}

impl TryInto<KeyType> for Value {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<KeyType> {
        if self == Value::Integer(KTY_OKP.into()) {
            return Ok(KeyType::Okp);
        }
        if self == Value::Integer(KTY_EC.into()) {
            return Ok(KeyType::Ec);
        }
        Err(anyhow!("unsupported key type: {self:?}"))
    }
}

impl From<Curve> for Value {
    fn from(crv: Curve) -> Self {
        match crv {
            Curve::Ed25519 => Self::Integer(CRV_ED25519.into()),
            Curve::Es256K => Self::Integer(CRV_ES256K.into()),
            Curve::X25519 => Self::Integer(CRV_X25519.into()),
        }
    }
}

impl TryInto<Curve> for Value {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Curve> {
        if self == Value::Integer(CRV_ED25519.into()) {
            return Ok(Curve::Ed25519);
        }
        if self == Value::Integer(CRV_ES256K.into()) {
            return Ok(Curve::Es256K);
        }
        Err(anyhow!("unsupported curve: {self:?}"))
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::cose::cbor;

    const ES256K_CBOR: &str = "a40102200821582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";
    const X_HEX: &str = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d";
    const Y_HEX: &str = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c";

    #[test]
    fn serialize() {
        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        let cbor = cbor::to_vec(&cose_key).expect("should serialize");
        let hex = hex::encode(cbor);

        assert_eq!(hex, ES256K_CBOR);
    }

    #[test]
    fn deserialize() {
        let bytes = hex::decode(ES256K_CBOR).expect("should decode");
        let key: CoseKey = cbor::from_slice(&bytes).expect("should serialize");

        let cose_key = CoseKey {
            kty: KeyType::Ec,
            crv: Curve::Es256K,
            x: Vec::from_hex(X_HEX).unwrap(),
            y: Some(Vec::from_hex(Y_HEX).unwrap()),
        };

        assert_eq!(key, cose_key);
    }
}
