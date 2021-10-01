use crate::{collections::TypedUsize, sdk::api::TofnFatal};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{error, warn};

use super::api::{BytesVec, TofnResult};

const TOFN_SERIALIZATION_VERSION: u16 = 0;

pub fn encode_message<K>(
    payload: BytesVec,
    from: TypedUsize<K>,
    msg_type: MsgType<K>,
    expected_msg_types: ExpectedMsgTypes,
) -> TofnResult<BytesVec> {
    encode(&WireBytes {
        msg_type,
        from,
        payload,
        expected_msg_types,
    })
}

pub fn encode<T: Serialize>(payload: &T) -> TofnResult<BytesVec> {
    serialize(&BytesVecVersioned {
        version: TOFN_SERIALIZATION_VERSION,
        payload: serialize(payload)?,
    })
}

pub fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
where
    T: serde::Serialize,
{
    match bincode::serialize(value) {
        Ok(bytes) => Ok(bytes),
        Err(err) => {
            error!("serialization failure: {}", err.to_string());
            Err(TofnFatal)
        }
    }
}

/// deserialization failures are non-fatal: do not return TofnResult
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let bytes_versioned: BytesVecVersioned = bincode::deserialize(bytes)
        .map_err(|err| {
            warn!("outer deserialization failure: {}", err.to_string());
        })
        .ok()?;
    if bytes_versioned.version != TOFN_SERIALIZATION_VERSION {
        warn!(
            "encoding version {}, expected {}",
            bytes_versioned.version, TOFN_SERIALIZATION_VERSION
        );
        return None;
    }
    bincode::deserialize(&bytes_versioned.payload)
        .map_err(|err| {
            warn!("inner deserialization failure: {}", err.to_string());
        })
        .ok()
}

pub fn decode_message<K>(bytes: &[u8]) -> Option<WireBytes<K>> {
    decode(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
pub struct WireBytes<K> {
    pub msg_type: MsgType<K>,
    pub from: TypedUsize<K>,
    pub payload: BytesVec,
    pub expected_msg_types: ExpectedMsgTypes,
}

// TODO serde can derive Serialize for structs with a type parameter.
// But I cannot derive Debug for these types unless `K: Debug`. How does serde do it?
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
pub enum MsgType<K> {
    Bcast,
    P2p { to: TypedUsize<K> },
    TotalShareCount1P2pOnly, // special case: used only when total_share_count is 1
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ExpectedMsgTypes {
    BcastAndP2p,
    BcastOnly,
    P2pOnly,
}

#[derive(Serialize, Deserialize)]
struct BytesVecVersioned {
    version: u16,
    payload: BytesVec,
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::error;

    use crate::sdk::api::{BytesVec, TofnFatal, TofnResult};

    use super::{decode_message, encode_message, WireBytes};

    pub fn corrupt_payload<K>(bytes: &[u8]) -> TofnResult<BytesVec> {
        // for simplicity, deserialization error is treated as fatal
        // (we're in a malicious module so who cares?)
        let wire_bytes: WireBytes<K> = decode_message(bytes).ok_or_else(|| {
            error!("can't corrupt payload: deserialization failure");
            TofnFatal
        })?;
        encode_message(
            b"these bytes are corrupted 1234".to_vec(),
            wire_bytes.from,
            wire_bytes.msg_type,
            wire_bytes.expected_msg_types,
        )
    }
}
