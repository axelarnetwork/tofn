use crate::{collections::TypedUsize, sdk::api::TofnFatal};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{error, warn};

use super::api::{BytesVec, TofnResult};
use bincode::{DefaultOptions, Options};

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

/// Serialize a value using bincode and log errors
pub fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
where
    T: serde::Serialize,
{
    // Create serialization options for bincode.
    // The default options don't bound pre-allocation size,
    // use little-endian and varint encoding, and reject trailing bytes.
    let options = DefaultOptions::new()
        .with_no_limit()
        .with_big_endian()
        .with_varint_encoding()
        .reject_trailing_bytes();

    options.serialize(value).map_err(|err| {
        error!("serialization failure: {}", err.to_string());
        TofnFatal
    })
}

/// Deserialize bytes to a type using bincode and log errors
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> TofnResult<T> {
    let options = DefaultOptions::new()
        .with_no_limit()
        .with_big_endian()
        .with_varint_encoding()
        .reject_trailing_bytes();

    options.deserialize(bytes).map_err(|err| {
        error!("deserialization failure: {}", err.to_string());
        TofnFatal
    })
}

/// deserialization failures are non-fatal: do not return TofnResult
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> TofnResult<T> {
    let bytes_versioned: BytesVecVersioned = deserialize(bytes).map_err(|err| {
        warn!("outer deserialization failure");
        err
    })?;

    if bytes_versioned.version != TOFN_SERIALIZATION_VERSION {
        warn!(
            "encoding version {}, expected {}",
            bytes_versioned.version, TOFN_SERIALIZATION_VERSION
        );
        return Err(TofnFatal);
    }

    deserialize(&bytes_versioned.payload).map_err(|err| {
        warn!("inner deserialization failure");
        err
    })
}

pub fn decode_message<K>(bytes: &[u8]) -> TofnResult<WireBytes<K>> {
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

    use crate::sdk::api::{BytesVec, TofnResult};

    use super::{decode_message, encode_message, WireBytes};

    pub fn corrupt_payload<K>(bytes: &[u8]) -> TofnResult<BytesVec> {
        // for simplicity, deserialization error is treated as fatal
        // (we're in a malicious module so who cares?)
        let wire_bytes: WireBytes<K> = decode_message(bytes).map_err(|err| {
            error!("can't corrupt payload: deserialization failure");
            err
        })?;

        encode_message(
            b"these bytes are corrupted 1234".to_vec(),
            wire_bytes.from,
            wire_bytes.msg_type,
            wire_bytes.expected_msg_types,
        )
    }
}
