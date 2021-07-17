use crate::refactor::collections::TypedUsize;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    api::{BytesVec, TofnResult},
    implementer_api::serialize,
};

const TOFN_SERIALIZATION_VERSION: u16 = 0;

pub fn wrap<K>(
    payload: BytesVec,
    from: TypedUsize<K>,
    msg_type: MsgType<K>,
) -> TofnResult<BytesVec> {
    serialize(&BytesVecVersioned {
        version: TOFN_SERIALIZATION_VERSION,
        payload: serialize(&WireBytes {
            msg_type,
            from,
            payload,
        })?,
    })
}

/// deserialization failures are non-fatal: do not return TofnResult
pub fn unwrap<K>(bytes: &[u8]) -> Option<WireBytes<K>> {
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

#[derive(Serialize, Deserialize)]
// disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
#[serde(bound(serialize = "", deserialize = ""))]
pub struct WireBytes<K> {
    pub msg_type: MsgType<K>,
    pub from: TypedUsize<K>,
    pub payload: BytesVec,
}

// TODO serde can derive Serialize for structs with a type parameter.
// But I cannot derive Debug for these types unless `K: Debug`. How does serde do it?
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
pub enum MsgType<K> {
    Bcast,
    P2p { to: TypedUsize<K> },
}

#[derive(Serialize, Deserialize)]
struct BytesVecVersioned {
    version: u16,
    payload: BytesVec,
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::error;

    use crate::refactor::protocol::api::{BytesVec, TofnFatal, TofnResult};

    use super::{unwrap, wrap};

    pub fn corrupt_payload<K>(bytes: &[u8]) -> TofnResult<BytesVec> {
        // for simplicity, deserialization error is treated as fatal
        // (we're in a malicious module so who cares?)
        let wire_bytes = unwrap::<K>(bytes).ok_or_else(|| {
            error!("can't corrupt payload: deserialization failure");
            TofnFatal
        })?;
        wrap(
            b"these bytes are corrupted 1234".to_vec(),
            wire_bytes.from,
            wire_bytes.msg_type,
        )
    }
}
