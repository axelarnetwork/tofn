use crate::refactor::collections::TypedUsize;
use serde::{Deserialize, Serialize};
use tracing::error;

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

/// Do not return TofnResult---that's for fatal errors only.
/// Deserialization failures are a party fault.
#[derive(Debug)]
pub struct DeserializationFailure;
pub fn unwrap<K>(bytes: &[u8]) -> Result<WireBytes<K>, DeserializationFailure> {
    let bytes_versioned: BytesVecVersioned =
        bincode::deserialize(bytes).map_err(|_| DeserializationFailure)?;
    if bytes_versioned.version != TOFN_SERIALIZATION_VERSION {
        error!(
            "encoding version {}, expected {}",
            bytes_versioned.version, TOFN_SERIALIZATION_VERSION
        );
        return Err(DeserializationFailure);
    }
    bincode::deserialize(&bytes_versioned.payload).map_err(|_| DeserializationFailure)
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
// But I cannot derive Debug for these types.
// How does serde do it?
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
// disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
#[serde(bound(serialize = "", deserialize = ""))]
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
        let wire_bytes = unwrap::<K>(bytes).map_err(|_| {
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
