use crate::refactor::collections::TypedUsize;
use serde::{Deserialize, Serialize};
use tracing::error;

use super::{
    api::{BytesVec, TofnResult},
    implementer_api::{deserialize, serialize},
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

pub fn unwrap<K>(bytes: BytesVec) -> TofnResult<WireBytes<K>> {
    let bytes_versioned: BytesVecVersioned = deserialize(&bytes)?;
    if bytes_versioned.version != TOFN_SERIALIZATION_VERSION {
        error!(
            "encoding version {}, expected {}",
            bytes_versioned.version, TOFN_SERIALIZATION_VERSION
        );
        return Err(());
    }
    deserialize(&bytes_versioned.payload)
}

#[derive(Serialize, Deserialize)]
// disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
#[serde(bound(serialize = "", deserialize = ""))]
pub struct WireBytes<K> {
    pub msg_type: MsgType<K>,
    pub from: TypedUsize<K>,
    pub payload: BytesVec,
}

#[derive(Serialize, Deserialize)]
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
