use crate::refactor::collections::TypedUsize;
use serde::{Deserialize, Serialize};
use tracing::error;

use super::{
    api::{BytesVec, TofnResult},
    implementer_api::{deserialize, serialize},
};
use MsgType::*;

const TOFN_SERIALIZATION_VERSION: u16 = 0;

pub fn wrap_bcast_bytes<K>(payload: BytesVec, from: TypedUsize<K>) -> TofnResult<BytesVec> {
    serialize(&BytesVecVersioned {
        version: TOFN_SERIALIZATION_VERSION,
        payload: serialize(&BytesVecMeta {
            msg_type: Bcast,
            from,
            payload,
        })?,
    })
}

pub fn wrap_p2p_bytes<K>(
    payload: BytesVec,
    from: TypedUsize<K>,
    to: TypedUsize<K>,
) -> TofnResult<BytesVec> {
    serialize(&BytesVecVersioned {
        version: TOFN_SERIALIZATION_VERSION,
        payload: serialize(&BytesVecMeta {
            msg_type: P2p { to },
            from,
            payload,
        })?,
    })
}

pub fn unwrap_msg_bytes<K>(bytes: BytesVec) -> TofnResult<BytesVecMeta<K>> {
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
pub struct BytesVecMeta<K> {
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
