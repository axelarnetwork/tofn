//! API for protocol implementers, but not for users of protocols
use super::api::{BytesVec, TofnResult};
use crate::refactor::{collections::TypedUsize, sdk::api::TofnFatal};
use tracing::{error, info, warn};

pub mod bcast_and_p2p;
pub mod bcast_only;
pub mod no_messages;
pub mod p2p_only;

pub use super::protocol::new_protocol;
pub use super::protocol_builder::{ProtocolBuilder, ProtocolBuilderOutput, RoundBuilder};
pub use super::protocol_info::ProtocolInfo;

pub(crate) fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
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

pub(crate) fn log_fault_info<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    info!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_fault_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    warn!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_accuse_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
    warn!("party {} accuse {} of [{}]", me, faulter, fault);
}
