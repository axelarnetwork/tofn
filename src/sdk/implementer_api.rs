//! API for protocol implementers, but not for users of protocols
pub use super::executer::{Executer, ExecuterRaw};
pub use super::protocol::new_protocol;
pub use super::protocol_builder::{ProtocolBuilder, ProtocolBuilderOutput, RoundBuilder};
pub use super::protocol_info::ProtocolInfo;

mod utils {
    use crate::{
        collections::TypedUsize,
        sdk::api::{BytesVec, TofnFatal, TofnResult},
    };
    use tracing::{error, info, warn};

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

    pub fn log_fault_info<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
        info!("peer {} detected [{}] by {}", me, fault, faulter);
    }

    pub fn log_fault_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
        warn!("peer {} detected [{}] by {}", me, fault, faulter);
    }

    pub fn log_accuse_warn<K>(me: TypedUsize<K>, faulter: TypedUsize<K>, fault: &str) {
        warn!("peer {} accused {} of [{}]", me, faulter, fault);
    }
}
pub use utils::{log_accuse_warn, log_fault_info, log_fault_warn, serialize};
