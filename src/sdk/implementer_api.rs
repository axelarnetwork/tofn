//! API for protocol implementers, but not for users of protocols
pub use super::executer::Executer;
pub use super::protocol::new_protocol;
pub use super::protocol_builder::{ProtocolBuilder, RoundBuilder};
pub use super::protocol_info::ProtocolInfo;
pub use super::wire_bytes::{decode, encode, serialize};

mod utils {
    use crate::collections::TypedUsize;
    use tracing::{info, warn};

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
pub use utils::{log_accuse_warn, log_fault_info, log_fault_warn};

#[cfg(any(test, feature = "malicious"))]
pub use super::wire_bytes::{decode_message, encode_message, ExpectedMsgTypes};

#[cfg(test)]
pub use super::wire_bytes::MsgType;

#[cfg(any(test, feature = "malicious"))]
pub use super::wire_bytes::deserialize;
