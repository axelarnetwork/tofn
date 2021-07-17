pub mod api {
    //! API for protocol implementers, but not for users of protocols
    #[derive(Debug)]
    pub struct TofnFatal;
    pub type TofnResult<T> = Result<T, TofnFatal>;

    pub type BytesVec = Vec<u8>;

    pub use super::{
        protocol::{Fault, Protocol, ProtocolOutput},
        round::Round,
    };

    #[cfg(feature = "malicious")]
    pub use super::wire_bytes::MsgType;
}
pub mod implementer_api {
    use crate::refactor::{collections::TypedUsize, protocol::api::TofnFatal};

    use super::api::{BytesVec, TofnResult};
    pub use super::{
        protocol_builder::{ProtocolBuilder, ProtocolBuilderOutput, RoundBuilder},
        round::{bcast_and_p2p, bcast_only, no_messages, ProtocolInfo, ProtocolInfoDeluxe},
    };
    use tracing::{error, info, warn};

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
}

mod protocol;
mod protocol_builder;
mod round;
mod wire_bytes;
