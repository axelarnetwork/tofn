//! API for protocol implementers, but not for users of protocols
pub mod bcast_and_p2p2;
pub mod bcast_only;
pub mod no_messages;
pub mod round;
pub use round::Round;

use crate::vecmap::{Behave, HoleVecMap, Index};

use super::api::{BytesVec, Protocol, ProtocolOutput};

pub enum ProtocolBuilder<F, K>
where
    K: Behave,
{
    NotDone(RoundBuilder<F, K>),
    Done(ProtocolOutput<F, K>),
}

impl<F, K> ProtocolBuilder<F, K>
where
    K: Behave,
{
    pub fn build(self, party_count: usize, index: Index<K>) -> Protocol<F, K> {
        match self {
            Self::NotDone(builder) => Protocol::NotDone(match builder {
                RoundBuilder::BcastAndP2p {
                    round,
                    bcast_out,
                    p2ps_out,
                } => Round::new_bcast_and_p2p(round, party_count, index, bcast_out, p2ps_out),
                RoundBuilder::BcastOnly { round, bcast_out } => {
                    Round::new_bcast_only(round, party_count, index, bcast_out)
                }
                RoundBuilder::NoMessages { round } => {
                    Round::new_no_messages(round, party_count, index)
                }
            }),
            Self::Done(output) => Protocol::Done(output),
        }
    }
}

// make it an enum for each of bcast_and_p2p, bcast_only, p2p_only, no_msgs
// each `round` is a Box<dyn ExecuterXXX> where XXX is one of bcast_and_p2p, etc.
pub enum RoundBuilder<F, K>
where
    K: Behave,
{
    BcastAndP2p {
        round: Box<dyn bcast_and_p2p2::ExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    },
    BcastOnly {
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: BytesVec,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
    },
}

use tracing::{error, info, warn};

pub(crate) fn serialize<T: ?Sized>(value: &T) -> BytesVec
where
    T: serde::Serialize,
{
    let result = bincode::serialize(value).map_err(|err| err.to_string());
    if let Err(ref err_msg) = result {
        error!("serialization failure: {}", err_msg);
    }
    result.unwrap()
}

pub(crate) fn log_fault_info<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    info!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_fault_warn<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    warn!("party {} detect [{}] by {}", me, fault, faulter,);
}

pub(crate) fn log_accuse_warn<K>(me: Index<K>, faulter: Index<K>, fault: &str)
where
    K: Behave,
{
    warn!("party {} accuse {} of [{}]", me, faulter, fault);
}
