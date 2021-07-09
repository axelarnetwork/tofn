mod bcast_and_p2p;
pub use bcast_and_p2p::BcastAndP2p;

use crate::vecmap::{Behave, HoleVecMap};

use super::api::{executer::RoundExecuterRaw, BytesVec, ProtocolOutput};

pub enum ProtocolBuilder<F, K>
where
    K: Behave,
{
    NotDone(ProtocolRoundBuilder<F, K>),
    Done(ProtocolOutput<F, K>),
}

// TODO rename to RoundBulder
// make it an enum for each of bcast_and_p2p, bcast_only, p2p_only, no_msgs
// each `round` is a Box<dyn ExecuterXXX> where XXX is one of bcast_and_p2p, etc.
pub struct ProtocolRoundBuilder<F, K>
where
    K: Behave,
{
    pub round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: Option<BytesVec>,
    pub p2ps_out: Option<HoleVecMap<K, BytesVec>>,
}
