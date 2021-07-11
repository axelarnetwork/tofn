pub mod bcast_and_p2p;
pub use bcast_and_p2p::BcastAndP2p;

use crate::vecmap::{Behave, HoleVecMap};

use self::bcast_and_p2p::executer::RoundExecuterRaw;

use super::api::{BytesVec, ProtocolOutput};

pub enum ProtocolBuilder<F, K>
where
    K: Behave,
{
    NotDone(RoundBuilder<F, K>),
    Done(ProtocolOutput<F, K>),
}

// make it an enum for each of bcast_and_p2p, bcast_only, p2p_only, no_msgs
// each `round` is a Box<dyn ExecuterXXX> where XXX is one of bcast_and_p2p, etc.
pub enum RoundBuilder<F, K>
where
    K: Behave,
{
    BcastAndP2p {
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    },
}
