pub mod bcast_and_p2p;
pub mod no_messages;

use crate::{
    refactor::api::Round,
    vecmap::{Behave, HoleVecMap, Index},
};

use self::bcast_and_p2p::executer::RoundExecuterRaw;

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
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
    },
}
