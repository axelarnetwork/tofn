use crate::collections::{FillVecMap, HoleVecMap};

use super::{
    api::{BytesVec, TofnResult},
    implementer_api::{bcast_and_p2p, bcast_only, no_messages, p2p_only},
    protocol::{Fault, Protocol},
    protocol_info::ProtocolInfoDeluxe,
    round::Round,
};

pub enum ProtocolBuilder<F, K> {
    NotDone(RoundBuilder<F, K>),
    Done(ProtocolBuilderOutput<F, K>),
}

pub enum RoundBuilder<F, K> {
    BcastAndP2p {
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    },
    BcastOnly {
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: BytesVec,
    },
    P2pOnly {
        round: Box<dyn p2p_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        p2ps_out: HoleVecMap<K, BytesVec>,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
    },
}

pub type ProtocolBuilderOutput<F, K> = Result<F, FillVecMap<K, Fault>>; // subshare faults

impl<F, K> ProtocolBuilder<F, K> {
    pub(super) fn build<P>(
        self,
        info: ProtocolInfoDeluxe<K, P>,
        round_num: usize,
    ) -> TofnResult<Protocol<F, K, P>> {
        Ok(match self {
            Self::NotDone(builder) => Protocol::NotDone(match builder {
                RoundBuilder::BcastAndP2p {
                    round,
                    bcast_out,
                    p2ps_out,
                } => Round::new_bcast_and_p2p(round, round_num, info, bcast_out, p2ps_out)?,
                RoundBuilder::BcastOnly { round, bcast_out } => {
                    Round::new_bcast_only(round, round_num, info, bcast_out)?
                }
                RoundBuilder::P2pOnly { round, p2ps_out } => {
                    Round::new_p2p_only(round, round_num, info, p2ps_out)?
                }
                RoundBuilder::NoMessages { round } => {
                    Round::new_no_messages(round, round_num, info)?
                }
            }),
            Self::Done(output) => Protocol::Done(info.share_to_party_faults(output)?),
        })
    }
}
