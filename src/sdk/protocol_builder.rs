use crate::collections::{FillVecMap, HoleVecMap};

use super::{
    api::{BytesVec, TofnResult},
    executer::ExecuterRaw,
    protocol::{Fault, Protocol},
    protocol_info::ProtocolInfoDeluxe,
    round::Round,
};

pub enum ProtocolBuilder<F, K> {
    NotDone(RoundBuilder<F, K>),
    Done(ProtocolBuilderOutput<F, K>),
}

pub struct RoundBuilder<F, K> {
    round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
    bcast_out: Option<BytesVec>,
    p2ps_out: Option<HoleVecMap<K, BytesVec>>,
}

impl<F, K> RoundBuilder<F, K> {
    pub fn new(
        round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    ) -> Self {
        Self {
            round,
            bcast_out,
            p2ps_out,
        }
    }
}

impl<F, K> ProtocolBuilder<F, K> {
    pub(super) fn build<P, const MAX_MSG_IN_LEN: usize>(
        self,
        info: ProtocolInfoDeluxe<K, P>,
    ) -> TofnResult<Protocol<F, K, P, MAX_MSG_IN_LEN>> {
        Ok(match self {
            Self::NotDone(builder) => Protocol::NotDone(Round::new(
                builder.round,
                info,
                builder.bcast_out,
                builder.p2ps_out,
            )?),
            Self::Done(output) => Protocol::Done(info.share_to_party_faults(output)?),
        })
    }
}

pub type ProtocolBuilderOutput<F, K> = Result<F, FillVecMap<K, Fault>>; // subshare faults
