use crate::collections::{FillVecMap, HoleVecMap};

use super::{
    api::{BytesVec, TofnResult},
    executer::ExecuterRaw,
    protocol::{Fault, XProtocol},
    protocol_info::ProtocolInfoDeluxe,
    round::XRound,
};

pub enum XProtocolBuilder<F, K> {
    NotDone(XRoundBuilder<F, K>),
    Done(ProtocolBuilderOutput<F, K>),
}

pub struct XRoundBuilder<F, K> {
    round: Box<dyn ExecuterRaw<FinalOutput = F, Index = K>>,
    bcast_out: Option<BytesVec>,
    p2ps_out: Option<HoleVecMap<K, BytesVec>>,
}

impl<F, K> XRoundBuilder<F, K> {
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

impl<F, K> XProtocolBuilder<F, K> {
    pub(super) fn build<P>(self, info: ProtocolInfoDeluxe<K, P>) -> TofnResult<XProtocol<F, K, P>> {
        Ok(match self {
            Self::NotDone(builder) => XProtocol::NotDone(XRound::new(
                builder.round,
                info,
                builder.bcast_out,
                builder.p2ps_out,
            )?),
            Self::Done(output) => XProtocol::Done(info.share_to_party_faults(output)?),
        })
    }
}

pub type ProtocolBuilderOutput<F, K> = Result<F, FillVecMap<K, Fault>>; // subshare faults
