use crate::collections::{FillVecMap, HoleVecMap};

use super::{
    api::{BytesVec, TofnResult},
    executer::ExecuterRaw,
    implementer_api::{bcast_and_p2p, bcast_only, no_messages, p2p_only},
    protocol::{Fault, Protocol, XProtocol},
    protocol_info::ProtocolInfoDeluxe,
    round::{Round, XRound},
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

// OLD

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
    pub(super) fn build<P>(self, info: ProtocolInfoDeluxe<K, P>) -> TofnResult<Protocol<F, K, P>> {
        Ok(match self {
            Self::NotDone(builder) => Protocol::NotDone(match builder {
                RoundBuilder::BcastAndP2p {
                    round,
                    bcast_out,
                    p2ps_out,
                } => Round::new_bcast_and_p2p(round, info, bcast_out, p2ps_out)?,
                RoundBuilder::BcastOnly { round, bcast_out } => {
                    Round::new_bcast_only(round, info, bcast_out)?
                }
                RoundBuilder::P2pOnly { round, p2ps_out } => {
                    Round::new_p2p_only(round, info, p2ps_out)?
                }
                RoundBuilder::NoMessages { round } => Round::new_no_messages(round, info)?,
            }),
            Self::Done(output) => Protocol::Done(info.share_to_party_faults(output)?),
        })
    }
}
