use super::{
    api::TofnResult, party_share_counts::PartyShareCounts, protocol_builder::XProtocolBuilder,
    protocol_info::ProtocolInfoDeluxe, round::XRound,
};
use crate::collections::{FillVecMap, TypedUsize};
use serde::{Deserialize, Serialize};

pub enum XProtocol<F, K, P> {
    NotDone(XRound<F, K, P>),
    Done(ProtocolOutput<F, P>),
}

pub type ProtocolOutput<F, P> = Result<F, ProtocolFaulters<P>>;
pub type ProtocolFaulters<P> = FillVecMap<P, Fault>; // party (not subhsare) faults

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Fault {
    MissingMessage,
    CorruptedMessage,
    ProtocolFault,
}

// not an associated function of `Protocol`
// because we want to expose it only in the implementer api
pub fn xnew_protocol<F, K, P>(
    party_share_counts: PartyShareCounts<P>,
    share_id: TypedUsize<K>,
    first_round: XProtocolBuilder<F, K>,
) -> TofnResult<XProtocol<F, K, P>> {
    first_round.build(ProtocolInfoDeluxe::new(party_share_counts, share_id)?)
}
