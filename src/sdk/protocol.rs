use super::{
    api::TofnResult, party_share_counts::PartyShareCounts, protocol_builder::ProtocolBuilder,
    protocol_info::ProtocolInfoDeluxe, round::Round,
};
use crate::collections::{FillVecMap, TypedUsize};
use serde::{Deserialize, Serialize};

pub enum Protocol<F, K, P, const MAX_MSG_IN_LEN: usize> {
    NotDone(Round<F, K, P, MAX_MSG_IN_LEN>),
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
pub fn new_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    party_share_counts: PartyShareCounts<P>,
    share_id: TypedUsize<K>,
    first_round: ProtocolBuilder<F, K>,
) -> TofnResult<Protocol<F, K, P, MAX_MSG_IN_LEN>> {
    first_round.build(ProtocolInfoDeluxe::new(party_share_counts, share_id)?)
}
