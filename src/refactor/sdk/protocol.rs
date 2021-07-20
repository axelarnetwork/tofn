use super::{
    api::TofnResult, no_messages, party_share_counts::PartyShareCounts,
    protocol_info::ProtocolInfoDeluxe, round::Round,
};
use crate::refactor::collections::{FillVecMap, TypedUsize};
use serde::{Deserialize, Serialize};

pub enum Protocol<F, K, P> {
    NotDone(Round<F, K, P>),
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
pub fn new_protocol<F, K, P>(
    party_share_counts: PartyShareCounts<P>,
    share_id: TypedUsize<K>,
    first_round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
) -> TofnResult<Protocol<F, K, P>> {
    Ok(Protocol::NotDone(Round::new_no_messages(
        first_round,
        ProtocolInfoDeluxe::new(party_share_counts, share_id)?,
    )?))
}
