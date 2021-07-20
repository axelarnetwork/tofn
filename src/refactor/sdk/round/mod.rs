use tracing::error;

use crate::refactor::{
    collections::{FillP2ps, FillVecMap, HoleVecMap, TypedUsize},
    sdk::api::{BytesVec, ProtocolFaulters, TofnFatal, TofnResult},
};

use super::{bcast_and_p2p, bcast_only, no_messages, p2p_only, protocol_info::ProtocolInfoDeluxe};

// TODO is there a way to restrict visibility of struct methods?
// currently anyone with visibility of `Round` can use all its methods
mod api; // Round methods for tofn users
mod implementer_api; // Round methods for protocol implementers

pub struct Round<F, K, P> {
    info: ProtocolInfoDeluxe<K, P>,
    round_type: RoundType<F, K>,
    msg_in_faulters: ProtocolFaulters<P>,
}

pub enum RoundType<F, K> {
    BcastAndP2p(BcastAndP2pRound<F, K>),
    BcastOnly(BcastOnlyRound<F, K>),
    P2pOnly(P2pOnlyRound<F, K>),
    NoMessages(NoMessagesRound<F, K>),
}

pub struct NoMessagesRound<F, K> {
    pub round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
}

pub struct BcastOnlyRound<F, K> {
    pub round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: BytesVec,
    pub bcasts_in: FillVecMap<K, BytesVec>,
}

pub struct P2pOnlyRound<F, K> {
    pub round: Box<dyn p2p_only::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}

pub struct BcastAndP2pRound<F, K> {
    pub round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: BytesVec,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub bcasts_in: FillVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}

impl<F, K, P> Round<F, K, P> {
    pub fn new(info: ProtocolInfoDeluxe<K, P>, round_type: RoundType<F, K>) -> Self {
        let party_count = info.party_share_counts().party_count();
        Self {
            info,
            round_type,
            msg_in_faulters: FillVecMap::with_size(party_count),
        }
    }
}
