use crate::refactor::collections::{Behave, FillP2ps, FillVecMap, HoleVecMap, TypedUsize};

use super::{api::BytesVec, bcast_and_p2p, bcast_only, no_messages};

// need RoundContainer because we don't want to expose all the variants of Round
pub struct Round<F, K>
where
    K: Behave,
{
    pub info: RoundInfo<K>,
    pub round_type: RoundType<F, K>,
}

pub struct RoundInfo<K>
where
    K: Behave,
{
    party_count: usize,
    index: TypedUsize<K>,
}

impl<K: Behave> RoundInfo<K> {
    pub fn new(party_count: usize, index: TypedUsize<K>) -> Self {
        Self { party_count, index }
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.index
    }
}

pub enum RoundType<F, K>
where
    K: Behave,
{
    BcastAndP2p(BcastAndP2pRound<F, K>),
    BcastOnly(BcastOnlyRound<F, K>),
    NoMessages(NoMessagesRound<F, K>),
}

pub struct NoMessagesRound<F, K>
where
    K: Behave,
{
    pub round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
}

pub struct BcastOnlyRound<F, K>
where
    K: Behave,
{
    pub round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: BytesVec,
    pub bcasts_in: FillVecMap<K, BytesVec>,
}

pub struct BcastAndP2pRound<F, K>
where
    K: Behave,
{
    pub round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: BytesVec,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub bcasts_in: FillVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}
