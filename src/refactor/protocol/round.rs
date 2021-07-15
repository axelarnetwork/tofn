use crate::refactor::collections::{Behave, FillP2ps, FillVecMap, HoleVecMap, TypedUsize, VecMap};

use super::{api::BytesVec, bcast_and_p2p, bcast_only, no_messages};

pub struct Round<F, K, P>
where
    K: Behave,
    P: Behave,
{
    pub info: RoundInfo<K, P>,
    pub round_type: RoundType<F, K, P>,
}

pub struct RoundInfo<K, P>
where
    K: Behave,
    P: Behave,
{
    party_share_counts: VecMap<P, usize>,
    party_count: usize, // sum of party_share_counts
    index: TypedUsize<K>,
}

impl<K, P> RoundInfo<K, P>
where
    K: Behave,
    P: Behave,
{
    pub fn new(party_share_counts: VecMap<P, usize>, index: TypedUsize<K>) -> Self {
        let party_count = party_share_counts.iter().map(|(_, n)| n).sum();
        Self {
            party_share_counts,
            party_count,
            index,
        }
    }
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.index
    }
}

pub enum RoundType<F, K, P>
where
    K: Behave,
    P: Behave,
{
    BcastAndP2p(BcastAndP2pRound<F, K, P>),
    BcastOnly(BcastOnlyRound<F, K, P>),
    NoMessages(NoMessagesRound<F, K, P>),
}

pub struct NoMessagesRound<F, K, P>
where
    K: Behave,
    P: Behave,
{
    pub round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K, PartyIndex = P>>,
}

pub struct BcastOnlyRound<F, K, P>
where
    K: Behave,
    P: Behave,
{
    pub round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
    pub bcast_out: BytesVec,
    pub bcasts_in: FillVecMap<K, BytesVec>,
}

pub struct BcastAndP2pRound<F, K, P>
where
    K: Behave,
    P: Behave,
{
    pub round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
    pub bcast_out: BytesVec,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub bcasts_in: FillVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}
