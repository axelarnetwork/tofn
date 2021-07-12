use tracing::error;

use crate::{
    refactor::api::{BytesVec, TofnResult},
    vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, TypedUsize},
};

use super::{
    bcast_and_p2p::{self, BcastAndP2pRound},
    bcast_only::{self, BcastOnlyRound},
    no_messages::{self, NoMessagesRound},
};

pub enum Round<F, K>
where
    K: Behave,
{
    BcastAndP2p(BcastAndP2pRound<F, K>),
    BcastOnly(BcastOnlyRound<F, K>),
    NoMessages(NoMessagesRound<F, K>),
}

impl<F, K> Round<F, K>
where
    K: Behave,
{
    pub fn new_bcast_and_p2p(
        round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: TypedUsize<K>,
        bcast_out: BytesVec,
        p2ps_out: HoleVecMap<K, BytesVec>,
    ) -> TofnResult<Self> {
        // validate args
        // TODO return error instead of panic?
        assert!(index.as_usize() < party_count);
        assert_eq!(p2ps_out.len(), party_count);

        Ok(Round::BcastAndP2p(BcastAndP2pRound {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out,
            bcasts_in: FillVecMap::with_size(party_count),
            p2ps_in: FillP2ps::with_size(party_count),
        }))
    }

    pub fn new_bcast_only(
        round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: TypedUsize<K>,
        bcast_out: BytesVec,
    ) -> TofnResult<Self> {
        if index.as_usize() >= party_count {
            error!("index {} out of bounds {}", index.as_usize(), party_count);
            return Err(());
        }

        Ok(Round::BcastOnly(BcastOnlyRound {
            round,
            party_count,
            index,
            bcast_out,
            bcasts_in: FillVecMap::with_size(party_count),
        }))
    }

    pub fn new_no_messages(
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: TypedUsize<K>,
    ) -> TofnResult<Self> {
        assert!(index.as_usize() < party_count);

        Ok(Round::NoMessages(NoMessagesRound {
            round,
            party_count,
            index,
        }))
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match self {
            Round::BcastAndP2p(r) => r.round.as_any(),
            Round::BcastOnly(r) => r.round.as_any(),
            Round::NoMessages(r) => r.round.as_any(),
        }
    }
}
