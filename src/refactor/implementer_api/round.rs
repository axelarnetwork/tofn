use crate::{
    refactor::api::BytesVec,
    vecmap::{Behave, FillP2ps, FillVecMap, HoleVecMap, Index},
};

use super::{bcast_and_p2p::executer::RoundExecuterRaw, no_messages};

pub enum Round<F, K>
where
    K: Behave,
{
    BcastAndP2p {
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
        bcasts_in: Option<FillVecMap<K, BytesVec>>,
        p2ps_in: Option<FillP2ps<K, BytesVec>>,
    },
    NoMessages {
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
    },
}

impl<F, K> Round<F, K>
where
    K: Behave,
{
    pub fn new_bcast_and_p2p(
        round: Box<dyn RoundExecuterRaw<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
        bcast_out: Option<BytesVec>,
        p2ps_out: Option<HoleVecMap<K, BytesVec>>,
    ) -> Self {
        // validate args
        // TODO return error instead of panic?
        assert!(index.as_usize() < party_count);
        if let Some(ref p2ps) = p2ps_out {
            assert_eq!(p2ps.len(), party_count);
        }

        // we expect to receive (bcast,p2p) messages if and only if (bcasts_in,p2ps_in) is Some
        let bcasts_in = bcast_out
            .as_ref()
            .map(|_| FillVecMap::with_size(party_count));
        let p2ps_in = p2ps_out.as_ref().map(|_| FillP2ps::with_size(party_count));

        Round::BcastAndP2p {
            round,
            party_count,
            index,
            bcast_out,
            p2ps_out,
            bcasts_in,
            p2ps_in,
        }
    }

    pub fn new_no_messages(
        round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K>>,
        party_count: usize,
        index: Index<K>,
    ) -> Self {
        assert!(index.as_usize() < party_count);

        Round::NoMessages {
            round,
            party_count,
            index,
        }
    }

    #[cfg(test)]
    pub fn round_as_any(&self) -> &dyn std::any::Any {
        match self {
            Round::BcastAndP2p {
                round,
                party_count: _,
                index: _,
                bcast_out: _,
                p2ps_out: _,
                bcasts_in: _,
                p2ps_in: _,
            } => round.as_any(),
            Round::NoMessages {
                round,
                party_count: _,
                index: _,
            } => round.as_any(),
        }
    }
}
