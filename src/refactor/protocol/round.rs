use tracing::error;

use crate::refactor::collections::{FillP2ps, FillVecMap, HoleVecMap, TypedUsize, VecMap};

use super::{
    api::{BytesVec, ProtocolOutput, TofnResult},
    bcast_and_p2p, bcast_only,
    implementer_api::ProtocolBuilderOutput,
    no_messages,
};

pub struct Round<F, K, P> {
    pub info: RoundInfo<K, P>,
    pub round_type: RoundType<F, K, P>,
}

pub struct RoundInfo<K, P> {
    party_share_counts: VecMap<P, usize>,
    party_count: usize, // sum of party_share_counts
    index: TypedUsize<K>,
}

impl<K, P> RoundInfo<K, P> {
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

    // TODO don't expose the following methods in the api
    pub fn share_to_party_faults<F>(
        &self,
        output: ProtocolBuilderOutput<F, K>,
    ) -> TofnResult<ProtocolOutput<F, P>> {
        Ok(match output {
            Ok(happy) => Ok(happy),
            Err(share_faulters) => {
                let mut party_faulters =
                    FillVecMap::<P, _>::with_size(self.party_share_counts.len());
                // TODO how to choose among multiple faults by one party?
                // For now just overwrite and use the final fault
                for (share_id, share_fault) in share_faulters.into_iter_some() {
                    party_faulters.set(self.share_to_party_id(share_id)?, share_fault)?;
                }
                Err(party_faulters)
            }
        })
    }
    fn share_to_party_id(&self, share_id: TypedUsize<K>) -> TofnResult<TypedUsize<P>> {
        let mut sum = 0;
        for (party_id, &share_count) in self.party_share_counts.iter() {
            sum += share_count;
            if share_id.as_usize() < sum {
                return Ok(party_id);
            }
        }
        error!("share_id {} out of bounds {}", share_id, sum);
        Err(())
    }
}

pub enum RoundType<F, K, P> {
    BcastAndP2p(BcastAndP2pRound<F, K, P>),
    BcastOnly(BcastOnlyRound<F, K, P>),
    NoMessages(NoMessagesRound<F, K, P>),
}

pub struct NoMessagesRound<F, K, P> {
    pub round: Box<dyn no_messages::Executer<FinalOutput = F, Index = K, PartyIndex = P>>,
}

pub struct BcastOnlyRound<F, K, P> {
    pub round: Box<dyn bcast_only::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
    pub bcast_out: BytesVec,
    pub bcasts_in: FillVecMap<K, BytesVec>,
}

pub struct BcastAndP2pRound<F, K, P> {
    pub round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K, PartyIndex = P>>,
    pub bcast_out: BytesVec,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub bcasts_in: FillVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}
