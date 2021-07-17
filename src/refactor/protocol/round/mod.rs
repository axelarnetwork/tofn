use tracing::error;

use crate::refactor::{
    collections::{FillP2ps, FillVecMap, HoleVecMap, TypedUsize, VecMap},
    protocol::{
        api::{BytesVec, ProtocolOutput, TofnFatal, TofnResult},
        implementer_api::ProtocolBuilderOutput,
    },
};

// TODO is there a way to restrict visibility of struct methods?
// currently anyone with visibility of `Round` can use all its methods
mod api; // Round methods for tofn users
mod implementer_api; // Round methods for protocol implementers

pub mod bcast_and_p2p;
pub mod bcast_only;
pub mod no_messages;

pub struct Round<F, K, P> {
    info: ProtocolInfoDeluxe<K, P>,
    round_type: RoundType<F, K>,
    msg_in_faulters: FillVecMap<P, MsgInFault>,
}

// info persisted throughout the protocol
// "deluxe" depends on `P`
pub struct ProtocolInfoDeluxe<K, P> {
    party_share_counts: VecMap<P, usize>,
    core: ProtocolInfo<K>,
}

// info persisted throughout the protocol
// cannot depend on `P`
pub struct ProtocolInfo<K> {
    party_count: usize,
    index: TypedUsize<K>,
}

pub enum RoundType<F, K> {
    BcastAndP2p(BcastAndP2pRound<F, K>),
    BcastOnly(BcastOnlyRound<F, K>),
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

pub struct BcastAndP2pRound<F, K> {
    pub round: Box<dyn bcast_and_p2p::ExecuterRaw<FinalOutput = F, Index = K>>,
    pub bcast_out: BytesVec,
    pub p2ps_out: HoleVecMap<K, BytesVec>,
    pub bcasts_in: FillVecMap<K, BytesVec>,
    pub p2ps_in: FillP2ps<K, BytesVec>,
}

#[derive(Debug)]
struct MsgInFault;

impl<F, K, P> Round<F, K, P> {
    pub fn new(info: ProtocolInfoDeluxe<K, P>, round_type: RoundType<F, K>) -> Self {
        let party_count = info.party_share_counts.len();
        Self {
            info,
            round_type,
            msg_in_faulters: FillVecMap::with_size(party_count),
        }
    }
}

impl<K> ProtocolInfo<K> {
    pub fn party_count(&self) -> usize {
        self.party_count
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.index
    }
}

impl<K, P> ProtocolInfoDeluxe<K, P> {
    pub fn new(party_share_counts: VecMap<P, usize>, index: TypedUsize<K>) -> Self {
        let party_count = party_share_counts.iter().map(|(_, n)| n).sum();
        Self {
            party_share_counts,
            core: ProtocolInfo { party_count, index },
        }
    }
    pub fn party_count(&self) -> usize {
        self.core.party_count
    }
    pub fn index(&self) -> TypedUsize<K> {
        self.core.index
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

    /// non-fatal out of bounds
    fn share_to_party_id_nonfatal(&self, share_id: TypedUsize<K>) -> Option<TypedUsize<P>> {
        let mut sum = 0;
        for (party_id, &share_count) in self.party_share_counts.iter() {
            sum += share_count;
            if share_id.as_usize() < sum {
                return Some(party_id);
            }
        }
        None
    }
    /// fatal out of bounds
    fn share_to_party_id(&self, share_id: TypedUsize<K>) -> TofnResult<TypedUsize<P>> {
        self.share_to_party_id_nonfatal(share_id).ok_or_else(|| {
            error!("share_id {} out of bounds {}", share_id, self.party_count());
            TofnFatal
        })
    }
}
