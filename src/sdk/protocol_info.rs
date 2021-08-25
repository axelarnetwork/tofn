use crate::{
    collections::{FillHoleVecMap, FillVecMap, TypedUsize},
    sdk::{api::TofnResult, protocol::ProtocolOutput, protocol_builder::ProtocolBuilderOutput},
};

use super::party_share_counts::PartyShareCounts;

// party-level info persisted throughout the protocol ("deluxe" depends on `P`)
pub struct ProtocolInfoDeluxe<K, P> {
    party_share_counts: PartyShareCounts<P>,
    party_id: TypedUsize<P>,
    share_info: ProtocolInfo<K>,
    round: usize,
}

// share-level info persisted throughout the protocol
// used by protocol implementers---cannot depend on `P`
pub struct ProtocolInfo<K> {
    share_count: usize,
    share_id: TypedUsize<K>,
}

impl<K> ProtocolInfo<K> {
    pub fn total_share_count(&self) -> usize {
        self.share_count
    }

    pub fn my_id(&self) -> TypedUsize<K> {
        self.share_id
    }

    pub fn new_fillholevecmap<V>(&self) -> TofnResult<FillHoleVecMap<K, V>> {
        FillHoleVecMap::with_size(self.share_count, self.share_id)
    }

    pub fn new_fillvecmap<V>(&self) -> FillVecMap<K, V> {
        FillVecMap::with_size(self.share_count)
    }
}

impl<K, P> ProtocolInfoDeluxe<K, P> {
    pub fn party_id(&self) -> TypedUsize<P> {
        self.party_id
    }

    pub fn share_info(&self) -> &ProtocolInfo<K> {
        &self.share_info
    }

    pub fn party_share_counts(&self) -> &PartyShareCounts<P> {
        &self.party_share_counts
    }

    pub fn round(&self) -> usize {
        self.round
    }

    pub fn advance_round(&mut self) {
        self.round += 1
    }

    // private methods
    pub(super) fn new(
        party_share_counts: PartyShareCounts<P>,
        share_id: TypedUsize<K>,
    ) -> TofnResult<Self> {
        let party_id = party_share_counts.share_to_party_id(share_id)?;
        let share_count = party_share_counts.total_share_count();
        Ok(Self {
            party_share_counts,
            party_id,
            share_info: ProtocolInfo {
                share_count,
                share_id,
            },
            round: 0,
        })
    }

    pub(super) fn share_to_party_faults<F>(
        &self,
        output: ProtocolBuilderOutput<F, K>,
    ) -> TofnResult<ProtocolOutput<F, P>> {
        Ok(match output {
            Ok(happy) => Ok(happy),
            Err(share_faulters) => {
                let mut party_faulters =
                    FillVecMap::<P, _>::with_size(self.party_share_counts.party_count());
                // TODO how to choose among multiple faults by one party?
                // For now just overwrite and use the final fault
                for (share_id, share_fault) in share_faulters.into_iter_some() {
                    party_faulters.set(
                        self.party_share_counts.share_to_party_id(share_id)?,
                        share_fault,
                    )?;
                }
                Err(party_faulters)
            }
        })
    }
}
