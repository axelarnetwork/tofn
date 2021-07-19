use tracing::error;

use crate::refactor::{
    collections::{TypedUsize, VecMap, VecMapIter},
    sdk::api::{TofnFatal, TofnResult},
};

#[derive(Debug, Clone)]
pub struct PartyShareCounts<P> {
    party_share_counts: VecMap<P, usize>,
    total_share_count: usize,
}

impl<P> PartyShareCounts<P> {
    pub fn from_vecmap(vecmap: VecMap<P, usize>) -> Self {
        // TODO enforce maxima here?
        let total_share_count = vecmap.iter().map(|(_, c)| c).sum();
        Self {
            party_share_counts: vecmap,
            total_share_count,
        }
    }
    pub fn from_vec(vec: Vec<usize>) -> Self {
        Self::from_vecmap(VecMap::from_vec(vec))
    }
    pub fn total_share_count(&self) -> usize {
        self.total_share_count
    }
    pub fn party_count(&self) -> usize {
        self.party_share_counts.len()
    }
    pub fn iter(&self) -> VecMapIter<P, std::slice::Iter<usize>> {
        self.party_share_counts.iter()
    }
    /// fatal out of bounds
    pub fn share_to_party_id<K>(&self, share_id: TypedUsize<K>) -> TofnResult<TypedUsize<P>> {
        self.share_to_party_id_nonfatal(share_id).ok_or_else(|| {
            error!(
                "share_id {} out of bounds {}",
                share_id, self.total_share_count
            );
            TofnFatal
        })
    }
    /// non-fatal out of bounds
    pub fn share_to_party_id_nonfatal<K>(&self, share_id: TypedUsize<K>) -> Option<TypedUsize<P>> {
        let mut sum = 0;
        for (party_id, &share_count) in self.party_share_counts.iter() {
            sum += share_count;
            if share_id.as_usize() < sum {
                return Some(party_id);
            }
        }
        None
    }
}
