use crate::{
    collections::{Subset, TypedUsize, VecMap, VecMapIter},
    sdk::api::{TofnFatal, TofnResult, MAX_PARTY_SHARE_COUNT, MAX_TOTAL_SHARE_COUNT},
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `P`: https://serde.rs/attr-bound.html
pub struct PartyShareCounts<P> {
    party_share_counts: VecMap<P, usize>,
    total_share_count: usize,
}

impl<P> PartyShareCounts<P> {
    pub fn from_vecmap(vecmap: VecMap<P, usize>) -> TofnResult<Self> {
        if vecmap.iter().any(|(_, &c)| c > MAX_PARTY_SHARE_COUNT) {
            error!(
                "detected a party with share count exceeding maximum {}",
                MAX_PARTY_SHARE_COUNT
            );
            return Err(TofnFatal);
        }
        let total_share_count = vecmap.iter().map(|(_, c)| c).sum();
        if total_share_count > MAX_TOTAL_SHARE_COUNT {
            error!(
                "total share count {} exceeds maximum {}",
                total_share_count, MAX_TOTAL_SHARE_COUNT
            );
            return Err(TofnFatal);
        }
        Ok(Self {
            party_share_counts: vecmap,
            total_share_count,
        })
    }
    pub fn from_vec(vec: Vec<usize>) -> TofnResult<Self> {
        Self::from_vecmap(VecMap::from_vec(vec))
    }
    pub fn total_share_count(&self) -> usize {
        self.total_share_count
    }
    pub fn party_share_count(&self, index: TypedUsize<P>) -> TofnResult<usize> {
        Ok(*self.party_share_counts.get(index)?)
    }
    pub fn party_count(&self) -> usize {
        self.party_share_counts.len()
    }
    pub fn iter(&self) -> VecMapIter<P, std::slice::Iter<usize>> {
        self.party_share_counts.iter()
    }
    pub fn share_to_party_subshare_ids<K>(
        &self,
        share_id: TypedUsize<K>,
    ) -> TofnResult<(TypedUsize<P>, usize)> {
        let mut sum = 0;
        for (party_id, &share_count) in self.party_share_counts.iter() {
            sum += share_count;
            if share_id.as_usize() < sum {
                return Ok((party_id, share_id.as_usize() - (sum - share_count)));
            }
        }
        error!(
            "share_id {} out of bounds {}",
            share_id, self.total_share_count
        );
        Err(TofnFatal)
    }
    pub fn share_to_party_id<K>(&self, share_id: TypedUsize<K>) -> TofnResult<TypedUsize<P>> {
        Ok(self.share_to_party_subshare_ids(share_id)?.0)
    }
    pub fn party_to_share_id<K>(
        &self,
        party_id: TypedUsize<P>,
        subshare_id: usize,
    ) -> TofnResult<TypedUsize<K>> {
        let mut sum = 0;
        for (p, &share_count) in self.party_share_counts.iter() {
            if p.as_usize() == party_id.as_usize() {
                if subshare_id < share_count {
                    return Ok(TypedUsize::from_usize(sum + subshare_id));
                } else {
                    error!(
                        "subshare_id {} exceeds party_share_count {}",
                        subshare_id, share_count
                    );
                    return Err(TofnFatal);
                }
            }
            sum += share_count;
        }
        error!(
            "party_id {} exceeds party_count {}",
            subshare_id,
            self.party_count()
        );
        Err(TofnFatal)
    }
    pub fn subset(&self, party_ids: &Subset<P>) -> TofnResult<Vec<usize>> {
        if party_ids.max_size() != self.party_count() {
            error!(
                "party_ids max size {} disagrees with self.party_count() {}",
                party_ids.max_size(),
                self.party_count()
            );
            return Err(TofnFatal);
        }
        party_ids
            .iter()
            .map(|i| self.party_share_count(i))
            .collect()
    }

    /// Return the sublist of (0..total_share_count) induced by party_ids
    /// Example self:
    ///   self.party_share_counts: [1, 2, 3]
    ///
    /// Example party_ids #1:
    ///   party_ids:        [0, 1, 2]          <- full subset of self.party_share_counts
    ///   output:           [0, 1, 2, 3, 4, 5] <- all share_ids present
    ///                      ^  ^  ^  ^  ^  ^
    ///                      0  1  1  2  2  2  <- party_ids repeated according to their share counts
    ///
    /// Example party_ids #2:
    ///   party_ids:        [0, 2]       <- subset does not include party_id 1
    ///   output:           [0, 3, 4, 5] <- missing share_ids 1, 2 belonging to excluded party_id 1
    ///                      ^  ^  ^  ^
    ///                      0  2  2  2  <- party_ids repeated according to their share counts
    pub fn share_id_subset<K>(&self, party_ids: &Subset<P>) -> TofnResult<Vec<TypedUsize<K>>> {
        if party_ids.max_size() != self.party_count() {
            error!(
                "party_ids max size {} disagrees with self.party_count() {}",
                party_ids.max_size(),
                self.party_count()
            );
            return Err(TofnFatal);
        }

        let mut participants = Vec::new();
        let mut sum = 0;
        for (party_id, &party_share_count) in self.iter() {
            if party_ids.is_member(party_id)? {
                for j in 0..party_share_count {
                    participants.push(TypedUsize::from_usize(sum + j));
                }
            }
            sum += party_share_count;
        }
        Ok(participants)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestParty;
    struct TestShare;

    #[test]
    fn share_id_subset() {
        struct TestCase {
            party_share_counts: PartyShareCounts<TestParty>,
            party_ids: Subset<TestParty>,
            result: TofnResult<Vec<TypedUsize<TestShare>>>,
        }

        impl TestCase {
            fn new(
                party_share_counts: Vec<usize>,
                party_ids: Subset<TestParty>,
                result: TofnResult<Vec<usize>>,
            ) -> Self {
                Self {
                    party_share_counts: PartyShareCounts::from_vec(party_share_counts).unwrap(),
                    party_ids,
                    result: result.map(|vec| vec.into_iter().map(TypedUsize::from_usize).collect()),
                }
            }
        }

        let tests = vec![
            TestCase::new(vec![1, 1, 1, 1], subset(4, vec![0, 2]), Ok(vec![0, 2])),
            TestCase::new(vec![1, 1, 1, 2], subset(4, vec![0, 3]), Ok(vec![0, 3, 4])),
            TestCase::new(
                vec![2, 1, 4, 1],
                subset(4, vec![0, 2]),
                Ok(vec![0, 1, 3, 4, 5, 6]),
            ),
        ];

        for t in tests {
            assert_eq!(t.party_share_counts.share_id_subset(&t.party_ids), t.result);
        }
    }

    fn subset<P>(max_size: usize, vec: Vec<usize>) -> Subset<P> {
        let len = std::cmp::max(max_size, vec.len());
        let mut output = Subset::with_max_size(len);
        for i in vec {
            output.add(TypedUsize::from_usize(i)).unwrap();
        }
        output
    }
}
