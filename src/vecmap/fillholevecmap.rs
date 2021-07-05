//! A fillable Vec
// use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::refactor::TofnResult;

use super::{holevecmap::Pair, holevecmap_iter::HoleVecMapIter, HoleVecMap, Index};

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct FillHoleVecMap<K, V>
where
    K: Clone,
{
    hole_vec: HoleVecMap<K, Option<V>>,
    some_count: usize, // TODO eliminate `some_count`?
}

impl<K, V> FillHoleVecMap<K, V>
where
    K: Clone,
{
    /// if hole >= len-1 then use hole = len-1
    pub fn with_size(len: usize, hole: Index<K>) -> Self {
        Self {
            hole_vec: (0..len - 1)
                .map(|i| Pair(Index::from_usize(if i < hole.0 { i } else { i + 1 }), None))
                .collect::<TofnResult<_>>()
                .expect("fail to initialize HoleVec"),
            some_count: 0,
        }
    }
    pub fn set(&mut self, index: Index<K>, value: V) {
        self.set_impl(index, value, false)
    }
    pub fn set_warn(&mut self, index: Index<K>, value: V) {
        self.set_impl(index, value, true)
    }
    fn set_impl(&mut self, index: Index<K>, value: V, warn: bool) {
        let stored = self.hole_vec.get_mut(index);
        if stored.is_none() {
            self.some_count += 1;
        } else {
            if warn {
                warn!("overwrite existing value at index {}", index);
            }
        }
        *stored = Some(value);
    }
    pub fn is_full(&self) -> bool {
        self.some_count == self.hole_vec.len() - 1
    }
}

impl<K, V> IntoIterator for FillHoleVecMap<K, V>
where
    K: Clone,
{
    type Item = <HoleVecMapIter<K, std::vec::IntoIter<Option<V>>> as Iterator>::Item;
    type IntoIter = HoleVecMapIter<K, std::vec::IntoIter<Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.hole_vec.into_iter()
    }
}
