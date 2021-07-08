//! A fillable Vec
// use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{holevecmap_iter::HoleVecMapIter, Behave, HoleVecMap, Index, VecMap};

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct FillHoleVecMap<K, V>
where
    K: Behave,
{
    hole_vec: HoleVecMap<K, Option<V>>,
    some_count: usize, // TODO eliminate `some_count`?
}

impl<K, V> FillHoleVecMap<K, V>
where
    K: Behave,
{
    /// if hole >= len-1 then use hole = len-1
    pub fn with_size(len: usize, hole: Index<K>) -> Self {
        Self {
            hole_vec: HoleVecMap::from_vecmap(
                VecMap::from_vec((0..len - 1).map(|_| None).collect()),
                hole,
            ),
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
    pub fn iter(&self) -> HoleVecMapIter<K, std::slice::Iter<Option<V>>> {
        self.hole_vec.iter()
    }
    pub fn unwrap_all_map<W, F>(self, mut f: F) -> HoleVecMap<K, W>
    where
        F: FnMut(V) -> W,
    {
        self.hole_vec.map(|x| f(x.unwrap()))
    }
    pub fn unwrap_all(self) -> HoleVecMap<K, V> {
        self.unwrap_all_map(std::convert::identity)
    }
}

// TODO don't impl IntoIterator for FillVecMap?
impl<K, V> IntoIterator for FillHoleVecMap<K, V>
where
    K: Behave,
{
    type Item = <HoleVecMapIter<K, std::vec::IntoIter<Option<V>>> as Iterator>::Item;
    type IntoIter = HoleVecMapIter<K, std::vec::IntoIter<Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.hole_vec.into_iter()
    }
}
