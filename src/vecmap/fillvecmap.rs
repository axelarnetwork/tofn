//! A fillable Vec
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{vecmap_iter::VecMapIter, Behave, Index, VecMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FillVecMap<K, V>
where
    K: Behave,
{
    vec: VecMap<K, Option<V>>,
    some_count: usize, // TODO eliminate `some_count`?
}

impl<K, V> FillVecMap<K, V>
where
    K: Behave,
{
    pub fn with_size(len: usize) -> Self {
        Self {
            vec: (0..len).map(|_| None).collect(),
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
        let stored = self.vec.get_mut(index);
        if stored.is_none() {
            self.some_count += 1;
        } else {
            if warn {
                warn!("overwrite existing value at index {}", index);
            }
        }
        *stored = Some(value);
    }
    // pub fn size(&self) -> usize {
    //     self.vec.len()
    // }
    // pub fn is_none(&self, index: usize) -> bool {
    //     matches!(self.vec[index], None)
    // }
    // /// Returns `true` if all items are `Some`, except possibly the `index`th item.
    // pub fn is_full_except(&self, index: usize) -> bool {
    //     (self.is_none(index) && self.some_count() >= self.vec.len() - 1)
    //         || self.some_count() >= self.vec.len()
    // }

    pub fn is_full(&self) -> bool {
        self.some_count == self.vec.len()
    }
    pub fn is_empty(&self) -> bool {
        self.some_count == 0
    }
    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<Option<V>>> {
        self.vec.iter()
    }

    /// Iterate only over items that are `Some`
    pub fn iter_some(&self) -> impl Iterator<Item = (Index<K>, &V)> + '_ {
        self.vec
            .iter()
            .filter_map(|(i, x)| if let Some(y) = x { Some((i, y)) } else { None })
    }
    pub fn into_iter_some(self) -> impl Iterator<Item = (Index<K>, V)> {
        self.into_iter()
            .filter_map(|(i, x)| if let Some(y) = x { Some((i, y)) } else { None })
    }

    // pub fn from_vec(vec: Vec<Option<T>>) -> Self {
    //     Self {
    //         some_count: vec.iter().filter(|x| x.is_some()).count(),
    //         vec,
    //     }
    // }
    pub fn unwrap_all_map<W, F>(self, mut f: F) -> VecMap<K, W>
    where
        F: FnMut(V) -> W,
    {
        self.vec.map(|x| f(x.unwrap()))
    }
    pub fn unwrap_all(self) -> VecMap<K, V> {
        self.unwrap_all_map(std::convert::identity)
    }
}

// TODO don't impl IntoIterator for FillVecMap?
impl<K, V> IntoIterator for FillVecMap<K, V>
where
    K: Behave,
{
    type Item = <VecMapIter<K, std::vec::IntoIter<Option<V>>> as Iterator>::Item;
    type IntoIter = VecMapIter<K, std::vec::IntoIter<Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter()
    }
}
