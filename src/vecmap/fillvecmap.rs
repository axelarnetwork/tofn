//! A fillable Vec
// use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{vecmap_iter::VecMapIter, Index, VecMap};

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct FillVecMap<K, V> {
    vec: VecMap<K, Option<V>>,
    some_count: usize, // TODO eliminate `some_count`?
}

impl<K, V> FillVecMap<K, V> {
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

    // Replicate std::vec interface https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#1800
    // pub fn is_empty(&self) -> bool {
    //     self.some_count == 0
    // }
    // pub fn from_vec(vec: Vec<Option<T>>) -> Self {
    //     Self {
    //         some_count: vec.iter().filter(|x| x.is_some()).count(),
    //         vec,
    //     }
    // }
}

impl<K, V> IntoIterator for FillVecMap<K, V> {
    type Item = <VecMapIter<K, std::vec::IntoIter<Option<V>>> as Iterator>::Item;
    type IntoIter = VecMapIter<K, std::vec::IntoIter<Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter()
    }
}
