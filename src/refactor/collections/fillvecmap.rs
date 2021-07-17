//! A fillable VecMap
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::refactor::protocol::api::{TofnFatal, TofnResult};

use super::{vecmap_iter::VecMapIter, TypedUsize, VecMap};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FillVecMap<K, V> {
    vec: VecMap<K, Option<V>>,
    some_count: usize,
}

impl<K, V> FillVecMap<K, V> {
    pub fn with_size(len: usize) -> Self {
        Self {
            vec: (0..len).map(|_| None).collect(),
            some_count: 0,
        }
    }
    // pub fn size(&self) -> usize {
    //     self.vec.len()
    // }
    // pub fn get(&self, index: Index<K>) -> &Option<V> {
    //     self.vec.get(index)
    // }
    pub fn set(&mut self, index: TypedUsize<K>, value: V) -> TofnResult<()> {
        self.set_impl(index, value, false)
    }
    pub fn set_warn(&mut self, index: TypedUsize<K>, value: V) -> TofnResult<()> {
        self.set_impl(index, value, true)
    }
    fn set_impl(&mut self, index: TypedUsize<K>, value: V, warn: bool) -> TofnResult<()> {
        let stored = self.vec.get_mut(index)?;
        if stored.is_none() {
            self.some_count += 1;
        } else if warn {
            warn!("overwrite existing value at index {}", index);
        }

        *stored = Some(value);
        Ok(())
    }
    pub fn is_none(&self, index: TypedUsize<K>) -> TofnResult<bool> {
        Ok(self.vec.get(index)?.is_none())
    }
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
    pub fn iter_some(&self) -> impl Iterator<Item = (TypedUsize<K>, &V)> + '_ {
        self.vec
            .iter()
            .filter_map(|(i, x)| x.as_ref().map(|y| (i, y)))
    }
    pub fn into_iter_some(self) -> impl Iterator<Item = (TypedUsize<K>, V)> {
        self.into_iter().filter_map(|(i, x)| x.map(|y| (i, y)))
    }

    pub fn unwrap_all_map<W, F>(self, mut f: F) -> TofnResult<VecMap<K, W>>
    where
        F: FnMut(V) -> W,
    {
        if !self.is_full() {
            error!("self is not full");
            return Err(TofnFatal);
        }
        Ok(self.vec.map(|x| f(x.unwrap())))
    }
    pub fn unwrap_all(self) -> TofnResult<VecMap<K, V>> {
        self.unwrap_all_map(std::convert::identity)
    }
}

impl<K, V> IntoIterator for FillVecMap<K, V> {
    type Item = <VecMapIter<K, std::vec::IntoIter<Option<V>>> as Iterator>::Item;
    type IntoIter = VecMapIter<K, std::vec::IntoIter<Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter()
    }
}

/// impl IntoIterator for &FillVecMap as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a FillVecMap<K, V> {
    type Item = (
        TypedUsize<K>,
        <std::slice::Iter<'a, Option<V>> as Iterator>::Item,
    );
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, Option<V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
