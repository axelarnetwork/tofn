//! A subset of typed indices
use super::{FillVecMap, TypedUsize, VecMapIter};
use crate::refactor::sdk::api::TofnResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subset<K>(FillVecMap<K, ()>);

impl<K> Subset<K> {
    pub fn with_max_size(len: usize) -> Self {
        Self(FillVecMap::with_size(len))
    }
    pub fn max_size(&self) -> usize {
        self.0.size()
    }
    pub fn member_count(&self) -> usize {
        self.0.some_count()
    }
    pub fn add(&mut self, index: TypedUsize<K>) -> TofnResult<()> {
        self.0.set(index, ())
    }
    pub fn is_member(&self, index: TypedUsize<K>) -> TofnResult<bool> {
        Ok(!self.0.is_none(index)?)
    }
    pub fn is_full(&self) -> bool {
        self.0.is_full()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate only over members of the subset
    pub fn iter(&self) -> impl Iterator<Item = TypedUsize<K>> + '_ {
        self.0.iter_some().map(|(i, _)| i)
    }
}

// TODO don't know how to impl IntoIterator because don't know `IntoIter` type


/// impl IntoIterator for &Subset as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K> IntoIterator for &'a Subset<K> {
    type Item = TypedUsize<K>;
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, Option<()>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
