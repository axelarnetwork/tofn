#[derive(Debug, Clone, PartialEq)]
pub struct VecMap<K, V>(Vec<V>, std::marker::PhantomData<Index<K>>);

impl<K, V> VecMap<K, V> {
    pub fn from_vec(vec: Vec<V>) -> Self {
        Self(vec, std::marker::PhantomData)
    }
    pub fn get(&self, index: Index<K>) -> &V {
        // TODO range check?
        &self.0[index.0]
    }
    pub fn get_mut(&mut self, index: Index<K>) -> &mut V {
        // TODO range check?
        &mut self.0[index.0]
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<V>> {
        VecMapIter::new(self.0.iter())
    }
}

impl<K, V> IntoIterator for VecMap<K, V> {
    type Item = (Index<K>, <std::vec::IntoIter<V> as Iterator>::Item);
    type IntoIter = VecMapIter<K, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        VecMapIter::new(self.0.into_iter())
    }
}

impl<K, V> FromIterator<V> for VecMap<K, V> {
    fn from_iter<Iter: IntoIterator<Item = V>>(iter: Iter) -> Self {
        VecMap::from_vec(Vec::from_iter(iter))
    }
}

#[derive(Debug, PartialEq)] // manual impls for Clone, Copy---see below
pub struct Index<K>(usize, std::marker::PhantomData<K>);

impl<K> Index<K> {
    // TODO remove `pub`
    pub fn from_usize(index: usize) -> Self {
        Index(index, std::marker::PhantomData)
    }
}

impl<K> std::fmt::Display for Index<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Manually impl `Clone`, `Copy` because https://stackoverflow.com/a/31371094
impl<K> Clone for Index<K> {
    fn clone(&self) -> Self {
        Self::from_usize(self.0)
    }
}
impl<K> Copy for Index<K> {}

mod vecmap_iter;
use std::iter::FromIterator;

use vecmap_iter::VecMapIter;

pub mod fillvecmap;
