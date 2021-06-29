use std::iter::FromIterator;

use super::{vecmap_iter::VecMapIter, Index};

#[derive(Debug, Clone, PartialEq)]
pub struct VecMap<K, V>(Vec<V>, std::marker::PhantomData<Index<K>>);

impl<K, V> VecMap<K, V> {
    fn from_vec(vec: Vec<V>) -> Self {
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
