use std::iter::FromIterator;

use super::{vecmap_iter::VecMapIter, Index};

#[derive(Debug, Clone, PartialEq)]
pub struct VecMap<K, V>(Vec<V>, std::marker::PhantomData<Index<K>>);

impl<K, V> VecMap<K, V> {
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

/// impl IntoIterator for &VecMap as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a VecMap<K, V> {
    type Item = (Index<K>, <std::slice::Iter<'a, V> as Iterator>::Item);
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K, V> FromIterator<V> for VecMap<K, V> {
    fn from_iter<Iter: IntoIterator<Item = V>>(iter: Iter) -> Self {
        Self(Vec::from_iter(iter), std::marker::PhantomData)
    }
}
