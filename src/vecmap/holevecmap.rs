use super::{holevecmap_iter::HoleVecMapIter, Index, VecMap};

#[derive(Debug, Clone, PartialEq)]
pub struct HoleVecMap<K, V> {
    vec: VecMap<K, V>,
    hole: Index<K>,
    phantom: std::marker::PhantomData<Index<K>>,
}

impl<K, V> HoleVecMap<K, V> {
    pub fn get(&self, index: Index<K>) -> &V {
        self.vec.get(self.map_index(index).expect("bad index"))
    }
    pub fn get_mut(&mut self, index: Index<K>) -> &mut V {
        self.vec.get_mut(self.map_index(index).expect("bad index"))
    }
    pub fn len(&self) -> usize {
        self.vec.len() + 1
    }
    // pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<V>> {
    //     VecMapIter::new(self.0.iter())
    // }

    fn map_index(&self, index: Index<K>) -> Result<Index<K>, &'static str> {
        match index.0 {
            i if i < self.hole.0 => Ok(index),
            i if i > self.hole.0 && i <= self.vec.len() => Ok(Index::from_usize(i - 1)),
            i if i == self.hole.0 => Err("index == hole"),
            _ => Err("index out of range"),
        }
    }
}

impl<K, V> IntoIterator for HoleVecMap<K, V> {
    type Item = (Index<K>, <std::vec::IntoIter<V> as Iterator>::Item);
    type IntoIter = HoleVecMapIter<K, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        HoleVecMapIter::new(self.vec.into_iter(), self.hole)
    }
}
