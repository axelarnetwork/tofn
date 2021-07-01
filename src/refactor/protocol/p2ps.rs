use crate::vecmap::{HoleVecMap, Index, VecMap};

pub struct P2ps<K, V>(VecMap<K, HoleVecMap<K, V>>);

impl<K, V> P2ps<K, V> {
    // TODO TEMPORARY eliminate from_vecmaps
    pub fn from_vecmaps(v: VecMap<K, HoleVecMap<K, V>>) -> Self {
        Self(v)
    }

    pub fn to_me(&self, me: Index<K>) -> impl Iterator<Item = (Index<K>, &V)> + '_ {
        self.0.iter().filter_map(move |(k, hole_vec)| {
            if k == me {
                None
            } else {
                Some((k, hole_vec.get(me)))
            }
        })
    }
}
