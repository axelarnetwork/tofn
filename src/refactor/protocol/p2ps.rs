use crate::vecmap::{Behave, FillHoleVecMap, HoleVecMap, Index, VecMap};

pub struct P2ps<K, V>(VecMap<K, HoleVecMap<K, V>>)
where
    K: Behave;

impl<K, V> P2ps<K, V>
where
    K: Behave,
{
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

pub struct FillP2ps<K, V>(VecMap<K, FillHoleVecMap<K, V>>)
where
    K: Behave;

impl<K, V> FillP2ps<K, V>
where
    K: Behave,
{
    pub fn with_size(len: usize) -> Self {
        Self(
            (0..len)
                .map(|hole| FillHoleVecMap::with_size(len, Index::from_usize(hole)))
                .collect(),
        )
    }
    pub fn set(&mut self, from: Index<K>, to: Index<K>, value: V) {
        self.0.get_mut(from).set(to, value);
    }
    pub fn set_warn(&mut self, from: Index<K>, to: Index<K>, value: V) {
        self.0.get_mut(from).set_warn(to, value);
    }
}
