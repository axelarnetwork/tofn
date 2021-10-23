use serde::{Deserialize, Serialize};
use std::iter::FromIterator;
use tracing::error;
use zeroize::Zeroize;

use crate::sdk::api::{TofnFatal, TofnResult};

use super::{vecmap_iter::VecMapIter, HoleVecMap, TypedUsize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VecMap<K, V>(Vec<V>, std::marker::PhantomData<TypedUsize<K>>);

impl<K, V> Zeroize for VecMap<K, V>
where
    V: Zeroize,
{
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<K, V> VecMap<K, V> {
    pub fn from_vec(vec: Vec<V>) -> Self {
        Self(vec, std::marker::PhantomData)
    }
    pub fn into_vec(self) -> Vec<V> {
        self.0
    }
    pub fn get(&self, index: TypedUsize<K>) -> TofnResult<&V> {
        self.0.get(index.as_usize()).ok_or_else(|| {
            error!("index {} out of bounds {}", index, self.0.len());
            TofnFatal
        })
    }
    pub fn get_mut(&mut self, index: TypedUsize<K>) -> TofnResult<&mut V> {
        let len = self.0.len(); // fight the borrow checker
        self.0.get_mut(index.as_usize()).ok_or_else(|| {
            error!("index {} out of bounds {}", index, len);
            TofnFatal
        })
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 2 ways to convert to `HoleVecMap`
    pub fn puncture_hole(mut self, hole: TypedUsize<K>) -> TofnResult<(HoleVecMap<K, V>, V)> {
        if hole.as_usize() >= self.0.len() {
            error!("hole {} out of bounds {}", hole.as_usize(), self.0.len());
            return Err(TofnFatal);
        }
        let hole_val = self.0.remove(hole.as_usize());
        Ok((HoleVecMap::from_vecmap(self, hole), hole_val))
    }
    pub fn remember_hole(self, hole: TypedUsize<K>) -> TofnResult<HoleVecMap<K, V>> {
        if hole.as_usize() > self.0.len() {
            error!("hole {} out of bounds {}", hole.as_usize(), self.0.len());
            return Err(TofnFatal);
        }
        Ok(HoleVecMap::from_vecmap(self, hole))
    }

    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<V>> {
        VecMapIter::new(self.0.iter())
    }
    pub fn iter_mut(&mut self) -> VecMapIter<K, std::slice::IterMut<V>> {
        VecMapIter::new(self.0.iter_mut())
    }
    pub fn map<W, F>(self, f: F) -> VecMap<K, W>
    where
        F: FnMut(V) -> W,
    {
        VecMap::<K, W>::from_vec(self.0.into_iter().map(f).collect())
    }

    pub fn ref_map<W, F>(&self, f: F) -> VecMap<K, W>
    where
        F: FnMut(&V) -> W,
    {
        VecMap::<K, W>::from_vec(self.0.iter().map(f).collect())
    }

    pub fn map_result<W, F>(self, f: F) -> TofnResult<VecMap<K, W>>
    where
        F: FnMut(V) -> TofnResult<W>,
    {
        Ok(VecMap::<K, W>::from_vec(
            self.0.into_iter().map(f).collect::<TofnResult<Vec<W>>>()?,
        ))
    }

    pub fn map2<W, F>(self, f: F) -> VecMap<K, W>
    where
        F: FnMut((TypedUsize<K>, V)) -> W,
    {
        self.into_iter().map(f).collect()
    }
    pub fn map2_result<W, F>(self, f: F) -> TofnResult<VecMap<K, W>>
    where
        F: FnMut((TypedUsize<K>, V)) -> TofnResult<W>,
    {
        self.into_iter().map(f).collect()
    }
}

impl<K, V> IntoIterator for VecMap<K, V> {
    type Item = (TypedUsize<K>, <std::vec::IntoIter<V> as Iterator>::Item);
    type IntoIter = VecMapIter<K, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        VecMapIter::new(self.0.into_iter())
    }
}

/// impl IntoIterator for &VecMap as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a VecMap<K, V> {
    type Item = (TypedUsize<K>, <std::slice::Iter<'a, V> as Iterator>::Item);
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<K, V> FromIterator<V> for VecMap<K, V> {
    fn from_iter<Iter: IntoIterator<Item = V>>(iter: Iter) -> Self {
        Self::from_vec(Vec::from_iter(iter))
    }
}
