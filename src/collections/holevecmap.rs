use tracing::error;

use crate::sdk::api::{TofnFatal, TofnResult};

use super::{holevecmap_iter::HoleVecMapIter, TypedUsize, VecMap};

// do not derive `Serialize`, `Deserialize`: `hole` might be an attack vector
// see https://github.com/axelarnetwork/tofn/issues/105
#[derive(Debug, Clone, PartialEq)]
pub struct HoleVecMap<K, V> {
    vec: VecMap<K, V>,
    hole: TypedUsize<K>,
}

impl<K, V> HoleVecMap<K, V> {
    // private constructor; use VecMap::remember_hole instead
    pub(super) fn from_vecmap(vec: VecMap<K, V>, hole: TypedUsize<K>) -> Self {
        Self { vec, hole }
    }

    pub fn get(&self, index: TypedUsize<K>) -> TofnResult<&V> {
        self.vec.get(self.map_index(index)?)
    }

    pub fn get_mut(&mut self, index: TypedUsize<K>) -> TofnResult<&mut V> {
        self.vec.get_mut(self.map_index(index)?)
    }

    /// never returns 0. `is_empty` returns `true` even when `len` is 1
    pub fn len(&self) -> usize {
        self.vec.len() + 1
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    /// two ways to convert to `VecMap`
    pub fn plug_hole(self, val: V) -> VecMap<K, V> {
        let mut vec = self.vec.into_vec();
        vec.insert(self.hole.as_usize(), val);
        VecMap::from_vec(vec)
    }

    pub fn get_hole(&self) -> TypedUsize<K> {
        self.hole
    }

    pub fn forget_hole(self) -> VecMap<K, V> {
        self.vec
    }

    pub fn iter(&self) -> HoleVecMapIter<K, std::slice::Iter<V>> {
        HoleVecMapIter::new(self.vec.iter(), self.hole)
    }

    fn map_index(&self, index: TypedUsize<K>) -> TofnResult<TypedUsize<K>> {
        match index.as_usize() {
            i if i < self.hole.as_usize() => Ok(index),
            i if i > self.hole.as_usize() && i <= self.vec.len() => {
                Ok(TypedUsize::from_usize(i - 1))
            }
            i if i == self.hole.as_usize() => {
                error!("attempt to index hole {}", i);
                Err(TofnFatal)
            }
            i => {
                error!("index {} out of bounds {}", i, self.len());
                Err(TofnFatal)
            }
        }
    }

    pub fn ref_map2_result<W, F>(&self, f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut((TypedUsize<K>, &V)) -> TofnResult<W>,
    {
        Ok(HoleVecMap::<K, W>::from_vecmap(
            self.iter().map(f).collect::<TofnResult<VecMap<K, W>>>()?,
            self.hole,
        ))
    }

    pub fn map<W, F>(self, f: F) -> HoleVecMap<K, W>
    where
        F: FnMut(V) -> W,
    {
        HoleVecMap::<K, W> {
            vec: self.vec.map(f),
            hole: self.hole,
        }
    }

    pub fn map_result<W, F>(self, f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut(V) -> TofnResult<W>,
    {
        let hole = self.hole;
        Ok(HoleVecMap::<K, W>::from_vecmap(
            self.vec.map_result(f)?,
            hole,
        ))
    }

    pub fn map2_result<W, F>(self, f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut((TypedUsize<K>, V)) -> TofnResult<W>,
    {
        let hole = self.hole;
        Ok(HoleVecMap::<K, W>::from_vecmap(
            self.into_iter()
                .map(f)
                .collect::<TofnResult<VecMap<K, W>>>()?,
            hole,
        ))
    }
}

impl<K, V> IntoIterator for HoleVecMap<K, V> {
    type Item = (TypedUsize<K>, <std::vec::IntoIter<V> as Iterator>::Item);
    type IntoIter = HoleVecMapIter<K, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        HoleVecMapIter::new(self.vec.into_iter(), self.hole)
    }
}

/// impl IntoIterator for &HoleVecMap as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a HoleVecMap<K, V> {
    type Item = (TypedUsize<K>, <std::slice::Iter<'a, V> as Iterator>::Item);
    type IntoIter = HoleVecMapIter<K, std::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
