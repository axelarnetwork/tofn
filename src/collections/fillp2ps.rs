use crate::{
    collections::{FillHoleVecMap, HoleVecMap, TypedUsize, VecMap, VecMapIter},
    sdk::api::TofnResult,
};

use super::{holevecmap_iter::HoleVecMapIter, FullP2ps, P2ps};

pub struct FillP2ps<K, V>(VecMap<K, FillHoleVecMap<K, V>>);

impl<K, V> FillP2ps<K, V> {
    pub fn with_size(len: usize) -> Self {
        Self(
            (0..len)
                .map(|hole| {
                    // don't use FillHoleVecMap::with_size because we can't return a TofnResult
                    FillHoleVecMap::from_holevecmap(HoleVecMap::from_vecmap(
                        VecMap::from_vec((0..len - 1).map(|_| None).collect()),
                        TypedUsize::from_usize(hole),
                    ))
                })
                .collect(),
        )
    }
    pub fn size(&self) -> usize {
        self.0.len()
    }
    pub fn set(&mut self, from: TypedUsize<K>, to: TypedUsize<K>, value: V) -> TofnResult<()> {
        self.0.get_mut(from)?.set(to, value)
    }

    /// Unset all items associated with `from`
    pub fn unset_all(&mut self, from: TypedUsize<K>) -> TofnResult<()> {
        *self.0.get_mut(from)? = FillHoleVecMap::with_size(self.size(), from)?;
        Ok(())
    }

    pub fn is_none(&self, from: TypedUsize<K>, to: TypedUsize<K>) -> TofnResult<bool> {
        self.0.get(from)?.is_none(to)
    }
    pub fn is_full(&self) -> bool {
        self.0.iter().all(|(_, v)| v.is_full())
    }
    pub fn is_full_from(&self, from: TypedUsize<K>) -> TofnResult<bool> {
        Ok(self.0.get(from)?.is_full())
    }

    /// if size = 1 then return `None` and not an empty size-1 `HoleVecMap`
    pub fn map_to_p2ps<W, F>(self, mut f: F) -> TofnResult<P2ps<K, W>>
    where
        F: FnMut(V) -> W,
    {
        Ok(P2ps::<K, W>::from_vecmap(self.0.map2_result(
            |(_, fill_hole_vec)| {
                if fill_hole_vec.is_empty() {
                    Ok(None)
                } else {
                    fill_hole_vec.map_to_holevec(&mut f).map(Some)
                }
            },
        )?))
    }

    pub fn map_to_fullp2ps<W, F>(self, mut f: F) -> TofnResult<FullP2ps<K, W>>
    where
        F: FnMut(V) -> W,
    {
        Ok(FullP2ps::<K, W>::from_vecmap(
            self.0
                .into_iter()
                .map(|(_, v)| v.map_to_holevec(&mut f))
                .collect::<TofnResult<VecMap<_, _>>>()?,
        ))
    }
    pub fn to_fullp2ps(self) -> TofnResult<FullP2ps<K, V>> {
        self.map_to_fullp2ps(std::convert::identity)
    }
    pub fn to_p2ps(self) -> TofnResult<P2ps<K, V>> {
        self.map_to_p2ps(std::convert::identity)
    }
    pub fn map<W, F>(self, mut f: F) -> FillP2ps<K, W>
    where
        F: FnMut(V) -> W,
    {
        FillP2ps::<K, W>(self.0.map(|h| h.map(&mut f)))
    }

    pub fn map_result<W, F>(self, mut f: F) -> TofnResult<FillP2ps<K, W>>
    where
        F: FnMut(V) -> TofnResult<W>,
    {
        Ok(FillP2ps::<K, W>(
            self.0.map_result(|h| h.map_result(&mut f))?,
        ))
    }

    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<FillHoleVecMap<K, V>>> {
        self.0.iter()
    }

    pub fn iter_from(
        &self,
        from: TypedUsize<K>,
    ) -> TofnResult<HoleVecMapIter<K, std::slice::Iter<Option<V>>>> {
        Ok(self.0.get(from)?.iter())
    }
}

impl<K, V> IntoIterator for FillP2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        <std::vec::IntoIter<FillHoleVecMap<K, V>> as Iterator>::Item,
    );
    type IntoIter = VecMapIter<K, std::vec::IntoIter<FillHoleVecMap<K, V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// impl IntoIterator for &FillP2ps as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a FillP2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        <std::slice::Iter<'a, FillHoleVecMap<K, V>> as Iterator>::Item,
    );
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, FillHoleVecMap<K, V>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::FillP2ps;

    struct TestIndex;

    #[test]
    fn size_0() {
        let fillp2ps_size0: FillP2ps<TestIndex, usize> = FillP2ps::with_size(0);
        assert_eq!(fillp2ps_size0.size(), 0);
        assert!(fillp2ps_size0.is_full());
        assert!(fillp2ps_size0.iter().next().is_none());

        let p2ps_size0 = fillp2ps_size0.to_p2ps().unwrap();
        assert_eq!(p2ps_size0.size(), 0);
        assert!(p2ps_size0.iter().next().is_none());

        let fillp2ps_size0: FillP2ps<TestIndex, usize> = FillP2ps::with_size(0);
        let fullp2ps_size0 = fillp2ps_size0.to_fullp2ps().unwrap();
        assert_eq!(fullp2ps_size0.size(), 0);
        assert!(fullp2ps_size0.iter().next().is_none());
    }

    #[test]
    fn size_1() {
        let fillp2ps_size1: FillP2ps<TestIndex, usize> = FillP2ps::with_size(1);
        assert_eq!(fillp2ps_size1.size(), 1);
        assert!(fillp2ps_size1.is_full());

        // iterator should have exactly 1 item
        let mut iter = fillp2ps_size1.iter();
        let (_, fillholevecmap) = iter.next().unwrap();
        assert!(iter.next().is_none());

        // the contained FillVecHoleMap iterator should be empty
        assert_eq!(fillholevecmap.size(), 1);
        assert!(fillholevecmap.iter().next().is_none());
    }
}
