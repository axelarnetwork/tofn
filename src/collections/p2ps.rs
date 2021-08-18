use tracing::error;

use crate::{
    collections::{
        p2ps_iter::P2psIter, FillHoleVecMap, HoleVecMap, TypedUsize, VecMap, VecMapIter,
    },
    sdk::api::{TofnFatal, TofnResult},
};

#[derive(Debug, Clone, PartialEq)]
pub struct P2ps<K, V>(VecMap<K, Option<HoleVecMap<K, V>>>);

impl<K, V> P2ps<K, V> {
    pub fn new_size_1_some() -> TofnResult<Self> {
        Ok(Self(VecMap::from_vec(vec![Some(HoleVecMap::from_vecmap(
            VecMap::from_vec(vec![]),
            TypedUsize::from_usize(0),
        )?)])))
    }
    pub fn get(&self, from: TypedUsize<K>) -> TofnResult<&Option<HoleVecMap<K, V>>> {
        self.0.get(from)
    }

    pub fn to_me(
        &self,
        me: TypedUsize<K>,
    ) -> TofnResult<impl Iterator<Item = (TypedUsize<K>, Option<&V>)> + '_> {
        // check `me` manually now instead of using `?` inside closure
        if me.as_usize() >= self.0.len() {
            error!("index {} out of bounds {}", me, self.0.len());
            return Err(TofnFatal);
        }
        Ok(self.0.iter().filter_map(move |(k, hole_vec_option)| {
            if k == me {
                None
            } else {
                Some((
                    k,
                    hole_vec_option
                        .as_ref()
                        .map(|hole_vec| hole_vec.get(me).expect("index out of bounds")),
                ))
            }
        }))
    }
    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<Option<HoleVecMap<K, V>>>> {
        self.0.iter()
    }
    pub fn map_to_me<W, F>(&self, me: TypedUsize<K>, mut f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut(Option<&V>) -> W,
    {
        HoleVecMap::from_vecmap(
            VecMap::from_vec(self.to_me(me)?.map(|(_, v)| f(v)).collect()),
            me,
        )
    }

    pub fn map<W, F>(self, f: F) -> P2ps<K, W>
    where
        F: FnMut(V) -> W + Clone,
    {
        P2ps::<K, W>(
            self.0
                .map(|hole_vec_option| hole_vec_option.map(|hole_vec| hole_vec.map(f.clone()))),
        )
    }

    pub fn map_to_fullp2ps<W, F>(self, f: F) -> TofnResult<FullP2ps<K, W>>
    where
        F: FnMut(V) -> W + Clone,
    {
        Ok(FullP2ps::<K, W>(self.0.map2_result(
            |(from, hole_vec_option)| {
                Ok(hole_vec_option
                    .ok_or_else(|| {
                        error!("missing HoleVecMap at index {}", from);
                        TofnFatal
                    })?
                    .map(f.clone()))
            },
        )?))
    }
    pub fn to_fullp2ps(self) -> TofnResult<FullP2ps<K, V>> {
        self.map_to_fullp2ps(std::convert::identity)
    }
}

#[allow(clippy::type_complexity)]
impl<K, V> IntoIterator for P2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        <std::vec::IntoIter<Option<HoleVecMap<K, V>>> as Iterator>::Item,
    );
    type IntoIter = VecMapIter<K, std::vec::IntoIter<Option<HoleVecMap<K, V>>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// impl IntoIterator for &P2ps as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
#[allow(clippy::type_complexity)]
impl<'a, K, V> IntoIterator for &'a P2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        <std::slice::Iter<'a, Option<HoleVecMap<K, V>>> as Iterator>::Item,
    );
    type IntoIter = VecMapIter<K, std::slice::Iter<'a, Option<HoleVecMap<K, V>>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// TODO is `FullP2ps` too similar to `FillP2ps`?
// do not derive serde for anything with a `HoleVecMap`
#[derive(Debug, Clone, PartialEq)]
pub struct FullP2ps<K, V>(VecMap<K, HoleVecMap<K, V>>);

impl<K, V> FullP2ps<K, V> {
    pub fn get(&self, from: TypedUsize<K>, to: TypedUsize<K>) -> TofnResult<&V> {
        self.0.get(from)?.get(to)
    }
    pub fn to_me(
        &self,
        me: TypedUsize<K>,
    ) -> TofnResult<impl Iterator<Item = (TypedUsize<K>, &V)> + '_> {
        // check `me` manually now instead of using `?` inside closure
        if me.as_usize() >= self.0.len() {
            error!("index {} out of bounds {}", me, self.0.len());
            return Err(TofnFatal);
        }
        Ok(self.0.iter().filter_map(move |(k, hole_vec)| {
            if k == me {
                None
            } else {
                // TODO: Remove possible panic using Result
                Some((k, hole_vec.get(me).expect("index out of bounds")))
            }
        }))
    }
    pub fn iter(&self) -> P2psIter<K, std::slice::Iter<HoleVecMap<K, V>>, std::slice::Iter<V>> {
        P2psIter::new(self.0.iter())
    }
    pub fn map_to_me<W, F>(&self, me: TypedUsize<K>, mut f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut(&V) -> W,
    {
        HoleVecMap::from_vecmap(
            VecMap::from_vec(self.to_me(me)?.map(|(_, v)| f(v)).collect()),
            me,
        )
    }
    pub fn map_to_me2<W, F>(&self, me: TypedUsize<K>, f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut((TypedUsize<K>, &V)) -> W,
    {
        HoleVecMap::from_vecmap(VecMap::from_vec(self.to_me(me)?.map(f).collect()), me)
    }
    pub fn map<W, F>(self, f: F) -> FullP2ps<K, W>
    where
        F: FnMut(V) -> W + Clone,
    {
        FullP2ps::<K, W>(self.0.map(|v| v.map(f.clone())))
    }

    pub fn map2_result<W, F>(self, f: F) -> TofnResult<FullP2ps<K, W>>
    where
        F: FnMut((TypedUsize<K>, V)) -> TofnResult<W> + Clone,
    {
        Ok(FullP2ps::<K, W>(
            self.0.map2_result(|(_, v)| v.map2_result(f.clone()))?,
        ))
    }
}

impl<K, V> IntoIterator for FullP2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        TypedUsize<K>,
        <std::vec::IntoIter<V> as Iterator>::Item,
    );
    type IntoIter = P2psIter<K, std::vec::IntoIter<HoleVecMap<K, V>>, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        P2psIter::new(self.0.into_iter())
    }
}

/// impl IntoIterator for &P2ps as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a FullP2ps<K, V> {
    type Item = (
        TypedUsize<K>,
        TypedUsize<K>,
        <std::slice::Iter<'a, V> as Iterator>::Item,
    );
    type IntoIter = P2psIter<K, std::slice::Iter<'a, HoleVecMap<K, V>>, std::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

// `FillP2ps` is a `(VecMap<_,_>)` instead of `(P2ps<_,_>)` because `P2ps` has no public constructor.
// Can't put `FillP2ps` in a separate module because `FillP2ps` has methods that construct a `P2ps`.
pub struct FillP2ps<K, V>(VecMap<K, FillHoleVecMap<K, V>>);

impl<K, V> FillP2ps<K, V> {
    pub fn with_size(len: usize) -> TofnResult<Self> {
        Ok(Self(
            (0..len)
                .map(|hole| FillHoleVecMap::with_size(len, TypedUsize::from_usize(hole)))
                .collect::<TofnResult<_>>()?,
        ))
    }
    pub fn size(&self) -> usize {
        self.0.len()
    }
    pub fn set(&mut self, from: TypedUsize<K>, to: TypedUsize<K>, value: V) -> TofnResult<()> {
        self.0.get_mut(from)?.set(to, value)
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

    // if size = 1 then return `None` and not an empty size-1 `HoleVecMap`
    pub fn map_to_p2ps<W, F>(self, f: F) -> TofnResult<P2ps<K, W>>
    where
        F: FnMut(V) -> W + Clone,
    {
        Ok(P2ps::<K, W>(self.0.map2_result(|(_, fill_hole_vec)| {
            if fill_hole_vec.is_empty() {
                Ok(None)
            } else {
                fill_hole_vec.map_to_holevec(f.clone()).map(Some)
            }
        })?))
    }

    pub fn map_to_fullp2ps<W, F>(self, f: F) -> TofnResult<FullP2ps<K, W>>
    where
        F: FnMut(V) -> W + Clone,
    {
        Ok(FullP2ps::<K, W>(
            self.0
                .into_iter()
                .map(|(_, v)| v.map_to_holevec(f.clone()))
                .collect::<TofnResult<VecMap<_, _>>>()?,
        ))
    }
    pub fn to_fullp2ps(self) -> TofnResult<FullP2ps<K, V>> {
        self.map_to_fullp2ps(std::convert::identity)
    }
    pub fn to_p2ps(self) -> TofnResult<P2ps<K, V>> {
        self.map_to_p2ps(std::convert::identity)
    }
    pub fn map<W, F>(self, f: F) -> FillP2ps<K, W>
    where
        F: FnMut(V) -> W + Clone,
    {
        FillP2ps::<K, W>(self.0.map(|h| h.map(f.clone())))
    }
    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<FillHoleVecMap<K, V>>> {
        self.0.iter()
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
    use crate::collections::TypedUsize;

    struct TestIndex;

    #[test]
    fn basic_correctness() {
        let zero = TypedUsize::from_usize(0);
        let one = TypedUsize::from_usize(1);
        let two = TypedUsize::from_usize(2);

        let mut fill_p2ps: FillP2ps<TestIndex, usize> = FillP2ps::with_size(3).expect("bad hole");
        fill_p2ps.set(zero, one, 0).unwrap();
        fill_p2ps.set(zero, two, 1).unwrap();
        fill_p2ps.set(one, zero, 2).unwrap();
        fill_p2ps.set(one, two, 3).unwrap();
        fill_p2ps.set(two, zero, 4).unwrap();
        fill_p2ps.set(two, one, 5).unwrap();
        assert!(fill_p2ps.is_full());
        let p2ps = fill_p2ps.to_fullp2ps().unwrap();

        let expects: Vec<(_, _, &usize)> = vec![
            (zero, one, &0),
            (zero, two, &1),
            (one, zero, &2),
            (one, two, &3),
            (two, zero, &4),
            (two, one, &5),
        ];

        // test P2ps::iter()
        for (p2ps, &expect) in p2ps.iter().zip(expects.iter()) {
            assert_eq!(p2ps, expect);
        }

        // test P2ps::into_iter()
        for (p2ps, expect) in p2ps.into_iter().zip(expects.into_iter()) {
            assert_eq!(p2ps, (expect.0, expect.1, *expect.2));
        }
    }
}
