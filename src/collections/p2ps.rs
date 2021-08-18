use tracing::error;

use crate::{
    collections::{HoleVecMap, TypedUsize, VecMap, VecMapIter},
    sdk::api::{TofnFatal, TofnResult},
};

use super::FullP2ps;

#[derive(Debug, Clone, PartialEq)]
pub struct P2ps<K, V>(pub(super) VecMap<K, Option<HoleVecMap<K, V>>>);

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

#[cfg(test)]
mod tests {
    use crate::collections::{FillP2ps, TypedUsize};

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
