use tracing::error;

use crate::{
    collections::{HoleVecMap, TypedUsize, VecMap, VecMapIter},
    sdk::api::{TofnFatal, TofnResult},
};

use super::FullP2ps;

#[derive(Debug, Clone, PartialEq)]
pub struct P2ps<K, V>(VecMap<K, Option<HoleVecMap<K, V>>>);

impl<K, V> P2ps<K, V> {
    pub fn new_size_1_some() -> Self {
        Self(VecMap::from_vec(vec![Some(HoleVecMap::from_vecmap(
            VecMap::from_vec(vec![]),
            TypedUsize::from_usize(0),
        ))]))
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, from: TypedUsize<K>) -> TofnResult<&Option<HoleVecMap<K, V>>> {
        self.0.get(from)
    }

    pub fn iter(&self) -> VecMapIter<K, std::slice::Iter<Option<HoleVecMap<K, V>>>> {
        self.0.iter()
    }

    pub fn map<W, F>(self, mut f: F) -> P2ps<K, W>
    where
        F: FnMut(V) -> W,
    {
        P2ps::<K, W>(
            self.0
                .map(|hole_vec_option| hole_vec_option.map(|hole_vec| hole_vec.map(&mut f))),
        )
    }

    pub fn map_to_fullp2ps<W, F>(self, mut f: F) -> TofnResult<FullP2ps<K, W>>
    where
        F: FnMut(V) -> W,
    {
        Ok(FullP2ps::<K, W>::from_vecmap(self.0.map2_result(
            |(from, hole_vec_option)| {
                Ok(hole_vec_option
                    .ok_or_else(|| {
                        error!("missing HoleVecMap at index {}", from);
                        TofnFatal
                    })?
                    .map(&mut f))
            },
        )?))
    }
    pub fn to_fullp2ps(self) -> TofnResult<FullP2ps<K, V>> {
        self.map_to_fullp2ps(std::convert::identity)
    }

    // private constructor does no checks, does not return TofnResult, cannot panic
    pub(super) fn from_vecmap(vec: VecMap<K, Option<HoleVecMap<K, V>>>) -> Self {
        Self(vec)
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

        let mut fill_p2ps: FillP2ps<TestIndex, usize> = FillP2ps::with_size(3);
        fill_p2ps.set(zero, one, 0).unwrap();
        fill_p2ps.set(zero, two, 1).unwrap();
        fill_p2ps.set(one, zero, 2).unwrap();
        fill_p2ps.set(one, two, 3).unwrap();
        fill_p2ps.set(two, zero, 4).unwrap();
        fill_p2ps.set(two, one, 5).unwrap();
        assert!(fill_p2ps.is_full());
        let all_p2ps = fill_p2ps.to_fullp2ps().unwrap();

        let all_expects: Vec<(_, Vec<(_, &usize)>)> = vec![
            (zero, vec![(one, &0), (two, &1)]),
            (one, vec![(zero, &2), (two, &3)]),
            (two, vec![(zero, &4), (one, &5)]),
        ];

        // test P2ps::iter()
        assert_eq!(all_p2ps.iter().count(), 3);
        for ((_, p2ps), (_, expects)) in all_p2ps.iter().zip(all_expects.iter()) {
            assert_eq!(p2ps.iter().count(), 2);
            for (p2p, expect) in p2ps.iter().zip(expects.iter()) {
                assert_eq!(p2p, *expect);
            }
        }

        // test P2ps::into_iter()
        for ((_, p2ps), (_, expects)) in all_p2ps.into_iter().zip(all_expects.into_iter()) {
            for (p2p, expect) in p2ps.iter().zip(expects.iter()) {
                assert_eq!(p2p, *expect);
            }
        }
    }
}
