use crate::vecmap::{Behave, FillHoleVecMap, HoleVecMap, Index, VecMap};

use super::p2ps_iter::P2psIter;

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
    pub fn iter(&self) -> P2psIter<K, std::slice::Iter<HoleVecMap<K, V>>, std::slice::Iter<V>> {
        P2psIter::new(self.0.iter())
    }

    pub fn map_to_me<W, F>(&self, me: Index<K>, mut f: F) -> HoleVecMap<K, W>
    where
        F: FnMut(&V) -> W,
    {
        HoleVecMap::from_vecmap(
            VecMap::from_vec(self.to_me(me).map(|(_, v)| f(v)).collect()),
            me,
        )
    }

    pub fn map_to_me2<W, F>(&self, me: Index<K>, f: F) -> HoleVecMap<K, W>
    where
        F: FnMut((Index<K>, &V)) -> W,
    {
        HoleVecMap::from_vecmap(VecMap::from_vec(self.to_me(me).map(f).collect()), me)
    }

    pub fn map<W, F>(self, f: F) -> P2ps<K, W>
    where
        F: FnMut(V) -> W + Clone,
    {
        P2ps::<K, W>(self.0.map(|v| v.map(f.clone())))
    }
}

impl<K, V> IntoIterator for P2ps<K, V>
where
    K: Behave,
{
    type Item = (
        Index<K>,
        Index<K>,
        <std::vec::IntoIter<V> as Iterator>::Item,
    );
    type IntoIter = P2psIter<K, std::vec::IntoIter<HoleVecMap<K, V>>, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        P2psIter::new(self.0.into_iter())
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
    pub fn is_full(&self) -> bool {
        self.0.iter().all(|(_, v)| v.is_full())
    }
    pub fn unwrap_all_map<W, F>(self, f: F) -> P2ps<K, W>
    where
        F: FnMut(V) -> W + Clone,
    {
        P2ps::<K, W>(self.0.map(|v| v.unwrap_all_map(f.clone())))
    }
    pub fn unwrap_all(self) -> P2ps<K, V> {
        self.unwrap_all_map(std::convert::identity)
    }
}

#[cfg(test)]
mod tests {
    use super::FillP2ps;
    use crate::vecmap::{Behave, Index};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    struct TestIndex;
    impl Behave for TestIndex {}

    #[test]
    fn basic_correctness() {
        let zero = Index::from_usize(0);
        let one = Index::from_usize(1);
        let two = Index::from_usize(2);

        let mut fill_p2ps: FillP2ps<TestIndex, usize> = FillP2ps::with_size(3);
        fill_p2ps.set(zero, one, 0);
        fill_p2ps.set(zero, two, 1);
        fill_p2ps.set(one, zero, 2);
        fill_p2ps.set(one, two, 3);
        fill_p2ps.set(two, zero, 4);
        fill_p2ps.set(two, one, 5);
        assert!(fill_p2ps.is_full());
        let p2ps = fill_p2ps.unwrap_all();

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
