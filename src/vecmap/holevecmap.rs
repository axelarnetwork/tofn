use crate::refactor::TofnResult;
use std::iter::FromIterator;

use super::{holevecmap_iter::HoleVecMapIter, Behave, Index, VecMap};

#[derive(Debug, Clone, PartialEq)]
pub struct HoleVecMap<K, V>
where
    K: Behave,
{
    vec: VecMap<K, V>,
    hole: Index<K>,
    phantom: std::marker::PhantomData<Index<K>>,
}

impl<K, V> HoleVecMap<K, V>
where
    K: Behave,
{
    pub fn from_vecmap(vec: VecMap<K, V>, hole: Index<K>) -> Self {
        HoleVecMap {
            vec,
            hole,
            phantom: std::marker::PhantomData,
        }
    }
    pub fn get(&self, index: Index<K>) -> &V {
        self.vec.get(self.map_index(index).expect("bad index"))
    }
    pub fn get_mut(&mut self, index: Index<K>) -> &mut V {
        self.vec.get_mut(self.map_index(index).expect("bad index"))
    }
    pub fn len(&self) -> usize {
        self.vec.len() + 1
    }
    pub fn plug_hole(self, val: V) -> VecMap<K, V> {
        let mut vec = self.vec.into_vec();
        vec.insert(self.hole.0, val);
        VecMap::from_vec(vec)
    }
    pub fn iter(&self) -> HoleVecMapIter<K, std::slice::Iter<V>> {
        HoleVecMapIter::new(self.vec.iter(), self.hole)
    }
    fn map_index(&self, index: Index<K>) -> Result<Index<K>, &'static str> {
        match index.0 {
            i if i < self.hole.0 => Ok(index),
            i if i > self.hole.0 && i <= self.vec.len() => Ok(Index::from_usize(i - 1)),
            i if i == self.hole.0 => Err("index == hole"),
            _ => Err("index out of range"),
        }
    }
    pub fn map<W, F>(self, f: F) -> HoleVecMap<K, W>
    where
        F: FnMut(V) -> W,
    {
        HoleVecMap::<K, W>::from_vecmap(self.vec.map(f), self.hole)
    }
    pub fn map2<W, F>(self, f: F) -> HoleVecMap<K, W>
    where
        F: FnMut((Index<K>, V)) -> W,
    {
        let hole = self.hole;
        HoleVecMap::<K, W>::from_vecmap(self.into_iter().map(f).collect(), hole)
    }
}

impl<K, V> IntoIterator for HoleVecMap<K, V>
where
    K: Behave,
{
    type Item = (Index<K>, <std::vec::IntoIter<V> as Iterator>::Item);
    type IntoIter = HoleVecMapIter<K, std::vec::IntoIter<V>>;

    fn into_iter(self) -> Self::IntoIter {
        HoleVecMapIter::new(self.vec.into_iter(), self.hole)
    }
}

/// impl IntoIterator for &HoleVecMap as suggested here: https://doc.rust-lang.org/std/iter/index.html#iterating-by-reference
/// follow the template of Vec: https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#2451-2458
impl<'a, K, V> IntoIterator for &'a HoleVecMap<K, V>
where
    K: Behave,
{
    type Item = (Index<K>, <std::slice::Iter<'a, V> as Iterator>::Item);
    type IntoIter = HoleVecMapIter<K, std::slice::Iter<'a, V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/*
/// Need our own crate-local `Pair` struct instead of tuple `(Index<K>,V)` because this...
/// ```compile_fail
/// impl<K, V> FromIterator<(Index<K>,V)> for TofnResult<HoleVecMap<K, V>> {
///     fn from_iter<Iter: IntoIterator<Item = (Index<K>,V)>>(iter: Iter) -> Self {
///         todo!()
///     }
/// }
/// ```
/// ...makes the compiler complain:
/// "this is not defined in the current crate because tuples are always foreign"
pub struct Pair<K, V>(pub Index<K>, pub V)
where
    K: Behave;

impl<K, V> FromIterator<Pair<K, V>> for TofnResult<HoleVecMap<K, V>>
where
    K: Behave,
{
    fn from_iter<Iter: IntoIterator<Item = Pair<K, V>>>(iter: Iter) -> Self {
        Self::from_iter(
            iter.into_iter()
                .map(|pair| Pair(pair.0, TofnResult::Ok(pair.1))),
        )
    }
}

/// Follow the lead: https://doc.rust-lang.org/std/result/enum.Result.html#method.from_iter
impl<K, V, E> FromIterator<Pair<K, Result<V, E>>> for TofnResult<HoleVecMap<K, V>>
where
    E: std::fmt::Display,
    K: Behave,
{
    fn from_iter<Iter: IntoIterator<Item = Pair<K, Result<V, E>>>>(iter: Iter) -> Self {
        // indices must be in ascending order with at most one hole
        // (if there is no hole then the hole is the final index)
        let mut hole: Option<Index<K>> = None;
        let vec: VecMap<K, V> = iter
            .into_iter()
            .enumerate()
            .map(|(i, pair)| {
                let j = pair.0 .0;
                if hole.is_none() && j == i + 1 {
                    hole = Some(Index::from_usize(i));
                }
                if (hole.is_none() && j == i) || (hole.is_some() && j == i + 1) {
                    pair.1.map_err(|err| err.to_string())
                } else {
                    // Need to manually convert `hole` to String
                    // because https://stackoverflow.com/a/31371094
                    let hole_str = match hole {
                        Some(index) => index.0.to_string(),
                        None => "`None`".to_string(),
                    };
                    Err(format!(
                        "invalid iterator: index {} at position {} with hole {}",
                        j, i, hole_str
                    ))
                }
            })
            .collect::<TofnResult<VecMap<K, V>>>()?;

        let hole = match hole {
            Some(index) => index,
            None => Index::from_usize(vec.len()), // hole is the final index
        };

        Ok(HoleVecMap::from_vecmap(vec, hole))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        refactor::TofnResult,
        vecmap::{holevecmap::HoleVecMap, Behave, Index},
    };
    use serde::{Deserialize, Serialize};

    use super::Pair;

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    struct TestIndex;
    impl Behave for TestIndex {}

    #[test]
    fn basic_correctness() {
        let hole = 2;
        let vec: Vec<Pair<TestIndex, _>> = (0..5)
            .map(|i| {
                if i >= hole {
                    Pair(Index::from_usize(i + 1), 100 + i)
                } else {
                    Pair(Index::from_usize(i), 10 + i)
                }
            })
            .collect();
        let res: TofnResult<HoleVecMap<TestIndex, _>> = vec.into_iter().collect();
        let holevecmap = res.expect("test fail");
        assert_eq!(holevecmap.len(), 6);
        assert_eq!(holevecmap.hole.0, hole);
        assert_eq!(*holevecmap.get(Index::from_usize(0)), 10);
        assert_eq!(*holevecmap.get(Index::from_usize(1)), 11);
        assert_eq!(*holevecmap.get(Index::from_usize(3)), 102);
        assert_eq!(*holevecmap.get(Index::from_usize(4)), 103);
        assert_eq!(*holevecmap.get(Index::from_usize(5)), 104);
    }

    #[test]
    fn hole_at_the_end() {
        let hole = 5;
        let vec: Vec<Pair<TestIndex, _>> = (0..5)
            .map(|i| {
                if i >= hole {
                    Pair(Index::from_usize(i + 1), 100 + i)
                } else {
                    Pair(Index::from_usize(i), 10 + i)
                }
            })
            .collect();
        let res: TofnResult<HoleVecMap<TestIndex, _>> = vec.into_iter().collect();
        let holevecmap = res.expect("test fail");
        assert_eq!(holevecmap.len(), 6);
        assert_eq!(holevecmap.hole.0, hole);
        assert_eq!(*holevecmap.get(Index::from_usize(0)), 10);
        assert_eq!(*holevecmap.get(Index::from_usize(1)), 11);
        assert_eq!(*holevecmap.get(Index::from_usize(2)), 12);
        assert_eq!(*holevecmap.get(Index::from_usize(3)), 13);
        assert_eq!(*holevecmap.get(Index::from_usize(4)), 14);
    }
}
*/
