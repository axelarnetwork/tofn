use tracing::error;

use crate::{
    collections::{p2ps_iter::P2psIter, HoleVecMap, TypedUsize, VecMap},
    sdk::api::{TofnFatal, TofnResult},
};

// TODO is `FullP2ps` too similar to `FillP2ps`?
// do not derive serde for anything with a `HoleVecMap`
#[derive(Debug, Clone, PartialEq)]
pub struct FullP2ps<K, V>(pub(super) VecMap<K, HoleVecMap<K, V>>);

impl<K, V> FullP2ps<K, V> {
    pub fn get(&self, from: TypedUsize<K>, to: TypedUsize<K>) -> TofnResult<&V> {
        self.0.get(from)?.get(to)
    }

    pub fn to_me(
        &self,
        me: TypedUsize<K>,
    ) -> TofnResult<impl Iterator<Item = (TypedUsize<K>, &V)> + '_> {
        if me.as_usize() >= self.0.len() {
            error!("index {} out of bounds {}", me, self.0.len());
            return Err(TofnFatal);
        }
        Ok(self.0.iter().filter_map(move |(from, hole_vec)| {
            if from == me {
                None
            } else {
                // Avoid panic: we already checked `me` so `get(me)` should never fail.
                // Normally we would bubble the error from `get(me)` via Result::collect`.
                // But we can't do that here because this method returns an iterator.
                // Instead we log the error and discard failures by returning `None` in the `filter_map` closure.
                match hole_vec.get(me) {
                    Ok(v) => Some((from, v)),
                    Err(err) => {
                        error!(
                            "unreachable because we already verified `me` {} is in bounds {} (from {}, err {:?})",
                            me, self.0.len(), from, err,
                        );
                        None
                    }
                }
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
        VecMap::from_vec(self.to_me(me)?.map(|(_, v)| f(v)).collect()).remember_hole(me)
    }
    pub fn map_to_me2<W, F>(&self, me: TypedUsize<K>, f: F) -> TofnResult<HoleVecMap<K, W>>
    where
        F: FnMut((TypedUsize<K>, &V)) -> W,
    {
        VecMap::from_vec(self.to_me(me)?.map(f).collect()).remember_hole(me)
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