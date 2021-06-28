#[derive(Debug, Clone, PartialEq)]
pub struct VecMap<T, I>(Vec<T>, std::marker::PhantomData<Index<I>>);

impl<T, I> VecMap<T, I> {
    pub fn from_vec(vec: Vec<T>) -> Self {
        Self(vec, std::marker::PhantomData)
    }
    pub fn get(&self, index: Index<I>) -> &T {
        // TODO range check?
        &self.0[index.0]
    }
    pub fn get_mut(&mut self, index: Index<I>) -> &mut T {
        // TODO range check?
        &mut self.0[index.0]
    }
}

impl<T, I> IntoIterator for VecMap<T, I> {
    type Item = (Index<I>, <std::vec::IntoIter<T> as Iterator>::Item);
    type IntoIter = VecMapIter<T, I>;

    fn into_iter(self) -> Self::IntoIter {
        VecMapIter::new(self.0.into_iter())
    }
}

impl<T, I> FromIterator<T> for VecMap<T, I> {
    fn from_iter<Iter: IntoIterator<Item = T>>(iter: Iter) -> Self {
        VecMap::from_vec(Vec::from_iter(iter))
    }
}

#[derive(Debug, PartialEq)] // manual impls for Clone, Copy---see below
pub struct Index<I>(usize, std::marker::PhantomData<I>);

impl<I> Index<I> {
    fn from_usize(index: usize) -> Self {
        Index(index, std::marker::PhantomData)
    }
}

/// Manually impl `Clone`, `Copy` because https://stackoverflow.com/a/31371094
impl<I> Clone for Index<I> {
    fn clone(&self) -> Self {
        Self::from_usize(self.0)
    }
}
impl<I> Copy for Index<I> {}

mod vecmap_iter;
use std::iter::FromIterator;

use vecmap_iter::VecMapIter;
