use super::{vecmap_iter::VecMapIter, TypedUsize};

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct HoleVecMapIter<K, I> {
    iter: VecMapIter<K, I>,
    hole: TypedUsize<K>,
}

impl<K, I> HoleVecMapIter<K, I> {
    pub fn new(iter: VecMapIter<K, I>, hole: TypedUsize<K>) -> Self {
        Self { iter, hole }
    }
}

impl<K, I> Iterator for HoleVecMapIter<K, I>
where
    I: Iterator,
{
    type Item = <VecMapIter<K, I> as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let (mut i, a) = self.iter.next()?;
        if i.as_usize() >= self.hole.as_usize() {
            i = TypedUsize::from_usize(i.as_usize() + 1); // skip hole
        }
        Some((i, a))
    }
}
