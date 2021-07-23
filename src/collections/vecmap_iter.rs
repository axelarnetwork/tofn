use super::TypedUsize;

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct VecMapIter<K, I> {
    iter: I,
    count: TypedUsize<K>,
}

impl<K, I> VecMapIter<K, I> {
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            count: TypedUsize::from_usize(0),
        }
    }
}

impl<K, I> Iterator for VecMapIter<K, I>
where
    I: Iterator,
{
    type Item = (TypedUsize<K>, <I as Iterator>::Item);

    fn next(&mut self) -> Option<Self::Item> {
        let a = self.iter.next()?;
        let i = self.count;
        self.count = TypedUsize::from_usize(self.count.as_usize() + 1);
        Some((i, a))
    }
}
