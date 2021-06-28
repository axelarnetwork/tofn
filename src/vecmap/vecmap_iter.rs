use super::Index;

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct VecMapIter<T, I> {
    iter: std::vec::IntoIter<T>,
    count: Index<I>,
}

impl<T, I> VecMapIter<T, I> {
    pub fn new(iter: std::vec::IntoIter<T>) -> Self {
        Self {
            iter,
            count: Index::from_usize(0),
        }
    }
}

impl<T, I> Iterator for VecMapIter<T, I> {
    type Item = (Index<I>, <std::vec::IntoIter<T> as Iterator>::Item);

    fn next(&mut self) -> Option<Self::Item> {
        let a = self.iter.next()?;
        let i = self.count;
        self.count.0 += 1;
        Some((i, a))
    }

    /// forbid use of `enumerate` because this functionality is already provided by this iterator
    fn enumerate(self) -> std::iter::Enumerate<Self>
    where
        Self: Sized,
    {
        unimplemented!("iterator already returns a type-safe (index,value) pair");
    }
}

mod tests {

    struct TestIndex;

    #[test]
    #[should_panic]
    fn override_enumerate() {
        let _ = super::super::VecMap::<_, TestIndex>::from_vec(vec![1, 2, 3, 4])
            .into_iter()
            .enumerate();
    }
}
