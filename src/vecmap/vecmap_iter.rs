use super::Index;

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct VecMapIter<K, I> {
    iter: I,
    count: Index<K>,
}

impl<K, I> VecMapIter<K, I> {
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            count: Index::from_usize(0),
        }
    }
}

impl<K, I> Iterator for VecMapIter<K, I>
where
    I: Iterator,
{
    type Item = (Index<K>, <I as Iterator>::Item);

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

#[cfg(test)]
mod tests {
    use crate::vecmap::vecmap::VecMap;

    struct TestIndex;

    #[test]
    #[should_panic]
    fn override_enumerate() {
        let vecmap: VecMap<TestIndex, _> = (0..4).collect();
        let _ = vecmap.into_iter().enumerate();
    }
}