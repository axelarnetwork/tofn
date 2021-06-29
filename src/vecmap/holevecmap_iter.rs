use super::{vecmap_iter::VecMapIter, Index};

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct HoleVecMapIter<K, I> {
    iter: VecMapIter<K, I>,
    hole: Index<K>,
}

impl<K, I> HoleVecMapIter<K, I> {
    pub fn new(iter: VecMapIter<K, I>, hole: Index<K>) -> Self {
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
        if i.0 >= self.hole.0 {
            i.0 += 1; // skip hole
        }
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
