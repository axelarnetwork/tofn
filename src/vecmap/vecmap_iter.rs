use super::{Behave, TypedUsize};

/// Follows the implementation of std::iter::Enumerate https://doc.rust-lang.org/std/iter/struct.Enumerate.html
pub struct VecMapIter<K, I>
where
    K: Behave,
{
    iter: I,
    count: TypedUsize<K>,
}

impl<K, I> VecMapIter<K, I>
where
    K: Behave,
{
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            count: TypedUsize::from_usize(0),
        }
    }
}

impl<K, I> Iterator for VecMapIter<K, I>
where
    K: Behave,
    I: Iterator,
{
    type Item = (TypedUsize<K>, <I as Iterator>::Item);

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
    use crate::vecmap::{vecmap::VecMap, Behave};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    struct TestIndex;
    impl Behave for TestIndex {}

    #[test]
    #[should_panic]
    fn override_enumerate() {
        let vecmap: VecMap<TestIndex, _> = (0..4).collect();
        let _ = vecmap.into_iter().enumerate();
    }
}
