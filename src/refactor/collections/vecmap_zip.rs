use super::{vecmap_iter::VecMapIter, TypedUsize, VecMap};

pub fn zip2<'a, K, V0, V1>(
    v0: &'a VecMap<K, V0>,
    v1: &'a VecMap<K, V1>,
) -> Zip2<K, std::slice::Iter<'a, V0>, std::slice::Iter<'a, V1>> {
    Zip2::new(v0.iter(), v1.iter())
}

pub struct Zip2<K, I0, I1> {
    iter0: VecMapIter<K, I0>,
    iter1: VecMapIter<K, I1>,
    phantom: std::marker::PhantomData<K>,
}

impl<K, I0, I1> Zip2<K, I0, I1> {
    pub fn new(iter0: VecMapIter<K, I0>, iter1: VecMapIter<K, I1>) -> Self {
        Self {
            iter0,
            iter1,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<K, I0, I1> Iterator for Zip2<K, I0, I1>
where
    I0: Iterator,
    I1: Iterator,
{
    type Item = (
        TypedUsize<K>,
        <I0 as Iterator>::Item,
        <I1 as Iterator>::Item,
    );

    fn next(&mut self) -> Option<Self::Item> {
        let (i, a0) = self.iter0.next()?;
        let (_, a1) = self.iter1.next()?;
        Some((i, a0, a1))
    }
}

#[cfg(test)]
mod tests {
    use crate::refactor::collections::vecmap::VecMap;

    use super::zip2;

    struct TestIndex;

    #[test]
    fn basic_correctness() {
        let test_size = 5;
        let v0: VecMap<TestIndex, _> = (0..test_size).collect();
        let v1: VecMap<TestIndex, _> = (test_size..2 * test_size).collect();

        for (counter, (i, a0, a1)) in zip2(&v0, &v1).enumerate() {
            assert_eq!(i.as_usize(), counter);
            assert_eq!(*a0, counter);
            assert_eq!(*a1, counter + test_size);
        }
    }
}
