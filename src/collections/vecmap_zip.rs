use super::{vecmap_iter::VecMapIter, TypedUsize};

pub fn zip2<K, I0, I1>(
    v0: impl IntoIterator<IntoIter = VecMapIter<K, I0>>,
    v1: impl IntoIterator<IntoIter = VecMapIter<K, I1>>,
) -> Zip2<K, I0, I1> {
    Zip2::new(v0.into_iter(), v1.into_iter())
}

pub fn zip3<K, I0, I1, I2>(
    v0: impl IntoIterator<IntoIter = VecMapIter<K, I0>>,
    v1: impl IntoIterator<IntoIter = VecMapIter<K, I1>>,
    v2: impl IntoIterator<IntoIter = VecMapIter<K, I2>>,
) -> Zip3<K, I0, I1, I2> {
    Zip3::new(v0.into_iter(), v1.into_iter(), v2.into_iter())
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

pub struct Zip3<K, I0, I1, I2> {
    iter0: VecMapIter<K, I0>,
    iter1: VecMapIter<K, I1>,
    iter2: VecMapIter<K, I2>,
    phantom: std::marker::PhantomData<K>,
}

impl<K, I0, I1, I2> Zip3<K, I0, I1, I2> {
    pub fn new(
        iter0: VecMapIter<K, I0>,
        iter1: VecMapIter<K, I1>,
        iter2: VecMapIter<K, I2>,
    ) -> Self {
        Self {
            iter0,
            iter1,
            iter2,
            phantom: std::marker::PhantomData,
        }
    }
}

impl<K, I0, I1, I2> Iterator for Zip3<K, I0, I1, I2>
where
    I0: Iterator,
    I1: Iterator,
    I2: Iterator,
{
    type Item = (
        TypedUsize<K>,
        <I0 as Iterator>::Item,
        <I1 as Iterator>::Item,
        <I2 as Iterator>::Item,
    );

    fn next(&mut self) -> Option<Self::Item> {
        let (i, a0) = self.iter0.next()?;
        let (_, a1) = self.iter1.next()?;
        let (_, a2) = self.iter2.next()?;
        Some((i, a0, a1, a2))
    }
}

#[cfg(test)]
mod tests {
    use crate::collections::vecmap::VecMap;

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
