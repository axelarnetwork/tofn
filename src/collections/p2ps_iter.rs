use super::{holevecmap_iter::HoleVecMapIter, vecmap_iter::VecMapIter, TypedUsize};

// follow the example of std::iter::Flatten: https://doc.rust-lang.org/src/core/iter/adapters/flatten.rs.html#251-278
pub struct P2psIter<K, I0, I1> {
    iter0: VecMapIter<K, I0>,
    iter1: Option<HoleVecMapIter<K, I1>>,
    from: TypedUsize<K>,
}

impl<K, I0, I1> P2psIter<K, I0, I1> {
    pub fn new(iter: VecMapIter<K, I0>) -> Self {
        Self {
            iter0: iter,
            iter1: None,
            from: TypedUsize::from_usize(0),
        }
    }
}

impl<K, I0, I1> Iterator for P2psIter<K, I0, I1>
where
    I0: Iterator,
    <I0 as Iterator>::Item: IntoIterator<IntoIter = HoleVecMapIter<K, I1>>,
    I1: Iterator,
{
    type Item = (TypedUsize<K>, TypedUsize<K>, <I1 as Iterator>::Item);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut iter1) = self.iter1 {
                if let Some((to, item)) = iter1.next() {
                    return Some((self.from, to, item));
                } else {
                    self.iter1 = None;
                }
            }
            // self.iter1 is None; grab the next one and try again
            if let Some((from, holevecmap)) = self.iter0.next() {
                self.from = from;
                self.iter1 = Some(holevecmap.into_iter());
            } else {
                return None;
            }
        }
    }
}
