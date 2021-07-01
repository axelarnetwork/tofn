#[derive(Debug)] // manual impls for Clone, Copy, PartialEq---see below
pub struct Index<K>(usize, std::marker::PhantomData<K>);

impl<K> Index<K> {
    // TODO provide a range iterator (0..n)?
    // TODO from_usize, as_usize should be private
    pub fn from_usize(index: usize) -> Self {
        Index(index, std::marker::PhantomData)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl<K> std::fmt::Display for Index<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Manually impl `Clone`, `Copy`, `PartialEq` because https://stackoverflow.com/a/31371094
impl<K> Clone for Index<K> {
    fn clone(&self) -> Self {
        Self::from_usize(self.0)
    }
}
impl<K> Copy for Index<K> {}

impl<K> PartialEq for Index<K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

mod vecmap;
mod vecmap_iter;
mod vecmap_zip;
pub use vecmap::VecMap;

mod fillvecmap;
pub use fillvecmap::FillVecMap;

mod holevecmap;
mod holevecmap_iter;
pub use holevecmap::{HoleVecMap, Pair};

mod fillholevecmap;
pub use fillholevecmap::FillHoleVecMap;
